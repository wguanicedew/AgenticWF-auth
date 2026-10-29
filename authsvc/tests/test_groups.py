import time
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from agenticwf.auth.app import create_app
from agenticwf.auth.context import HEADER_CONTEXT, HEADER_SIGNATURE, decode_context
from agenticwf.auth.groups import Memberships, MemoryRequestStore
from agenticwf.auth.oidc import TokenSet
from agenticwf.auth.sessions import MemorySessionStore, SessionManager
from agenticwf.auth.tokens import ManagementError, ManagementUnavailableError

from .conftest import SECRET
from .test_web import APP, CLIENT_ID, FakeLogto, fwd, login

SAME_ORIGIN = {"Origin": APP}
ROLES = {"admin": "r_admin", "member": "r_member"}


class FakeOrgs:
    """Logto organizations, members and organization roles, as the Management API answers."""

    def __init__(self):
        self.orgs = {}       # id -> {id, name, description}
        self.members = {}    # org id -> {user id: set of role names}
        self.users = {"alice": "alice@example.org", "bob": "bob@example.org", "carol": "carol@example.org"}
        self.down = False

    def organizations(self):
        return list(self.orgs.values())

    def organization(self, org_id):
        if org_id not in self.orgs:
            raise ManagementError(404, "reading the group: not found.")
        return self.orgs[org_id]

    def create_organization(self, name, description):
        org_id = f"o{len(self.orgs) + 1}"
        self.orgs[org_id] = {"id": org_id, "name": name, "description": description}
        self.members[org_id] = {}
        return self.orgs[org_id]

    def update_organization(self, org_id, fields):
        self.organization(org_id).update(fields)
        return self.orgs[org_id]

    def delete_organization(self, org_id):
        self.organization(org_id)
        del self.orgs[org_id], self.members[org_id]

    def organization_members(self, org_id):
        self.organization(org_id)
        return [{"id": u, "name": u.title(), "primaryEmail": self.users[u],
                 "organizationRoles": [{"id": ROLES[r], "name": r} for r in sorted(roles)]}
                for u, roles in self.members[org_id].items()]

    def add_member(self, org_id, user_id, role_ids):
        self.members[org_id][user_id] = set()
        self.set_member_roles(org_id, user_id, role_ids)

    def remove_member(self, org_id, user_id):
        del self.members[org_id][user_id]

    def set_member_roles(self, org_id, user_id, role_ids):
        names = {v: k for k, v in ROLES.items()}
        self.members[org_id][user_id] = {names[r] for r in role_ids}

    def user_organizations(self, user_id):
        if self.down:
            raise ManagementUnavailableError("down")
        return [{**self.orgs[o], "organizationRoles": [{"id": ROLES[r], "name": r} for r in roles]}
                for o, m in self.members.items() for u, roles in m.items() if u == user_id]

    def organization_role_ids(self):
        return dict(ROLES)

    def find_user(self, email):
        return next(({"id": u, "primaryEmail": e} for u, e in self.users.items() if e == email), None)


class UserLogto(FakeLogto):
    """Signs in as `sub`."""

    def __init__(self, make_token, sub, scope):
        super().__init__(make_token)
        self.sub, self.scope = sub, scope

    def _tokens(self, rt, scope=None):
        return TokenSet(access_token=self.make_token(scope=scope or self.scope, sub=self.sub),
                        expires_at=int(time.time()) + 3600, refresh_token=rt,
                        id_token=self.make_token(aud=CLIENT_ID, nonce=self.nonce, sub=self.sub, name=self.sub.title()))


@pytest.fixture
def env(settings, verifier, make_token):
    settings = replace(settings, web_client_id=CLIENT_ID, web_client_secret="x", app_origin=APP,
                       logto_endpoint="https://auth.example.org")
    orgs = FakeOrgs()
    memberships = Memberships(orgs, ttl=60)
    requests = MemoryRequestStore()

    def client(sub, scope="app:access agent:use knowledge:read"):
        logto = UserLogto(make_token, sub, scope)
        manager = SessionManager(MemorySessionStore(), logto, idle_ttl=3600, max_ttl=86400)
        app = create_app(settings=settings, verifier=verifier, sessions=manager, logto=logto, management=orgs,
                         memberships=memberships, group_requests=requests)
        c = TestClient(app, base_url=APP, follow_redirects=False)
        login(c)
        return c

    return client, orgs, memberships


def test_admin_creates_group_and_appoints_group_admin(env):
    client, orgs, _ = env
    admin, alice = client("root", "app:access admin"), client("alice")
    assert alice.post("/auth/groups", json={"name": "EIC"}, headers=SAME_ORIGIN).status_code == 403
    r = admin.post("/auth/groups", json={"name": "EIC", "description": "detector"}, headers=SAME_ORIGIN)
    assert r.status_code == 201
    gid = r.json()["id"]
    assert r.json()["group"] == f"org:{gid}"
    r = admin.post(f"/auth/groups/{gid}/members", json={"email": "alice@example.org", "admin": True}, headers=SAME_ORIGIN)
    assert r.status_code == 201 and r.json()["members"][0] == {
        "user_id": "alice", "name": "Alice", "email": "alice@example.org", "admin": True}
    assert orgs.members[gid]["alice"] == {"admin", "member"}
    [g] = alice.get("/auth/groups").json()["groups"]
    assert g["member"] and g["admin"] and g["can_manage"] and g["pending"] == 0
    assert admin.post(f"/auth/groups/{gid}/members", json={"email": "nobody@example.org"},
                      headers=SAME_ORIGIN).status_code == 404


def test_request_approve_and_group_admin_limits(env):
    client, orgs, _ = env
    gid = orgs.create_organization("EIC", "")["id"]
    orgs.add_member(gid, "alice", [ROLES["member"], ROLES["admin"]])
    alice, bob, carol = client("alice"), client("bob"), client("carol")

    assert bob.get(f"/auth/groups/{gid}/members").status_code == 403          # not a member: no member list
    assert bob.post(f"/auth/groups/{gid}/requests", json={"message": "hi"}, headers=SAME_ORIGIN).status_code == 201
    assert bob.post(f"/auth/groups/{gid}/requests", json={}, headers={"Origin": "https://evil"}).status_code == 403
    [g] = bob.get("/auth/groups").json()["groups"]
    assert g["requested"] and not g["member"] and "pending" not in g
    assert alice.get("/auth/groups").json()["groups"][0]["pending"] == 1
    listed = alice.get(f"/auth/groups/{gid}/members").json()
    assert [r["user_id"] for r in listed["requests"]] == ["bob"] and listed["requests"][0]["message"] == "hi"

    assert carol.post(f"/auth/groups/{gid}/requests/bob", json={"approve": True}, headers=SAME_ORIGIN).status_code == 403
    r = alice.post(f"/auth/groups/{gid}/requests/bob", json={"approve": True}, headers=SAME_ORIGIN)
    assert r.status_code == 200 and orgs.members[gid]["bob"] == {"member"}
    assert bob.get(f"/auth/groups/{gid}/members").json().get("requests") is None   # members see members only
    assert bob.post(f"/auth/groups/{gid}/members", json={"email": "carol@example.org"},
                    headers=SAME_ORIGIN).status_code == 403                    # not a group admin
    assert bob.delete("/auth/groups/" + gid, headers=SAME_ORIGIN).status_code == 403

    # the last admin cannot leave or step down; with another admin, they can
    assert alice.delete(f"/auth/groups/{gid}/members/alice", headers=SAME_ORIGIN).status_code == 409
    assert alice.patch(f"/auth/groups/{gid}/members/alice", json={"admin": False}, headers=SAME_ORIGIN).status_code == 409
    assert alice.patch(f"/auth/groups/{gid}/members/bob", json={"admin": True}, headers=SAME_ORIGIN).status_code == 200
    assert alice.delete(f"/auth/groups/{gid}/members/alice", headers=SAME_ORIGIN).status_code == 204
    assert bob.delete(f"/auth/groups/{gid}/members/bob", headers=SAME_ORIGIN).status_code == 409   # now the last one

    assert carol.post(f"/auth/groups/{gid}/requests", json={}, headers=SAME_ORIGIN).status_code == 201
    assert carol.delete(f"/auth/groups/{gid}/requests", headers=SAME_ORIGIN).status_code == 204
    assert carol.delete(f"/auth/groups/{gid}/requests", headers=SAME_ORIGIN).status_code == 404


def test_verify_carries_memberships(env, make_token):
    client, orgs, memberships = env
    gid = orgs.create_organization("EIC", "")["id"]
    alice = client("alice")
    headers = {**fwd("GET", "/api/v1/sessions/1"), "Authorization": f"Bearer {make_token(sub='alice', scope='app:access agent:use knowledge:read')}"}
    ctx = decode_context(*(alice.get("/verify", headers=headers).headers[h] for h in (HEADER_CONTEXT, HEADER_SIGNATURE)), SECRET)
    assert ctx.organizations == {}

    orgs.add_member(gid, "alice", [ROLES["member"]])
    memberships.forget("alice")   # what the group routes do after a change
    ctx = decode_context(*(alice.get("/verify", headers=headers).headers[h] for h in (HEADER_CONTEXT, HEADER_SIGNATURE)), SECRET)
    assert ctx.organizations == {gid: "EIC"}
    assert alice.get("/whoami", headers={"Authorization": headers["Authorization"]}).json()["organizations"] == {gid: "EIC"}

    orgs.down = True              # Logto unreachable: the last known groups stay, requests still pass
    memberships.forget("alice")
    assert alice.get("/verify", headers=headers).status_code == 200


def test_memberships_cache_and_failure():
    orgs, now = FakeOrgs(), [1000.0]
    gid = orgs.create_organization("EIC", "")["id"]
    orgs.add_member(gid, "alice", [ROLES["member"]])
    m = Memberships(orgs, ttl=60, clock=lambda: now[0])
    assert m.names("alice") == {gid: "EIC"}
    orgs.remove_member(gid, "alice")
    assert m.names("alice") == {gid: "EIC"}           # cached
    now[0] += 61
    assert m.names("alice") == {}
    orgs.add_member(gid, "alice", [ROLES["member"]])
    orgs.down = True
    now[0] += 61
    assert m.names("alice") == {}                     # down: the last known answer
    with pytest.raises(ManagementUnavailableError):
        m.of("alice", fresh=True)                     # permission checks never use a stale answer
