import time
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from agenticwf.auth.app import create_app
from agenticwf.auth.directory import ManagementError, ManagementUnavailableError
from agenticwf.auth.context import HEADER_CONTEXT, HEADER_SIGNATURE, decode_context
from agenticwf.auth.groups import Memberships, MemoryRequestStore, Profiles
from agenticwf.auth.oidc import TokenSet
from agenticwf.auth.provider import Provider
from agenticwf.auth.sessions import MemorySessionStore, SessionManager

from .conftest import SECRET
from .test_web import APP, CLIENT_ID, FakeOIDC, fwd, login

SAME_ORIGIN = {"Origin": APP}


class FakeGroups:
    """A provider's groups and their members, as a Directory answers."""

    def __init__(self):
        self.groups_ = {}    # id -> {id, name, description}
        self.members = {}    # group id -> {user id: admin?}
        self.users = {"alice": "alice@example.org", "bob": "bob@example.org", "carol": "carol@example.org"}
        self.down = False

    def groups(self):
        return list(self.groups_.values())

    def group(self, group_id):
        if group_id not in self.groups_:
            raise ManagementError(404, "reading the group: not found.")
        return self.groups_[group_id]

    def create_group(self, name, description):
        group_id = f"g{len(self.groups_) + 1}"
        self.groups_[group_id] = {"id": group_id, "name": name, "description": description}
        self.members[group_id] = {}
        return self.groups_[group_id]

    def update_group(self, group_id, fields):
        self.group(group_id).update(fields)
        return self.groups_[group_id]

    def delete_group(self, group_id):
        self.group(group_id)
        del self.groups_[group_id], self.members[group_id]

    def group_members(self, group_id):
        self.group(group_id)
        return [{"id": u, "username": u, "name": u.title(), "email": self.users.get(u, f"{u}@example.org"), "admin": admin}
                for u, admin in self.members[group_id].items()]

    def add_member(self, group_id, user_id, admin=False):
        self.members[group_id][user_id] = admin

    def remove_member(self, group_id, user_id):
        del self.members[group_id][user_id]

    def set_admin(self, group_id, user_id, admin):
        self.members[group_id][user_id] = admin

    def user_groups(self, user_id):
        if self.down:
            raise ManagementUnavailableError("down")
        return [{"id": g, "name": self.groups_[g]["name"], "admin": m[user_id]}
                for g, m in self.members.items() if user_id in m]

    def user(self, user_id):
        if self.down:
            raise ManagementUnavailableError("down")
        return {"id": user_id, "username": user_id, "name": user_id.title(), "email": self.users.get(user_id)}

    def find_user(self, email):
        return next(({"id": u, "email": e} for u, e in self.users.items() if e == email), None)


class UserOIDC(FakeOIDC):
    """Signs in as `sub`."""

    def __init__(self, make_token, sub, scope):
        super().__init__(make_token)
        self.sub, self.scope = sub, scope

    def _tokens(self, rt, scope=None):
        return TokenSet(access_token=self.make_token(scope=scope or self.scope, sub=self.sub,
                                                     preferred_username=self.sub, email=f"{self.sub}@example.org"),
                        expires_at=int(time.time()) + 3600, refresh_token=rt,
                        id_token=self.make_token(aud=CLIENT_ID, typ="ID", nonce=self.nonce, sub=self.sub,
                                                 name=self.sub.title()))


@pytest.fixture
def env(settings, verifier, make_token):
    settings = replace(settings, web_client_id=CLIENT_ID, web_client_secret="x", app_origin=APP,
                       session_store="memory")
    orgs = FakeGroups()
    memberships = Memberships(orgs, ttl=60)
    requests = MemoryRequestStore()

    def client(sub, scope="app:access agent:use knowledge:read"):
        oidc = UserOIDC(make_token, sub, scope)
        manager = SessionManager(MemorySessionStore(), oidc, idle_ttl=3600, max_ttl=86400)
        app = create_app(settings=settings, verifier=verifier, sessions=manager, oidc=oidc,
                         provider=Provider(directory=orgs), memberships=memberships, group_requests=requests)
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
    assert orgs.members[gid] == {"root": True}                               # its creator is its first admin
    assert r.json()["member"] and r.json()["admin"]
    r = admin.post(f"/auth/groups/{gid}/members", json={"email": "alice@example.org", "admin": True}, headers=SAME_ORIGIN)
    assert r.status_code == 201 and r.json()["members"][0] == {
        "user_id": "alice", "name": "Alice", "email": "alice@example.org", "admin": True}
    assert orgs.members[gid]["alice"] is True
    [g] = alice.get("/auth/groups").json()["groups"]
    assert g["member"] and g["admin"] and g["can_manage"] and g["pending"] == 0
    assert admin.post(f"/auth/groups/{gid}/members", json={"email": "nobody@example.org"},
                      headers=SAME_ORIGIN).status_code == 404


def test_request_approve_and_group_admin_limits(env):
    client, orgs, _ = env
    gid = orgs.create_group("EIC", "")["id"]
    orgs.add_member(gid, "alice", admin=True)
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
    assert r.status_code == 200 and orgs.members[gid]["bob"] is False
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
    gid = orgs.create_group("EIC", "")["id"]
    alice = client("alice")
    alice_token = make_token(sub="alice", preferred_username="alice", email="alice@example.org", name="Alice",
                             scope="app:access agent:use knowledge:read")
    headers = {**fwd("GET", "/api/v1/sessions/1"), "Authorization": f"Bearer {alice_token}"}
    ctx = decode_context(*(alice.get("/verify", headers=headers).headers[h] for h in (HEADER_CONTEXT, HEADER_SIGNATURE)), SECRET)
    assert ctx.organizations == {}

    orgs.add_member(gid, "alice")
    memberships.forget("alice")   # what the group routes do after a change
    ctx = decode_context(*(alice.get("/verify", headers=headers).headers[h] for h in (HEADER_CONTEXT, HEADER_SIGNATURE)), SECRET)
    assert ctx.organizations == {gid: "EIC"} and ctx.managed_organizations == frozenset()
    orgs.add_member(gid, "bob", admin=True)
    bob_headers = {**headers, "Authorization": f"Bearer {make_token(sub='bob', scope='app:access agent:use')}"}
    bob_ctx = decode_context(*(client("bob").get("/verify", headers=bob_headers).headers[h]
                               for h in (HEADER_CONTEXT, HEADER_SIGNATURE)), SECRET)
    assert bob_ctx.managed_organizations == {gid}      # bob administers the group: backends may let him approve for it
    me = alice.get("/whoami", headers={"Authorization": headers["Authorization"]}).json()
    assert me["organizations"] == {gid: "EIC"}
    assert (me["username"], me["name"], me["email"]) == ("alice", "Alice", "alice@example.org")
    assert (ctx.username, ctx.email) == ("alice", "alice@example.org")      # the backends see who it is

    orgs.down = True              # the provider unreachable: the last known groups stay, requests still pass
    memberships.forget("alice")
    assert alice.get("/verify", headers=headers).status_code == 200


def test_memberships_cache_and_failure():
    orgs, now = FakeGroups(), [1000.0]
    gid = orgs.create_group("EIC", "")["id"]
    orgs.add_member(gid, "alice")
    m = Memberships(orgs, ttl=60, clock=lambda: now[0])
    assert m.names("alice") == {gid: "EIC"}
    orgs.remove_member(gid, "alice")
    assert m.names("alice") == {gid: "EIC"}           # cached
    now[0] += 61
    assert m.names("alice") == {}
    orgs.add_member(gid, "alice")
    orgs.down = True
    now[0] += 61
    assert m.names("alice") == {}                     # down: the last known answer
    with pytest.raises(ManagementUnavailableError):
        m.of("alice", fresh=True)                     # permission checks never use a stale answer


def test_profiles_keep_only_what_is_set():
    orgs = FakeGroups()
    orgs.users["dave"] = None
    assert Profiles(orgs).of("dave") == {"username": "dave", "name": "Dave"}
    orgs.down = True
    assert Profiles(orgs).of("alice") == {}            # unknown while the provider is down: nothing shown


def test_profiles_username_falls_back_to_email():
    class NoUsername(FakeGroups):
        def user(self, user_id):
            return {"id": user_id, "email": f"{user_id}@example.org"}
    assert Profiles(NoUsername()).of("erin") == {"username": "erin@example.org", "email": "erin@example.org"}


def test_profiles_looked_up_when_the_token_has_none(settings, verifier, make_token):
    """Logto-like: the access token carries no name; the provider asks authsvc to look it up."""
    orgs = FakeGroups()
    app = create_app(settings=settings, verifier=verifier, provider=Provider(directory=orgs, lookup_profiles=True))
    r = TestClient(app).get("/whoami", headers={"Authorization": f"Bearer {make_token(sub='alice')}"})
    assert (r.json()["username"], r.json()["name"], r.json()["email"]) == ("alice", "Alice", "alice@example.org")
