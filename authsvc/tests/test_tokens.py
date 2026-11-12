import time
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from agenticwf.auth.app import create_app
from agenticwf.auth.context import HEADER_CONTEXT, HEADER_SIGNATURE, decode_context
from agenticwf.auth.directory import ManagementError, ManagementUnavailableError
from agenticwf.auth.pats import LocalTokens, MemoryTokenStore, hash_token
from agenticwf.auth.provider import Provider
from agenticwf.auth.sessions import MemorySessionStore, SessionManager

from .conftest import SECRET
from .test_web import APP, CLIENT_ID, FakeOIDC, fwd, login


class FakeAdmin:
    """The provider's `grants` (who the user is, their effective roles) and a directory."""

    def __init__(self):
        self.permissions = ["app:access", "agent:use", "knowledge:read"]
        self.roles = ["researcher"]
        self.enabled = True
        self.deleted = False
        self.down = False
        self.calls = 0

    def user_grants(self, user_id):
        self.calls += 1
        if self.down:
            raise ManagementUnavailableError("down")
        if self.deleted:
            raise ManagementError(404, "reading the user: not found.")
        return {"user": {"id": user_id, "username": "user1", "name": "User One", "email": "user1@example.org",
                         "enabled": self.enabled},
                "roles": list(self.roles), "permissions": list(self.permissions)}

    def user_groups(self, user_id):
        return []


@pytest.fixture
def env(settings, verifier, make_token):
    settings = replace(settings, web_client_id=CLIENT_ID, web_client_secret="x", app_origin=APP,
                       cli_client_id="agenticwf-cli", pat_max_days=90, group_cache_ttl=60, session_store="memory")
    oidc = FakeOIDC(make_token)
    manager = SessionManager(MemorySessionStore(), oidc, idle_ttl=3600, max_ttl=86400)
    admin = FakeAdmin()
    now = [time.time()]
    pats = LocalTokens(MemoryTokenStore(), admin.user_grants, settings, clock=lambda: now[0])
    app = create_app(settings=settings, verifier=verifier, sessions=manager, oidc=oidc,
                     provider=Provider(directory=admin, tokens=pats))
    return TestClient(app, base_url=APP, follow_redirects=False), oidc, admin, pats, now


SAME_ORIGIN = {"Origin": APP}


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_create_list_delete(env):
    client, _, _, pats, _ = env
    login(client)
    r = client.post("/auth/tokens", json={"name": "laptop", "expires_in_days": 30}, headers=SAME_ORIGIN)
    assert r.status_code == 201
    raw = r.json()["token"]
    assert raw.startswith("pat_") and r.json()["expires_at"] > time.time() + 29 * 86400
    stored = pats.store.list("user_1")
    assert [t.name for t in stored] == ["laptop"] and stored[0].id_hash == hash_token(raw)   # only the hash

    r = client.get("/auth/tokens")
    body = r.json()
    assert [t["name"] for t in body["tokens"]] == ["laptop"]
    assert "token" not in body["tokens"][0]
    assert body["cli"] == {"auth_url": "https://auth.example.com/oidc", "api_url": APP, "client_id": "agenticwf-cli"}
    assert r.headers["cache-control"] == "no-store"

    assert client.delete("/auth/tokens/laptop", headers=SAME_ORIGIN).status_code == 204
    assert pats.store.list("user_1") == []
    assert client.delete("/auth/tokens/laptop", headers=SAME_ORIGIN).status_code == 404


def test_pat_authenticates_with_current_roles(env):
    client, _, admin, pats, now = env
    raw, _ = pats.issue("user_1", "ci", int(now[0]) + 86400)
    r = client.get("/verify", headers={**fwd("GET", "/api/v1/sessions/1"), **bearer(raw)})
    assert r.status_code == 200 and r.headers["X-Auth-Method"] == "bearer"
    ctx = decode_context(r.headers[HEADER_CONTEXT], r.headers[HEADER_SIGNATURE], SECRET)
    assert ctx.user_id == "user_1" and not ctx.is_machine and ctx.client_id == "agenticwf-cli"
    assert "agent:use" in ctx.scopes and ctx.roles == {"researcher"}
    assert (ctx.username, ctx.email) == ("user1", "user1@example.org")
    assert ctx.expires_at <= now[0] + 300                      # streams come back through /verify

    # roles are cached; after the TTL, removed permissions apply
    admin.permissions = ["agent:use"]
    assert client.get("/verify", headers={**fwd("GET", "/api/v1/sessions/1"), **bearer(raw)}).status_code == 200
    now[0] += 61
    r = client.get("/verify", headers={**fwd("GET", "/api/v1/sessions/1", Accept="application/json"), **bearer(raw)})
    assert r.status_code == 403 and r.json()["error"] == "approval_pending"


def test_pat_rejected_when_revoked_expired_or_disabled(env):
    client, _, admin, pats, now = env
    get = lambda raw: client.get("/verify", headers={**fwd("GET", "/api/v1/sessions/1"), **bearer(raw)})
    assert get("pat_unknown").status_code == 401
    raw, _ = pats.issue("user_1", "old", int(now[0]) + 10)
    assert get(raw).status_code == 200
    now[0] += 11
    assert get(raw).status_code == 401                          # expired

    raw, _ = pats.issue("user_1", "ci", int(now[0]) + 86400)
    admin.enabled = False
    now[0] += 61
    assert get(raw).status_code == 401                          # account disabled at the provider
    admin.enabled, admin.deleted = True, True
    now[0] += 61
    assert get(raw).status_code == 401                          # user deleted

    admin.deleted = False
    pats.store.remove("user_1", "ci")
    assert get(raw).status_code == 401                          # revoked


def test_pat_fails_closed_when_the_provider_is_down(env):
    client, _, admin, pats, now = env
    raw, _ = pats.issue("user_1", "ci", int(now[0]) + 86400)
    admin.down = True
    assert client.get("/verify", headers={**fwd("GET", "/api/v1/sessions/1"), **bearer(raw)}).status_code == 503
    admin.down = False
    assert client.get("/verify", headers={**fwd("GET", "/api/v1/sessions/1"), **bearer(raw)}).status_code == 200
    admin.down = True
    now[0] += 61                    # known before: the last known roles stay
    assert client.get("/verify", headers={**fwd("GET", "/api/v1/sessions/1"), **bearer(raw)}).status_code == 200


def test_tokens_are_per_user(env):
    client, _, _, pats, now = env
    pats.issue("someone_else", "theirs", int(now[0]) + 86400)
    login(client)
    assert client.get("/auth/tokens").json()["tokens"] == []
    assert client.delete("/auth/tokens/theirs", headers=SAME_ORIGIN).status_code == 404


def test_requires_session_not_bearer(env, make_token):
    client, _, _, pats, now = env
    assert client.get("/auth/tokens", headers=bearer(make_token())).status_code == 401
    raw, _ = pats.issue("user_1", "ci", int(now[0]) + 86400)
    assert client.get("/auth/tokens", headers=bearer(raw)).status_code == 401      # a PAT cannot mint PATs


def test_rejects_cross_origin(env):
    client, _, _, pats, _ = env
    login(client)
    r = client.post("/auth/tokens", json={"name": "x", "expires_in_days": 1}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403 and pats.store.list("user_1") == []
    r = client.post("/auth/tokens", json={"name": "x", "expires_in_days": 1})  # no Origin/Referer
    assert r.status_code == 403


def test_pending_account_cannot_create(env):
    client, oidc, _, pats, _ = env
    oidc.scope = "agent:use"  # no app:access: not approved
    login(client)
    r = client.post("/auth/tokens", json={"name": "x", "expires_in_days": 1}, headers=SAME_ORIGIN)
    assert r.status_code == 403 and r.json()["error"] == "approval_pending" and pats.store.list("user_1") == []


@pytest.mark.parametrize("body", [
    {"name": "", "expires_in_days": 1},
    {"name": "a/b", "expires_in_days": 1},
    {"name": "x" * 65, "expires_in_days": 1},
    {"name": "ok", "expires_in_days": 0},
    {"name": "ok", "expires_in_days": 91},
    {"name": "ok", "expires_in_days": None},
    {"name": "ok", "expires_in_days": True},
])
def test_validates_input(env, body):
    client, *_ = env
    login(client)
    assert client.post("/auth/tokens", json=body, headers=SAME_ORIGIN).status_code == 400


def test_duplicate_name(env):
    client, *_ = env
    login(client)
    client.post("/auth/tokens", json={"name": "ci", "expires_in_days": 1}, headers=SAME_ORIGIN)
    assert client.post("/auth/tokens", json={"name": "ci", "expires_in_days": 1}, headers=SAME_ORIGIN).status_code == 409


def test_disabled_without_management(settings, verifier, make_token):
    settings = replace(settings, web_client_id=CLIENT_ID, web_client_secret="x", app_origin=APP)
    oidc = FakeOIDC(make_token)
    manager = SessionManager(MemorySessionStore(), oidc, idle_ttl=3600, max_ttl=86400)
    client = TestClient(create_app(settings=settings, verifier=verifier, sessions=manager, oidc=oidc), base_url=APP)
    assert client.get("/auth/tokens").status_code == 404     # the provider offers no tokens
    r = client.get("/verify", headers={**fwd("GET", "/api/v1/sessions/1"), **bearer("pat_x")})
    assert r.status_code == 401


class ExchangedTokens:
    """A provider that keeps PATs itself and lets the CLI exchange them (Logto)."""

    accepts_bearer = False

    def __init__(self):
        self.tokens = {}

    def list(self, user_id):
        return [v for (u, _), v in self.tokens.items() if u == user_id]

    def create(self, user_id, name, expires_at):
        if (user_id, name) in self.tokens:
            raise ManagementError(409, "A token with this name already exists.")
        self.tokens[(user_id, name)] = {"name": name, "created_at": int(time.time()), "expires_at": expires_at}
        return f"pat_{name}", self.tokens[(user_id, name)]

    def delete(self, user_id, name):
        if self.tokens.pop((user_id, name), None) is None:
            raise ManagementError(404, "No such token.")

    def resolve(self, raw):
        raise AssertionError("never called: accepts_bearer is False")


def test_exchanged_tokens(settings, verifier, make_token):
    settings = replace(settings, web_client_id=CLIENT_ID, web_client_secret="x", app_origin=APP)
    oidc = FakeOIDC(make_token)
    backend = ExchangedTokens()
    client = TestClient(create_app(settings=settings, verifier=verifier, oidc=oidc,
                                   sessions=SessionManager(MemorySessionStore(), oidc, idle_ttl=3600, max_ttl=86400),
                                   provider=Provider(tokens=backend, client_config={"pat_token_type": "urn:x"})),
                        base_url=APP, follow_redirects=False)
    login(client)
    r = client.post("/auth/tokens", json={"name": "ci", "expires_in_days": 1}, headers=SAME_ORIGIN)
    assert r.status_code == 201 and r.json()["token"] == "pat_ci"
    assert client.post("/auth/tokens", json={"name": "ci", "expires_in_days": 1}, headers=SAME_ORIGIN).status_code == 409
    assert client.get("/auth/tokens").json()["cli"]["pat_token_type"] == "urn:x"
    # /verify never takes the PAT itself: it is no JWT
    assert client.get("/verify", headers={**fwd("GET", "/api/v1/sessions/1"), **bearer("pat_ci")}).status_code == 401
    assert client.delete("/auth/tokens/ci", headers=SAME_ORIGIN).status_code == 204
