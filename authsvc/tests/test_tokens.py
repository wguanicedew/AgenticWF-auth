import time
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from agenticwf.auth.app import create_app
from agenticwf.auth.sessions import MemorySessionStore, SessionManager
from agenticwf.auth.tokens import ManagementError

from .test_web import APP, CLIENT_ID, FakeLogto, login


class FakeManagement:
    def __init__(self):
        self.tokens = {}  # (user, name) -> token

    def list(self, user_id):
        return [t for (u, _), t in self.tokens.items() if u == user_id]

    def create(self, user_id, name, expires_at):
        if (user_id, name) in self.tokens:
            raise ManagementError(409, "A token with this name already exists.")
        token = {"userId": user_id, "name": name, "value": f"pat_{name}", "createdAt": int(time.time() * 1000),
                 "expiresAt": expires_at * 1000 if expires_at else None}
        self.tokens[(user_id, name)] = token
        return token

    def delete(self, user_id, name):
        if self.tokens.pop((user_id, name), None) is None:
            raise ManagementError(404, "No such token.")


@pytest.fixture
def env(settings, verifier, make_token):
    settings = replace(settings, web_client_id=CLIENT_ID, web_client_secret="x", app_origin=APP,
                       logto_endpoint="https://auth.example.org", cli_client_id="cli_app", pat_max_days=90)
    logto = FakeLogto(make_token)
    manager = SessionManager(MemorySessionStore(), logto, idle_ttl=3600, max_ttl=86400)
    mgmt = FakeManagement()
    app = create_app(settings=settings, verifier=verifier, sessions=manager, logto=logto, management=mgmt)
    return TestClient(app, base_url=APP, follow_redirects=False), logto, mgmt


SAME_ORIGIN = {"Origin": APP}


def test_create_list_delete(env):
    client, _, mgmt = env
    login(client)
    r = client.post("/auth/tokens", json={"name": "laptop", "expires_in_days": 30}, headers=SAME_ORIGIN)
    assert r.status_code == 201
    assert r.json()["token"] == "pat_laptop" and r.json()["expires_at"] > time.time() + 29 * 86400

    r = client.get("/auth/tokens")
    body = r.json()
    assert [t["name"] for t in body["tokens"]] == ["laptop"]
    assert "token" not in body["tokens"][0] and "value" not in body["tokens"][0]
    assert body["cli"] == {"auth_url": "https://auth.example.org", "api_url": APP, "client_id": "cli_app",
                           "resource": "https://api.example.com"}
    assert r.headers["cache-control"] == "no-store"

    assert client.delete("/auth/tokens/laptop", headers=SAME_ORIGIN).status_code == 204
    assert mgmt.tokens == {}
    assert client.delete("/auth/tokens/laptop", headers=SAME_ORIGIN).status_code == 404


def test_tokens_are_per_user(env):
    client, _, mgmt = env
    mgmt.create("someone_else", "theirs", None)
    login(client)
    assert client.get("/auth/tokens").json()["tokens"] == []
    assert client.delete("/auth/tokens/theirs", headers=SAME_ORIGIN).status_code == 404


def test_requires_session_not_bearer(env, make_token):
    client, _, _ = env
    r = client.get("/auth/tokens", headers={"Authorization": f"Bearer {make_token()}"})
    assert r.status_code == 401


def test_rejects_cross_origin(env):
    client, _, mgmt = env
    login(client)
    r = client.post("/auth/tokens", json={"name": "x", "expires_in_days": 1}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403 and mgmt.tokens == {}
    r = client.post("/auth/tokens", json={"name": "x", "expires_in_days": 1})  # no Origin/Referer
    assert r.status_code == 403


def test_pending_account_cannot_create(env):
    client, logto, mgmt = env
    logto.scope = "agent:use"  # no app:access: not approved
    login(client)
    r = client.post("/auth/tokens", json={"name": "x", "expires_in_days": 1}, headers=SAME_ORIGIN)
    assert r.status_code == 403 and r.json()["error"] == "approval_pending" and mgmt.tokens == {}


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
    client, _, _ = env
    login(client)
    assert client.post("/auth/tokens", json=body, headers=SAME_ORIGIN).status_code == 400


def test_duplicate_name(env):
    client, _, _ = env
    login(client)
    client.post("/auth/tokens", json={"name": "ci", "expires_in_days": 1}, headers=SAME_ORIGIN)
    assert client.post("/auth/tokens", json={"name": "ci", "expires_in_days": 1}, headers=SAME_ORIGIN).status_code == 409


def test_disabled_without_management(settings, verifier, make_token):
    settings = replace(settings, web_client_id=CLIENT_ID, web_client_secret="x", app_origin=APP,
                       logto_endpoint="https://auth.example.org")
    logto = FakeLogto(make_token)
    manager = SessionManager(MemorySessionStore(), logto, idle_ttl=3600, max_ttl=86400)
    client = TestClient(create_app(settings=settings, verifier=verifier, sessions=manager, logto=logto), base_url=APP)
    assert client.get("/auth/tokens").status_code == 404


def test_management_client_calls_logto(settings):
    import httpx

    from agenticwf.auth.tokens import ManagementClient

    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.raw_path.decode(), request.headers.get("authorization"), request.content))
        if request.url.path == "/oidc/token":
            assert b"resource=https%3A%2F%2Fdefault.logto.app%2Fapi" in request.content and b"scope=all" in request.content
            return httpx.Response(200, json={"access_token": "mgmt", "expires_in": 3600})
        if request.method == "POST":
            return httpx.Response(201, json={"name": "ci", "value": "pat_x", "createdAt": 1_000_000, "expiresAt": 2_000_000})
        if request.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(200, json=[])

    settings = replace(settings, mgmt_client_id="m2m", mgmt_client_secret="s", logto_endpoint="https://auth.example.org")
    client = ManagementClient(settings, http=httpx.Client(base_url="http://logto", transport=httpx.MockTransport(handler)))
    assert client.create("u/1", "ci", 2000)["value"] == "pat_x"
    client.list("u/1")
    client.delete("u/1", "my token")
    paths = [(m, p) for m, p, _, _ in calls]
    assert paths == [("POST", "/oidc/token"), ("POST", "/api/users/u%2F1/personal-access-tokens"),
                     ("GET", "/api/users/u%2F1/personal-access-tokens"),
                     ("DELETE", "/api/users/u%2F1/personal-access-tokens/my%20token")]  # one M2M token, reused
    assert calls[1][2] == "Bearer mgmt" and b'"expiresAt":2000000' in calls[1][3]
