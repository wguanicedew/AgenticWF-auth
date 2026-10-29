import time
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from agenticwf.auth.app import create_app
from agenticwf.auth.oidc import OIDCError, TokenSet
from agenticwf.auth.sessions import MemorySessionStore, SessionManager
from agenticwf.auth.web import LOGIN_COOKIE, SESSION_COOKIE, safe_return_to

APP = "https://app.example.org"
CLIENT_ID = "web_app"


class FakeLogto:
    def __init__(self, make_token):
        self.make_token = make_token
        self.nonce = None
        self.refresh_calls = 0
        self.refresh_fails = False
        self.revoked = []
        self.scope = "app:access agent:use knowledge:read"

    def authorization_url(self, state, nonce, code_challenge):
        self.nonce = nonce
        return f"https://auth.example.org/oidc/auth?state={state}&nonce={nonce}&code_challenge={code_challenge}"

    def end_session_url(self, id_token_hint):
        return "https://auth.example.org/oidc/session/end"

    def _tokens(self, rt, scope=None):
        return TokenSet(
            access_token=self.make_token(scope=scope or self.scope),
            expires_at=int(time.time()) + 3600,
            refresh_token=rt,
            id_token=self.make_token(aud=CLIENT_ID, nonce=self.nonce, name="Alice"),
        )

    def exchange_code(self, code, code_verifier):
        assert code == "good-code"
        self.granted = self.scope  # Logto: the grant holds the scopes the roles allow now
        return self._tokens("rt-1")

    def refresh(self, refresh_token):
        self.refresh_calls += 1
        if self.refresh_fails:
            raise OIDCError("invalid_grant")
        # Logto: a refresh can only narrow the granted scopes, never add new ones
        narrowed = " ".join(sorted(set(self.granted.split()) & set(self.scope.split())))
        return self._tokens(f"rt-{self.refresh_calls + 1}", scope=narrowed)

    def revoke(self, token, hint="refresh_token"):
        self.revoked.append(token)


@pytest.fixture
def env(settings, verifier, make_token):
    settings = replace(settings, web_client_id=CLIENT_ID, web_client_secret="x", app_origin=APP,
                       logto_endpoint="https://auth.example.org")
    logto = FakeLogto(make_token)
    store = MemorySessionStore()
    manager = SessionManager(store, logto, idle_ttl=3600, max_ttl=86400)
    app = create_app(settings=settings, verifier=verifier, sessions=manager, logto=logto)
    client = TestClient(app, base_url=APP, follow_redirects=False)
    return client, logto, store


def login(client):
    r = client.get("/auth/login", params={"return_to": "/chat?x=1"})
    assert r.status_code == 302 and LOGIN_COOKIE in r.cookies
    state = parse_qs(urlsplit(r.headers["location"]).query)["state"][0]
    r = client.get("/auth/callback", params={"code": "good-code", "state": state})
    assert r.status_code == 303 and r.headers["location"] == "/chat?x=1"
    assert SESSION_COOKIE in r.cookies
    return r


def fwd(method, uri, **headers):
    return {"X-Forwarded-Method": method, "X-Forwarded-Uri": uri, **headers}


def test_login_and_cookie_auth(env):
    client, _, _ = env
    login(client)
    r = client.get("/verify", headers=fwd("GET", "/api/v1/sessions/1"))
    assert r.status_code == 200 and r.headers["X-Auth-Method"] == "session"
    info = client.get("/auth/session").json()
    assert info["authenticated"] and info["user"]["name"] == "Alice"
    assert "agent:use" in info["scopes"]
    assert info["account_url"] is None


def test_session_reports_account_url(settings, verifier, make_token):
    settings = replace(settings, web_client_id=CLIENT_ID, web_client_secret="x", app_origin=APP,
                       logto_endpoint="https://auth.example.org", account_url="https://auth.example.org/account")
    logto = FakeLogto(make_token)
    manager = SessionManager(MemorySessionStore(), logto, idle_ttl=3600, max_ttl=86400)
    client = TestClient(create_app(settings=settings, verifier=verifier, sessions=manager, logto=logto),
                        base_url=APP, follow_redirects=False)
    login(client)
    assert client.get("/auth/session").json()["account_url"] == "https://auth.example.org/account"


def test_callback_rejects_bad_state(env):
    client, _, _ = env
    client.get("/auth/login")
    assert client.get("/auth/callback", params={"code": "good-code", "state": "forged"}).status_code == 400


def test_csrf_origin_checks(env):
    client, _, _ = env
    login(client)
    assert client.post("/verify", headers=fwd("POST", "/api/v1/sessions/1", Origin="https://evil.example")).status_code == 403
    assert client.post("/verify", headers=fwd("POST", "/api/v1/sessions/1")).status_code == 403  # no origin
    assert client.post("/verify", headers=fwd("POST", "/api/v1/sessions/1", Origin=APP)).status_code == 200
    ws = fwd("GET", "/api/v1/sessions/1/ws", **{"X-Forwarded-Upgrade": "websocket"}, Origin="https://evil.example")
    assert client.get("/verify", headers=ws).status_code == 403


def test_bearer_takes_precedence_over_cookie(env, make_token):
    client, _, _ = env
    login(client)
    r = client.get("/verify", headers=fwd("GET", "/api/v1/sessions/1", Authorization="Bearer garbage"))
    assert r.status_code == 401


def test_transparent_refresh(env):
    client, logto, store = env
    login(client)
    (id_hash,) = store._data
    store._data[id_hash] = replace(store._data[id_hash], access_expires_at=int(time.time()) + 5)
    assert client.get("/verify", headers=fwd("GET", "/api/v1/sessions/1")).status_code == 200
    assert logto.refresh_calls == 1 and store._data[id_hash].refresh_token == "rt-2"


def test_failed_refresh_ends_session(env):
    client, logto, store = env
    login(client)
    (id_hash,) = store._data
    store._data[id_hash] = replace(store._data[id_hash], access_expires_at=int(time.time()) - 5)
    logto.refresh_fails = True
    r = client.get("/verify", headers=fwd("GET", "/api/v1/sessions/1", Accept="text/html"))
    assert r.status_code == 302 and r.headers["location"].startswith("/auth/login?return_to=")
    assert not store._data


def test_api_call_without_credentials_gets_401_not_redirect(env):
    client, _, _ = env
    r = client.get("/verify", headers=fwd("GET", "/api/v1/sessions/1", Accept="application/json"))
    assert r.status_code == 401


def test_logout(env):
    client, logto, store = env
    login(client)
    assert client.post("/auth/logout", headers={"Origin": "https://evil.example"}).status_code == 403
    r = client.post("/auth/logout", headers={"Origin": APP})
    assert r.status_code == 303 and not store._data and logto.revoked == ["rt-1"]
    assert client.get("/auth/session").json()["authenticated"] is False


@pytest.mark.parametrize("value,expected", [
    ("/chat", "/chat"), (None, "/"), ("https://evil.com", "/"), ("//evil.com", "/"),
    ("/\\evil.com", "/"), ("/\t/evil.com", "/"), ("/auth/logout", "/"), ("/a/../b", "/"),
])
def test_safe_return_to(value, expected):
    assert safe_return_to(value) == expected


@pytest.mark.parametrize("value,expected", [
    ("/app/chat?x=1", "/app/chat?x=1"), ("/app", "/app"), ("/oidc/auth", "/app/"),
    ("/application", "/app/"), ("/app/../oidc", "/app/"), ("/app/%2e%2e/oidc", "/app/"),
    ("/app/auth/login", "/app/"), (None, "/app/"),
])
def test_safe_return_to_with_base_path(value, expected):
    assert safe_return_to(value, "/app") == expected


@pytest.fixture
def single_host(settings, verifier, make_token):
    """One hostname: Logto at '/', application under '/app' (Caddy strips the prefix)."""
    settings = replace(settings, web_client_id=CLIENT_ID, web_client_secret="x",
                       app_origin="https://host.example.org", app_base_path="/app",
                       logto_endpoint="https://host.example.org")
    logto = FakeLogto(make_token)
    manager = SessionManager(MemorySessionStore(), logto, idle_ttl=3600, max_ttl=86400)
    app = create_app(settings=settings, verifier=verifier, sessions=manager, logto=logto)
    return TestClient(app, base_url="https://host.example.org", follow_redirects=False), settings


def test_single_host_base_path(single_host):
    client, settings = single_host
    # page load without session: stripped URI "/" -> redirect keeps the /app prefix
    r = client.get("/verify", headers=fwd("GET", "/", Accept="text/html"))
    assert r.headers["location"] == "/app/auth/login?return_to=%2Fapp%2F"
    # Caddy strips /app, so authsvc serves /auth/login; return_to arrives with the prefix
    r = client.get("/auth/login", params={"return_to": "/app/chat"})
    state = parse_qs(urlsplit(r.headers["location"]).query)["state"][0]
    r = client.get("/auth/callback", params={"code": "good-code", "state": state})
    assert r.headers["location"] == "/app/chat"
    assert client.get("/verify", headers=fwd("GET", "/api/v1/sessions/1")).status_code == 200
    assert client.get("/auth/session").json()["authenticated"]


def test_single_host_redirect_uris(settings):
    from agenticwf.auth.oidc import LogtoClient

    s = replace(settings, web_client_id=CLIENT_ID, web_client_secret="x", app_origin="https://host.example.org",
                app_base_path="/app", logto_endpoint="https://host.example.org")
    client = LogtoClient(s)
    assert client.redirect_uri == "https://host.example.org/app/auth/callback"
    assert "post_logout_redirect_uri=https%3A%2F%2Fhost.example.org%2Fapp%2F" in client.end_session_url(None)


def test_pending_user_sees_approval_page_then_recheck(env):
    client, logto, store = env
    logto.scope = "agent:use"                      # registered, but no role carrying app:access
    login(client)
    assert client.get("/auth/session").json()["approved"] is False

    page = client.get("/verify", headers=fwd("GET", "/", Accept="text/html"))
    assert page.status_code == 403 and "awaiting approval" in page.text
    assert "/auth/recheck?return_to=%2F" in page.text

    api = client.get("/verify", headers=fwd("GET", "/api/v1/sessions/1", Accept="application/json"))
    assert api.status_code == 403 and api.json()["error"] == "approval_pending"
    # allow_pending route still works, e.g. "whoami"
    assert client.get("/verify", headers=fwd("GET", "/api/v1/me")).status_code == 200

    # admin assigns a role -> "Check again": the refresh cannot add app:access, so the user
    # is sent through login again (silent at Logto), which grants the current roles
    logto.scope = "app:access agent:use"
    r = client.get("/auth/recheck", params={"return_to": "/"})
    assert logto.refresh_calls == 1
    assert r.status_code == 302 and r.headers["location"] == "/auth/login?return_to=%2F"
    (old_hash,) = store._data
    r = client.get("/auth/login", params={"return_to": "/"})
    state = parse_qs(urlsplit(r.headers["location"]).query)["state"][0]
    r = client.get("/auth/callback", params={"code": "good-code", "state": state})
    assert r.headers["location"] == "/"
    assert old_hash not in store._data and len(store._data) == 1   # previous session replaced
    assert client.get("/auth/session").json()["approved"] is True
    assert client.get("/verify", headers=fwd("GET", "/api/v1/sessions/1")).status_code == 200

    # once approved, "Check again" is a plain refresh and goes straight back
    r = client.get("/auth/recheck", params={"return_to": "/"})
    assert r.status_code == 303 and r.headers["location"] == "/"


def test_recheck_without_session_goes_to_login(env):
    client, _, _ = env
    r = client.get("/auth/recheck", params={"return_to": "/chat"})
    assert r.status_code == 302 and r.headers["location"] == "/auth/login?return_to=%2Fchat"


def test_pending_page_escapes_user_and_keeps_base_path():
    from agenticwf.auth.web import pending_page

    page = pending_page("/app", "/chat?x=1", "<script>alert(1)</script>").body.decode()
    assert "<script>alert(1)" not in page and "&lt;script&gt;" in page
    assert "/app/auth/recheck?return_to=%2Fapp%2Fchat%3Fx%3D1" in page
    assert 'action="/app/auth/logout"' in page
