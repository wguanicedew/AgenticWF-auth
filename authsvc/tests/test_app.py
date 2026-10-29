from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from agenticwf.auth.app import create_app
from agenticwf.auth.client import AuthContextMiddleware, current_auth_context, require_scopes
from agenticwf.auth.context import decode_context
from tests.conftest import SECRET


def fwd(method, uri, token=None, **extra):
    headers = {"X-Forwarded-Method": method, "X-Forwarded-Uri": uri, **extra}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def client(settings, verifier):
    return TestClient(create_app(settings=settings, verifier=verifier))


def test_verify_allows_and_emits_context(settings, verifier, make_token):
    r = client(settings, verifier).get("/verify", headers=fwd("GET", "/api/v1/datasets/abc?x=1", make_token()))
    assert r.status_code == 200
    assert r.headers["X-Auth-User-Id"] == "user_1"
    ctx = decode_context(r.headers["X-Auth-Context"], r.headers["X-Auth-Context-Sig"], SECRET,
                         method="GET", path="/api/v1/datasets/abc")
    assert "dataset:read" in ctx.scopes


def test_verify_status_codes(settings, verifier, make_token):
    c = client(settings, verifier)
    r = c.get("/verify", headers=fwd("GET", "/api/v1/datasets/abc"))
    assert r.status_code == 401 and r.headers["WWW-Authenticate"].startswith("Bearer")
    assert c.get("/verify", headers=fwd("GET", "/api/v1/datasets/abc", "garbage")).status_code == 401
    assert c.get("/verify", headers=fwd("POST", "/api/v1/datasets/abc", make_token())).status_code == 403
    assert c.get("/verify", headers=fwd("GET", "/api/../admin", make_token())).status_code == 400


def test_public_route_ignores_bad_token(settings, verifier):
    r = client(settings, verifier).get("/verify", headers=fwd("GET", "/healthz", "garbage"))
    assert r.status_code == 200 and "X-Auth-Context" not in r.headers


def test_whoami(settings, verifier, make_token):
    r = client(settings, verifier).get("/whoami", headers={"Authorization": f"Bearer {make_token()}"})
    assert r.status_code == 200 and r.json()["user_id"] == "user_1"


def _backend():
    app = FastAPI()
    app.add_middleware(AuthContextMiddleware, secret=SECRET)

    @app.get("/api/v1/datasets/{name}")
    def get(name: str, ctx=Depends(require_scopes("dataset:read"))):
        # sync handler runs in a threadpool: the ContextVar must still be visible
        return {"subject": current_auth_context().subject}

    return TestClient(app)


def test_end_to_end_propagation(settings, verifier, make_token):
    r = client(settings, verifier).get("/verify", headers=fwd("GET", "/api/v1/datasets/abc", make_token()))
    copied = {k: r.headers[k] for k in ("X-Auth-Context", "X-Auth-Context-Sig")}
    backend = _backend()
    assert backend.get("/api/v1/datasets/abc", headers=copied).json() == {"subject": "user_1"}
    # replay against a different path, forged header, or no header at all
    assert backend.get("/api/v1/datasets/other", headers=copied).status_code == 401
    forged = {**copied, "X-Auth-Context-Sig": "AAAA"}
    assert backend.get("/api/v1/datasets/abc", headers=forged).status_code == 401
    assert backend.get("/api/v1/datasets/abc").status_code == 401
