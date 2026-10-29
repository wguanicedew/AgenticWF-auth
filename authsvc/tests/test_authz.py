import pytest

from agenticwf.auth.authz import InvalidPathError, Policy, PolicyError, normalize_path
from agenticwf.auth.context import AuthContext

POLICY = Policy.from_dict({"rules": [
    {"path": "/healthz", "public": True},
    {"path": "/api/v1/items/*/meta", "methods": ["GET"], "scopes": ["items:read"]},
    {"path": "/api/v1/compute/**", "methods": ["POST"], "scopes": ["compute:submit"], "organization": True},
    {"path": "/api/v1/admin/**", "roles_any": ["admin"], "allow_machine": False},
]})


def ctx(**kw):
    return AuthContext(subject=kw.pop("subject", "u1"), user_id=kw.pop("user_id", "u1"), **kw)


def test_public_and_default_deny():
    assert POLICY.authorize(None, "GET", "/healthz").allowed
    assert POLICY.authorize(None, "GET", "/unknown").status == 401
    assert POLICY.authorize(ctx(), "GET", "/unknown").status == 403


def test_single_segment_wildcard():
    c = ctx(scopes=frozenset({"items:read"}))
    assert POLICY.authorize(c, "GET", "/api/v1/items/42/meta").allowed
    assert not POLICY.authorize(c, "GET", "/api/v1/items/42/x/meta").allowed
    assert not POLICY.authorize(c, "POST", "/api/v1/items/42/meta").allowed


def test_scopes_and_organization():
    c = ctx(scopes=frozenset({"compute:submit"}))
    assert POLICY.authorize(c, "POST", "/api/v1/compute/jobs").status == 403
    c = ctx(scopes=frozenset({"compute:submit"}), organization_id="org1")
    assert POLICY.authorize(c, "POST", "/api/v1/compute/jobs").allowed
    assert POLICY.authorize(c, "POST", "/api/v1/compute").allowed
    assert not POLICY.authorize(c, "POST", "/api/v1/computex").allowed


def test_roles_and_machine():
    assert POLICY.authorize(ctx(roles=frozenset({"admin"})), "GET", "/api/v1/admin/x").allowed
    assert POLICY.authorize(ctx(), "GET", "/api/v1/admin/x").status == 403
    machine = AuthContext(subject="app", client_id="app", roles=frozenset({"admin"}))
    assert POLICY.authorize(machine, "GET", "/api/v1/admin/x").status == 403


@pytest.mark.parametrize("uri", ["/api/../admin", "/api/%2e%2e/admin", "/api%2fadmin", "/a/./b"])
def test_normalize_rejects_ambiguous_paths(uri):
    with pytest.raises(InvalidPathError):
        normalize_path(uri)


def test_normalize_strips_query_and_slashes():
    assert normalize_path("//api//v1/x?y=1") == "/api/v1/x"


def test_invalid_policy():
    with pytest.raises(PolicyError):
        Policy.from_dict({"rules": [{"path": "/a/**/b"}]})
    with pytest.raises(PolicyError):
        Policy.from_dict({"rules": [{"path": "/a", "scope": ["typo"]}]})
    with pytest.raises(PolicyError):
        Policy.from_dict({"rules": [{"path": "/a", "public": True, "scopes": ["x"]}]})


def test_shipped_policy_loads(settings):
    Policy.load(settings.policy_file)


def test_required_scopes_mark_pending_accounts():
    policy = Policy.from_dict({"required_scopes": ["app:access"], "rules": [
        {"path": "/healthz", "public": True},
        {"path": "/api/v1/me", "allow_pending": True},
        {"path": "/api/**", "scopes": ["items:read"]},
    ]})
    pending = ctx(scopes=frozenset({"items:read"}))
    approved = ctx(scopes=frozenset({"items:read", "app:access"}))
    assert policy.authorize(None, "GET", "/healthz").allowed
    assert policy.authorize(pending, "GET", "/healthz").allowed
    d = policy.authorize(pending, "GET", "/api/x")
    assert (d.status, d.code) == (403, "approval_pending")
    assert policy.authorize(pending, "GET", "/api/v1/me").allowed
    assert policy.authorize(pending, "GET", "/nowhere").code == "approval_pending"
    assert policy.authorize(approved, "GET", "/api/x").allowed
    assert policy.authorize(approved, "GET", "/nowhere").code == "insufficient_scope"
    assert policy.authorize(None, "GET", "/api/x").code == "missing_token"


def test_policy_rejects_bad_top_level_keys():
    with pytest.raises(PolicyError):
        Policy.from_dict({"required_scope": ["typo"], "rules": []})
    with pytest.raises(PolicyError):
        Policy.from_dict({"required_scopes": "app:access", "rules": []})
