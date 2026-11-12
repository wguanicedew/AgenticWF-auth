import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from agenticwf.auth.authn import AuthenticationError, extract_bearer
from agenticwf.auth.context import AuthContext


def test_valid_token(verifier, make_token):
    claims = verifier.verify(make_token())
    assert claims["sub"] == "user_1"


@pytest.mark.parametrize(
    "overrides",
    [
        {"exp": int(time.time()) - 3600},
        {"iss": "https://evil.example.com/oidc"},
        {"aud": "https://other-api.example.com"},
        {"exp": None},
    ],
)
def test_rejected_claims(verifier, make_token, overrides):
    with pytest.raises(AuthenticationError):
        verifier.verify(make_token(**overrides))


def test_wrong_signing_key(verifier, make_token):
    other = ec.generate_private_key(ec.SECP384R1())
    with pytest.raises(AuthenticationError):
        verifier.verify(make_token(key=other))


def test_unknown_kid_and_opaque_token(verifier, make_token):
    with pytest.raises(AuthenticationError):
        verifier.verify(make_token(kid="nope"))
    with pytest.raises(AuthenticationError):
        verifier.verify("opaque-token")


def test_hs256_confusion_rejected(verifier):
    token = jwt.encode({"iss": "x", "sub": "a", "exp": 9999999999}, "secret", algorithm="HS256", headers={"kid": "k1"})
    with pytest.raises(AuthenticationError):
        verifier.verify(token)


def test_extract_bearer():
    assert extract_bearer(None) is None
    assert extract_bearer("Bearer abc") == "abc"
    with pytest.raises(AuthenticationError):
        extract_bearer("Basic abc")


def test_user_token_context(verifier, make_token):
    ctx = verifier.context(make_token(roles=["researcher"], organization_id="org_9", preferred_username="alice",
                                      name="Alice", email="alice@example.org"))
    assert ctx.organization_id == "org_9" and ctx.roles == {"researcher"}
    assert ctx.scopes == {"app:access", "dataset:read", "knowledge:read"}
    assert (ctx.username, ctx.name, ctx.email) == ("alice", "Alice", "alice@example.org")
    assert ctx.client_id == "app_1" and not ctx.is_machine


def test_username_falls_back_to_email(verifier, make_token):
    assert verifier.context(make_token(email="bob@example.org")).username == "bob@example.org"


def test_machine_token_context(verifier, make_token):
    ctx = verifier.context(make_token(sub="app_1"))     # client credentials: sub is the client
    assert ctx.is_machine and ctx.user_id is None and ctx.username is None


def test_dotted_roles_claim():
    ctx = AuthContext.from_claims({"sub": "u", "realm_access": {"roles": ["x"]}}, roles_claim="realm_access.roles")
    assert ctx.roles == {"x"}


def test_provider_hooks(settings, private_key, make_token):
    from tests.conftest import FakeJWKS
    from agenticwf.auth.authn import TokenVerifier

    def check(claims):
        if claims.get("typ") == "ID":
            raise AuthenticationError("invalid_token", "Not an access token")

    jwks = FakeJWKS()
    jwks.add("k1", private_key)
    verifier = TokenVerifier(settings, jwks_client=jwks, check_claims=check,
                             claims=lambda c: AuthContext(subject=c["sub"], user_id=c["sub"], scopes=frozenset({"mapped"})))
    assert verifier.context(make_token()).scopes == {"mapped"}
    with pytest.raises(AuthenticationError):
        verifier.verify(make_token(typ="ID"))
