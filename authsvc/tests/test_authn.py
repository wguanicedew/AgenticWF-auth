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
        verifier.verify("opaque-logto-token")


def test_hs256_confusion_rejected(verifier):
    token = jwt.encode({"iss": "x", "sub": "a", "exp": 9999999999}, "secret", algorithm="HS256", headers={"kid": "k1"})
    with pytest.raises(AuthenticationError):
        verifier.verify(token)


def test_extract_bearer():
    assert extract_bearer(None) is None
    assert extract_bearer("Bearer abc") == "abc"
    with pytest.raises(AuthenticationError):
        extract_bearer("Basic abc")


def test_organization_token_context(verifier, make_token):
    claims = verifier.verify(make_token(aud="urn:logto:organization:org_9", roles=["researcher"]))
    ctx = AuthContext.from_claims(claims)
    assert ctx.organization_id == "org_9"
    assert ctx.roles == {"researcher"}
    assert not ctx.is_machine


def test_machine_token_context(verifier, make_token):
    ctx = AuthContext.from_claims(verifier.verify(make_token(sub="app_1")))
    assert ctx.is_machine and ctx.user_id is None
