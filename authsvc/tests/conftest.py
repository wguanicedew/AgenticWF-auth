import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from agenticwf.auth.authn import TokenVerifier
from agenticwf.auth.config import Settings

ISSUER = "https://auth.example.com/oidc"
AUDIENCE = "https://api.example.com"
SECRET = b"s" * 48
POLICY_FILE = Path(__file__).resolve().parents[2] / "container" / "config" / "policy.yaml"


class _Key:
    def __init__(self, key):
        self.key = key


class FakeJWKS:
    """Stands in for PyJWKClient: resolves `kid` to an in-memory public key."""

    def __init__(self):
        self.keys = {}

    def add(self, kid, private_key):
        self.keys[kid] = private_key.public_key()

    def get_signing_key_from_jwt(self, token):
        kid = jwt.get_unverified_header(token).get("kid")
        if kid not in self.keys:
            raise jwt.PyJWKClientError(f"Unable to find a signing key that matches: {kid}")
        return _Key(self.keys[kid])


@pytest.fixture
def private_key():
    return ec.generate_private_key(ec.SECP384R1())


@pytest.fixture
def settings():
    return Settings(issuer=ISSUER, jwks_uri="unused", audiences=(AUDIENCE, "urn:logto:organization:*"),
                    policy_file=POLICY_FILE, context_secret=SECRET)


@pytest.fixture
def verifier(settings, private_key):
    jwks = FakeJWKS()
    jwks.add("k1", private_key)
    return TokenVerifier(settings, jwks_client=jwks)


@pytest.fixture
def make_token(private_key):
    def _make(kid="k1", key=None, **overrides):
        now = int(time.time())
        claims = {"iss": ISSUER, "sub": "user_1", "aud": AUDIENCE, "iat": now, "exp": now + 600,
                  "client_id": "app_1", "scope": "app:access dataset:read knowledge:read", "jti": "t1"}
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, key or private_key, algorithm="ES384", headers={"kid": kid})

    return _make
