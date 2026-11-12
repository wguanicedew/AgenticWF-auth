"""Authentication: verify JWT access tokens of the identity provider."""

from __future__ import annotations

from typing import Any, Callable

import jwt
from jwt import PyJWKClient

from agenticwf.auth.config import Settings
from agenticwf.auth.context import AuthContext

# Providers sign with EC or RSA keys. Symmetric algorithms are never accepted, which rules out
# alg-confusion attacks (and HS-signed Keycloak refresh tokens).
ALLOWED_ALGORITHMS = ["ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]


class AuthenticationError(Exception):
    """The request carries no usable credentials (HTTP 401)."""

    def __init__(self, error: str, description: str):
        super().__init__(description)
        self.error = error
        self.description = description


class AuthUnavailableError(Exception):
    """Signing keys (or a credential's owner) could not be fetched; fail closed (HTTP 503)."""


def extract_bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise AuthenticationError("invalid_request", "Authorization header must use the Bearer scheme")
    return token.strip()


def audience_matches(token_aud: Any, accepted: tuple[str, ...]) -> bool:
    values = [token_aud] if isinstance(token_aud, str) else list(token_aud or [])
    for value in values:
        for pattern in accepted:
            if pattern.endswith("*") and value.startswith(pattern[:-1]):
                return True
            if value == pattern:
                return True
    return False


class TokenVerifier:
    """Verifies access tokens; ``claims`` and ``check_claims`` are the provider's (agenticwf.auth.provider)."""

    def __init__(self, settings: Settings, jwks_client: PyJWKClient | None = None,
                 claims: Callable[[dict[str, Any]], AuthContext] | None = None,
                 check_claims: Callable[[dict[str, Any]], None] | None = None):
        self._settings = settings
        self._jwks = jwks_client or PyJWKClient(
            settings.jwks_uri,
            cache_jwk_set=True,
            lifespan=settings.jwks_cache_ttl,
            timeout=5,
        )
        self._claims = claims or (lambda c: AuthContext.from_claims(c, settings.roles_claim,
                                                                    settings.external_identity_claim))
        self._check = check_claims

    def verify(self, token: str) -> dict[str, Any]:
        """Verify an access token for this API; returns its claims."""
        claims = self._decode(token)
        if self._check is not None:
            self._check(claims)
        if not audience_matches(claims.get("aud"), self._settings.audiences):
            raise AuthenticationError("invalid_token", "Token audience is not accepted by this API")
        return claims

    def context(self, token: str, auth_method: str = "bearer") -> AuthContext:
        """The AuthContext of a verified access token."""
        return self._claims(self.verify(token)).with_method(auth_method)

    def verify_id_token(self, token: str, client_id: str, nonce: str) -> dict[str, Any]:
        """Verify an OIDC ID token from the browser login flow."""
        claims = self._decode(token)
        if not audience_matches(claims.get("aud"), (client_id,)):
            raise AuthenticationError("invalid_token", "ID token was issued to another client")
        if claims.get("nonce") != nonce:
            raise AuthenticationError("invalid_token", "ID token nonce mismatch")
        return claims

    def _decode(self, token: str) -> dict[str, Any]:
        try:
            # Unknown `kid` triggers one JWKS refresh, so the provider's key rotation is picked up.
            signing_key = self._jwks.get_signing_key_from_jwt(token)
        except jwt.PyJWKClientConnectionError as exc:
            raise AuthUnavailableError(str(exc)) from exc
        except (jwt.PyJWKClientError, jwt.DecodeError) as exc:
            # Includes opaque (non-JWT) tokens.
            raise AuthenticationError("invalid_token", f"Malformed or unknown token: {exc}") from exc

        try:
            return jwt.decode(
                token,
                signing_key.key,
                algorithms=ALLOWED_ALGORITHMS,
                issuer=self._settings.issuer,
                leeway=self._settings.leeway,
                options={"require": ["exp", "iss", "sub"], "verify_aud": False},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthenticationError("invalid_token", "Token expired") from exc
        except jwt.InvalidTokenError as exc:
            raise AuthenticationError("invalid_token", f"Token rejected: {exc}") from exc
