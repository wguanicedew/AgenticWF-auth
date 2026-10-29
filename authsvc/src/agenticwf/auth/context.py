"""AuthContext: the identity-provider-neutral principal passed to the rest of the system.

Downstream components (REST service, session handler, agent runtime, retriever, tools)
only ever see an AuthContext; they never parse Logto, INDIGO IAM or CERN SSO tokens.

Across process boundaries the context travels as two headers:

    X-Auth-Context      base64url(JSON payload)
    X-Auth-Context-Sig  base64url(HMAC-SHA256(secret, X-Auth-Context))

The payload carries a short expiry and the request it was issued for, so a captured
header pair cannot be replayed for long or against a different endpoint.
"""

from __future__ import annotations

import hmac
import json
import time
from dataclasses import dataclass, field, replace
from typing import Any

from agenticwf.auth.signing import b64d, b64e, mac

ORG_AUDIENCE_PREFIX = "urn:logto:organization:"

HEADER_CONTEXT = "X-Auth-Context"
HEADER_SIGNATURE = "X-Auth-Context-Sig"


class ContextError(Exception):
    """A propagated AuthContext is missing, forged, expired or bound to another request."""


@dataclass(frozen=True)
class AuthContext:
    subject: str
    user_id: str | None = None
    client_id: str | None = None
    organization_id: str | None = None
    roles: frozenset[str] = field(default_factory=frozenset)
    scopes: frozenset[str] = field(default_factory=frozenset)
    audience: tuple[str, ...] = ()
    external_identity: dict[str, Any] | None = None
    token_id: str | None = None
    expires_at: int | None = None
    # "bearer" (Authorization header: CLI, scripts, M2M) or "session" (browser cookie)
    auth_method: str = "bearer"
    # Every Logto organization the user belongs to, id -> name (groups, agenticwf.auth.groups).
    # Not in the token: authsvc looks the memberships up, so they apply within a minute.
    organizations: dict[str, str] = field(default_factory=dict)

    def with_method(self, auth_method: str) -> "AuthContext":
        return replace(self, auth_method=auth_method)

    def with_organizations(self, organizations: dict[str, str]) -> "AuthContext":
        return replace(self, organizations=dict(organizations))

    @property
    def is_machine(self) -> bool:
        """True for Logto machine-to-machine (client credentials) tokens."""
        return self.user_id is None

    def has_scopes(self, *required: str) -> bool:
        return set(required) <= self.scopes

    def has_any_role(self, *roles: str) -> bool:
        return bool(self.roles & set(roles))

    @classmethod
    def from_claims(
        cls,
        claims: dict[str, Any],
        roles_claim: str = "roles",
        external_identity_claim: str = "external_identity",
    ) -> "AuthContext":
        aud = claims.get("aud")
        audience = (aud,) if isinstance(aud, str) else tuple(aud or ())

        organization_id = claims.get("organization_id")
        if not organization_id:
            # Logto organization tokens carry the org in the audience.
            organization_id = next(
                (a[len(ORG_AUDIENCE_PREFIX):] for a in audience if a.startswith(ORG_AUDIENCE_PREFIX)),
                None,
            )

        sub = claims["sub"]
        client_id = claims.get("client_id")
        # Logto M2M tokens use the application id as `sub`.
        user_id = None if client_id and sub == client_id else sub

        raw_roles = claims.get(roles_claim) or []
        if isinstance(raw_roles, str):
            raw_roles = raw_roles.split()

        external = claims.get(external_identity_claim)
        return cls(
            subject=sub,
            user_id=user_id,
            client_id=client_id,
            organization_id=organization_id,
            roles=frozenset(raw_roles),
            scopes=frozenset((claims.get("scope") or "").split()),
            audience=audience,
            external_identity=external if isinstance(external, dict) else None,
            token_id=claims.get("jti"),
            expires_at=claims.get("exp"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "user_id": self.user_id,
            "client_id": self.client_id,
            "organization_id": self.organization_id,
            "roles": sorted(self.roles),
            "scopes": sorted(self.scopes),
            "audience": list(self.audience),
            "external_identity": self.external_identity,
            "token_id": self.token_id,
            "expires_at": self.expires_at,
            "is_machine": self.is_machine,
            "auth_method": self.auth_method,
            # getattr: a context pickled before this field existed (e.g. a queued agent task) has none
            "organizations": dict(sorted(getattr(self, "organizations", {}).items())),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuthContext":
        return cls(
            subject=data["subject"],
            user_id=data.get("user_id"),
            client_id=data.get("client_id"),
            organization_id=data.get("organization_id"),
            roles=frozenset(data.get("roles") or ()),
            scopes=frozenset(data.get("scopes") or ()),
            audience=tuple(data.get("audience") or ()),
            external_identity=data.get("external_identity"),
            token_id=data.get("token_id"),
            expires_at=data.get("expires_at"),
            auth_method=data.get("auth_method", "bearer"),
            organizations={str(k): str(v) for k, v in (data.get("organizations") or {}).items()},
        )


def encode_context(
    ctx: AuthContext,
    secret: bytes,
    ttl: int,
    method: str,
    path: str,
    now: float | None = None,
) -> tuple[str, str]:
    """Return the (X-Auth-Context, X-Auth-Context-Sig) header values."""
    now = int(now if now is not None else time.time())
    expiry = now + ttl
    if ctx.expires_at:
        expiry = min(expiry, ctx.expires_at)
    body = {"ctx": ctx.to_dict(), "iat": now, "exp": expiry, "req": {"method": method.upper(), "path": path}}
    payload = b64e(json.dumps(body, separators=(",", ":"), sort_keys=True).encode())
    return payload, mac(secret, payload)


def decode_context(
    payload: str | None,
    signature: str | None,
    secret: bytes,
    method: str | None = None,
    path: str | None = None,
    now: float | None = None,
) -> AuthContext:
    """Verify and decode a propagated AuthContext.

    Pass ``method``/``path`` to require that the context was issued for this request.
    """
    if not payload or not signature:
        raise ContextError("missing auth context")
    if not hmac.compare_digest(mac(secret, payload), signature):
        raise ContextError("invalid auth context signature")
    try:
        body = json.loads(b64d(payload))
    except ValueError as exc:
        raise ContextError("malformed auth context") from exc

    now = now if now is not None else time.time()
    if body.get("exp", 0) < now:
        raise ContextError("auth context expired")
    req = body.get("req") or {}
    if method is not None and req.get("method") != method.upper():
        raise ContextError("auth context issued for a different method")
    if path is not None and req.get("path") != path:
        raise ContextError("auth context issued for a different path")
    return AuthContext.from_dict(body["ctx"])
