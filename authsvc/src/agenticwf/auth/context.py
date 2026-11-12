"""AuthContext: the identity-provider-neutral principal passed to the rest of the system.

Downstream components (REST service, session handler, agent runtime, retriever, tools)
only ever see an AuthContext; they never parse Keycloak, Logto, INDIGO IAM or CERN SSO tokens.

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
    # Every group the user belongs to, id -> name (agenticwf.auth.groups: Keycloak groups, Logto
    # organizations). Not in the token: authsvc looks the memberships up, so they apply within a
    # minute. The KB shares with them as `org:<id>`.
    organizations: dict[str, str] = field(default_factory=dict)
    # The ones of them the user administers: a backend may let them approve
    # what concerns the group, e.g. the KB's requests to share with it.
    managed_organizations: frozenset[str] = frozenset()
    # Who the user is, for display: from the token, or looked up by authsvc.
    username: str | None = None
    name: str | None = None
    email: str | None = None

    def with_method(self, auth_method: str) -> "AuthContext":
        return replace(self, auth_method=auth_method)

    def with_organizations(self, organizations: dict[str, str], managed=()) -> "AuthContext":
        return replace(self, organizations=dict(organizations),
                       managed_organizations=frozenset(m for m in managed if m in organizations))

    def with_profile(self, profile: dict[str, str]) -> "AuthContext":
        return replace(self, username=profile.get("username"), name=profile.get("name"), email=profile.get("email"))

    @property
    def is_machine(self) -> bool:
        """True for tokens without a user (client credentials, service accounts)."""
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
        """The context of verified access-token claims, read the plain OIDC / RFC 9068 way.

        ``scopes``: the ``scope`` claim. ``roles``: the claim at the dotted path ``roles_claim``.
        A token whose ``sub`` is its ``client_id`` (client credentials) has no user. Provider
        packages map their own tokens (agenticwf.auth.provider.Provider.claims).
        """
        aud = claims.get("aud")
        audience = (aud,) if isinstance(aud, str) else tuple(aud or ())

        sub = claims["sub"]
        client_id = claims.get("client_id") or claims.get("azp")
        is_machine = bool(claims.get("client_id")) and sub == claims.get("client_id")

        raw_roles = claim(claims, roles_claim) or []
        if isinstance(raw_roles, str):
            raw_roles = raw_roles.split()

        external = claims.get(external_identity_claim)
        email = claims.get("email")
        username = claims.get("preferred_username") or claims.get("username")
        return cls(
            subject=sub,
            user_id=None if is_machine else sub,
            client_id=client_id,
            organization_id=claims.get("organization_id"),
            roles=frozenset(str(r) for r in raw_roles),
            scopes=frozenset((claims.get("scope") or "").split()),
            audience=audience,
            external_identity=external if isinstance(external, dict) else None,
            token_id=claims.get("jti"),
            expires_at=claims.get("exp"),
            # Who the user is, for display, when the token says it; the email stands in for a
            # missing username, so `username` always names a person.
            username=None if is_machine else (username or email or None),
            name=None if is_machine else (claims.get("name") or None),
            email=None if is_machine else (email or None),
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
            "managed_organizations": sorted(getattr(self, "managed_organizations", ())),
            "username": getattr(self, "username", None),
            "name": getattr(self, "name", None),
            "email": getattr(self, "email", None),
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
            managed_organizations=frozenset(str(m) for m in data.get("managed_organizations") or ()),
            username=data.get("username"),
            name=data.get("name"),
            email=data.get("email"),
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


def claim(claims: dict[str, Any], path: str) -> Any:
    """The claim at a dotted path, e.g. ``realm_access.roles``; a claim whose own name has dots wins."""
    if path in claims:
        return claims[path]
    value: Any = claims
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value
