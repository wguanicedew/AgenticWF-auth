"""Settings loaded from environment variables.

Only provider-neutral settings live here. A provider package reads its own (KEYCLOAK_*, LOGTO_*)
and passes what follows from them as defaults: ``Settings.from_env(issuer=..., jwks_uri=...)``.
An AUTH_* variable that is set always wins over such a default.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def read_secret(name: str) -> str | None:
    """Return secret ``name`` from ``$NAME`` or from the file named by ``$NAME_FILE``."""
    value = _env(name)
    if value:
        return value
    path = _env(f"{name}_FILE")
    if path:
        return Path(path).read_text().strip() or None
    return None


@dataclass(frozen=True)
class Settings:
    # Expected `iss` of access tokens (the provider's public issuer URL).
    issuer: str
    # Where to fetch signing keys; usually the provider inside the same container.
    jwks_uri: str
    # Accepted `aud` values. A trailing `*` is a prefix match.
    audiences: tuple[str, ...]
    policy_file: Path
    # HMAC secret used to sign the AuthContext handed to backend services.
    context_secret: bytes
    context_ttl: int = 60
    jwks_cache_ttl: int = 300
    leeway: int = 30
    # Claims read by the generic mapping (AuthContext.from_claims); providers may map otherwise.
    roles_claim: str = "roles"  # dotted path, e.g. realm_access.roles
    external_identity_claim: str = "external_identity"
    realm: str = "agenticwf"  # WWW-Authenticate realm

    # --- Browser (cookie session) login; enabled when web_client_id is set ----------
    # A confidential OIDC client of the provider (authorization code + PKCE).
    web_client_id: str | None = None
    web_client_secret: str | None = None
    app_origin: str | None = None  # e.g. https://app.example.org (scheme + host, no path)
    # Path prefix of the application on that origin, e.g. "/app" when another service owns "/"
    # of a shared hostname. Caddy strips it before authsvc/backend see the request.
    app_base_path: str = ""
    web_scopes: str = "openid profile email"
    session_store: str = "postgres"  # or "memory" (single process, development)
    session_db_url: str | None = None
    session_idle_ttl: int = 8 * 3600
    session_max_ttl: int = 7 * 24 * 3600
    # Where users edit their own profile; the web UI links to it when set.
    account_url: str | None = None

    # --- The provider's admin API: groups (/auth/groups), personal access tokens (/auth/tokens)
    mgmt_client_id: str | None = None
    mgmt_client_secret: str | None = None
    cli_client_id: str | None = None  # client of `agenticwf login` (device flow); published
    cli_scopes: str = "openid offline_access"  # what the CLI asks for; published
    pat_max_days: int = 365
    group_cache_ttl: int = 60  # seconds a user's groups (and profile, PAT roles) are cached

    @property
    def web_enabled(self) -> bool:
        return bool(self.web_client_id)

    @property
    def management_enabled(self) -> bool:
        return bool(self.mgmt_client_id)

    @property
    def app_url(self) -> str:
        """Browser-facing base URL of the application."""
        return f"{self.app_origin}{self.app_base_path}"

    @property
    def default_audience(self) -> str | None:
        return next((a for a in self.audiences if not a.endswith("*")), None)

    @classmethod
    def from_env(cls, **defaults: Any) -> "Settings":
        """Settings from AUTH_* / APP_* variables; ``defaults`` (field names) fill what is unset."""
        def get(env: str, field: str, fallback: Any = None) -> Any:
            return _env(env) or defaults.get(field) or fallback

        def number(env: str, field: str, fallback: int) -> int:
            return int(get(env, field, fallback))

        issuer = (get("AUTH_ISSUER", "issuer") or "").rstrip("/")
        if not issuer:
            raise RuntimeError("Set AUTH_ISSUER (or the provider's settings it is derived from)")
        jwks_uri = get("AUTH_JWKS_URI", "jwks_uri")
        if not jwks_uri:
            raise RuntimeError("Set AUTH_JWKS_URI (or the provider's settings it is derived from)")

        raw_aud = get("AUTH_AUDIENCES", "audiences", "")
        if not isinstance(raw_aud, str):
            raw_aud = " ".join(raw_aud)
        audiences = tuple(a for a in raw_aud.replace(",", " ").split() if a)
        if not audiences:
            raise RuntimeError("Set AUTH_AUDIENCES to the audience(s) of the API's access tokens")

        secret = read_secret("AUTH_CONTEXT_SECRET")
        if not secret or len(secret) < 32:
            raise RuntimeError("AUTH_CONTEXT_SECRET(_FILE) must provide at least 32 characters")

        web_client_id = get("AUTH_WEB_CLIENT_ID", "web_client_id")
        app_origin = (_env("APP_ORIGIN") or "").rstrip("/") or None
        base_path = (_env("APP_BASE_PATH") or "").strip("/")
        base_path = f"/{base_path}" if base_path else ""
        web_client_secret = read_secret("AUTH_WEB_CLIENT_SECRET")
        if web_client_id and not (app_origin and web_client_secret):
            raise RuntimeError("Browser login needs APP_ORIGIN and AUTH_WEB_CLIENT_SECRET(_FILE)")
        mgmt_client_id = get("AUTH_MGMT_CLIENT_ID", "mgmt_client_id")
        mgmt_client_secret = read_secret("AUTH_MGMT_CLIENT_SECRET")
        if mgmt_client_id and not mgmt_client_secret:
            raise RuntimeError("AUTH_MGMT_CLIENT_ID needs AUTH_MGMT_CLIENT_SECRET(_FILE)")

        return cls(
            issuer=issuer,
            jwks_uri=jwks_uri,
            audiences=audiences,
            policy_file=Path(get("AUTH_POLICY_FILE", "policy_file", "/etc/agenticwf/policy.yaml")),
            context_secret=secret.encode(),
            context_ttl=number("AUTH_CONTEXT_TTL", "context_ttl", 60),
            jwks_cache_ttl=number("AUTH_JWKS_CACHE_TTL", "jwks_cache_ttl", 300),
            leeway=number("AUTH_LEEWAY", "leeway", 30),
            roles_claim=get("AUTH_ROLES_CLAIM", "roles_claim", "roles"),
            external_identity_claim=get("AUTH_EXTERNAL_IDENTITY_CLAIM", "external_identity_claim", "external_identity"),
            realm=get("AUTH_REALM", "realm", "agenticwf"),
            web_client_id=web_client_id,
            web_client_secret=web_client_secret,
            app_origin=app_origin,
            app_base_path=base_path,
            web_scopes=get("AUTH_WEB_SCOPES", "web_scopes", "openid profile email"),
            session_store=get("AUTH_SESSION_STORE", "session_store", "postgres"),
            session_db_url=read_secret("AUTH_SESSION_DB_URL"),
            session_idle_ttl=number("AUTH_SESSION_IDLE_TTL", "session_idle_ttl", 8 * 3600),
            session_max_ttl=number("AUTH_SESSION_MAX_TTL", "session_max_ttl", 7 * 24 * 3600),
            account_url=(get("AUTH_ACCOUNT_URL", "account_url") or "").rstrip("/") or None,
            mgmt_client_id=mgmt_client_id,
            mgmt_client_secret=mgmt_client_secret,
            cli_client_id=get("AUTH_CLI_CLIENT_ID", "cli_client_id"),
            cli_scopes=get("AUTH_CLI_SCOPES", "cli_scopes", "openid offline_access"),
            pat_max_days=number("AUTH_PAT_MAX_DAYS", "pat_max_days", 365),
            group_cache_ttl=number("AUTH_GROUP_CACHE_TTL", "group_cache_ttl", 60),
        )
