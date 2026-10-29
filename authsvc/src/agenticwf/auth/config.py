"""Settings loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


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
    # Public Logto issuer, e.g. https://auth.example.com/oidc. Must match the `iss` claim.
    issuer: str
    # Where to fetch signing keys. Defaults to Logto inside the same container, so
    # key fetches do not hairpin through Caddy.
    jwks_uri: str
    # Accepted `aud` values (Logto API resource indicators). A trailing `*` is a prefix
    # match, e.g. `urn:logto:organization:*` for organization tokens.
    audiences: tuple[str, ...]
    policy_file: Path
    # HMAC secret used to sign the AuthContext handed to backend services.
    context_secret: bytes
    context_ttl: int = 60
    jwks_cache_ttl: int = 300
    leeway: int = 30
    roles_claim: str = "roles"
    external_identity_claim: str = "external_identity"
    realm: str = "agenticwf"

    # --- Browser (cookie session) login; enabled when web_client_id is set ----------
    # Logto "Traditional web" application acting as a confidential client.
    logto_endpoint: str | None = None  # public, used for browser redirects
    logto_internal_url: str = "http://127.0.0.1:3001"  # server-to-server calls
    web_client_id: str | None = None
    web_client_secret: str | None = None
    app_origin: str | None = None  # e.g. https://app.example.org (scheme + host, no path)
    # Path prefix of the application on that origin, e.g. "/app" when Logto owns "/" of a
    # single shared hostname. Caddy strips it before authsvc/backend see the request.
    app_base_path: str = ""
    web_scopes: str = "openid profile email offline_access"
    web_resource: str | None = None  # defaults to the first non-wildcard audience
    session_store: str = "postgres"  # or "memory" (single process, development)
    session_db_url: str | None = None
    session_idle_ttl: int = 8 * 3600
    session_max_ttl: int = 7 * 24 * 3600
    # Where users edit their own profile, e.g. Logto's Account Center ${LOGTO_ENDPOINT}/account;
    # the web UI links to it when set.
    account_url: str | None = None

    # --- Personal access tokens (/auth/tokens); enabled with browser login and mgmt_client_id
    # Logto "Machine-to-machine" app holding the "Logto Management API access" role.
    mgmt_client_id: str | None = None
    mgmt_client_secret: str | None = None
    mgmt_resource: str = "https://default.logto.app/api"  # Logto OSS Management API
    cli_client_id: str | None = None  # Logto Native app the CLI uses; shown to users
    pat_max_days: int = 365

    # --- Groups (/auth/groups): Logto organizations, managed through the same Management API app.
    # Members' organizations reach the backends in the AuthContext (the KB shares with org:<id>).
    group_admin_role: str = "admin"    # organization role of a group's admins
    group_member_role: str = "member"  # organization role given to the members they add
    group_cache_ttl: int = 60          # seconds a user's memberships are cached (per worker)

    @property
    def web_enabled(self) -> bool:
        return bool(self.web_client_id)

    @property
    def tokens_enabled(self) -> bool:
        return self.web_enabled and bool(self.mgmt_client_id)

    @property
    def groups_enabled(self) -> bool:
        """Memberships are looked up (and /auth/groups served, with browser login)."""
        return bool(self.mgmt_client_id)

    @property
    def app_url(self) -> str:
        """Browser-facing base URL of the application."""
        return f"{self.app_origin}{self.app_base_path}"

    @property
    def resource(self) -> str:
        return self.web_resource or next(a for a in self.audiences if not a.endswith("*"))

    @classmethod
    def from_env(cls) -> "Settings":
        endpoint = _env("LOGTO_ENDPOINT")
        issuer = _env("AUTH_ISSUER") or (f"{endpoint.rstrip('/')}/oidc" if endpoint else None)
        if not issuer:
            raise RuntimeError("Set LOGTO_ENDPOINT (public Logto URL) or AUTH_ISSUER")

        audiences = tuple(a for a in (_env("AUTH_AUDIENCES", "") or "").replace(",", " ").split() if a)
        if not audiences:
            raise RuntimeError("Set AUTH_AUDIENCES to the Logto API resource indicator(s)")

        secret = read_secret("AUTH_CONTEXT_SECRET")
        if not secret or len(secret) < 32:
            raise RuntimeError("AUTH_CONTEXT_SECRET(_FILE) must provide at least 32 characters")

        web_client_id = _env("AUTH_WEB_CLIENT_ID")
        app_origin = (_env("APP_ORIGIN") or "").rstrip("/") or None
        base_path = (_env("APP_BASE_PATH") or "").strip("/")
        base_path = f"/{base_path}" if base_path else ""
        web_client_secret = read_secret("AUTH_WEB_CLIENT_SECRET")
        if web_client_id and not (endpoint and app_origin and web_client_secret):
            raise RuntimeError("Browser login needs LOGTO_ENDPOINT, APP_ORIGIN and AUTH_WEB_CLIENT_SECRET(_FILE)")
        mgmt_client_id = _env("AUTH_MGMT_CLIENT_ID")
        mgmt_client_secret = read_secret("AUTH_MGMT_CLIENT_SECRET")
        if mgmt_client_id and not mgmt_client_secret:
            raise RuntimeError("AUTH_MGMT_CLIENT_ID needs AUTH_MGMT_CLIENT_SECRET(_FILE)")

        return cls(
            issuer=issuer,
            jwks_uri=_env("AUTH_JWKS_URI", "http://127.0.0.1:3001/oidc/jwks"),
            audiences=audiences,
            policy_file=Path(_env("AUTH_POLICY_FILE", "/etc/agenticwf/policy.yaml")),
            context_secret=secret.encode(),
            context_ttl=int(_env("AUTH_CONTEXT_TTL", "60")),
            jwks_cache_ttl=int(_env("AUTH_JWKS_CACHE_TTL", "300")),
            leeway=int(_env("AUTH_LEEWAY", "30")),
            roles_claim=_env("AUTH_ROLES_CLAIM", "roles"),
            external_identity_claim=_env("AUTH_EXTERNAL_IDENTITY_CLAIM", "external_identity"),
            realm=_env("AUTH_REALM", "agenticwf"),
            logto_endpoint=endpoint.rstrip("/") if endpoint else None,
            logto_internal_url=_env("LOGTO_INTERNAL_URL", "http://127.0.0.1:3001").rstrip("/"),
            web_client_id=web_client_id,
            web_client_secret=web_client_secret,
            app_origin=app_origin,
            app_base_path=base_path,
            web_scopes=_env("AUTH_WEB_SCOPES", "openid profile email offline_access"),
            web_resource=_env("AUTH_WEB_RESOURCE"),
            session_store=_env("AUTH_SESSION_STORE", "postgres"),
            session_db_url=read_secret("AUTH_SESSION_DB_URL"),
            session_idle_ttl=int(_env("AUTH_SESSION_IDLE_TTL", str(8 * 3600))),
            session_max_ttl=int(_env("AUTH_SESSION_MAX_TTL", str(7 * 24 * 3600))),
            account_url=(_env("AUTH_ACCOUNT_URL") or "").rstrip("/") or None,
            mgmt_client_id=mgmt_client_id,
            mgmt_client_secret=mgmt_client_secret,
            mgmt_resource=_env("AUTH_MGMT_RESOURCE", "https://default.logto.app/api"),
            cli_client_id=_env("AUTH_CLI_CLIENT_ID"),
            pat_max_days=int(_env("AUTH_PAT_MAX_DAYS", "365")),
            group_admin_role=_env("AUTH_GROUP_ADMIN_ROLE", "admin"),
            group_member_role=_env("AUTH_GROUP_MEMBER_ROLE", "member"),
            group_cache_ttl=int(_env("AUTH_GROUP_CACHE_TTL", "60")),
        )
