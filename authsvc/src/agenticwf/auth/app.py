"""HTTP front of the auth service.

Endpoints:
    /verify   Caddy ``forward_auth`` target: authenticate + authorize the original request
              (taken from X-Forwarded-Method / X-Forwarded-Uri). 2xx lets Caddy forward the
              request with the X-Auth-* headers below; other responses go to the client.
    /whoami   Return the AuthContext of the presented token (debugging / clients).
    /healthz  Liveness.
    /auth/config  Public: what the `agenticwf` CLI needs besides a credential (the issuer URL, the
              application URL, the CLI client id, the scopes to ask for, and the provider's extras),
              so a client finds them from a URL.
    /auth/*   Browser login (see ``agenticwf.auth.web``), when AUTH_WEB_CLIENT_ID is configured.
    /auth/tokens  Personal access tokens for the CLI (see ``agenticwf.auth.tokens``), when the
              provider offers them.
    /auth/groups  Groups, their members and join requests (see ``agenticwf.auth.groups``), with
              browser login and the provider's directory.

The identity provider plugs in as an ``agenticwf.auth.provider.Provider`` (claims mapping, OIDC
endpoints, directory, tokens). Provider packages call ``create_app(settings, provider)`` from their
own factory, e.g. ``uvicorn --factory agenticwf_auth_keycloak:create_app``.

Credentials accepted by /verify:
    Authorization: Bearer <access token>   CLI tools, scripts, machine clients
    Authorization: Bearer pat_…            personal access tokens, if the provider's TokenBackend
                                           accepts them (agenticwf.auth.pats)
    __Host-agenticwf_session cookie        browser chat / status pages (incl. SSE, WebSocket)
A request carrying a Bearer token is never evaluated against the cookie.

Tracing and metrics: ``agenticwf.auth.telemetry``, off unless an OTLP endpoint is set.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from agenticwf.auth.authn import AuthenticationError, AuthUnavailableError, TokenVerifier, extract_bearer
from agenticwf.auth.authz import APPROVAL_PENDING, InvalidPathError, Policy, normalize_path
from agenticwf.auth.config import Settings
from agenticwf.auth.context import HEADER_CONTEXT, HEADER_SIGNATURE, AuthContext, encode_context
from agenticwf.auth.oidc import OIDCClient, OIDCUnavailableError
from agenticwf.auth.provider import Provider
from agenticwf.auth.sessions import SessionManager, WebSession, build_store
from agenticwf.auth import groups, telemetry, tokens, web

log = logging.getLogger("authsvc")

# Headers handed to the backend. Caddy strips client-supplied copies before forward_auth.
HEADER_USER_ID = "X-Auth-User-Id"
HEADER_CLIENT_ID = "X-Auth-Client-Id"
HEADER_ORG_ID = "X-Auth-Org-Id"
HEADER_ROLES = "X-Auth-Roles"
HEADER_SCOPES = "X-Auth-Scopes"
HEADER_METHOD = "X-Auth-Method"


class CsrfError(Exception):
    """Cookie-authenticated request from a foreign origin."""


def _error(status: int, error: str, description: str, realm: str) -> JSONResponse:
    headers = {"Cache-Control": "no-store"}
    if status == 401:
        challenge = f'Bearer realm="{realm}"'
        if error != "missing_token":
            challenge += f', error="{error}", error_description="{description.replace(chr(34), chr(39))}"'
        headers["WWW-Authenticate"] = challenge
    return JSONResponse({"error": error, "error_description": description}, status_code=status, headers=headers)


def create_app(
    settings: Settings | None = None,
    provider: Provider | None = None,
    verifier: TokenVerifier | None = None,
    policy: Policy | None = None,
    sessions: SessionManager | None = None,
    oidc: OIDCClient | None = None,
    memberships: groups.Memberships | None = None,
    profiles: groups.Profiles | None = None,
    group_requests: groups.RequestStore | None = None,
) -> FastAPI:
    """The auth service for ``provider`` (default: plain OIDC bearer tokens, no browser login)."""
    settings = settings or Settings.from_env()
    provider = provider or Provider()
    telemetry.setup()  # before the OIDC client exists; off unless an OTLP endpoint is set
    verifier = verifier or TokenVerifier(settings, claims=provider.claims, check_claims=provider.check_claims)
    policy = policy or Policy.load(settings.policy_file)
    if settings.web_enabled and sessions is None:
        if oidc is None:
            if provider.endpoints is None:
                raise RuntimeError(f"AUTH_WEB_CLIENT_ID is set, but provider {provider.name!r} has no OIDC endpoints")
            oidc = OIDCClient(settings, provider.endpoints)
        sessions = SessionManager(build_store(settings.session_store, settings.session_db_url), oidc,
                                  settings.session_idle_ttl, settings.session_max_ttl)
    directory, personal_tokens = provider.directory, provider.tokens
    cli_config = {"auth_url": settings.issuer, "api_url": settings.app_url if settings.app_origin else None,
                  "client_id": settings.cli_client_id, "scopes": settings.cli_scopes, **provider.client_config}

    app = FastAPI(title="AgenticWF auth service", docs_url=None, redoc_url=None, openapi_url=None)
    telemetry.instrument_app(app)  # a span per request
    if settings.web_enabled:
        assert sessions is not None
        app.include_router(web.build_router(settings, sessions, oidc or sessions.client, verifier,
                                            policy.required_scopes, provider.return_blocked))
    if personal_tokens is not None and settings.web_enabled:
        assert sessions is not None
        app.include_router(tokens.build_router(settings, sessions, verifier, personal_tokens, policy.required_scopes,
                                               {k: v for k, v in cli_config.items() if k != "scopes"}))
    if memberships is None and directory is not None:
        memberships = groups.Memberships(directory, settings.group_cache_ttl)
    if profiles is None and directory is not None and provider.lookup_profiles:
        profiles = groups.Profiles(directory, settings.group_cache_ttl)
    if memberships is not None and directory is not None and settings.web_enabled:
        assert sessions is not None
        group_requests = group_requests or groups.build_request_store(settings.session_store, settings.session_db_url)
        app.include_router(groups.build_router(settings, sessions, verifier, directory, memberships, group_requests,
                                               policy.required_scopes))

    def with_groups(ctx: AuthContext) -> AuthContext:
        """A user's groups (and profile, where the token has none), for the backends; machines have none."""
        if ctx.is_machine or ctx.user_id is None:
            return ctx
        if profiles is not None:
            ctx = ctx.with_profile(profiles.of(ctx.user_id))
        if memberships is None:
            return ctx
        found = memberships.of(ctx.user_id)
        return ctx.with_organizations({group_id: m["name"] for group_id, m in found.items()},
                                      managed=[group_id for group_id, m in found.items() if m.get("admin")])

    def context_from_token(token: str, method: str) -> AuthContext:
        return verifier.context(token, method)

    def authenticate(request: Request, method: str) -> tuple[AuthContext | None, bool, WebSession | None]:
        """Return (context, stale_cookie, session). Raises AuthenticationError / CsrfError / *Unavailable."""
        token = extract_bearer(request.headers.get("authorization"))
        if token is not None:
            if token.startswith(tokens.PAT_PREFIX) and personal_tokens is not None and personal_tokens.accepts_bearer:
                return personal_tokens.resolve(token), False, None
            return context_from_token(token, "bearer"), False, None
        raw = request.cookies.get(web.SESSION_COOKIE)
        if not (settings.web_enabled and sessions and raw):
            return None, False, None
        session = sessions.resolve(raw)
        if session is None:
            return None, True, None
        if web.needs_origin_check(method, request.headers) and not web.origin_allowed(request.headers, settings.app_origin or ""):
            raise CsrfError("cross-origin request with session cookie")
        try:
            return context_from_token(session.access_token, "session"), False, session
        except AuthenticationError as exc:
            # Treated like an expired session: /verify sends the browser to sign in (page loads)
            # or answers 401 (API calls, on which the web UI signs in), clearing the cookie.
            web.end_rejected_session(sessions, raw, exc)
            return None, True, None

    # Sync handlers: FastAPI runs them in a threadpool, so blocking I/O is fine.
    @app.api_route("/verify", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    def verify(request: Request) -> Response:
        method = (request.headers.get("x-forwarded-method") or request.method).upper()
        uri = request.headers.get("x-forwarded-uri") or "/"
        # What was presented, for the record (telemetry): never the credential itself.
        presented = "bearer" if request.headers.get("authorization") else (
            "session" if request.cookies.get(web.SESSION_COOKIE) else "none")
        try:
            path = normalize_path(uri)
        except InvalidPathError as exc:
            telemetry.record_verify(allowed=False, credential=presented, code="invalid_request")
            return _error(400, "invalid_request", str(exc), settings.realm)

        rule = policy.match(method, path)
        is_public = rule is not None and rule.public
        stale_cookie, session = False, None
        try:
            ctx, stale_cookie, session = authenticate(request, method)
        except AuthenticationError as exc:
            if not is_public:
                log.info("deny %s %s: %s", method, path, exc.description)
                telemetry.record_verify(allowed=False, credential=presented, code=exc.error)
                return _error(401, exc.error, exc.description, settings.realm)
            ctx = None  # a bad credential does not block public routes; it is simply ignored
        except CsrfError as exc:
            log.warning("deny %s %s: %s (origin=%s)", method, path, exc, request.headers.get("origin"))
            telemetry.record_verify(allowed=False, credential=presented, code="invalid_origin")
            return _error(403, "invalid_origin", str(exc), settings.realm)
        except (AuthUnavailableError, OIDCUnavailableError) as exc:
            log.error("identity provider unavailable: %s", exc)
            telemetry.record_verify(allowed=False, credential=presented, code="temporarily_unavailable")
            return _error(503, "temporarily_unavailable", "Cannot verify credentials right now", settings.realm)

        decision = policy.authorize(ctx, method, path)
        credential = ctx.auth_method if ctx is not None else "none"
        if not decision.allowed:
            log.info("deny %s %s sub=%s: %s", method, path, ctx and ctx.subject, decision.reason)
            telemetry.record_verify(allowed=False, credential=credential, public=is_public,
                                    code="missing_token" if decision.status == 401 else decision.code or "insufficient_scope")
            if decision.status == 401:
                if settings.web_enabled and web.wants_html(method, request.headers) and web.is_login_path(path, settings.app_base_path):
                    # The proxy sent authsvc's own login endpoints through /verify: redirecting to
                    # the login would loop (each round nesting return_to, until HTTP 431).
                    log.error("login endpoint %s reached /verify: the proxy routes {base}/auth/* through forward_auth; "
                              "APP_BASE_PATH=%r must match the Caddy site (it sends {base}/auth/* to authsvc directly)",
                              path, settings.app_base_path)
                    response: Response = _error(500, "proxy_misconfigured",
                                      f"The sign-in endpoint {path} is routed through authentication; check that "
                                      f"APP_BASE_PATH ({settings.app_base_path or 'empty'}) matches the reverse proxy's site file.",
                                      settings.realm)
                elif settings.web_enabled and web.wants_html(method, request.headers):
                    response = web.login_redirect(uri, settings.app_base_path)  # page load -> sign in
                else:
                    response = _error(401, "missing_token", decision.reason, settings.realm)
                if stale_cookie:
                    web.clear_session_cookie(response)
                return response
            if settings.web_enabled and web.wants_html(method, request.headers):
                info = session.user_info if session else {}
                user = info.get("email") or info.get("name") or info.get("username") or (ctx.subject if ctx else "")
                if decision.code == APPROVAL_PENDING:
                    return web.pending_page(settings.app_base_path, uri, user)
                return web.forbidden_page(settings.app_base_path, uri, user, decision.reason)
            return _error(403, decision.code or "insufficient_scope", decision.reason, settings.realm)

        telemetry.record_verify(allowed=True, credential=credential, public=is_public)
        response = Response(status_code=200)
        if ctx is not None:
            ctx = with_groups(ctx)
            payload, signature = encode_context(ctx, settings.context_secret, settings.context_ttl, method, path)
            response.headers[HEADER_CONTEXT] = payload
            response.headers[HEADER_SIGNATURE] = signature
            response.headers[HEADER_USER_ID] = ctx.user_id or ""
            response.headers[HEADER_CLIENT_ID] = ctx.client_id or ""
            response.headers[HEADER_ORG_ID] = ctx.organization_id or ""
            response.headers[HEADER_ROLES] = ",".join(sorted(ctx.roles))
            response.headers[HEADER_SCOPES] = " ".join(sorted(ctx.scopes))
            response.headers[HEADER_METHOD] = ctx.auth_method
        return response

    @app.get("/whoami")
    def whoami(request: Request) -> Response:
        try:
            ctx, stale_cookie, _ = authenticate(request, "GET")
        except AuthenticationError as exc:
            return _error(401, exc.error, exc.description, settings.realm)
        except (AuthUnavailableError, OIDCUnavailableError):
            return _error(503, "temporarily_unavailable", "Cannot verify credentials right now", settings.realm)
        if ctx is None:
            response = _error(401, "missing_token", "authentication required", settings.realm)
            if stale_cookie:
                web.clear_session_cookie(response)
            return response
        return JSONResponse({**with_groups(ctx).to_dict(), "approved": policy.is_approved(ctx)})

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/auth/config")
    def client_config() -> dict:
        # Not secret: the same values as the AGENTICWF_* settings shown with a new access token.
        # `auth_url` is the issuer; the CLI reads its OIDC discovery document from there.
        return dict(cli_config)

    return app
