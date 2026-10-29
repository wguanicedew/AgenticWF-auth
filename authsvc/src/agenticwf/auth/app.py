"""HTTP front of the auth service.

Endpoints:
    /verify   Caddy ``forward_auth`` target: authenticate + authorize the original request
              (taken from X-Forwarded-Method / X-Forwarded-Uri). 2xx lets Caddy forward the
              request with the X-Auth-* headers below; other responses go to the client.
    /whoami   Return the AuthContext of the presented token (debugging / clients).
    /healthz  Liveness.
    /auth/*   Browser login (see ``agenticwf.auth.web``), when AUTH_WEB_CLIENT_ID is configured.
    /auth/tokens  Personal access tokens for the CLI (see ``agenticwf.auth.tokens``), when
              AUTH_MGMT_CLIENT_ID is configured as well.
    /auth/groups  Groups: Logto organizations, their members and join requests (see
              ``agenticwf.auth.groups``), with browser login and AUTH_MGMT_CLIENT_ID.

With AUTH_MGMT_CLIENT_ID, the AuthContext of a user also carries their organizations (groups),
looked up through the Management API and cached briefly.

Two kinds of credentials are accepted by /verify:
    Authorization: Bearer <Logto access token>   CLI tools, scripts, M2M clients
    __Host-agenticwf_session cookie              browser chat / status pages (incl. SSE, WebSocket)
A request carrying a Bearer token is never evaluated against the cookie.

Tracing and metrics: ``agenticwf.auth.telemetry``, off unless an OTLP endpoint is set.

Run with:  uvicorn --factory agenticwf.auth.app:create_app
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from agenticwf.auth.authn import AuthenticationError, AuthUnavailableError, TokenVerifier, extract_bearer
from agenticwf.auth.authz import APPROVAL_PENDING, InvalidPathError, Policy, normalize_path
from agenticwf.auth.config import Settings
from agenticwf.auth.context import HEADER_CONTEXT, HEADER_SIGNATURE, AuthContext, encode_context
from agenticwf.auth.oidc import LogtoClient, OIDCUnavailableError
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
    verifier: TokenVerifier | None = None,
    policy: Policy | None = None,
    sessions: SessionManager | None = None,
    logto: LogtoClient | None = None,
    management: tokens.ManagementClient | None = None,
    memberships: groups.Memberships | None = None,
    group_requests: groups.RequestStore | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    telemetry.setup()  # before the Logto client exists; off unless an OTLP endpoint is set
    verifier = verifier or TokenVerifier(settings)
    policy = policy or Policy.load(settings.policy_file)
    if settings.web_enabled and sessions is None:
        logto = logto or LogtoClient(settings)
        sessions = SessionManager(build_store(settings.session_store, settings.session_db_url), logto,
                                  settings.session_idle_ttl, settings.session_max_ttl)

    app = FastAPI(title="AgenticWF auth service", docs_url=None, redoc_url=None, openapi_url=None)
    telemetry.instrument_app(app)  # a span per request
    if settings.web_enabled:
        assert sessions is not None
        app.include_router(web.build_router(settings, sessions, logto or sessions.client, verifier,
                                            policy.required_scopes))
    if management is None and settings.mgmt_client_id:
        management = tokens.ManagementClient(settings)
    if management is not None and settings.web_enabled:
        assert sessions is not None
        app.include_router(tokens.build_router(settings, sessions, verifier, management, policy.required_scopes))
    if memberships is None and settings.groups_enabled and management is not None:
        memberships = groups.Memberships(management, settings.group_cache_ttl)
    if memberships is not None and settings.web_enabled:
        assert sessions is not None and management is not None
        group_requests = group_requests or groups.build_request_store(settings.session_store, settings.session_db_url)
        app.include_router(groups.build_router(settings, sessions, verifier, management, memberships, group_requests,
                                               policy.required_scopes))

    def with_groups(ctx: AuthContext) -> AuthContext:
        """A user's organizations (groups), for the backends; machines have none."""
        if memberships is None or ctx.is_machine or ctx.user_id is None:
            return ctx
        return ctx.with_organizations(memberships.names(ctx.user_id))

    def context_from_token(token: str, method: str) -> AuthContext:
        claims = verifier.verify(token)
        return AuthContext.from_claims(claims, settings.roles_claim, settings.external_identity_claim).with_method(method)

    def authenticate(request: Request, method: str) -> tuple[AuthContext | None, bool, WebSession | None]:
        """Return (context, stale_cookie, session). Raises AuthenticationError / CsrfError / *Unavailable."""
        token = extract_bearer(request.headers.get("authorization"))
        if token is not None:
            return context_from_token(token, "bearer"), False, None
        raw = request.cookies.get(web.SESSION_COOKIE)
        if not (settings.web_enabled and sessions and raw):
            return None, False, None
        session = sessions.resolve(raw)
        if session is None:
            return None, True, None
        if web.needs_origin_check(method, request.headers) and not web.origin_allowed(request.headers, settings.app_origin or ""):
            raise CsrfError("cross-origin request with session cookie")
        return context_from_token(session.access_token, "session"), False, session

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
                if settings.web_enabled and web.wants_html(method, request.headers):
                    response: Response = web.login_redirect(uri, settings.app_base_path)  # page load -> sign in
                else:
                    response = _error(401, "missing_token", decision.reason, settings.realm)
                if stale_cookie:
                    web.clear_session_cookie(response)
                return response
            if decision.code == APPROVAL_PENDING and settings.web_enabled and web.wants_html(method, request.headers):
                info = session.user_info if session else {}
                user = info.get("email") or info.get("name") or info.get("username") or (ctx.subject if ctx else "")
                return web.pending_page(settings.app_base_path, uri, user)
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
            ctx, _, _ = authenticate(request, "GET")
        except AuthenticationError as exc:
            return _error(401, exc.error, exc.description, settings.realm)
        except (AuthUnavailableError, OIDCUnavailableError):
            return _error(503, "temporarily_unavailable", "Cannot verify credentials right now", settings.realm)
        if ctx is None:
            return _error(401, "missing_token", "authentication required", settings.realm)
        return JSONResponse({**with_groups(ctx).to_dict(), "approved": policy.is_approved(ctx)})

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    return app
