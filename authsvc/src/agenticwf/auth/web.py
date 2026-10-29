"""Browser login (backend-for-frontend): /auth/login, /auth/callback, /auth/logout, /auth/session.

Caddy routes ``<base>/auth/*`` on the application origin straight to authsvc (stripping
the optional base path, e.g. ``/app``), so cookies are first-party and the web UI never
handles Logto tokens. Browser-facing URLs built here always include the base path.

Cookie: ``__Host-agenticwf_session`` (Secure, HttpOnly, SameSite=Lax, Path=/, no Domain).
CSRF: SameSite=Lax plus an Origin check on state-changing requests and WebSocket upgrades
(see ``origin_allowed``), enforced in ``/verify`` for every cookie-authenticated request.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import logging
import secrets
from urllib.parse import quote, unquote, urlsplit

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from agenticwf.auth.authn import AuthenticationError, AuthUnavailableError, TokenVerifier
from agenticwf.auth.config import Settings
from agenticwf.auth.oidc import LogtoClient, OIDCError, OIDCUnavailableError
from agenticwf.auth.sessions import SessionManager
from agenticwf.auth import telemetry
from agenticwf.auth.signing import b64e, seal, unseal

log = logging.getLogger("agenticwf.auth.web")

SESSION_COOKIE = "__Host-agenticwf_session"
LOGIN_COOKIE = "__Host-agenticwf_login"
LOGIN_TTL = 600
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def safe_return_to(value: str | None, base: str = "") -> str:
    """Only same-origin paths inside the application; blocks open redirects like
    //evil.com or /\\evil.com, and redirects into other apps sharing the host (Logto)."""
    home = f"{base}/"
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return home
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in value):
        return home  # browsers drop tabs/newlines, turning "/\t/evil.com" into "//evil.com"
    path = unquote(value.split("?", 1)[0].split("#", 1)[0])
    if any(seg in (".", "..") for seg in path.split("/")):
        return home  # "/app/../oidc" would leave the application prefix after normalisation
    if base and not (value == base or value.startswith(home)):
        return home
    if value.startswith(f"{base}/auth/"):
        return home
    return value


def origin_allowed(headers, app_origin: str) -> bool:
    origin = headers.get("origin")
    if origin:
        return origin.rstrip("/") == app_origin
    referer = headers.get("referer")
    if referer:
        parts = urlsplit(referer)
        return f"{parts.scheme}://{parts.netloc}" == app_origin
    return False


def is_websocket(headers) -> bool:
    # Caddy forwards the upgrade intent as X-Forwarded-Upgrade (see deploy/caddy/sites/*.caddyfile).
    return "websocket" in (headers.get("x-forwarded-upgrade") or headers.get("upgrade") or "").lower()


def needs_origin_check(method: str, headers) -> bool:
    return method.upper() not in SAFE_METHODS or is_websocket(headers)


def wants_html(method: str, headers) -> bool:
    return method.upper() == "GET" and "text/html" in headers.get("accept", "") and not is_websocket(headers)


def login_redirect(uri: str, base: str = "") -> RedirectResponse:
    """``uri`` is the request URI as seen behind Caddy (base path already stripped)."""
    target = safe_return_to(f"{base}{uri}", base)
    return RedirectResponse(f"{base}/auth/login?return_to={quote(target, safe='')}", status_code=302)


def set_session_cookie(response: Response, raw: str, max_age: int) -> None:
    response.set_cookie(SESSION_COOKIE, raw, max_age=max_age, path="/", secure=True, httponly=True, samesite="lax")


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="lax")


def _no_store(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    return response


def _error_page(status: int, message: str) -> Response:
    return _no_store(JSONResponse({"error": "login_failed", "error_description": message}, status_code=status))


def pending_page(base: str, uri: str, user: str) -> HTMLResponse:
    """403 page for signed-in users whose account has not been approved yet.

    ``uri`` is the request URI behind Caddy (base path stripped); "Check again" refreshes the
    session's token, which picks up a role an admin has assigned in the meantime.
    """
    recheck = f"{base}/auth/recheck?return_to={quote(safe_return_to(f'{base}{uri}', base), safe='')}"
    body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Awaiting approval</title>
<style>body{{font:16px system-ui,sans-serif;max-width:560px;margin:4rem auto;padding:0 1rem;color:#222}}
.box{{border:1px solid #ddd;border-radius:8px;padding:1.5rem}} a.button,button{{display:inline-block;padding:.5rem 1rem;
margin-right:.5rem;border:1px solid #888;border-radius:6px;background:#f6f6f6;color:#222;text-decoration:none;font:inherit;cursor:pointer}}
form{{display:inline}}</style></head><body><div class="box">
<h1>Your account is awaiting approval</h1>
<p>You are signed in as <strong>{html.escape(user)}</strong>, but an administrator has not given your
account access yet. You will be able to continue once it has been approved.</p>
<p><a class="button" href="{html.escape(recheck)}">Check again</a>
<form method="post" action="{html.escape(base)}/auth/logout"><button>Sign out</button></form></p>
</div></body></html>"""
    return _no_store(HTMLResponse(body, status_code=403))  # type: ignore[return-value]


def build_router(settings: Settings, sessions: SessionManager, client: LogtoClient, verifier: TokenVerifier,
                 required_scopes: frozenset[str] = frozenset()) -> APIRouter:
    router = APIRouter(prefix="/auth")
    login_key = settings.context_secret
    base = settings.app_base_path

    @router.get("/login")
    def login(return_to: str | None = None) -> Response:
        verifier_raw = secrets.token_urlsafe(48)
        state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        challenge = b64e(hashlib.sha256(verifier_raw.encode()).digest())
        response = RedirectResponse(client.authorization_url(state, nonce, challenge), status_code=302)
        response.set_cookie(
            LOGIN_COOKIE,
            seal(login_key, "login", {"s": state, "n": nonce, "v": verifier_raw, "r": safe_return_to(return_to, base)}, LOGIN_TTL),
            max_age=LOGIN_TTL, path="/", secure=True, httponly=True, samesite="lax",
        )
        return _no_store(response)

    @router.get("/callback")
    def callback(request: Request, code: str | None = None, state: str | None = None,
                 error: str | None = None, error_description: str | None = None) -> Response:
        try:
            pending = unseal(login_key, "login", request.cookies.get(LOGIN_COOKIE))
        except ValueError:
            telemetry.record_login("expired")
            return _error_page(400, "Login expired or was started in another browser; please retry.")
        if error:
            telemetry.record_login("provider_error")
            return _error_page(400, f"{error}: {error_description or ''}".strip(": "))
        if not code or not state or not hmac.compare_digest(state, pending["s"]):
            telemetry.record_login("invalid_state")
            return _error_page(400, "Invalid login state.")

        try:
            tokens = client.exchange_code(code, pending["v"])
            if not tokens.id_token:
                telemetry.record_login("rejected_token")
                return _error_page(502, "Logto returned no ID token (is 'openid' in AUTH_WEB_SCOPES?)")
            id_claims = verifier.verify_id_token(tokens.id_token, settings.web_client_id or "", pending["n"])
            verifier.verify(tokens.access_token)  # must be a JWT for this API resource
        except OIDCError as exc:
            log.warning("code exchange failed: %s", exc)
            telemetry.record_login("provider_error")
            return _error_page(400, "Login could not be completed; please retry.")
        except AuthenticationError as exc:
            log.warning("token from code exchange rejected: %s", exc.description)
            telemetry.record_login("rejected_token")
            return _error_page(502, exc.description)
        except (OIDCUnavailableError, AuthUnavailableError):
            telemetry.record_login("unavailable")
            return _error_page(503, "Identity service unavailable; please retry.")

        user_info = {k: id_claims[k] for k in ("name", "email", "picture", "username") if id_claims.get(k)}
        # Signing in again (e.g. "Check again" after approval) replaces the previous session.
        sessions.end(request.cookies.get(SESSION_COOKIE))  # revocation is best effort
        raw, _ = sessions.start(tokens, id_claims["sub"], user_info)
        response = RedirectResponse(pending["r"], status_code=303)
        set_session_cookie(response, raw, settings.session_max_ttl)
        telemetry.record_login("ok")
        response.delete_cookie(LOGIN_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
        return _no_store(response)

    @router.post("/logout")
    def logout(request: Request) -> Response:
        if not origin_allowed(request.headers, settings.app_origin or ""):
            return _error_page(403, "Cross-origin logout rejected.")
        session = sessions.end(request.cookies.get(SESSION_COOKIE))
        target = client.end_session_url(session.id_token if session else None)
        if "application/json" in request.headers.get("accept", ""):
            response: Response = JSONResponse({"logout_url": target})
        else:
            response = RedirectResponse(target, status_code=303)
        clear_session_cookie(response)
        return _no_store(response)

    @router.get("/recheck")
    def recheck(request: Request, return_to: str | None = None) -> Response:
        """Pick up roles assigned since sign-in ("Check again" on the approval page).

        A refreshed token can only carry the scopes granted at sign-in, so a newly granted
        scope such as app:access needs a new authorization. Try the cheap refresh first; if
        the account still is not approved, re-run the login. Logto's own session is still
        valid, so that passes without prompting and the new grant reflects the current roles.
        """
        target = safe_return_to(return_to, base)
        relogin = _no_store(RedirectResponse(f"{base}/auth/login?return_to={quote(target, safe='')}", status_code=302))
        try:
            session = sessions.refresh_now(request.cookies.get(SESSION_COOKIE))
        except OIDCUnavailableError:
            return _error_page(503, "Identity service unavailable; please retry.")
        if session is None:
            return relogin
        try:
            scopes = set((verifier.verify(session.access_token).get("scope") or "").split())
        except (AuthenticationError, AuthUnavailableError):
            return relogin
        if not required_scopes <= scopes:
            return relogin
        return _no_store(RedirectResponse(target, status_code=303))

    @router.get("/session")
    def session_info(request: Request) -> Response:
        """Login status for the web UI (no tokens are exposed)."""
        try:
            session = sessions.resolve(request.cookies.get(SESSION_COOKIE))
        except OIDCUnavailableError:
            return _error_page(503, "Identity service unavailable.")
        if session is None:
            response = JSONResponse({"authenticated": False, "login_url": f"{base}/auth/login"})
            if request.cookies.get(SESSION_COOKIE):
                clear_session_cookie(response)
            return _no_store(response)
        try:
            claims = verifier.verify(session.access_token)
        except (AuthenticationError, AuthUnavailableError):
            claims = {}
        scopes = set((claims.get("scope") or "").split())
        return _no_store(JSONResponse({
            "authenticated": True,
            "approved": required_scopes <= scopes,
            "user": {"id": session.subject, **session.user_info},
            "organization_id": claims.get("organization_id"),
            "scopes": sorted((claims.get("scope") or "").split()),
            "session_expires_at": session.expires_at,
            "account_url": settings.account_url,
        }))

    return router
