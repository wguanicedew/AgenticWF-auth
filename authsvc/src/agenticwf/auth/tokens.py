"""Personal access tokens (PATs) for the CLI: /auth/tokens, managed from the web UI.

Where the tokens live depends on the provider (agenticwf.auth.provider.Provider.tokens):

    Logto       Logto stores them; the CLI exchanges one for short-lived access tokens itself, so
                /verify only sees Logto JWTs (``accepts_bearer = False``).
    Keycloak    authsvc stores them (agenticwf.auth.pats.LocalTokens); the CLI sends one as it is,
                and /verify resolves it to the owner's current roles (``accepts_bearer = True``).

Only a browser session may manage tokens (a PAT cannot mint more PATs), the account must be
approved, and state-changing requests pass the same Origin check as /verify.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Protocol

from fastapi import APIRouter, Body, Request
from fastapi.responses import JSONResponse, Response

from agenticwf.auth.authn import AuthenticationError, AuthUnavailableError, TokenVerifier
from agenticwf.auth.config import Settings
from agenticwf.auth.context import AuthContext
from agenticwf.auth.directory import ManagementError, ManagementUnavailableError
from agenticwf.auth.oidc import OIDCUnavailableError
from agenticwf.auth.sessions import SessionManager, WebSession
from agenticwf.auth import web

log = logging.getLogger("authsvc.tokens")

PAT_PREFIX = "pat_"
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}")


class TokenBackend(Protocol):
    """Token views: {name, created_at, expires_at} (seconds). A taken name raises
    ManagementError(409), an unknown one ManagementError(404)."""

    # True: /verify accepts `Bearer pat_…` and calls resolve(); False: the CLI exchanges PATs.
    accepts_bearer: bool

    def list(self, user_id: str) -> list[dict]: ...
    def create(self, user_id: str, name: str, expires_at: int) -> tuple[str, dict]: ...
    def delete(self, user_id: str, name: str) -> None: ...

    def resolve(self, raw: str) -> AuthContext:
        """The owner's AuthContext; AuthenticationError for an unknown/expired token,
        AuthUnavailableError when the owner's roles cannot be read."""
        ...


def _no_store(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    return response


def _error(status: int, error: str, description: str) -> Response:
    return _no_store(JSONResponse({"error": error, "error_description": description}, status_code=status))


def signed_in(request: Request, settings: Settings, sessions: SessionManager, verifier: TokenVerifier,
              required_scopes: frozenset[str], what: str) -> tuple[WebSession, set[str]] | Response:
    """The approved browser session and its scopes, or the error response. Only a browser session
    passes (a PAT or other bearer token cannot), and state changes must come from the app's origin."""
    if web.needs_origin_check(request.method, request.headers) and not web.origin_allowed(request.headers, settings.app_origin or ""):
        return _error(403, "invalid_origin", "Cross-origin request rejected.")
    try:
        session = sessions.resolve(request.cookies.get(web.SESSION_COOKIE))
        if session is None:
            return _error(401, "missing_token", f"Sign in to {what}.")
        scopes = set(verifier.context(session.access_token, "session").scopes)
    except (OIDCUnavailableError, AuthUnavailableError):
        return _error(503, "temporarily_unavailable", "Identity service unavailable.")
    except AuthenticationError as exc:
        web.end_rejected_session(sessions, request.cookies.get(web.SESSION_COOKIE), exc)
        response = _error(401, "missing_token", f"Session is no longer valid; sign in again to {what}.")
        web.clear_session_cookie(response)
        return response
    if not required_scopes <= scopes:
        return _error(403, "approval_pending", "Your account has not been approved yet.")
    return session, scopes


def build_router(settings: Settings, sessions: SessionManager, verifier: TokenVerifier, tokens: TokenBackend,
                 required_scopes: frozenset[str] = frozenset(), cli_config: dict[str, Any] | None = None) -> APIRouter:
    """``cli_config``: what `agenticwf` needs besides the token (as /auth/config publishes it)."""
    router = APIRouter(prefix="/auth/tokens")

    def signed_in_session(request: Request) -> WebSession | Response:
        found = signed_in(request, settings, sessions, verifier, required_scopes, "manage personal access tokens")
        return found if isinstance(found, Response) else found[0]

    def call(fn):
        try:
            return fn()
        except ManagementUnavailableError:
            return _error(503, "temporarily_unavailable", "Identity service unavailable.")
        except ManagementError as exc:
            return _error(exc.status, "token_error", str(exc))

    @router.get("")
    def list_tokens(request: Request) -> Response:
        session = signed_in_session(request)
        if isinstance(session, Response):
            return session
        listed = call(lambda: tokens.list(session.subject))
        if isinstance(listed, Response):
            return listed
        now = int(time.time())
        listed = [t for t in listed if not t.get("expires_at") or t["expires_at"] > now]
        return _no_store(JSONResponse({
            "tokens": sorted(listed, key=lambda t: t.get("created_at") or 0, reverse=True),
            "max_days": settings.pat_max_days,
            # What `agenticwf` needs besides the token (AGENTICWF_* environment variables).
            "cli": dict(cli_config or {}),
        }))

    @router.post("")
    def create_token(request: Request, body: dict = Body(...)) -> Response:
        session = signed_in_session(request)
        if isinstance(session, Response):
            return session
        name = body.get("name")
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            return _error(400, "invalid_request", "Name: 1-64 letters, digits, spaces, dots, dashes or underscores.")
        days = body.get("expires_in_days")
        if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= settings.pat_max_days:
            return _error(400, "invalid_request", f"Expiry must be between 1 and {settings.pat_max_days} days.")
        created = call(lambda: tokens.create(session.subject, name, int(time.time()) + days * 86400))
        if isinstance(created, Response):
            return created
        raw, view = created
        log.info("personal access token %r created for %s", name, session.subject)
        # The value is shown this once; the UI never lists it again.
        return _no_store(JSONResponse({**view, "token": raw}, status_code=201))

    @router.delete("/{name}")
    def delete_token(request: Request, name: str) -> Response:
        session = signed_in_session(request)
        if isinstance(session, Response):
            return session
        done = call(lambda: tokens.delete(session.subject, name))
        if isinstance(done, Response):
            return done
        log.info("personal access token %r revoked by %s", name, session.subject)
        return Response(status_code=204)

    return router
