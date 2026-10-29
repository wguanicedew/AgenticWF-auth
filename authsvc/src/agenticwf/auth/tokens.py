"""Personal access tokens (PATs) for the CLI: /auth/tokens, managed from the web UI.

Logto stores the tokens. authsvc lists, creates and revokes the signed-in user's tokens
through the Logto Management API, as a Machine-to-machine app holding the "Logto
Management API access" role (AUTH_MGMT_CLIENT_ID / AUTH_MGMT_CLIENT_SECRET).

The CLI exchanges a PAT for a short-lived access token itself (token exchange on the
Native app, see cli/), so /verify only ever sees ordinary Logto JWTs: the scopes follow
the user's current roles, and blocking or deleting the user in Logto stops their PATs.

Only a browser session may manage tokens (a PAT cannot mint more PATs), the account must
be approved, and state-changing requests pass the same Origin check as /verify.
"""

from __future__ import annotations

import re
import threading
import time
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
from fastapi import APIRouter, Body, Request
from fastapi.responses import JSONResponse, Response

from agenticwf.auth.authn import AuthenticationError, AuthUnavailableError, TokenVerifier
from agenticwf.auth.config import Settings
from agenticwf.auth.oidc import OIDCUnavailableError
from agenticwf.auth.sessions import SessionManager, WebSession
from agenticwf.auth import web

NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}")
TOKEN_MARGIN = 60


class ManagementError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class ManagementUnavailableError(Exception):
    """Logto could not be reached."""


class ManagementClient:
    """The few Logto Management API calls authsvc needs: users' tokens (PATs), and organizations,
    their members and members' organization roles (groups, agenticwf.auth.groups)."""

    def __init__(self, settings: Settings, http: httpx.Client | None = None):
        self._s = settings
        public = urlsplit(settings.logto_endpoint or "")
        self._http = http or httpx.Client(
            base_url=settings.logto_internal_url,
            timeout=10,
            headers={"Host": public.netloc, "X-Forwarded-Proto": public.scheme or "https",
                     "X-Forwarded-Host": public.netloc},
        )
        self._token: tuple[str, float] | None = None
        self._lock = threading.Lock()

    def _access_token(self) -> str:
        with self._lock:
            if self._token and self._token[1] - time.time() > TOKEN_MARGIN:
                return self._token[0]
            try:
                r = self._http.post("/oidc/token", auth=(self._s.mgmt_client_id or "", self._s.mgmt_client_secret or ""),
                                    data={"grant_type": "client_credentials", "resource": self._s.mgmt_resource, "scope": "all"})
            except httpx.HTTPError as exc:
                raise ManagementUnavailableError(str(exc)) from exc
            if r.status_code != 200:
                raise ManagementError(502, f"Management API token request failed ({r.status_code})")
            body = r.json()
            self._token = (body["access_token"], time.time() + int(body.get("expires_in", 3600)))
            return self._token[0]

    def _call(self, method: str, path: str, json: Any = None) -> httpx.Response:
        try:
            r = self._http.request(method, path, json=json, headers={"Authorization": f"Bearer {self._access_token()}"})
        except httpx.HTTPError as exc:
            raise ManagementUnavailableError(str(exc)) from exc
        if r.status_code >= 500:
            raise ManagementUnavailableError(f"Management API returned {r.status_code}")
        return r

    def _path(self, user_id: str) -> str:
        return f"/api/users/{quote(user_id, safe='')}/personal-access-tokens"

    def list(self, user_id: str) -> list[dict]:
        r = self._call("GET", self._path(user_id))
        if r.status_code != 200:
            raise ManagementError(502, f"listing tokens failed ({r.status_code})")
        return r.json()

    def create(self, user_id: str, name: str, expires_at: int | None) -> dict:
        r = self._call("POST", self._path(user_id), json={"name": name, "expiresAt": expires_at * 1000 if expires_at else None})
        if r.status_code == 422:
            raise ManagementError(409, "A token with this name already exists.")
        if r.status_code not in (200, 201):
            raise ManagementError(502, f"creating the token failed ({r.status_code})")
        return r.json()

    def delete(self, user_id: str, name: str) -> None:
        r = self._call("DELETE", f"{self._path(user_id)}/{quote(name, safe='')}")
        if r.status_code == 404:
            raise ManagementError(404, "No such token.")
        if r.status_code != 204:
            raise ManagementError(502, f"revoking the token failed ({r.status_code})")

    # -- organizations (groups) ---------------------------------------------------------------
    def _expect(self, r: httpx.Response, what: str, ok: tuple[int, ...] = (200,)) -> Any:
        if r.status_code == 404:
            raise ManagementError(404, f"{what}: not found.")
        if r.status_code not in ok:
            raise ManagementError(502, f"{what} failed ({r.status_code})")
        return r.json() if r.content and "json" in r.headers.get("content-type", "") else None

    def _all(self, path: str, what: str) -> list[dict]:
        items, page = [], 1
        while True:
            sep = "&" if "?" in path else "?"
            batch = self._expect(self._call("GET", f"{path}{sep}page={page}&page_size=100"), what) or []
            items += batch
            if len(batch) < 100:
                return items
            page += 1

    def organizations(self) -> list[dict]:
        return self._all("/api/organizations", "listing groups")

    def organization(self, org_id: str) -> dict:
        return self._expect(self._call("GET", f"/api/organizations/{quote(org_id, safe='')}"), "reading the group")

    def create_organization(self, name: str, description: str) -> dict:
        return self._expect(self._call("POST", "/api/organizations", json={"name": name, "description": description}),
                            "creating the group", (200, 201))

    def update_organization(self, org_id: str, fields: dict) -> dict:
        return self._expect(self._call("PATCH", f"/api/organizations/{quote(org_id, safe='')}", json=fields),
                            "changing the group")

    def delete_organization(self, org_id: str) -> None:
        self._expect(self._call("DELETE", f"/api/organizations/{quote(org_id, safe='')}"), "deleting the group", (204,))

    def organization_members(self, org_id: str) -> list[dict]:
        """Users, each with `organizationRoles` ([{id, name}])."""
        return self._all(f"/api/organizations/{quote(org_id, safe='')}/users", "listing members")

    def add_member(self, org_id: str, user_id: str, role_ids: list[str]) -> None:
        base = f"/api/organizations/{quote(org_id, safe='')}/users"
        self._expect(self._call("POST", base, json={"userIds": [user_id]}), "adding the member", (201, 204))
        if role_ids:
            self.set_member_roles(org_id, user_id, role_ids)

    def remove_member(self, org_id: str, user_id: str) -> None:
        self._expect(self._call("DELETE", f"/api/organizations/{quote(org_id, safe='')}/users/{quote(user_id, safe='')}"),
                     "removing the member", (204,))

    def set_member_roles(self, org_id: str, user_id: str, role_ids: list[str]) -> None:
        """Replace the member's organization roles."""
        self._expect(self._call("PUT", f"/api/organizations/{quote(org_id, safe='')}/users/{quote(user_id, safe='')}/roles",
                                json={"organizationRoleIds": role_ids}), "setting the member's roles", (201, 204))

    def user_organizations(self, user_id: str) -> list[dict]:
        """The user's organizations, each with `organizationRoles` ([{id, name}])."""
        return self._expect(self._call("GET", f"/api/users/{quote(user_id, safe='')}/organizations"),
                            "listing the user's groups") or []

    def organization_role_ids(self) -> dict[str, str]:
        return {r["name"]: r["id"] for r in self._all("/api/organization-roles", "listing group roles")}

    def find_user(self, email: str) -> dict | None:
        r = self._call("GET", f"/api/users?search.primaryEmail={quote(email, safe='')}&mode.primaryEmail=exact")
        users = self._expect(r, "looking up the user") or []
        return next((u for u in users if (u.get("primaryEmail") or "").lower() == email.lower()), None)


def _seconds(ms: Any) -> int | None:
    return int(ms) // 1000 if ms else None


def public_view(token: dict) -> dict:
    """Never the token value: Logto returns it on every listing."""
    return {"name": token["name"], "created_at": _seconds(token.get("createdAt")),
            "expires_at": _seconds(token.get("expiresAt"))}


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
        scopes = set((verifier.verify(session.access_token).get("scope") or "").split())
    except (OIDCUnavailableError, AuthUnavailableError):
        return _error(503, "temporarily_unavailable", "Identity service unavailable.")
    except AuthenticationError:
        return _error(401, "invalid_token", "Session is no longer valid; sign in again.")
    if not required_scopes <= scopes:
        return _error(403, "approval_pending", "Your account has not been approved yet.")
    return session, scopes


def build_router(settings: Settings, sessions: SessionManager, verifier: TokenVerifier, management: ManagementClient,
                 required_scopes: frozenset[str] = frozenset()) -> APIRouter:
    router = APIRouter(prefix="/auth/tokens")

    def signed_in_session(request: Request) -> WebSession | Response:
        found = signed_in(request, settings, sessions, verifier, required_scopes, "manage personal access tokens")
        return found if isinstance(found, Response) else found[0]

    def management_call(fn):
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
        tokens = management_call(lambda: management.list(session.subject))
        if isinstance(tokens, Response):
            return tokens
        return _no_store(JSONResponse({
            "tokens": sorted((public_view(t) for t in tokens), key=lambda t: t["created_at"] or 0, reverse=True),
            "max_days": settings.pat_max_days,
            # What `agenticwf` needs besides the token (AGENTICWF_* environment variables).
            "cli": {"auth_url": settings.logto_endpoint, "api_url": settings.app_url,
                    "client_id": settings.cli_client_id, "resource": settings.resource},
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
        created = management_call(lambda: management.create(session.subject, name, int(time.time()) + days * 86400))
        if isinstance(created, Response):
            return created
        # The value is shown this once; the UI never lists it again.
        return _no_store(JSONResponse({**public_view(created), "token": created["value"]}, status_code=201))

    @router.delete("/{name}")
    def delete_token(request: Request, name: str) -> Response:
        session = signed_in_session(request)
        if isinstance(session, Response):
            return session
        done = management_call(lambda: management.delete(session.subject, name))
        return done if isinstance(done, Response) else Response(status_code=204)

    return router
