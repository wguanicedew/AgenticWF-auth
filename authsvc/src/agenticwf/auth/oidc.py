"""Confidential OIDC client for browser login against Logto (authorization code + PKCE).

Browser redirects use the public Logto URL; server-to-server calls (token, revocation)
go to Logto inside the container and present the public host/scheme, as Caddy would.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

import httpx

from agenticwf.auth.config import Settings


class OIDCError(Exception):
    """Logto rejected the request (e.g. invalid_grant: refresh token revoked/expired)."""

    def __init__(self, error: str, description: str = ""):
        super().__init__(f"{error}: {description}" if description else error)
        self.error = error


class OIDCUnavailableError(Exception):
    """Logto could not be reached."""


@dataclass(frozen=True)
class TokenSet:
    access_token: str
    expires_at: int
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str = ""


class LogtoClient:
    def __init__(self, settings: Settings, http: httpx.Client | None = None):
        self._s = settings
        public = urlsplit(settings.logto_endpoint or "")
        self._http = http or httpx.Client(
            base_url=settings.logto_internal_url,
            timeout=10,
            headers={"Host": public.netloc, "X-Forwarded-Proto": public.scheme or "https",
                     "X-Forwarded-Host": public.netloc},
        )

    @property
    def redirect_uri(self) -> str:
        return f"{self._s.app_url}/auth/callback"

    def authorization_url(self, state: str, nonce: str, code_challenge: str) -> str:
        params = {
            "client_id": self._s.web_client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": self._s.web_scopes,
            "resource": self._s.resource,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            # Logto only issues refresh tokens (offline_access) with prompt=consent;
            # first-party apps are consented automatically.
            "prompt": "consent",
        }
        return f"{self._s.logto_endpoint}/oidc/auth?{urlencode(params)}"

    def end_session_url(self, id_token_hint: str | None) -> str:
        params = {"client_id": self._s.web_client_id, "post_logout_redirect_uri": f"{self._s.app_url}/"}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        return f"{self._s.logto_endpoint}/oidc/session/end?{urlencode(params)}"

    def exchange_code(self, code: str, code_verifier: str) -> TokenSet:
        return self._token({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": code_verifier,
            "resource": self._s.resource,
        })

    def refresh(self, refresh_token: str) -> TokenSet:
        return self._token({"grant_type": "refresh_token", "refresh_token": refresh_token, "resource": self._s.resource})

    def revoke(self, token: str, hint: str = "refresh_token") -> None:
        """Best effort: logout must not fail because Logto is briefly unreachable."""
        try:
            self._http.post("/oidc/token/revocation", data={"token": token, "token_type_hint": hint}, auth=self._auth)
        except httpx.HTTPError:
            pass

    @property
    def _auth(self) -> tuple[str, str]:
        return (self._s.web_client_id or "", self._s.web_client_secret or "")

    def _token(self, form: dict[str, str]) -> TokenSet:
        try:
            response = self._http.post("/oidc/token", data=form, auth=self._auth)
        except httpx.HTTPError as exc:
            raise OIDCUnavailableError(str(exc)) from exc
        if response.status_code >= 500:
            raise OIDCUnavailableError(f"token endpoint returned {response.status_code}")
        body = response.json()
        if response.status_code != 200 or "access_token" not in body:
            raise OIDCError(body.get("error", "token_error"), body.get("error_description", ""))
        return TokenSet(
            access_token=body["access_token"],
            expires_at=int(time.time()) + int(body.get("expires_in", 3600)),
            refresh_token=body.get("refresh_token"),
            id_token=body.get("id_token"),
            scope=body.get("scope", ""),
        )
