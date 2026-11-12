"""Confidential OIDC client for browser login (authorization code + PKCE).

Browser redirects use the provider's public endpoints; server-to-server calls (token, revocation)
go where the provider says (usually inside the container), with its internal headers. The
endpoints come from the provider package (agenticwf.auth.provider.OIDCEndpoints).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

from agenticwf.auth.config import Settings
from agenticwf.auth.provider import OIDCEndpoints


class OIDCError(Exception):
    """The provider rejected the request (e.g. invalid_grant: refresh token revoked/expired)."""

    def __init__(self, error: str, description: str = ""):
        super().__init__(f"{error}: {description}" if description else error)
        self.error = error


class OIDCUnavailableError(Exception):
    """The provider could not be reached."""


@dataclass(frozen=True)
class TokenSet:
    access_token: str
    expires_at: int
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str = ""


class OIDCClient:
    def __init__(self, settings: Settings, endpoints: OIDCEndpoints, http: httpx.Client | None = None):
        self._s = settings
        self._e = endpoints
        self._http = http or httpx.Client(timeout=10, headers=dict(endpoints.internal_headers))

    @property
    def redirect_uri(self) -> str:
        return f"{self._s.app_url}/auth/callback"

    def authorization_url(self, state: str, nonce: str, code_challenge: str) -> str:
        params = {
            "client_id": self._s.web_client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": self._s.web_scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            **self._e.auth_params,
        }
        return f"{self._e.authorization}?{urlencode(params)}"

    def end_session_url(self, id_token_hint: str | None) -> str:
        if not self._e.end_session:
            return f"{self._s.app_url}/"
        params = {"client_id": self._s.web_client_id, "post_logout_redirect_uri": f"{self._s.app_url}/"}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        return f"{self._e.end_session}?{urlencode(params)}"

    def exchange_code(self, code: str, code_verifier: str) -> TokenSet:
        return self._token({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": code_verifier,
        })

    def refresh(self, refresh_token: str) -> TokenSet:
        return self._token({"grant_type": "refresh_token", "refresh_token": refresh_token})

    def revoke(self, token: str, hint: str = "refresh_token") -> None:
        """Best effort: logout must not fail because the provider is briefly unreachable."""
        if not self._e.revocation:
            return
        try:
            self._http.post(self._e.revocation, data={"token": token, "token_type_hint": hint}, auth=self._auth)
        except httpx.HTTPError:
            pass

    @property
    def _auth(self) -> tuple[str, str]:
        return (self._s.web_client_id or "", self._s.web_client_secret or "")

    def _token(self, form: dict[str, str]) -> TokenSet:
        try:
            response = self._http.post(self._e.token, data={**form, **self._e.token_params}, auth=self._auth)
        except httpx.HTTPError as exc:
            raise OIDCUnavailableError(str(exc)) from exc
        if response.status_code >= 500:
            raise OIDCUnavailableError(f"token endpoint returned {response.status_code}")
        try:
            body = response.json()
        except ValueError:
            body = {}
        if response.status_code != 200 or "access_token" not in body:
            raise OIDCError(body.get("error", "token_error"), body.get("error_description", ""))
        return TokenSet(
            access_token=body["access_token"],
            expires_at=int(time.time()) + int(body.get("expires_in", 300)),
            refresh_token=body.get("refresh_token"),
            id_token=body.get("id_token"),
            scope=body.get("scope", ""),
        )
