"""Token acquisition and API calls for command-line use (standard library only).

Credentials, in order of preference:
  * AGENTICWF_CLIENT_SECRET set -> machine-to-machine (client credentials), no user involved
  * AGENTICWF_TOKEN set -> a personal access token (created in the web UI under Admin > Tokens),
    exchanged for short-lived access tokens (token exchange); for scripts and CI
  * otherwise -> cached user tokens from `agenticwf login` (OAuth 2.0 device flow),
    refreshed automatically with the refresh token

`service_access` finds one service (kb, agent) for its client package: behind Caddy with the
tokens above, or directly with the service's own token (a personal agent, a standalone KB).
"""

from __future__ import annotations

import json
import os
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
PAT_TOKEN_TYPE = "urn:logto:token-type:personal_access_token"
EXPIRY_MARGIN = 60


class AuthError(Exception):
    """Not logged in, or login/refresh failed."""


class ApiError(Exception):
    def __init__(self, status: int, body: Any):
        super().__init__(f"HTTP {status}: {body}")
        self.status = status
        self.body = body


@dataclass
class Config:
    auth_url: str  # public Logto endpoint, e.g. https://auth.example.org
    api_url: str  # application, e.g. https://app.example.org
    client_id: str  # Logto Native app (device flow) or M2M app
    resource: str  # Logto API resource indicator
    scopes: str = "openid offline_access"
    client_secret: Optional[str] = None  # set -> client credentials
    personal_token: Optional[str] = None  # set -> exchange this PAT for access tokens
    cache_file: Path = Path.home() / ".config" / "agenticwf" / "credentials.json"

    @classmethod
    def from_env(cls, **overrides: Any) -> "Config":
        env = os.environ.get
        values = {
            "auth_url": env("AGENTICWF_AUTH_URL"),
            "api_url": env("AGENTICWF_API_URL"),
            "client_id": env("AGENTICWF_CLIENT_ID"),
            "resource": env("AGENTICWF_RESOURCE"),
            "scopes": env("AGENTICWF_SCOPES", "openid offline_access"),
            "client_secret": env("AGENTICWF_CLIENT_SECRET"),
            "personal_token": env("AGENTICWF_TOKEN"),
        }
        if not values["personal_token"] and env("AGENTICWF_TOKEN_FILE"):
            values["personal_token"] = Path(env("AGENTICWF_TOKEN_FILE")).expanduser().read_text().strip() or None
        if env("AGENTICWF_CREDENTIALS"):
            values["cache_file"] = Path(env("AGENTICWF_CREDENTIALS"))
        values.update({k: v for k, v in overrides.items() if v is not None})
        missing = [k for k in ("auth_url", "api_url", "client_id", "resource") if not values.get(k)]
        if missing:
            raise AuthError("missing configuration: " + ", ".join(f"AGENTICWF_{m.upper()}" for m in missing))
        values["auth_url"] = values["auth_url"].rstrip("/")
        values["api_url"] = values["api_url"].rstrip("/")
        return cls(**{k: v for k, v in values.items() if v is not None})

    @property
    def cache_key(self) -> str:
        return f"{self.auth_url}|{self.client_id}|{self.resource}"


def _http(method: str, url: str, form: Optional[dict] = None, body: Any = None,
          headers: Optional[dict] = None, auth: Optional[tuple] = None) -> tuple[int, Any]:
    data = None
    headers = {"Accept": "application/json", **(headers or {})}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if auth:
        import base64

        pair = f"{urllib.parse.quote(auth[0], safe='')}:{urllib.parse.quote(auth[1], safe='')}"
        headers["Authorization"] = "Basic " + base64.b64encode(pair.encode()).decode()
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    except urllib.error.URLError as exc:
        raise AuthError(f"cannot reach {url}: {exc.reason}") from exc
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        return status, raw.decode(errors="replace")


class TokenCache:
    def __init__(self, path: Path):
        self.path = path

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}

    def get(self, key: str) -> Optional[dict]:
        return self._load().get(key)

    def put(self, key: str, value: Optional[dict]) -> None:
        data = self._load()
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, self.path)


class Client:
    def __init__(self, config: Config, out: Callable[[str], None] = lambda m: print(m, file=sys.stderr)):
        self.config = config
        self.cache = TokenCache(config.cache_file)
        self.out = out
        self._discovery: Optional[dict] = None
        self._issued: Optional[dict] = None  # client credentials / PAT exchange; kept in memory only

    @classmethod
    def from_env(cls, **overrides: Any) -> "Client":
        return cls(Config.from_env(**overrides))

    # --- OIDC plumbing ---------------------------------------------------------------
    @property
    def discovery(self) -> dict:
        if self._discovery is None:
            status, body = _http("GET", f"{self.config.auth_url}/oidc/.well-known/openid-configuration")
            if status != 200 or not isinstance(body, dict):
                raise AuthError(f"OIDC discovery failed ({status})")
            self._discovery = body
        return self._discovery

    def _token_request(self, form: dict) -> tuple[int, dict]:
        auth = (self.config.client_id, self.config.client_secret) if self.config.client_secret else None
        if not auth:
            form = {**form, "client_id": self.config.client_id}
        status, body = _http("POST", self.discovery["token_endpoint"], form=form, auth=auth)
        return status, body if isinstance(body, dict) else {"error": str(body)}

    @staticmethod
    def _stamp(body: dict) -> dict:
        body["expires_at"] = int(time.time()) + int(body.get("expires_in", 3600))
        return body

    # --- login flows -----------------------------------------------------------------
    def login(self, open_browser: bool = True) -> dict:
        """Interactive user login with the OAuth 2.0 device authorization grant."""
        if self.config.client_secret:
            raise AuthError("AGENTICWF_CLIENT_SECRET is set: machine clients do not log in")
        if self.config.personal_token:
            raise AuthError("AGENTICWF_TOKEN is set: a personal access token needs no login")
        endpoint = self.discovery.get("device_authorization_endpoint")
        if not endpoint:
            raise AuthError("Logto does not advertise a device_authorization_endpoint")
        status, device = _http("POST", endpoint, form={
            "client_id": self.config.client_id, "scope": self.config.scopes, "resource": self.config.resource})
        if status != 200 or not isinstance(device, dict):
            raise AuthError(f"device authorization failed: {device}")

        url = device.get("verification_uri_complete") or device["verification_uri"]
        self.out(f"To sign in, open:\n\n    {url}\n\nand confirm the code: {device['user_code']}\n")
        if open_browser:
            try:
                webbrowser.open(url)
            except Exception:  # noqa: BLE001 - headless machines
                pass

        interval = int(device.get("interval", 5))
        deadline = time.time() + int(device.get("expires_in", 600))
        while time.time() < deadline:
            time.sleep(interval)
            status, body = self._token_request({
                "grant_type": DEVICE_GRANT, "device_code": device["device_code"], "resource": self.config.resource})
            if status == 200 and "access_token" in body:
                tokens = self._stamp(body)
                self.cache.put(self.config.cache_key, tokens)
                self.out("Signed in.")
                return tokens
            error = body.get("error")
            if error == "authorization_pending":
                continue
            if error == "slow_down":
                interval += 5
                continue
            raise AuthError(f"login failed: {error}: {body.get('error_description', '')}")
        raise AuthError("login timed out")

    def logout(self) -> None:
        tokens = self.cache.get(self.config.cache_key)
        if tokens and tokens.get("refresh_token") and self.discovery.get("revocation_endpoint"):
            _http("POST", self.discovery["revocation_endpoint"], form={
                "token": tokens["refresh_token"], "token_type_hint": "refresh_token", "client_id": self.config.client_id})
        self.cache.put(self.config.cache_key, None)

    def access_token(self) -> str:
        """A valid access token, refreshing or re-acquiring as needed."""
        now = time.time()
        api_scopes = " ".join(s for s in self.config.scopes.split() if s not in ("openid", "offline_access"))
        if self.config.client_secret or self.config.personal_token:
            if not self._issued or self._issued["expires_at"] - now < EXPIRY_MARGIN:
                if self.config.client_secret:
                    form, what = {"grant_type": "client_credentials"}, "client credentials"
                else:
                    form = {"grant_type": TOKEN_EXCHANGE_GRANT, "subject_token": self.config.personal_token,
                            "subject_token_type": PAT_TOKEN_TYPE}
                    what = "personal access token (expired or revoked?)"
                status, body = self._token_request({**form, "resource": self.config.resource, "scope": api_scopes})
                if status != 200 or "access_token" not in body:
                    raise AuthError(f"{what} rejected: {body.get('error')}: {body.get('error_description', '')}")
                self._issued = self._stamp(body)
            return self._issued["access_token"]

        tokens = self.cache.get(self.config.cache_key)
        if not tokens:
            raise AuthError("not logged in; run `agenticwf login`")
        if tokens["expires_at"] - now >= EXPIRY_MARGIN:
            return tokens["access_token"]
        if not tokens.get("refresh_token"):
            raise AuthError("session expired; run `agenticwf login`")
        status, body = self._token_request({
            "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "resource": self.config.resource})
        if status != 200 or "access_token" not in body:
            self.cache.put(self.config.cache_key, None)
            raise AuthError("session expired; run `agenticwf login`")
        body.setdefault("refresh_token", tokens["refresh_token"])
        tokens = self._stamp(body)
        self.cache.put(self.config.cache_key, tokens)
        return tokens["access_token"]

    # --- API -------------------------------------------------------------------------
    def request(self, method: str, path: str, json_body: Any = None, params: Optional[dict] = None) -> Any:
        url = f"{self.config.api_url}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        status, body = _http(method.upper(), url, body=json_body,
                             headers={"Authorization": f"Bearer {self.access_token()}"})
        if status >= 400:
            raise ApiError(status, body)
        return body


def service_access(service: str, path: str, url: Optional[str] = None, token: Optional[str] = None,
                   **overrides: Any) -> tuple[str, Callable[[], str]]:
    """The base URL of a service and a function returning a valid Bearer token for it.

    AGENTICWF_<SERVICE>_TOKEN (or _TOKEN_FILE) is the service's own token, sent as it is: the
    personal agent's (`agenticwf-agent token`) or a standalone KB's (`agenticwf-kb token`).
    Without one, tokens come from Logto as for `agenticwf token`. The URL is
    AGENTICWF_<SERVICE>_URL, else AGENTICWF_API_URL + `path` (where Caddy serves the service).
    `url`, `token` and `overrides` (Config fields) take precedence over the environment."""
    env, prefix = os.environ.get, f"AGENTICWF_{service.upper()}_"
    url = url or env(prefix + "URL")
    token = token or env(prefix + "TOKEN")
    if not token and env(prefix + "TOKEN_FILE"):
        token = Path(env(prefix + "TOKEN_FILE")).expanduser().read_text().strip() or None
    if token:
        api_url = overrides.get("api_url") or env("AGENTICWF_API_URL")
        if not url and not api_url:
            raise AuthError(f"{prefix}TOKEN is set: set {prefix}URL (or AGENTICWF_API_URL) too")
        return (url or api_url.rstrip("/") + path).rstrip("/"), lambda: token
    try:
        client = Client.from_env(**overrides)
    except AuthError as exc:
        raise AuthError(f"{exc} (or, for the service's own token, {prefix}URL and {prefix}TOKEN)") from None
    return (url or client.config.api_url + path).rstrip("/"), client.access_token
