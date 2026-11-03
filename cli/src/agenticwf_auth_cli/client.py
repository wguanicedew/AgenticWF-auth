"""Token acquisition and API calls for command-line use (standard library only).

Credentials, in order of preference:
  * AGENTICWF_CLIENT_SECRET set -> machine-to-machine (client credentials), no user involved
  * AGENTICWF_TOKEN set -> a personal access token (created in the web UI under Admin > Tokens),
    exchanged for short-lived access tokens (token exchange); for scripts and CI
  * otherwise -> cached user tokens from `agenticwf login` (OAuth 2.0 device flow),
    refreshed automatically with the refresh token

`service_access` finds one service (kb, agent) for its client package: behind Caddy with the
tokens above, or directly with the service's own token (a personal agent, a standalone KB).

Only a URL is needed: a service publishes how it signs clients in at <its URL>/.well-known/agenticwf,
and behind Caddy authsvc publishes the Logto settings (AGENTICWF_AUTH_URL, _API_URL, _CLIENT_ID,
_RESOURCE, and the scopes to ask for: _SCOPES) at <application URL>/auth/config. Variables that are
set take precedence.
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from agenticwf_auth_cli.tls import ssl_context

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
PAT_TOKEN_TYPE = "urn:logto:token-type:personal_access_token"
EXPIRY_MARGIN = 60
WELL_KNOWN = "/.well-known/agenticwf"   # a service's: {service, mode, auth, base_path, token_help}
CLIENT_CONFIG = "/auth/config"          # authsvc's, under the application URL: the Config fields
REQUIRED = ("auth_url", "api_url", "client_id", "resource")
DEFAULT_SCOPES = "openid offline_access"


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
    scopes: Optional[str] = None  # None: what the application publishes (Client.scopes)
    client_secret: Optional[str] = None  # set -> client credentials
    personal_token: Optional[str] = None  # set -> exchange this PAT for access tokens
    cache_file: Path = Path.home() / ".config" / "agenticwf" / "credentials.json"

    @classmethod
    def from_env(cls, discovered: Optional[dict] = None, **overrides: Any) -> "Config":
        """The AGENTICWF_* environment, then `overrides`. What is still missing comes from
        `discovered`, or else is looked up (`sign_in_settings`) from AGENTICWF_API_URL,
        AGENTICWF_AGENT_URL or AGENTICWF_KB_URL, the first one set."""
        env = os.environ.get
        values = {
            "auth_url": env("AGENTICWF_AUTH_URL"),
            "api_url": env("AGENTICWF_API_URL"),
            "client_id": env("AGENTICWF_CLIENT_ID"),
            "resource": env("AGENTICWF_RESOURCE"),
            "scopes": env("AGENTICWF_SCOPES"),
            "client_secret": env("AGENTICWF_CLIENT_SECRET"),
            "personal_token": env("AGENTICWF_TOKEN"),
        }
        if not values["personal_token"] and env("AGENTICWF_TOKEN_FILE"):
            values["personal_token"] = Path(env("AGENTICWF_TOKEN_FILE")).expanduser().read_text().strip() or None
        if env("AGENTICWF_CREDENTIALS"):
            values["cache_file"] = Path(env("AGENTICWF_CREDENTIALS"))
        values.update({k: v for k, v in overrides.items() if v is not None})
        where = None
        if discovered is None and not all(values.get(k) for k in REQUIRED):
            where = values["api_url"] or env("AGENTICWF_AGENT_URL") or env("AGENTICWF_KB_URL")
            discovered = sign_in_settings(where) if where else {}
        values.update({k: v for k, v in (discovered or {}).items() if v and not values.get(k)})
        missing = [k for k in REQUIRED if not values.get(k)]
        if missing:
            found = f" (not published by {_link_token(where)[0]})" if where else ""
            raise AuthError("missing configuration: " + ", ".join(f"AGENTICWF_{m.upper()}" for m in missing) + found)
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
        with urllib.request.urlopen(request, timeout=30, context=ssl_context()) as response:
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

    def scopes(self) -> str:
        """AGENTICWF_SCOPES, else the application's (authsvc /auth/config: the browser sign-in's), else
        openid offline_access. Logto puts in a token only the API permissions asked for (and granted)."""
        if not self.config.scopes:
            published = (_get_json(self.config.api_url + CLIENT_CONFIG) or {}).get("scopes")
            self.config.scopes = published if isinstance(published, str) and published.strip() else DEFAULT_SCOPES
        return self.config.scopes

    # --- login flows -----------------------------------------------------------------
    def login(self) -> dict:
        """Interactive user login with the OAuth 2.0 device authorization grant. No browser is
        started (on a remote or headless machine it would be a text browser, or fail): the user
        opens the link in a browser of their own, signs in and approves, while this waits."""
        if self.config.client_secret:
            raise AuthError("AGENTICWF_CLIENT_SECRET is set: machine clients do not log in")
        if self.config.personal_token:
            raise AuthError("AGENTICWF_TOKEN is set: a personal access token needs no login")
        endpoint = self.discovery.get("device_authorization_endpoint")
        if not endpoint:
            raise AuthError("Logto does not advertise a device_authorization_endpoint")
        status, device = _http("POST", endpoint, form={
            "client_id": self.config.client_id, "scope": self.scopes(), "resource": self.config.resource})
        if status != 200 or not isinstance(device, dict):
            raise AuthError(f"device authorization failed: {device}")

        url = device.get("verification_uri_complete") or device["verification_uri"]
        self.out(f"To sign in, paste this link into a web browser (on any machine):\n\n    {url}\n\n"
                 f"sign in, check that the code is {device['user_code']} and approve.\n"
                 "Waiting for the approval (Ctrl-C to cancel)...")

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
        # A machine client asks for what AGENTICWF_SCOPES says; a person's token for what they sign in with.
        scopes = (self.config.scopes or DEFAULT_SCOPES) if self.config.client_secret else self.scopes()
        api_scopes = " ".join(s for s in scopes.split() if s not in ("openid", "offline_access"))
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


def _get_json(url: str) -> Optional[dict]:
    """A public JSON document, or None (none there, not JSON, or the server cannot be reached)."""
    try:
        status, body = _http("GET", url)
    except AuthError:
        return None
    return body if status == 200 and isinstance(body, dict) else None


def _link_token(url: str) -> tuple[str, Optional[str]]:
    """A service URL without a trailing slash, and the token of a sign-in link (…/?token=…, as
    `agenticwf-agent serve` and `agenticwf-kb token --ensure` print it), if it is one."""
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qs(parts.query)
    token = (query.pop("token", None) or [None])[0]
    if token is not None:
        url = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query, doseq=True), fragment=""))
    return url.rstrip("/"), token


def describe(url: str) -> Optional[dict]:
    """How the service at `url` signs clients in (its /.well-known/agenticwf): `auth` is "logto"
    (behind Caddy and authsvc), "token" (its own token) or "none"; `base_path` is where it lives
    under the application URL. None when it publishes nothing (an older server, or unreachable)."""
    return _get_json(_link_token(url)[0] + WELL_KNOWN)


def sign_in_settings(url: str, about: Optional[dict] = None) -> dict:
    """The Logto settings (Config fields auth_url, api_url, client_id, resource) of the application
    behind the service at `url` (or the application URL itself): authsvc's /auth/config at the
    service URL without its base_path. `about` is the service's `describe`. Empty when not found."""
    url = _link_token(url)[0]
    about = describe(url) if about is None else about
    if not about or about.get("auth") != "logto":
        return {}
    base = (about.get("base_path") or "").rstrip("/")
    app = url[:-len(base)] if base and url.endswith(base) else url
    found = {k: v.rstrip("/") for k, v in (_get_json(app + CLIENT_CONFIG) or {}).items()
             if k in (*REQUIRED, "scopes") and isinstance(v, str) and v}
    return {"api_url": app, **found} if found else {}


def _is_loopback(url: str) -> bool:
    host = urllib.parse.urlsplit(url).hostname or ""
    return host == "localhost" or host.startswith("127.") or host == "::1"


def service_access(service: str, path: str, url: Optional[str] = None, token: Optional[str] = None,
                   token_file: Optional[Path] = None, **overrides: Any) -> tuple[str, Callable[[], str]]:
    """The base URL of a service and a function returning a valid Bearer token for it.

    AGENTICWF_<SERVICE>_TOKEN (or _TOKEN_FILE, or a sign-in link …/?token=… as the URL) is the
    service's own token, sent as it is: the personal agent's (`agenticwf-agent token`) or a
    standalone KB's (`agenticwf-kb token`). Without one, and unless the Logto settings are all set,
    the service tells how it signs clients in (`describe`): with its own token (then `token_file`, when it exists and the service is on this
    machine), or with Logto as for `agenticwf token`, whose settings the application publishes
    (`sign_in_settings`), so AGENTICWF_<SERVICE>_URL alone is enough. Without that URL, it is
    AGENTICWF_API_URL + `path` (where Caddy serves the service). `url`, `token` and `overrides`
    (Config fields) take precedence over the environment."""
    env, prefix = os.environ.get, f"AGENTICWF_{service.upper()}_"
    url = url or env(prefix + "URL")
    linked = None
    if url:
        url, linked = _link_token(url)
    token = token or env(prefix + "TOKEN") or linked
    if not token and env(prefix + "TOKEN_FILE"):
        token = Path(env(prefix + "TOKEN_FILE")).expanduser().read_text().strip() or None
    # Asked only when the Logto settings are not all set: then they are what the service uses.
    configured = all(overrides.get(k) or env(f"AGENTICWF_{k.upper()}") for k in REQUIRED)
    about = describe(url) if url and not token and not configured else None
    if about and about.get("auth") == "token" and token_file and _is_loopback(url):
        token_file = Path(token_file).expanduser()
        token = (token_file.read_text().strip() or None) if token_file.is_file() else None
    if token:
        api_url = overrides.get("api_url") or env("AGENTICWF_API_URL")
        if not url and not api_url:
            raise AuthError(f"{prefix}TOKEN is set: set {prefix}URL (or AGENTICWF_API_URL) too")
        return (url or api_url.rstrip("/") + path).rstrip("/"), lambda: token
    if about and about.get("auth") == "token":
        how = f"; to get it: {about['token_help']}" if about.get("token_help") else ""
        raise AuthError(f"{url} is a {service} with its own token ({about.get('mode')} mode): set {prefix}TOKEN "
                        f"(or {prefix}TOKEN_FILE), or {prefix}URL to its sign-in link (…/?token=…){how}")
    if about and about.get("auth") not in (None, "logto"):
        raise AuthError(f"{url} takes no sign-ins ({about.get('mode')} mode: for other services only)")
    try:
        discovered = sign_in_settings(url, about) if about else None
        client = Client(Config.from_env(discovered=discovered, **overrides))
    except AuthError as exc:
        raise AuthError(f"{exc} (or, for the service's own token, {prefix}URL and {prefix}TOKEN)") from None
    return (url or client.config.api_url + path).rstrip("/"), client.access_token
