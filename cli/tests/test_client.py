import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agenticwf_auth_cli import ApiError, AuthError, Client, Config, service_access
from agenticwf_auth_cli import __main__ as cli
from agenticwf_auth_cli.__main__ import main


class FakeServer(BaseHTTPRequestHandler):
    """Logto-like OIDC endpoints + a tiny API."""

    state = {}

    def log_message(self, *args):
        pass

    def _send(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        base = f"http://127.0.0.1:{self.server.server_port}"
        if self.path == "/oidc/.well-known/openid-configuration":
            return self._send(200, {"token_endpoint": f"{base}/oidc/token",
                                    "device_authorization_endpoint": f"{base}/oidc/device/auth",
                                    "revocation_endpoint": f"{base}/oidc/token/revocation"})
        if self.path == "/api/v1/pending":
            return self._send(403, {"error": "approval_pending", "error_description": "account is awaiting approval"})
        if self.path == "/api/v1/me":
            auth = self.headers.get("Authorization", "")
            if auth != f"Bearer {self.state.get('valid')}":
                return self._send(401, {"error": "invalid_token"})
            return self._send(200, {"subject": "u1"})
        self._send(404, {})

    def do_POST(self):
        form = urllib.parse.parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        form = {k: v[0] for k, v in form.items()}
        s = self.state
        s.setdefault("requests", []).append((self.path, form))
        if self.path == "/oidc/device/auth":
            return self._send(200, {"device_code": "dc", "user_code": "ABCD-EFGH",
                                    "verification_uri": "https://auth/device", "interval": 0, "expires_in": 30})
        if self.path == "/oidc/token/revocation":
            return self._send(200, {})
        if self.path == "/oidc/token":
            grant = form["grant_type"]
            if grant.endswith("device_code"):
                s["polls"] = s.get("polls", 0) + 1
                if s["polls"] < 2:
                    return self._send(400, {"error": "authorization_pending"})
                s["valid"] = "at-1"
                return self._send(200, {"access_token": "at-1", "refresh_token": "rt-1", "expires_in": 3600})
            if grant == "refresh_token":
                if form["refresh_token"] != "rt-1":
                    return self._send(400, {"error": "invalid_grant"})
                s["valid"] = "at-2"
                return self._send(200, {"access_token": "at-2", "expires_in": 3600})
            if grant == "client_credentials":
                if "Basic " not in self.headers.get("Authorization", ""):
                    return self._send(401, {"error": "invalid_client"})
                s["valid"] = "m2m"
                return self._send(200, {"access_token": "m2m", "expires_in": 3600})
            if grant.endswith("token-exchange"):
                if form.get("subject_token") != "pat_good" or form.get("client_id") != "cli":
                    return self._send(400, {"error": "invalid_grant", "error_description": "token revoked"})
                s["valid"] = "from-pat"
                return self._send(200, {"access_token": "from-pat", "expires_in": 3600})
        self._send(404, {})


@pytest.fixture
def server():
    FakeServer.state = {}
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), FakeServer)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()


@pytest.fixture
def config(server, tmp_path):
    return Config(auth_url=server, api_url=server, client_id="cli", resource="https://api.example.org",
                  cache_file=tmp_path / "credentials.json")


def test_device_login_cache_and_refresh(config):
    client = Client(config, out=lambda m: None)
    client.login(open_browser=False)
    assert FakeServer.state["polls"] == 2
    assert (config.cache_file.stat().st_mode & 0o777) == 0o600
    device_req = next(f for p, f in FakeServer.state["requests"] if p == "/oidc/device/auth")
    assert device_req["resource"] == "https://api.example.org"
    assert client.request("GET", "/api/v1/me") == {"subject": "u1"}

    # expire the cached token -> transparent refresh, refresh token kept
    data = json.loads(config.cache_file.read_text())
    data[config.cache_key]["expires_at"] = int(time.time())
    config.cache_file.write_text(json.dumps(data))
    assert Client(config).access_token() == "at-2"
    assert json.loads(config.cache_file.read_text())[config.cache_key]["refresh_token"] == "rt-1"


def test_not_logged_in_and_logout(config):
    client = Client(config, out=lambda m: None)
    with pytest.raises(AuthError):
        client.access_token()
    client.login(open_browser=False)
    client.logout()
    assert any(p == "/oidc/token/revocation" for p, _ in FakeServer.state["requests"])
    with pytest.raises(AuthError):
        client.access_token()


def test_machine_to_machine(config):
    config.client_secret = "s3cret"
    client = Client(config)
    assert client.request("GET", "/api/v1/me") == {"subject": "u1"}
    with pytest.raises(AuthError):
        client.login()


def test_personal_access_token(config, monkeypatch):
    config.personal_token = "pat_good"
    client = Client(config)
    assert client.request("GET", "/api/v1/me") == {"subject": "u1"}
    client.access_token()  # cached in memory: one exchange
    exchanges = [f for p, f in FakeServer.state["requests"] if f.get("grant_type", "").endswith("token-exchange")]
    assert len(exchanges) == 1
    assert exchanges[0]["subject_token_type"] == "urn:logto:token-type:personal_access_token"
    assert exchanges[0]["resource"] == "https://api.example.org"
    assert not config.cache_file.exists()  # the PAT and its tokens are never written to disk
    with pytest.raises(AuthError):
        client.login()

    config.personal_token = "pat_revoked"
    with pytest.raises(AuthError, match="token revoked"):
        Client(config).access_token()


def test_personal_access_token_from_env(server, tmp_path, monkeypatch):
    for k, v in {"AGENTICWF_AUTH_URL": server, "AGENTICWF_API_URL": server, "AGENTICWF_CLIENT_ID": "cli",
                 "AGENTICWF_RESOURCE": "https://api.example.org"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("AGENTICWF_TOKEN", raising=False)
    (tmp_path / "token").write_text("pat_good\n")
    monkeypatch.setenv("AGENTICWF_TOKEN_FILE", str(tmp_path / "token"))
    assert Client.from_env().access_token() == "from-pat"


def test_api_error(config):
    config.client_secret = "s3cret"
    client = Client(config)
    client.access_token()
    FakeServer.state["valid"] = "other"
    with pytest.raises(ApiError) as exc:
        client.request("GET", "/api/v1/me")
    assert exc.value.status == 401


def test_cli_entrypoint(config, monkeypatch, capsys):
    monkeypatch.setenv("AGENTICWF_CREDENTIALS", str(config.cache_file))
    args = ["--auth-url", config.auth_url, "--api-url", config.api_url, "--client-id", "cli",
            "--resource", config.resource]
    assert main(args + ["token"]) == 2
    assert main(args + ["login", "--no-browser"]) == 0
    assert main(args + ["token"]) == 0
    assert capsys.readouterr().out.strip().endswith("at-1")


def test_cli_reports_pending_approval(config, monkeypatch, capsys):
    monkeypatch.setenv("AGENTICWF_CLIENT_SECRET", "s3cret")
    args = ["--auth-url", config.auth_url, "--api-url", config.api_url, "--client-id", "cli",
            "--resource", config.resource]
    assert main(args + ["call", "GET", "/api/v1/pending"]) == 3
    assert "awaiting approval" in capsys.readouterr().err


def test_service_access_with_logto(server, tmp_path, monkeypatch):
    for k, v in {"AGENTICWF_AUTH_URL": server, "AGENTICWF_API_URL": server + "/app/", "AGENTICWF_CLIENT_ID": "cli",
                 "AGENTICWF_RESOURCE": "https://api.example.org", "AGENTICWF_TOKEN": "pat_good"}.items():
        monkeypatch.setenv(k, v)
    for k in ("AGENTICWF_KB_URL", "AGENTICWF_KB_TOKEN", "AGENTICWF_KB_TOKEN_FILE"):
        monkeypatch.delenv(k, raising=False)
    base, token = service_access("kb", "/kb")
    assert base == server + "/app/kb" and token() == "from-pat"
    monkeypatch.setenv("AGENTICWF_KB_URL", "https://kb.example.org/kb/")
    assert service_access("kb", "/kb")[0] == "https://kb.example.org/kb"


def test_service_access_with_its_own_token(tmp_path, monkeypatch):
    for k in ("AGENTICWF_AUTH_URL", "AGENTICWF_API_URL", "AGENTICWF_AGENT_URL", "AGENTICWF_AGENT_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    (tmp_path / "token").write_text("local-token\n")
    monkeypatch.setenv("AGENTICWF_AGENT_TOKEN_FILE", str(tmp_path / "token"))
    with pytest.raises(AuthError, match="AGENTICWF_AGENT_URL"):
        service_access("agent", "")
    monkeypatch.setenv("AGENTICWF_AGENT_URL", "http://127.0.0.1:8765/")
    base, token = service_access("agent", "")
    assert base == "http://127.0.0.1:8765" and token() == "local-token"   # no Logto configuration needed


class _Plugin:
    name, value = "demo", "demo:register"

    @staticmethod
    def load():
        def register(sub):
            parser = sub.add_parser("demo")
            parser.set_defaults(run=lambda args: print("demo", args.auth["api_url"]) or 7)
        return register


class _Broken:
    name, value = "broken", "broken:register"

    @staticmethod
    def load():
        raise ImportError("no module named broken")


def test_cli_command_plugins(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_command_plugins", lambda: [_Broken, _Plugin])
    assert main(["--api-url", "https://app", "demo"]) == 7
    captured = capsys.readouterr()
    assert captured.out.strip() == "demo https://app"
    assert "`broken` commands unavailable" in captured.err
