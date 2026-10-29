import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from agenticwf.auth.context import AuthContext, encode_context
from tests.conftest import SECRET


@pytest.fixture
def backend(monkeypatch):
    monkeypatch.setenv("AUTH_CONTEXT_SECRET", SECRET.decode())
    from examples.rest_service import create_app

    return TestClient(create_app())


def headers_for(method, path, **ctx_kw):
    ctx = AuthContext(subject="u1", user_id="u1", expires_at=int(time.time()) + 600, **ctx_kw)
    payload, sig = encode_context(ctx, SECRET, 60, method, path)
    return {"X-Auth-Context": payload, "X-Auth-Context-Sig": sig}


def test_page_and_message(backend):
    assert backend.get("/").status_code == 401
    assert "EventSource" in backend.get("/", headers=headers_for("GET", "/")).text
    path = "/api/v1/sessions/demo/messages"
    r = backend.post(path, json={"text": "hi"}, headers=headers_for("POST", path, scopes=frozenset({"agent:use"}),
                                                                     auth_method="session"))
    assert r.json()["reply"] == "echo: hi"
    assert backend.post(path, json={"text": "hi"}, headers=headers_for("POST", path)).status_code == 403


def test_updates_stream_delivers_published_events():
    from examples.rest_service import Updates

    class Req:
        async def is_disconnected(self):
            return False

    async def run():
        updates = Updates()
        ctx = AuthContext(subject="u1", user_id="u1", expires_at=int(time.time()) + 600, auth_method="session")
        stream = updates.stream(Req(), ctx)
        assert (await stream.__anext__()).startswith("retry:")
        assert "connected" in await stream.__anext__()
        updates.publish("u1", {"type": "message", "text": "hello"})
        updates.publish("someone-else", {"type": "message", "text": "not for u1"})
        chunk = await stream.__anext__()
        await stream.aclose()
        return chunk

    chunk = asyncio.run(run())
    assert chunk.startswith("event: message") and "hello" in chunk
