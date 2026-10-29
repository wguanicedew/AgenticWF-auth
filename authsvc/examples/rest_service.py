"""Example backend showing the three access paths behind Caddy + authsvc.

    CLI / scripts   GET  /api/v1/me, /api/v1/search          (Bearer token)
    Browser chat    GET  /  (page)  POST /api/v1/sessions/{sid}/messages   (session cookie)
    Live updates    GET  /api/v1/events  (Server-Sent Events, session cookie or Bearer)

Runs on :8000 (supervisorctl start auth:rest-example):

    AUTH_CONTEXT_SECRET_FILE=/var/lib/agenticwf/secrets/auth_context_secret \
        uvicorn --factory examples.rest_service:create_app --port 8000
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import defaultdict

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from agenticwf.auth.client import AuthContextMiddleware, current_auth_context, require_auth, require_scopes
from agenticwf.auth.config import read_secret
from agenticwf.auth.context import AuthContext

HEARTBEAT = 15


class Message(BaseModel):
    text: str


class Updates:
    """In-process fan-out of status updates per subject (use Redis/NATS across processes)."""

    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue]] = defaultdict(set)

    def publish(self, subject: str, event: dict) -> None:
        for queue in self._subscribers.get(subject, ()):
            queue.put_nowait(event)

    async def stream(self, request: Request, ctx: AuthContext):
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._subscribers[ctx.subject].add(queue)
        # End the stream when the token behind this context expires; EventSource reconnects
        # automatically and /verify then refreshes the browser session.
        deadline = min(ctx.expires_at or time.time() + 3600, time.time() + 3600)
        try:
            yield "retry: 2000\n\n"
            yield _sse("status", {"state": "connected", "user": ctx.subject, "auth": ctx.auth_method})
            while time.time() < deadline and not await request.is_disconnected():
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT)
                    yield _sse(event.pop("type", "update"), event)
                except asyncio.TimeoutError:
                    yield _sse("status", {"state": "idle", "time": int(time.time())})
        finally:
            self._subscribers[ctx.subject].discard(queue)


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def retrieve_documents(query: str) -> dict:
    """Stand-in for the agent runtime's retriever: tenant filtering comes from the
    ambient AuthContext, not from parameters the caller could tamper with."""
    ctx = current_auth_context()
    assert ctx is not None
    return {"query": query, "filters": {"tenant_id": ctx.organization_id, "subject": ctx.subject}}


def create_app() -> FastAPI:
    secret = read_secret("AUTH_CONTEXT_SECRET")
    if not secret:
        raise RuntimeError("AUTH_CONTEXT_SECRET(_FILE) is required")

    app = FastAPI(title="AgenticWF example REST service")
    app.add_middleware(AuthContextMiddleware, secret=secret.encode())
    updates = Updates()

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/api/v1/me")
    def me(ctx: AuthContext = Depends(require_auth)) -> dict:
        return ctx.to_dict()

    @app.get("/api/v1/search")
    def search(q: str, ctx: AuthContext = Depends(require_scopes("knowledge:read"))) -> dict:
        return retrieve_documents(q)

    @app.post("/api/v1/sessions/{sid}/messages")
    async def post_message(sid: str, msg: Message, ctx: AuthContext = Depends(require_scopes("agent:use"))) -> dict:
        updates.publish(ctx.subject, {"type": "status", "state": "thinking", "session": sid})
        reply = f"echo: {msg.text}"  # the agent runtime would run here
        updates.publish(ctx.subject, {"type": "message", "session": sid, "role": "assistant", "text": reply})
        updates.publish(ctx.subject, {"type": "status", "state": "done", "session": sid})
        return {"session": sid, "reply": reply}

    @app.get("/api/v1/events")
    async def events(request: Request, ctx: AuthContext = Depends(require_auth)) -> StreamingResponse:
        return StreamingResponse(updates.stream(request, ctx), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    @app.get("/", response_class=HTMLResponse)
    def index(ctx: AuthContext = Depends(require_auth)) -> str:
        return PAGE

    return app


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgenticWF</title>
<style>
 body{font:15px system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem}
 header{display:flex;justify-content:space-between;align-items:center}
 #status{padding:.2rem .6rem;border-radius:1rem;background:#eee}
 #log{border:1px solid #ddd;border-radius:6px;height:340px;overflow:auto;padding:.5rem;margin:1rem 0}
 #log div{margin:.25rem 0} .assistant{color:#05a} .event{color:#888;font-size:13px}
 form{display:flex;gap:.5rem} input{flex:1;padding:.5rem}
</style></head><body>
<header><strong id="who">…</strong><span id="status">connecting</span>
<form method="post" action="auth/logout"><button>Sign out</button></form></header>
<div id="log"></div>
<form id="chat"><input id="text" placeholder="Message" autocomplete="off"><button>Send</button></form>
<script>
// All URLs are relative to the page, so the app works at "/" or under a prefix like "/app/".
const login = () => { location = 'auth/login?return_to=' + encodeURIComponent(location.pathname); };
const log = (cls, text) => { const d = document.createElement('div'); d.className = cls; d.textContent = text;
  const l = document.getElementById('log'); l.append(d); l.scrollTop = l.scrollHeight; };
fetch('auth/session').then(r => r.json()).then(s => {
  if (!s.authenticated) { login(); return; }
  document.getElementById('who').textContent = s.user.name || s.user.email || s.user.id;
});
const es = new EventSource('api/v1/events');   // cookie is sent automatically
es.addEventListener('status', e => { const d = JSON.parse(e.data);
  document.getElementById('status').textContent = d.state; });
es.addEventListener('message', e => { const d = JSON.parse(e.data); log('assistant', d.text); });
es.onerror = () => { document.getElementById('status').textContent = 'reconnecting'; };
document.getElementById('chat').onsubmit = async ev => {
  ev.preventDefault(); const t = document.getElementById('text'); if (!t.value) return;
  log('user', t.value);
  const r = await fetch('api/v1/sessions/demo/messages', {method: 'POST',
    headers: {'Content-Type': 'application/json'}, body: JSON.stringify({text: t.value})});
  if (r.status === 401) login();
  else if (!r.ok) log('event', 'error ' + r.status);
  t.value = '';
};
</script></body></html>"""
