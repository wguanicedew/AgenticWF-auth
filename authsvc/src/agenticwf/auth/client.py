"""Helpers for backend services (REST, agent runtime, ...) behind the auth service.

    from agenticwf.auth.client import AuthContextMiddleware, current_auth_context, require_auth

    app.add_middleware(AuthContextMiddleware, secret=secret)

    @app.get("/api/v1/datasets")
    def list_datasets(ctx: AuthContext = Depends(require_auth)):
        return repo.list(tenant_id=ctx.organization_id)

The middleware verifies the signed X-Auth-Context headers produced by ``/verify`` and
stores the AuthContext in a ContextVar, so code deeper in the call stack (session
handler, planner, retriever, tools) can call ``current_auth_context()`` without the
context being threaded through every function signature.
"""

from __future__ import annotations

import contextvars
from typing import Any

from agenticwf.auth.context import HEADER_CONTEXT, HEADER_SIGNATURE, AuthContext, ContextError, decode_context

_current: contextvars.ContextVar[AuthContext | None] = contextvars.ContextVar("auth_context", default=None)


def current_auth_context() -> AuthContext | None:
    return _current.get()


def require_auth_context() -> AuthContext:
    ctx = _current.get()
    if ctx is None:
        raise PermissionError("no authenticated AuthContext for this request")
    return ctx


def context_from_headers(headers: Any, secret: bytes, method: str | None = None, path: str | None = None) -> AuthContext:
    return decode_context(headers.get(HEADER_CONTEXT), headers.get(HEADER_SIGNATURE), secret, method, path)


class AuthContextMiddleware:
    """ASGI middleware: verify the propagated AuthContext and expose it via ContextVar.

    Requests without context headers proceed anonymously (public routes); requests with
    invalid or replayed context headers are rejected with 401.
    """

    def __init__(self, app: Any, secret: bytes, bind_request: bool = True):
        self.app = app
        self.secret = secret
        self.bind_request = bind_request

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        payload = headers.get(HEADER_CONTEXT.lower())
        signature = headers.get(HEADER_SIGNATURE.lower())
        ctx = None
        if payload or signature:
            try:
                ctx = decode_context(
                    payload,
                    signature,
                    self.secret,
                    method=scope["method"] if self.bind_request else None,
                    path=scope["path"] if self.bind_request else None,
                )
            except ContextError as exc:
                await _send_json(send, 401, {"error": "invalid_auth_context", "error_description": str(exc)})
                return

        scope.setdefault("state", {})["auth_context"] = ctx
        token = _current.set(ctx)
        try:
            await self.app(scope, receive, send)
        finally:
            _current.reset(token)


async def _send_json(send: Any, status: int, body: dict) -> None:
    import json

    data = json.dumps(body).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]})
    await send({"type": "http.response.body", "body": data})


def require_auth() -> AuthContext:
    """FastAPI dependency returning the request's AuthContext or raising 401."""
    from fastapi import HTTPException

    ctx = _current.get()
    if ctx is None:
        raise HTTPException(status_code=401, detail="authentication required")
    return ctx


def require_scopes(*scopes: str):
    """FastAPI dependency factory for in-handler scope checks (defence in depth)."""
    from fastapi import Depends, HTTPException

    def dependency(ctx: AuthContext = Depends(require_auth)) -> AuthContext:
        if not ctx.has_scopes(*scopes):
            raise HTTPException(status_code=403, detail=f"missing scopes: {' '.join(sorted(set(scopes) - ctx.scopes))}")
        return ctx

    return dependency
