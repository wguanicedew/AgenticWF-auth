"""Small HMAC helpers shared by the AuthContext headers and browser login cookies."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def mac(key: bytes, message: str) -> str:
    return b64e(hmac.new(key, message.encode(), hashlib.sha256).digest())


def derive_key(secret: bytes, purpose: str) -> bytes:
    """Separate keys per purpose, so a value signed for one use is invalid for another."""
    return hmac.new(secret, purpose.encode(), hashlib.sha256).digest()


def seal(secret: bytes, purpose: str, data: dict[str, Any], ttl: int, now: float | None = None) -> str:
    """Tamper-proof (not encrypted) token: ``payload.signature``."""
    body = {"d": data, "exp": int((now if now is not None else time.time()) + ttl)}
    payload = b64e(json.dumps(body, separators=(",", ":")).encode())
    return f"{payload}.{mac(derive_key(secret, purpose), payload)}"


def unseal(secret: bytes, purpose: str, token: str | None, now: float | None = None) -> dict[str, Any]:
    if not token or "." not in token:
        raise ValueError("missing token")
    payload, signature = token.rsplit(".", 1)
    if not hmac.compare_digest(mac(derive_key(secret, purpose), payload), signature):
        raise ValueError("bad signature")
    body = json.loads(b64d(payload))
    if body["exp"] < (now if now is not None else time.time()):
        raise ValueError("expired")
    return body["d"]
