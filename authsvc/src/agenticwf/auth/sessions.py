"""Server-side browser sessions.

The browser only holds an opaque, HttpOnly session cookie. Logto tokens stay on the
server, keyed by SHA-256 of the session id (a leaked database does not yield usable
cookies). Access tokens are refreshed transparently inside ``/verify``, which matters for
long-lived chat UIs and for SSE/WebSocket clients that cannot attach Authorization headers.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Callable, Iterator, Protocol

from agenticwf.auth.oidc import LogtoClient, OIDCError, TokenSet

# Refresh access tokens this many seconds before they expire.
REFRESH_MARGIN = 60
# Throttle last-seen writes.
TOUCH_INTERVAL = 60


@dataclass(frozen=True)
class WebSession:
    id_hash: str
    subject: str
    access_token: str
    access_expires_at: int
    refresh_token: str | None
    id_token: str | None
    created_at: int
    last_seen_at: int
    expires_at: int  # absolute session end
    user_info: dict[str, Any] = field(default_factory=dict)


def hash_session_id(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


class SessionStore(Protocol):
    def create(self, session: WebSession) -> None: ...
    def get(self, id_hash: str) -> WebSession | None: ...
    def delete(self, id_hash: str) -> WebSession | None: ...
    def touch(self, id_hash: str, last_seen_at: int) -> None: ...
    def update(self, id_hash: str, fn: Callable[[WebSession], WebSession | None]) -> WebSession | None:
        """Atomically apply ``fn`` to the locked session; ``None`` deletes it."""
        ...


class MemorySessionStore:
    """For tests and single-process development only (not shared between workers)."""

    def __init__(self) -> None:
        self._data: dict[str, WebSession] = {}
        self._lock = threading.RLock()

    def create(self, session: WebSession) -> None:
        with self._lock:
            self._data[session.id_hash] = session

    def get(self, id_hash: str) -> WebSession | None:
        return self._data.get(id_hash)

    def delete(self, id_hash: str) -> WebSession | None:
        with self._lock:
            return self._data.pop(id_hash, None)

    def touch(self, id_hash: str, last_seen_at: int) -> None:
        with self._lock:
            if id_hash in self._data:
                self._data[id_hash] = replace(self._data[id_hash], last_seen_at=last_seen_at)

    def update(self, id_hash, fn):
        with self._lock:
            current = self._data.get(id_hash)
            if current is None:
                return None
            new = fn(current)
            if new is None:
                self._data.pop(id_hash, None)
            else:
                self._data[id_hash] = new
            return new


_SCHEMA = """
CREATE TABLE IF NOT EXISTS web_sessions (
    id_hash           text PRIMARY KEY,
    subject           text NOT NULL,
    access_token      text NOT NULL,
    access_expires_at bigint NOT NULL,
    refresh_token     text,
    id_token          text,
    created_at        bigint NOT NULL,
    last_seen_at      bigint NOT NULL,
    expires_at        bigint NOT NULL,
    user_info         jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS web_sessions_expires_at_idx ON web_sessions (expires_at);
CREATE INDEX IF NOT EXISTS web_sessions_subject_idx ON web_sessions (subject);
"""

_COLUMNS = [f for f in WebSession.__dataclass_fields__]


class PostgresSessionStore:
    """Shared across uvicorn workers; refresh is serialised with a row lock."""

    def __init__(self, dsn: str):
        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool

        self._pool = ConnectionPool(dsn, min_size=1, max_size=10, open=True,
                                    kwargs={"autocommit": True, "row_factory": dict_row})
        with self._tx() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(4242001)")  # workers start concurrently
            cur.execute(_SCHEMA)

    @contextmanager
    def _tx(self) -> Iterator[Any]:
        with self._pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
            yield cur

    @staticmethod
    def _row(row: dict | None) -> WebSession | None:
        return WebSession(**row) if row else None

    def create(self, session: WebSession) -> None:
        values = asdict(session)
        values["user_info"] = json.dumps(values["user_info"])
        with self._tx() as cur:
            cur.execute("DELETE FROM web_sessions WHERE expires_at < %s", (int(time.time()),))
            cur.execute(
                f"INSERT INTO web_sessions ({', '.join(_COLUMNS)}) VALUES ({', '.join(['%s'] * len(_COLUMNS))})",
                [values[c] for c in _COLUMNS],
            )

    def get(self, id_hash: str) -> WebSession | None:
        with self._tx() as cur:
            cur.execute("SELECT * FROM web_sessions WHERE id_hash = %s", (id_hash,))
            return self._row(cur.fetchone())

    def delete(self, id_hash: str) -> WebSession | None:
        with self._tx() as cur:
            cur.execute("DELETE FROM web_sessions WHERE id_hash = %s RETURNING *", (id_hash,))
            return self._row(cur.fetchone())

    def touch(self, id_hash: str, last_seen_at: int) -> None:
        with self._tx() as cur:
            cur.execute("UPDATE web_sessions SET last_seen_at = %s WHERE id_hash = %s", (last_seen_at, id_hash))

    def update(self, id_hash, fn):
        with self._tx() as cur:
            cur.execute("SELECT * FROM web_sessions WHERE id_hash = %s FOR UPDATE", (id_hash,))
            current = self._row(cur.fetchone())
            if current is None:
                return None
            new = fn(current)
            if new is None:
                cur.execute("DELETE FROM web_sessions WHERE id_hash = %s", (id_hash,))
                return None
            cur.execute(
                "UPDATE web_sessions SET access_token = %s, access_expires_at = %s, refresh_token = %s,"
                " id_token = %s, last_seen_at = %s WHERE id_hash = %s",
                (new.access_token, new.access_expires_at, new.refresh_token, new.id_token, new.last_seen_at, id_hash),
            )
            return new


class SessionManager:
    def __init__(self, store: SessionStore, client: LogtoClient, idle_ttl: int, max_ttl: int,
                 clock: Callable[[], float] = time.time):
        self.store = store
        self.client = client
        self.idle_ttl = idle_ttl
        self.max_ttl = max_ttl
        self.clock = clock

    def start(self, tokens: TokenSet, subject: str, user_info: dict[str, Any]) -> tuple[str, WebSession]:
        """Create a session; returns the raw id for the cookie (never stored)."""
        now = int(self.clock())
        raw = secrets.token_urlsafe(32)
        session = WebSession(
            id_hash=hash_session_id(raw), subject=subject,
            access_token=tokens.access_token, access_expires_at=tokens.expires_at,
            refresh_token=tokens.refresh_token, id_token=tokens.id_token,
            created_at=now, last_seen_at=now, expires_at=now + self.max_ttl, user_info=user_info,
        )
        self.store.create(session)
        return raw, session

    def resolve(self, raw: str | None) -> WebSession | None:
        """Return a live session with a fresh access token, or None.

        Raises ``OIDCUnavailableError`` if a refresh is needed but Logto is unreachable.
        """
        if not raw:
            return None
        id_hash = hash_session_id(raw)
        session = self.store.get(id_hash)
        now = int(self.clock())
        if session is None:
            return None
        if now >= session.expires_at or now - session.last_seen_at > self.idle_ttl:
            self.end(raw)
            return None
        if session.access_expires_at - now < REFRESH_MARGIN:
            session = self.store.update(id_hash, self._refresh)
            if session is None:
                return None
        elif now - session.last_seen_at > TOUCH_INTERVAL:
            self.store.touch(id_hash, now)
        return session

    def refresh_now(self, raw: str | None) -> WebSession | None:
        """Re-issue the access token immediately, e.g. after an admin changed the user's roles
        (Logto computes the token's scopes from the roles at issuance)."""
        if not raw or self.resolve(raw) is None:
            return None
        return self.store.update(hash_session_id(raw), lambda s: self._refresh(s, force=True))

    def _refresh(self, session: WebSession, force: bool = False) -> WebSession | None:
        now = int(self.clock())
        if not force and session.access_expires_at - now >= REFRESH_MARGIN:
            return session  # another worker refreshed while we waited for the lock
        if not session.refresh_token:
            # Nothing to refresh with: a forced refresh keeps the session as it is, an
            # expiring one ends (the user must sign in again).
            return session if force else None
        try:
            tokens = self.client.refresh(session.refresh_token)
        except OIDCError:
            return None  # refresh token revoked/expired: the user must sign in again
        return replace(
            session,
            access_token=tokens.access_token,
            access_expires_at=tokens.expires_at,
            refresh_token=tokens.refresh_token or session.refresh_token,
            id_token=tokens.id_token or session.id_token,
            last_seen_at=now,
        )

    def end(self, raw: str | None) -> WebSession | None:
        if not raw:
            return None
        session = self.store.delete(hash_session_id(raw))
        if session and session.refresh_token:
            self.client.revoke(session.refresh_token)
        return session


def build_store(kind: str, dsn: str | None) -> SessionStore:
    if kind == "memory":
        return MemorySessionStore()
    if kind == "postgres":
        if not dsn:
            raise RuntimeError("AUTH_SESSION_DB_URL(_FILE) is required for the postgres session store")
        return PostgresSessionStore(dsn)
    raise RuntimeError(f"unknown AUTH_SESSION_STORE {kind!r}")
