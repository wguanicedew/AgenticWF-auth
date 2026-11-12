"""Personal access tokens kept by authsvc, for providers without their own (Keycloak).

A PAT is ``pat_`` + 32 random bytes; the session database stores only its SHA-256, with the owner,
a name and an expiry. The CLI sends a PAT as it is (``Authorization: Bearer pat_…``). /verify
recognises the prefix, looks the token up, and builds the AuthContext from what an access token of
the owner would carry *now*: their roles and API permissions, read through the provider's admin API
(``grants``) and cached for AUTH_GROUP_CACHE_TTL seconds. So the permissions follow the user's
current roles, and disabling or deleting the user stops their PATs within that time. If the admin
API cannot be reached and nothing is cached, /verify answers 503 (fail closed).
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from typing import Any, Callable, Iterator, Protocol

from agenticwf.auth.authn import AuthenticationError, AuthUnavailableError
from agenticwf.auth.config import Settings
from agenticwf.auth.context import AuthContext
from agenticwf.auth.directory import ManagementError, ManagementUnavailableError
from agenticwf.auth.tokens import PAT_PREFIX

log = logging.getLogger("authsvc.pats")

# A PAT's AuthContext expires after this many seconds at most (as an access token would),
# so long-lived streams opened with it come back through /verify.
CONTEXT_TTL = 300
RETRY_AFTER_FAILURE = 10


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


# --- storage -------------------------------------------------------------------------------------

@dataclass(frozen=True)
class PersonalToken:
    id_hash: str
    user_id: str
    name: str
    created_at: int
    expires_at: int


class TokenExistsError(Exception):
    """The user already has a token with this name."""


class TokenStore(Protocol):
    def add(self, token: PersonalToken) -> None: ...
    def find(self, id_hash: str) -> PersonalToken | None: ...
    def list(self, user_id: str) -> list[PersonalToken]: ...
    def remove(self, user_id: str, name: str) -> bool: ...


class MemoryTokenStore:
    """For tests and single-process development only."""

    def __init__(self) -> None:
        self._data: dict[str, PersonalToken] = {}
        self._lock = threading.Lock()

    def add(self, token):
        with self._lock:
            if any(t.user_id == token.user_id and t.name == token.name for t in self._data.values()):
                raise TokenExistsError(token.name)
            self._data[token.id_hash] = token

    def find(self, id_hash):
        return self._data.get(id_hash)

    def list(self, user_id):
        return [t for t in list(self._data.values()) if t.user_id == user_id]

    def remove(self, user_id, name):
        with self._lock:
            for key, t in list(self._data.items()):
                if t.user_id == user_id and t.name == name:
                    del self._data[key]
                    return True
            return False


_SCHEMA = """
CREATE TABLE IF NOT EXISTS personal_tokens (
    id_hash     text PRIMARY KEY,
    user_id     text NOT NULL,
    name        text NOT NULL,
    created_at  bigint NOT NULL,
    expires_at  bigint NOT NULL,
    UNIQUE (user_id, name)
);
"""
_COLUMNS = list(PersonalToken.__dataclass_fields__)


class PostgresTokenStore:
    """In the session database: shared across uvicorn workers."""

    def __init__(self, dsn: str):
        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool

        self._pool = ConnectionPool(dsn, min_size=1, max_size=4, open=True,
                                    kwargs={"autocommit": True, "row_factory": dict_row})
        with self._tx() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(4242003)")  # workers start concurrently
            cur.execute(_SCHEMA)

    @contextmanager
    def _tx(self) -> Iterator[Any]:
        with self._pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
            yield cur

    def add(self, token):
        from psycopg.errors import UniqueViolation

        values = asdict(token)
        try:
            with self._tx() as cur:
                cur.execute("DELETE FROM personal_tokens WHERE expires_at < %s", (int(time.time()),))
                cur.execute(f"INSERT INTO personal_tokens ({', '.join(_COLUMNS)}) "
                            f"VALUES ({', '.join(['%s'] * len(_COLUMNS))})", [values[c] for c in _COLUMNS])
        except UniqueViolation as exc:
            raise TokenExistsError(token.name) from exc

    def find(self, id_hash):
        with self._tx() as cur:
            cur.execute("SELECT * FROM personal_tokens WHERE id_hash = %s", (id_hash,))
            row = cur.fetchone()
            return PersonalToken(**row) if row else None

    def list(self, user_id):
        with self._tx() as cur:
            cur.execute("SELECT * FROM personal_tokens WHERE user_id = %s", (user_id,))
            return [PersonalToken(**row) for row in cur.fetchall()]

    def remove(self, user_id, name):
        with self._tx() as cur:
            cur.execute("DELETE FROM personal_tokens WHERE user_id = %s AND name = %s", (user_id, name))
            return cur.rowcount > 0


def build_token_store(kind: str, dsn: str | None) -> TokenStore:
    """The same backend as the sessions (AUTH_SESSION_STORE, AUTH_SESSION_DB_URL)."""
    if kind == "memory":
        return MemoryTokenStore()
    if kind == "postgres":
        if not dsn:
            raise RuntimeError("AUTH_SESSION_DB_URL(_FILE) is required for personal access tokens")
        return PostgresTokenStore(dsn)
    raise RuntimeError(f"unknown AUTH_SESSION_STORE {kind!r}")


# --- resolving a PAT in /verify ------------------------------------------------------------------

class LocalTokens:
    """PATs kept by authsvc, as a TokenBackend (agenticwf.auth.tokens). ``grants(user_id)`` is the
    provider's: {"user": {id, username, name, email, enabled} or None, "roles": [...],
    "permissions": [...]}, what an access token of the user would carry now; it raises
    ManagementError(404) for an unknown user, ManagementUnavailableError when it cannot tell."""

    accepts_bearer = True

    def __init__(self, store: TokenStore, grants: Callable[[str], dict], settings: Settings,
                 clock: Callable[[], float] = time.time, audience: str | None = None):
        self.store = store
        self.fetch_grants = grants
        self.settings = settings
        self.audience = audience if audience is not None else settings.default_audience
        self.clock = clock
        self._grants: dict[str, tuple[float, dict]] = {}
        self._lock = threading.Lock()

    def issue(self, user_id: str, name: str, expires_at: int) -> tuple[str, PersonalToken]:
        """A new token; the raw value is returned once and never stored."""
        raw = PAT_PREFIX + secrets.token_urlsafe(32)
        token = PersonalToken(hash_token(raw), user_id, name, int(self.clock()), expires_at)
        self.store.add(token)
        return raw, token

    def grants(self, user_id: str) -> dict:
        """The owner's account and effective roles, cached; on an Admin API failure the last known,
        else AuthUnavailableError."""
        now = self.clock()
        with self._lock:
            cached = self._grants.get(user_id)
        if cached and cached[0] > now:
            return cached[1]
        try:
            found = self.fetch_grants(user_id)
        except ManagementError as exc:
            if exc.status != 404:
                raise AuthUnavailableError(str(exc)) from exc
            found = {"user": None, "roles": [], "permissions": []}   # the user was deleted
        except ManagementUnavailableError as exc:
            if not cached:
                raise AuthUnavailableError(str(exc)) from exc
            log.warning("roles of %s unknown (%s); using the last known", user_id, exc)
            with self._lock:
                self._grants[user_id] = (now + RETRY_AFTER_FAILURE, cached[1])
            return cached[1]
        with self._lock:
            self._grants[user_id] = (now + self.settings.group_cache_ttl, found)
        return found

    # -- TokenBackend ------------------------------------------------------------------------------
    def list(self, user_id: str) -> list[dict]:
        return [public_view(t) for t in self.store.list(user_id)]

    def create(self, user_id: str, name: str, expires_at: int) -> tuple[str, dict]:
        try:
            raw, token = self.issue(user_id, name, expires_at)
        except TokenExistsError:
            raise ManagementError(409, "A token with this name already exists.") from None
        return raw, public_view(token)

    def delete(self, user_id: str, name: str) -> None:
        if not self.store.remove(user_id, name):
            raise ManagementError(404, "No such token.")

    def resolve(self, raw: str) -> AuthContext:
        now = int(self.clock())
        token = self.store.find(hash_token(raw))
        if token is None or token.expires_at <= now:
            raise AuthenticationError("invalid_token", "Personal access token unknown, revoked or expired")
        grants = self.grants(token.user_id)
        user = grants.get("user")
        if not user or not user.get("enabled", True):
            raise AuthenticationError("invalid_token", "The token's account is disabled or deleted")
        return AuthContext(
            subject=token.user_id,
            user_id=token.user_id,
            client_id=self.settings.cli_client_id,
            roles=frozenset(grants.get("roles") or ()),
            scopes=frozenset(grants.get("permissions") or ()),
            audience=tuple(a for a in (self.audience,) if a),
            token_id=f"pat:{token.id_hash[:16]}",
            expires_at=min(token.expires_at, now + CONTEXT_TTL),
            auth_method="bearer",
            username=user.get("username") or user.get("email") or None,
            name=user.get("name") or None,
            email=user.get("email") or None,
        )


def public_view(token: PersonalToken) -> dict:
    """Never the token value (authsvc does not have it anyway)."""
    return {"name": token.name, "created_at": token.created_at, "expires_at": token.expires_at}
