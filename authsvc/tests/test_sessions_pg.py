"""PostgresSessionStore against a real database; set AUTHSVC_TEST_PG_DSN to run."""

import os
import threading
import time
from dataclasses import replace

import pytest

from agenticwf.auth.sessions import WebSession

DSN = os.environ.get("AUTHSVC_TEST_PG_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="AUTHSVC_TEST_PG_DSN not set")


@pytest.fixture
def store():
    from agenticwf.auth.sessions import PostgresSessionStore

    s = PostgresSessionStore(DSN)
    with s._tx() as cur:
        cur.execute("TRUNCATE web_sessions")
    return s


def session(id_hash="h1"):
    now = int(time.time())
    return WebSession(id_hash=id_hash, subject="u1", access_token="at", access_expires_at=now + 10,
                      refresh_token="rt", id_token=None, created_at=now, last_seen_at=now,
                      expires_at=now + 100, user_info={"name": "Alice"})


def test_crud(store):
    store.create(session())
    assert store.get("h1").user_info == {"name": "Alice"}
    store.touch("h1", 123)
    assert store.get("h1").last_seen_at == 123
    assert store.delete("h1").subject == "u1"
    assert store.get("h1") is None


def test_update_serialises_concurrent_refresh(store):
    store.create(session())
    calls = []

    def refresh(current):
        if current.access_token != "at":
            return current  # someone else already refreshed
        calls.append(1)
        time.sleep(0.2)
        return replace(current, access_token="at2")

    threads = [threading.Thread(target=store.update, args=("h1", refresh)) for _ in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(calls) == 1 and store.get("h1").access_token == "at2"


def test_update_none_deletes(store):
    store.create(session())
    assert store.update("h1", lambda s: None) is None
    assert store.get("h1") is None
