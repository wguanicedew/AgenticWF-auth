"""Groups for the web UI (/auth/groups): Logto organizations, managed through the Management API.

A group is a Logto organization. Its members hold the organization role AUTH_GROUP_MEMBER_ROLE
(default `member`); its admins also hold AUTH_GROUP_ADMIN_ROLE (default `admin`).

    everyone (approved)   list the groups, see which are theirs, request to join one, cancel the
                          request, leave a group, list the members of their own groups
    a group's admins      add members (by email), remove them, make them admins or not, approve or
                          decline requests, rename the group
    `admin` scope         all of the above for every group; create and delete groups

A group keeps at least one admin unless an `admin` scope holder changes it. Join requests are kept
here (the session database), since Logto has none.

The backends learn a user's groups from the AuthContext: /verify adds the user's organizations
(``AuthContext.organizations``), looked up through the Management API and cached per worker for
AUTH_GROUP_CACHE_TTL seconds, so a membership change applies within that time without a new
sign-in. The KB shares with them as ``org:<id>``.

Only a browser session may use /auth/groups (as for /auth/tokens).
"""

from __future__ import annotations

import logging
import re
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from typing import Any, Callable, Iterator, Protocol

from fastapi import APIRouter, Body, Request
from fastapi.responses import JSONResponse, Response

from agenticwf.auth.authn import TokenVerifier
from agenticwf.auth.config import Settings
from agenticwf.auth.sessions import SessionManager
from agenticwf.auth.tokens import ManagementClient, ManagementError, ManagementUnavailableError, signed_in

log = logging.getLogger("authsvc.groups")

ADMIN_SCOPE = "admin"
NAME_RE = re.compile(r"\S.{0,127}", re.S)
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+")
RETRY_AFTER_FAILURE = 10


# --- memberships ---------------------------------------------------------------------------------

class Memberships:
    """Each user's organizations ({org id: {"name", "roles"}}), cached for `ttl` seconds. When the
    Management API fails, the last known answer stays (or none), retried after a few seconds."""

    def __init__(self, management: ManagementClient, ttl: int = 60, clock: Callable[[], float] = time.time):
        self.management = management
        self.ttl = ttl
        self.clock = clock
        self._cache: dict[str, tuple[float, dict[str, dict]]] = {}
        self._lock = threading.Lock()

    def of(self, user_id: str, fresh: bool = False) -> dict[str, dict]:
        now = self.clock()
        with self._lock:
            cached = self._cache.get(user_id)
        if cached and not fresh and cached[0] > now:
            return cached[1]
        try:
            found = {o["id"]: {"name": o.get("name") or o["id"], "roles": {r["name"] for r in o.get("organizationRoles") or ()}}
                     for o in self.management.user_organizations(user_id)}
        except (ManagementError, ManagementUnavailableError) as exc:
            if fresh:
                raise
            log.warning("groups of %s unknown (%s); using the last known", user_id, exc)
            found = cached[1] if cached else {}
            with self._lock:
                self._cache[user_id] = (now + RETRY_AFTER_FAILURE, found)
            return found
        with self._lock:
            self._cache[user_id] = (now + self.ttl, found)
        return found

    def names(self, user_id: str) -> dict[str, str]:
        return {org_id: m["name"] for org_id, m in self.of(user_id).items()}

    def forget(self, *user_ids: str) -> None:
        with self._lock:
            for user_id in user_ids:
                self._cache.pop(user_id, None)


# --- join requests -------------------------------------------------------------------------------

@dataclass(frozen=True)
class JoinRequest:
    org_id: str
    user_id: str
    name: str
    email: str
    message: str
    created_at: int


class RequestStore(Protocol):
    def list(self, org_id: str | None = None, user_id: str | None = None) -> list[JoinRequest]: ...
    def add(self, request: JoinRequest) -> None: ...
    def remove(self, org_id: str, user_id: str) -> bool: ...
    def remove_group(self, org_id: str) -> None: ...


class MemoryRequestStore:
    """For tests and single-process development only."""

    def __init__(self) -> None:
        self._data: dict[tuple[str, str], JoinRequest] = {}
        self._lock = threading.Lock()

    def list(self, org_id=None, user_id=None):
        return sorted((r for r in list(self._data.values())
                       if (org_id is None or r.org_id == org_id) and (user_id is None or r.user_id == user_id)),
                      key=lambda r: r.created_at)

    def add(self, request):
        with self._lock:
            self._data[(request.org_id, request.user_id)] = request

    def remove(self, org_id, user_id):
        with self._lock:
            return self._data.pop((org_id, user_id), None) is not None

    def remove_group(self, org_id):
        with self._lock:
            for key in [k for k in self._data if k[0] == org_id]:
                del self._data[key]


_SCHEMA = """
CREATE TABLE IF NOT EXISTS group_requests (
    org_id      text NOT NULL,
    user_id     text NOT NULL,
    name        text NOT NULL DEFAULT '',
    email       text NOT NULL DEFAULT '',
    message     text NOT NULL DEFAULT '',
    created_at  bigint NOT NULL,
    PRIMARY KEY (org_id, user_id)
);
CREATE INDEX IF NOT EXISTS group_requests_user_idx ON group_requests (user_id);
"""
_COLUMNS = list(JoinRequest.__dataclass_fields__)


class PostgresRequestStore:
    """In the session database: shared across uvicorn workers."""

    def __init__(self, dsn: str):
        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool

        self._pool = ConnectionPool(dsn, min_size=1, max_size=4, open=True,
                                    kwargs={"autocommit": True, "row_factory": dict_row})
        with self._tx() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(4242002)")  # workers start concurrently
            cur.execute(_SCHEMA)

    @contextmanager
    def _tx(self) -> Iterator[Any]:
        with self._pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
            yield cur

    def list(self, org_id=None, user_id=None):
        clauses, args = [], []
        for column, value in (("org_id", org_id), ("user_id", user_id)):
            if value is not None:
                clauses.append(f"{column} = %s")
                args.append(value)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._tx() as cur:
            cur.execute(f"SELECT * FROM group_requests{where} ORDER BY created_at", args)
            return [JoinRequest(**row) for row in cur.fetchall()]

    def add(self, request):
        values = asdict(request)
        with self._tx() as cur:
            cur.execute(
                f"INSERT INTO group_requests ({', '.join(_COLUMNS)}) VALUES ({', '.join(['%s'] * len(_COLUMNS))})"
                " ON CONFLICT (org_id, user_id) DO UPDATE SET message = EXCLUDED.message, created_at = EXCLUDED.created_at",
                [values[c] for c in _COLUMNS],
            )

    def remove(self, org_id, user_id):
        with self._tx() as cur:
            cur.execute("DELETE FROM group_requests WHERE org_id = %s AND user_id = %s", (org_id, user_id))
            return cur.rowcount > 0

    def remove_group(self, org_id):
        with self._tx() as cur:
            cur.execute("DELETE FROM group_requests WHERE org_id = %s", (org_id,))


def build_request_store(kind: str, dsn: str | None) -> RequestStore:
    """The same backend as the sessions (AUTH_SESSION_STORE, AUTH_SESSION_DB_URL)."""
    if kind == "memory":
        return MemoryRequestStore()
    if kind == "postgres":
        if not dsn:
            raise RuntimeError("AUTH_SESSION_DB_URL(_FILE) is required for group requests")
        return PostgresRequestStore(dsn)
    raise RuntimeError(f"unknown AUTH_SESSION_STORE {kind!r}")


# --- /auth/groups --------------------------------------------------------------------------------

class GroupError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _no_store(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    return response


def _error(status: int, error: str, description: str) -> Response:
    return _no_store(JSONResponse({"error": error, "error_description": description}, status_code=status))


def _text(body: dict, key: str, limit: int) -> str:
    value = body.get(key, "")
    if not isinstance(value, str) or len(value) > limit:
        raise GroupError(400, f"{key}: text of at most {limit} characters.")
    return value.strip()


def build_router(settings: Settings, sessions: SessionManager, verifier: TokenVerifier, management: ManagementClient,
                 memberships: Memberships, requests: RequestStore,
                 required_scopes: frozenset[str] = frozenset()) -> APIRouter:
    router = APIRouter(prefix="/auth/groups")
    role_ids: dict[str, str] = {}

    def role_id(name: str) -> str:
        if name not in role_ids:
            role_ids.update(management.organization_role_ids())
        if name not in role_ids:
            raise GroupError(409, f"Logto has no organization role {name!r}: create it (Organization template) "
                                  "or restart the container to have it created.")
        return role_ids[name]

    class Caller:
        def __init__(self, session, scopes: set[str]):
            self.id = session.subject
            info = session.user_info or {}
            self.name = info.get("name") or info.get("username") or ""
            self.email = info.get("email") or ""
            self.is_admin = ADMIN_SCOPE in scopes
            self.groups = memberships.of(self.id, fresh=True)   # what the caller may do: never stale

        def member(self, org_id: str) -> bool:
            return org_id in self.groups

        def manages(self, org_id: str) -> bool:
            return self.is_admin or settings.group_admin_role in self.groups.get(org_id, {}).get("roles", ())

    def handle(fn: Callable[..., Any]) -> Callable[..., Response]:
        """Run a route as the signed-in caller; errors become JSON answers."""
        def run(request: Request, *args, **kwargs) -> Response:
            found = signed_in(request, settings, sessions, verifier, required_scopes, "manage groups")
            if isinstance(found, Response):
                return found
            try:
                result = fn(Caller(*found), *args, **kwargs)
            except GroupError as exc:
                return _error(exc.status, "group_error", str(exc))
            except ManagementUnavailableError:
                return _error(503, "temporarily_unavailable", "Identity service unavailable.")
            except ManagementError as exc:
                return _error(exc.status, "group_error", str(exc))
            if isinstance(result, Response):
                return result
            return _no_store(JSONResponse(result))
        return run

    def require_manager(caller: Caller, org_id: str) -> None:
        if not caller.manages(org_id):
            raise GroupError(403, "Only the group's admins can do this.")

    def members_of(org_id: str) -> list[dict]:
        out = []
        for user in management.organization_members(org_id):
            roles = {r["name"] for r in user.get("organizationRoles") or ()}
            out.append({"user_id": user["id"], "name": user.get("name") or user.get("username") or "",
                        "email": user.get("primaryEmail") or "", "admin": settings.group_admin_role in roles})
        return sorted(out, key=lambda m: (not m["admin"], (m["name"] or m["email"]).lower()))

    def keep_an_admin(caller: Caller, org_id: str, user_id: str) -> None:
        """A group admin cannot leave the group without admins; the `admin` scope can."""
        if caller.is_admin:
            return
        admins = [m["user_id"] for m in members_of(org_id) if m["admin"]]
        if admins == [user_id]:
            raise GroupError(409, "The group needs another admin first.")

    def roles_for(admin: bool) -> list[str]:
        return [role_id(settings.group_member_role)] + ([role_id(settings.group_admin_role)] if admin else [])

    def view(org: dict, caller: Caller, pending: dict[str, int], mine: set[str]) -> dict:
        org_id = org["id"]
        out = {"id": org_id, "group": f"org:{org_id}", "name": org.get("name") or org_id,
               "description": org.get("description") or "", "member": caller.member(org_id),
               "admin": settings.group_admin_role in caller.groups.get(org_id, {}).get("roles", ()),
               "requested": org_id in mine, "can_manage": caller.manages(org_id)}
        if out["can_manage"]:
            out["pending"] = pending.get(org_id, 0)
        return out

    @router.get("")
    def list_groups(request: Request) -> Response:
        def run(caller: Caller):
            mine = {r.org_id for r in requests.list(user_id=caller.id)}
            pending: dict[str, int] = {}
            for r in requests.list():
                pending[r.org_id] = pending.get(r.org_id, 0) + 1
            groups = [view(o, caller, pending, mine) for o in management.organizations()]
            groups.sort(key=lambda g: (not g["member"], g["name"].lower()))
            return {"groups": groups, "can_create": caller.is_admin}
        return handle(run)(request)

    @router.post("")
    def create_group(request: Request, body: dict = Body(...)) -> Response:
        def run(caller: Caller):
            if not caller.is_admin:
                raise GroupError(403, "Only administrators can create groups.")
            name = _text(body, "name", 128)
            if not NAME_RE.fullmatch(name):
                raise GroupError(400, "A group needs a name.")
            org = management.create_organization(name, _text(body, "description", 1000))
            log.info("group %s (%s) created by %s", org["id"], name, caller.id)
            return _no_store(JSONResponse(view(org, caller, {}, set()), status_code=201))
        return handle(run)(request)

    @router.patch("/{org_id}")
    def change_group(request: Request, org_id: str, body: dict = Body(...)) -> Response:
        def run(caller: Caller):
            require_manager(caller, org_id)
            fields = {}
            if "name" in body:
                fields["name"] = _text(body, "name", 128)
                if not NAME_RE.fullmatch(fields["name"]):
                    raise GroupError(400, "A group needs a name.")
            if "description" in body:
                fields["description"] = _text(body, "description", 1000)
            org = management.update_organization(org_id, fields) if fields else management.organization(org_id)
            memberships.forget(*(m["user_id"] for m in members_of(org_id)))   # the name travels with the context
            return view(org, caller, {}, set())
        return handle(run)(request)

    @router.delete("/{org_id}")
    def delete_group(request: Request, org_id: str) -> Response:
        def run(caller: Caller):
            if not caller.is_admin:
                raise GroupError(403, "Only administrators can delete groups.")
            members = [m["user_id"] for m in members_of(org_id)]
            management.delete_organization(org_id)
            requests.remove_group(org_id)
            memberships.forget(*members)
            log.info("group %s deleted by %s", org_id, caller.id)
            return Response(status_code=204)
        return handle(run)(request)

    @router.get("/{org_id}/members")
    def list_members(request: Request, org_id: str) -> Response:
        def run(caller: Caller):
            if not (caller.member(org_id) or caller.manages(org_id)):
                raise GroupError(403, "Only the group's members can see who is in it.")
            out: dict[str, Any] = {"group": view(management.organization(org_id), caller, {}, set()),
                                   "members": members_of(org_id)}
            if caller.manages(org_id):
                out["requests"] = [{"user_id": r.user_id, "name": r.name, "email": r.email, "message": r.message,
                                    "created_at": r.created_at} for r in requests.list(org_id=org_id)]
            return out
        return handle(run)(request)

    @router.post("/{org_id}/members")
    def add_member(request: Request, org_id: str, body: dict = Body(...)) -> Response:
        def run(caller: Caller):
            require_manager(caller, org_id)
            email = _text(body, "email", 320)
            if not EMAIL_RE.fullmatch(email):
                raise GroupError(400, "An email address is needed.")
            user = management.find_user(email)
            if user is None:
                raise GroupError(404, "No user with this email: they need to sign up first.")
            if any(m["user_id"] == user["id"] for m in members_of(org_id)):
                raise GroupError(409, "Already a member.")
            management.add_member(org_id, user["id"], roles_for(bool(body.get("admin"))))
            requests.remove(org_id, user["id"])
            memberships.forget(user["id"])
            log.info("group %s: %s added by %s", org_id, user["id"], caller.id)
            return _no_store(JSONResponse({"members": members_of(org_id)}, status_code=201))
        return handle(run)(request)

    @router.patch("/{org_id}/members/{user_id}")
    def change_member(request: Request, org_id: str, user_id: str, body: dict = Body(...)) -> Response:
        def run(caller: Caller):
            require_manager(caller, org_id)
            if not isinstance(body.get("admin"), bool):
                raise GroupError(400, "admin: true or false.")
            if not any(m["user_id"] == user_id for m in members_of(org_id)):
                raise GroupError(404, "Not a member of this group.")
            if not body["admin"]:
                keep_an_admin(caller, org_id, user_id)
            management.set_member_roles(org_id, user_id, roles_for(body["admin"]))
            memberships.forget(user_id)
            log.info("group %s: %s admin=%s by %s", org_id, user_id, body["admin"], caller.id)
            return {"members": members_of(org_id)}
        return handle(run)(request)

    @router.delete("/{org_id}/members/{user_id}")
    def remove_member(request: Request, org_id: str, user_id: str) -> Response:
        def run(caller: Caller):
            if user_id != caller.id:
                require_manager(caller, org_id)
            elif not caller.member(org_id):
                raise GroupError(404, "Not a member of this group.")
            keep_an_admin(caller, org_id, user_id)
            management.remove_member(org_id, user_id)
            memberships.forget(user_id)
            log.info("group %s: %s removed by %s", org_id, user_id, caller.id)
            return Response(status_code=204)
        return handle(run)(request)

    @router.post("/{org_id}/requests")
    def request_to_join(request: Request, org_id: str, body: dict = Body(default={})) -> Response:
        def run(caller: Caller):
            if caller.member(org_id):
                raise GroupError(409, "Already a member.")
            management.organization(org_id)   # 404 for a group that does not exist
            requests.add(JoinRequest(org_id, caller.id, caller.name, caller.email,
                                     _text(body or {}, "message", 500), int(time.time())))
            log.info("group %s: %s asks to join", org_id, caller.id)
            return _no_store(JSONResponse({"requested": True}, status_code=201))
        return handle(run)(request)

    @router.delete("/{org_id}/requests")
    def cancel_request(request: Request, org_id: str) -> Response:
        def run(caller: Caller):
            if not requests.remove(org_id, caller.id):
                raise GroupError(404, "No request to cancel.")
            return Response(status_code=204)
        return handle(run)(request)

    @router.post("/{org_id}/requests/{user_id}")
    def answer_request(request: Request, org_id: str, user_id: str, body: dict = Body(...)) -> Response:
        def run(caller: Caller):
            require_manager(caller, org_id)
            if not isinstance(body.get("approve"), bool):
                raise GroupError(400, "approve: true or false.")
            if not any(r.user_id == user_id for r in requests.list(org_id=org_id)):
                raise GroupError(404, "No such request.")
            if body["approve"] and not any(m["user_id"] == user_id for m in members_of(org_id)):
                management.add_member(org_id, user_id, roles_for(False))
                memberships.forget(user_id)
            requests.remove(org_id, user_id)
            log.info("group %s: request of %s %s by %s", org_id, user_id,
                     "approved" if body["approve"] else "declined", caller.id)
            return {"members": members_of(org_id)}
        return handle(run)(request)

    return router
