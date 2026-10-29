"""Authorization: route-level policy evaluated against an AuthContext.

Policy file (YAML), first matching rule wins, unmatched requests are denied::

    # Scopes every authenticated request needs on non-public routes. Used as the
    # "account approved" marker: new users have no roles, hence no app:access, and are
    # reported as pending until an admin assigns a role that carries it.
    required_scopes: [app:access]

    rules:
      - path: /healthz
        public: true
      - path: /api/v1/datasets/**
        methods: [GET]
        scopes: [dataset:read]          # all required
      - path: /api/v1/compute/**
        methods: [POST]
        scopes: [compute:submit]
        roles_any: [researcher, admin]  # at least one required
        organization: true              # token must be organization-scoped
      - path: /api/v1/me
        allow_pending: true             # reachable before approval (e.g. "whoami")
      - path: /api/**
        authenticated: true

Path patterns: ``*`` matches one path segment, ``**`` matches any remainder.
Fine-grained, data-level checks (e.g. which knowledge base a user may query) belong in
the backend, which reads the same AuthContext.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

import yaml

from agenticwf.auth.context import AuthContext

_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}


class PolicyError(Exception):
    """The policy file is invalid."""


class InvalidPathError(Exception):
    """The request path is ambiguous and is rejected before policy evaluation."""


def normalize_path(uri: str) -> str:
    """Return the decoded path of ``uri``; reject dot segments and encoded separators."""
    # Not urlsplit(): it would parse `//host/x` as a network location and drop `host`.
    raw = uri.split("?", 1)[0].split("#", 1)[0] or "/"
    if re.search(r"%2f|%5c", raw, re.IGNORECASE):
        raise InvalidPathError("encoded path separators are not allowed")
    path = unquote(raw)
    if "\\" in path or "\x00" in path:
        raise InvalidPathError("invalid characters in path")
    if any(seg in (".", "..") for seg in path.split("/")):
        raise InvalidPathError("dot segments are not allowed")
    path = re.sub(r"/{2,}", "/", path)
    return path if path.startswith("/") else "/" + path


def _compile(pattern: str) -> re.Pattern[str]:
    if not pattern.startswith("/"):
        raise PolicyError(f"path pattern must start with '/': {pattern!r}")
    segments = [s for s in pattern.split("/") if s]
    tail = ""
    if segments and segments[-1] == "**":
        segments.pop()
        tail = "(?:/.*)?"  # `/api/**` matches `/api` and everything below it
    if "**" in segments:
        raise PolicyError(f"'**' is only allowed as the last segment: {pattern!r}")
    body = "".join("/" + "[^/]+".join(re.escape(part) for part in seg.split("*")) for seg in segments)
    return re.compile(f"^{body}{tail or '/?'}$")


@dataclass(frozen=True)
class Rule:
    path: str
    methods: frozenset[str] = frozenset()
    public: bool = False
    scopes: frozenset[str] = frozenset()
    roles_any: frozenset[str] = frozenset()
    organization: bool = False
    allow_machine: bool = True
    allow_pending: bool = False  # skip the policy-wide required_scopes
    regex: re.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "regex", _compile(self.path))

    def matches(self, method: str, path: str) -> bool:
        return (not self.methods or method in self.methods) and bool(self.regex.match(path))

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        unknown = set(data) - {"path", "methods", "public", "authenticated", "scopes", "roles_any", "organization",
                         "allow_machine", "allow_pending"}
        if unknown:
            raise PolicyError(f"unknown rule keys {sorted(unknown)} in {data!r}")
        if "path" not in data:
            raise PolicyError(f"rule without 'path': {data!r}")
        methods = frozenset(m.upper() for m in data.get("methods") or ())
        if methods - _METHODS:
            raise PolicyError(f"unknown methods {sorted(methods - _METHODS)} in {data!r}")
        rule = cls(
            path=data["path"],
            methods=methods,
            public=bool(data.get("public", False)),
            scopes=frozenset(data.get("scopes") or ()),
            roles_any=frozenset(data.get("roles_any") or ()),
            organization=bool(data.get("organization", False)),
            allow_machine=bool(data.get("allow_machine", True)),
            allow_pending=bool(data.get("allow_pending", False)),
        )
        if rule.public and (rule.scopes or rule.roles_any or rule.organization):
            raise PolicyError(f"public rule cannot also require scopes/roles/organization: {data!r}")
        return rule


# Decision codes, used as the `error` of the HTTP response.
MISSING_TOKEN = "missing_token"
INSUFFICIENT_SCOPE = "insufficient_scope"
APPROVAL_PENDING = "approval_pending"


@dataclass(frozen=True)
class Decision:
    allowed: bool
    status: int  # 200, 401 or 403
    reason: str
    rule: Rule | None = None
    code: str = ""

    @property
    def public(self) -> bool:
        return self.rule is not None and self.rule.public


class Policy:
    def __init__(self, rules: list[Rule], required_scopes: frozenset[str] = frozenset()):
        self.rules = rules
        self.required_scopes = required_scopes

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
            raise PolicyError("policy must be a mapping with a 'rules' list")
        unknown = set(data) - {"rules", "required_scopes"}
        if unknown:
            raise PolicyError(f"unknown policy keys {sorted(unknown)}")
        required = data.get("required_scopes") or []
        if not isinstance(required, list):
            raise PolicyError("required_scopes must be a list")
        return cls([Rule.from_dict(r) for r in data["rules"]], frozenset(required))

    def is_approved(self, ctx: AuthContext) -> bool:
        return self.required_scopes <= ctx.scopes

    @classmethod
    def load(cls, path: Path) -> "Policy":
        with open(path) as fh:
            return cls.from_dict(yaml.safe_load(fh))

    def match(self, method: str, path: str) -> Rule | None:
        method = method.upper()
        return next((r for r in self.rules if r.matches(method, path)), None)

    def authorize(self, ctx: AuthContext | None, method: str, path: str) -> Decision:
        rule = self.match(method, path)
        if rule is not None and rule.public:
            return Decision(True, 200, "public route", rule)
        if ctx is None:
            # Default deny; say 401 to anonymous callers so clients know to log in.
            return Decision(False, 401, "authentication required", rule, MISSING_TOKEN)
        if not (rule is not None and rule.allow_pending) and not self.is_approved(ctx):
            return Decision(False, 403, "account is awaiting approval", rule, APPROVAL_PENDING)
        if rule is None:
            return Decision(False, 403, "no policy rule grants access to this route", None, INSUFFICIENT_SCOPE)
        if ctx.is_machine and not rule.allow_machine:
            return Decision(False, 403, "machine clients are not allowed on this route", rule, INSUFFICIENT_SCOPE)
        if rule.organization and not ctx.organization_id:
            return Decision(False, 403, "an organization-scoped token is required", rule, INSUFFICIENT_SCOPE)
        missing = rule.scopes - ctx.scopes
        if missing:
            return Decision(False, 403, f"missing scopes: {' '.join(sorted(missing))}", rule, INSUFFICIENT_SCOPE)
        if rule.roles_any and not ctx.has_any_role(*rule.roles_any):
            return Decision(False, 403, f"requires one of roles: {', '.join(sorted(rule.roles_any))}", rule,
                            INSUFFICIENT_SCOPE)
        return Decision(True, 200, "allowed", rule)
