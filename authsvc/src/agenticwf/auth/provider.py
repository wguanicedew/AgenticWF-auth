"""The identity-provider plug-in of the auth service.

authsvc itself is provider-neutral. A provider package (AgenticWF-auth-keycloak,
AgenticWF-auth-logto) builds a ``Provider`` from its own settings and passes it to
``agenticwf.auth.app.create_app``:

    claims          verified access-token claims -> AuthContext (where the provider keeps roles,
                    API permissions, organizations, the user's name)
    check_claims    extra checks of an access token, raising AuthenticationError (e.g. its type)
    endpoints       the OIDC endpoints of browser login (authorization, token, revocation, end session)
    directory       the provider's admin API, as a ``Directory`` (groups, users): /auth/groups and the
                    groups in the AuthContext
    tokens          personal access tokens, as a ``TokenBackend``: /auth/tokens, and PATs in /verify
    lookup_profiles the access token lacks username/name/email: look them up in the directory
    client_config   extra fields of /auth/config for the `agenticwf` CLI (e.g. `resource`,
                    `pat_token_type`)
    return_blocked  path prefixes on the application's origin that belong to the provider (a single
                    shared hostname): never a place to send the browser back to after sign-in

Without a provider (``Provider()``), authsvc verifies bearer tokens of any OIDC issuer with
AuthContext.from_claims, and offers no browser login, groups or personal access tokens.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from agenticwf.auth.context import AuthContext
    from agenticwf.auth.directory import Directory
    from agenticwf.auth.tokens import TokenBackend


@dataclass(frozen=True)
class OIDCEndpoints:
    """Where authsvc's browser login talks to the provider.

    ``authorization`` and ``end_session`` are public (the browser is sent there); ``token`` and
    ``revocation`` are server-to-server, usually the provider inside the container, called with
    ``internal_headers`` (e.g. the public Host, so the provider builds the public issuer)."""

    authorization: str
    token: str
    revocation: str | None = None
    end_session: str | None = None
    auth_params: dict[str, str] = field(default_factory=dict)   # extra authorization request parameters
    token_params: dict[str, str] = field(default_factory=dict)  # extra code-exchange / refresh parameters
    internal_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Provider:
    name: str = "oidc"
    claims: Callable[[dict[str, Any]], "AuthContext"] | None = None
    check_claims: Callable[[dict[str, Any]], None] | None = None
    endpoints: OIDCEndpoints | None = None
    directory: "Directory | None" = None
    tokens: "TokenBackend | None" = None
    lookup_profiles: bool = False
    client_config: dict[str, Any] = field(default_factory=dict)
    return_blocked: tuple[str, ...] = ()
