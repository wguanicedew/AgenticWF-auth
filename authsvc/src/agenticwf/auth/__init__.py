"""AgenticWF auth service.

Pipeline for every request:

    Bearer token --(authn)--> verified claims --(context)--> AuthContext --(authz)--> Decision

The service is used by Caddy ``forward_auth`` (see ``agenticwf.auth.app``); backend
services consume the resulting signed AuthContext via ``agenticwf.auth.client``.
"""

from agenticwf.auth.context import AuthContext

__all__ = ["AuthContext"]
