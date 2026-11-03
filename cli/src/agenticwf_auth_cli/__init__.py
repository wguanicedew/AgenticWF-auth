"""AgenticWF CLI client.

    from agenticwf_auth_cli import Client
    api = Client.from_env()
    print(api.request("GET", "/api/v1/me"))
    headers = {"Authorization": f"Bearer {api.access_token()}"}   # e.g. for `requests`

    base, token = service_access("kb", "/kb")    # a service's URL, and its tokens (refreshed)
    httpx.Client(verify=ssl_context())           # the system's CAs plus CERN's (tls.py)
"""

from agenticwf_auth_cli.client import (ApiError, AuthError, Client, Config, describe, service_access,
                                      sign_in_settings)
from agenticwf_auth_cli.tls import ssl_context

__all__ = ["ApiError", "AuthError", "Client", "Config", "describe", "service_access", "sign_in_settings",
           "ssl_context"]
