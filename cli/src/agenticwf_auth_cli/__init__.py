"""AgenticWF CLI client.

    from agenticwf_auth_cli import Client
    api = Client.from_env()
    print(api.request("GET", "/api/v1/me"))
    headers = {"Authorization": f"Bearer {api.access_token()}"}   # e.g. for `requests`

    base, token = service_access("kb", "/kb")    # a service's URL, and its tokens (refreshed)
"""

from agenticwf_auth_cli.client import ApiError, AuthError, Client, Config, service_access

__all__ = ["ApiError", "AuthError", "Client", "Config", "service_access"]
