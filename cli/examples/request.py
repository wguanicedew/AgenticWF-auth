"""Calling the AgenticWF API from a Python script.

Prerequisite (once per machine/user):   agenticwf login
Machine/automation use instead:         export AGENTICWF_CLIENT_SECRET=...   (M2M app)

    export AGENTICWF_AUTH_URL=https://auth.example.org
    export AGENTICWF_API_URL=https://app.example.org
    export AGENTICWF_CLIENT_ID=<Logto native app id>
    export AGENTICWF_RESOURCE=https://api.example.org
    export AGENTICWF_SCOPES="openid offline_access app:access agent:use knowledge:read"
    python request.py
"""

import requests  # any HTTP library works; the client only supplies the token

from agenticwf_auth_cli import Client

api = Client.from_env()

# 1. Built-in helper (standard library only)
print(api.request("GET", "/api/v1/me"))

# 2. Bring your own HTTP library: just add the bearer token
response = requests.post(
    f"{api.config.api_url}/api/v1/sessions/demo/messages",
    json={"text": "summarise yesterday's runs"},
    headers={"Authorization": f"Bearer {api.access_token()}"},
    timeout=60,
)
response.raise_for_status()
print(response.json())

# 3. Follow live updates (Server-Sent Events) from a script
with requests.get(
    f"{api.config.api_url}/api/v1/events",
    headers={"Authorization": f"Bearer {api.access_token()}", "Accept": "text/event-stream"},
    stream=True,
    timeout=(10, None),
) as stream:
    for line in stream.iter_lines(decode_unicode=True):
        if line.startswith("data:"):
            print(line[5:].strip())
