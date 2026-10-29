# agenticwf-auth-client

The `agenticwf` command for [AgenticWF](https://github.com/InnovateAILab/AgenticWF): sign-in
(OAuth device flow via Logto), access tokens, and calls to the AgenticWF API. Standard library only.

```bash
pip install agenticwf-auth-client
agenticwf login                 # opens the browser; works over SSH too
agenticwf token                 # a valid access token, e.g. for curl
agenticwf whoami
agenticwf call GET /api/v1/me
```

Behind the AgenticWF server (Caddy, Logto) the commands sign in with `agenticwf login`; set the
connection once (an administrator gets the values with
`docker exec agenticwf cat /var/lib/agenticwf/logto/clients.env`):

```bash
export AGENTICWF_AUTH_URL=https://host.example.org
export AGENTICWF_API_URL=https://host.example.org/app
export AGENTICWF_CLIENT_ID=<Logto native app id>
export AGENTICWF_RESOURCE=<API resource indicator>
agenticwf login
```

Scripts and CI use a personal access token instead (`AGENTICWF_TOKEN=pat_…`), or a machine
client (`AGENTICWF_CLIENT_ID` + `AGENTICWF_CLIENT_SECRET`).

The service clients add their commands to `agenticwf`, with the same sign-in:

```bash
pip install agenticwf-kb-client       # agenticwf kb …
pip install agenticwf-agent-client    # agenticwf agent …
```

From Python:

```python
from agenticwf_auth_cli import Client, service_access

api = Client.from_env()
print(api.request("GET", "/api/v1/me"))
base, token = service_access("kb", "/kb")     # a service's URL, and a function giving a valid token
```
