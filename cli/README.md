# agenticwf-auth-client

The `agenticwf` command for [AgenticWF](https://github.com/InnovateAILab/AgenticWF): sign-in
(OAuth device flow via Logto), access tokens, and calls to the AgenticWF API. Standard library only.

```bash
pip install agenticwf-auth-client
agenticwf login                 # prints a link to paste into a browser; works over SSH too
agenticwf token                 # a valid access token, e.g. for curl
agenticwf whoami
agenticwf call GET /api/v1/me
```

Behind the AgenticWF server (Caddy, Logto) the commands sign in with `agenticwf login`. The
application URL is enough: authsvc publishes the rest at `<application URL>/auth/config`, and a
service's URL works as well (`AGENTICWF_KB_URL`, `AGENTICWF_AGENT_URL`):

```bash
export AGENTICWF_API_URL=https://host.example.org/app
agenticwf login
```

Variables that are set take precedence over what is published (an administrator gets the values
with `docker exec agenticwf cat /var/lib/agenticwf/logto/clients.env`):

```bash
export AGENTICWF_AUTH_URL=https://host.example.org
export AGENTICWF_CLIENT_ID=<Logto native app id>
export AGENTICWF_RESOURCE=<API resource indicator>
```

Scripts and CI use a personal access token instead (`AGENTICWF_TOKEN=pat_…`), or a machine
client (`AGENTICWF_CLIENT_ID` + `AGENTICWF_CLIENT_SECRET`).

HTTPS: the clients trust the system's CAs plus CERN's, which are installed with the package
(`agenticwf_auth_cli/cacerts/`), so a server with a CERN certificate works from a machine that
lacks CERN's CA. A site CA of your own is added with `AGENTICWF_CA_BUNDLE=/path/to/ca.pem` (a
file, or a `c_rehash`ed directory). These come on top of the system's, never instead of them.

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
