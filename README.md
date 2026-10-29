# AgenticWF-auth

Identity and access layer of AgenticWF, the agentic workflow server. Every request passes
through Caddy and the auth service (authsvc), which authenticates the caller, checks the route
policy and hands the backend a signed `AuthContext`. The agent backend runs in its own
container, built from [AgenticWF-agent](https://github.com/wguanicedew/AgenticWF-agent); the
all-in-one image is built by [AgenticWF](https://github.com/wguanicedew/AgenticWF).

```
CLI / scripts  ── Bearer ──┐
Browser chat   ── cookie ──┼─HTTPS─► Caddy (host) ─► authsvc /verify ─► REST / Agent API
Status / SSE   ── cookie ──┘              │                │ Logto JWT / session
                                          ▼                ▼
                              Logto OSS ◄── INDIGO IAM / CERN SSO / Google / …
         [ AlmaLinux 9 container: Logto + PostgreSQL + authsvc, under supervisord ]
```

Build the image:

```bash
docker build --network=host -f container/Dockerfile -t agenticwf-auth .
```

| Path | Content |
|---|---|
| [authsvc/](authsvc) | Auth service (authentication, browser sessions, authorization, AuthContext) + example backend, package `agenticwf-auth-server` |
| [cli/](cli) | `agenticwf` command-line client and Python API (`request.py` example), package `agenticwf-auth-client`; `agenticwf kb` and `agenticwf agent` come from the KB and agent client packages |
| [scripts/build-packages.sh](scripts/build-packages.sh) | Builds the two wheels into `dist/` (`server`, `client`, or both) |
| [container/](container) | AlmaLinux 9 Dockerfile, supervisord config, scripts, default policy |
| [deploy/caddy/Caddyfile](deploy/caddy/Caddyfile) | Main `/etc/caddy/Caddyfile` for every layout (`import Caddyfile.d/*.caddyfile`) |
| [deploy/caddy/sites/](deploy/caddy/sites) | Site layouts; install one into `/etc/caddy/Caddyfile.d/`: `agenticwf-single-host.caddyfile` (one hostname, port 443 only) or `agenticwf-multi-host.caddyfile` (separate hostnames); optional `agenticwf-admin-console.caddyfile` exposes the Logto admin console on `:8443` for development (single-host only) |
| [.github/workflows/build-container.yml](.github/workflows/build-container.yml) | Builds and pushes the image on every new tag |
