# AgenticWF-auth

Identity and access layer of AgenticWF, the agentic workflow server: the **provider-neutral**
part. Every request passes through Caddy and the auth service (authsvc), which authenticates the
caller, checks the route policy and hands the backend a signed `AuthContext`. The agent backend runs
in its own container, built from [AgenticWF-agent](https://github.com/InnovateAILab/AgenticWF-agent).

```
CLI / scripts  ── Bearer ──┐
Browser chat   ── cookie ──┼─HTTPS─► Caddy (host) ─► authsvc /verify ─► REST / Agent API
Status / SSE   ── cookie ──┘              │                │ JWT / PAT / session
                                          ▼                ▼
                         Keycloak or Logto ◄── INDIGO IAM / CERN SSO / GitHub / …
       [ AlmaLinux 9 container: identity provider + PostgreSQL + authsvc, under supervisord ]
```

The identity provider plugs into authsvc as a `Provider` (claims mapping, OIDC endpoints, admin
API for groups, personal access tokens). Each provider has its own repository, with its provider
package, the container image, the Caddy sites and the deployment guide:

| Repository | Identity provider | Image |
|---|---|---|
| [AgenticWF-auth-keycloak](https://github.com/InnovateAILab/AgenticWf-auth-keycloak) | Keycloak 26 (realm provisioned on first boot) | `ghcr.io/<owner>/agenticwf-auth-keycloak` |
| [AgenticWF-auth-logto](https://github.com/InnovateAILab/AgenticWF-auth-logto) | Logto OSS | `ghcr.io/<owner>/agenticwf-auth-logto` |

Both build their image with this repository as a build context (`--build-context
agenticwf-auth=../AgenticWF-auth`). Backends see the same `AuthContext` whatever the provider, so the
agent and KB containers work with either.

| Path | Content |
|---|---|
| [authsvc/](authsvc) | Auth service (authentication, browser sessions, authorization, groups, personal access tokens, AuthContext) + example backend, package `agenticwf-auth-server`, module `agenticwf.auth`; the backends use `agenticwf.auth.client` / `.context` |
| [cli/](cli) | `agenticwf` command-line client and Python API (`request.py` example), package `agenticwf-auth-client`, for every provider; `agenticwf kb` and `agenticwf agent` come from the KB and agent client packages |
| [config/policy.yaml](config/policy.yaml) | Default route policy, installed into the provider images as `/etc/agenticwf/policy.yaml` |
| [docs/](docs) | [architecture](docs/architecture.md), [auth service](docs/auth-service.md) (endpoints, configuration, policy, providers, backends), [access modes](docs/access-modes.md) |
| [scripts/build-packages.sh](scripts/build-packages.sh) | Builds the two wheels into `dist/` (`server`, `client`, or both) |
| [.github/workflows/test.yml](.github/workflows/test.yml) | Tests authsvc and the CLI |
