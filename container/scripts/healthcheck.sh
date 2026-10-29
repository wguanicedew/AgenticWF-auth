#!/usr/bin/env bash
# Container health: PostgreSQL accepts connections, Logto serves OIDC discovery, authsvc is up.
set -euo pipefail
pg_isready -q -h 127.0.0.1 -p "${PGPORT:-5432}"
curl -fsS -o /dev/null "http://127.0.0.1:${LOGTO_PORT:-3001}/oidc/.well-known/openid-configuration"
curl -fsS -o /dev/null "http://127.0.0.1:${AUTHSVC_PORT:-8010}/healthz"
