#!/usr/bin/env bash
# supervisord program: AgenticWF auth service (runs as user `authsvc`).
set -euo pipefail

SECRETS_DIR="$DATA_ROOT/secrets"
urlencode() { python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }

export AUTH_CONTEXT_SECRET_FILE=${AUTH_CONTEXT_SECRET_FILE:-$SECRETS_DIR/auth_context_secret}
# Fetch signing keys from Logto inside the container (no hairpin through Caddy).
export AUTH_JWKS_URI=${AUTH_JWKS_URI:-http://127.0.0.1:${LOGTO_PORT:-3001}/oidc/jwks}
export LOGTO_INTERNAL_URL=${LOGTO_INTERNAL_URL:-http://127.0.0.1:${LOGTO_PORT:-3001}}

# Browser sessions (only used when AUTH_WEB_CLIENT_ID is set).
if [[ -s "$SECRETS_DIR/auth_web_client_secret" ]]; then
    export AUTH_WEB_CLIENT_SECRET_FILE=${AUTH_WEB_CLIENT_SECRET_FILE:-$SECRETS_DIR/auth_web_client_secret}
fi
# Personal access tokens (only used when AUTH_MGMT_CLIENT_ID is set).
if [[ -s "$SECRETS_DIR/auth_mgmt_client_secret" ]]; then
    export AUTH_MGMT_CLIENT_SECRET_FILE=${AUTH_MGMT_CLIENT_SECRET_FILE:-$SECRETS_DIR/auth_mgmt_client_secret}
fi
if [[ "${AUTH_SESSION_STORE:-postgres}" == "postgres" && -z "${AUTH_SESSION_DB_URL:-}" ]]; then
    export AUTH_SESSION_DB_URL="postgresql://authsvc:$(urlencode "$(cat "$SECRETS_DIR/authsvc_db_password")")@127.0.0.1:${PGPORT}/authsvc"
fi

for _ in $(seq 1 60); do
    pg_isready -q -h 127.0.0.1 && break
    sleep 1
done

exec /opt/authsvc/venv/bin/uvicorn --factory agenticwf.auth.app:create_app \
    --host "$LISTEN_HOST" --port "${AUTHSVC_PORT:-8010}" \
    --workers "$AUTHSVC_WORKERS" \
    --log-level "$AUTHSVC_LOG_LEVEL" \
    --no-server-header \
    --proxy-headers --forwarded-allow-ips "${AUTHSVC_FORWARDED_ALLOW_IPS:-*}"
