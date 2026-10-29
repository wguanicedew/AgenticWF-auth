#!/usr/bin/env bash
# supervisord program: Logto OSS (runs as user `logto`).
set -euo pipefail

cd /opt/logto

PW_FILE="$DATA_ROOT/secrets/logto_db_password"
urlencode() { python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }

export DB_URL="postgresql://${LOGTO_DB_USER}:$(urlencode "$(cat "$PW_FILE")")@127.0.0.1:${PGPORT}/${LOGTO_DB_NAME}"
export ENDPOINT="$LOGTO_ENDPOINT"
export ADMIN_ENDPOINT="$LOGTO_ADMIN_ENDPOINT"
export PORT=${LOGTO_PORT:-3001}
export ADMIN_PORT=${LOGTO_ADMIN_PORT:-3002}
# Caddy terminates TLS on the host; trust its X-Forwarded-* headers.
export TRUST_PROXY_HEADER=${TRUST_PROXY_HEADER:-1}
export NODE_ENV=production
# Logto binds every interface; restrict it when LISTEN_HOST is set (host networking).
if [[ "${LISTEN_HOST:-0.0.0.0}" != "0.0.0.0" ]]; then
    export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--require /usr/local/bin/listen-host.cjs"
fi

echo "[logto] waiting for PostgreSQL" >&2
for _ in $(seq 1 60); do
    pg_isready -q -h 127.0.0.1 && break
    sleep 1
done
pg_isready -q -h 127.0.0.1 || { echo "[logto] PostgreSQL not ready" >&2; exit 1; }

# Logto CLI from the release tarball, called with node directly (npm is not installed:
# on EL9 it is only a weak dependency of nodejs).
logto_cli() { node /opt/logto/packages/cli/bin/logto.js "$@"; }

# Seed on first start; --swe = skip when the database is already seeded.
logto_cli db seed --swe

# At runtime Logto connects as the tenant role its seed created (logto_tenant_<db>).
# The entrypoint revokes CONNECT from PUBLIC, so grant it to exactly that role
# (the logto user owns the database and may grant it). Idempotent.
PGPASSWORD="$(cat "$PW_FILE")" psql -h 127.0.0.1 -U "$LOGTO_DB_USER" -d "$LOGTO_DB_NAME" \
    -v ON_ERROR_STOP=1 -q -X -v db="$LOGTO_DB_NAME" <<'SQL'
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'db', 'logto_tenant_' || :'db') \gexec
SQL

# Database schema upgrades after bumping LOGTO_VERSION are opt-in.
if [[ "${LOGTO_AUTO_ALTERATION:-0}" == "1" ]]; then
    logto_cli db alteration deploy "$LOGTO_VERSION"
fi

cd packages/core
exec node .
