#!/usr/bin/env bash
# Container entrypoint: prepare persistent state, then hand over to supervisord.
#
#  1. create /var/lib/agenticwf/{pgdata,secrets}
#  2. generate secrets on first boot (unless supplied via environment)
#  3. initialise PostgreSQL on first boot; ensure logto/authsvc roles + databases
#  4. exec supervisord (postgres, logto, authsvc)
set -euo pipefail

DATA_ROOT=${DATA_ROOT:-/var/lib/agenticwf}
PGDATA=${PGDATA:-$DATA_ROOT/pgdata}
SECRETS_DIR=$DATA_ROOT/secrets
LOGTO_DB_NAME=${LOGTO_DB_NAME:-logto}
LOGTO_DB_USER=${LOGTO_DB_USER:-logto}
# PostgreSQL port (127.0.0.1 only); change it if the host already uses 5432 (host networking).
export PGPORT=${PGPORT:-5432}

log() { echo "[entrypoint] $*" >&2; }

: "${LOGTO_ENDPOINT:?LOGTO_ENDPOINT must be set, e.g. https://auth.example.com}"
# Admin console: own public URL, or (default) localhost only, reached via SSH tunnel.
export LOGTO_ADMIN_ENDPOINT=${LOGTO_ADMIN_ENDPOINT:-http://localhost:3002}
: "${AUTH_AUDIENCES:?AUTH_AUDIENCES must be set to the Logto API resource indicator(s)}"

install -d -m 0755 "$DATA_ROOT"
# 0711: services can open their own secret file but cannot list the directory.
install -d -m 0711 -o root -g root "$SECRETS_DIR"
install -d -m 0775 -o postgres -g postgres /run/postgresql

# write_secret NAME FILE OWNER: take $NAME if set, else keep the existing file, else generate.
write_secret() {
    local name=$1 file=$2 owner=$3 value=${!1:-}
    if [[ -n "$value" ]]; then
        printf '%s' "$value" > "$file"
    elif [[ ! -s "$file" ]]; then
        log "generating $name"
        openssl rand -hex 32 | tr -d '\n' > "$file"
    fi
    chown "$owner" "$file"
    chmod 0440 "$file"
    unset "$name"
}

write_secret LOGTO_DB_PASSWORD   "$SECRETS_DIR/logto_db_password"   "logto:logto"
write_secret AUTHSVC_DB_PASSWORD "$SECRETS_DIR/authsvc_db_password" "authsvc:authsvc"
write_secret AUTH_CONTEXT_SECRET "$SECRETS_DIR/auth_context_secret" "root:agenticwf"
# Browser login (optional): client secret of the Logto "Traditional web" application.
if [[ -n "${AUTH_WEB_CLIENT_SECRET:-}" || -s "$SECRETS_DIR/auth_web_client_secret" ]]; then
    write_secret AUTH_WEB_CLIENT_SECRET "$SECRETS_DIR/auth_web_client_secret" "authsvc:authsvc"
fi
# Personal access tokens (optional): secret of the Logto Management API M2M application.
if [[ -n "${AUTH_MGMT_CLIENT_SECRET:-}" || -s "$SECRETS_DIR/auth_mgmt_client_secret" ]]; then
    write_secret AUTH_MGMT_CLIENT_SECRET "$SECRETS_DIR/auth_mgmt_client_secret" "authsvc:authsvc"
fi

if [[ ! -s "$PGDATA/PG_VERSION" ]]; then
    log "initialising PostgreSQL cluster in $PGDATA"
    install -d -m 0700 -o postgres -g postgres "$PGDATA"
    runuser -u postgres -- initdb -D "$PGDATA" \
        --encoding=UTF8 --locale=C.UTF-8 \
        --auth-local=peer --auth-host=scram-sha-256 >/dev/null
    cat >> "$PGDATA/postgresql.conf" <<EOF

# --- agenticwf ---
listen_addresses = '127.0.0.1'
unix_socket_directories = '/run/postgresql'
password_encryption = 'scram-sha-256'
logging_collector = off
EOF
fi

# On every boot, make sure roles/databases exist and passwords match the secret files,
# so an upgrade can add databases and changing a secret only needs a restart.
runuser -u postgres -- pg_ctl -D "$PGDATA" -o "-c listen_addresses=''" -w start >/dev/null
trap 'runuser -u postgres -- pg_ctl -D "$PGDATA" -m fast -w stop >/dev/null 2>&1 || true' EXIT
ensure_db() {  # ensure_db USER DB PASSWORD_FILE ROLE_OPTIONS
    runuser -u postgres -- psql -v ON_ERROR_STOP=1 -q -X \
        -v user="$1" -v db="$2" -v pw="$(cat "$3")" -v opts="$4" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN', :'user')
 WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'user') \gexec
SELECT format('ALTER ROLE %I %s PASSWORD %L', :'user', :'opts', :'pw') \gexec
SELECT format('CREATE DATABASE %I OWNER %I ENCODING %L', :'db', :'user', 'UTF8')
 WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'db') \gexec
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'db') \gexec
SQL
}
# Logto's seed creates a `logto_tenant_<db>` role and grants on it, so the Logto user
# needs CREATEROLE and must own its database; it does not need SUPERUSER.
ensure_db "$LOGTO_DB_USER" "$LOGTO_DB_NAME" "$SECRETS_DIR/logto_db_password" "CREATEROLE"
# authsvc keeps browser sessions in its own database.
ensure_db authsvc authsvc "$SECRETS_DIR/authsvc_db_password" "NOCREATEROLE"
runuser -u postgres -- pg_ctl -D "$PGDATA" -m fast -w stop >/dev/null
trap - EXIT
log "PostgreSQL ready"

# Values consumed by supervisord's %(ENV_...)s expansions.
export LOGTO_DB_NAME LOGTO_DB_USER PGDATA DATA_ROOT PGPORT
# Address the services listen on: 0.0.0.0 for bridge networking with `-p 127.0.0.1:...`,
# 127.0.0.1 for `docker run --network host` (keeps them off the host's public interfaces).
export LISTEN_HOST=${LISTEN_HOST:-0.0.0.0}
export AUTH_POLICY_FILE=${AUTH_POLICY_FILE:-/etc/agenticwf/policy.yaml}
export AUTHSVC_WORKERS=${AUTHSVC_WORKERS:-2}
export AUTHSVC_LOG_LEVEL=${AUTHSVC_LOG_LEVEL:-info}

exec "$@"
