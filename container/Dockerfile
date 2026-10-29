# AgenticWF identity container (AlmaLinux 9)
#
#   supervisord
#   ├── postgres   127.0.0.1:${PGPORT:-5432}  (internal only)
#   ├── logto      :3001 (OIDC / sign-in)   :3002 (admin console)
#   └── authsvc    :8010 (Caddy forward_auth target)
#
# Build from the repository root:
#   docker build -f container/Dockerfile -t agenticwf-auth .

FROM almalinux:9

ARG LOGTO_VERSION=1.44.0
# Official Node.js build (Logto requires ^22.14). Not the AlmaLinux `nodejs` module: its
# shared-library build (libnode.so + system OpenSSL 3.5) segfaults in Logto's database seed.
ARG NODE_VERSION=22.23.3
ARG POSTGRES_STREAM=16
ARG PYTHON=python3.12

LABEL org.opencontainers.image.title="agenticwf-auth" \
      org.opencontainers.image.description="Logto OSS + PostgreSQL + AgenticWF auth service on AlmaLinux 9" \
      org.opencontainers.image.licenses="Apache-2.0"

# Base packages: PostgreSQL from its AppStream module stream, supervisor from EPEL.
RUN dnf -y install epel-release \
 && dnf -y module enable "postgresql:${POSTGRES_STREAM}" \
 && dnf -y install --setopt=install_weak_deps=False \
        postgresql-server postgresql \
        "${PYTHON}" "${PYTHON}-pip" \
        supervisor \
        openssl procps-ng tar gzip xz \
 && dnf clean all && rm -rf /var/cache/dnf

# Node.js from nodejs.org, checked against the release's published SHA-256 sums.
RUN cd /tmp \
 && tarball="node-v${NODE_VERSION}-linux-x64.tar.xz" \
 && curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/${tarball}" \
 && curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt" | grep " ${tarball}\$" | sha256sum -c - \
 && tar -xJf "${tarball}" -C /usr/local --strip-components=1 --no-same-owner \
        --exclude='*/CHANGELOG.md' --exclude='*/README.md' --exclude='*/LICENSE' \
 && rm -f "${tarball}" \
 && node --version

# Service accounts: each service runs unprivileged under supervisord.
# Members of group `agenticwf` may read the AuthContext signing secret (backend services).
RUN groupadd --system agenticwf \
 && useradd --system --create-home --home-dir /home/logto --shell /sbin/nologin logto \
 && useradd --system --create-home --home-dir /home/authsvc --shell /sbin/nologin -G agenticwf authsvc

# Logto OSS (open-source, self-hosted edition) prebuilt release.
# The tarball ships compiled packages, production node_modules and official connectors
# (including the generic OIDC connector used for INDIGO IAM). Its native addons are
# linux-x64-gnu builds, so the image is linux/amd64 only. Code stays root-owned; the
# logto user may only write alteration scripts.
RUN curl -fsSL "https://github.com/logto-io/logto/releases/download/v${LOGTO_VERSION}/logto.tar.gz" \
        | tar -xz -C /opt \
 && install -d -o logto -g logto /opt/logto/packages/cli/alteration-scripts \
 && echo "${LOGTO_VERSION}" > /opt/logto/.agenticwf-version

# Auth service in its own virtualenv.
COPY authsvc /opt/authsvc/src
RUN "${PYTHON}" -m venv /opt/authsvc/venv \
 && /opt/authsvc/venv/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/authsvc/venv/bin/pip install --no-cache-dir "/opt/authsvc/src[otel]"

COPY container/supervisord.conf /etc/supervisord.conf
COPY container/supervisord.d/ /etc/supervisord.d/
COPY container/config/policy.yaml /etc/agenticwf/policy.yaml
COPY container/scripts/ /usr/local/bin/
RUN chmod 0755 /usr/local/bin/*.sh

ENV DATA_ROOT=/var/lib/agenticwf \
    PGDATA=/var/lib/agenticwf/pgdata \
    LOGTO_VERSION=${LOGTO_VERSION}

# Persist the database and generated secrets.
VOLUME ["/var/lib/agenticwf"]

EXPOSE 3001 3002 8010 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
    CMD /usr/local/bin/healthcheck.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisord.conf"]
