#!/usr/bin/env bash
# Build the pip packages of this repository into dist/:
#   server   agenticwf-auth-server   authsvc/: the auth service, and the AuthContext verification
#                                    the KB and agent servers need (agenticwf.auth)
#   client   agenticwf-auth-client   cli/: the `agenticwf` command (sign-in, tokens, API calls;
#                                    `agenticwf kb` and `agenticwf agent` come with their clients)
#
#   scripts/build-packages.sh                 both wheels
#   scripts/build-packages.sh client          one of them (client or server)
#   SDIST=1 scripts/build-packages.sh         source distributions too (needs `pip install build`)
#   OUT=/tmp/wheels PYTHON=python3.11 scripts/build-packages.sh
#
# Install, e.g. on a laptop: pip install dist/agenticwf_auth_client-*.whl, plus the KB and agent
# clients (scripts/build-packages.sh client in AgenticWF-KB and AgenticWF-agent).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=${OUT:-$root/dist}
python=${PYTHON:-python3}

source_of() {
    case $1 in
        server) echo "$root/authsvc" ;;
        client) echo "$root/cli" ;;
        *) echo "unknown package '$1' (client or server)" >&2; return 1 ;;
    esac
}

[[ $# -gt 0 ]] || set -- server client
mkdir -p "$out"
for name in "$@"; do
    src=$(source_of "$name")
    echo "[build-packages] $name: $src"
    # setuptools copies into build/lib and never removes from it: a module moved or deleted since
    # the last build would still be packaged.
    rm -rf "$src/build"
    "$python" -m pip wheel --quiet --no-deps --wheel-dir "$out" "$src"
    if [[ ${SDIST:-0} == 1 ]]; then
        "$python" -m build --sdist --outdir "$out" "$src"
    fi
done
ls -1 "$out"
