#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
arguments=(--both --debug-cross-only)

usage() {
    cat <<'EOF'
usage: test-fast.sh [--warm] [--keep]

Runs the cheapest-first Lorry gate once for both artifact profiles. --warm
preserves native target directories for iterative development.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --warm | --keep) arguments+=("$1") ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "test-fast: unknown option '$1'" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

exec "$SCRIPT_DIR/test-local.sh" "${arguments[@]}"
