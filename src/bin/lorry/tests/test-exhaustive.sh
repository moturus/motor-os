#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

if [ "$#" -gt 0 ]; then
    case "$1" in
        -h | --help)
            cat <<'EOF'
usage: test-exhaustive.sh

Runs three clean Lorry-local passes for both artifact profiles, followed by
the debug- and release-image repository integration campaigns including the
second native Lorry generation.
EOF
            exit 0
            ;;
        *)
            echo "test-exhaustive: unknown option '$1'" >&2
            exit 1
            ;;
    esac
fi

"$SCRIPT_DIR/test-local.sh" --both --repeat 3
"$ROOT_DIR/src/tests/lorry-integration-test.sh" --exhaustive
"$ROOT_DIR/src/tests/lorry-integration-test.sh" --release --exhaustive
