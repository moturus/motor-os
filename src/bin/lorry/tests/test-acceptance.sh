#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
fast_arguments=()

usage() {
    cat <<'EOF'
usage: test-acceptance.sh [--warm] [--keep]

Runs the fast Lorry gate, then the release-image repository acceptance lane.
The latter adds real downstream packages, local acquisition/TLS fixtures, and
one native Stage-1 cycle without the second-generation exhaustive campaign.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --warm | --keep) fast_arguments+=("$1") ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "test-acceptance: unknown option '$1'" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

"$SCRIPT_DIR/test-fast.sh" "${fast_arguments[@]}"
"$ROOT_DIR/src/tests/lorry-integration-test.sh" --release --acceptance
