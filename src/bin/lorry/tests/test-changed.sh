#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
PRINT_ONLY=0
WARM=0
BASE=""
paths=()

usage() {
    cat <<'EOF'
usage: test-changed.sh [--print] [--warm] [--base REVISION] [--] [PATH ...]

Selects and runs the strongest gate required by the changed paths. With no
paths, reads the working tree relative to HEAD; --base reads REVISION...HEAD.
--print reports only: fast, acceptance, exhaustive, full-test, or none.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --print) PRINT_ONLY=1 ;;
        --warm) WARM=1 ;;
        --base)
            [ "$#" -ge 2 ] || { usage >&2; exit 1; }
            BASE="$2"
            shift
            ;;
        --)
            shift
            paths+=("$@")
            break
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        -*)
            echo "test-changed: unknown option '$1'" >&2
            usage >&2
            exit 1
            ;;
        *) paths+=("$1") ;;
    esac
    shift
done

if [ "${#paths[@]}" -eq 0 ]; then
    if [ -n "$BASE" ]; then
        mapfile -t paths < <(git -C "$ROOT_DIR" diff --name-only "$BASE"...HEAD)
    else
        mapfile -t paths < <(
            {
                git -C "$ROOT_DIR" diff --name-only HEAD
                git -C "$ROOT_DIR" ls-files --others --exclude-standard
            } | sort -u
        )
    fi
fi

gate=none
rank=0
select_gate() {
    local candidate="$1"
    local candidate_rank="$2"
    if [ "$candidate_rank" -gt "$rank" ]; then
        gate="$candidate"
        rank="$candidate_rank"
    fi
}

for path in "${paths[@]}"; do
    path="${path#./}"
    case "$path" in
        src/bin/lorry/*.md)
            ;;
        src/tests/lorry-* | src/bin/lorry/bootstrap/* | src/bin/lorry/tests/* | \
            src/bin/lorry/Cargo.toml | \
            src/bin/lorry/Cargo.lock | src/bin/lorry/src/cache.rs | \
            src/bin/lorry/src/identity.rs | src/bin/lorry/src/native_tool.rs)
            select_gate exhaustive 3
            ;;
        src/bin/lorry/src/archive.rs | src/bin/lorry/src/cache.rs | \
            src/bin/lorry/src/cargo_registry.rs | src/bin/lorry/src/curl.rs | \
            src/bin/lorry/src/git.rs | src/bin/lorry/src/policy.rs | \
            src/bin/lorry/src/redirect.rs | src/bin/lorry/src/repository.rs | \
            src/bin/lorry/src/sandbox.rs | src/bin/lorry/src/source_tree.rs | \
            src/bin/lorry/src/sparse.rs | src/bin/lorry/src/vendor.rs | \
            src/bin/lorry/src/vendor_lock.rs)
            select_gate acceptance 2
            ;;
        src/bin/lorry/*)
            select_gate fast 1
            ;;
        *)
            select_gate full-test 4
            ;;
    esac
done

if [ "$PRINT_ONLY" -eq 1 ]; then
    echo "$gate"
    exit 0
fi

case "$gate" in
    none)
        echo "test-changed: no test gate required"
        ;;
    fast)
        arguments=()
        [ "$WARM" -eq 0 ] || arguments+=(--warm)
        exec "$SCRIPT_DIR/test-fast.sh" "${arguments[@]}"
        ;;
    acceptance)
        arguments=()
        [ "$WARM" -eq 0 ] || arguments+=(--warm)
        exec "$SCRIPT_DIR/test-acceptance.sh" "${arguments[@]}"
        ;;
    exhaustive)
        [ "$WARM" -eq 0 ] || {
            echo "test-changed: --warm is only valid for fast or acceptance gates" >&2
            exit 1
        }
        exec "$SCRIPT_DIR/test-exhaustive.sh"
        ;;
    full-test)
        [ "$WARM" -eq 0 ] || {
            echo "test-changed: --warm is not valid for repository full tests" >&2
            exit 1
        }
        for _ in 1 2 3; do
            "$ROOT_DIR/src/tests/full-test.sh"
        done
        for _ in 1 2 3; do
            "$ROOT_DIR/src/tests/full-test.sh" --release
        done
        ;;
esac
