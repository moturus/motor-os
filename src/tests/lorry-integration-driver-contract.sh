#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d /tmp/lorry-integration-driver-XXXXXX)"
DRIVER="$WORK/src/tests/lorry-integration-test.sh"
LOG="$WORK/arguments.log"

cleanup() {
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/src/tests"
cp "$SCRIPT_DIR/lorry-integration-test.sh" "$DRIVER"
for child in lorry-native-integration.sh lorry-motor-registry-cache.sh; do
    stub="$WORK/src/tests/$child"
    printf '%s\n' '#!/usr/bin/env bash' \
        'printf "%s" "${0##*/}" >>"$LORRY_DRIVER_LOG"' \
        'for argument in "$@"; do' \
        '    printf " <%s>" "$argument" >>"$LORRY_DRIVER_LOG"' \
        'done' \
        'printf "\n" >>"$LORRY_DRIVER_LOG"' >"$stub"
    chmod +x "$stub"
done

run_case() {
    local expected="$1"
    shift
    : >"$LOG"
    LORRY_DRIVER_LOG="$LOG" "$DRIVER" "$@"
    [ "$(<"$LOG")" = "$expected" ] || {
        echo "lorry integration driver routed unexpected arguments:" >&2
        cat "$LOG" >&2
        exit 1
    }
}

run_case $'lorry-native-integration.sh <--full> <--reuse-running-vm>\nlorry-motor-registry-cache.sh' \
    --native-only --reuse-running-vm
run_case $'lorry-native-integration.sh <--full> <--release> <--reuse-running-vm>\nlorry-motor-registry-cache.sh <--release>' \
    --release --native-only --reuse-running-vm
run_case $'lorry-native-integration.sh <--release> <--reuse-running-vm>' \
    --release --acceptance --native-only --reuse-running-vm
run_case $'lorry-native-integration.sh <--full> <--reuse-running-vm>\nlorry-motor-registry-cache.sh' \
    --exhaustive --native-only --reuse-running-vm

echo "PASS: Lorry integration driver routes native profile arguments"
