#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d /tmp/lorry-timing-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# shellcheck source=timing.sh
source "$SCRIPT_DIR/timing.sh"

TIMING_LOG="$WORK/timings.tsv"
timing_init "$TIMING_LOG"

timing_start direct-phase
timing_finish

timing_run successful-command /bin/true
status=0
timing_run failing-command /bin/sh -c 'exit 7' || status=$?
[ "$status" -eq 7 ] || {
    echo "timing-contract: failing command returned $status, expected 7" >&2
    exit 1
}

[ "$(sed -n '1p' "$TIMING_LOG")" = $'phase\tstatus\tmilliseconds' ]
awk -F '\t' '
    NR == 2 { good = $1 == "direct-phase" && $2 == 0 && $3 ~ /^[0-9]+$/ }
    NR == 3 { good = good && $1 == "successful-command" && $2 == 0 && $3 ~ /^[0-9]+$/ }
    NR == 4 { good = good && $1 == "failing-command" && $2 == 7 && $3 ~ /^[0-9]+$/ }
    END { exit !(NR == 4 && good) }
' "$TIMING_LOG" || {
    echo "timing-contract: unexpected timing log" >&2
    cat "$TIMING_LOG" >&2
    exit 1
}

echo "PASS: Lorry phase timing contract"
