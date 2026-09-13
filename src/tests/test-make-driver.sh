#!/usr/bin/env bash
# A failed top-level make must end with a loud summary naming what failed.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
fail() { echo "test-make-driver: $*" >&2; exit 1; }

selector="$temporary/selector"
printf '%s\n' '#!/bin/bash' 'echo "selector says no: $*" >&2' 'exit 3' > "$selector"
chmod +x "$selector"
export MOTOR_MAKE_LOG="$temporary/make.log"
run_make() {
  local status=0
  make -C "$ROOT_DIR" "$@" > "$temporary/out" 2> "$temporary/err" || status=$?
  echo "$status"
}

# The failing recipe is named, its output is quoted, and the verdict is last.
status="$(run_make assembly-selected "ASSEMBLY_SELECTOR=$selector")"
[ "$status" -ne 0 ] || fail 'a failing recipe left make successful'
grep -q 'assembly-selected\] Error 3' "$temporary/err" || fail 'failed recipe not named'
grep -q 'selector says no: --resolve' "$temporary/err" || fail 'recipe output not quoted'
grep -q "^Full log: $MOTOR_MAKE_LOG\$" "$temporary/err" || fail 'log path missing'
grep -q 'selector says no' "$MOTOR_MAKE_LOG" || fail 'log lacks the recipe output'
[ "$(tail -n 2 "$temporary/err" | head -n 1)" = \
  "BUILD FAILED: make BUILD=debug assembly-selected (exit status 2)" ] ||
  fail "verdict is not the driver's last line: $(tail -n 2 "$temporary/err" | head -n 1)"
tail -n 1 "$temporary/err" | grep -q '^make: \*\*\* \[.*assembly-selected\] Error' ||
  fail 'make did not report the top-level goal after the verdict'
! grep -q $'\033' "$temporary/err" || fail 'color escapes without a terminal'

status="$(FORCE_COLOR=1 run_make assembly-selected "ASSEMBLY_SELECTOR=$selector")"
[ "$status" -ne 0 ] || fail 'colored run left make successful'
grep -q $'\033\\[1;31mBUILD FAILED\033\\[0m: make' "$temporary/err" || fail 'forced color missing'

# A passing build prints no verdict, and a dry run neither captures nor logs.
status="$(run_make assembly-selected ASSEMBLY_SELECTOR=/bin/true)"
[ "$status" -eq 0 ] || fail 'a passing recipe failed'
! grep -q 'BUILD FAILED' "$temporary/err" "$temporary/out" || fail 'verdict printed on success'
rm -f "$MOTOR_MAKE_LOG"
status="$(run_make -n assembly-selected mbr.bin "ASSEMBLY_SELECTOR=$selector")"
[ "$status" -eq 0 ] || fail 'dry run failed'
grep -q -- "$selector\" --resolve" "$temporary/out" || fail 'dry run hides the first goal'
grep -q 'x64.mbr' "$temporary/out" || fail 'dry run hides the second goal'
[ ! -e "$MOTOR_MAKE_LOG" ] || fail 'dry run wrote a log'
echo 'test-make-driver PASS'
