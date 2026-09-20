#!/usr/bin/env bash
# A failed top-level make must end with a loud summary naming what failed.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
fail() { echo "test-make-driver: $*" >&2; exit 1; }

resolver="$temporary/resolver"
printf '%s\n' '#!/bin/bash' 'echo "resolver says no: $*" >&2' 'exit 3' > "$resolver"
chmod +x "$resolver"
export MOTOR_MAKE_LOG="$temporary/make.log"
run_make() {
  local status=0
  make -C "$ROOT_DIR" "$@" > "$temporary/out" 2> "$temporary/err" || status=$?
  echo "$status"
}

# The failing recipe is named, its output is quoted, and the verdict is last.
status="$(run_make assembly-resolved "ASSEMBLY_RESOLVER=$resolver")"
[ "$status" -ne 0 ] || fail 'a failing recipe left make successful'
grep -q 'assembly-resolved\] Error 3' "$temporary/err" || fail 'failed recipe not named'
grep -q 'resolver says no: --resolve' "$temporary/err" || fail 'recipe output not quoted'
grep -q "^Full log: $MOTOR_MAKE_LOG\$" "$temporary/err" || fail 'log path missing'
grep -q 'resolver says no' "$MOTOR_MAKE_LOG" || fail 'log lacks the recipe output'
[ "$(tail -n 2 "$temporary/err" | head -n 1)" = \
  "BUILD FAILED: make BUILD=debug assembly-resolved (exit status 2)" ] ||
  fail "verdict is not the driver's last line: $(tail -n 2 "$temporary/err" | head -n 1)"
tail -n 1 "$temporary/err" | grep -q '^make: \*\*\* \[.*assembly-resolved\] Error' ||
  fail 'make did not report the top-level goal after the verdict'
! grep -q $'\033' "$temporary/err" || fail 'color escapes without a terminal'

status="$(FORCE_COLOR=1 run_make assembly-resolved "ASSEMBLY_RESOLVER=$resolver")"
[ "$status" -ne 0 ] || fail 'colored run left make successful'
grep -q $'\033\\[1;31mBUILD FAILED\033\\[0m: make' "$temporary/err" || fail 'forced color missing'

# A passing build prints no verdict, and a dry run neither captures nor logs.
status="$(run_make assembly-resolved ASSEMBLY_RESOLVER=/bin/true)"
[ "$status" -eq 0 ] || fail 'a passing recipe failed'
! grep -q 'BUILD FAILED' "$temporary/err" "$temporary/out" || fail 'verdict printed on success'
rm -f "$MOTOR_MAKE_LOG"
status="$(run_make -n assembly-resolved mbr.bin "ASSEMBLY_RESOLVER=$resolver")"
[ "$status" -eq 0 ] || fail 'dry run failed'
grep -q -- "$resolver\" --resolve" "$temporary/out" || fail 'dry run hides the first goal'
grep -q 'x64.mbr' "$temporary/out" || fail 'dry run hides the second goal'
[ ! -e "$MOTOR_MAKE_LOG" ] || fail 'dry run wrote a log'

# A fresh gix cache must be populated before the offline build starts. Stub
# Cargo so this also checks fetch failures without accessing the network.
mkdir -p "$temporary/bin" "$temporary/assembly/images" "$temporary/assembly/sysroot"
export MOTOR_TEST_ASSEMBLY="$temporary/assembly/images"
export MOTOR_TEST_CARGO_LOG="$temporary/cargo.log"
export MOTOR_TEST_FETCH_STATUS=0
cat > "$resolver" <<'EOF'
#!/bin/bash
printf '%s\n' "$MOTOR_TEST_ASSEMBLY"
EOF
cat > "$temporary/bin/cargo" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" >> "$MOTOR_TEST_CARGO_LOG"
case "$1" in
  fetch) exit "$MOTOR_TEST_FETCH_STATUS" ;;
  build) exit 42 ;; # Stop before ELF validation and installation.
  *) exit 99 ;;
esac
EOF
chmod +x "$temporary/bin/cargo"
status="$(PATH="$temporary/bin:$PATH" run_make gix "ASSEMBLY_RESOLVER=$resolver" \
  "BIN_DIR=$temporary/output" "OBJ_DIR=$temporary/objects")"
[ "$status" -ne 0 ] || fail 'stub build unexpectedly succeeded'
printf '%s\n' 'fetch --locked' \
  'build --target x86_64-unknown-motor --locked --offline' > "$temporary/expected-cargo.log"
cmp -s "$temporary/expected-cargo.log" "$MOTOR_TEST_CARGO_LOG" ||
  fail 'gix did not fetch locked sources before its offline build'
grep -q 'gix\] Error 42' "$temporary/err" || fail 'gix did not reach the build'

: > "$MOTOR_TEST_CARGO_LOG"
export MOTOR_TEST_FETCH_STATUS=43
status="$(PATH="$temporary/bin:$PATH" run_make gix "ASSEMBLY_RESOLVER=$resolver" \
  "BIN_DIR=$temporary/output" "OBJ_DIR=$temporary/objects")"
[ "$status" -ne 0 ] || fail 'failed gix fetch left make successful'
printf '%s\n' 'fetch --locked' > "$temporary/expected-cargo.log"
cmp -s "$temporary/expected-cargo.log" "$MOTOR_TEST_CARGO_LOG" ||
  fail 'gix started building after a failed fetch'
grep -q 'gix\] Error 43' "$temporary/err" || fail 'gix did not report the fetch failure'
echo 'test-make-driver PASS'
