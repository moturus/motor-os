#!/usr/bin/env bash
# Exercise the wrapper's real environment assignments without booting a VM.
set -euo pipefail
WD="$(cd "$(dirname "$0")" && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
mkdir -p "$temporary/src/tests" "$temporary/src/bin/lorry/tests" "$temporary/bin"
cp "$WD/full-test-dev.sh" "$temporary/src/tests/"
for script in full-test.sh test-dev-sources.sh; do
  printf '%s\n' '#!/bin/bash' \
    'printf "%s %s %s\n" "${0##*/}" "${MOTO_MEMORY_MIB:-unset}" "$*" >> "$MEMORY_TEST_LOG"' \
    > "$temporary/src/tests/$script"
  chmod +x "$temporary/src/tests/$script"
done
printf '%s\n' '#!/bin/bash' 'exit 0' > "$temporary/bin/python3"
cp "$temporary/bin/python3" "$temporary/src/bin/lorry/tests/test-all.sh"
chmod +x "$temporary/bin/python3" "$temporary/src/bin/lorry/tests/test-all.sh"
export MEMORY_TEST_LOG="$temporary/observed"
export PATH="$temporary/bin:$PATH"

env -u MOTO_MEMORY_MIB bash "$temporary/src/tests/full-test-dev.sh" --release > "$temporary/wrapper.log"
expected=$'full-test.sh 8192 --release\ntest-dev-sources.sh 4096 --release'
[ "$(<"$MEMORY_TEST_LOG")" = "$expected" ] || {
  echo 'developer VM defaults changed' >&2; exit 1;
}
: > "$MEMORY_TEST_LOG"
MOTO_MEMORY_MIB=6144 bash "$temporary/src/tests/full-test-dev.sh" --release >> "$temporary/wrapper.log"
expected=$'full-test.sh 6144 --release\ntest-dev-sources.sh 6144 --release'
[ "$(<"$MEMORY_TEST_LOG")" = "$expected" ] || {
  echo 'developer VM caller override was not preserved' >&2; exit 1;
}
echo 'test-dev-memory-contract PASS'
