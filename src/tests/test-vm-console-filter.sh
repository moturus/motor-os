#!/bin/bash

set -euo pipefail

WD="$(dirname "$0")"
. "$WD/vm-console-filter.sh"

input=$'before\033[6nafter\033[18tmode\033[?2048$penable\033[?2048hdisable\033[?2048lend\0337\033[9999;9999H\0338'
expected=$'beforeaftermodeenabledisableend\0337\033[9999;9999H\0338'
actual="$(printf '%s' "$input" | filter_vm_console)"

if [ "$actual" != "$expected" ]; then
  echo "test-vm-console-filter: unexpected filtered output" >&2
  printf 'expected: %q\nactual:   %q\n' "$expected" "$actual" >&2
  exit 1
fi

echo "test-vm-console-filter PASS"
