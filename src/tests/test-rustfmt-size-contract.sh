#!/usr/bin/env bash
set -euo pipefail
WD="$(cd "$(dirname "$0")" && pwd)"
. "$WD/test-rustfmt-size.sh"

for limit in "$RUSTFMT_BINARY_MAX_BYTES" "$RUSTFMT_QCOW2_GROWTH_MAX_BYTES"; do
  check_rustfmt_size fixture "$((limit - 1))" "$limit"
  check_rustfmt_size fixture "$limit" "$limit"
  for bad in '' -1 not-a-number "$((limit + 1))"; do
    if check_rustfmt_size fixture "$bad" "$limit" 2>/dev/null; then
      echo "rustfmt size check accepted $bad with limit $limit" >&2
      exit 1
    fi
  done
done
echo 'test-rustfmt-size-contract PASS'
