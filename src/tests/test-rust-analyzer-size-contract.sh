#!/usr/bin/env bash
set -euo pipefail
WD="$(cd "$(dirname "$0")" && pwd)"
. "$WD/test-rust-analyzer-size.sh"
for limit in 33554432 83886080 134217728; do
  check_size fixture "$((limit - 1))" "$limit"
  check_size fixture "$limit" "$limit"
  for bad in '' -1 not-a-number "$((limit + 1))"; do
    if check_size fixture "$bad" "$limit" 2>/dev/null; then
      echo "size check accepted $bad with limit $limit" >&2
      exit 1
    fi
  done
done
echo 'test-rust-analyzer-size-contract PASS'
