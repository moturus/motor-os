#!/bin/bash
set -euo pipefail
WD="$(cd "$(dirname "$0")" && pwd)"
TEST_DIR="$(mktemp -d)"
trap 'rm -r "$TEST_DIR"' EXIT
rustc_args=()
for arg in "$@"; do
  case "$arg" in
    --self-test) rustc_args+=(--test) ;;
    --release) rustc_args+=(-O -C debug-assertions=no) ;;
    *) echo "usage: $0 [--self-test] [--release]" >&2; exit 2 ;;
  esac
done
rustc --edition=2024 -D warnings "${rustc_args[@]}" \
  "$WD/rmux-copy-status.rs" -o "$TEST_DIR/rmux-copy-status"
"$TEST_DIR/rmux-copy-status"
