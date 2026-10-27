#!/usr/bin/env bash
# Run against the already booted developer-image VM: the command-debug fixture
# of the rust-analyzer smoke test, built against the selected Motor standard
# library, must pass on Motor.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
WD="$ROOT_DIR/src/tests"
SSH_OPTIONS=(-F /dev/null -o IdentitiesOnly=yes -o BatchMode=yes
	-o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts"
	-i "$WD/test.key")

if [ "${1:-}" = --run-motor ]; then
	binary="$2"
	shift 2
	guest=/user/tmp/rust-analyzer-crate-tests
	printf 'put "%s" "%s"\nchmod 755 "%s"\n' "$binary" "$guest" "$guest" |
		sftp "${SSH_OPTIONS[@]}" -P 2222 -b - motor@192.168.4.2
	status=0
	ssh "${SSH_OPTIONS[@]}" -p 2222 motor@192.168.4.2 "$guest" "$@" || status=$?
	ssh "${SSH_OPTIONS[@]}" -p 2222 motor@192.168.4.2 /system/bin/rm "$guest"
	exit "$status"
fi
[ "$#" = 0 ] || { echo "usage: $0 [--run-motor BINARY ARGS...]" >&2; exit 2; }

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
rustc="$(cd "$ROOT_DIR" && rustup which rustc)"
# Exercise the actual selected Motor stdlib, not a host-side formatter adapter.
"$rustc" --test --edition=2024 -O --target x86_64-unknown-motor \
  "$WD/rust-analyzer-smoke/fixtures/command-debug.rs" -o "$temporary/command-debug"
"$WD/test-rust-analyzer-crates.sh" --run-motor "$temporary/command-debug"
echo 'test-rust-analyzer-crates PASS'
