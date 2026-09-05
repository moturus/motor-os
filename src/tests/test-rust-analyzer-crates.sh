#!/usr/bin/env bash
# Run against the already booted developer-image VM; all sources are offline.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
WD="$ROOT_DIR/src/tests"
SSH_OPTIONS=(-F /dev/null -o IdentitiesOnly=yes -o BatchMode=yes
	-o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts"
	-i "$WD/test.key")

if [ "${1:-}" = --run-motor ]; then
	binary="$2"
	shift 2
	guest=/devtools/tmp/rust-analyzer-crate-tests
	printf 'put "%s" "%s"\nchmod 755 "%s"\n' "$binary" "$guest" "$guest" |
		sftp "${SSH_OPTIONS[@]}" -P 2222 -b - motor@192.168.4.2
	status=0
	ssh "${SSH_OPTIONS[@]}" -p 2222 motor@192.168.4.2 "$guest" "$@" || status=$?
	ssh "${SSH_OPTIONS[@]}" -p 2222 motor@192.168.4.2 /system/bin/rm "$guest"
	exit "$status"
fi
[ "$#" = 0 ] || { echo "usage: $0 [--run-motor BINARY ARGS...]" >&2; exit 2; }

for helper in lib sources runtime assembly patched-crates; do
	. "$ROOT_DIR/src/toolchain-$helper.sh"
done
. "$ROOT_DIR/src/patches/crates.sh"
MOTORH="$(realpath "${MOTORH:-$ROOT_DIR/..}")"
archive="$(toolchain_cached_crate "${CARGO_HOME:-$HOME/.cargo}" \
	"url-$MOTOR_URL_VERSION.crate" "$MOTOR_URL_CHECKSUM")"
source="$(toolchain_prepare_patched_crate "$MOTORH/patched-crates" url \
	"$MOTOR_URL_VERSION" "$MOTOR_URL_CHECKSUM" "$archive" \
	"$ROOT_DIR/src/patches/url-$MOTOR_URL_VERSION-motor.patch")"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
cargo="$(rustup which cargo)"
export RUSTC="$(rustup which rustc)"

# Cargo's runner receives the artifact path, avoiding assumptions about the
# Motor toolchain's test-binary layout. Escape the path as a TOML string.
runner="$WD/test-rust-analyzer-crates.sh"
runner="${runner//\\/\\\\}"
runner="${runner//\"/\\\"}"
runner_config="target.x86_64-unknown-motor.runner=[\"bash\",\"$runner\",\"--run-motor\"]"
args=(--release --locked --offline --manifest-path "$source/Cargo.toml"
	--test unit --target-dir "$temporary/target")
"$cargo" test "${args[@]}"
"$cargo" test "${args[@]}" --target x86_64-unknown-motor --config "$runner_config"

# Locked tests must not mutate the published/patched source tree either.
toolchain_prepare_patched_crate "$MOTORH/patched-crates" url \
	"$MOTOR_URL_VERSION" "$MOTOR_URL_CHECKSUM" "$archive" \
	"$ROOT_DIR/src/patches/url-$MOTOR_URL_VERSION-motor.patch" >/dev/null
echo 'test-rust-analyzer-crates PASS'
