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

for helper in lib sources runtime assembly patched-crates rust-analyzer; do
	. "$ROOT_DIR/src/toolchain-$helper.sh"
done
. "$ROOT_DIR/src/patches/crates.sh"
MOTORH="$(realpath "${MOTORH:-$ROOT_DIR/..}")"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
cargo="$(rustup which cargo)"
export RUSTC="$(rustup which rustc)"
assembly_images="$("$ROOT_DIR/src/select-toolchain-assembly.sh" --resolve)"
linker="${assembly_images%/images}/sysroot/bin/motor-clang"

# Cargo's runner receives the artifact path, avoiding assumptions about the
# Motor toolchain's test-binary layout. Escape the path as a TOML string.
runner="$WD/test-rust-analyzer-crates.sh"
runner="${runner//\\/\\\\}"
runner="${runner//\"/\\\"}"
runner_config="target.x86_64-unknown-motor.runner=[\"bash\",\"$runner\",\"--run-motor\"]"
test_crate() {
	local name="$1" test_target="$2" source
	source="$(toolchain_rust_analyzer_crate "$ROOT_DIR" "$MOTORH" \
		"${CARGO_HOME:-$HOME/.cargo}" "$name" false)"
	local args=(--release --locked --offline --manifest-path "$source/Cargo.toml"
		--test "$test_target" --target-dir "$temporary/target")
	"$cargo" test "${args[@]}"
	CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER="$linker" \
	CARGO_TARGET_X86_64_UNKNOWN_MOTOR_RUSTFLAGS='-C link-self-contained=no -C default-linker-libraries=yes' \
		"$cargo" test "${args[@]}" --target x86_64-unknown-motor --config "$runner_config"

	# Locked tests must not mutate the published/patched source tree either.
	toolchain_rust_analyzer_crate "$ROOT_DIR" "$MOTORH" \
		"${CARGO_HOME:-$HOME/.cargo}" "$name" false >/dev/null
}
test_crate url unit
test_crate inventory test
echo 'test-rust-analyzer-crates PASS'
