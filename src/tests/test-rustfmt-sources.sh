#!/usr/bin/env bash
# Check that the selected compiler's rustfmt sources need no dirs crate on Motor.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
for helper in versions lib bootstrap; do
	. "$ROOT_DIR/src/toolchain-$helper.sh"
done
[ "$#" = 0 ] || { echo "usage: $0" >&2; exit 2; }
MOTORH="$(realpath "${MOTORH:-$ROOT_DIR/..}")"
rust="$(realpath "${MOTOR_RUST_SOURCE:-$MOTORH/toolchain-src/rust}")"
toolchain_bootstrap_absolute_path rust "$rust"
cargo="$(rustup which cargo)"
rustc="$(rustup which rustc)"
revision="$("$rustc" -vV | sed -n 's/^commit-hash: //p')"
[ "$(git -C "$rust" rev-parse HEAD)" = "$revision" ] || {
	toolchain_die 'rustfmt test sources differ from the selected compiler'; exit 1;
}
graph() {
	"$cargo" tree --manifest-path "$rust/Cargo.toml" --locked --offline \
		-p rustfmt-nightly --target "$1" --edges normal,build --prefix none --format '{p}'
}
motor="$(graph x86_64-unknown-motor)"
grep -Eq '^rustfmt-nightly ' <<< "$motor" || {
	toolchain_die 'native rustfmt graph does not contain rustfmt-nightly'; exit 1
}
if grep -Eq '^(dirs|dirs-sys) ' <<< "$motor"; then
	toolchain_die 'native rustfmt graph contains dirs or dirs-sys'; exit 1
fi
# The host formatter keeps the upstream lookup, so its graph must still change nothing.
grep -Eq '^dirs v6\.0\.0$' <<< "$(graph x86_64-unknown-linux-gnu)" || {
	toolchain_die 'host rustfmt graph lost its dirs dependency'; exit 1
}
echo 'test-rustfmt-sources PASS'
