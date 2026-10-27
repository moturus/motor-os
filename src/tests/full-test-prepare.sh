#!/bin/bash
#
# full-test-prepare.sh -- build what full-test.sh needs, before its clock starts.
#
# src/build-motor-os.sh re-keys every build directory, so the first suite run
# after it compiles the whole tree, and that alone outlasts the suite's timeout.
# The suite still builds what it needs itself; these steps only move that work
# out of the timed run. A build missing here is not an error -- the suite simply
# pays for it on its own clock -- but a command that differs from the suite's,
# flag for flag, builds a second set of artifacts and helps nothing.

set -e

usage() {
  echo "usage: $0 debug|release qemu|chv|fc" >&2
  exit 2
}

[ "$#" -eq 2 ] || usage
BUILD="$1"
VMM="$2"
case "$BUILD" in debug|release) ;; *) usage ;; esac
case "$VMM" in qemu|chv|fc) ;; *) usage ;; esac

WD="$(dirname "$0")"
ROOT_DIR="$WD/../.."
. "$WD/vm-test-selection.sh"

profile_args=()
if [ "$BUILD" = "release" ]; then
  profile_args=(--release)
fi

progress() {
  echo "full-test-prepare ($BUILD): $*"
}

TEST_VM_PHASE=standard
if [ "${FULL_TEST_VERIFY_DEV_SOURCES:-0}" = 1 ]; then
  TEST_VM_PHASE=developer
fi
select_test_vm "$ROOT_DIR" "$BUILD" "$TEST_VM_PHASE" "$VMM"
IMG_TARGET="${FULL_TEST_IMG_TARGET:-$TEST_VM_IMG_TARGET}"

# Dedicated test images are created only while their owning tests run.
IMAGE_TARGETS=("$IMG_TARGET")
if [ "$TEST_VM_PHASE" = standard ]; then
  for required_target in main.img base.img; do
    [ "$IMG_TARGET" = "$required_target" ] || IMAGE_TARGETS+=("$required_target")
  done
fi

progress "building VM images and guest test binaries"
make -C "$ROOT_DIR" "${IMAGE_TARGETS[@]}" boot core sys-base user-base systest mio-test tokio-tests \
  crossterm-smoke wg-self-test BUILD="$BUILD" -j"$(nproc)"

# The host-side test binaries the suite runs. --no-run builds exactly what a
# later `cargo test` with the same build flags then runs. Keep Cargo's progress
# visible so lengthy compilation and linking do not look like a stalled suite.
host_build() {
  progress "building host tests: $1"
  shift
  cargo test --no-run "${profile_args[@]}" "$@"
}

(cd "$ROOT_DIR/src/imager" && host_build imager)
host_build rnetbench --manifest-path "$ROOT_DIR/src/bin/rnetbench/Cargo.toml"
host_build wg-peer --locked --manifest-path "$ROOT_DIR/src/tests/wg-peer/Cargo.toml"
for crate in red rmux rush russhd wg; do
  (cd "$ROOT_DIR/src/bin/$crate" && host_build "$crate")
done
# Fetches what test-crossterm-host.sh then runs offline.
progress "preparing crossterm host tests"
bash "$WD/test-crossterm-host.sh" --prepare "${profile_args[@]}"
host_build httpd-axum --locked --offline --manifest-path "$ROOT_DIR/src/bin/httpd-axum/Cargo.toml" --tests
host_build sys-init --manifest-path "$ROOT_DIR/src/sys/sys-init/Cargo.toml"
host_build moto-sys --manifest-path "$ROOT_DIR/src/sys/lib/moto-sys/Cargo.toml"
host_build moto-sdk --manifest-path "$ROOT_DIR/src/sys/lib/moto-sdk/Cargo.toml"
host_build "moto-sdk (no default features)" --no-default-features \
  --manifest-path "$ROOT_DIR/src/sys/lib/moto-sdk/Cargo.toml"
# Fetches and builds what test-sdk-package.sh then runs offline.
progress "preparing moto-sdk package tests"
bash "$WD/test-sdk-package.sh" --prepare "${profile_args[@]}"
host_build frusa --manifest-path "$ROOT_DIR/src/sys/lib/frusa/Cargo.toml"
# The same feature closure full-test.sh tests the netstack under: a different
# one compiles different code, and would be built again by the suite.
NETSTACK_FEATURES="async,assembler-max-segment-count-32,fragmentation-buffer-size-65536,iface-neighbor-cache-count-64,medium-ethernet,medium-ip,proto-ipv4,proto-ipv4-fragmentation,proto-ipv6,proto-ipv6-fragmentation,reassembly-buffer-count-4,reassembly-buffer-size-65536,socket-icmp,socket-tcp,socket-udp"
host_build netstack --manifest-path "$ROOT_DIR/src/sys/sys-io/netstack/Cargo.toml" \
  --no-default-features --features "$NETSTACK_FEATURES"
host_build "netstack (SLAAC)" --locked --offline --manifest-path "$ROOT_DIR/src/sys/sys-io/netstack/Cargo.toml" \
  --no-default-features --features "$NETSTACK_FEATURES,proto-ipv6-slaac" --lib
# motor-fs reads --cfg tokio_unstable from its own .cargo/config.toml, which
# cargo picks up only from the crate directory.
(cd "$ROOT_DIR/src/sys/lib/motor-fs" && host_build "motor-fs (image-admin)" --features image-admin)
# test-rust-analyzer.sh both tests and runs the analyzer smoke crate.
host_build rust-analyzer-smoke --locked --offline \
  --manifest-path "$ROOT_DIR/src/tests/rust-analyzer-smoke/Cargo.toml"
progress "building rust-analyzer-smoke host binary"
cargo build --locked --offline "${profile_args[@]}" \
  --manifest-path "$ROOT_DIR/src/tests/rust-analyzer-smoke/Cargo.toml"
# Only the developer-image suite runs test-gix.sh.
if [ "$TEST_VM_PHASE" = developer ]; then
  bash "$WD/test-gix.sh" --prepare
fi

echo "full-test-prepare ($BUILD) done"
