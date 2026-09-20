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

TEST_VM_PHASE=standard
if [ "${FULL_TEST_VERIFY_DEV_SOURCES:-0}" = 1 ]; then
  TEST_VM_PHASE=developer
fi
select_test_vm "$ROOT_DIR" "$BUILD" "$TEST_VM_PHASE" "$VMM"
IMG_TARGET="${FULL_TEST_IMG_TARGET:-$TEST_VM_IMG_TARGET}"

# The suite's own image targets, plus the two images its VM tests build for
# themselves: test-vsock.sh and test-system-tty.sh.
IMAGE_TARGETS=("$IMG_TARGET" vsock-test.img system-tty.img)
if [ "$TEST_VM_PHASE" = standard ]; then
  for required_target in main.img base.img; do
    [ "$IMG_TARGET" = "$required_target" ] || IMAGE_TARGETS+=("$required_target")
  done
fi

make -C "$ROOT_DIR" "${IMAGE_TARGETS[@]}" systest mio-test tokio-tests \
  crossterm-smoke BUILD="$BUILD" -j"$(nproc)"

# The host-side test binaries the suite runs. --no-run builds exactly what a
# later `cargo test` with the same flags then runs; --quiet only keeps the
# output of this script to the compilation that is actually new.
host_build() {
  cargo test --no-run --quiet "${profile_args[@]}" "$@"
}

(cd "$ROOT_DIR/src/imager" && host_build)
host_build --manifest-path "$ROOT_DIR/src/bin/rnetbench/Cargo.toml"
for crate in red rmux rush russhd; do
  (cd "$ROOT_DIR/src/bin/$crate" && host_build)
done
host_build --offline --manifest-path "$ROOT_DIR/src/bin/httpd-axum/Cargo.toml" --tests
# test-gears-http.sh: curl's host binary, then Gears against it.
for crate in curl gears gears-mock-provider; do
  host_build --locked --manifest-path "$ROOT_DIR/src/bin/$crate/Cargo.toml"
done
cargo build --quiet --locked "${profile_args[@]}" \
  --manifest-path "$ROOT_DIR/src/bin/gears-mock-provider/Cargo.toml"
host_build --manifest-path "$ROOT_DIR/src/sys/sys-init/Cargo.toml"
host_build --manifest-path "$ROOT_DIR/src/sys/lib/moto-sys/Cargo.toml"
host_build --locked --offline \
  --manifest-path "$ROOT_DIR/src/sys/lib/moto-mpmc/Cargo.toml" --test fallible
host_build --locked --offline \
  --manifest-path "$ROOT_DIR/src/sys/lib/moto-async/Cargo.toml" \
  --features host-construction-test --test fallible
host_build --manifest-path "$ROOT_DIR/src/sys/lib/moto-tooling/Cargo.toml"
host_build --manifest-path "$ROOT_DIR/src/sys/lib/frusa/Cargo.toml"
# The same feature closure full-test.sh tests the netstack under: a different
# one compiles different code, and would be built again by the suite.
NETSTACK_FEATURES="async,assembler-max-segment-count-32,fragmentation-buffer-size-65536,iface-neighbor-cache-count-64,medium-ethernet,medium-ip,proto-ipv4,proto-ipv4-fragmentation,proto-ipv6,proto-ipv6-fragmentation,reassembly-buffer-count-4,reassembly-buffer-size-65536,socket-icmp,socket-tcp,socket-udp"
host_build --manifest-path "$ROOT_DIR/src/sys/sys-io/netstack/Cargo.toml" \
  --no-default-features --features "$NETSTACK_FEATURES"
# motor-fs reads --cfg tokio_unstable from its own .cargo/config.toml, which
# cargo picks up only from the crate directory.
(cd "$ROOT_DIR/src/sys/lib/motor-fs" && host_build --features image-admin)
# test-rust-analyzer.sh both tests and runs the analyzer smoke crate.
host_build --locked --offline \
  --manifest-path "$ROOT_DIR/src/tests/rust-analyzer-smoke/Cargo.toml"
cargo build --quiet --locked --offline "${profile_args[@]}" \
  --manifest-path "$ROOT_DIR/src/tests/rust-analyzer-smoke/Cargo.toml"

echo "full-test-prepare ($BUILD) done"
