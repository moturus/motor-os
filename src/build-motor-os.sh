#!/usr/bin/env bash
#
# build-motor-os.sh — build the complete Motor OS release environment.
#
# This is the single entry point for the workflows implemented by
# build-base.sh, build-llvm.sh, and build-rustc.sh. Run it from a Motor OS
# checkout; sibling Rust, LLVM, mlibc, sysroot, and Lua sources/builds live
# under $MOTORH (the checkout's parent by default).
#
# The stage scripts remain independently useful and contain the detailed build
# recipes. This driver supplies their common paths and orders them so the DNS
# resolver is built only after its mlibc/LLVM sysroot and the final Motor Rust
# toolchain exist.
#
# Generated image inputs are staged under:
#
#   img_files/generated/llvm
#   img_files/generated/rustc
#
# The tracked img_files/motor-os directory remains source-only. The imager
# combines all three roots when it creates the final filesystem.

set -euo pipefail

log()  { printf '\033[1;34m[build-motor-os]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[build-motor-os]\033[0m ERROR: %s\n' "$*" >&2; exit 1; }
trap 'die "failed at line $LINENO"' ERR

usage() {
	cat << 'EOF'
Usage: src/build-motor-os.sh

Build the complete Motor OS release image, including:
  - the bootstrap Motor Rust target toolchain;
  - host cross LLVM/Clang and the mlibc/libc++ sysroot;
  - native Motor OS LLVM/Clang, Lua, and rustc;
  - all Motor OS binaries, including /sys/dns-resolver;
  - vm_images/release/motor-os.img.

Environment:
  MOTORH  Development root for sibling checkouts and build trees.
          Defaults to the parent of the Motor OS checkout.

The build is incremental and safe to rerun. It downloads sources and packages,
uses sudo for missing Ubuntu packages and host VM setup, and does not start the
VM.
EOF
}

if [ "$#" -gt 0 ]; then
	case "$1" in
		-h|--help)
			usage
			exit 0
			;;
		*)
			usage >&2
			die "unknown argument: $1"
			;;
	esac
fi

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
MOTOR="$(cd "$SCRIPT_DIR/.." && pwd)"
[ -e "$MOTOR/.git" ] ||
	die "run this script from its Motor OS checkout; .git is missing at $MOTOR"

MOTORH="$(readlink -f "${MOTORH:-$MOTOR/..}")"
export MOTORH
export MOTOR_OS_DIR="$MOTOR"

BASE="$SCRIPT_DIR/build-base.sh"
LLVM="$SCRIPT_DIR/build-llvm.sh"
RUSTC="$SCRIPT_DIR/build-rustc.sh"
for stage in "$BASE" "$LLVM" "$RUSTC"; do
	[ -x "$stage" ] || die "required build stage is not executable: $stage"
done

log "complete Motor OS build starting"
log "Motor OS checkout: $MOTOR"
log "development root:  $MOTORH"

# A clean checkout cannot build dns-resolver yet: its C bridge needs the mlibc
# sysroot produced by the LLVM stage. The base stage therefore installs host
# dependencies and creates the bootstrap Rust target toolchain, but defers its
# historical early `make all`.
log "stage 1/3: host setup and bootstrap Motor Rust target"
MOTOR_SKIP_OS_BUILD=1 "$BASE"

# Build every C/C++ input, the native LLVM multicall, and Lua. Stage them into
# the generated LLVM image root, but do not create an intermediate image: the
# Rust stage will replace the bootstrap compiler and perform the definitive
# full build.
log "stage 2/3: Motor LLVM, mlibc/libc++, native LLVM, and Lua"
MOTOR_SKIP_BASE=1 MOTOR_SKIP_IMAGE_BUILD=1 "$LLVM"

# Build the forked native rustc and both standard libraries, rebuild the C ABI
# shim with that final toolchain, stage the native Rust toolchain, clear stale
# Cargo outputs, and run the final make all. `make all` includes dns-resolver.
log "stage 3/3: native Motor rustc and final Motor OS image"
"$RUSTC"

required_outputs=(
	"$MOTOR/img_files/generated/llvm/sys/tools/llvm/bin/llvm"
	"$MOTOR/img_files/generated/llvm/bin/cc"
	"$MOTOR/img_files/generated/rustc/sys/tools/rust/bin/rustc"
	"$MOTOR/build/bin/release/dns-resolver"
	"$MOTOR/vm_images/release/motor-os.img"
)
for output in "${required_outputs[@]}"; do
	[ -f "$output" ] || die "final build output is missing: $output"
done

log "complete release image built successfully"
log "image: $MOTOR/vm_images/release/motor-os.img"
log "run:   cd \"$MOTOR/vm_images/release\" && ./run-qemu.sh"
