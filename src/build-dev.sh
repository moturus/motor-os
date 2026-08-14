#!/usr/bin/env bash
#
# build-dev.sh — build the Motor OS dev image (vm_images/release/motor-os-dev.img).
#
# The dev image is the main image plus the native build tools and development
# programs: /bin/lorry, its /bin/curl transport, /bin/gears, /bin/rg, /bin/cc,
# /bin/c++, LLVM/Clang, rustc, and the Red/curl/Lorry sources under /user/src.
# It assumes the complete release environment already exists — run
# src/build-motor-os.sh first to stage LLVM, rustc, and ripgrep.

set -euo pipefail

log()  { printf '\033[1;34m[build-dev]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[build-dev]\033[0m ERROR: %s\n' "$*" >&2; exit 1; }
trap 'die "failed at line $LINENO"' ERR

usage() {
	cat << 'EOF'
Usage: src/build-dev.sh

Build the Motor OS dev image: everything the main image carries plus the native
build toolchain and development programs. Requires the release environment
built by src/build-motor-os.sh (the generated LLVM/rustc/rg inputs must exist).
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

[ -f "$MOTOR/img_files/generated/llvm/sys/tools/llvm/bin/llvm" ] ||
	die "generated LLVM image inputs are missing — run src/build-motor-os.sh first"
[ -f "$MOTOR/img_files/generated/rustc/sys/tools/rust/bin/rustc" ] ||
	die "generated rustc image inputs are missing — run src/build-motor-os.sh first"
[ -x "$MOTOR/img_files/generated/rg/bin/rg" ] ||
	die "generated ripgrep image input is missing — run src/build-motor-os.sh first"

[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

log "building the Motor OS dev image (make dev.img BUILD=release)"
( cd "$MOTOR" && make dev.img BUILD=release -j"$(nproc)" )

log "dev image built successfully"
log "image: $MOTOR/vm_images/release/motor-os-dev.img"
log "run:   cd \"$MOTOR/vm_images/release\" && ./run-dev.sh"
