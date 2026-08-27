#!/usr/bin/env bash
# Build Motor OS curl and put it in $MOTO_BIN.
#
# ring generates files from its Git checkout with host Perl before compiling
# them for Motor. Keep that host-only packaging step out of the native Lorry
# surface and cross-build curl directly with Cargo.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

MOTOR_TARGET="x86_64-unknown-motor"
MOTOR_LINKER="${LORRY_MOTOR_LINKER:-}"
MOTOR_C_COMPILER="${LORRY_MOTOR_C_COMPILER:-}"
MOTOR_C_SYSROOT="${LORRY_MOTOR_C_SYSROOT:-}"
MOTOR_ARCHIVER="${LORRY_MOTOR_ARCHIVER:-$(command -v ar)}"

if [ -n "${MOTOR_ASSEMBLY_IMAGE_ROOT:-}" ]; then
    ASSEMBLY_ROOT="$(realpath "$MOTOR_ASSEMBLY_IMAGE_ROOT/..")"
    MOTOR_C_SYSROOT="${MOTOR_C_SYSROOT:-$ASSEMBLY_ROOT/sysroot}"
    MOTOR_LINKER="${MOTOR_LINKER:-$MOTOR_C_SYSROOT/bin/motor-clang}"
    MOTOR_C_COMPILER="${MOTOR_C_COMPILER:-$MOTOR_C_SYSROOT/bin/motor-clang}"
fi

MOTO_BIN="${MOTO_BIN:?set MOTO_BIN to the image bin directory}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT_DIR/build/obj/curl}"

RELEASE=()
PROFILE="debug"
case "${1:-}" in
"") ;;
--release)
    RELEASE=(--release)
    PROFILE="release"
    ;;
*)
    echo "usage: build-motor.sh [--release]" >&2
    exit 1
    ;;
esac

fail() {
    echo "curl/build-motor: $*" >&2
    exit 1
}

[ -x "$MOTOR_LINKER" ] || fail "Motor linker '$MOTOR_LINKER' is not executable"
[ -x "$MOTOR_C_COMPILER" ] || fail "Motor C compiler '$MOTOR_C_COMPILER' is not executable"
[ -d "$MOTOR_C_SYSROOT" ] || fail "Motor C sysroot '$MOTOR_C_SYSROOT' is not a directory"
[ -x "$MOTOR_ARCHIVER" ] || fail "archiver '$MOTOR_ARCHIVER' is not executable"
type -P perl >/dev/null || fail "ring's Git build requires host Perl"

mkdir -p "$MOTO_BIN"
(cd "$SCRIPT_DIR" && \
    CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER="$MOTOR_LINKER" \
    CC_x86_64_unknown_motor="$MOTOR_C_COMPILER" \
    CFLAGS_x86_64_unknown_motor="--no-default-config --target=$MOTOR_TARGET --sysroot=$MOTOR_C_SYSROOT -D_GNU_SOURCE -D_DEFAULT_SOURCE" \
    AR_x86_64_unknown_motor="$MOTOR_ARCHIVER" \
    ARFLAGS_x86_64_unknown_motor="" \
    CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
    cargo build --target "$MOTOR_TARGET" "${RELEASE[@]}")

strip -o "$MOTO_BIN/curl" \
    "$CARGO_TARGET_DIR/$MOTOR_TARGET/$PROFILE/curl"
echo "built $MOTO_BIN/curl"
