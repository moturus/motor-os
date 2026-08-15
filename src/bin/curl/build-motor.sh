#!/usr/bin/env bash
# Build Motor OS curl and put it in $MOTO_BIN.
#
# curl cannot be built by plain cargo: its Cargo.toml patches `cc` and `ring`
# with the reviewed Motor trees under `.lorry/vendor/`, which only lorry
# materializes, from the Stage 2 system seed. So this script is the lorry
# pipeline that src/bin/lorry's gates use, cut down to one deliverable:
# seed (once, cached under build/lorry/stage2/), a staged copy of the curl
# package with the Motor linker and native-tool configs, and
# `lorry build --target x86_64-unknown-motor`.
#
# The seed's download cache lives under build/, so a `make clean` means the
# next build re-downloads the reviewed crates; everything after that first
# seeding is offline.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
LORRY_DIR="$ROOT_DIR/src/bin/lorry"
MOTO_RT_DIR="$ROOT_DIR/src/sys/lib/moto-rt"

MOTOR_TARGET="x86_64-unknown-motor"
MOTOR_TOOLCHAIN="${LORRY_MOTOR_TOOLCHAIN:-dev-x86_64-unknown-motor}"
# The same conventions as src/bin/lorry/tests/test-native.sh and the dns-resolver
# Makefile block: the cross linker and C toolchain live beside the checkout.
MOTOR_LINKER="${LORRY_MOTOR_LINKER:-$(realpath "$ROOT_DIR/../motor-sysroot")/bin/motor-clang}"
MOTOR_C_COMPILER="${LORRY_MOTOR_C_COMPILER:-$(realpath "$ROOT_DIR/../llvm-project")/build/bin/clang}"
MOTOR_C_SYSROOT="${LORRY_MOTOR_C_SYSROOT:-$(realpath "$ROOT_DIR/../motor-sysroot")}"
MOTOR_ARCHIVER="${LORRY_MOTOR_ARCHIVER:-$(realpath "$ROOT_DIR/../llvm-project")/build/bin/llvm-ar}"

STAGE2="$ROOT_DIR/build/lorry/stage2"
SEED="$STAGE2/system-seed"
CACHE="$STAGE2/download-cache"
# lorry reads its configuration from $HOME; a build-owned home keeps this
# pipeline out of the user's real ~/.config/lorry.
MAKE_HOME="$STAGE2/make-home"
STAGE="$STAGE2/curl-stage"

MOTO_BIN="${MOTO_BIN:?set MOTO_BIN to the image bin directory}"
LORRY="${LORRY_HOST:-}"

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
[ -x "$MOTOR_ARCHIVER" ] || fail "Motor archiver '$MOTOR_ARCHIVER' is not executable"

# Resolved before anything changes directory.
MOTOR_RUSTC="$(rustup which rustc --toolchain "$MOTOR_TOOLCHAIN")"

# The Stage 2 seed, installed once. With the download cache present this is
# offline; on a clean build directory it downloads the reviewed objects.
if [ ! -d "$SEED/objects" ] || [ ! -f "$MAKE_HOME/.config/lorry/lorry.toml" ]; then
    OFFLINE=()
    [ ! -d "$CACHE" ] || OFFLINE=(--offline)
    python3 "$LORRY_DIR/bootstrap/install_stage2_seed.py" \
        --manifest "$LORRY_DIR/bootstrap/stage2-seed.toml" \
        --build-repository "$SEED" \
        --host-repository "$MAKE_HOME/.config/lorry/system/vendor" \
        --host-user-repository "$MAKE_HOME/.config/lorry/vendor" \
        --host-config "$MAKE_HOME/.config/lorry/lorry.toml" \
        --image-repository "$STAGE2/image/vendor" \
        --motor-config "$STAGE2/image/lorry.toml" \
        --cache "$CACHE" \
        --mode full "${OFFLINE[@]}" \
        --host-c-compiler "$(type -P clang || echo "$MOTOR_C_COMPILER")" \
        --host-archiver "$(type -P ar || echo "$MOTOR_ARCHIVER")"
fi

# The Makefile supplies its explicit host-tool prerequisite. Keep direct
# script invocation useful for focused development builds.
if [ -z "$LORRY" ]; then
    (cd "$LORRY_DIR" && cargo build --release --locked)
    LORRY="$LORRY_DIR/target/release/lorry"
else
    [ -x "$LORRY" ] || fail "host lorry '$LORRY' is not executable"
fi

# A staged copy of the package, so the source tree stays pristine (the build
# writes `.lorry/vendor/` and machine-specific configs into the package).
# `target/` and `.lorry/` are kept between runs: they are the build cache.
PACKAGE="$STAGE/src/bin/curl"
mkdir -p "$PACKAGE" "$STAGE/src/sys/lib" "$STAGE/img_files/motor-os/sys/cfg/ssl"
find "$PACKAGE" -mindepth 1 -maxdepth 1 \
    ! -name target ! -name .lorry -exec rm -rf {} +
cp "$SCRIPT_DIR/Cargo.toml" "$SCRIPT_DIR/Cargo.lock" "$PACKAGE/"
cp -R "$SCRIPT_DIR/src" "$PACKAGE/src"
cp -R "$SCRIPT_DIR/tests" "$PACKAGE/tests"
rm -rf "$STAGE/src/sys/lib/moto-rt"
mkdir -p "$STAGE/src/sys/lib/moto-rt"
cp "$MOTO_RT_DIR/Cargo.toml" "$STAGE/src/sys/lib/moto-rt/"
cp -R "$MOTO_RT_DIR/src" "$STAGE/src/sys/lib/moto-rt/src"
cp "$ROOT_DIR/img_files/motor-os/sys/cfg/ssl/ssl-cert.pem" \
    "$STAGE/img_files/motor-os/sys/cfg/ssl/ssl-cert.pem"

mkdir -p "$PACKAGE/.cargo"
cat >"$PACKAGE/.cargo/config.toml" <<EOF
[target.$MOTOR_TARGET]
linker = "$MOTOR_LINKER"
EOF
cat >"$PACKAGE/lorry.toml" <<EOF
config-version = 1

[native-tools."$MOTOR_TARGET".c-compiler]
program = "$MOTOR_C_COMPILER"
prefix-args = []
flags = [
    "--no-default-config",
    "--target=$MOTOR_TARGET",
    "--sysroot=$MOTOR_C_SYSROOT",
    "-D_GNU_SOURCE",
    "-D_DEFAULT_SOURCE",
]

[native-tools."$MOTOR_TARGET".archiver]
program = "$MOTOR_ARCHIVER"
prefix-args = []
flags = []
EOF

(cd "$PACKAGE" && HOME="$MAKE_HOME" RUSTC="$MOTOR_RUSTC" \
    "$LORRY" build "${RELEASE[@]}" --target "$MOTOR_TARGET")

strip -o "$MOTO_BIN/curl" \
    "$PACKAGE/target/lorry/$MOTOR_TARGET/$PROFILE/curl"
echo "built $MOTO_BIN/curl"
