#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: cargo-identity.sh LORRY" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
FIXTURE="$SCRIPT_DIR/fixtures/cargo-identity"
LORRY="$(realpath "$1")"
MOTOR_TARGET="x86_64-unknown-motor"
if [ -z "${LORRY_TEST_CARGO:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
MOTOR_TOOLCHAIN="$LORRY_MOTOR_TOOLCHAIN"
MOTOR_LINKER="$LORRY_MOTOR_LINKER"
MOTOR_SYSROOT="$LORRY_MOTOR_SYSROOT"
WORK="$(mktemp -d /tmp/lorry-cargo-identity-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
LORRY_HOME="$WORK/home"
GLOBAL_CACHE="$WORK/global-cache"
HOST_RUSTUP_HOME="${RUSTUP_HOME:-${HOME:?}/.rustup}"
mkdir -p "$LORRY_HOME/.config/lorry"
printf 'config-version = 1\ncargo-compat-version = "1.99"\n[cache]\ndirectory = "%s"\n' \
    "$GLOBAL_CACHE" \
    >"$LORRY_HOME/.config/lorry/lorry.toml"

fail() {
    echo "cargo-identity: $*" >&2
    exit 1
}

compare_workspace_harnesses() {
    local lorry_root="$1" cargo_root="$2" label="$3" name lorry_file cargo_file
    local -a cargo_names
    mapfile -t cargo_names < <(find "$cargo_root" -type f -perm -111 \
        ! -name app -printf '%f\n' | sort)
    [ "${#cargo_names[@]}" -eq 3 ] || fail "$label Cargo harnesses are absent"
    for name in "${cargo_names[@]}"; do
        lorry_file="$(find "$lorry_root" -type f -name "$name" -print -quit)"
        cargo_file="$(find "$cargo_root" -type f -name "$name" -print -quit)"
        [ -n "$lorry_file" ] || fail "$label selected harness '$name' is absent"
        cmp "$lorry_file" "$cargo_file" ||
            fail "$label selected harness '$name' differs from Cargo"
    done
}

compare_shared_workspace() {
    local platform="$1" rustc="$2" label="$3" selectors member directory
    local -a target_arguments=() selection_arguments
    if [ -n "$platform" ]; then target_arguments=(--target "$platform"); fi
    for selectors in '' '-p app -p second' '--workspace' '--workspace --exclude second'; do
        read -r -a selection_arguments <<<"$selectors"
        directory="$WORK/cargo-workspace-$label-shared"
        (
            cd "$WORKSPACE"
            HOME="$LORRY_HOME" RUSTUP_HOME="$HOST_RUSTUP_HOME" RUSTC="$rustc" \
                "$LORRY" build --release "${target_arguments[@]}" "${selection_arguments[@]}" \
                --target-dir "$WORK/lorry-workspace-$label-shared" --message-format=json \
                >"$WORK/workspace-$label.lorry.json"
            RUSTC="$rustc" "$CARGO" build --release --locked --offline \
                "${target_arguments[@]}" "${selection_arguments[@]}" --target-dir "$directory" \
                --message-format=json >"$WORK/workspace-$label.cargo.json"
        )
        for member in app second; do
            if [ "$member" = second ] && [[ "$selectors" == *'--exclude second'* ]]; then continue; fi
            cmp "$WORK/lorry-workspace-$label-shared/lorry/${platform:+$platform/}release/$member" \
                "$directory/${platform:+$platform/}release/$member" ||
                fail "$label shared workspace executable '$member' differs from Cargo ($selectors)"
        done
        "$CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" \
            --locked --offline -- differential-workspace-messages \
            "$WORK/workspace-$label.lorry.json" "$WORK/workspace-$label.cargo.json"
    done
}

NATIVE_RUSTC="$LORRY_TEST_RUSTC"
MOTOR_RUSTC="$LORRY_TEST_RUSTC"
CARGO="$LORRY_TEST_CARGO"
[ -x "$MOTOR_LINKER" ] || fail "Motor linker '$MOTOR_LINKER' is absent"
[ -d "$MOTOR_SYSROOT/lib/rustlib/$MOTOR_TARGET" ] ||
    fail "Motor sysroot '$MOTOR_SYSROOT' is incomplete"

cp -R "$FIXTURE" "$WORK/project"
PROJECT="$WORK/project"

echo "== Comparing native release build, run, and test artifacts with Cargo =="
(
    cd "$PROJECT"
    HOME="$LORRY_HOME" RUSTUP_HOME="$HOST_RUSTUP_HOME" \
        RUSTC="$NATIVE_RUSTC" "$LORRY" build --release
    [ "$(HOME="$LORRY_HOME" RUSTUP_HOME="$HOST_RUSTUP_HOME" \
        RUSTC="$NATIVE_RUSTC" "$LORRY" run --release)" = \
        "lorry cargo identity fixture" ]
    [ "$(HOME="$LORRY_HOME" RUSTUP_HOME="$HOST_RUSTUP_HOME" \
        RUSTC="$NATIVE_RUSTC" "$LORRY" run --release --bin helper)" = \
        "lorry cargo identity helper" ]
    cp target/lorry/release/lorry_identity "$WORK/lorry-native"
    cp target/lorry/release/helper "$WORK/lorry-native-helper"
    HOME="$LORRY_HOME" RUSTUP_HOME="$HOST_RUSTUP_HOME" \
        RUSTC="$NATIVE_RUSTC" "$LORRY" test --release -- --quiet
    RUSTC="$NATIVE_RUSTC" "$CARGO" build --locked --offline --release \
        --target-dir "$WORK/cargo-native"
    RUSTC="$NATIVE_RUSTC" "$CARGO" test --locked --offline --release \
        --no-run --target-dir "$WORK/cargo-native-test"
)
cmp "$WORK/lorry-native" "$WORK/cargo-native/release/lorry_identity" ||
    fail "native release executable differs from Cargo"
cmp "$WORK/lorry-native-helper" "$WORK/cargo-native/release/helper" ||
    fail "native release helper executable differs from Cargo"
LORRY_NATIVE_TEST="$(find "$PROJECT/target/lorry/release/build/lorry_identity" \
    -type f -perm -111 -name 'lorry_identity-*' -print -quit)"
CARGO_NATIVE_TEST="$(find \
    "$WORK/cargo-native-test/release/build/lorry_identity" \
    -type f -perm -111 -name 'lorry_identity-*' -print -quit)"
[ -n "$LORRY_NATIVE_TEST" ] && [ -n "$CARGO_NATIVE_TEST" ] ||
    fail "native test harness is absent"
cmp "$LORRY_NATIVE_TEST" "$CARGO_NATIVE_TEST" ||
    fail "native release test harness differs from Cargo"
LORRY_NATIVE_HELPER_TEST="$(find "$PROJECT/target/lorry/release/build/lorry_identity" \
    -type f -perm -111 -name 'helper-*' -print -quit)"
CARGO_NATIVE_HELPER_TEST="$(find \
    "$WORK/cargo-native-test/release/build/lorry_identity" \
    -type f -perm -111 -name 'helper-*' -print -quit)"
cmp "$LORRY_NATIVE_HELPER_TEST" "$CARGO_NATIVE_HELPER_TEST" ||
    fail "native release helper test harness differs from Cargo"

cp -R "$SCRIPT_DIR/fixtures/cargo-identity-workspace" "$WORK/workspace"
WORKSPACE="$WORK/workspace"
echo "== Comparing selected workspace member with Cargo =="
(
    cd "$WORKSPACE"
    HOME="$LORRY_HOME" RUSTUP_HOME="$HOST_RUSTUP_HOME" \
        RUSTC="$NATIVE_RUSTC" "$LORRY" vendor --workspace --accept-all
    HOME="$LORRY_HOME" RUSTUP_HOME="$HOST_RUSTUP_HOME" \
        RUSTC="$NATIVE_RUSTC" "$LORRY" build -p app --release
    RUSTC="$NATIVE_RUSTC" "$CARGO" build -p app --locked --offline --release \
        --target-dir "$WORK/cargo-workspace-native"
)
cmp "$WORKSPACE/target/lorry/release/app" \
    "$WORK/cargo-workspace-native/release/app" ||
    fail "native selected member executable differs from Cargo"
[ "$("$WORKSPACE/target/lorry/release/app")" = \
    "app/src/main.rs app/src/lib.rs shared/src/lib.rs" ] ||
    fail "selected member source paths differ from Cargo"
(
    cd "$WORKSPACE"
    HOME="$LORRY_HOME" RUSTUP_HOME="$HOST_RUSTUP_HOME" \
        RUSTC="$NATIVE_RUSTC" "$LORRY" test -p app --release --no-run
    RUSTC="$NATIVE_RUSTC" "$CARGO" test -p app --locked --offline --release \
        --no-run --target-dir "$WORK/cargo-workspace-native-test"
)
compare_workspace_harnesses \
    "$WORKSPACE/target/lorry/release/build/app" \
    "$WORK/cargo-workspace-native-test/release/build/app" native
cmp "$WORKSPACE/target/lorry/release/app" \
    "$WORK/cargo-workspace-native-test/release/app" ||
    fail "native integration-test program differs from Cargo"

echo "== Comparing shared workspace selections and Cargo JSON =="
compare_shared_workspace "" "$NATIVE_RUSTC" native
[ "$("$WORK/lorry-workspace-native-shared/lorry/release/second")" = \
    "second/src/main.rs shared/src/lib.rs true true" ] ||
    fail "selected members did not share their dependency feature union"

echo "== Comparing native dev panic-abort artifacts with Cargo =="
(
    cd "$PROJECT"
    HOME="$LORRY_HOME" RUSTUP_HOME="$HOST_RUSTUP_HOME" \
        RUSTC="$NATIVE_RUSTC" "$LORRY" build
    cp target/lorry/debug/lorry_identity "$WORK/lorry-native-dev"
    cp target/lorry/debug/helper "$WORK/lorry-native-dev-helper"
    RUSTC="$NATIVE_RUSTC" "$CARGO" build --locked --offline \
        --target-dir "$WORK/cargo-native-dev"
)
cmp "$WORK/lorry-native-dev" "$WORK/cargo-native-dev/debug/lorry_identity" ||
    fail "native dev panic-abort executable differs from Cargo"
cmp "$WORK/lorry-native-dev-helper" "$WORK/cargo-native-dev/debug/helper" ||
    fail "native dev panic-abort helper differs from Cargo"

echo "== Comparing Linux-to-Motor release artifacts with Cargo =="
mkdir "$PROJECT/.cargo"
printf '[target.%s]\nlinker = "%s"\nrustflags = ["--sysroot=%s"]\n' \
    "$MOTOR_TARGET" "$MOTOR_LINKER" "$MOTOR_SYSROOT" \
    >"$PROJECT/.cargo/config.toml"
(
    cd "$PROJECT"
    HOME="$LORRY_HOME" RUSTUP_HOME="$HOST_RUSTUP_HOME" \
        "$LORRY" +"$MOTOR_TOOLCHAIN" build --release --target "$MOTOR_TARGET"
    cp "target/lorry/$MOTOR_TARGET/release/lorry_identity" \
        "$WORK/lorry-motor"
    cp "target/lorry/$MOTOR_TARGET/release/helper" "$WORK/lorry-motor-helper"
    HOME="$LORRY_HOME" RUSTUP_HOME="$HOST_RUSTUP_HOME" \
        "$LORRY" +"$MOTOR_TOOLCHAIN" test --release --target "$MOTOR_TARGET" \
            --no-run
    RUSTC="$MOTOR_RUSTC" "$CARGO" build --locked --offline --release \
        --target "$MOTOR_TARGET" --target-dir "$WORK/cargo-motor"
    RUSTC="$MOTOR_RUSTC" "$CARGO" test --locked --offline --release \
        --target "$MOTOR_TARGET" --no-run --target-dir "$WORK/cargo-motor-test"
)
cmp "$WORK/lorry-motor" \
    "$WORK/cargo-motor/$MOTOR_TARGET/release/lorry_identity" ||
    fail "Motor release executable differs from Cargo"
cmp "$WORK/lorry-motor-helper" \
    "$WORK/cargo-motor/$MOTOR_TARGET/release/helper" ||
    fail "Motor release helper executable differs from Cargo"
LORRY_MOTOR_TEST="$(find \
    "$PROJECT/target/lorry/$MOTOR_TARGET/release/build/lorry_identity" \
    -type f -perm -111 -name 'lorry_identity-*' -print -quit)"
CARGO_MOTOR_TEST="$(find \
    "$WORK/cargo-motor-test/$MOTOR_TARGET/release/build/lorry_identity" \
    -type f -perm -111 -name 'lorry_identity-*' -print -quit)"
[ -n "$LORRY_MOTOR_TEST" ] && [ -n "$CARGO_MOTOR_TEST" ] ||
    fail "Motor test harness is absent"
cmp "$LORRY_MOTOR_TEST" "$CARGO_MOTOR_TEST" ||
    fail "Motor release test harness differs from Cargo"
LORRY_MOTOR_HELPER_TEST="$(find \
    "$PROJECT/target/lorry/$MOTOR_TARGET/release/build/lorry_identity" \
    -type f -perm -111 -name 'helper-*' -print -quit)"
CARGO_MOTOR_HELPER_TEST="$(find \
    "$WORK/cargo-motor-test/$MOTOR_TARGET/release/build/lorry_identity" \
    -type f -perm -111 -name 'helper-*' -print -quit)"
cmp "$LORRY_MOTOR_HELPER_TEST" "$CARGO_MOTOR_HELPER_TEST" ||
    fail "Motor release helper test harness differs from Cargo"

mkdir "$WORKSPACE/.cargo"
cp "$PROJECT/.cargo/config.toml" "$WORKSPACE/.cargo/config.toml"
(
    cd "$WORKSPACE"
    HOME="$LORRY_HOME" RUSTUP_HOME="$HOST_RUSTUP_HOME" \
        "$LORRY" +"$MOTOR_TOOLCHAIN" build -p app --release --target "$MOTOR_TARGET"
    RUSTC="$MOTOR_RUSTC" "$CARGO" build -p app --locked --offline --release \
        --target "$MOTOR_TARGET" --target-dir "$WORK/cargo-workspace-motor"
)
cmp "$WORKSPACE/target/lorry/$MOTOR_TARGET/release/app" \
    "$WORK/cargo-workspace-motor/$MOTOR_TARGET/release/app" ||
    fail "Motor selected member executable differs from Cargo"
(
    cd "$WORKSPACE"
    HOME="$LORRY_HOME" RUSTUP_HOME="$HOST_RUSTUP_HOME" \
        "$LORRY" +"$MOTOR_TOOLCHAIN" test -p app --release \
        --target "$MOTOR_TARGET" --no-run
    RUSTC="$MOTOR_RUSTC" "$CARGO" test -p app --locked --offline --release \
        --target "$MOTOR_TARGET" --no-run \
        --target-dir "$WORK/cargo-workspace-motor-test"
)
compare_workspace_harnesses \
    "$WORKSPACE/target/lorry/$MOTOR_TARGET/release/build/app" \
    "$WORK/cargo-workspace-motor-test/$MOTOR_TARGET/release/build/app" Motor
cmp "$WORKSPACE/target/lorry/$MOTOR_TARGET/release/app" \
    "$WORK/cargo-workspace-motor-test/$MOTOR_TARGET/release/app" ||
    fail "Motor integration-test program differs from Cargo"

compare_shared_workspace "$MOTOR_TARGET" "$MOTOR_RUSTC" Motor

echo "== Cleaning the package-independent global Lorry cache =="
[ -d "$GLOBAL_CACHE/v1/units/sha256" ] ||
    fail "configured global cache was not created"
HOME="$LORRY_HOME" "$LORRY" cache clean
[ ! -e "$GLOBAL_CACHE" ] ||
    fail "cache clean retained the global cache root"
HOME="$LORRY_HOME" "$LORRY" --quiet cache clean

echo "PASS: Lorry matches Cargo's native and Motor release artifacts"
