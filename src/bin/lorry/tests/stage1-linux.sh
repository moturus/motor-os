#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LORRY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$LORRY_DIR/../../.." && pwd)"
RED_DIR="$ROOT_DIR/src/bin/red"
MOTOR_TARGET="x86_64-unknown-motor"
MOTOR_TOOLCHAIN="${LORRY_MOTOR_TOOLCHAIN:-dev-x86_64-unknown-motor}"

WORK="$(mktemp -d /tmp/lorry-stage1-linux-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

fail() {
    echo "stage1-linux: $*" >&2
    exit 1
}

copy_package() {
    local source="$1"
    local destination="$2"
    cp -R "$source" "$destination"
    rm -rf "$destination/target"
}

expect_status() {
    local expected="$1"
    local pattern="$2"
    shift 2
    local output="$WORK/expected-failure"
    set +e
    "$@" >"$output.out" 2>"$output.err"
    local status=$?
    set -e
    [ "$status" -eq "$expected" ] ||
        fail "expected status $expected, got $status from: $*"
    grep -F "$pattern" "$output.err" >/dev/null ||
        fail "failure from '$*' did not contain '$pattern'"
}

unset CARGO_TARGET_DIR RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export HOME="$WORK/home"
export CARGO_HOME="$WORK/cargo-home"
mkdir -p "$HOME" "$CARGO_HOME"

NATIVE_RUSTC="$(rustup which rustc --toolchain nightly-2026-06-19)"
MOTOR_RUSTC="$(rustup which rustc --toolchain "$MOTOR_TOOLCHAIN")"
CARGO_197="$(rustup which cargo --toolchain stable)"
CARGO_198="$(rustup which cargo --toolchain nightly-2026-06-19)"
SEED="$WORK/lorry-seed"

echo "== Stage 1 unit and direct-rustc bootstrap =="
cargo test --manifest-path "$LORRY_DIR/Cargo.toml" --locked
rustc --edition=2024 "$LORRY_DIR/src/main.rs" -o "$SEED"
"$SEED" --version | grep -Fx "lorry 0.1.0" >/dev/null

echo "== CLI, manifest, lock, and environment failures =="
expect_status 1 "unknown option" "$SEED" build --jobs 2
copy_package "$RED_DIR" "$WORK/red-stale"
sed -i 's/version = "0.1.0"/version = "0.1.1"/' "$WORK/red-stale/Cargo.toml"
(
    cd "$WORK/red-stale"
    expect_status 101 "Cargo.lock is stale" "$SEED" build
)
(
    cd "$RED_DIR"
    expect_status 101 "CARGO_TARGET_DIR" env CARGO_TARGET_DIR="$WORK/elsewhere" "$SEED" build
    expect_status 101 "RUSTC_WRAPPER" env RUSTC_WRAPPER=/bin/false "$SEED" build
)

echo "== Native red build/test and Cargo release identity =="
copy_package "$RED_DIR" "$WORK/red"
(
    cd "$WORK/red"
    RUSTC="$NATIVE_RUSTC" "$SEED" build
    RUSTC="$NATIVE_RUSTC" "$SEED" test
    RUSTC="$NATIVE_RUSTC" "$SEED" build --release
)
native_expected="19fff3757a528fab4ea897ea097282512caa10ea33431e858a68697b21eadc63"
[ "$(sha256sum "$WORK/red/target/lorry/release/red" | awk '{print $1}')" = "$native_expected" ] ||
    fail "native red release artifact differs from the frozen oracle"

for family in 197 198; do
    cargo_var="CARGO_$family"
    cargo_bin="${!cargo_var}"
    target_dir="$WORK/cargo-$family-native"
    (
        cd "$WORK/red"
        RUSTC="$NATIVE_RUSTC" "$cargo_bin" build --locked --release --target-dir "$target_dir"
    )
    cmp "$WORK/red/target/lorry/release/red" "$target_dir/release/red" ||
        fail "Cargo $family and Lorry native release outputs differ"
done

(
    cd "$WORK/red"
    RUSTC="$NATIVE_RUSTC" "$SEED" test --release
)
native_test="$WORK/red/target/lorry/release/deps/red-07186d9f96045ca2"
native_test_digest="$(sha256sum "$native_test" | awk '{print $1}')"
native_test_expected="a9158a495c753ef588b2eaccb9a227e7c7168ad1ecea0d6db909c40c3d7a9938"
[ "$native_test_digest" = "$native_test_expected" ] ||
    fail "native red release-test artifact differs from the frozen oracle"
(
    cd "$WORK/red"
    RUSTC="$NATIVE_RUSTC" "$CARGO_198" test --locked --release --no-run \
        --target-dir "$WORK/cargo-test-native"
)
cargo_native_test="$(find "$WORK/cargo-test-native/release/deps" -maxdepth 1 \
    -type f -perm -111 -name 'red-*' | head -1)"
cmp "$native_test" "$cargo_native_test" ||
    fail "Cargo and Lorry native release-test outputs differ"

echo "== Linux-to-Motor red build/test identity =="
mkdir -p "$WORK/red/.cargo"
cat >"$WORK/red/.cargo/config.toml" <<EOF
[target.$MOTOR_TARGET]
runner = "/bin/true"
EOF
(
    cd "$WORK/red"
    "$SEED" +"$MOTOR_TOOLCHAIN" build --release --target "$MOTOR_TARGET"
)
motor_expected="707cac65e1f0ed3c6d9a38ab52393965eb573fc758df0ccfb38a2b3f12bfe647"
motor_lorry="$WORK/red/target/lorry/$MOTOR_TARGET/release/red"
[ "$(sha256sum "$motor_lorry" | awk '{print $1}')" = "$motor_expected" ] ||
    fail "cross-Motor red release artifact differs from the frozen oracle"

for family in 197 198; do
    cargo_var="CARGO_$family"
    cargo_bin="${!cargo_var}"
    target_dir="$WORK/cargo-$family-motor"
    (
        cd "$WORK/red"
        RUSTC="$MOTOR_RUSTC" "$cargo_bin" build --locked --release \
            --target "$MOTOR_TARGET" --target-dir "$target_dir"
    )
    cmp "$motor_lorry" "$target_dir/$MOTOR_TARGET/release/red" ||
        fail "Cargo $family and Lorry cross-Motor release outputs differ"
done

(
    cd "$WORK/red"
    "$SEED" +"$MOTOR_TOOLCHAIN" test --release --target "$MOTOR_TARGET"
)
motor_test="$WORK/red/target/lorry/$MOTOR_TARGET/release/deps/red-d6ce5b974d464d9b"
motor_test_digest="$(sha256sum "$motor_test" | awk '{print $1}')"
motor_test_expected="31baa390cf86af978633f5b882e4d308b20e3e42b06726a20d539d3cb7be1f7f"
[ "$motor_test_digest" = "$motor_test_expected" ] ||
    fail "cross-Motor red release-test artifact differs from the frozen oracle"
(
    cd "$WORK/red"
    RUSTC="$MOTOR_RUSTC" "$CARGO_198" test --locked --release --no-run \
        --target "$MOTOR_TARGET" --target-dir "$WORK/cargo-test-motor"
)
cargo_motor_test="$(find "$WORK/cargo-test-motor/$MOTOR_TARGET/release/deps" \
    -maxdepth 1 -type f -perm -111 -name 'red-*' | head -1)"
cmp "$motor_test" "$cargo_motor_test" ||
    fail "Cargo and Lorry cross-Motor release-test outputs differ"

echo "== run arguments, unit-test arguments, and child status =="
mkdir -p "$WORK/run-fixture/src"
cat >"$WORK/run-fixture/Cargo.toml" <<'EOF'
[package]
name = "stage1-run"
version = "1.2.3-alpha"
edition = "2024"

[dependencies]
EOF
cat >"$WORK/run-fixture/Cargo.lock" <<'EOF'
version = 4

[[package]]
name = "stage1-run"
version = "1.2.3-alpha"
EOF
cat >"$WORK/run-fixture/src/main.rs" <<'EOF'
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str) == Some("exit-7") {
        std::process::exit(7);
    }
    println!("{}", args.join("|"));
}

#[test]
fn package_environment_is_set() {
    assert_eq!(env!("CARGO_PKG_NAME"), "stage1-run");
    assert_eq!(env!("CARGO_PKG_VERSION_PRE"), "alpha");
}
EOF
(
    cd "$WORK/run-fixture"
    [ "$("$SEED" run -- one "two words" --flag)" = "one|two words|--flag" ] ||
        fail "run did not preserve child arguments"
    "$SEED" test -- --exact package_environment_is_set
    set +e
    "$SEED" run -- exit-7 >/dev/null 2>&1
    status=$?
    set -e
    [ "$status" -eq 7 ] || fail "run did not preserve child status 7"
)

echo "== core self-build and second-generation red gate =="
copy_package "$LORRY_DIR" "$WORK/lorry"
(
    cd "$WORK/lorry"
    RUSTC="$NATIVE_RUSTC" "$SEED" build --release
    RUSTC="$NATIVE_RUSTC" "$CARGO_198" build --locked --release \
        --target-dir "$WORK/cargo-lorry-native"
)
cmp "$WORK/lorry/target/lorry/release/lorry" \
    "$WORK/cargo-lorry-native/release/lorry" ||
    fail "Cargo and Lorry core native release outputs differ"
cp "$WORK/lorry/target/lorry/release/lorry" "$WORK/lorry-generation-1"
(
    cd "$WORK/lorry"
    RUSTC="$NATIVE_RUSTC" "$WORK/lorry-generation-1" build --release
)
cmp "$WORK/lorry/target/lorry/release/lorry" \
    "$WORK/cargo-lorry-native/release/lorry" ||
    fail "second-generation Lorry differs from Cargo oracle"

copy_package "$RED_DIR" "$WORK/red-generation-2"
(
    cd "$WORK/red-generation-2"
    RUSTC="$NATIVE_RUSTC" "$WORK/lorry/target/lorry/release/lorry" build --release
)
generation_2_digest="$(
    sha256sum "$WORK/red-generation-2/target/lorry/release/red" | awk '{print $1}'
)"
[ "$generation_2_digest" = "$native_expected" ] ||
    fail "second-generation Lorry failed the red release identity gate"

echo "== cross-Motor core self-build identity =="
(
    cd "$WORK/lorry"
    "$SEED" +"$MOTOR_TOOLCHAIN" build --release --target "$MOTOR_TARGET"
    RUSTC="$MOTOR_RUSTC" "$CARGO_198" build --locked --release \
        --target "$MOTOR_TARGET" --target-dir "$WORK/cargo-lorry-motor"
)
cmp "$WORK/lorry/target/lorry/$MOTOR_TARGET/release/lorry" \
    "$WORK/cargo-lorry-motor/$MOTOR_TARGET/release/lorry" ||
    fail "Cargo and Lorry core cross-Motor release outputs differ"

echo
echo "PASS: Stage 1 Linux, Cargo-oracle, cross-Motor, and self-build gates passed"
