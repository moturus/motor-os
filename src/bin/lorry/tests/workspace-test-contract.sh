#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true
LORRY="$(realpath "${1:?usage: workspace-test-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
export RUSTC="$LORRY_TEST_RUSTC"
WORK="$(mktemp -d /tmp/lorry-workspace-test-XXXXXX)"
trap 'status=$?; if [ "$status" = 0 ]; then rm -rf "$WORK"; else echo "Retained failed fixture: $WORK" >&2; fi' EXIT
mkdir -p "$WORK/home/.config/lorry" "$WORK/project/.cargo"
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" >"$WORK/home/.config/lorry/lorry.toml"
cat >"$WORK/project/Cargo.toml" <<'EOF'
[workspace]
members = ["zeta", "alpha"]
resolver = "2"
EOF
cat >"$WORK/project/lorry.toml" <<'EOF'
config-version = 1
[policy.rules.alpha]
action = "allow"
name = "alpha"
source = "path"
allow-build-script = true
[policy.rules.zeta]
action = "allow"
name = "zeta"
source = "path"
allow-build-script = true
EOF
for member in alpha zeta; do
    mkdir -p "$WORK/project/$member/src" "$WORK/project/$member/tests"
    cat >"$WORK/project/$member/Cargo.toml" <<EOF
[package]
name = "$member"
version = "1.0.0"
edition = "2024"
[lib]
harness = false
doctest = false
[[bin]]
name = "$member"
harness = false
[[test]]
name = "integration"
harness = false
[features]
manual = []
selected = []
dev = []
EOF
    cat >"$WORK/project/$member/build.rs" <<'EOF'
fn main() {
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("generated.rs"), "pub const GENERATED: u32 = 42;").unwrap();
    println!("cargo:rustc-env=SCRIPT_OWNER={}", std::env::var("CARGO_PKG_NAME").unwrap());
    println!("cargo:rerun-if-changed=build.rs");
}
EOF
    cat >"$WORK/project/$member/assert-runtime.rs" <<'EOF'
fn assert_runtime(kind: &str) {
    assert_eq!(std::env::current_dir().unwrap(), std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    assert_eq!(std::env::var("CARGO_PKG_NAME").unwrap(), env!("CARGO_PKG_NAME"));
    assert_eq!(std::env::var("SCRIPT_OWNER").unwrap(), env!("CARGO_PKG_NAME"));
    assert_eq!(std::env::var("OUT_DIR").unwrap(), env!("OUT_DIR"));
    println!("{} {kind} manual={}", env!("CARGO_PKG_NAME"), cfg!(feature = "manual"));
}
EOF
    cat >"$WORK/project/$member/src/lib.rs" <<'EOF'
include!(concat!(env!("OUT_DIR"), "/generated.rs"));
pub fn value() -> u32 { GENERATED }
#[cfg(test)]
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/assert-runtime.rs"));
#[cfg(test)]
fn main() { assert_runtime("library"); }
EOF
    cat >"$WORK/project/$member/src/main.rs" <<'EOF'
#[cfg(test)]
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/assert-runtime.rs"));
fn main() {
    #[cfg(test)] {
        assert_runtime("binary");
        if std::env::var_os("TEST_FAIL").is_some() && env!("CARGO_PKG_NAME") == "alpha" {
            std::process::exit(7);
        }
    }
    #[cfg(not(test))] { print!("{}", env!("CARGO_PKG_NAME")); }
}
EOF
    cat >"$WORK/project/$member/tests/integration.rs" <<EOF
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/assert-runtime.rs"));
fn main() {
    assert_eq!($member::value(), 42);
    let program = std::process::Command::new(env!("CARGO_BIN_EXE_$member")).output().unwrap();
    assert!(program.status.success());
    assert_eq!(program.stdout, b"$member");
    assert_runtime("integration");
}
EOF
done
cat >>"$WORK/project/alpha/Cargo.toml" <<'EOF'
[dev-dependencies]
zeta = { path = "../zeta", features = ["dev"] }
EOF
cat >>"$WORK/project/alpha/src/lib.rs" <<'EOF'
#[cfg(test)]
const _: fn() -> u32 = zeta::value;
EOF
cat >>"$WORK/project/zeta/Cargo.toml" <<'EOF'
[dependencies]
alpha = { path = "../alpha", features = ["selected"] }
EOF
printf '[target.x86_64-unknown-motor]\nlinker = "%s"\nrustflags = ["--sysroot=%s"]\n' \
    "$LORRY_MOTOR_LINKER" "$LORRY_MOTOR_SYSROOT" >"$WORK/project/.cargo/config.toml"
cd "$WORK/project"
"$LORRY_TEST_CARGO" generate-lockfile --offline
for platform in native motor; do
    target=()
    if [ "$platform" = motor ]; then target=(--target x86_64-unknown-motor); fi
    env HOME="$WORK/home" "$LORRY" test --workspace --no-run "${target[@]}" --message-format=json >"$WORK/lorry.json"
    "$LORRY_TEST_CARGO" test --workspace --no-run "${target[@]}" --offline --message-format=json >"$WORK/cargo.json"
    "$LORRY_TEST_CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" --locked --offline -- \
        differential-script-clean-messages "$WORK/lorry.json" "$WORK/cargo.json"
done
for arguments in workspace named features; do
    selection=(--workspace)
    if [ "$arguments" = named ]; then selection=(-p zeta -p alpha --test integration); fi
    if [ "$arguments" = features ]; then selection=(-p alpha --features manual --test integration); fi
    env HOME="$WORK/home" "$LORRY" test "${selection[@]}" >"$WORK/lorry.out"
    "$LORRY_TEST_CARGO" test "${selection[@]}" --offline >"$WORK/cargo.out"
    cmp "$WORK/lorry.out" "$WORK/cargo.out"
done
for policy in default all; do
    arguments=()
    expected=7
    if [ "$policy" = all ]; then arguments=(--no-fail-fast); expected=101; fi
    set +e
    env HOME="$WORK/home" TEST_FAIL=1 "$LORRY" test --workspace "${arguments[@]}" >"$WORK/lorry-failure.out" 2>"$WORK/lorry-failure.err"
    lorry_status=$?
    TEST_FAIL=1 "$LORRY_TEST_CARGO" test --workspace --offline "${arguments[@]}" >"$WORK/cargo-failure.out" 2>"$WORK/cargo-failure.err"
    cargo_status=$?
    set -e
    [ "$lorry_status" = "$expected" ] && [ "$cargo_status" = "$expected" ]
    cmp "$WORK/lorry-failure.out" "$WORK/cargo-failure.out"
    if [ "$policy" = all ]; then rg -F '1 test targets failed:' "$WORK/lorry-failure.err" >/dev/null; fi
done
printf '\ncompile_error!("later target failed");\n' >>zeta/tests/integration.rs
for compiler in lorry cargo; do
    command=(env HOME="$WORK/home" "$LORRY")
    if [ "$compiler" = cargo ]; then command=("$LORRY_TEST_CARGO"); fi
    set +e
    "${command[@]}" test --workspace --no-fail-fast --message-format=json >"$WORK/$compiler-build-failure.json" 2>"$WORK/$compiler-build-failure.err"
    status=$?
    set -e
    [ "$status" = 101 ]
    python3 - "$WORK/$compiler-build-failure.json" <<'PY'
import json, sys
events = [json.loads(line) for line in open(sys.argv[1])]
assert events[-1] == {'reason': 'build-finished', 'success': False}
assert any(event['reason'] == 'compiler-message' and event['message']['level'] == 'error' for event in events)
assert not any(event['reason'] == 'build-finished' and event['success'] for event in events)
PY
done
mkdir -p "$WORK/empty/src"
cat >"$WORK/empty/Cargo.toml" <<'EOF'
[package]
name = "empty"
version = "1.0.0"
edition = "2024"
[lib]
test = false
doctest = false
EOF
printf 'compile_error!("unused library");\n' >"$WORK/empty/src/lib.rs"
cd "$WORK/empty"
"$LORRY_TEST_CARGO" generate-lockfile --offline
env HOME="$WORK/home" "$LORRY" test --message-format=json >"$WORK/lorry-empty.json"
"$LORRY_TEST_CARGO" test --offline --message-format=json >"$WORK/cargo-empty.json"
cmp "$WORK/lorry-empty.json" "$WORK/cargo-empty.json"
echo "PASS: workspace tests match Cargo target order, dev cycle, script environments, features, and native/cross artifacts"
