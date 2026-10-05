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
printf '\n[test]\nextraction-root = "%s"\n' "$WORK/extracted" >>"$WORK/project/lorry.toml"
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
        if std::env::var_os("TEST_ABORT").is_some() && env!("CARGO_PKG_NAME") == "alpha" {
            std::process::abort();
        }
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
cp alpha/Cargo.toml "$WORK/alpha-default-targets.toml"
mkdir -p alpha/examples alpha/benches
cat >>alpha/Cargo.toml <<'EOF'
[[example]]
name = "compiled"
[[example]]
name = "tested"
test = true
harness = false
[[example]]
name = "library-tested"
crate-type = ["rlib"]
test = true
harness = false
[[example]]
name = "disabled-test"
path = "examples/tested.rs"
test = true
harness = false
required-features = ["manual"]
[[bench]]
name = "optin"
test = true
harness = false
EOF
cat >alpha/examples/compiled.rs <<'EOF'
fn main() { panic!("compile-only example must never run"); }
EOF
for name in tested library-tested; do
    cat >"alpha/examples/$name.rs" <<EOF
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/assert-runtime.rs"));
fn main() {
    assert_eq!(alpha::value(), zeta::value());
    assert_runtime("$name");
}
EOF
done
cat >alpha/benches/optin.rs <<'EOF'
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/assert-runtime.rs"));
fn main() {
    assert_eq!(alpha::value(), zeta::value());
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_alpha")).output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"alpha");
    assert_runtime("bench");
}
EOF
for platform in native motor; do
    target=()
    if [ "$platform" = motor ]; then target=(--target x86_64-unknown-motor); fi
    env HOME="$WORK/home" "$LORRY" test --workspace --no-run "${target[@]}" --message-format=json >"$WORK/lorry.json"
    "$LORRY_TEST_CARGO" test --workspace --no-run "${target[@]}" --offline --message-format=json >"$WORK/cargo.json"
    "$LORRY_TEST_CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" --locked --offline -- \
        differential-script-clean-messages "$WORK/lorry.json" "$WORK/cargo.json"
done
for mode in ordinary bundle; do
    args=()
    if [ "$mode" = bundle ]; then args=(--bundle); fi
    env HOME="$WORK/home" "$LORRY" test --workspace "${args[@]}" >"$WORK/default-lorry.out"
    "$LORRY_TEST_CARGO" test --workspace --offline >"$WORK/default-cargo.out"
    cmp "$WORK/default-lorry.out" "$WORK/default-cargo.out"
done
# Prove compiler bytes separately from runtime assertions embedding artifact paths.
for selection in example library bench integration combined; do
    args=(--example tested)
    if [ "$selection" = library ]; then args=(--example library-tested); fi
    if [ "$selection" = bench ]; then args=(--bench optin); fi
    if [ "$selection" = integration ]; then args=(--test integration); fi
    if [ "$selection" = combined ]; then args=(--test integration --example tested --example library-tested --bench optin); fi
    for mode in ordinary bundle; do
        bundle=()
        if [ "$mode" = bundle ]; then bundle=(--bundle); fi
        env HOME="$WORK/home" "$LORRY" test -p alpha "${args[@]}" "${bundle[@]}" >"$WORK/selected-lorry.out"
        "$LORRY_TEST_CARGO" test -p alpha "${args[@]}" --offline >"$WORK/selected-cargo.out"
        cmp "$WORK/selected-lorry.out" "$WORK/selected-cargo.out"
    done
done
for source in alpha/examples/tested.rs alpha/examples/library-tested.rs alpha/benches/optin.rs; do
    printf 'fn main() { assert_eq!(alpha::value(), zeta::value()); }\n' >"$source"
done
for platform in native motor; do
    target=()
    if [ "$platform" = motor ]; then target=(--target x86_64-unknown-motor); fi
    env HOME="$WORK/home" "$LORRY" test --workspace --no-run "${target[@]}" --message-format=json >"$WORK/lorry-bytes.json"
    "$LORRY_TEST_CARGO" test --workspace --no-run "${target[@]}" --offline --message-format=json >"$WORK/cargo-bytes.json"
    python3 - "$WORK/lorry-bytes.json" "$WORK/cargo-bytes.json" <<'PYBYTES'
import json, pathlib, sys
def executables(path):
    return {event['target']['name']: pathlib.Path(event['executable']).read_bytes()
            for line in open(path) for event in [json.loads(line)]
            if event['reason'] == 'compiler-artifact' and event.get('executable')
            and event['target']['kind'] in [['example'], ['bench']]}
lorry, cargo = map(executables, sys.argv[1:])
assert set(lorry) == {'compiled', 'tested', 'library-tested', 'optin'}
assert lorry == cargo
PYBYTES
done
cp "$WORK/alpha-default-targets.toml" alpha/Cargo.toml
rm -r alpha/examples alpha/benches
for member in alpha zeta; do
    cp "$member/tests/integration.rs" "$WORK/$member-integration.rs"
    cat >>"$member/tests/integration.rs" <<EOF
const BIN_PATH: &[u8] = env!("CARGO_BIN_EXE_$member").as_bytes();
const _: () = assert!(BIN_PATH.len() == "placeholder:$member".len() && BIN_PATH[0] == b'p');
const TMP_PATH: &[u8] = env!("CARGO_TARGET_TMPDIR").as_bytes();
const _: () = assert!(TMP_PATH[TMP_PATH.len() - 3] == b't' && TMP_PATH[TMP_PATH.len() - 1] == b'p');
EOF
done
cp alpha/Cargo.toml "$WORK/alpha-manifest.toml"
mkdir alpha/examples alpha/benches
cat >alpha/examples/demo.rs <<'EOF'
fn main() {
    assert_eq!(alpha::value(), zeta::value());
    assert_eq!(env!("CARGO_BIN_NAME"), "demo");
}
EOF
cat >alpha/benches/measured.rs <<'EOF'
fn main() {
    assert_eq!(alpha::value(), zeta::value());
}
const BIN_PATH: &[u8] = env!("CARGO_BIN_EXE_alpha").as_bytes();
const _: () = assert!(BIN_PATH.len() == "placeholder:alpha".len() && BIN_PATH[0] == b'p');
const TMP_PATH: &[u8] = env!("CARGO_TARGET_TMPDIR").as_bytes();
const _: () = assert!(TMP_PATH[TMP_PATH.len() - 3] == b't' && TMP_PATH[TMP_PATH.len() - 1] == b'p');
EOF
cat >alpha/examples/library.rs <<'EOF'
pub fn example_value() -> u32 { alpha::value() + zeta::value() }
#[cfg(test)]
fn main() { assert_eq!(example_value(), 84); }
const _: () = assert!(option_env!("CARGO_BIN_NAME").is_none());
EOF
cat >>alpha/Cargo.toml <<'EOF'
[[example]]
name = "demo"
test = true
bench = true
harness = false
edition = "2021"
[[example]]
name = "disabled"
path = "examples/demo.rs"
required-features = ["manual"]
[[example]]
name = "library"
test = true
bench = true
harness = false
crate-type = ["rlib", "staticlib"]
[[bench]]
name = "measured"
test = true
bench = false
harness = false
[[test]]
name = "second"
test = false
bench = true
path = "tests/integration.rs"
harness = false
[[bench]]
name = "second"
path = "benches/measured.rs"
harness = false
EOF
python3 - <<'PY'
from pathlib import Path
path = Path('alpha/Cargo.toml')
path.write_text(path.read_text().replace('[lib]\n', '[lib]\ntest = false\nbench = true\ndoc = true\n')
                .replace('[[bin]]\n', '[[bin]]\ntest = false\nbench = true\ndoc = true\n'))
PY
for platform in native motor; do
    target=()
    if [ "$platform" = motor ]; then target=(--target x86_64-unknown-motor); fi
    for selection in all named examples example bench repeated tests benches groups; do
        args=(--workspace --all-targets)
        if [ "$selection" = named ]; then args=(-p zeta -p alpha --test second); fi
        if [ "$selection" = examples ]; then args=(--workspace --examples); fi
        if [ "$selection" = example ]; then args=(--workspace --example demo); fi
        if [ "$selection" = bench ]; then args=(-p alpha --bench measured); fi
        if [ "$selection" = tests ]; then args=(--workspace --tests --test missing); fi
        if [ "$selection" = benches ]; then args=(--workspace --benches --bench missing); fi
        if [ "$selection" = groups ]; then args=(--workspace --bins --tests --benches --bin missing --test missing --bench missing); fi
        if [ "$selection" = repeated ]; then args=(--workspace --bin alpha --bin zeta --test integration --test second --example demo --example library --bench measured --bench second); fi
        env HOME="$WORK/home" "$LORRY" check "${args[@]}" "${target[@]}" --message-format=json >"$WORK/lorry-check.json"
        "$LORRY_TEST_CARGO" check "${args[@]}" "${target[@]}" --offline --message-format=json >"$WORK/cargo-check.json"
        "$LORRY_TEST_CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" --locked --offline -- \
            differential-script-clean-check-messages "$WORK/lorry-check.json" "$WORK/cargo-check.json"
    done
done
for selector in --example --bench; do
    for tool in "$LORRY" "$LORRY_TEST_CARGO"; do
        if env HOME="$WORK/home" "$tool" check --workspace "$selector" missing --offline >"$WORK/missing.out" 2>"$WORK/missing.err"; then exit 1; fi
        rg -q 'no (example|bench) target named.*missing' "$WORK/missing.err"
    done
done
for tool in "$LORRY" "$LORRY_TEST_CARGO"; do
    if env HOME="$WORK/home" "$tool" check -p alpha --example disabled --offline >"$WORK/disabled.out" 2>"$WORK/disabled.err"; then exit 1; fi
    rg -q 'requires.*features' "$WORK/disabled.err"
    env HOME="$WORK/home" "$tool" check -p alpha --example disabled --features manual --offline
done
for member in alpha zeta; do cp "$WORK/$member-integration.rs" "$member/tests/integration.rs"; done
cp "$WORK/alpha-manifest.toml" alpha/Cargo.toml
rm -r alpha/examples alpha/benches
for arguments in workspace named features; do
    selection=(--workspace)
    if [ "$arguments" = named ]; then selection=(-p zeta -p alpha --test integration); fi
    if [ "$arguments" = features ]; then selection=(-p alpha --features manual --test integration); fi
    env HOME="$WORK/home" "$LORRY" test "${selection[@]}" >"$WORK/lorry.out"
    "$LORRY_TEST_CARGO" test "${selection[@]}" --offline >"$WORK/cargo.out"
    cmp "$WORK/lorry.out" "$WORK/cargo.out"
done
for platform in native motor; do
    target=()
    if [ "$platform" = motor ]; then target=(--target x86_64-unknown-motor); fi
    env HOME="$WORK/home" "$LORRY" test --workspace --bundle --no-run "${target[@]}" >"$WORK/bundles.out"
python3 - "$WORK/bundles.out" <<'PY'
import pathlib, sys
paths = [pathlib.Path(line.strip()) for line in open(sys.argv[1])]
assert [path.name for path in paths] == ['alpha-test-bundle', 'zeta-test-bundle']
assert all(path.is_file() for path in paths)
PY
done
env HOME="$WORK/home" "$LORRY" test --workspace --bundle >"$WORK/bundle-run.out"
"$LORRY_TEST_CARGO" test --workspace --offline >"$WORK/cargo-bundle-run.out"
cmp "$WORK/bundle-run.out" "$WORK/cargo-bundle-run.out"
env HOME="$WORK/home" "$LORRY" test --workspace --bundle --features alpha/manual >"$WORK/bundle-feature.out"
"$LORRY_TEST_CARGO" test --workspace --offline --features alpha/manual >"$WORK/cargo-bundle-feature.out"
cmp "$WORK/bundle-feature.out" "$WORK/cargo-bundle-feature.out"
env HOME="$WORK/home" "$LORRY" clean -p alpha
[ ! -e target/lorry/debug/alpha-test-bundle ]
[ -e target/lorry/debug/zeta-test-bundle ]
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
set +e
env HOME="$WORK/home" TEST_ABORT=1 "$LORRY" test --workspace >"$WORK/lorry-signal.out" 2>"$WORK/lorry-signal.err"
lorry_status=$?
TEST_ABORT=1 "$LORRY_TEST_CARGO" test --workspace --offline >"$WORK/cargo-signal.out" 2>"$WORK/cargo-signal.err"
cargo_status=$?
set -e
printf 'Signal failure exit statuses: lorry=%s cargo=%s\n' "$lorry_status" "$cargo_status"
[ "$cargo_status" = 101 ] && [ "$lorry_status" = "$cargo_status" ]
cmp "$WORK/lorry-signal.out" "$WORK/cargo-signal.out"
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
