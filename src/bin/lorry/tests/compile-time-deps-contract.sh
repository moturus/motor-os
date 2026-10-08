#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true
LORRY="$(realpath "${1:?usage: compile-time-deps-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
export RUSTC="$LORRY_TEST_RUSTC"
WORK="$(mktemp -d /tmp/lorry-compile-time-deps-XXXXXX)"
trap 'status=$?; if [ "$status" = 0 ]; then rm -rf "$WORK"; else echo "Retained compile-time fixture: $WORK" >&2; fi' EXIT
mkdir -p "$WORK/home/.config/lorry" "$WORK/project"/{app,normal,derive,helper}/src "$WORK/project/.cargo"
printf 'config-version = 1\nuse-cargo-registry = false\n[cache]\ndirectory = "%s"\n' "$WORK/cache" >"$WORK/home/.config/lorry/lorry.toml"
cat >"$WORK/project/Cargo.toml" <<'EOF'
[workspace]
members = ["app", "normal", "derive", "helper"]
resolver = "2"
EOF
for member in app normal derive helper; do
    cat >"$WORK/project/$member/Cargo.toml" <<EOF
[package]
name = "$member"
version = "1.0.0"
edition = "2024"
[lib]
doctest = false
EOF
done
cat >>"$WORK/project/app/Cargo.toml" <<'EOF'
[dependencies]
normal = { path = "../normal" }
derive = { path = "../derive" }
[build-dependencies]
helper = { path = "../helper" }
EOF
cat >>"$WORK/project/derive/Cargo.toml" <<'EOF'
proc-macro = true
[dependencies]
helper = { path = "../helper" }
EOF
printf 'pub fn value() -> u32 { 42 }\n' >"$WORK/project/helper/src/lib.rs"
cat >"$WORK/project/derive/src/lib.rs" <<'EOF'
extern crate proc_macro;
#[proc_macro]
pub fn value(_: proc_macro::TokenStream) -> proc_macro::TokenStream {
    helper::value().to_string().parse().unwrap()
}
EOF
for member in app normal; do
    printf 'compile_error!("ordinary source must be skipped");\n' >"$WORK/project/$member/src/lib.rs"
done
printf 'config-version = 1\nuse-cargo-registry = false\n' >"$WORK/project/lorry.toml"
for member in app normal derive; do
    cat >"$WORK/project/$member/build.rs" <<'EOF'
fn main() {
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("generated.rs"), "const GENERATED: u32 = 42;\n").unwrap();
    println!("cargo::rustc-env=SCRIPT_OWNER={}", std::env::var("CARGO_PKG_NAME").unwrap());
}
EOF
    cat >>"$WORK/project/lorry.toml" <<EOF
[policy.rules.$member]
action = "allow"
source = "path"
name = "$member"
allow-build-script = true
EOF
    if [ "$member" = derive ]; then echo 'allow-proc-macro = true' >>"$WORK/project/lorry.toml"; fi
done
printf '[target.x86_64-unknown-motor]\nlinker = "%s"\nrustflags = ["--sysroot=%s"]\n' \
    "$LORRY_MOTOR_LINKER" "$LORRY_MOTOR_SYSROOT" >"$WORK/project/.cargo/config.toml"
cd "$WORK/project"
"$LORRY_TEST_CARGO" generate-lockfile --offline
cp Cargo.lock "$WORK/original.lock"
for platform in native motor; do
    target=()
    if [ "$platform" = motor ]; then target=(--target x86_64-unknown-motor); fi
    for selection in workspace macro-only; do
        packages=(--workspace)
        if [ "$selection" = macro-only ]; then packages=(-p derive); fi
        for builder in lorry cargo; do
            tool="$LORRY"
            unstable=()
            if [ "$builder" = cargo ]; then tool="$LORRY_TEST_CARGO"; unstable=(-Zunstable-options); fi
            env HOME="$WORK/home" __CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS=nightly \
                "$tool" check "${packages[@]}" --all-targets --keep-going --compile-time-deps \
                "${unstable[@]}" "${target[@]}" --offline --message-format=json \
                >"$WORK/$builder-$platform-$selection.json"
        done
        "$LORRY_TEST_CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" \
            --locked --offline -- differential-script-clean-check-messages \
            "$WORK/lorry-$platform-$selection.json" "$WORK/cargo-$platform-$selection.json"
        python3 - "$WORK/lorry-$platform-$selection.json" "$WORK/cargo-$platform-$selection.json" "$selection" <<'PY'
import json, pathlib, sys
def events(path):
    return [json.loads(line) for line in open(path)]
lorry, cargo = map(events, sys.argv[1:3])
expected_scripts = {'app', 'normal', 'derive'} if sys.argv[3] == 'workspace' else {'derive'}
for stream in [lorry, cargo]:
    assert stream[-1] == {'reason': 'build-finished', 'success': True}
    scripts = [e for e in stream if e['reason'] == 'build-script-executed']
    assert {dict(e['env'])['SCRIPT_OWNER'] for e in scripts} == expected_scripts
    for e in scripts:
        assert (pathlib.Path(e['out_dir']) / 'generated.rs').read_text() == 'const GENERATED: u32 = 42;\n'
    libraries = [e['target']['name'] for e in stream if e['reason'] == 'compiler-artifact'
                 and e['target']['kind'] != ['custom-build']]
    assert set(libraries) == ({'derive', 'helper'} if sys.argv[3] == 'workspace' else set())
def executable_artifacts(stream):
    return {pathlib.Path(p).name: pathlib.Path(p).read_bytes()
            for e in stream if e['reason'] == 'compiler-artifact' and e['target']['kind'] == ['proc-macro']
            for p in e['filenames']}
assert executable_artifacts(lorry) == executable_artifacts(cargo)
PY
    done
    for tool in "$LORRY" "$LORRY_TEST_CARGO"; do
        if env HOME="$WORK/home" "$tool" check --workspace --all-targets --keep-going \
            "${target[@]}" --offline >"$WORK/ordinary.out" 2>"$WORK/ordinary.err"; then exit 1; fi
        grep -F 'ordinary source must be skipped' "$WORK/ordinary.err" >/dev/null
    done
done
# rustc hashes the physical OUT_DIR used by include!, even with path remapping.
# Compile generated macro code separately from the path-free byte comparison.
sed -i '/extern crate proc_macro;/a include!(concat!(env!("OUT_DIR"), "/generated.rs"));' derive/src/lib.rs
sed -i 's/helper::value()/GENERATED/' derive/src/lib.rs
for platform in native motor; do
    target=()
    if [ "$platform" = motor ]; then target=(--target x86_64-unknown-motor); fi
    env HOME="$WORK/home" "$LORRY" check --workspace --all-targets --compile-time-deps \
        "${target[@]}" --message-format=json >"$WORK/generated-lorry.json"
    env HOME="$WORK/home" __CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS=nightly \
        "$LORRY_TEST_CARGO" check --workspace --all-targets --compile-time-deps -Zunstable-options \
        "${target[@]}" --offline --message-format=json >"$WORK/generated-cargo.json"
    "$LORRY_TEST_CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" \
        --locked --offline -- differential-script-clean-check-messages \
        "$WORK/generated-lorry.json" "$WORK/generated-cargo.json"
done
mv lorry.toml "$WORK/grants.toml"
if env HOME="$WORK/home" "$LORRY" check --workspace --compile-time-deps \
    --message-format=json >"$WORK/denied.json" 2>"$WORK/denied.err"; then exit 1; fi
grep -F 'build script' "$WORK/denied.err" >/dev/null
python3 - "$WORK/denied.json" <<'PY'
import json, sys
events = [json.loads(line) for line in open(sys.argv[1])]
assert events == [{'reason': 'build-finished', 'success': False}], events
PY
if env HOME="$WORK/home" "$LORRY" clippy --compile-time-deps >"$WORK/clippy.out" 2>"$WORK/clippy.err"; then exit 1; fi
grep -F 'unexpected argument' "$WORK/clippy.err" >/dev/null
cmp Cargo.lock "$WORK/original.lock"
echo 'PASS: compile-time checks match Cargo scripts, executable macros, artifacts, and policy without checking ordinary sources'
