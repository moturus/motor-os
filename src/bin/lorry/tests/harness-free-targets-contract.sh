#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true
LORRY="$(realpath "${1:?usage: harness-free-targets-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
export RUSTC="$LORRY_TEST_RUSTC"
WORK="$(mktemp -d /tmp/lorry-harness-free-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/home" "$WORK/project/src" "$WORK/project/.cargo"
cat >"$WORK/project/Cargo.toml" <<'EOF'
[package]
name = "probe"
version = "1.0.0"
edition = "2024"
[lib]
harness = false
doctest = false
[[bin]]
name = "probe"
harness = false
EOF
cat >"$WORK/project/src/lib.rs" <<'EOF'
pub fn answer() -> u32 { 42 }
#[cfg(test)]
fn main() {
    assert_eq!(answer(), 42);
    assert_eq!(std::env::var("CARGO_PKG_NAME").unwrap(), "probe");
    assert_eq!(std::env::current_dir().unwrap(), std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    println!("library test ran");
}
EOF
cat >"$WORK/project/src/main.rs" <<'EOF'
fn main() {
    assert_eq!(probe::answer(), 42);
    #[cfg(test)] {
        assert_eq!(std::env::var("CARGO_PKG_NAME").unwrap(), "probe");
        assert_eq!(std::env::current_dir().unwrap(), std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")));
        println!("binary test ran");
    }
}
EOF
printf '[target.x86_64-unknown-motor]\nlinker = "%s"\nrustflags = ["--sysroot=%s"]\n' \
    "$LORRY_MOTOR_LINKER" "$LORRY_MOTOR_SYSROOT" >"$WORK/project/.cargo/config.toml"
cd "$WORK/project"
"$LORRY_TEST_CARGO" generate-lockfile --offline
for platform in native motor; do
    target=()
    if [ "$platform" = motor ]; then target=(--target x86_64-unknown-motor); fi
    for command in test check; do
        arguments=(--no-run)
        if [ "$command" = check ]; then arguments=(--all-targets); fi
        env HOME="$WORK/home" "$LORRY" "$command" "${arguments[@]}" "${target[@]}" \
            --message-format=json >"$WORK/lorry.json"
        "$LORRY_TEST_CARGO" "$command" "${arguments[@]}" "${target[@]}" --offline \
            --message-format=json >"$WORK/cargo.json"
        comparison=differential-workspace-messages
        if [ "$command" = check ]; then comparison=differential-workspace-check-messages; fi
        "$LORRY_TEST_CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" \
            --locked --offline -- "$comparison" "$WORK/lorry.json" "$WORK/cargo.json"
        if [ "$command" = test ]; then
            python3 - "$WORK/lorry.json" "$WORK/cargo.json" <<'PY'
import json, pathlib, sys
def programs(path):
    return {(event['target']['name'], tuple(event['target']['kind'])):
            pathlib.Path(event['executable']).read_bytes()
            for line in open(path) for event in [json.loads(line)]
            if event['reason'] == 'compiler-artifact' and event['profile']['test']}
lorry, cargo = map(programs, sys.argv[1:])
assert len(lorry) == 2 and lorry == cargo
PY
        fi
    done
done
env HOME="$WORK/home" "$LORRY" test >"$WORK/lorry-run.out"
"$LORRY_TEST_CARGO" test --offline >"$WORK/cargo-run.out"
cmp "$WORK/lorry-run.out" "$WORK/cargo-run.out"
printf 'library test ran\nbinary test ran\n' >"$WORK/expected.out"
cmp "$WORK/expected.out" "$WORK/lorry-run.out"
echo "PASS: harness-free library/binary tests match Cargo native/cross bytes, check artifacts, and runtime"
