#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true
LORRY="$(realpath "${1:?usage: explicit-tests-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
export RUSTC="$LORRY_TEST_RUSTC"
WORK="$(mktemp -d /tmp/lorry-explicit-tests-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/home" "$WORK/project/src" "$WORK/project/tests/directory" "$WORK/project/.cargo"
printf 'pub fn answer() -> u32 { 42 }\n' >"$WORK/project/src/lib.rs"
cat >"$WORK/project/tests/basic.rs" <<'EOF'
#[test]
fn basic() { assert_eq!(2 + 2, 4); }
EOF
cp "$WORK/project/tests/basic.rs" "$WORK/project/tests/directory/main.rs"
cp "$WORK/project/tests/basic.rs" "$WORK/project/tests/disabled.rs"
cat >"$WORK/project/tests/free.rs" <<'EOF'
#[cfg(test)]
fn main() {
    assert_eq!(std::env::var("CARGO_PKG_NAME").unwrap(), "probe");
    assert_eq!(std::env::current_dir().unwrap(), std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")));
}
EOF
printf 'compile_error!("unavailable feature target compiled");\n' >"$WORK/project/tests/needs.rs"
printf '[target.x86_64-unknown-motor]\nlinker = "%s"\nrustflags = ["--sysroot=%s"]\n' \
    "$LORRY_MOTOR_LINKER" "$LORRY_MOTOR_SYSROOT" >"$WORK/project/.cargo/config.toml"
cd "$WORK/project"
for discovery in disabled automatic legacy; do
    edition=2024
    if [ "$discovery" = legacy ]; then edition=2015; fi
    printf '[package]\nname = "probe"\nversion = "1.0.0"\nedition = "%s"\n' "$edition" >Cargo.toml
    if [ "$discovery" = disabled ]; then printf 'autotests = false\n' >>Cargo.toml; fi
    cat >>Cargo.toml <<'EOF'
[features]
extra = []
[lib]
test = false
doctest = false
[[test]]
name = "basic"
[[test]]
name = "directory"
[[test]]
name = "free"
harness = false
[[test]]
name = "disabled"
test = false
[[test]]
name = "needs"
required-features = ["extra"]
EOF
    if [ "$discovery" = automatic ]; then
        cp tests/basic.rs tests/ignored.rs
    else
        printf 'compile_error!("autodiscovery should be disabled");\n' >tests/ignored.rs
    fi
    "$LORRY_TEST_CARGO" generate-lockfile --offline
    for platform in native motor; do
        target=()
        if [ "$platform" = motor ]; then target=(--target x86_64-unknown-motor); fi
        for command in test check; do
            arguments=(--no-run)
            if [ "$command" = check ]; then arguments=(--test free); fi
            env HOME="$WORK/home" "$LORRY" "$command" "${arguments[@]}" "${target[@]}" \
                --message-format=json >"$WORK/lorry.json"
            "$LORRY_TEST_CARGO" "$command" "${arguments[@]}" "${target[@]}" --offline \
                --message-format=json >"$WORK/cargo.json"
            python3 - "$WORK/lorry.json" "$WORK/cargo.json" "$command" <<'PY'
import json, pathlib, sys
def artifacts(path):
    return sorted([(event['target'], event['profile'], event['features'],
                   sorted(pathlib.Path(p).suffix for p in event['filenames']))
                  for line in open(path) for event in [json.loads(line)]
                  if event['reason'] == 'compiler-artifact'], key=lambda event: (event[0]['name'], event[0]['kind']))
assert artifacts(sys.argv[1]) == artifacts(sys.argv[2])
if sys.argv[3] == 'test':
    def programs(path):
        return {event['target']['name']: pathlib.Path(event['executable']).read_bytes()
                for line in open(path) for event in [json.loads(line)]
                if event['reason'] == 'compiler-artifact' and event['profile']['test']}
    assert programs(sys.argv[1]) == programs(sys.argv[2])
PY
        done
    done
    env HOME="$WORK/home" "$LORRY" test --test free
    "$LORRY_TEST_CARGO" test --test free --offline
    env HOME="$WORK/home" "$LORRY" test --test disabled --no-run
    "$LORRY_TEST_CARGO" test --test disabled --no-run --offline
    for tool in "$LORRY" "$LORRY_TEST_CARGO"; do
        status=0
        env HOME="$WORK/home" "$tool" test --test needs --no-run >"$WORK/needs.out" 2>"$WORK/needs.err" || status=$?
        [ "$status" = 101 ]
        grep -Eq 'requires the features:.*extra' "$WORK/needs.err"
    done
done
echo "PASS: explicit, inferred, disabled, feature-gated, and harness-free tests match Cargo native/cross artifacts"
