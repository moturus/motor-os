#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true
LORRY="$(realpath "${1:?usage: motor-crate-types-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
export RUSTC="$LORRY_TEST_RUSTC"
WORK="$(mktemp -d /tmp/lorry-motor-crate-types-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/home" "$WORK/project/src" "$WORK/project/.cargo"
printf 'pub fn answer() -> u32 { 42 }\n' >"$WORK/project/src/lib.rs"
printf '[target.x86_64-unknown-motor]\nlinker = "%s"\nrustflags = ["--sysroot=%s"]\n' \
    "$LORRY_MOTOR_LINKER" "$LORRY_MOTOR_SYSROOT" >"$WORK/project/.cargo/config.toml"
cd "$WORK/project"
for types in '"rlib","cdylib"' '"rlib","dylib"' '"staticlib","cdylib"' '"cdylib"' '"dylib"'; do
    printf '[package]\nname = "probe"\nversion = "1.0.0"\nedition = "2024"\n[lib]\ncrate-type = [%s]\n' "$types" >Cargo.toml
    "$LORRY_TEST_CARGO" generate-lockfile --offline
    for command in build check; do
        cargo_status=0
        lorry_status=0
        env HOME="$WORK/home" "$LORRY" "$command" --target x86_64-unknown-motor \
            --message-format=json >"$WORK/lorry.json" 2>"$WORK/lorry.err" || lorry_status=$?
        "$LORRY_TEST_CARGO" "$command" --target x86_64-unknown-motor --offline \
            --message-format=json >"$WORK/cargo.json" 2>"$WORK/cargo.err" || cargo_status=$?
        [ "$lorry_status" = "$cargo_status" ]
        if [ "$cargo_status" != 0 ]; then
            [ "$command" = build ] && [ "$cargo_status" = 101 ]
            rg -q 'does not support these crate types' "$WORK/lorry.err"
            rg -q 'does not support these crate types' "$WORK/cargo.err"
            continue
        fi
        python3 - "$WORK/lorry.json" "$WORK/cargo.json" "$command" <<'PY'
import json, pathlib, sys
def events(path):
    return [json.loads(line) for line in open(path)]
lorry, cargo = map(events, sys.argv[1:3])
def artifacts(events):
    return [(event['target'], event['profile'], event['features'],
             sorted(pathlib.Path(path).suffix for path in event['filenames']))
            for event in events if event['reason'] == 'compiler-artifact']
assert artifacts(lorry) == artifacts(cargo) and len(artifacts(lorry)) == 1
def messages(events):
    return [event['message'] for event in events if event['reason'] == 'compiler-message']
assert messages(lorry) == messages(cargo) and len(messages(lorry)) == 1
assert messages(lorry)[0]['message'].startswith('dropping unsupported crate type')
assert lorry[-1] == cargo[-1] == {'reason': 'build-finished', 'success': True}
PY
    done
    # Linux dynamic outputs remain an explicit unsupported capability.
    status=0
    env HOME="$WORK/home" "$LORRY" build >"$WORK/linux.out" 2>"$WORK/linux.err" || status=$?
    [ "$status" = 101 ]
    rg -q 'Linux .* execution is not yet supported' "$WORK/linux.err"
done
echo "PASS: Motor crate-type dropping, diagnostics, metadata-only checking, and unusable-output errors match Cargo"
