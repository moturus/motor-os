#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true
LORRY="$(realpath "${1:?usage: required-binary-features-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
export RUSTC="$LORRY_TEST_RUSTC"
WORK="$(mktemp -d /tmp/lorry-required-binary-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/home" "$WORK/project"/{app,helper}/src "$WORK/project/app/src/bin" "$WORK/project/.cargo"
printf '[workspace]\nmembers = ["app", "helper"]\ndefault-members = ["app"]\nresolver = "2"\n' >"$WORK/project/Cargo.toml"
cat >"$WORK/project/app/Cargo.toml" <<'EOF'
[package]
name = "app"
version = "1.0.0"
edition = "2024"
[features]
default = ["present"]
present = []
extra = ["helper/enabled"]
[dependencies]
helper = { path = "../helper" }
[dev-dependencies]
helper = { path = "../helper", features = ["enabled"] }
[target.'cfg(target_os = "motor")'.dev-dependencies]
helper = { path = "../helper", features = ["enabled"] }
[[bin]]
name = "gated"
required-features = ["present", "extra"]
[[bin]]
name = "qualified"
required-features = ["helper/enabled"]
EOF
printf '[package]\nname = "helper"\nversion = "1.0.0"\nedition = "2024"\n[features]\nenabled = []\n' >"$WORK/project/helper/Cargo.toml"
printf '#[cfg(feature = "enabled")]\npub fn value() -> u32 { 42 }\n' >"$WORK/project/helper/src/lib.rs"
printf 'pub fn value() -> u32 { 42 }\n' >"$WORK/project/app/src/lib.rs"
printf 'fn main() { println!("{}", app::value()); }\n' >"$WORK/project/app/src/main.rs"
printf '#[cfg(not(feature = "extra"))]\ncompile_error!("disabled binary compiled");\nfn main() { println!("{}", helper::value()); }\n' >"$WORK/project/app/src/bin/gated.rs"
printf 'fn main() { println!("{}", helper::value()); }\n' >"$WORK/project/app/src/bin/qualified.rs"
printf '[target.x86_64-unknown-motor]\nlinker = "%s"\nrustflags = ["--sysroot=%s"]\n' \
    "$LORRY_MOTOR_LINKER" "$LORRY_MOTOR_SYSROOT" >"$WORK/project/.cargo/config.toml"
cd "$WORK/project"
"$LORRY_TEST_CARGO" generate-lockfile --offline
for platform in native motor; do
    target=()
    if [ "$platform" = motor ]; then target=(--target x86_64-unknown-motor); fi
    for selection in implicit enabled named; do
        arguments=()
        if [ "$selection" != implicit ]; then arguments=(--features extra); fi
        if [ "$selection" = named ]; then arguments+=(--bin gated); fi
        for command in build check; do
            env HOME="$WORK/home" "$LORRY" "$command" "${target[@]}" "${arguments[@]}" --message-format=json >"$WORK/lorry.json"
            "$LORRY_TEST_CARGO" "$command" "${target[@]}" "${arguments[@]}" --offline --message-format=json >"$WORK/cargo.json"
            comparison=differential-workspace-messages
            if [ "$command" = check ]; then comparison=differential-workspace-check-messages; fi
            "$LORRY_TEST_CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" \
                --locked --offline -- "$comparison" "$WORK/lorry.json" "$WORK/cargo.json"
            if [ "$command" = build ]; then
                python3 - "$WORK/lorry.json" "$WORK/cargo.json" <<'PY'
import json, pathlib, sys
def programs(path):
    return {event['target']['name']: pathlib.Path(event['executable']).read_bytes()
            for line in open(path) for event in [json.loads(line)]
            if event['reason'] == 'compiler-artifact' and event['executable']}
assert programs(sys.argv[1]) == programs(sys.argv[2])
PY
            fi
        done
    done
done
for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
    status=0
    env HOME="$WORK/home" "$builder" build --bin gated >"$WORK/named.out" 2>"$WORK/named.err" || status=$?
    [ "$status" = 101 ]
    rg -q 'requires the features: `present`, `extra`' "$WORK/named.err"
done
# No available implicit target is a successful build with no compiler units.
printf 'autolib = false\nautobins = false\n' >"$WORK/disabled.package"
sed '/^edition = /r /dev/stdin' app/Cargo.toml <"$WORK/disabled.package" >"$WORK/disabled.manifest"
sed '/^name = "gated"/,$!b; /^name = "qualified"/,$d' "$WORK/disabled.manifest" >app/Cargo.toml
# Remove the last empty [[bin]] header left by dropping the qualified target.
sed -i '$d' app/Cargo.toml
for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
    env HOME="$WORK/home" "$builder" build --message-format=json >"$WORK/empty.json"
    [ "$(wc -l <"$WORK/empty.json")" -eq 1 ]
    rg -q '"reason":"build-finished","success":true' "$WORK/empty.json"
done
echo "PASS: binary feature filtering, qualified dependencies, named errors, and empty builds match Cargo"
