#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true
LORRY="$(realpath "${1:?usage: library-crate-type-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
export RUSTC="$LORRY_TEST_RUSTC"
WORK="$(mktemp -d /tmp/lorry-library-crate-type-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/home/.config/lorry" "$WORK/project"/{app,shared}/src "$WORK/project/.cargo"
printf 'config-version = 1\nuse-cargo-registry = false\n[cache]\ndirectory = "%s"\n' "$WORK/cache" >"$WORK/home/.config/lorry/lorry.toml"
cat >"$WORK/project/Cargo.toml" <<'EOF'
[workspace]
members = ["app", "shared"]
resolver = "2"
EOF
cat >"$WORK/app.toml" <<'EOF'
[package]
name = "app"
version = "1.0.0"
edition = "2024"
[dependencies]
shared = { path = "../shared" }
EOF
cat >"$WORK/shared.toml" <<'EOF'
[package]
name = "shared"
version = "1.0.0"
edition = "2024"
EOF
cat >"$WORK/project/shared/src/lib.rs" <<'EOF'
#[inline(never)]
pub fn value() -> u32 { std::hint::black_box(42) }
#[test]
fn shared_test() { assert_eq!(value(), 42); }
EOF
cat >"$WORK/project/app/src/lib.rs" <<'EOF'
pub fn value() -> u32 { shared::value() }
#[test]
fn app_test() { assert_eq!(value(), 42); }
EOF
printf 'fn main() { println!("{}", app::value()); }\n' >"$WORK/project/app/src/main.rs"
printf '[target.x86_64-unknown-motor]\nlinker = "%s"\nrustflags = ["--sysroot=%s"]\n' \
    "$LORRY_MOTOR_LINKER" "$LORRY_MOTOR_SYSROOT" >"$WORK/project/.cargo/config.toml"
cd "$WORK/project"
for crate_types in '"lib"' '"rlib"'; do
    for member in app shared; do
        cp "$WORK/$member.toml" "$member/Cargo.toml"
        printf '\n[lib]\ncrate-type = [%s]\n' "$crate_types" >>"$member/Cargo.toml"
    done
    "$LORRY_TEST_CARGO" generate-lockfile --offline
    for platform in native motor; do
        target=()
        profile=debug
        if [ "$platform" = motor ]; then target=(--target x86_64-unknown-motor); profile=x86_64-unknown-motor/debug; fi
        for command in build check test; do
            selection=(--workspace)
            comparison=differential-workspace-messages
            if [ "$command" = check ]; then comparison=differential-workspace-check-messages; fi
            if [ "$command" = test ]; then selection=(-p app --no-run); fi
            env HOME="$WORK/home" "$LORRY" "$command" -j1 "${selection[@]}" "${target[@]}" \
                --message-format=json >"$WORK/lorry.json"
            "$LORRY_TEST_CARGO" "$command" -j1 "${selection[@]}" "${target[@]}" --offline \
                --message-format=json >"$WORK/cargo.json"
            if [ "$command" = build ]; then cmp "target/$profile/app" "target/lorry/$profile/app"; fi
            if [ "$command" = test ]; then
                python3 - "$WORK/lorry.json" "$WORK/cargo.json" <<'PY'
import json, pathlib, sys
def harnesses(filename):
    return sorted(pathlib.Path(event['executable']).read_bytes()
                  for line in open(filename) for event in [json.loads(line)]
                  if event['reason'] == 'compiler-artifact' and event['profile']['test'])
lorry, cargo = map(harnesses, sys.argv[1:])
assert lorry and lorry == cargo
PY
            fi
            "$LORRY_TEST_CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" \
                --locked --offline -- "$comparison" "$WORK/lorry.json" "$WORK/cargo.json"
        done
    done
done
echo "PASS: explicit library crate types match Cargo native/cross build, check, and test JSON"
