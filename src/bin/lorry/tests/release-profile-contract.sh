#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true
LORRY="$(realpath "${1:?usage: release-profile-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
export RUSTC="$LORRY_TEST_RUSTC"
WORK="$(mktemp -d /tmp/lorry-release-profile-contract-XXXXXX)"
trap 'status=$?; if [ "$status" = 0 ]; then rm -rf "$WORK"; else echo "Retained profile fixture: $WORK" >&2; fi' EXIT
mkdir -p "$WORK/home/.config/lorry" "$WORK/project"/{app,shared,builder}/src "$WORK/project/.cargo"
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" >"$WORK/home/.config/lorry/lorry.toml"
cat >"$WORK/manifest.toml" <<'EOF'
[workspace]
members = ["app", "shared", "builder"]
resolver = "2"
EOF
cat >"$WORK/project/app/Cargo.toml" <<'EOF'
[package]
name = "app"
version = "1.0.0"
edition = "2024"
[dependencies]
shared = { path = "../shared" }
EOF
cat >"$WORK/project/shared/Cargo.toml" <<'EOF'
[package]
name = "shared"
version = "1.0.0"
edition = "2024"
[lib]
doctest = false
[build-dependencies]
builder = { path = "../builder" }
EOF
cat >"$WORK/project/builder/Cargo.toml" <<'EOF'
[package]
name = "builder"
version = "1.0.0"
edition = "2024"
[lib]
doctest = false
EOF
printf 'pub fn value() -> u32 { 42 }\n' >"$WORK/project/builder/src/lib.rs"
cat >"$WORK/project/shared/build.rs" <<'EOF'
fn main() {
    let value = builder::value();
    std::fs::write(std::path::Path::new(&std::env::var_os("OUT_DIR").unwrap()).join("generated.rs"), value.to_string()).unwrap();
    println!("cargo::rustc-env=BUILD_VALUE={value}");
    println!("cargo::rustc-env=BUILD_PROFILE={}", std::env::var("PROFILE").unwrap());
}
EOF
cat >"$WORK/project/lorry.toml" <<'EOF'
config-version = 1
[policy.rules.shared-script]
action = "allow"
source = "path"
name = "shared"
allow-build-script = true
EOF
cat >"$WORK/project/shared/src/lib.rs" <<'EOF'
#[inline(never)]
pub fn value() -> u32 { std::hint::black_box(env!("BUILD_VALUE").parse().unwrap()) }
EOF
printf 'fn main() { println!("{}", shared::value()); }\n' >"$WORK/project/app/src/main.rs"
printf '[target.x86_64-unknown-motor]\nlinker = "%s"\nrustflags = ["--sysroot=%s"]\n' \
    "$LORRY_MOTOR_LINKER" "$LORRY_MOTOR_SYSROOT" >"$WORK/project/.cargo/config.toml"
cd "$WORK/project"
cp "$WORK/manifest.toml" Cargo.toml
"$LORRY_TEST_CARGO" generate-lockfile --offline
for strip in default false none debuginfo symbols debug-limited debug-full debug-lines debug-off dev-abort dev-limited dev-full dev-off dev-settings release-settings named-opt named-dev named-test named-builtin-test env-dev env-release env-custom env-inherited; do
    cp "$WORK/manifest.toml" Cargo.toml
    mode=(--release)
    profile_environment=()
    if [[ "$strip" == named-* || "$strip" == env-custom || "$strip" == env-inherited ]]; then
        mode=(--profile "${strip#named-}")
        cat >>Cargo.toml <<'EOF'
[profile.release]
lto = "thin"
[profile.opt]
inherits = "release"
opt-level = "s"
codegen-units = 1
strip = true
[profile.friendly]
inherits = "dev"
debug = 1
opt-level = 2
[profile.developer]
inherits = "friendly"
EOF
        if [ "$strip" = named-dev ]; then mode=(--profile developer); fi
        if [ "$strip" = named-test ]; then mode=(--profile integration); fi
        if [ "$strip" = named-builtin-test ]; then mode=(--profile test); fi
        if [ "$strip" = env-custom ]; then
            mode=(--profile opt)
            profile_environment=(CARGO_PROFILE_RELEASE_OPT_LEVEL=0 CARGO_PROFILE_OPT_OPT_LEVEL=1 CARGO_PROFILE_OPT_LTO=off CARGO_PROFILE_UNUSED_RPATH=true)
        fi
        if [ "$strip" = env-inherited ]; then
            mode=(--profile opt)
            profile_environment=(CARGO_PROFILE_RELEASE_OPT_LEVEL=1 CARGO_PROFILE_RELEASE_DEBUG=1 CARGO_PROFILE_RELEASE_LTO=off)
        fi
        cat >>Cargo.toml <<'EOF'
[profile.integration]
inherits = "test"
debug = false
opt-level = 1
EOF
    elif [ "$strip" = env-dev ]; then
        mode=()
        printf '\n[profile.dev]\nopt-level = 3\ndebug = true\n' >>Cargo.toml
        profile_environment=(CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=false CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false CARGO_PROFILE_DEV_OVERFLOW_CHECKS=false CARGO_PROFILE_DEV_INCREMENTAL=false)
    elif [ "$strip" = env-release ]; then
        profile_environment=(CARGO_PROFILE_RELEASE_OPT_LEVEL=z CARGO_PROFILE_RELEASE_DEBUG=true CARGO_PROFILE_RELEASE_STRIP=none CARGO_PROFILE_RELEASE_CODEGEN_UNITS=2)
    elif [ "$strip" = dev-settings ]; then
        mode=()
        cat >>Cargo.toml <<'EOF'
[profile.dev]
opt-level = 1
lto = "thin"
strip = "symbols"
codegen-units = 2
debug-assertions = false
overflow-checks = false
incremental = false
EOF
    elif [ "$strip" = release-settings ]; then
        cat >>Cargo.toml <<'EOF'
[profile.release]
debug-assertions = true
overflow-checks = true
incremental = true
EOF
    elif [ "$strip" = dev-abort ]; then
        mode=()
        printf '\n[profile.dev]\npanic = "abort"\n' >>Cargo.toml
    elif [[ "$strip" == dev-* ]]; then
        mode=()
        case "$strip" in
            dev-limited) debug=1; opt=1 ;;
            dev-full) debug=true; opt=0 ;;
            dev-off) debug=false; opt='"z"' ;;
        esac
        printf '\n[profile.dev]\ndebug = %s\nopt-level = %s\n' "$debug" "$opt" >>Cargo.toml
    elif [[ "$strip" == debug-* ]]; then
        case "$strip" in
            debug-limited) debug=1; opt=1 ;;
            debug-full) debug=true; opt='"s"' ;;
            debug-lines) debug='"line-tables-only"'; opt=0 ;;
            debug-off) debug=false; opt='"z"' ;;
        esac
        printf '\n[profile.release]\ndebug = %s\nopt-level = %s\n' "$debug" "$opt" >>Cargo.toml
    elif [ "$strip" != default ]; then
        value="\"$strip\""
        if [ "$strip" = false ]; then value=false; fi
        printf '\n[profile.release]\nstrip = %s\n' "$value" >>Cargo.toml
    fi
    for platform in native motor; do
        target=()
        profile=release
        if [[ "$strip" == dev-* ]]; then profile=debug; fi
        if [ "$strip" = env-dev ]; then profile=debug; fi
        if [[ "$strip" == named-* || "$strip" == env-custom || "$strip" == env-inherited ]]; then profile="${mode[1]}"; fi
        if [ "$profile" = test ]; then profile=debug; fi
        if [ "$platform" = motor ]; then target=(--target x86_64-unknown-motor); profile=x86_64-unknown-motor/$profile; fi
        commands=(build check)
        if [[ "$strip" == named-* ]]; then commands+=(test); fi
        for command in "${commands[@]}"; do
        execution=()
        if [ "$command" = test ]; then execution=(--no-run); fi
        comparison=differential-script-clean-messages
        if [ "$command" = check ]; then comparison=differential-script-clean-check-messages; fi
        env HOME="$WORK/home" "${profile_environment[@]}" "$LORRY" "$command" "${execution[@]}" "${mode[@]}" --workspace -j1 "${target[@]}" \
            --message-format=json >"$WORK/lorry-$strip-$platform.json"
        env "${profile_environment[@]}" "$LORRY_TEST_CARGO" "$command" "${execution[@]}" "${mode[@]}" --workspace -j1 "${target[@]}" --offline \
            --message-format=json >"$WORK/cargo-$strip-$platform.json"
        if [ "$command" = build ]; then cmp "target/$profile/app" "target/lorry/$profile/app"; fi
        if [ "$command" = test ]; then
            python3 - "$WORK/lorry-$strip-$platform.json" "$WORK/cargo-$strip-$platform.json" <<'PY'
import json, pathlib, sys
def harnesses(path):
    return sorted(pathlib.Path(event['executable']).read_bytes() for line in open(path)
                  for event in [json.loads(line)] if event['reason'] == 'compiler-artifact'
                  and event['profile']['test'])
lorry, cargo = map(harnesses, sys.argv[1:])
assert lorry and lorry == cargo
PY
        fi
        "$LORRY_TEST_CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" \
            --locked --offline -- "$comparison" \
            "$WORK/lorry-$strip-$platform.json" "$WORK/cargo-$strip-$platform.json"
        done
        if [[ "$strip" == named-* ]] && [ "$platform" = native ]; then
            for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
                [ "$(env HOME="$WORK/home" "$builder" run --quiet "${mode[@]}" -p app --offline)" = 42 ]
            done
        fi
    done
done
if env HOME="$WORK/home" CARGO_PROFILE_DEV_RPATH=true "$LORRY" check --workspace 2>"$WORK/unsupported.err"; then exit 1; fi
rg -F 'unsupported selected profile environment variable `CARGO_PROFILE_DEV_RPATH`' "$WORK/unsupported.err"
for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
    if env HOME="$WORK/home" CARGO_PROFILE_RELEASE_INCREMENTAL=invalid "$builder" build --release --workspace --offline 2>"$WORK/invalid.err"; then exit 1; fi
done
[ "$(target/lorry/release/app)" = 42 ]
echo "PASS: release stripping, debug information, optimization, and host tools match Cargo native/cross bytes and JSON"
