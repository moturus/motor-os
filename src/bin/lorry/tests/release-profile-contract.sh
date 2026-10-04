#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true
LORRY="$(realpath "${1:?usage: release-profile-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
export RUSTC="$LORRY_TEST_RUSTC"
WORK="$(mktemp -d /tmp/lorry-release-profile-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/home/.config/lorry" "$WORK/project"/{app,shared}/src "$WORK/project/.cargo"
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" >"$WORK/home/.config/lorry/lorry.toml"
cat >"$WORK/manifest.toml" <<'EOF'
[workspace]
members = ["app", "shared"]
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
EOF
cat >"$WORK/project/shared/src/lib.rs" <<'EOF'
#[inline(never)]
pub fn value() -> u32 { std::hint::black_box(42) }
EOF
printf 'fn main() { println!("{}", shared::value()); }\n' >"$WORK/project/app/src/main.rs"
printf '[target.x86_64-unknown-motor]\nlinker = "%s"\nrustflags = ["--sysroot=%s"]\n' \
    "$LORRY_MOTOR_LINKER" "$LORRY_MOTOR_SYSROOT" >"$WORK/project/.cargo/config.toml"
cd "$WORK/project"
cp "$WORK/manifest.toml" Cargo.toml
"$LORRY_TEST_CARGO" generate-lockfile --offline
for strip in default false none debuginfo symbols; do
    cp "$WORK/manifest.toml" Cargo.toml
    if [ "$strip" != default ]; then
        value="\"$strip\""
        if [ "$strip" = false ]; then value=false; fi
        printf '\n[profile.release]\nstrip = %s\n' "$value" >>Cargo.toml
    fi
    for platform in native motor; do
        target=()
        profile=release
        if [ "$platform" = motor ]; then target=(--target x86_64-unknown-motor); profile=x86_64-unknown-motor/release; fi
        env HOME="$WORK/home" "$LORRY" build --release --workspace -j1 "${target[@]}" \
            --message-format=json >"$WORK/lorry-$strip-$platform.json"
        "$LORRY_TEST_CARGO" build --release --workspace -j1 "${target[@]}" --offline \
            --message-format=json >"$WORK/cargo-$strip-$platform.json"
        cmp "target/$profile/app" "target/lorry/$profile/app"
        "$LORRY_TEST_CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" \
            --locked --offline -- differential-workspace-messages \
            "$WORK/lorry-$strip-$platform.json" "$WORK/cargo-$strip-$platform.json"
    done
done
[ "$(target/lorry/release/app)" = 42 ]
echo "PASS: default and explicit release stripping match Cargo native/cross bytes and JSON"
