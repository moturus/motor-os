#!/usr/bin/env bash
# Two checkouts must not share a dependency that embeds a configured path.
set -euo pipefail
export CARGO_NET_OFFLINE=true
unset ASSET_DIR
[ "$#" -eq 1 ] || { echo "usage: env-cache-contract.sh LORRY" >&2; exit 2; }
LORRY="$(realpath "$1")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
WORK="$(mktemp -d /tmp/lorry-env-cache-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
export HOME="$WORK/home" CARGO_HOME="$WORK/cargo-home" RUSTC="$LORRY_TEST_RUSTC"
mkdir -p "$HOME/.config/lorry"
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" >"$HOME/.config/lorry/lorry.toml"
REGISTRY=index.crates.io-env-fixture
SOURCE="$CARGO_HOME/registry/src/$REGISTRY"
ARCHIVES="$CARGO_HOME/registry/cache/$REGISTRY"
mkdir -p "$ARCHIVES"
for name in env-path env-script; do
    leaf="$name-1.0.0"
    mkdir -p "$SOURCE/$leaf/src"
    printf '[package]\nname = "%s"\nversion = "1.0.0"\nedition = "2024"\n' "$name" >"$SOURCE/$leaf/Cargo.toml"
    if [ "$name" = env-path ]; then
        printf 'pub const VALUE: &str = env!("ASSET_DIR");\n' >"$SOURCE/$leaf/src/lib.rs"
    else
        printf 'pub const VALUE: &str = env!("SCRIPT_ASSET_DIR");\n' >"$SOURCE/$leaf/src/lib.rs"
        cat >"$SOURCE/$leaf/build.rs" <<'EOF'
fn main() {
    println!("cargo:rerun-if-env-changed=ASSET_DIR");
    println!("cargo:rustc-env=SCRIPT_ASSET_DIR={}", std::env::var("ASSET_DIR").unwrap());
}
EOF
    fi
    tar --format=ustar -czf "$ARCHIVES/$leaf.crate" -C "$SOURCE" "$leaf"
    printf '{"v":1}' >"$SOURCE/$leaf/.cargo-ok"
    checksum="$(sha256sum "$ARCHIVES/$leaf.crate" | cut -d' ' -f1)"
    printf '\n[[package]]\nname = "%s"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "%s"\n' "$name" "$checksum" >>"$WORK/dependencies.lock"
done
for kind in relative shared; do
    for checkout in a b; do
        app="$WORK/$kind/$checkout/app"
        mkdir -p "$app/src" "$app/.cargo"
        cat >"$app/Cargo.toml" <<'EOF'
[package]
name = "env-cache-app"
version = "0.1.0"
edition = "2024"
[dependencies]
env-path = "1"
env-script = "1"
EOF
        cat >"$app/src/main.rs" <<'EOF'
fn main() {
    println!("member={} dependency={} script={}", env!("ASSET_DIR"), env_path::VALUE, env_script::VALUE);
    assert_eq!(env!("ASSET_DIR"), env_path::VALUE);
    assert_eq!(env!("ASSET_DIR"), env_script::VALUE);
}
EOF
        printf 'version = 4\n[[package]]\nname = "env-cache-app"\nversion = "0.1.0"\ndependencies = ["env-path", "env-script"]\n' >"$app/Cargo.lock"
        cat "$WORK/dependencies.lock" >>"$app/Cargo.lock"
        if [ "$kind" = relative ]; then
            printf '[env]\nASSET_DIR = { value = "assets", relative = true }\n' >"$app/.cargo/config.toml"
        else
            printf '[env]\nASSET_DIR = "%s/shared-assets"\n' "$WORK" >"$app/.cargo/config.toml"
        fi
        (cd "$app" && "$LORRY" run -v) >"$WORK/$kind-$checkout.out" 2>"$WORK/$kind-$checkout.err" || {
            cat "$WORK/$kind-$checkout.out" "$WORK/$kind-$checkout.err" >&2
            exit 1
        }
    done
done
# Equal configured values remain shareable across checkouts.
for name in env-path env-script; do
    grep -F "Fresh $name v1.0.0 (verified Lorry cache)" "$WORK/shared-b.err"
done
echo "PASS: configured paths isolate shared dependency caches; equal values reuse them"
