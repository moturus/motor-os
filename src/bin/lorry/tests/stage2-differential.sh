#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: stage2-differential.sh LORRY" >&2
    exit 1
fi

LORRY="$(realpath "$1")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${LORRY_TEST_CARGO:-}" ] || [ -z "${LORRY_TEST_RUSTC:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
WORK="$(mktemp -d /tmp/lorry-stage2-differential-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
PROJECT="$WORK/project"
HOME_DIR="$WORK/home"
CARGO_HOME_DIR="${CARGO_HOME:-${HOME:?}/.cargo}"
mkdir -p "$HOME_DIR/.config/lorry" "$PROJECT/src" \
    "$PROJECT/generated/src" "$PROJECT/build-helper/src" "$PROJECT/derive/src"

cat >"$HOME_DIR/.config/lorry/lorry.toml" <<EOF
config-version = 1

[cache]
directory = "$WORK/cache"

[policy]
default = "allow"

[policy.rules.generated]
action = "allow"
name = "generated"
version = "=1.0.0"
source = "path"
allow-build-script = true

[policy.rules.derive]
action = "allow"
name = "derive-fixture"
version = "=1.0.0"
source = "path"
allow-proc-macro = true
EOF
cat >"$PROJECT/Cargo.toml" <<'EOF'
[package]
name = "stage2-differential"
version = "0.1.0"
edition = "2024"

[dependencies]
cfg-if = "=1.0.4"
generated = { path = "generated" }
derive-fixture = { path = "derive" }
EOF
cat >"$PROJECT/src/lib.rs" <<'EOF'
#[derive(derive_fixture::Identity)]
pub struct Derived;

#[deprecated(note = "stage2 differential warning")]
fn old_function() {}

pub fn exercise() -> u32 {
    old_function();
    cfg_if::cfg_if! {
        if #[cfg(target_os = "motor")] {
            generated::GENERATED
        } else {
            0
        }
    }
}
EOF
cat >"$PROJECT/generated/Cargo.toml" <<'EOF'
[package]
name = "generated"
version = "1.0.0"
edition = "2024"
build = "build.rs"

[build-dependencies]
build-helper = { path = "../build-helper" }
EOF
cat >"$PROJECT/generated/build.rs" <<'EOF'
fn main() {
    let _ = build_helper::VALUE;
    let out = std::env::var_os("OUT_DIR").unwrap();
    std::fs::write(
        std::path::Path::new(&out).join("generated.rs"),
        "pub const GENERATED: u32 = 42;\n",
    )
    .unwrap();
    println!("cargo:rustc-check-cfg=cfg(generated_fixture)");
    println!("cargo:rustc-cfg=generated_fixture");
    println!("cargo:rustc-env=GENERATED_ENV=enabled");
}
EOF
cat >"$PROJECT/generated/src/lib.rs" <<'EOF'
#[cfg(not(generated_fixture))]
compile_error!("missing generated cfg");
include!(concat!(env!("OUT_DIR"), "/generated.rs"));
pub const ENVIRONMENT: &str = env!("GENERATED_ENV");
EOF
cat >"$PROJECT/build-helper/Cargo.toml" <<'EOF'
[package]
name = "build-helper"
version = "1.0.0"
edition = "2024"
EOF
printf 'pub const VALUE: u32 = 42;\n' >"$PROJECT/build-helper/src/lib.rs"
cat >"$PROJECT/derive/Cargo.toml" <<'EOF'
[package]
name = "derive-fixture"
version = "1.0.0"
edition = "2024"

[lib]
proc-macro = true
EOF
cat >"$PROJECT/derive/src/lib.rs" <<'EOF'
extern crate proc_macro;

#[proc_macro_derive(Identity)]
pub fn identity(_input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    proc_macro::TokenStream::new()
}
EOF

CARGO_HOME="$CARGO_HOME_DIR" "$LORRY_TEST_CARGO" generate-lockfile --offline \
    --manifest-path "$PROJECT/Cargo.toml"

CARGO_HOME="$CARGO_HOME_DIR" "$LORRY_TEST_CARGO" metadata --format-version 1 \
    --filter-platform x86_64-unknown-motor --locked --offline \
    --manifest-path "$PROJECT/Cargo.toml" >"$WORK/cargo.metadata"
HOME="$HOME_DIR" CARGO_HOME="$CARGO_HOME_DIR" RUSTC="$LORRY_TEST_RUSTC" \
    "$LORRY" --use-cargo-registry metadata --format-version 1 \
    --filter-platform x86_64-unknown-motor --locked \
    --manifest-path "$PROJECT/Cargo.toml" >"$WORK/lorry.metadata"
CARGO_HOME="$CARGO_HOME_DIR" "$LORRY_TEST_CARGO" run --quiet --locked --offline \
    --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" -- \
    compare-projection "$WORK/lorry.metadata" "$WORK/cargo.metadata"

CARGO_HOME="$CARGO_HOME_DIR" "$LORRY_TEST_CARGO" tree --locked --offline \
    --manifest-path "$PROJECT/Cargo.toml" --target x86_64-unknown-motor \
    >"$WORK/cargo.tree"
HOME="$HOME_DIR" CARGO_HOME="$CARGO_HOME_DIR" RUSTC="$LORRY_TEST_RUSTC" \
    "$LORRY" --use-cargo-registry tree --manifest-path "$PROJECT/Cargo.toml" \
    --target x86_64-unknown-motor >"$WORK/lorry.tree"
cmp "$WORK/lorry.tree" "$WORK/cargo.tree"

# Establish complete output directories first. The failing checks below then
# prove that both tools report restored build-script results without treating
# an incomplete check profile as successful.
CARGO_HOME="$CARGO_HOME_DIR" RUSTC="$LORRY_TEST_RUSTC" \
    "$LORRY_TEST_CARGO" check --lib --keep-going --message-format=json \
    --locked --offline --target x86_64-unknown-motor \
    --target-dir "$WORK/cargo-target" --manifest-path "$PROJECT/Cargo.toml" \
    >"$WORK/cargo-success.messages" 2>"$WORK/cargo-success.stderr"
HOME="$HOME_DIR" CARGO_HOME="$CARGO_HOME_DIR" RUSTC="$LORRY_TEST_RUSTC" \
    "$LORRY" --use-cargo-registry check --lib --keep-going --quiet \
    --message-format=json --target x86_64-unknown-motor \
    --target-dir "$WORK/lorry-target" --manifest-path "$PROJECT/Cargo.toml" \
    >"$WORK/lorry-success.messages" 2>"$WORK/lorry-success.stderr"
printf '\ncompile_error!("stage2 differential error");\n' >>"$PROJECT/src/lib.rs"

set +e
CARGO_HOME="$CARGO_HOME_DIR" RUSTC="$LORRY_TEST_RUSTC" \
    "$LORRY_TEST_CARGO" check --lib --keep-going \
    --message-format=json --locked --offline --target x86_64-unknown-motor \
    --target-dir "$WORK/cargo-target" --manifest-path "$PROJECT/Cargo.toml" \
    >"$WORK/cargo.messages" 2>"$WORK/cargo.stderr"
cargo_status="$?"
HOME="$HOME_DIR" CARGO_HOME="$CARGO_HOME_DIR" RUSTC="$LORRY_TEST_RUSTC" \
    "$LORRY" --use-cargo-registry check --lib --keep-going --quiet \
    --message-format=json --target x86_64-unknown-motor \
    --target-dir "$WORK/lorry-target" --manifest-path "$PROJECT/Cargo.toml" \
    >"$WORK/lorry.messages" 2>"$WORK/lorry.stderr"
lorry_status="$?"
set -e
[ "$cargo_status" -ne 0 ]
[ "$lorry_status" -eq "$cargo_status" ]
CARGO_HOME="$CARGO_HOME_DIR" "$LORRY_TEST_CARGO" run --quiet --locked --offline \
    --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" -- \
    differential-messages "$WORK/lorry.messages" "$WORK/cargo.messages"

echo "PASS: Stage 2 metadata, check messages, and tree match the keyed Cargo"
