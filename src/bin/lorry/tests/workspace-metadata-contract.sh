#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

LORRY="$(realpath "${1:?usage: workspace-metadata-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${LORRY_TEST_CARGO:-}" ]; then
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
WORK="$(mktemp -d /tmp/lorry-workspace-metadata-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
PROJECT="$WORK/project"
mkdir -p "$PROJECT/app/src" "$PROJECT/shared/src" "$WORK/home"
cat >"$PROJECT/Cargo.toml" <<'EOF'
[workspace]
members = ["app", "shared"]
resolver = "2"
EOF
cat >"$PROJECT/app/Cargo.toml" <<'EOF'
[package]
name = "app"
version = "0.1.0"
edition = "2021"
[dependencies]
shared = { path = "../shared" }
[dev-dependencies]
unprepared = "1"
EOF
cat >"$PROJECT/shared/Cargo.toml" <<'EOF'
[package]
name = "shared"
version = "0.1.0"
edition = "2021"
resolver = "2"
[lib]
crate-type = ["staticlib"]
EOF
printf 'fn main() { shared::answer(); }\n' >"$PROJECT/app/src/main.rs"
printf 'pub fn answer() {}\n' >"$PROJECT/shared/src/lib.rs"

# No compiler, configuration, lockfile, or admission is needed to describe
# source targets. This also proves the command cannot fetch dependencies.
source_metadata() {
    local manifest="$1"
    shift
    HOME="$WORK/home" RUSTC="$WORK/absent-rustc" "$LORRY" metadata \
        --format-version 1 --no-deps --locked \
        --filter-platform x86_64-unknown-motor --manifest-path "$manifest" "$@"
}
source_files=("$PROJECT/Cargo.toml" "$PROJECT/app/Cargo.toml" "$PROJECT/shared/Cargo.toml"
    "$PROJECT/app/src/main.rs" "$PROJECT/shared/src/lib.rs")
sha256sum "${source_files[@]}" >"$WORK/sources.before"
source_metadata "$PROJECT/Cargo.toml" >"$WORK/root.json"
source_metadata "$PROJECT/app/Cargo.toml" >"$WORK/member.json"
cmp "$WORK/root.json" "$WORK/member.json"
sha256sum "${source_files[@]}" >"$WORK/sources.after"
cmp "$WORK/sources.before" "$WORK/sources.after"
source_metadata "$PROJECT/Cargo.toml" -p app >"$WORK/selected.json"
grep -F "\"workspace_members\":[\"path+file://$PROJECT/app#0.1.0\"]" \
    "$WORK/selected.json" >/dev/null
[ "$(grep -o '"manifest_path":' "$WORK/selected.json" | wc -l)" -eq 1 ]
[ ! -e "$PROJECT/Cargo.lock" ]
[ ! -e "$PROJECT/target" ]
[ ! -e "$PROJECT/.lorry" ]

RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" metadata --format-version 1 \
    --no-deps --offline --manifest-path "$PROJECT/Cargo.toml" >"$WORK/cargo.json"
RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" run --locked --offline \
    --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" -- \
    compare-projection "$WORK/root.json" "$WORK/cargo.json"

# Existing, invalid lock bytes must survive editor discovery untouched.
printf 'not a Cargo lockfile\n' >"$PROJECT/Cargo.lock"
cp "$PROJECT/Cargo.lock" "$WORK/lock.before"
source_metadata "$PROJECT/Cargo.toml" >"$WORK/invalid-lock.json"
cmp "$WORK/root.json" "$WORK/invalid-lock.json"
cmp "$PROJECT/Cargo.lock" "$WORK/lock.before"
rm "$PROJECT/Cargo.lock"

# A root package has different Cargo default-member semantics.
cat >>"$PROJECT/Cargo.toml" <<'EOF'
[package]
name = "root"
version = "0.1.0"
edition = "2021"
EOF
mkdir "$PROJECT/src"
printf 'pub fn root() {}\n' >"$PROJECT/src/lib.rs"
source_metadata "$PROJECT/Cargo.toml" >"$WORK/nonvirtual.json"
RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" metadata --format-version 1 \
    --no-deps --offline --manifest-path "$PROJECT/Cargo.toml" >"$WORK/cargo.json"
RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" run --locked --offline \
    --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" -- \
    compare-projection "$WORK/nonvirtual.json" "$WORK/cargo.json"

echo "PASS: unprepared workspace source metadata agrees with Cargo"
