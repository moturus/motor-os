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
# Source metadata reads only membership. Build-only tables need no support.
cat >"$PROJECT/Cargo.toml" <<'EOF'
[workspace]
members = ["app", "shared"]
exclude = ["tools/excluded"]
resolver = "2"
[workspace.package]
version = "9.9.9"
[workspace.dependencies]
unprepared = "1"
[profile.custom]
inherits = "release"
debug = 1
EOF
cat >"$PROJECT/app/Cargo.toml" <<'EOF'
[package]
name = "app"
version = "0.1.0"
edition = "2021"
[dependencies]
shared = { path = "../shared" }
helper = { path = "../tools/helper" }
outside = { path = "../../outside" }
excluded = { path = "../tools/excluded" }
[dev-dependencies]
unprepared = "1"
[features]
extra = []
[[bin]]
name = "app"
path = "src/main.rs"
required-features = ["extra"]
doc = true
[badges]
maintenance = { status = "experimental" }
EOF
cat >"$PROJECT/shared/Cargo.toml" <<'EOF'
[package]
name = "shared"
version = "0.1.0"
edition = "2021"
resolver = "2"
keywords = ["motor", "source"]
categories = ["development-tools"]
[lib]
crate-type = ["staticlib"]
EOF
printf 'fn main() { shared::answer(); }\n' >"$PROJECT/app/src/main.rs"
printf 'pub fn answer() {}\n' >"$PROJECT/shared/src/lib.rs"
# Path dependencies below the root are implicit members, recursively and for
# every dependency kind. Excluded paths and paths outside the root are not.
package() {
    mkdir -p "$1/src"
    printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\n' \
        "$(basename "$1")" >"$1/Cargo.toml"
    printf 'pub fn answer() {}\n' >"$1/src/lib.rs"
}
for directory in "$PROJECT/tools/helper" "$PROJECT/tools/helper/nested" \
    "$PROJECT/tools/excluded" "$WORK/outside"; do
    package "$directory"
done
printf '[dev-dependencies]\nnested = { path = "nested" }\n' >>"$PROJECT/tools/helper/Cargo.toml"

# No compiler, configuration, lockfile, or admission is needed to describe
# source targets. This also proves the command cannot fetch dependencies.
source_metadata() {
    local manifest="$1"
    shift
    HOME="$WORK/home" RUSTC="$WORK/absent-rustc" "$LORRY" metadata \
        --format-version 1 --no-deps --locked \
        --filter-platform x86_64-unknown-motor --manifest-path "$manifest" "$@"
}
agrees_with_cargo() {
    local manifest="$1" name="$2"
    source_metadata "$manifest" >"$WORK/$name.json"
    RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" metadata --format-version 1 \
        --no-deps --offline --manifest-path "$manifest" >"$WORK/$name.cargo.json"
    RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" run --quiet --locked --offline \
        --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" -- \
        compare-projection "$WORK/$name.json" "$WORK/$name.cargo.json"
}
source_files=("$PROJECT/Cargo.toml" "$PROJECT/app/Cargo.toml" "$PROJECT/shared/Cargo.toml"
    "$PROJECT/app/src/main.rs" "$PROJECT/shared/src/lib.rs" "$PROJECT/tools/helper/Cargo.toml")
sha256sum "${source_files[@]}" >"$WORK/sources.before"
# A member, including an implicit one, describes the whole workspace and
# selects itself as the default member. An excluded package stands alone.
agrees_with_cargo "$PROJECT/Cargo.toml" root
agrees_with_cargo "$PROJECT/app/Cargo.toml" member
agrees_with_cargo "$PROJECT/tools/helper/Cargo.toml" implicit
agrees_with_cargo "$PROJECT/tools/excluded/Cargo.toml" excluded
sha256sum "${source_files[@]}" >"$WORK/sources.after"
cmp "$WORK/sources.before" "$WORK/sources.after"
source_metadata "$PROJECT/Cargo.toml" -p app >"$WORK/selected.json"
grep -F "\"workspace_members\":[\"path+file://$PROJECT/app#0.1.0\"]" \
    "$WORK/selected.json" >/dev/null
[ "$(grep -o '"manifest_path":' "$WORK/selected.json" | wc -l)" -eq 1 ]
[ ! -e "$PROJECT/Cargo.lock" ]
[ ! -e "$PROJECT/target" ]
[ ! -e "$PROJECT/.lorry" ]

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
agrees_with_cargo "$PROJECT/Cargo.toml" nonvirtual

# A root may list itself as ".", declare default-members, or use an empty
# `[workspace]` table. Its path dependencies are still implicit members.
for root in "$WORK/dot" "$WORK/empty"; do
    package "$root"
    package "$root/inner"
    package "$root/listed"
    printf '[dependencies]\ninner = { path = "inner" }\n[workspace]\n' >>"$root/Cargo.toml"
done
printf 'members = [".", "listed"]\ndefault-members = ["listed"]\n' >>"$WORK/dot/Cargo.toml"
agrees_with_cargo "$WORK/dot/Cargo.toml" dot
agrees_with_cargo "$WORK/empty/Cargo.toml" empty
agrees_with_cargo "$WORK/empty/inner/Cargo.toml" empty-inner

# All manifest modes use the same workspace discovery for inherited compiler
# identity fields, including implicit members in a root without members.
for root in "$WORK/dot" "$WORK/empty"; do
    printf '\n[workspace.package]\nversion = "1.2.3"\nedition = "2024"\nrust-version = "1.85.0"\n' \
        >>"$root/Cargo.toml"
    for package in "$root" "$root/inner" "$root/listed"; do
        sed -i 's/version = "0.1.0"/version.workspace = true/; s/edition = "2021"/edition.workspace = true/' \
            "$package/Cargo.toml"
        sed -i '/^name = /a rust-version.workspace = true' "$package/Cargo.toml"
    done
done
agrees_with_cargo "$WORK/dot/Cargo.toml" inherited-listed
agrees_with_cargo "$WORK/empty/inner/Cargo.toml" inherited-implicit

echo "PASS: unprepared workspace source metadata agrees with Cargo"
