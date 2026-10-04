#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: metadata-contract.sh LORRY" >&2
    exit 1
fi

LORRY="$(realpath "$1")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
fail() {
    echo "metadata-contract: $*" >&2
    exit 1
}
if [ -z "${LORRY_TEST_CARGO:-}" ] || [ -z "${LORRY_TEST_RUSTC:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
WORK="$(mktemp -d /tmp/lorry-metadata-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
HOST_CARGO_HOME="${CARGO_HOME:-${HOME:?}/.cargo}"
TEST_HOME="$WORK/home"
PROJECT="$WORK/metadata-fixture"
DEPENDENCY="$WORK/dep"
mkdir -p "$TEST_HOME/.config/lorry" "$PROJECT/src" "$PROJECT/tests" "$DEPENDENCY/src"
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" \
    >"$TEST_HOME/.config/lorry/lorry.toml"

printf '%s\n' \
    '[package]' \
    'name = "metadata-fixture"' \
    'version = "0.1.0"' \
    'edition = "2024"' \
    'authors = ["Motor OS"]' \
    'description = "metadata differential fixture"' \
    'license = "MIT"' \
    'license-file = "LICENSE"' \
    'readme = "README.md"' \
    'repository = "https://example.test/repository"' \
    'homepage = "https://example.test"' \
    'documentation = "https://docs.example.test"' \
    'rust-version = "1.85"' \
    'default-run = "metadata-fixture"' \
    'build = "build.rs"' \
    '' \
    '[lib]' \
    'doc = false' \
    'doctest = false' \
    '' \
    '[[bin]]' \
    'name = "metadata-fixture"' \
    'doc = false' \
    '' \
    '[dependencies]' \
    'renamed-dep = { package = "dep", path = "../dep", features = ["extra"] }' \
    '' \
    '[features]' \
    'default = ["renamed-dep/extra"]' >"$PROJECT/Cargo.toml"
printf '%s\n' \
    '[package]' \
    'name = "dep"' \
    'version = "1.2.3"' \
    'edition = "2021"' \
    '' \
    '[lib]' \
    'crate-type = ["rlib"]' \
    'doc = false' \
    '' \
    '[features]' \
    'extra = []' >"$DEPENDENCY/Cargo.toml"
printf '\n[package.metadata.editor]\ncommands = ["build", "check"]\n[workspace.metadata]\nname = "resolved fixture"\n' \
    >>"$PROJECT/Cargo.toml"
printf '\n[package.metadata.source]\nrole = "dependency"\n' >>"$DEPENDENCY/Cargo.toml"
printf '%s\n' \
    'version = 4' \
    '[[package]]' \
    'name = "metadata-fixture"' \
    'version = "0.1.0"' \
    'dependencies = [' \
    ' "dep",' \
    ']' \
    '[[package]]' \
    'name = "dep"' \
    'version = "1.2.3"' >"$PROJECT/Cargo.lock"
printf 'pub fn root() -> u8 { dep::answer() }\n' >"$PROJECT/src/lib.rs"
printf 'fn main() {}\n' >"$PROJECT/src/main.rs"
printf '#[test]\nfn integration() {}\n' >"$PROJECT/tests/integration.rs"
printf 'fn main() {}\n' >"$PROJECT/build.rs"
printf 'MIT\n' >"$PROJECT/LICENSE"
printf '# fixture\n' >"$PROJECT/README.md"
printf 'pub fn answer() -> u8 { 42 }\n' >"$DEPENDENCY/src/lib.rs"

export RUSTC="$LORRY_TEST_RUSTC"
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME:?}/.rustup}"
export HOME="$TEST_HOME"
(
    cd "$PROJECT"
    "$LORRY" vendor --accept-all
)
"$LORRY" metadata --format-version 1 --no-deps \
    --manifest-path "$PROJECT/Cargo.toml" >"$WORK/no-deps.json"
[ ! -e "$WORK/cache/sources" ]
mv "$PROJECT/.lorry" "$WORK/admission-backup"
cp -R "$PROJECT/target" "$WORK/target-before"
"$LORRY" metadata --format-version 1 --filter-platform x86_64-unknown-linux-gnu \
    --locked --offline --frozen --manifest-path "$PROJECT/Cargo.toml" >"$WORK/lorry.json"
"$LORRY" metadata --format-version 1 --filter-platform x86_64-unknown-linux-gnu \
    --locked --manifest-path "$PROJECT/Cargo.toml" >"$WORK/lorry-again.json"
cmp "$WORK/lorry.json" "$WORK/lorry-again.json"
[ ! -e "$PROJECT/.lorry" ] || fail "metadata created admission state"
diff -r "$WORK/target-before" "$PROJECT/target" || fail "metadata changed compilation outputs"
mv "$WORK/admission-backup" "$PROJECT/.lorry"
cp "$PROJECT/Cargo.lock" "$WORK/lock-before"
"$LORRY" metadata --offline --frozen --locked --no-deps \
    --manifest-path "$PROJECT/Cargo.toml" >"$WORK/default.json" 2>"$WORK/default.err"
cmp "$WORK/no-deps.json" "$WORK/default.json"
cmp "$WORK/lock-before" "$PROJECT/Cargo.lock"
"$LORRY_TEST_CARGO" metadata --offline --frozen --locked --no-deps \
    --manifest-path "$PROJECT/Cargo.toml" >"$WORK/cargo-default.json" \
    2>"$WORK/cargo-default.err"
cmp "$WORK/default.err" "$WORK/cargo-default.err"
grep -F 'please specify `--format-version` flag explicitly' "$WORK/default.err" >/dev/null
"$LORRY" metadata -q --no-deps --frozen \
    --manifest-path "$PROJECT/Cargo.toml" >"$WORK/default-quiet.json" \
    2>"$WORK/default-quiet.err"
cmp "$WORK/no-deps.json" "$WORK/default-quiet.json"
[ ! -s "$WORK/default-quiet.err" ] || fail "quiet metadata emitted the format warning"
"$LORRY_TEST_CARGO" metadata --format-version 1 \
    --filter-platform x86_64-unknown-linux-gnu --locked \
    --manifest-path "$PROJECT/Cargo.toml" >"$WORK/cargo.json"
"$LORRY_TEST_CARGO" metadata --format-version 1 --no-deps --locked \
    --manifest-path "$PROJECT/Cargo.toml" >"$WORK/cargo-no-deps.json"
CARGO_HOME="$HOST_CARGO_HOME" "$LORRY_TEST_CARGO" run \
    --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" \
    --locked --offline -- compare "$WORK/lorry.json" "$WORK/cargo.json"
CARGO_HOME="$HOST_CARGO_HOME" "$LORRY_TEST_CARGO" run \
    --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" \
    --locked --offline -- compare "$WORK/no-deps.json" "$WORK/cargo-no-deps.json"

# The package limit counts packages from outside the workspace, never the
# root. With two path dependencies, a limit of 1 fails and 2 succeeds.
LIMITED="$WORK/limited"
mkdir -p "$LIMITED/app/src" "$LIMITED/one/src" "$LIMITED/two/src"
printf '%s\n' '[package]' 'name = "app"' 'version = "0.1.0"' 'edition = "2021"' \
    '[dependencies]' 'one = { path = "../one" }' 'two = { path = "../two" }' \
    >"$LIMITED/app/Cargo.toml"
for package in one two; do
    printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\n' "$package" \
        >"$LIMITED/$package/Cargo.toml"
    printf 'pub fn answer() {}\n' >"$LIMITED/$package/src/lib.rs"
done
printf 'pub fn app() {}\n' >"$LIMITED/app/src/lib.rs"
printf '%s\n' 'version = 4' '[[package]]' 'name = "app"' 'version = "0.1.0"' \
    'dependencies = [' ' "one",' ' "two",' ']' '[[package]]' 'name = "one"' \
    'version = "0.1.0"' '[[package]]' 'name = "two"' 'version = "0.1.0"' \
    >"$LIMITED/app/Cargo.lock"
cp "$TEST_HOME/.config/lorry/lorry.toml" "$WORK/config.backup"
limited_metadata() {
    cp "$WORK/config.backup" "$TEST_HOME/.config/lorry/lorry.toml"
    printf '%s\n' '' '[policy.limits]' "max-packages = $1" \
        >>"$TEST_HOME/.config/lorry/lorry.toml"
    "$LORRY" metadata --format-version 1 --locked \
        --manifest-path "$LIMITED/app/Cargo.toml" >"$WORK/limited.out" 2>"$WORK/limited.err"
}
if limited_metadata 1; then
    fail "metadata accepted a graph above the configured package limit"
fi
if ! grep -F "limit of 1 (set in \`$TEST_HOME/.config/lorry/lorry.toml\`)" \
    "$WORK/limited.err" >/dev/null ||
    ! grep -F 'raise `max-packages` in the `[policy.limits]` table' \
        "$WORK/limited.err" >/dev/null; then
    cat "$WORK/limited.err" >&2
    fail "package-limit rejection omitted its cause, setting, or source"
fi
limited_metadata 2 || {
    cat "$WORK/limited.err" >&2
    fail "the package limit counted the root package"
}
cp "$WORK/config.backup" "$TEST_HOME/.config/lorry/lorry.toml"

cp -R "$PROJECT" "$WORK/unsupported-target"
sed -i '/^\[lib\]$/a crate-type = ["cdylib"]' \
    "$WORK/unsupported-target/Cargo.toml"
"$LORRY" metadata --format-version 1 \
    --manifest-path "$WORK/unsupported-target/Cargo.toml" \
    >"$WORK/unsupported.out" 2>"$WORK/unsupported.err"
"$LORRY_TEST_CARGO" metadata --offline --format-version 1 \
    --manifest-path "$WORK/unsupported-target/Cargo.toml" >"$WORK/unsupported-cargo.json"
CARGO_HOME="$HOST_CARGO_HOME" "$LORRY_TEST_CARGO" run \
    --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" --locked --offline -- \
    compare "$WORK/unsupported.out" "$WORK/unsupported-cargo.json"

echo "PASS: metadata is deterministic and matches Cargo for a complete path graph"
