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
"$LORRY" metadata --format-version 1 --filter-platform x86_64-unknown-linux-gnu \
    --locked --manifest-path "$PROJECT/Cargo.toml" >"$WORK/lorry.json"
"$LORRY" metadata --format-version 1 --filter-platform x86_64-unknown-linux-gnu \
    --locked --manifest-path "$PROJECT/Cargo.toml" >"$WORK/lorry-again.json"
cmp "$WORK/lorry.json" "$WORK/lorry-again.json"
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

cp "$TEST_HOME/.config/lorry/lorry.toml" "$WORK/config.backup"
printf '%s\n' '' '[policy.limits]' 'max-packages = 1' \
    >>"$TEST_HOME/.config/lorry/lorry.toml"
if "$LORRY" metadata --format-version 1 \
    --filter-platform x86_64-unknown-linux-gnu --locked \
    --manifest-path "$PROJECT/Cargo.toml" >"$WORK/limited.out" 2>"$WORK/limited.err"; then
    fail "metadata accepted a graph above the configured package limit"
fi
if ! grep -F 'package' "$WORK/limited.err" >/dev/null; then
    cat "$WORK/limited.err" >&2
    fail "package-limit rejection omitted its cause"
fi
cp "$WORK/config.backup" "$TEST_HOME/.config/lorry/lorry.toml"

cp -R "$PROJECT" "$WORK/unsupported-target"
sed -i '/^\[lib\]$/a crate-type = ["cdylib"]' \
    "$WORK/unsupported-target/Cargo.toml"
if "$LORRY" metadata --format-version 1 --no-deps \
    --manifest-path "$WORK/unsupported-target/Cargo.toml" \
    >"$WORK/unsupported.out" 2>"$WORK/unsupported.err"; then
    fail "metadata accepted an unsupported custom target"
fi
grep -F 'custom library crate types are not supported' \
    "$WORK/unsupported.err" >/dev/null ||
    fail "custom-target rejection omitted its cause"

echo "PASS: metadata is deterministic and matches Cargo for a complete path graph"
