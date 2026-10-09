#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: registry-contract.sh LORRY" >&2
    exit 1
fi

LORRY="$(realpath "$1")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CACHE_CURL_SOURCE="$SCRIPT_DIR/helpers/cache-curl.rs"
WORK="$(mktemp -d /tmp/lorry-registry-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

fail() {
    echo "registry-contract: $*" >&2
    exit 1
}

if [ -z "${LORRY_TEST_CARGO:-}" ] || [ -z "${LORRY_TEST_RUSTC:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
RUSTC="$LORRY_TEST_RUSTC"
HOST_CARGO_HOME="${CARGO_HOME:-${HOME:?}/.cargo}"
PROJECT="$WORK/project"
HOME_DIR="$WORK/home"
REPOSITORY="$HOME_DIR/.config/lorry/vendor"
CONFIG="$HOME_DIR/.config/lorry/lorry.toml"
mkdir -p "$PROJECT/src" "$HOME_DIR/.config/lorry" \
    "$REPOSITORY/objects/crates-io/sha256" \
    "$REPOSITORY/.staging"

cat >"$PROJECT/Cargo.toml" <<'EOF'
[package]
name = "registry-fixture"
version = "0.1.0"
edition = "2024"

[dependencies]
cfg-if = "=1.0.4"
EOF
cat >"$PROJECT/Cargo.lock" <<'EOF'
version = 4

[[package]]
name = "cfg-if"
version = "1.0.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801"

[[package]]
name = "registry-fixture"
version = "0.1.0"
dependencies = ["cfg-if"]
EOF
cat >"$PROJECT/src/main.rs" <<'EOF'
fn main() { cfg_if::cfg_if! { if #[cfg(unix)] {} else {} } }
EOF

echo "== Preparing the fail-closed Cargo-cache crates.io fixture =="
"$RUSTC" --edition=2024 -D warnings -O "$CACHE_CURL_SOURCE" \
    -o "$WORK/cache-curl"
"$WORK/cache-curl" prepare "$HOST_CARGO_HOME" \
    "$WORK/crates-io" "$PROJECT/Cargo.lock"
# Like Cargo, Lorry reads repeated features and skips an unreadable entry.
INDEX="$WORK/crates-io/index/cf/g-/cfg-if"
[ -f "$INDEX" ] || fail "fixture has no cfg-if index response"
UNUSED_CHECKSUM="$(printf '0%.0s' $(seq 64))"
cat >>"$INDEX" <<EOF
{"name":"cfg-if","vers":"0.0.1","deps":[{"name":"core","req":"^1","features":["a","a"]}],"cksum":"$UNUSED_CHECKSUM","features":{},"yanked":false}
{"name":"cfg-if","vers":"0.0.2","deps":"unreadable","cksum":"$UNUSED_CHECKSUM","features":{},"yanked":false}
EOF
cat >"$CONFIG" <<EOF
config-version = 1
use-cargo-registry = false

[repositories]
user = "$REPOSITORY"

[network]
curl = "$WORK/crates-io/curl"

[cache]
directory = "$WORK/cache"

[policy]
default = "allow"
EOF
cat >"$REPOSITORY/repository.toml" <<'EOF'
format-version = 1
object-hash = "sha256"
EOF

echo "== Vendoring one exact crates.io package =="
# Exercise the same review in machine mode before the existing human contract.
cp "$PROJECT/Cargo.lock" "$WORK/original.lock"
if (cd "$PROJECT" && HOME="$HOME_DIR" RUSTC="$RUSTC" \
    "$LORRY" -q --lorry-messages vendor) >"$WORK/declined.out" 2>"$WORK/declined.jsonl"; then
    fail "machine review approved a fresh acquisition without confirmation"
fi
cmp "$PROJECT/Cargo.lock" "$WORK/original.lock"
[ ! -e "$PROJECT/.lorry/dependencies-v2.toml" ] || fail "declined machine review wrote admission"
(cd "$PROJECT" && HOME="$HOME_DIR" RUSTC="$RUSTC" \
    "$LORRY" -q --lorry-messages vendor --accept-all) >"$WORK/machine.out" 2>"$WORK/machine.jsonl"
[ ! -s "$WORK/machine.out" ] || fail "vendor wrote machine messages to stdout"
python3 - "$WORK/machine.jsonl" "$WORK/declined.jsonl" <<'PY'
import json, sys
accepted = [json.loads(line) for line in open(sys.argv[1])]
declined = [json.loads(line) for line in open(sys.argv[2])]
assert len(accepted) == 1, accepted
message = accepted[0]
assert message['reason'] == 'lorry-vendor-change'
assert len(message['added']) == 1
assert message['added'][0]['name'] == 'cfg-if'
assert message['added'][0]['checksum'] == '9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801'
assert message['removed'] == []
assert message['capabilities_added'] == []
assert message['capabilities_removed'] == []
assert len(declined) == 2, declined
assert declined[0] == message
assert declined[1]['reason'] == 'lorry-error'
assert 'no interactive terminal' in declined[1]['text']
PY
# Reset both archives and immutable index inputs for a genuinely fresh request.
rm -rf "$PROJECT/.lorry" "$REPOSITORY/objects/crates-io/sha256" "$REPOSITORY/resolution"
mkdir "$REPOSITORY/objects/crates-io/sha256"
(cd "$PROJECT" && HOME="$HOME_DIR" RUSTC="$RUSTC" \
    "$LORRY" vendor --accept-all) >"$WORK/fresh.log" 2>&1
grep -F "New crates.io packages (1):" "$WORK/fresh.log" >/dev/null || {
    cat "$WORK/fresh.log" >&2
    fail "fresh acquisition did not publish one package"
}
[ "$(grep -c '^  Package: cfg-if ' "$WORK/fresh.log")" -eq 1 ] ||
    fail "human review did not group the package once"
grep -F 'member users: registry-fixture' "$WORK/fresh.log" >/dev/null ||
    fail "human review omitted the package's member users"
grep -F 'Updating crates.io index for `cfg-if`' "$WORK/fresh.log" >/dev/null ||
    fail "fresh acquisition did not report its sparse-index request"
grep -F 'Downloading cfg-if v1.0.4' "$WORK/fresh.log" >/dev/null ||
    fail "fresh acquisition did not report its archive request"
grep -F 'Resolving dependency graph' "$WORK/fresh.log" >/dev/null ||
    fail "fresh acquisition did not report graph resolution"
grep -F 'Checking dependency repository state' "$WORK/fresh.log" >/dev/null ||
    fail "fresh acquisition did not report repository verification"
grep -F 'Verifying selected dependency sources' "$WORK/fresh.log" >/dev/null ||
    fail "fresh acquisition did not report source verification"
if grep -F 'warning: crates.io index' "$WORK/fresh.log" >/dev/null; then
    fail "ordinary acquisition printed sparse-index warnings"
fi
OBJECT_ROOT="$REPOSITORY/objects/crates-io/sha256"
[ "$(find "$OBJECT_ROOT" -mindepth 2 -maxdepth 2 -type d | wc -l)" -eq 1 ] ||
    fail "fresh acquisition published an unexpected object count"

echo "== Naming lenient sparse-index entries with --verbose =="
rm -rf "$PROJECT/.lorry" "$REPOSITORY/objects/crates-io/sha256" "$REPOSITORY/resolution"
mkdir "$REPOSITORY/objects/crates-io/sha256"
(cd "$PROJECT" && HOME="$HOME_DIR" RUSTC="$RUSTC" \
    "$LORRY" -v vendor --accept-all) >"$WORK/verbose.log" 2>&1
grep -F 'warning: crates.io index for `cfg-if`: dependency `core` repeats feature `a` in version 0.0.1' \
    "$WORK/verbose.log" >/dev/null || {
    cat "$WORK/verbose.log" >&2
    fail "verbose acquisition did not name the repeated dependency feature"
}
grep -F 'warning: crates.io index for `cfg-if`: skipped version 0.0.2: ' \
    "$WORK/verbose.log" >/dev/null || {
    cat "$WORK/verbose.log" >&2
    fail "verbose acquisition did not name the skipped index entry"
}

echo "== Proving warm reuse performs no archive download =="
ARGS="$WORK/warm-curl-arguments"
cat >"$WORK/warm-curl" <<EOF
#!/bin/sh
printf '%s\n' "\$@" >> "$ARGS"
exec "$WORK/crates-io/curl" "\$@"
EOF
chmod 0700 "$WORK/warm-curl"
sed -i "s|$WORK/crates-io/curl|$WORK/warm-curl|" "$CONFIG"
(cd "$PROJECT" && HOME="$HOME_DIR" RUSTC="$RUSTC" \
    "$LORRY" vendor --accept-all) >"$WORK/warm.log" 2>&1
grep -F "Verified Cargo.lock" "$WORK/warm.log" >/dev/null ||
    fail "warm acquisition did not verify Cargo.lock"
if [ -f "$ARGS" ] && grep -F "https://static.crates.io/" "$ARGS" >/dev/null; then
    fail "warm acquisition attempted to download the selected archive"
fi

echo "== Publishing a stable metadata source view =="
(cd "$PROJECT" && HOME="$HOME_DIR" RUSTC="$RUSTC" \
    "$LORRY" metadata --format-version 1 \
    --filter-platform x86_64-unknown-linux-gnu --locked) >"$WORK/metadata.json"
SOURCE_VIEW="$(find "$WORK/cache/sources" -mindepth 1 -maxdepth 1 \
    -type d -name 'cfg-if-1.0.4-*' -print -quit)"
[ -n "$SOURCE_VIEW" ] || fail "metadata did not publish the registry source view"
grep -F "\"manifest_path\":\"$SOURCE_VIEW/Cargo.toml\"" \
    "$WORK/metadata.json" >/dev/null ||
    fail "metadata did not reference the stable registry source view"
# Retained sources need no scratch space, so a read-only temp dir suffices.
mkdir -m 0500 "$WORK/readonly-tmp"
(cd "$PROJECT" && HOME="$HOME_DIR" RUSTC="$RUSTC" TMPDIR="$WORK/readonly-tmp" \
    "$LORRY" metadata --format-version 1 \
    --filter-platform x86_64-unknown-linux-gnu --locked) >"$WORK/metadata-again.json"
cmp "$WORK/metadata.json" "$WORK/metadata-again.json"

(cd "$PROJECT" && HOME="$HOME_DIR" RUSTC="$RUSTC" TMPDIR="$WORK/readonly-tmp" \
    "$LORRY" tree --target x86_64-unknown-linux-gnu) >"$WORK/lorry.tree"
CARGO_HOME="$HOST_CARGO_HOME" "$LORRY_TEST_CARGO" tree --locked --offline \
    --manifest-path "$PROJECT/Cargo.toml" --target x86_64-unknown-linux-gnu \
    >"$WORK/cargo.tree"
cmp "$WORK/lorry.tree" "$WORK/cargo.tree"

echo "PASS: cached crates.io acquisition, metadata views, and tree output are stable and need no temp dir"
