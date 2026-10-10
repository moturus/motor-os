#!/usr/bin/env bash
# A crates.io package whose name has capitals, like `Inflector`. As in Cargo,
# its index file is found by the lowercase name, while the records, the
# download, and the lock keep the name's case, and a dependency must spell
# the name as the index does.
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: mixed-case-name-contract.sh LORRY" >&2
    exit 1
fi

LORRY="$(realpath "$1")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d /tmp/lorry-mixed-case-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

fail() {
    echo "mixed-case-name-contract: $*" >&2
    exit 1
}

if [ -z "${LORRY_TEST_RUSTC:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
RUSTC="$LORRY_TEST_RUSTC"
HOME_DIR="$WORK/home"
REPOSITORY="$HOME_DIR/.config/lorry/vendor"
FIXTURE="$WORK/crates-io"
mkdir -p "$HOME_DIR/.config/lorry" "$REPOSITORY/objects/crates-io/sha256" \
    "$REPOSITORY/.staging" "$FIXTURE/archives/MixedCase" "$FIXTURE/index/mi/xe"

# The package as crates.io serves it: files only, below NAME-VERSION/.
SOURCE="$WORK/source/MixedCase-1.0.0"
mkdir -p "$SOURCE/src"
printf '%s\n' '[package]' 'name = "MixedCase"' 'version = "1.0.0"' 'edition = "2021"' \
    >"$SOURCE/Cargo.toml"
printf '%s\n' 'pub fn answer() -> u32 {' '    42' '}' >"$SOURCE/src/lib.rs"
ARCHIVE="$FIXTURE/archives/MixedCase/MixedCase-1.0.0.crate"
tar --format=ustar --no-recursion --owner=0 --group=0 --numeric-owner --mode=0644 \
    -C "$WORK/source" -czf "$ARCHIVE" \
    MixedCase-1.0.0/Cargo.toml MixedCase-1.0.0/src/lib.rs
CHECKSUM="$(sha256sum "$ARCHIVE" | cut -d' ' -f1)"
printf '{"name":"MixedCase","vers":"1.0.0","deps":[],"cksum":"%s","features":{},"yanked":false}\n' \
    "$CHECKSUM" >"$FIXTURE/index/mi/xe/mixedcase"
"$RUSTC" --edition=2024 -D warnings -O "$SCRIPT_DIR/helpers/cache-curl.rs" \
    -o "$FIXTURE/curl"
# The fixture serves exact paths only; the log shows how each was spelled.
cat >"$WORK/curl" <<EOF
#!/bin/sh
printf '%s\n' "\$@" >>"$WORK/requests"
exec "$FIXTURE/curl" "\$@"
EOF
chmod 0700 "$WORK/curl"

cat >"$HOME_DIR/.config/lorry/lorry.toml" <<EOF
config-version = 1
use-cargo-registry = false

[repositories]
user = "$REPOSITORY"

[network]
curl = "$WORK/curl"

[cache]
directory = "$WORK/cache"

[policy]
default = "allow"
EOF
printf '%s\n' 'format-version = 1' 'object-hash = "sha256"' >"$REPOSITORY/repository.toml"

# A consumer in directory $1 whose dependency is spelled $2.
consumer() {
    mkdir -p "$1/src"
    printf '%s\n' '[package]' 'name = "consumer"' 'version = "0.1.0"' 'edition = "2021"' \
        '' '[dependencies]' "$2 = \"=1.0.0\"" >"$1/Cargo.toml"
    printf '%s\n' 'fn main() {' '    println!("answer {}", MixedCase::answer());' '}' \
        >"$1/src/main.rs"
}

lorry_in() {
    local directory="$1"
    shift
    (cd "$directory" && HOME="$HOME_DIR" RUSTC="$RUSTC" "$LORRY" -q "$@")
}

echo "== A dependency spelled as the index spells it =="
consumer "$WORK/exact" MixedCase
lorry_in "$WORK/exact" vendor --accept-all || fail "vendoring MixedCase failed"
grep -Fx 'https://index.crates.io/mi/xe/mixedcase' "$WORK/requests" >/dev/null ||
    fail "the index was not read at its lowercase path"
grep -Fx 'https://static.crates.io/crates/MixedCase/MixedCase-1.0.0.crate' \
    "$WORK/requests" >/dev/null || fail "the download did not keep the name's case"
grep -Fx 'name = "MixedCase"' "$WORK/exact/Cargo.lock" >/dev/null ||
    fail "Cargo.lock does not spell MixedCase as the index does"
output="$(lorry_in "$WORK/exact" run --offline)" || fail "building against MixedCase failed"
[ "$output" = "answer 42" ] || fail "the consumer printed '$output'"

echo "== A dependency spelled in another case =="
consumer "$WORK/lower" mixedcase
if lorry_in "$WORK/lower" vendor --accept-all >"$WORK/lower.out" 2>"$WORK/lower.err"; then
    fail "the dependency mixedcase matched the package MixedCase"
fi
if grep -F 'contains package' "$WORK/lower.err" >/dev/null ||
    ! grep -F '`mixedcase`' "$WORK/lower.err" >/dev/null; then
    fail "unexpected error for mixedcase: $(cat "$WORK/lower.err")"
fi

echo "PASS: crates.io package names keep their case"
