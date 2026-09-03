#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: git-patch-contract.sh LORRY" >&2
    exit 1
fi

LORRY="$(realpath "$1")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${LORRY_TEST_RUSTC:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
export RUSTC="$LORRY_TEST_RUSTC"
WORK="$(mktemp -d /tmp/lorry-git-patch-contract-XXXXXX)"
trap 'chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"' EXIT
PROJECT="$WORK/project"
HOME_DIR="$WORK/home"
REPOSITORY="$WORK/repository"
GIT_URL="https://fixture.invalid/repository.git"
mkdir -p "$WORK/bin" "$WORK/git" "$WORK/source/src" \
    "$PROJECT/app/src" "$HOME_DIR/.config/lorry" "$REPOSITORY"

fail() {
    echo "git-patch-contract: $*" >&2
    exit 1
}

echo "== Building the local smart-HTTP Git fixture =="
"$RUSTC" --edition=2024 "$SCRIPT_DIR/helpers/git-curl.rs" \
    -o "$WORK/bin/git-curl"
cat >"$WORK/source/Cargo.toml" <<'EOF'
[package]
name = "demo"
version = "1.2.3"
edition = "2024"
license = "MIT"
EOF
cat >"$WORK/source/src/lib.rs" <<'EOF'
pub fn answer() -> u32 { 42 }
EOF
/usr/bin/git init -q -b main "$WORK/source"
/usr/bin/git -C "$WORK/source" config user.name "Lorry Test"
/usr/bin/git -C "$WORK/source" config user.email "lorry@example.invalid"
/usr/bin/git -C "$WORK/source" add Cargo.toml src/lib.rs
/usr/bin/git -C "$WORK/source" commit -q -m fixture
COMMIT="$(/usr/bin/git -C "$WORK/source" rev-parse HEAD)"
/usr/bin/git clone -q --bare "$WORK/source" "$WORK/git/repository.git"
CARGO_SOURCE="git+$GIT_URL?branch=main#$COMMIT"

cat >"$PROJECT/Cargo.toml" <<EOF
[workspace]
members = ["app"]
resolver = "2"

[patch.crates-io]
renamed = { package = "demo", git = "$GIT_URL", branch = "main" }

[profile.dev]
panic = "abort"
EOF
cat >"$PROJECT/app/Cargo.toml" <<'EOF'
[package]
name = "app"
version = "0.1.0"
edition = "2024"
license = "MIT"

[dependencies]
renamed = { package = "demo", version = "=1.2.3" }
EOF
cat >"$PROJECT/app/src/main.rs" <<'EOF'
fn main() {
    println!("{}", renamed::answer());
}
EOF
cat >"$PROJECT/Cargo.lock" <<EOF
version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "demo 1.2.3 ($CARGO_SOURCE)",
]

[[package]]
name = "demo"
version = "1.2.3"
source = "$CARGO_SOURCE"
EOF
cat >"$HOME_DIR/.config/lorry/lorry.toml" <<EOF
config-version = 1

[network]
curl = "$WORK/bin/git-curl"

[repositories]
user = "$REPOSITORY"

[policy]
default = "allow"
EOF
cat >"$REPOSITORY/repository.toml" <<'EOF'
format-version = 1
object-hash = "sha256"
EOF

manifest_hashes() {
    sha256sum "$PROJECT/Cargo.toml" "$PROJECT/app/Cargo.toml"
}

MANIFEST_HASHES="$(manifest_hashes)"
chmod a-w "$PROJECT/Cargo.toml" "$PROJECT/app/Cargo.toml"

echo "== Vendoring a Git patch without rewriting manifests =="
(cd "$PROJECT" && HOME="$HOME_DIR" "$LORRY" vendor -p app --accept-all)
[ "$(manifest_hashes)" = "$MANIFEST_HASHES" ] || fail "vendor changed an input manifest"
[ ! -e "$PROJECT/.lorry/vendor/renamed" ] || fail "vendor created the legacy patch path"
OBJECT="$(printf %s "$CARGO_SOURCE" | sha256sum | cut -d' ' -f1)"
[ -f "$PROJECT/.lorry/vendor/git/$OBJECT/git.toml" ] ||
    fail "vendor did not publish the content-addressed Git object"
grep -F "source = \"$CARGO_SOURCE\"" "$PROJECT/Cargo.lock" >/dev/null ||
    fail "Cargo.lock lost the Cargo-compatible Git identity"
if grep -F 'checksum =' "$PROJECT/Cargo.lock" >/dev/null; then
    fail "Cargo.lock gave a Git package a registry checksum"
fi
LOCK_HASH="$(sha256sum "$PROJECT/Cargo.lock")"

echo "== Reusing unchanged Git state non-interactively =="
(cd "$PROJECT" && HOME="$HOME_DIR" "$LORRY" vendor -p app </dev/null)
[ "$(manifest_hashes)" = "$MANIFEST_HASHES" ] || fail "warm vendor changed a manifest"
[ "$(sha256sum "$PROJECT/Cargo.lock")" = "$LOCK_HASH" ] ||
    fail "warm vendor changed Cargo.lock"

echo "== Consuming the verified Git patch offline =="
chmod 000 "$WORK/bin/git-curl"
(
    cd "$PROJECT"
    HOME="$HOME_DIR" "$LORRY" build -p app
    [ "$(HOME="$HOME_DIR" "$LORRY" run -p app)" = 42 ]
    HOME="$HOME_DIR" "$LORRY" test -p app -- --quiet
    HOME="$HOME_DIR" "$LORRY" review -p app >"$WORK/review.toml"
)
grep -F '[[locked-git]]' "$WORK/review.toml" >/dev/null ||
    fail "review omitted the locked Git identity"
grep -F '[[crates-io-patch]]' "$WORK/review.toml" >/dev/null ||
    fail "review omitted the patch alias and package identity"
grep -F "source = \"$CARGO_SOURCE\"" "$WORK/review.toml" >/dev/null ||
    fail "review omitted the exact Cargo Git source"
grep -F '[[git-source]]' "$WORK/review.toml" >/dev/null ||
    fail "review omitted verified Git evidence"
[ "$(manifest_hashes)" = "$MANIFEST_HASHES" ] || fail "an offline command changed a manifest"

echo "PASS: Git patches keep manifests immutable and retain Git identity"
