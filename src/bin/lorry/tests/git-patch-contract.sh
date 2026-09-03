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
mkdir -p "$WORK/bin" "$WORK/git" "$WORK/source" \
    "$PROJECT/app/src" "$HOME_DIR/.config/lorry" "$REPOSITORY"

fail() {
    echo "git-patch-contract: $*" >&2
    exit 1
}

echo "== Building the local smart-HTTP Git fixture =="
"$RUSTC" --edition=2024 "$SCRIPT_DIR/helpers/git-curl.rs" \
    -o "$WORK/bin/git-curl"
cat >"$WORK/source/Cargo.toml" <<'EOF'
[workspace]
members = ["demo", "head-demo", "tag-demo", "named-demo", "pinned-demo"]
resolver = "2"
EOF
for package in demo head-demo tag-demo named-demo pinned-demo; do
    mkdir -p "$WORK/source/$package/src"
    cat >"$WORK/source/$package/Cargo.toml" <<EOF
[package]
name = "$package"
version = "1.2.3"
edition = "2024"
license = "MIT"
EOF
    cat >"$WORK/source/$package/src/lib.rs" <<'EOF'
pub fn answer() -> u32 { 42 }
EOF
done
/usr/bin/git init -q -b main "$WORK/source"
/usr/bin/git -C "$WORK/source" config user.name "Lorry Test"
/usr/bin/git -C "$WORK/source" config user.email "lorry@example.invalid"
/usr/bin/git -C "$WORK/source" add Cargo.toml */Cargo.toml */src/lib.rs
/usr/bin/git -C "$WORK/source" commit -q -m fixture
COMMIT="$(/usr/bin/git -C "$WORK/source" rev-parse HEAD)"
/usr/bin/git -C "$WORK/source" branch topic
/usr/bin/git -C "$WORK/source" tag v1
/usr/bin/git clone -q --bare "$WORK/source" "$WORK/git/repository.git"
CARGO_SOURCE="git+$GIT_URL?branch=main#$COMMIT"
HEAD_SOURCE="git+$GIT_URL#$COMMIT"
TAG_SOURCE="git+$GIT_URL?tag=v1#$COMMIT"
NAMED_SOURCE="git+$GIT_URL?rev=refs%2Fheads%2Ftopic#$COMMIT"
PINNED_SOURCE="git+$GIT_URL?rev=$COMMIT#$COMMIT"

cat >"$PROJECT/Cargo.toml" <<EOF
[workspace]
members = ["app"]
resolver = "2"

[patch.crates-io]
renamed = { package = "demo", git = "$GIT_URL", branch = "main" }
head-demo = { git = "$GIT_URL" }
tag-demo = { git = "$GIT_URL", tag = "v1" }
named-demo = { git = "$GIT_URL", rev = "refs/heads/topic" }
pinned-demo = { git = "$GIT_URL", rev = "$COMMIT" }

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
head-demo = "=1.2.3"
tag-demo = "=1.2.3"
named-demo = "=1.2.3"
pinned-demo = "=1.2.3"
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
 "head-demo 1.2.3 ($HEAD_SOURCE)",
 "named-demo 1.2.3 ($NAMED_SOURCE)",
 "pinned-demo 1.2.3 ($PINNED_SOURCE)",
 "tag-demo 1.2.3 ($TAG_SOURCE)",
]

[[package]]
name = "demo"
version = "1.2.3"
source = "$CARGO_SOURCE"

[[package]]
name = "head-demo"
version = "1.2.3"
source = "$HEAD_SOURCE"

[[package]]
name = "named-demo"
version = "1.2.3"
source = "$NAMED_SOURCE"

[[package]]
name = "pinned-demo"
version = "1.2.3"
source = "$PINNED_SOURCE"

[[package]]
name = "tag-demo"
version = "1.2.3"
source = "$TAG_SOURCE"
EOF
cat >"$HOME_DIR/.config/lorry/lorry.toml" <<EOF
config-version = 1

[network]
curl = "$WORK/bin/git-curl"

[repositories]
user = "$REPOSITORY"

[policy]
default = "allow"

[policy.rules.allow-demo-script]
action = "allow"
name = "demo"
version = "=1.2.3"
source = "git"
allow-build-script = true
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

echo "== Rejecting first materialization without automation approval =="
INITIAL_LOCK_HASH="$(sha256sum "$PROJECT/Cargo.lock")"
if (cd "$PROJECT" && HOME="$HOME_DIR" "$LORRY" vendor -p app \
    </dev/null >"$WORK/initial-unapproved.out" 2>&1); then
    fail "non-interactive vendor approved first Git materialization"
fi
grep -F 'no interactive terminal is available' \
    "$WORK/initial-unapproved.out" >/dev/null ||
    fail "first-materialization rejection had the wrong diagnostic"
[ "$(sha256sum "$PROJECT/Cargo.lock")" = "$INITIAL_LOCK_HASH" ] ||
    fail "unapproved first materialization changed Cargo.lock"
[ ! -e "$PROJECT/app/.lorry/dependencies-v2.toml" ] ||
    fail "unapproved first materialization published admission state"
[ "$(manifest_hashes)" = "$MANIFEST_HASHES" ] ||
    fail "unapproved first materialization changed an input manifest"

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
STATE_PATH="$PROJECT/app/.lorry/dependencies-v2.toml"
STATE_HASH="$(sha256sum "$STATE_PATH")"

echo "== Reusing unchanged Git state non-interactively =="
(cd "$PROJECT" && HOME="$HOME_DIR" "$LORRY" vendor -p app </dev/null)
[ "$(manifest_hashes)" = "$MANIFEST_HASHES" ] || fail "warm vendor changed a manifest"
[ "$(sha256sum "$PROJECT/Cargo.lock")" = "$LOCK_HASH" ] ||
    fail "warm vendor changed Cargo.lock"

echo "== Reviewing a moved branch as one atomic candidate =="
cat >"$WORK/source/demo/src/lib.rs" <<'EOF'
pub fn answer() -> u32 { 43 }
EOF
cat >"$WORK/source/demo/build.rs" <<'EOF'
fn main() {}
EOF
/usr/bin/git -C "$WORK/source" add demo/build.rs demo/src/lib.rs
/usr/bin/git -C "$WORK/source" commit -q -m update
NEW_COMMIT="$(/usr/bin/git -C "$WORK/source" rev-parse HEAD)"
/usr/bin/git -C "$WORK/source" push -q "$WORK/git/repository.git" main

if (cd "$PROJECT" && HOME="$HOME_DIR" "$LORRY" vendor -p app \
    </dev/null >"$WORK/unapproved.out" 2>&1); then
    fail "non-interactive vendor approved a moved branch"
fi
grep -F "old commit: $COMMIT" "$WORK/unapproved.out" >/dev/null ||
    fail "moved-branch review omitted the old commit"
grep -F "new commit: $NEW_COMMIT" "$WORK/unapproved.out" >/dev/null ||
    fail "moved-branch review omitted the new commit"
grep -F 'no interactive terminal is available' "$WORK/unapproved.out" >/dev/null ||
    fail "moved-branch rejection had the wrong diagnostic"
[ "$(sha256sum "$PROJECT/Cargo.lock")" = "$LOCK_HASH" ] ||
    fail "unapproved Git movement changed Cargo.lock"
[ "$(sha256sum "$STATE_PATH")" = "$STATE_HASH" ] ||
    fail "unapproved Git movement changed admission state"
[ "$(manifest_hashes)" = "$MANIFEST_HASHES" ] ||
    fail "unapproved Git movement changed an input manifest"

(cd "$PROJECT" && HOME="$HOME_DIR" "$LORRY" vendor -p app --accept-all \
    </dev/null >"$WORK/accepted.out" 2>&1)
[ "$(grep -c '^Git patch candidate:' "$WORK/accepted.out")" -eq 2 ] ||
    fail "moved branch and default HEAD were not both shown"
if grep -F '[y/N]' "$WORK/accepted.out" >/dev/null; then
    fail "--accept-all emitted an interactive prompt"
fi
grep -F '+ capability:' "$WORK/accepted.out" >/dev/null ||
    fail "combined Git and capability change omitted the capability review"
grep -F "source = \"git+$GIT_URL?branch=main#$NEW_COMMIT\"" \
    "$PROJECT/Cargo.lock" >/dev/null || fail "accepted branch did not update Cargo.lock"
CARGO_SOURCE="git+$GIT_URL?branch=main#$NEW_COMMIT"
[ "$(manifest_hashes)" = "$MANIFEST_HASHES" ] ||
    fail "accepted Git movement changed an input manifest"
LOCK_HASH="$(sha256sum "$PROJECT/Cargo.lock")"
STATE_HASH="$(sha256sum "$STATE_PATH")"

echo "== Batching branch, HEAD, tag, and named-rev movement =="
cat >"$WORK/source/demo/src/lib.rs" <<'EOF'
pub fn answer() -> u32 { 44 }
EOF
/usr/bin/git -C "$WORK/source" add demo/src/lib.rs
/usr/bin/git -C "$WORK/source" commit -q -m multi-selector-update
BATCH_COMMIT="$(/usr/bin/git -C "$WORK/source" rev-parse HEAD)"
/usr/bin/git -C "$WORK/source" tag -f v1 >/dev/null
/usr/bin/git -C "$WORK/source" branch -f topic HEAD
/usr/bin/git -C "$WORK/source" push -q "$WORK/git/repository.git" main
/usr/bin/git -C "$WORK/source" push -q --force "$WORK/git/repository.git" v1 topic

if printf '\n' | script -qefc \
    "cd '$PROJECT' && HOME='$HOME_DIR' '$LORRY' vendor -p app" \
    "$WORK/declined.typescript" >/dev/null; then
    fail "interactive default accepted a multi-selector update"
fi
[ "$(grep -c 'Approve this dependency and capability change?' \
    "$WORK/declined.typescript")" -eq 1 ] ||
    fail "multi-selector update did not ask exactly once"
[ "$(grep -c 'Git patch candidate:' "$WORK/declined.typescript")" -eq 4 ] ||
    fail "multi-selector review did not show all four mutable selectors"
grep -F '[WARNING: RETARGETED TAG]' "$WORK/declined.typescript" >/dev/null ||
    fail "moved tag was not labeled prominently"
[ "$(sha256sum "$PROJECT/Cargo.lock")" = "$LOCK_HASH" ] ||
    fail "declined multi-selector update changed Cargo.lock"
[ "$(sha256sum "$STATE_PATH")" = "$STATE_HASH" ] ||
    fail "declined multi-selector update changed admission state"
[ "$(manifest_hashes)" = "$MANIFEST_HASHES" ] ||
    fail "declined multi-selector update changed an input manifest"

(cd "$PROJECT" && HOME="$HOME_DIR" "$LORRY" vendor -p app --accept-all \
    </dev/null >"$WORK/batch-accepted.out" 2>&1)
[ "$(grep -c '^Git patch candidate:' "$WORK/batch-accepted.out")" -eq 4 ] ||
    fail "automated multi-selector review did not show all candidates"
grep -F "source = \"git+$GIT_URL#$BATCH_COMMIT\"" \
    "$PROJECT/Cargo.lock" >/dev/null || fail "default HEAD did not update"
grep -F "source = \"git+$GIT_URL?tag=v1#$BATCH_COMMIT\"" \
    "$PROJECT/Cargo.lock" >/dev/null || fail "retargeted tag did not update"
grep -F "source = \"git+$GIT_URL?rev=refs%2Fheads%2Ftopic#$BATCH_COMMIT\"" \
    "$PROJECT/Cargo.lock" >/dev/null || fail "named revision did not update"
grep -F "source = \"$PINNED_SOURCE\"" "$PROJECT/Cargo.lock" >/dev/null ||
    fail "exact commit revision moved after newer commits"
CARGO_SOURCE="git+$GIT_URL?branch=main#$BATCH_COMMIT"
LOCK_HASH="$(sha256sum "$PROJECT/Cargo.lock")"
STATE_HASH="$(sha256sum "$STATE_PATH")"

echo "== Preserving state after a bad materialized candidate =="
/usr/bin/git -C "$WORK/source" rm -q named-demo/Cargo.toml
/usr/bin/git -C "$WORK/source" commit -q -m invalid-candidate
BAD_COMMIT="$(/usr/bin/git -C "$WORK/source" rev-parse HEAD)"
/usr/bin/git -C "$WORK/source" tag -f v1 >/dev/null
/usr/bin/git -C "$WORK/source" branch -f topic HEAD
/usr/bin/git -C "$WORK/source" push -q "$WORK/git/repository.git" main
/usr/bin/git -C "$WORK/source" push -q --force "$WORK/git/repository.git" v1 topic
if (cd "$PROJECT" && HOME="$HOME_DIR" "$LORRY" vendor -p app --accept-all \
    </dev/null >"$WORK/invalid.out" 2>&1); then
    fail "vendor accepted a Git candidate missing a locked package"
fi
grep -F 'named-demo' "$WORK/invalid.out" >/dev/null ||
    fail "bad Git candidate did not identify the missing package"
BAD_SOURCE="git+$GIT_URL?rev=refs%2Fheads%2Ftopic#$BAD_COMMIT"
BAD_OBJECT="$(printf %s "$BAD_SOURCE" | sha256sum | cut -d' ' -f1)"
[ -f "$PROJECT/.lorry/vendor/git/$BAD_OBJECT/git.toml" ] ||
    fail "failed candidate did not retain its complete immutable object"
[ "$(sha256sum "$PROJECT/Cargo.lock")" = "$LOCK_HASH" ] ||
    fail "bad Git candidate changed Cargo.lock"
[ "$(sha256sum "$STATE_PATH")" = "$STATE_HASH" ] ||
    fail "bad Git candidate changed admission state"
/usr/bin/git -C "$WORK/source" push -q --force "$WORK/git/repository.git" \
    "$BATCH_COMMIT:refs/heads/main" "$BATCH_COMMIT:refs/heads/topic" \
    "$BATCH_COMMIT:refs/tags/v1"

echo "== Enforcing explicit denial before approval =="
cp "$HOME_DIR/.config/lorry/lorry.toml" "$WORK/allowed-lorry.toml"
cat >>"$HOME_DIR/.config/lorry/lorry.toml" <<'EOF'

[policy.rules.deny-demo]
action = "deny"
name = "demo"
version = "=1.2.3"
source = "git"
EOF
if (cd "$PROJECT" && HOME="$HOME_DIR" "$LORRY" vendor -p app --accept-all \
    </dev/null >"$WORK/denied.out" 2>&1); then
    fail "--accept-all bypassed an explicit policy denial"
fi
grep -F 'denied by policy rule `deny-demo`' "$WORK/denied.out" >/dev/null ||
    fail "explicit policy denial had the wrong diagnostic"
[ "$(sha256sum "$PROJECT/Cargo.lock")" = "$LOCK_HASH" ] ||
    fail "policy denial changed Cargo.lock"
[ "$(sha256sum "$STATE_PATH")" = "$STATE_HASH" ] ||
    fail "policy denial changed admission state"
cp "$WORK/allowed-lorry.toml" "$HOME_DIR/.config/lorry/lorry.toml"

echo "== Consuming the verified Git patch offline =="
chmod 000 "$WORK/bin/git-curl"
(
    cd "$PROJECT"
    HOME="$HOME_DIR" "$LORRY" build -p app
    [ "$(HOME="$HOME_DIR" "$LORRY" run -p app)" = 44 ]
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
