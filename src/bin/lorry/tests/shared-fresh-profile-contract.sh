#!/usr/bin/env bash
# An unchanged shared workspace build or run reuses its completed profile:
# no rustc compile and no build script. Each input change takes the full path.
set -euo pipefail
export CARGO_NET_OFFLINE=true

LORRY="$(realpath "${1:?usage: shared-fresh-profile-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${LORRY_TEST_RUSTC:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
WORK="$(mktemp -d /tmp/lorry-shared-fresh-contract-XXXXXX)"
trap 'status=$?; if [ "$status" = 0 ]; then rm -rf "$WORK"; else echo "Retained failed fixture: $WORK" >&2; fi' EXIT
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME:?}/.rustup}"
export CARGO_HOME="${CARGO_HOME:-${HOME:?}/.cargo}"
mkdir -p "$WORK/home/.config/lorry" "$WORK/project"/{app,util,other}/src
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" \
    >"$WORK/home/.config/lorry/lorry.toml"
cd "$WORK/project"
cat >Cargo.toml <<'EOF'
[workspace]
members = ["app", "util", "other"]
resolver = "2"
EOF
cat >app/Cargo.toml <<'EOF'
[package]
name = "app"
version = "0.1.0"
edition = "2024"
[dependencies]
util = { path = "../util" }
EOF
cat >app/build.rs <<'EOF'
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-env=APP_SCRIPT=one");
}
EOF
printf 'fn main() { println!("{} {}", env!("APP_SCRIPT"), util::describe()); }\n' >app/src/main.rs
printf '[package]\nname = "util"\nversion = "0.1.0"\nedition = "2024"\n[features]\nextra = []\n' \
    >util/Cargo.toml
cat >util/src/lib.rs <<'EOF'
pub fn describe() -> &'static str { if cfg!(feature = "extra") { "extra" } else { "plain" } }
EOF
cat >other/Cargo.toml <<'EOF'
[package]
name = "other"
version = "0.1.0"
edition = "2024"
[dependencies]
util = { path = "../util", features = ["extra"] }
EOF
printf 'pub fn value() -> &%sstatic str { util::describe() }\n' "'" >other/src/lib.rs
cat >lorry.toml <<'EOF'
config-version = 1
[policy.rules.app]
action = "allow"
name = "app"
source = "path"
allow-build-script = true
EOF
"$LORRY_TEST_CARGO" generate-lockfile --offline

cat >"$WORK/rustc-log" <<'EOF'
#!/usr/bin/env bash
{
    printf 'BEGIN'
    printf ' <%s>' "$@"
    printf '\n'
} >>"${LORRY_FRESH_RUSTC_LOG:?}"
exec "${REAL_RUSTC:?}" "$@"
EOF
chmod +x "$WORK/rustc-log"
export HOME="$WORK/home"
export RUSTC="$WORK/rustc-log"
export REAL_RUSTC="$LORRY_TEST_RUSTC"
export LORRY_FRESH_RUSTC_LOG="$WORK/rustc.log"
export LORRY_JOBS=1

step=0
lorry() {
    step=$((step + 1))
    : >"$LORRY_FRESH_RUSTC_LOG"
    "$LORRY" -v "$@" >"$WORK/$step.out" 2>"$WORK/$step.err"
}
fail() {
    echo "shared-fresh-profile-contract: step $step: $*" >&2
    exit 1
}
reused() {
    grep -F 'accepted fresh root profile after dependency admission' "$WORK/$step.err" >/dev/null
}
expect_fresh() {
    reused || fail "did not reuse the completed profile"
    if grep -F -- '<--crate-name>' "$LORRY_FRESH_RUSTC_LOG" >/dev/null; then
        fail "a reused profile invoked rustc"
    fi
    if grep -F 'Running build script' "$WORK/$step.err" >/dev/null; then
        fail "a reused profile ran a build script"
    fi
}
expect_rebuilt() {
    if reused; then fail "reused a stale completed profile ($1)"; fi
}
compiled() {
    grep -F -- "<--crate-name> <$1>" "$LORRY_FRESH_RUSTC_LOG" >/dev/null ||
        fail "did not compile $1"
}
output() {
    [ "$(target/lorry/debug/app)" = "$1" ] ||
        fail "app printed '$(target/lorry/debug/app)', expected '$1'"
}

"$LORRY" vendor --accept-all >/dev/null 2>&1
lorry build
compiled app
output "one extra"
lorry build
expect_fresh

# The default selection unifies util/extra through other; -p app does not.
# Each selection keeps its own record, and a reinstalled binary invalidates
# the record of the selection that installed the previous one.
lorry build -p app
expect_rebuilt "member selection"
output "one plain"
lorry build -p app
expect_fresh
lorry build
expect_rebuilt "binary reinstalled by another selection"
output "one extra"
lorry build
expect_fresh

printf '// edited\n' >>util/src/lib.rs
lorry build
expect_rebuilt "member source edit"
compiled util
lorry build
expect_fresh

sed -i 's/APP_SCRIPT=one/APP_SCRIPT=two/' app/build.rs
lorry build
expect_rebuilt "build-script input"
grep -F 'Running build script app' "$WORK/$step.err" >/dev/null || fail "did not rerun the build script"
output "two extra"
lorry build
expect_fresh

lorry build -p app --features util/extra
expect_rebuilt "feature request"
output "two extra"
lorry build -p app --features util/extra
expect_fresh
lorry build -p app
expect_rebuilt "removed feature request"
output "two plain"

lorry build --bin app
expect_rebuilt "target selection"
lorry build --bin app
expect_fresh

lorry run -p app
[ "$(cat "$WORK/$step.out")" = "two plain" ] || fail "run printed the wrong output"
lorry run -p app
expect_fresh
[ "$(cat "$WORK/$step.out")" = "two plain" ] || fail "a reused run printed the wrong output"

# A new member changes the member set and the lock.
mkdir -p added/src
printf '[package]\nname = "added"\nversion = "0.1.0"\nedition = "2024"\n' >added/Cargo.toml
printf 'pub fn added() {}\n' >added/src/lib.rs
sed -i 's/members = \["app", "util", "other"\]/members = ["app", "util", "other", "added"]/' Cargo.toml
cp Cargo.lock "$WORK/lock.before"
"$LORRY_TEST_CARGO" generate-lockfile --offline
if cmp -s Cargo.lock "$WORK/lock.before"; then fail "adding a member did not change the lock"; fi
"$LORRY" vendor --accept-all >/dev/null 2>&1
lorry build
expect_rebuilt "member set and lock"
compiled added
lorry build
expect_fresh

echo "PASS: shared workspace builds reuse completed profiles and rebuild on each input change"
