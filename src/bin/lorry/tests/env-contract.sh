#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

[ "$#" -eq 1 ] || { echo "usage: env-contract.sh LORRY" >&2; exit 2; }
LORRY="$(realpath "$1")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
WORK="$(mktemp -d /tmp/lorry-env-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
export HOME="$WORK/home" CARGO_HOME="$WORK/home/.cargo" RUSTC="$LORRY_TEST_RUSTC"
mkdir -p "$HOME/.config/lorry" "$CARGO_HOME" "$WORK/project"/{src,.cargo,dep/src}
cat >"$HOME/.config/lorry/lorry.toml" <<EOF
config-version = 1
use-cargo-registry = false
[cache]
directory = "$WORK/cache"
[test]
extraction-root = "$WORK/extracted"
EOF
cat >"$CARGO_HOME/config.toml" <<'EOF'
[env]
LORRY_ENV_VALUE = "home-default"
LORRY_ENV_PARENT = { value = "parent-assets", relative = true, force = true }
EOF
cat >"$WORK/project/.cargo/config.toml" <<'EOF'
[env]
LORRY_ENV_VALUE = "project-default"
LORRY_ENV_FORCED = { value = "forced", force = true }
LORRY_ENV_EMPTY = ""
LORRY_ENV_PATH = { value = "assets", relative = true }
LORRY_ENV_PARENT = { force = false }
CARGO_PKG_NAME = { value = "must-not-replace-package-metadata", force = true }
CFLAGS_x86_64_unknown_motor = "--target=x86_64-unknown-motor"
EOF
cat >"$WORK/project/Cargo.toml" <<'EOF'
[package]
name = "env-fixture"
version = "0.1.0"
edition = "2024"
[dependencies]
env-dep = { path = "dep" }
EOF
cat >"$WORK/project/dep/Cargo.toml" <<'EOF'
[package]
name = "env-dep"
version = "0.1.0"
edition = "2024"
EOF
cat >"$WORK/project/dep/build.rs" <<'EOF'
fn main() {
    println!("cargo:rerun-if-env-changed=LORRY_ENV_VALUE");
    println!("cargo:rustc-env=SCRIPT_VALUE={}", std::env::var("LORRY_ENV_VALUE").unwrap());
    assert_eq!(std::env::var("LORRY_ENV_FORCED").unwrap(), "forced");
    assert_eq!(std::env::var("LORRY_ENV_EMPTY").unwrap(), "");
    assert_eq!(std::env::var("CARGO_PKG_NAME").unwrap(), "env-dep");
    assert_eq!(std::env::var("CFLAGS_x86_64_unknown_motor").unwrap(), "--target=x86_64-unknown-motor");
}
EOF
printf 'pub const VALUE: &str = env!("SCRIPT_VALUE");\n' >"$WORK/project/dep/src/lib.rs"
cat >"$WORK/project/src/main.rs" <<'EOF'
fn verify() {
    assert_eq!(env!("LORRY_ENV_VALUE"), std::env::var("LORRY_ENV_VALUE").unwrap());
    assert_eq!(env!("LORRY_ENV_VALUE"), env_dep::VALUE);
    assert_eq!(env!("LORRY_ENV_FORCED"), "forced");
    assert_eq!(std::env::var("LORRY_ENV_FORCED").unwrap(), "forced");
    assert_eq!(env!("LORRY_ENV_EMPTY"), "");
    assert_eq!(env!("CARGO_PKG_NAME"), "env-fixture");
    assert_eq!(std::env::var("CARGO_PKG_NAME").unwrap(), "env-fixture");
}
fn main() {
    verify();
    println!("{}|{}|{}", env!("LORRY_ENV_VALUE"), env!("LORRY_ENV_PATH"), env!("LORRY_ENV_PARENT"));
}
#[test]
fn configured_environment() { verify(); }
EOF
cd "$WORK/project"
"$LORRY_TEST_CARGO" generate-lockfile --offline
if "$LORRY" build >"$WORK/unapproved.log" 2>&1; then
    echo "env-contract: an unapproved repository environment was used" >&2
    exit 1
fi
grep -F 'you have not approved' "$WORK/unapproved.log"
"$LORRY" vendor --accept-all -q
export LORRY_ENV_FORCED=caller
for value in project-default caller-value '' changed-caller; do
    if [ "$value" = project-default ]; then unset LORRY_ENV_VALUE
    else export LORRY_ENV_VALUE="$value"; fi
    "$LORRY_TEST_CARGO" run --offline -q >"$WORK/cargo.out"
    "$LORRY" run --offline -q >"$WORK/lorry.out"
    cmp "$WORK/cargo.out" "$WORK/lorry.out"
    printf '%s|%s/assets|%s/parent-assets\n' "$value" "$WORK/project" "$HOME" >"$WORK/expected"
    cmp "$WORK/expected" "$WORK/lorry.out"
done
cp .cargo/config.toml "$WORK/original-config.toml"
for spelling in './assets' 'a//b' 'a/./b/.' "$WORK/absolute//assets/."; do
    sed "s|value = \"assets\"|value = \"$spelling\"|" "$WORK/original-config.toml" >.cargo/config.toml
    "$LORRY" vendor --accept-all -q
    "$LORRY_TEST_CARGO" run --offline -q >"$WORK/cargo.out"
    "$LORRY" run --offline -q >"$WORK/lorry.out"
    diff -u "$WORK/cargo.out" "$WORK/lorry.out"
done
cp "$WORK/original-config.toml" .cargo/config.toml
# A relative Cargo home still defines absolute environment paths.
CARGO_HOME=../home/.cargo "$LORRY_TEST_CARGO" run --offline -q >"$WORK/cargo.out"
CARGO_HOME=../home/.cargo "$LORRY" run --offline -q >"$WORK/lorry.out"
diff -u "$WORK/cargo.out" "$WORK/lorry.out"
"$LORRY_TEST_CARGO" test --offline -q
"$LORRY" test --offline -q
"$LORRY" test --offline --bundle -q
unset LORRY_ENV_VALUE
sed -i 's/project-default/changed-config/' .cargo/config.toml
# Accepting again must persist even when the dependency review is unchanged.
sed -i '/^accept-all = true$/d' "$HOME"/.config/lorry/workspaces/*.toml
"$LORRY" vendor --accept-all -q
"$LORRY_TEST_CARGO" run --offline -q >"$WORK/cargo.out"
"$LORRY" run --offline -q >"$WORK/lorry.out"
cmp "$WORK/cargo.out" "$WORK/lorry.out"
grep -F 'changed-config|' "$WORK/lorry.out"
for reserved in CARGO_HOME RUSTUP_HOME RUSTUP_TOOLCHAIN; do
    printf '[env]\n%s = "forbidden"\n' "$reserved" >.cargo/config.toml
    if "$LORRY_TEST_CARGO" check --offline >"$WORK/cargo.err" 2>&1; then
        echo "env-contract: Cargo accepted $reserved" >&2; exit 1
    fi
    grep -F "$reserved" "$WORK/cargo.err" >/dev/null
    if "$LORRY" build --offline >"$WORK/lorry.err" 2>&1; then
        echo "env-contract: Lorry accepted $reserved" >&2; exit 1
    fi
    grep -F "Cargo does not allow \`$reserved\` in \`[env]\`" "$WORK/lorry.err"
done
echo "PASS: Cargo env defaults, overrides, paths, trust, execution, and cache invalidation"
