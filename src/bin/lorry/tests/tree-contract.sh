#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: tree-contract.sh LORRY" >&2
    exit 1
fi

LORRY="$(realpath "$1")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${LORRY_TEST_CARGO:-}" ] || [ -z "${LORRY_TEST_RUSTC:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
WORK="$(mktemp -d /tmp/lorry-tree-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
PROJECT="$WORK/project"
HOME_DIR="$WORK/home"
mkdir -p "$HOME_DIR/.config/lorry" "$PROJECT/src"

cat >"$HOME_DIR/.config/lorry/lorry.toml" <<EOF
config-version = 1

[cache]
directory = "$WORK/cache"

[policy]
default = "allow"

[policy.rules.allow-derive-fixture]
action = "allow"
name = "derive-fixture"
version = "=1.0.0"
source = "path"
allow-proc-macro = true
EOF
cat >"$PROJECT/Cargo.toml" <<'EOF'
[package]
name = "tree-fixture"
version = "0.1.0"
edition = "2024"

[dependencies]
shared = { path = "shared" }
alpha = { path = "alpha" }
derive-fixture = { path = "derive-fixture" }

[target.'cfg(target_os = "motor")'.dependencies]
motor-only = { path = "motor-only" }

[target.'cfg(target_os = "linux")'.dependencies]
linux-only = { path = "linux-only" }
EOF
printf 'fn main() {}\n' >"$PROJECT/src/main.rs"

for package in shared leaf build-helper motor-only linux-only; do
    mkdir -p "$PROJECT/$package/src"
    cat >"$PROJECT/$package/Cargo.toml" <<EOF
[package]
name = "$package"
version = "1.0.0"
edition = "2024"
EOF
    printf 'pub fn value() {}\n' >"$PROJECT/$package/src/lib.rs"
done
cat >>"$PROJECT/shared/Cargo.toml" <<'EOF'

[dependencies]
leaf = { path = "../leaf" }
EOF

mkdir -p "$PROJECT/alpha/src"
cat >"$PROJECT/alpha/Cargo.toml" <<'EOF'
[package]
name = "alpha"
version = "1.0.0"
edition = "2024"

[dependencies]
shared = { path = "../shared" }

[build-dependencies]
build-helper = { path = "../build-helper" }
EOF
printf 'pub fn value() {}\n' >"$PROJECT/alpha/src/lib.rs"

mkdir -p "$PROJECT/derive-fixture/src"
cat >"$PROJECT/derive-fixture/Cargo.toml" <<'EOF'
[package]
name = "derive-fixture"
version = "1.0.0"
edition = "2024"

[lib]
proc-macro = true

[dependencies]
shared = { path = "../shared" }
EOF
printf 'extern crate proc_macro;\n' >"$PROJECT/derive-fixture/src/lib.rs"

HOME="$HOME_DIR" RUSTC="$LORRY_TEST_RUSTC" \
    "$LORRY_TEST_CARGO" generate-lockfile --offline \
    --manifest-path "$PROJECT/Cargo.toml"
(
    cd "$PROJECT"
    HOME="$HOME_DIR" RUSTC="$LORRY_TEST_RUSTC" "$LORRY" vendor --accept-all
)

"$LORRY_TEST_CARGO" tree --locked --offline \
    --manifest-path "$PROJECT/Cargo.toml" --target x86_64-unknown-motor \
    >"$WORK/cargo.tree"
HOME="$HOME_DIR" RUSTC="$LORRY_TEST_RUSTC" "$LORRY" tree \
    --manifest-path "$PROJECT/Cargo.toml" --target x86_64-unknown-motor \
    >"$WORK/lorry.tree"
if ! cmp "$WORK/cargo.tree" "$WORK/lorry.tree"; then
    diff -u "$WORK/cargo.tree" "$WORK/lorry.tree" >&2
    exit 1
fi

HOME="$HOME_DIR" RUSTC="$LORRY_TEST_RUSTC" "$LORRY" tree \
    -p tree-fixture --manifest-path "$PROJECT/Cargo.toml" \
    --target x86_64-unknown-motor >"$WORK/lorry-again.tree"
cmp "$WORK/lorry.tree" "$WORK/lorry-again.tree"
grep -F 'derive-fixture v1.0.0' "$WORK/lorry.tree" | \
    grep -F '(proc-macro)' >/dev/null
grep -F '[build-dependencies]' "$WORK/lorry.tree" >/dev/null
grep -F 'shared v1.0.0' "$WORK/lorry.tree" | grep -F '(*)' >/dev/null
grep -F 'motor-only v1.0.0' "$WORK/lorry.tree" >/dev/null
if grep -F 'linux-only v1.0.0' "$WORK/lorry.tree" >/dev/null; then
    echo "tree-contract: Motor tree contains the Linux-only dependency" >&2
    exit 1
fi

echo "PASS: tree is deterministic and matches Cargo for path, build, and proc-macro edges"
