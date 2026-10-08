#!/usr/bin/env bash
# A dependency's build script reads its own package and its dependencies,
# not the root package's directory, which here is the whole workspace.
set -euo pipefail
export CARGO_NET_OFFLINE=true

LORRY="$(realpath "${1:?usage: script-sandbox-scope-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${LORRY_TEST_RUSTC:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
WORK="$(mktemp -d /tmp/lorry-script-scope-XXXXXX)"
trap 'status=$?; if [ "$status" = 0 ]; then rm -rf "$WORK"; else echo "Retained failed fixture: $WORK" >&2; fi' EXIT
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME:?}/.rustup}"
export CARGO_HOME="${CARGO_HOME:-${HOME:?}/.cargo}"
mkdir -p "$WORK/home/.config/lorry" "$WORK/app/src" "$WORK/dep/src"
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" \
    >"$WORK/home/.config/lorry/lorry.toml"
printf '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2024"\n[dependencies]\ndep = { path = "../dep" }\n' \
    >"$WORK/app/Cargo.toml"
printf 'fn main() { println!("{}", dep::READ); }\n' >"$WORK/app/src/main.rs"
printf 'secret\n' >"$WORK/app/secret.txt"
printf '[package]\nname = "dep"\nversion = "0.1.0"\nedition = "2024"\n' >"$WORK/dep/Cargo.toml"
printf 'pub const READ: &str = env!("ROOT_READ");\n' >"$WORK/dep/src/lib.rs"
cat >"$WORK/dep/build.rs" <<'EOF'
fn main() {
    let secret = std::path::Path::new("../app/secret.txt");
    let read = if std::fs::read(secret).is_ok() { "read" } else { "denied" };
    println!("cargo:rustc-env=ROOT_READ={read}");
}
EOF
cat >"$WORK/app/lorry.toml" <<'EOF'
config-version = 1
[policy.rules.dep]
action = "allow"
name = "dep"
source = "path"
allow-build-script = true
EOF
cd "$WORK/app"
"$LORRY_TEST_CARGO" generate-lockfile --offline
[ "$(env HOME="$WORK/home" "$LORRY" run -q)" = denied ] ||
    { echo "script-sandbox-scope-contract: a dependency's build script read the root package" >&2; exit 1; }

echo "PASS: a dependency's build script cannot read the root package's directory"
