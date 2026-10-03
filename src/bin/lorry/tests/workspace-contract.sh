#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: workspace-contract.sh LORRY" >&2
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
WORK="$(mktemp -d /tmp/lorry-workspace-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME:?}/.rustup}"
mkdir -p "$WORK/home/.config/lorry" "$WORK/project/app/src" \
    "$WORK/project/tool/src" "$WORK/project/shared/src" "$WORK/project/scripted/src"
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" \
    >"$WORK/home/.config/lorry/lorry.toml"
export HOME="$WORK/home"

printf '%s\n' \
    '[workspace]' \
    'members = ["app", "tool", "shared", "scripted"]' \
    'resolver = "2"' \
    '' \
    '[profile.dev]' \
    'panic = "abort"' >"$WORK/project/Cargo.toml"
printf '%s\n' \
    'version = 4' \
    '[[package]]' \
    'name = "app"' \
    'version = "0.1.0"' \
    '[[package]]' \
    'name = "tool"' \
    'version = "0.1.0"' \
    'dependencies = [' \
    ' "shared",' \
    ']' \
    '[[package]]' \
    'name = "shared"' \
    'version = "0.1.0"' \
    '[[package]]' \
    'name = "scripted"' \
    'version = "0.1.0"' >"$WORK/project/Cargo.lock"
for package in app tool; do
    printf '%s\n' \
        '[package]' \
        "name = \"$package\"" \
        'version = "0.1.0"' \
        'edition = "2024"' >"$WORK/project/$package/Cargo.toml"
    printf 'fn main() { println!("%s"); }\n' "$package" \
        >"$WORK/project/$package/src/main.rs"
done
printf '%s\n' \
    '[dependencies]' \
    'shared = { path = "../shared" }' >>"$WORK/project/tool/Cargo.toml"
printf 'fn main() { println!("{}", shared::VALUE); }\n' \
    >"$WORK/project/tool/src/main.rs"
printf '%s\n' \
    '[package]' \
    'name = "shared"' \
    'version = "0.1.0"' \
    'edition = "2024"' \
    '' \
    '[lib]' \
    'path = "src/lib.rs"' >"$WORK/project/shared/Cargo.toml"
printf 'pub const VALUE: &str = "tool";\n' >"$WORK/project/shared/src/lib.rs"
printf '%s\n' \
    '[package]' \
    'name = "scripted"' \
    'version = "0.1.0"' \
    'edition = "2024"' >"$WORK/project/scripted/Cargo.toml"
printf 'fn main() { println!("cargo:rustc-cfg=scripted"); }\n' \
    >"$WORK/project/scripted/build.rs"
printf 'fn main() {}\n' >"$WORK/project/scripted/src/main.rs"

(
    cd "$WORK/project"
    "$LORRY" vendor -p app --accept-all
    "$LORRY" review -p app >/dev/null
    "$LORRY" -v build -p app 2>"$WORK/app-build.stderr"
    grep -F 'panic=abort' "$WORK/app-build.stderr" >/dev/null
    [ "$("$LORRY" run -p app)" = app ]
    "$LORRY" test -p app -- --quiet
    "$LORRY" build -p app
    "$LORRY" build -p tool 2>"$WORK/tool-build.stderr"
    grep -F 'Verifying dependency state' "$WORK/tool-build.stderr" >/dev/null
    grep -F 'Preparing dependency graph' "$WORK/tool-build.stderr" >/dev/null
    grep -F 'Compiling shared v0.1.0' "$WORK/tool-build.stderr" >/dev/null
    grep -F '[library]' "$WORK/tool-build.stderr" >/dev/null
    grep -F 'Compiling tool v0.1.0' "$WORK/tool-build.stderr" >/dev/null
    grep -F '[binary `tool`]' "$WORK/tool-build.stderr" >/dev/null
    "$LORRY" clean -p tool
    "$LORRY" --quiet build -p tool 2>"$WORK/quiet-build.stderr"
    [ ! -s "$WORK/quiet-build.stderr" ]
)
[ -x "$WORK/project/target/lorry/debug/app" ]
[ -x "$WORK/project/target/lorry/debug/tool" ]
(
    cd "$WORK/project/app"
    [ "$("$LORRY" run)" = app ]
)
(
    cd "$WORK/project"
    "$LORRY" clean -p app
)
[ ! -e "$WORK/project/target/lorry/debug/app" ]
[ -x "$WORK/project/target/lorry/debug/tool" ]

# Cargo rejects force-warn in a manifest, in both supported lint forms.
cp "$WORK/project/app/Cargo.toml" "$WORK/app-baseline.toml"
for declaration in 'unused = "force-warn"' \
    'unused = { level = "force-warn" }'; do
    cp "$WORK/app-baseline.toml" "$WORK/project/app/Cargo.toml"
    printf '\n[lints.rust]\n%s\n' "$declaration" >>"$WORK/project/app/Cargo.toml"
    if (cd "$WORK/project" && "$LORRY" build -p app) \
        2>"$WORK/force-warn.stderr"; then
        echo "workspace-contract: accepted force-warn manifest lint" >&2
        exit 1
    fi
    grep -F 'unsupported rustc lint level `force-warn`' \
        "$WORK/force-warn.stderr" >/dev/null
done
cp "$WORK/app-baseline.toml" "$WORK/project/app/Cargo.toml"

# A selected member's build script is never silently skipped.
for command in build check test run; do
    if (cd "$WORK/project" && "$LORRY" "$command" -p scripted) \
        2>"$WORK/scripted.stderr"; then
        echo "workspace-contract: $command ignored a member build script" >&2
        exit 1
    fi
    grep -F 'package `scripted` has a build script' "$WORK/scripted.stderr" >/dev/null || {
        cat "$WORK/scripted.stderr" >&2
        exit 1
    }
done
[ ! -e "$WORK/project/target/lorry/debug/scripted" ]

# The package limit skips members by directory, not by name: a nonmember
# below the root that shares a member's name still counts.
LIMITED="$WORK/limited"
mkdir -p "$LIMITED/app/src" "$LIMITED/one/src" "$LIMITED/three/src" \
    "$LIMITED/vendored/one/src" "$LIMITED/two/src"
printf '%s\n' '[workspace]' 'members = ["app", "one", "three"]' 'resolver = "2"' \
    >"$LIMITED/Cargo.toml"
printf '%s\n' '[package]' 'name = "app"' 'version = "0.1.0"' 'edition = "2024"' \
    '[dependencies]' 'one = { path = "../vendored/one" }' 'two = { path = "../two" }' \
    'three = { path = "../three" }' >"$LIMITED/app/Cargo.toml"
for package in one:0.3.0:one three:0.1.0:three one:0.1.0:vendored/one two:0.1.0:two; do
    IFS=: read -r name version directory <<<"$package"
    printf '[package]\nname = "%s"\nversion = "%s"\nedition = "2024"\n' \
        "$name" "$version" >"$LIMITED/$directory/Cargo.toml"
    printf 'pub fn value() {}\n' >"$LIMITED/$directory/src/lib.rs"
done
printf 'pub fn value() {}\n' >"$LIMITED/app/src/lib.rs"
printf '%s\n' 'version = 4' \
    '[[package]]' 'name = "app"' 'version = "0.1.0"' \
    'dependencies = [' ' "one 0.1.0",' ' "three",' ' "two",' ']' \
    '[[package]]' 'name = "one"' 'version = "0.1.0"' \
    '[[package]]' 'name = "one"' 'version = "0.3.0"' \
    '[[package]]' 'name = "three"' 'version = "0.1.0"' \
    '[[package]]' 'name = "two"' 'version = "0.1.0"' >"$LIMITED/Cargo.lock"
cp "$WORK/home/.config/lorry/lorry.toml" "$WORK/config.backup"
limited_vendor() {
    cp "$WORK/config.backup" "$WORK/home/.config/lorry/lorry.toml"
    printf '%s\n' '[policy.limits]' "max-packages = $1" >>"$WORK/home/.config/lorry/lorry.toml"
    (cd "$LIMITED" && "$LORRY" vendor -p app --accept-all) 2>"$WORK/limited.stderr"
}
if limited_vendor 1; then
    echo "workspace-contract: a member's namesake was exempt from the package limit" >&2
    exit 1
fi
grep -F 'than the limit of 1' "$WORK/limited.stderr" >/dev/null || {
    cat "$WORK/limited.stderr" >&2
    exit 1
}
limited_vendor 2 || {
    cat "$WORK/limited.stderr" >&2
    echo "workspace-contract: a member counted toward the package limit" >&2
    exit 1
}
cp "$WORK/config.backup" "$WORK/home/.config/lorry/lorry.toml"

echo "PASS: selected members build, run, test, and clean; unsupported lint levels and member build scripts fail; the package limit matches members by directory"
