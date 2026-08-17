#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: workspace-contract.sh LORRY" >&2
    exit 1
fi

LORRY="$(realpath "$1")"
WORK="$(mktemp -d /tmp/lorry-workspace-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME:?}/.rustup}"
mkdir -p "$WORK/home/.config/lorry" "$WORK/project/app/src" \
    "$WORK/project/tool/src" "$WORK/project/shared/src"
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" \
    >"$WORK/home/.config/lorry/lorry.toml"
export HOME="$WORK/home"

printf '%s\n' \
    '[workspace]' \
    'members = ["app", "tool", "shared"]' \
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
    grep -F 'Compiling shared v0.1.0' "$WORK/tool-build.stderr" >/dev/null
    grep -F '[library]' "$WORK/tool-build.stderr" >/dev/null
    grep -F 'Compiling tool v0.1.0' "$WORK/tool-build.stderr" >/dev/null
    grep -F '[binary `tool`]' "$WORK/tool-build.stderr" >/dev/null
    "$LORRY" clean -p tool
    "$LORRY" --quiet build -p tool 2>"$WORK/quiet-build.stderr"
    [ ! -s "$WORK/quiet-build.stderr" ]
)
[ -x "$WORK/project/target/lorry/packages/app/debug/app" ]
[ -x "$WORK/project/target/lorry/packages/tool/debug/tool" ]
(
    cd "$WORK/project/app"
    [ "$("$LORRY" run)" = app ]
)
(
    cd "$WORK/project"
    "$LORRY" clean -p app
)
[ ! -e "$WORK/project/target/lorry/packages/app" ]
[ -x "$WORK/project/target/lorry/packages/tool/debug/tool" ]

echo "PASS: selected workspace members build, run, test, and clean independently"
