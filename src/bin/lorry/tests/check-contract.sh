#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: check-contract.sh LORRY" >&2
    exit 1
fi

LORRY="$(realpath "$1")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${LORRY_TEST_RUSTC:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
WORK="$(mktemp -d /tmp/lorry-check-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
HOME_DIR="$WORK/home"
PROJECT="$WORK/project"
DEPENDENCY="$WORK/dependency"
LOG="$WORK/rustc.log"
mkdir -p "$HOME_DIR/.config/lorry" "$PROJECT/src/bin" "$PROJECT/tests" \
    "$DEPENDENCY/src"
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" \
    >"$HOME_DIR/.config/lorry/lorry.toml"

printf '%s\n' \
    '[package]' \
    'name = "check-fixture"' \
    'version = "0.1.0"' \
    'edition = "2024"' \
    '' \
    '[dependencies]' \
    'fixture-dependency = { path = "../dependency" }' \
    >"$PROJECT/Cargo.toml"
printf '%s\n' \
    '[package]' \
    'name = "fixture-dependency"' \
    'version = "1.0.0"' \
    'edition = "2024"' \
    >"$DEPENDENCY/Cargo.toml"
printf '%s\n' \
    'version = 4' \
    '[[package]]' \
    'name = "check-fixture"' \
    'version = "0.1.0"' \
    'dependencies = [' \
    ' "fixture-dependency",' \
    ']' \
    '[[package]]' \
    'name = "fixture-dependency"' \
    'version = "1.0.0"' \
    >"$PROJECT/Cargo.lock"
printf 'pub const VALUE: u8 = 42;\n' >"$DEPENDENCY/src/lib.rs"
printf 'pub fn value() -> u8 { fixture_dependency::VALUE }\n' >"$PROJECT/src/lib.rs"
printf 'fn main() { assert_eq!(check_fixture::value(), 42); }\n' \
    >"$PROJECT/src/bin/first.rs"
printf 'fn main() { assert_eq!(check_fixture::value(), 42); }\n' \
    >"$PROJECT/src/bin/second.rs"
printf '#[test]\nfn integration() { assert_eq!(check_fixture::value(), 42); }\n' \
    >"$PROJECT/tests/integration.rs"

cat >"$WORK/rustc-log" <<'EOF'
#!/usr/bin/env bash
{
    printf 'BEGIN'
    printf ' <%s>' "$@"
    printf '\n'
} >>"${LORRY_CHECK_RUSTC_LOG:?}"
exec "${REAL_RUSTC:?}" "$@"
EOF
chmod +x "$WORK/rustc-log"
export HOME="$HOME_DIR"
export RUSTC="$WORK/rustc-log"
export REAL_RUSTC="$LORRY_TEST_RUSTC"
export LORRY_CHECK_RUSTC_LOG="$LOG"

(
    cd "$PROJECT"
    "$LORRY" vendor --accept-all
)

TARGET="$WORK/editor-target"
: >"$LOG"
"$LORRY" check --workspace --manifest-path "$PROJECT/Cargo.toml" \
    --target-dir "$TARGET"
PROFILE="$TARGET/lorry/check"
[ -d "$PROFILE" ]
grep -F '<src/lib.rs>' "$LOG" >"$WORK/default-root.log"
grep -F '<src/bin/first.rs>' "$LOG" >>"$WORK/default-root.log"
grep -F '<src/bin/second.rs>' "$LOG" >>"$WORK/default-root.log"
[ "$(wc -l <"$WORK/default-root.log")" -eq 3 ]
if grep -F '<tests/integration.rs>' "$LOG" >/dev/null; then
    echo "check-contract: default check compiled an integration test" >&2
    exit 1
fi
if grep -F -- '--emit=dep-info,metadata,link' "$WORK/default-root.log" >/dev/null; then
    echo "check-contract: check requested a linked root artifact" >&2
    exit 1
fi
[ "$(grep -Fc '<--emit=dep-info,metadata>' "$WORK/default-root.log")" -eq 3 ]
if find "$PROFILE/build/check-fixture" -type f -perm /111 -print -quit | grep .; then
    echo "check-contract: check produced an executable root artifact" >&2
    exit 1
fi

LIB_TARGET="$WORK/lib-target"
: >"$LOG"
"$LORRY" check --lib --quiet --manifest-path "$PROJECT/Cargo.toml" \
    --target-dir "$LIB_TARGET"
[ "$(grep -Fc '<src/lib.rs>' "$LOG")" -eq 1 ]
if grep -F '<src/bin/' "$LOG" >/dev/null; then
    echo "check-contract: --lib selected a binary" >&2
    exit 1
fi

: >"$LOG"
"$LORRY" check --all-targets --keep-going --quiet \
    --manifest-path "$PROJECT/Cargo.toml" --target-dir "$TARGET"
[ "$(grep -Fc '<src/lib.rs>' "$LOG")" -eq 2 ]
[ "$(grep -Fc '<src/bin/first.rs>' "$LOG")" -eq 2 ]
[ "$(grep -Fc '<src/bin/second.rs>' "$LOG")" -eq 2 ]
[ "$(grep -Fc '<tests/integration.rs>' "$LOG")" -eq 1 ]

touch "$PROFILE/successful-profile"
printf 'fn main() { compile_error!("first check failure"); }\n' \
    >"$PROJECT/src/bin/first.rs"
printf 'fn main() { compile_error!("second check failure"); }\n' \
    >"$PROJECT/src/bin/second.rs"
: >"$LOG"
if "$LORRY" check --bins --manifest-path "$PROJECT/Cargo.toml" \
    --target-dir "$TARGET" >"$WORK/fail-fast.out" 2>"$WORK/fail-fast.err"; then
    echo "check-contract: failing check succeeded" >&2
    exit 1
else
    status="$?"
fi
[ "$status" -eq 101 ]
grep -F 'first check failure' "$WORK/fail-fast.err" >/dev/null
if grep -F '<src/bin/second.rs>' "$LOG" >/dev/null; then
    echo "check-contract: check continued without --keep-going" >&2
    exit 1
fi
[ -f "$PROFILE/successful-profile" ]

: >"$LOG"
if "$LORRY" check --bins --keep-going --manifest-path "$PROJECT/Cargo.toml" \
    --target-dir "$TARGET" >"$WORK/keep-going.out" 2>"$WORK/keep-going.err"; then
    echo "check-contract: failing keep-going check succeeded" >&2
    exit 1
else
    status="$?"
fi
[ "$status" -eq 101 ]
grep -F 'first check failure' "$WORK/keep-going.err" >/dev/null
grep -F 'second check failure' "$WORK/keep-going.err" >/dev/null
grep -F '<src/bin/first.rs>' "$LOG" >/dev/null
grep -F '<src/bin/second.rs>' "$LOG" >/dev/null
[ -f "$PROFILE/successful-profile" ]

(
    cd "$PROJECT"
    "$LORRY" --quiet clean --target-dir "$TARGET"
)
[ ! -e "$TARGET/lorry" ]

echo "PASS: check selects root targets, links none, and honors keep-going"
