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
HOST_CARGO_HOME="${CARGO_HOME:-${HOME:?}/.cargo}"
HOME_DIR="$WORK/home"
PROJECT="$WORK/project"
DEPENDENCY="$WORK/dependency"
LOG="$WORK/rustc.log"
mkdir -p "$HOME_DIR/.config/lorry" "$PROJECT/src/bin" "$PROJECT/tests" \
    "$DEPENDENCY/src"
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" \
    >"$HOME_DIR/.config/lorry/lorry.toml"
printf '%s\n' \
    'config-version = 1' \
    '[policy.rules.allow-fixture-dependency]' \
    'action = "allow"' \
    'name = "fixture-dependency"' \
    'version = "=1.0.0"' \
    'source = "path"' \
    'license = "MIT"' \
    'allow-build-script = true' \
    >"$PROJECT/lorry.toml"

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
    'license = "MIT"' \
    'build = "build.rs"' \
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
printf '%s\n' \
    'fn main() {' \
    '    let out = std::env::var_os("OUT_DIR").unwrap();' \
    '    std::fs::write(std::path::Path::new(&out).join("generated.rs"), "pub const VALUE: u8 = 42;\n").unwrap();' \
    '    println!("cargo:rustc-check-cfg=cfg(generated_fixture)");' \
    '    println!("cargo:rustc-cfg=generated_fixture");' \
    '    println!("cargo:rustc-env=GENERATED_FIXTURE=enabled");' \
    '    println!("cargo:rerun-if-changed=build.rs");' \
    '}' >"$DEPENDENCY/build.rs"
printf '%s\n' \
    '#[cfg(generated_fixture)]' \
    'include!(concat!(env!("OUT_DIR"), "/generated.rs"));' \
    >"$DEPENDENCY/src/lib.rs"
printf '%s\n' \
    '#[deprecated]' \
    'pub fn old_value() -> u8 { fixture_dependency::VALUE }' \
    'pub fn value() -> u8 { fixture_dependency::VALUE }' \
    >"$PROJECT/src/lib.rs"
printf 'fn main() { assert_eq!(check_fixture::old_value(), 42); }\n' \
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
if [ -n "${LORRY_CHECK_PAUSE_FILE:-}" ]; then
    for argument in "$@"; do
        if [ "$argument" = "src/lib.rs" ]; then
            : >"$LORRY_CHECK_PAUSE_FILE"
            exec /bin/sleep 30
        fi
    done
fi
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

SCHEMA_MANIFEST="$SCRIPT_DIR/metadata-schema/Cargo.toml"
JSON_TARGET="$WORK/json-target"
"$LORRY" metadata --format-version 1 --manifest-path "$PROJECT/Cargo.toml" \
    >"$WORK/metadata.json"
"$LORRY" check --all-targets --keep-going --quiet --message-format=json \
    --manifest-path "$PROJECT/Cargo.toml" --target-dir "$JSON_TARGET" \
    >"$WORK/messages.json" 2>"$WORK/messages.err"
CARGO_HOME="$HOST_CARGO_HOME" "$LORRY_TEST_CARGO" run \
    --manifest-path "$SCHEMA_MANIFEST" --locked --offline --quiet \
    -- messages "$WORK/messages.json" "$WORK/metadata.json" success plain any
"$LORRY" check --all-targets --keep-going --quiet \
    --message-format=json-diagnostic-rendered-ansi \
    --manifest-path "$PROJECT/Cargo.toml" --target-dir "$JSON_TARGET" \
    >"$WORK/messages-ansi.json" 2>"$WORK/messages-ansi.err"
CARGO_HOME="$HOST_CARGO_HOME" "$LORRY_TEST_CARGO" run \
    --manifest-path "$SCHEMA_MANIFEST" --locked --offline --quiet \
    -- messages "$WORK/messages-ansi.json" "$WORK/metadata.json" success ansi fresh

touch "$PROFILE/successful-profile"
export LORRY_CHECK_PAUSE_FILE="$WORK/check-paused"
setsid "$LORRY" check --lib --quiet --message-format=json \
    --manifest-path "$PROJECT/Cargo.toml" --target-dir "$TARGET" \
    >"$WORK/killed.out" 2>"$WORK/killed.err" &
check_pid="$!"
for _ in {1..250}; do
    [ -e "$LORRY_CHECK_PAUSE_FILE" ] && break
    /bin/sleep 0.02
done
if [ ! -e "$LORRY_CHECK_PAUSE_FILE" ]; then
    kill -TERM -- "-$check_pid" 2>/dev/null || true
    wait "$check_pid" 2>/dev/null || true
    echo "check-contract: check did not reach the cancellation point" >&2
    exit 1
fi
kill -TERM -- "-$check_pid"
if wait "$check_pid"; then
    echo "check-contract: killed check succeeded" >&2
    exit 1
else
    status="$?"
fi
[ "$status" -eq 143 ]
unset LORRY_CHECK_PAUSE_FILE
[ -f "$PROFILE/successful-profile" ]
if grep -F '"reason":"build-finished"' "$WORK/killed.out" >/dev/null; then
    echo "check-contract: killed check emitted build-finished" >&2
    exit 1
fi

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

if "$LORRY" check --bins --keep-going --quiet --message-format=json \
    --manifest-path "$PROJECT/Cargo.toml" --target-dir "$JSON_TARGET" \
    >"$WORK/messages-failure.json" 2>"$WORK/messages-failure.err"; then
    echo "check-contract: failing JSON check succeeded" >&2
    exit 1
else
    status="$?"
fi
[ "$status" -eq 101 ]
CARGO_HOME="$HOST_CARGO_HOME" "$LORRY_TEST_CARGO" run \
    --manifest-path "$SCHEMA_MANIFEST" --locked --offline --quiet \
    -- messages "$WORK/messages-failure.json" "$WORK/metadata.json" failure plain fresh

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
