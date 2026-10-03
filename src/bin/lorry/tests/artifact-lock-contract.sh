#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: artifact-lock-contract.sh LORRY" >&2
    exit 2
fi
LORRY="$(realpath "$1")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${LORRY_TEST_RUSTC:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
export RUSTC="$LORRY_TEST_RUSTC"
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME:?}/.rustup}"
WORK="$(mktemp -d /tmp/lorry-artifact-lock-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/home/.config/lorry" "$WORK/src" "$WORK/tests"
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" \
    >"$WORK/home/.config/lorry/lorry.toml"
export HOME="$WORK/home"
cat >"$WORK/Cargo.toml" <<'EOF'
[package]
name = "artifact-lock-fixture"
version = "0.1.0"
edition = "2024"
EOF
cat >"$WORK/Cargo.lock" <<'EOF'
version = 4
[[package]]
name = "artifact-lock-fixture"
version = "0.1.0"
EOF
cat >"$WORK/src/main.rs" <<'EOF'
fn main() {
    let lorry = std::env::var_os("LORRY_NESTED").unwrap();
    assert!(std::process::Command::new(lorry).arg("build").status().unwrap().success());
}
EOF
cat >"$WORK/tests/integration.rs" <<'EOF'
#[test]
fn starts_another_build() {
    let lorry = std::env::var_os("LORRY_NESTED").unwrap();
    assert!(std::process::Command::new(lorry).arg("build").status().unwrap().success());
}
EOF

(
    cd "$WORK"
    LORRY_NESTED="$LORRY" timeout 90 "$LORRY" run
    LORRY_NESTED="$LORRY" timeout 90 "$LORRY" test --test integration
    test -f target/.lorry-artifacts.lock
    "$LORRY" clean
    test -f target/.lorry-artifacts.lock
    test ! -e target/lorry
)

# Killing Lorry must leave its active compiler holding the child lease. The
# next build waits for that writer, then reconstructs the interrupted unit.
cat >"$WORK/rustc-wrapper" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
for argument in "$@"; do
    if [ "$argument" = "--crate-name" ] && [ -e "$BLOCK_FILE" ]; then
        if [ -e "$ENTERED_FILE" ]; then
            : >"$SECOND_ENTERED_FILE"
        else
            : >"$ENTERED_FILE"
        fi
        while [ ! -e "$RELEASE_FILE" ]; do /bin/sleep 0.02; done
        break
    fi
done
exec "$REAL_RUSTC" "$@"
EOF
chmod 700 "$WORK/rustc-wrapper"
printf 'fn main() {}\n' >"$WORK/src/main.rs"
export REAL_RUSTC="$RUSTC"
export BLOCK_FILE="$WORK/block" ENTERED_FILE="$WORK/entered" \
    SECOND_ENTERED_FILE="$WORK/second-entered" RELEASE_FILE="$WORK/release"
(
    cd "$WORK"
    RUSTC="$WORK/rustc-wrapper" "$LORRY" build
)
printf 'fn main() { println!("recovered"); }\n' >"$WORK/src/main.rs"
: >"$BLOCK_FILE"
(
    cd "$WORK"
    exec env RUSTC="$WORK/rustc-wrapper" "$LORRY" build
) >"$WORK/killed.log" 2>&1 &
killed="$!"
for attempt in $(seq 1 250); do
    [ ! -e "$ENTERED_FILE" ] || break
    /bin/sleep 0.02
done
[ -e "$ENTERED_FILE" ] || {
    cat "$WORK/killed.log" >&2
    echo "artifact-lock-contract: compiler did not enter the controlled build" >&2
    kill "$killed" 2>/dev/null || true
    exit 1
}
kill -KILL "$killed"
wait "$killed" 2>/dev/null || true
test -f "$WORK/target/lorry/debug/artifact-lock-fixture"
staging_parent="$WORK/target/lorry/debug/build/artifact-lock-fixture"
test -n "$(find "$staging_parent" -maxdepth 1 -type d -name '.*.lorry-staging-*' -print -quit)"
(
    cd "$WORK"
    exec env RUSTC="$WORK/rustc-wrapper" "$LORRY" build
) >"$WORK/recovered.log" 2>&1 &
recovered="$!"
/bin/sleep 0.1
test ! -e "$SECOND_ENTERED_FILE"
: >"$RELEASE_FILE"
wait "$recovered"
test "$("$WORK/target/lorry/debug/artifact-lock-fixture")" = recovered
test -z "$(find "$staging_parent" -maxdepth 1 -type d -name '.*.lorry-staging-*' -print -quit)"
echo "PASS: artifact lock survives clean, releases before programs, and cleans killed builds' staging after children exit"
