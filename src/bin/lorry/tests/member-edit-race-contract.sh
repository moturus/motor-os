#!/usr/bin/env bash
# A member source saved while rustc compiles it may be missing from the
# outputs. Like Cargo, the next build compiles that member again, and its
# dependents too, instead of trusting the record or the cache.
set -euo pipefail
export CARGO_NET_OFFLINE=true

LORRY="$(realpath "${1:?usage: member-edit-race-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${LORRY_TEST_RUSTC:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
WORK="$(mktemp -d /tmp/lorry-member-edit-race-XXXXXX)"
trap 'status=$?; if [ "$status" = 0 ]; then rm -rf "$WORK"; else echo "Retained failed fixture: $WORK" >&2; fi' EXIT
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME:?}/.rustup}"
export CARGO_HOME="${CARGO_HOME:-${HOME:?}/.cargo}"
mkdir -p "$WORK/home/.config/lorry" "$WORK/project"/{app,base}/src
printf 'config-version = 1\nuse-cargo-registry = false\n[cache]\ndirectory = "%s"\n' "$WORK/cache" \
    >"$WORK/home/.config/lorry/lorry.toml"
cd "$WORK/project"
printf '[workspace]\nmembers = ["app", "base"]\nresolver = "2"\n' >Cargo.toml
printf '[package]\nname = "base"\nversion = "0.1.0"\nedition = "2024"\n' >base/Cargo.toml
printf 'pub fn value() -> u32 { 1 }\n' >base/src/lib.rs
printf '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2024"\n[dependencies]\nbase = { path = "../base" }\n' \
    >app/Cargo.toml
printf 'fn main() { println!("{}", base::value()); }\n' >app/src/main.rs
RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" generate-lockfile --offline

# While $EDIT exists, the next compile of base saves its new contents after
# rustc has read the old ones, and logs every compile.
cat >"$WORK/rustc-wrapper" <<'EOF'
#!/usr/bin/env bash
crate=query
for ((i = 1; i < $#; i++)); do
    if [ "${!i}" = --crate-name ]; then
        next=$((i + 1))
        crate="${!next}"
    fi
done
echo "$crate" >>"$EVENTS"
status=0
"$REAL_RUSTC" "$@" || status=$?
if [ "$crate" = base ] && [ -e "$EDIT" ]; then
    cat "$EDIT" >base/src/lib.rs
    rm "$EDIT"
fi
exit "$status"
EOF
chmod +x "$WORK/rustc-wrapper"
export HOME="$WORK/home" RUSTC="$WORK/rustc-wrapper" REAL_RUSTC="$LORRY_TEST_RUSTC"
export EVENTS="$WORK/events" EDIT="$WORK/edit"

fail() {
    echo "member-edit-race-contract: $*" >&2
    exit 1
}

"$LORRY" build -q
[ "$(target/lorry/debug/app)" = 1 ] || fail "the first build printed the wrong value"

printf 'pub fn value() -> u32 { 2 }\n' >"$WORK/edit"
printf '// started\n' >>base/src/lib.rs
"$LORRY" build -q
[ -e "$WORK/edit" ] && fail "the build did not compile base"
: >"$EVENTS"
"$LORRY" build -q
grep -qx base "$EVENTS" || fail "a member edited during its compile was not compiled again"
grep -qx app "$EVENTS" || fail "a dependent of the edited member was not compiled again"
[ "$(target/lorry/debug/app)" = 2 ] || fail "app kept the source from before the edit"

echo "PASS: a member edited during its compile is compiled again with its dependents"
