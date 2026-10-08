#!/usr/bin/env bash
# Like Cargo, a library's dependent that reads only its metadata starts while
# the library's code generation continues, and a binary waits for the whole
# library. An interrupted in-place compile is rebuilt by the next build.
set -euo pipefail
export CARGO_NET_OFFLINE=true

LORRY="$(realpath "${1:?usage: pipelining-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${LORRY_TEST_RUSTC:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
WORK="$(mktemp -d /tmp/lorry-pipelining-contract-XXXXXX)"
trap 'status=$?; if [ "$status" = 0 ]; then rm -rf "$WORK"; else echo "Retained failed fixture: $WORK" >&2; fi' EXIT
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME:?}/.rustup}"
export CARGO_HOME="${CARGO_HOME:-${HOME:?}/.cargo}"
mkdir -p "$WORK/home/.config/lorry" "$WORK/project"/{app,base,middle}/src
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" \
    >"$WORK/home/.config/lorry/lorry.toml"
cd "$WORK/project"
printf '[workspace]\nmembers = ["app", "base", "middle"]\nresolver = "2"\n' >Cargo.toml
printf '[package]\nname = "base"\nversion = "0.1.0"\nedition = "2024"\n' >base/Cargo.toml
printf 'pub fn value() -> u32 { 1 }\n' >base/src/lib.rs
printf '[package]\nname = "middle"\nversion = "0.1.0"\nedition = "2024"\n[dependencies]\nbase = { path = "../base" }\n' \
    >middle/Cargo.toml
printf 'pub fn value() -> u32 { base::value() + 1 }\n' >middle/src/lib.rs
printf '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2024"\n[dependencies]\nmiddle = { path = "../middle" }\n' \
    >app/Cargo.toml
printf 'fn main() { println!("{}", middle::value()); }\n' >app/src/main.rs
"$LORRY_TEST_CARGO" generate-lockfile --offline

# Logs when each compile starts and ends. While $LINGER exists, base's compile
# lingers after rustc exits, as a long code generation would: until middle has
# started if $LINGER says so, otherwise until $LINGER is removed. Without
# pipelining middle cannot start first, and base gives up after 60 s.
cat >"$WORK/rustc-wrapper" <<'EOF'
#!/usr/bin/env bash
crate=query
for ((i = 1; i < $#; i++)); do
    if [ "${!i}" = --crate-name ]; then
        next=$((i + 1))
        crate="${!next}"
    fi
done
printf 'start %s %s\n' "$crate" "$(date +%s%N)" >>"$EVENTS"
status=0
"$REAL_RUSTC" "$@" || status=$?
if [ "$crate" = base ]; then
    for _ in $(seq 600); do
        [ -e "$LINGER" ] || break
        if [ "$(cat "$LINGER")" = middle ] && grep -q '^start middle ' "$EVENTS"; then break; fi
        sleep 0.1
    done
fi
printf 'end %s %s\n' "$crate" "$(date +%s%N)" >>"$EVENTS"
exit "$status"
EOF
chmod +x "$WORK/rustc-wrapper"
export HOME="$WORK/home" RUSTC="$WORK/rustc-wrapper" REAL_RUSTC="$LORRY_TEST_RUSTC"
export EVENTS="$WORK/events" LINGER="$WORK/linger"

fail() {
    echo "pipelining-contract: $*" >&2
    exit 1
}
event() {
    awk -v kind="$1" -v crate="$2" '$1 == kind && $2 == crate { print $3; exit }' "$EVENTS"
}
compiled() {
    grep -q "^start $1 " "$EVENTS"
}

echo middle >"$LINGER"
"$LORRY" build -j2 >"$WORK/build.log" 2>&1 || { cat "$WORK/build.log"; fail "build failed"; }
[ "$(target/lorry/debug/app)" = 2 ] || fail "app printed the wrong value"
[ "$(event start middle)" -lt "$(event end base)" ] || fail "middle waited for base's code generation"
[ "$(event start app)" -gt "$(event end base)" ] || fail "app started before base was complete"
[ "$(event start app)" -gt "$(event end middle)" ] || fail "app started before middle was complete"

rm "$LINGER"
: >"$EVENTS"
"$LORRY" build -j2 >/dev/null 2>&1
for crate in base middle app; do
    if compiled "$crate"; then fail "an unchanged build compiled $crate"; fi
done

# Killed after base's rustc wrote its outputs in place, before Lorry recorded
# them: the next build compiles base again.
printf '// edited\n' >>base/src/lib.rs
echo killed >"$LINGER"
: >"$EVENTS"
"$LORRY" build -j2 >/dev/null 2>&1 &
lorry_pid=$!
until grep -q '^start middle ' "$EVENTS"; do
    kill -0 "$lorry_pid" 2>/dev/null || fail "the build ended before middle started"
    sleep 0.05
done
kill -KILL "$lorry_pid"
wait "$lorry_pid" 2>/dev/null || true
rm "$LINGER"
: >"$EVENTS"
"$LORRY" build -j2 >"$WORK/recovered.log" 2>&1 || { cat "$WORK/recovered.log"; fail "recovery build failed"; }
compiled base || fail "an interrupted in-place compile was reused"
[ "$(target/lorry/debug/app)" = 2 ] || fail "app printed the wrong value after recovery"

echo "PASS: dependents start on library metadata, binaries wait for whole libraries, and interrupted libraries rebuild"
