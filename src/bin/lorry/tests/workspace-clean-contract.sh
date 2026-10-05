#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true
LORRY="$(realpath "${1:?usage: workspace-clean-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
export RUSTC="$LORRY_TEST_RUSTC"
WORK="$(mktemp -d /tmp/lorry-workspace-clean-XXXXXX)"
trap 'status=$?; if [ "$status" = 0 ]; then rm -rf "$WORK"; else echo "Retained clean fixture: $WORK" >&2; fi' EXIT
mkdir -p "$WORK/home" "$WORK/project"/{one,two,dep}/src
cat >"$WORK/project/Cargo.toml" <<'EOF'
[workspace]
members = ["one", "two"]
exclude = ["dep"]
resolver = "2"
[profile.custom]
inherits = "release"
EOF
for member in one two dep; do
    printf '[package]\nname = "%s"\nversion = "1.0.0"\nedition = "2024"\n' "$member" >"$WORK/project/$member/Cargo.toml"
done
printf 'pub fn value() -> u32 { 42 }\n' >"$WORK/project/dep/src/lib.rs"
for member in one two; do
    printf '[dependencies]\ndep = { path = "../dep" }\n' >>"$WORK/project/$member/Cargo.toml"
    printf 'fn main() { println!("{}", dep::value()); }\n' >"$WORK/project/$member/src/main.rs"
done
cd "$WORK/project"
"$LORRY_TEST_CARGO" generate-lockfile --offline
cp Cargo.lock "$WORK/lock"
for selection in repeated workspace; do
    for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
        directory=cargo-out
        prefix=cargo-out
        if [ "$builder" = "$LORRY" ]; then directory=lorry-out; prefix=lorry-out/lorry; fi
        env HOME="$WORK/home" "$builder" build --workspace --target-dir "$directory"
        env HOME="$WORK/home" "$builder" build --workspace --release --target-dir "$directory"
        packages=(-p one -p two -p one)
        if [ "$selection" = workspace ]; then packages=(--workspace); fi
        env HOME="$WORK/home" "$builder" clean "${packages[@]}" --target-dir "$directory"
        for member in one two; do
            [ ! -e "$prefix/debug/$member" ]
            [ -x "$prefix/release/$member" ]
        done
        [ -d "$prefix/debug/build/dep" ]
        env HOME="$WORK/home" "$builder" clean --workspace --release --target-dir "$directory"
        for member in one two; do [ ! -e "$prefix/release/$member" ]; done
        [ -d "$prefix/release/build/dep" ]
        cmp Cargo.lock "$WORK/lock"
    done
done
# Named clean removes the selected member and preserves other profiles/owners.
for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
    directory=cargo-out
    prefix=cargo-out
    if [ "$builder" = "$LORRY" ]; then directory=lorry-out; prefix=lorry-out/lorry; fi
    env HOME="$WORK/home" "$builder" build --workspace --target-dir "$directory"
    env HOME="$WORK/home" "$builder" build --workspace --profile custom --target-dir "$directory"
    env HOME="$WORK/home" "$builder" clean -p one --profile custom --target-dir "$directory"
    [ ! -e "$prefix/custom/one" ]
    [ -x "$prefix/custom/two" ]
    [ -x "$prefix/debug/one" ]
    [ -x "$prefix/debug/two" ]
    # Build-only deferred settings must not prevent source-only cleanup.
    printf 'rpath = true\n' >>Cargo.toml
    env HOME="$WORK/home" "$builder" clean --profile custom --target-dir "$directory"
    [ ! -e "$prefix/custom" ]
    [ -x "$prefix/debug/two" ]
    sed -i '/^rpath = true$/d' Cargo.toml
    if env HOME="$WORK/home" "$builder" clean --profile missing --target-dir "$directory" 2>"$WORK/missing.err"; then exit 1; fi
    rg -F 'profile `missing` is not defined' "$WORK/missing.err"
    cmp Cargo.lock "$WORK/lock"
done
# An unselected member invocation removes the shared tree, as at the root.
env HOME="$WORK/home" "$LORRY" build --workspace
(cd one; env HOME="$WORK/home" "$LORRY" clean)
[ ! -e target/lorry ]
"$LORRY_TEST_CARGO" build --workspace --offline
(cd one; "$LORRY_TEST_CARGO" clean)
[ ! -e target ]
# Clean needs source descriptions, not a compilable target or a lockfile.
rm Cargo.lock
mkdir -p empty
printf '[workspace]\nmembers = []\n' >empty/Cargo.toml
mkdir -p empty/target/lorry/debug
env HOME="$WORK/home" "$LORRY" clean --workspace --manifest-path empty/Cargo.toml
[ ! -e empty/target/lorry ]
env HOME="$WORK/home" "$LORRY" clean --workspace --target-dir lorry-out
echo "PASS: repeated/workspace clean preserves dependency owners, other profiles, and shared-root behavior"
