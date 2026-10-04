#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

LORRY="$(realpath "${1:?usage: member-proc-macro-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
export RUSTC="$LORRY_TEST_RUSTC"
WORK="$(mktemp -d /tmp/lorry-member-macro-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/home/.config/lorry" "$WORK/project"/{app,derive,helper}/src "$WORK/project/.cargo"
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" >"$WORK/home/.config/lorry/lorry.toml"
cat >"$WORK/project/Cargo.toml" <<'EOF'
[workspace]
members = ["app", "derive", "helper"]
default-members = ["app", "derive"]
resolver = "2"
EOF
for member in app derive helper; do
    printf '[package]\nname = "%s"\nversion = "1.0.0"\nedition = "2024"\n' "$member" >"$WORK/project/$member/Cargo.toml"
done
cat >>"$WORK/project/derive/Cargo.toml" <<'EOF'
[lib]
proc-macro = true
[dependencies]
helper = { path = "../helper", features = ["host"] }
EOF
cat >>"$WORK/project/app/Cargo.toml" <<'EOF'
[dependencies]
derive = { path = "../derive" }
helper = { path = "../helper", features = ["target"] }
EOF
cat >>"$WORK/project/helper/Cargo.toml" <<'EOF'
[features]
host = []
target = []
EOF
cat >"$WORK/project/helper/src/lib.rs" <<'EOF'
#[cfg(feature = "host")]
pub fn expansion() -> &'static str { "41" }
#[cfg(feature = "target")]
pub fn value() -> u32 { 1 }
EOF
cat >"$WORK/project/derive/src/lib.rs" <<'EOF'
extern crate proc_macro;
#[proc_macro]
pub fn answer(_: proc_macro::TokenStream) -> proc_macro::TokenStream {
    helper::expansion().parse().unwrap()
}
EOF
cat >"$WORK/project/app/src/main.rs" <<'EOF'
fn main() { println!("{}", derive::answer!() + helper::value()); }
EOF
printf '[target.x86_64-unknown-motor]\nlinker = "%s"\nrustflags = ["--sysroot=%s"]\n' \
    "$LORRY_MOTOR_LINKER" "$LORRY_MOTOR_SYSROOT" >"$WORK/project/.cargo/config.toml"
cat >"$WORK/project/lorry.toml" <<'EOF'
config-version = 1
[policy.rules.member-macro]
action = "allow"
name = "derive"
source = "path"
allow-proc-macro = true
EOF
cd "$WORK/project"
"$LORRY_TEST_CARGO" generate-lockfile --offline
cp lorry.toml "$WORK/grant.toml"
sed -i 's/name = "derive"/name = "ungranted"/' lorry.toml
if env HOME="$WORK/home" "$LORRY" build -p derive >"$WORK/denied.out" 2>"$WORK/denied.err"; then exit 1; fi
rg -F 'procedural macro without an explicit matching policy grant' "$WORK/denied.err" >/dev/null
[ ! -d target/lorry/debug/deps ]
cp "$WORK/grant.toml" lorry.toml
for platform in native motor native-release motor-release; do
    target=()
    release=()
    profile=debug
    if [[ "$platform" = motor* ]]; then target=(--target x86_64-unknown-motor); profile=x86_64-unknown-motor/debug; fi
    if [[ "$platform" = *-release ]]; then release=(--release); profile="${profile%debug}release"; fi
    for command in build check; do
        for selection in defaults all macro; do
            packages=()
            if [ "$selection" = all ]; then packages=(--workspace); fi
            if [ "$selection" = macro ]; then packages=(-p derive); fi
            stem="$platform-$command-$selection"
            env HOME="$WORK/home" "$LORRY" "$command" -j1 "${target[@]}" "${release[@]}" "${packages[@]}" \
                --message-format=json >"$WORK/lorry-$stem.json"
            "$LORRY_TEST_CARGO" "$command" -j1 "${target[@]}" "${release[@]}" "${packages[@]}" \
                --offline --message-format=json >"$WORK/cargo-$stem.json"
            if [ "$command" = build ]; then
                if [ "$selection" != macro ]; then cmp "target/$profile/app" "target/lorry/$profile/app"; fi
                python3 - "$WORK/lorry-$stem.json" "$WORK/cargo-$stem.json" <<'PY'
import json, pathlib, sys
def macro_files(filename):
    return [path for line in open(filename) for event in [json.loads(line)]
            if event['reason'] == 'compiler-artifact' and event['target']['kind'] == ['proc-macro']
            for path in event['filenames']]
lorry, cargo = map(macro_files, sys.argv[1:])
assert len(lorry) == len(cargo) and lorry, (lorry, cargo)
assert sorted(pathlib.Path(path).read_bytes() for path in lorry) == \
       sorted(pathlib.Path(path).read_bytes() for path in cargo), (lorry, cargo)
PY
            fi
            comparison=differential-workspace-messages
            if [ "$command" = check ]; then comparison=differential-workspace-check-messages; fi
            "$LORRY_TEST_CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" \
                --locked --offline -- "$comparison" "$WORK/lorry-$stem.json" "$WORK/cargo-$stem.json"
        done
    done
done
[ "$(target/lorry/debug/app)" = 42 ]
echo "PASS: selected member macros match Cargo host/cross bytes and JSON"
