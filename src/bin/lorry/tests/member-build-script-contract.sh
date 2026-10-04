#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

LORRY="$(realpath "${1:?usage: member-build-script-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
export RUSTC="$LORRY_TEST_RUSTC"
export PATH="$(dirname "$RUSTC"):$PATH"
WORK="$(mktemp -d /tmp/lorry-member-script-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/home/.config/lorry" "$WORK/project"/{a,b,builder}/src
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" \
    >"$WORK/home/.config/lorry/lorry.toml"
cat >"$WORK/project/Cargo.toml" <<'EOF'
[workspace]
members = ["a", "b", "builder"]
default-members = ["a", "b"]
resolver = "2"
EOF
for member in a b builder; do
    printf '[package]\nname = "%s"\nversion = "1.0.0"\nedition = "2024"\n' "$member" \
        >"$WORK/project/$member/Cargo.toml"
done
cat >>"$WORK/project/builder/Cargo.toml" <<'EOF'
[features]
build = []
EOF
cat >"$WORK/project/builder/src/lib.rs" <<'EOF'
pub fn value() -> &'static str { if cfg!(feature = "build") { "host" } else { "target" } }
EOF
for member in a b; do
    cat >>"$WORK/project/$member/Cargo.toml" <<'EOF'
[build-dependencies]
builder = { path = "../builder", features = ["build"] }
EOF
    cat >"$WORK/project/$member/build.rs" <<'EOF'
fn main() {
    assert_eq!(option_env!("CARGO_PRIMARY_PACKAGE"), Some("1"));
    assert!(std::env::var_os("CARGO_PRIMARY_PACKAGE").is_none());
    assert_eq!(builder::value(), "host");
    let value = std::env::var("SCRIPT_INPUT").unwrap_or_else(|_| "absent".into());
    std::fs::write(std::path::Path::new(&std::env::var_os("OUT_DIR").unwrap()).join("generated.rs"), format!("{value:?}")).unwrap();
    println!("cargo:rustc-cfg=scripted");
    println!("cargo:rustc-check-cfg=cfg(scripted)");
    println!("cargo:rustc-env=FROM_SCRIPT=present");
    println!("cargo:rustc-link-arg=-Wl,--gc-sections");
    println!("cargo:rustc-link-arg=-Wl,--as-needed");
    println!("cargo:rerun-if-env-changed=SCRIPT_INPUT");
}
EOF
    cat >"$WORK/project/$member/src/main.rs" <<'EOF'
#[cfg(not(scripted))]
compile_error!("missing member script cfg");
#[deprecated(note = "member script diagnostic")]
fn warning_marker() {}
fn main() {
    warning_marker();
    assert_eq!(env!("FROM_SCRIPT"), "present");
    println!("{}", include!(concat!(env!("OUT_DIR"), "/generated.rs")));
}
EOF
done
cat >"$WORK/project/a/src/lib.rs" <<'EOF'
#[cfg(not(scripted))]
compile_error!("missing member script library cfg");
pub const VALUE: &str = include!(concat!(env!("OUT_DIR"), "/generated.rs"));
EOF
cat >"$WORK/project/lorry.toml" <<'EOF'
config-version = 1
[policy.rules.a]
action = "allow"
name = "a"
source = "path"
allow-build-script = true
caller-env = ["SCRIPT_INPUT"]
[policy.rules.b]
action = "allow"
name = "b"
source = "path"
allow-build-script = true
caller-env = ["SCRIPT_INPUT"]
EOF
cd "$WORK/project"
"$LORRY_TEST_CARGO" generate-lockfile --offline
cp lorry.toml "$WORK/grants.toml"
sed -i 's/name = "a"/name = "ungranted-a"/' lorry.toml
if env HOME="$WORK/home" "$LORRY" build --message-format=json >"$WORK/denied.json" 2>"$WORK/denied.err"; then exit 1; fi
rg -F 'build script without an explicit matching policy grant' "$WORK/denied.err" >/dev/null
[ ! -d target/lorry/debug/build/a ]
python3 - "$WORK/denied.json" <<'PY'
import json, sys
assert [json.loads(line) for line in open(sys.argv[1])] == [{'reason': 'build-finished', 'success': False}]
PY
cp "$WORK/grants.toml" lorry.toml
for command in build check; do
    for selection in defaults all single; do
        arguments=()
        binaries=(a b)
        if [ "$selection" = all ]; then arguments=(--workspace); fi
        if [ "$selection" = single ]; then arguments=(-p a); binaries=(a); fi
        env HOME="$WORK/home" SCRIPT_INPUT=visible "$LORRY" "$command" -j1 "${arguments[@]}" \
            --message-format=json >"$WORK/lorry-$command-$selection.json"
        SCRIPT_INPUT=visible "$LORRY_TEST_CARGO" "$command" -j1 "${arguments[@]}" \
            --offline --message-format=json >"$WORK/cargo-$command-$selection.json"
        if [ "$command" = build ]; then
            for member in "${binaries[@]}"; do
                cmp "target/debug/$member" "target/lorry/debug/$member"
                [ "$("target/lorry/debug/$member")" = visible ]
            done
        fi
        comparison=differential-success-messages
        if [ "$command" = check ]; then comparison=differential-check-messages; fi
        "$LORRY_TEST_CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" \
            --locked --offline -- "$comparison" \
            "$WORK/lorry-$command-$selection.json" "$WORK/cargo-$command-$selection.json"
    done
done
env HOME="$WORK/home" SCRIPT_INPUT=visible "$LORRY" clippy -p a -j1 --message-format=json >"$WORK/lorry-clippy.json"
SCRIPT_INPUT=visible "$LORRY_TEST_CARGO" clippy -p a -j1 --offline --message-format=json >"$WORK/cargo-clippy.json"
"$LORRY_TEST_CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" \
    --locked --offline -- differential-check-messages "$WORK/lorry-clippy.json" "$WORK/cargo-clippy.json"
# A grant for a does not expose its caller variable to b.
sed -i '/\[policy.rules.b\]/,$ {/caller-env/d;}' lorry.toml
env HOME="$WORK/home" SCRIPT_INPUT=private-marker "$LORRY" build -j1 2>"$WORK/hidden.err"
[ "$(target/lorry/debug/a)" = private-marker ]
[ "$(target/lorry/debug/b)" = absent ]
rg -F 'hidden caller variable `SCRIPT_INPUT`' "$WORK/hidden.err" >/dev/null
if rg -F private-marker "$WORK/hidden.err"; then exit 1; fi
echo "PASS: selected member scripts match Cargo binaries and JSON with package-specific caller grants"
