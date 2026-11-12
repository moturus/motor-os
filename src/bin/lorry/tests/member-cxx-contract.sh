#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

LORRY="$(realpath "${1:?usage: member-cxx-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
export RUSTC="$LORRY_TEST_RUSTC"
export PATH="$(dirname "$RUSTC"):$PATH"
HOST_CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
WORK="$(mktemp -d /tmp/lorry-member-cxx-contract-XXXXXX)"
cleanup() {
    status=$?
    if [ "$status" -eq 0 ]; then rm -rf "$WORK"; else echo "Retained C++ fixture: $WORK" >&2; fi
}
trap cleanup EXIT
mkdir -p "$WORK/home/.config/lorry" "$WORK/project/grammar/src" "$WORK/project/.cargo"
cat >"$WORK/project/Cargo.toml" <<'EOF'
[workspace]
members = ["grammar"]
resolver = "2"
EOF
cat >"$WORK/project/grammar/Cargo.toml" <<'EOF'
[package]
name = "grammar"
version = "1.0.0"
edition = "2024"
[build-dependencies]
cc = "=1.2.29"
EOF
cat >"$WORK/project/grammar/src/main.rs" <<'EOF'
unsafe extern "C" { fn grammar_scanner() -> i32; }
fn main() { assert_eq!(unsafe { grammar_scanner() }, include!(concat!(env!("OUT_DIR"), "/generated.rs"))); }
EOF
printf '#define GRAMMAR_VALUE 42\n' >"$WORK/project/grammar/scanner.h"
cat >"$WORK/project/grammar/scanner.cc" <<'EOF'
#include "scanner.h"
namespace grammar { constexpr int value = GRAMMAR_VALUE; }
extern "C" int grammar_scanner() { return grammar::value; }
EOF
cat >"$WORK/project/grammar/build.rs" <<'EOF'
fn main() {
    let target = std::env::var("TARGET").unwrap().replace(['-', '.'], "_");
    assert_eq!(std::env::var(format!("CXXSTDLIB_{target}")).unwrap(), "");
    std::fs::write(std::path::Path::new(&std::env::var_os("OUT_DIR").unwrap()).join("generated.rs"), "42").unwrap();
    println!("cargo:rerun-if-changed=scanner.cc");
    println!("cargo:rerun-if-changed=scanner.h");
    cc::Build::new().cpp(true).warnings(false).include(".").file("scanner.cc")
        .compile("helix_grammar_fixture_scanner");
}
EOF
# Use the same compiler and archiver environment for Cargo and Lorry.
HOST_CXX="$(realpath /usr/bin/clang++)"
HOST_AR="$(realpath "$(dirname "$HOST_CXX")/llvm-ar")"
# A compiler installation outside the built-in system and Rust paths needs
# both execution and read access to its own resources. Include a space too.
mkdir -p "$WORK/native tools/bin" "$WORK/native tools/include"
printf '#define CUSTOM_COMPILER_HEADER 1\n' >"$WORK/native tools/include/compiler.h"
cat >"$WORK/native tools/bin/custom-c++" <<EOF
#!/bin/sh
exec "$HOST_CXX" -include "$WORK/native tools/include/compiler.h" "\$@"
EOF
chmod +x "$WORK/native tools/bin/custom-c++"
HOST_CXX="$WORK/native tools/bin/custom-c++"
SDK_ROOT="$(dirname "$(dirname "$LORRY_MOTOR_LINKER")")"
# The Clang that the toolchain's motor-clang++ wrapper runs.
MOTOR_LLVM="$("$RUSTC" --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin"
MOTOR_CXX="$(realpath "$MOTOR_LLVM/clang")"
MOTOR_AR="$(realpath "$MOTOR_LLVM/llvm-ar")"
cat >"$WORK/project/.cargo/config.toml" <<EOF
[target.x86_64-unknown-motor]
linker = "$LORRY_MOTOR_LINKER"
rustflags = ["--sysroot", "$LORRY_MOTOR_SYSROOT"]
EOF
"$SCRIPT_DIR/approve-cargo-config.sh" "$WORK/home" "$WORK/project" "$WORK/project/.cargo/config.toml"
cd "$WORK/project"
"$LORRY_TEST_CARGO" generate-lockfile --offline
"$RUSTC" --edition=2024 -D warnings -O "$SCRIPT_DIR/helpers/cache-curl.rs" -o "$WORK/cache-curl"
"$WORK/cache-curl" prepare "$HOST_CARGO_HOME" "$WORK/crates-io" Cargo.lock
cat >"$WORK/home/.config/lorry/lorry.toml" <<EOF
config-version = 1
use-cargo-registry = false
[repositories]
user = "$WORK/repository"
[network]
curl = "$WORK/crates-io/curl"
[cache]
directory = "$WORK/cache"
[policy]
default = "allow"
[workspaces."$WORK/project".policy.rules.grammar]
action = "allow"
name = "grammar"
source = "path"
allow-build-script = true
EOF
env HOME="$WORK/home" "$LORRY" vendor --locked --accept-all
# Compiler selection is supplied by the caller, without tool grants.
for target in x86_64-unknown-linux-gnu x86_64-unknown-motor; do
    compiler="$HOST_CXX"; archiver="$HOST_AR"; flags=()
    if [ "$target" = x86_64-unknown-motor ]; then
        compiler="$MOTOR_CXX"; archiver="$MOTOR_AR"
        flags=(--no-default-config "--sysroot=$SDK_ROOT" --target=x86_64-unknown-motor -D_GNU_SOURCE -D_DEFAULT_SOURCE)
    fi
    suffix="${target//-/_}"
    env HOME="$WORK/home" "CXX_$suffix=$compiler" "CXXFLAGS_$suffix=${flags[*]}" "CXXSTDLIB_$suffix=" "AR_$suffix=$archiver" "$LORRY" build --target "$target" -j1 --message-format=json >"$WORK/lorry-$target.json"
    env "CXX_$suffix=$compiler" "CXXFLAGS_$suffix=${flags[*]}" "CXXSTDLIB_$suffix=" "AR_$suffix=$archiver" \
        "$LORRY_TEST_CARGO" build --target "$target" -j1 --locked --offline --message-format=json >"$WORK/cargo-$target.json"
    cmp "target/lorry/$target/debug/grammar" "target/$target/debug/grammar"
    # The same verified registry sources live in different physical caches.
    python3 - "$WORK/lorry-$target.json" "$WORK/cargo-$target.json" "$WORK/cargo-view-$target.json" <<'PY'
import json, sys
lorry = [json.loads(line) for line in open(sys.argv[1])]
paths = {m['package_id']: m['target']['src_path'] for m in lorry
         if m['reason'] == 'compiler-artifact' and m['package_id'].startswith('registry+')}
assert len(paths) == 2
with open(sys.argv[3], 'w') as output:
    for line in open(sys.argv[2]):
        message = json.loads(line)
        if message.get('package_id') in paths and 'target' in message:
            assert message['target']['src_path'].endswith('/src/lib.rs')
            message['target']['src_path'] = paths[message['package_id']]
        output.write(json.dumps(message) + '\n')
PY
    "$LORRY_TEST_CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" \
        --locked --offline -- differential-script-clean-messages "$WORK/lorry-$target.json" "$WORK/cargo-view-$target.json"
done
target/lorry/x86_64-unknown-linux-gnu/debug/grammar
# Resolve the same compiler through PATH as well as the absolute CXX above.
mkdir -p "$WORK/tool-shims"
ln -s "$HOST_CXX" "$WORK/tool-shims/custom-c++"
env HOME="$WORK/home" PATH="$WORK/tool-shims:$PATH" \
    CXX_x86_64_unknown_linux_gnu=custom-c++ CXXSTDLIB_x86_64_unknown_linux_gnu= \
    AR_x86_64_unknown_linux_gnu="$HOST_AR" \
    "$LORRY" run --target x86_64-unknown-linux-gnu -j1 --offline
echo "PASS: compiler environment drives cc-rs C++ builds matching Cargo natively and for Motor"
