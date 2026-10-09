#!/usr/bin/env bash
# Build-script metadata reaches dependents as DEP_<LINKS>_<KEY>; rustc-flags
# and rustc-link-arg-bins apply; and a dependency's link search path reaches
# the final link of its dependents, all as under Cargo.
set -euo pipefail
export CARGO_NET_OFFLINE=true

LORRY="$(realpath "${1:?usage: build-script-metadata-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${LORRY_TEST_RUSTC:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
export RUSTC="$LORRY_TEST_RUSTC"
WORK="$(mktemp -d /tmp/lorry-script-metadata-XXXXXX)"
trap 'status=$?; if [ "$status" = 0 ]; then rm -rf "$WORK"; else echo "Retained fixture: $WORK" >&2; fi' EXIT
fail() {
    echo "build-script-metadata-contract: $*" >&2
    exit 1
}

mkdir -p "$WORK/home/.config/lorry" "$WORK/project"/{sys,app}/src
printf 'config-version = 1\nuse-cargo-registry = false\n[cache]\ndirectory = "%s"\n' "$WORK/cache" \
    >"$WORK/home/.config/lorry/lorry.toml"
cd "$WORK/project"
printf '[workspace]\nmembers = ["app", "sys"]\nresolver = "2"\n' >Cargo.toml
printf '[package]\nname = "demo-sys"\nversion = "0.1.0"\nedition = "2021"\nlinks = "demo"\n' \
    >sys/Cargo.toml
cat >sys/build.rs <<'EOF'
fn main() {
    println!("cargo:root=/opt/demo-root");
    println!("cargo::metadata=include=include-dir");
    // An empty archive that only a dependent's final link looks for.
    let out = std::env::var("OUT_DIR").unwrap();
    std::fs::write(std::path::Path::new(&out).join("libdemo.a"), b"!<arch>\n").unwrap();
    println!("cargo:rustc-link-search=native={out}");
    println!("cargo:rustc-link-lib=static:-bundle=demo");
}
EOF
printf 'pub fn value() -> u32 { 7 }\n' >sys/src/lib.rs
printf '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n[dependencies]\ndemo-sys = { path = "../sys" }\n' \
    >app/Cargo.toml
cat >app/build.rs <<'EOF'
fn main() {
    let root = std::env::var("DEP_DEMO_ROOT").unwrap();
    let include = std::env::var("DEP_DEMO_INCLUDE").unwrap();
    println!("cargo:rustc-env=DEMO={root}:{include}");
    println!("cargo:rustc-flags=-l c");
    println!("cargo:rustc-link-arg-bins=-Wl,--as-needed");
}
EOF
printf 'fn main() { println!("{} {}", env!("DEMO"), demo_sys::value()); }\n' >app/src/main.rs
cat >lorry.toml <<'EOF'
config-version = 1
use-cargo-registry = false
[policy.rules.app]
action = "allow"
name = "app"
source = "path"
allow-build-script = true
[policy.rules.demo-sys]
action = "allow"
name = "demo-sys"
source = "path"
allow-build-script = true
EOF
"$LORRY_TEST_CARGO" generate-lockfile --offline

lorry() {
    env HOME="$WORK/home" "$LORRY" "$@"
}
# The run of app's script and its OUT_DIR hash match Cargo's.
out_dir_hash() {
    python3 -I - "$1" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    message = json.loads(line)
    if message.get("reason") == "build-script-executed" and message["package_id"].split("#")[0].endswith("/app"):
        parts = message["out_dir"].split("/")
        print(parts[parts.index("app") + 1])
PY
}
"$LORRY_TEST_CARGO" build -p app --offline --message-format=json >"$WORK/cargo.json"
lorry build -p app --message-format=json >"$WORK/lorry.json"
[ -n "$(out_dir_hash "$WORK/cargo.json")" ] || fail "Cargo reported no app build script"
[ "$(out_dir_hash "$WORK/lorry.json")" = "$(out_dir_hash "$WORK/cargo.json")" ] ||
    fail "app's OUT_DIR hash differs from Cargo's"
cmp target/debug/app target/lorry/debug/app || fail "the app binary differs from Cargo's"
[ "$(target/lorry/debug/app)" = "/opt/demo-root:include-dir 7" ] ||
    fail "app did not receive DEP_DEMO_* metadata"

# New metadata reruns the dependent script.
sed -i 's|/opt/demo-root|/opt/other-root|' sys/build.rs
lorry build -p app -q
[ "$(target/lorry/debug/app)" = "/opt/other-root:include-dir 7" ] ||
    fail "changed metadata did not reach the dependent script"
echo "PASS: build-script metadata, rustc-flags, bin link arguments, and dependency link paths match Cargo"
