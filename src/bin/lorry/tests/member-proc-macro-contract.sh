#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

LORRY="$(realpath "${1:?usage: member-proc-macro-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
export RUSTC="$LORRY_TEST_RUSTC"
WORK="$(mktemp -d /tmp/lorry-member-macro-contract-XXXXXX)"
trap 'status=$?; if [ "$status" = 0 ]; then rm -rf "$WORK"; else echo "Retained failed fixture: $WORK" >&2; fi' EXIT
mkdir -p "$WORK/home/.config/lorry" "$WORK/project"/{app,derive,helper}/src "$WORK/project/.cargo"
printf 'config-version = 1\nuse-cargo-registry = false\n[cache]\ndirectory = "%s"\n' "$WORK/cache" >"$WORK/home/.config/lorry/lorry.toml"
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
use-cargo-registry = false
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
grep -F 'procedural macro without an explicit matching policy grant' "$WORK/denied.err" >/dev/null
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
cat >>derive/Cargo.toml <<'EOF'
[features]
default = ["checked"]
checked = []
EOF
sed -i '/proc-macro = true/a doctest = false' derive/Cargo.toml
printf '\nallow-build-script = true\n' >>lorry.toml
cat >derive/build.rs <<'EOF'
fn main() {
    assert!(cfg!(feature = "checked"));
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("generated.rs"), "const SCRIPT_VALUE: &str = \"generated\";").unwrap();
    println!("cargo:rustc-env=SCRIPT_OWNER=derive");
    println!("cargo:rerun-if-changed=build.rs");
}
EOF
cat >>derive/src/lib.rs <<'EOF'
#[test]
fn host_harness() {
    assert!(cfg!(feature = "checked"));
    if let Some(expected) = std::env::var_os("EXPECTED_HOST_LIBDIR") {
        let paths = std::env::var_os("LD_LIBRARY_PATH").unwrap();
        assert!(std::env::split_paths(&paths).any(|path| path == std::path::PathBuf::from(&expected)));
    }
    assert_eq!(helper::expansion(), "41");
    assert_eq!(std::env::var("SCRIPT_OWNER").unwrap(), "derive");
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    assert_eq!(std::fs::read_to_string(out.join("generated.rs")).unwrap(), "const SCRIPT_VALUE: &str = \"generated\";");
}
EOF
for platform in native motor native-release motor-release native-opt motor-opt; do
    if [ "$platform" = native-opt ]; then printf '\n[profile.dev]\nopt-level = 2\n' >>Cargo.toml; fi
    target=()
    release=()
    if [[ "$platform" = motor* ]]; then target=(--target x86_64-unknown-motor); fi
    if [[ "$platform" = *-release ]]; then release=(--release); fi
    if [[ "$platform" = *-opt || "$platform" = *-release ]]; then
        for command in build check; do
            env HOME="$WORK/home" "$LORRY" "$command" --workspace "${target[@]}" "${release[@]}" --message-format=json >"$WORK/lorry-optimized.json"
            "$LORRY_TEST_CARGO" "$command" --workspace "${target[@]}" "${release[@]}" --offline --message-format=json >"$WORK/cargo-optimized.json"
            comparison=differential-script-clean-messages
            if [ "$command" = check ]; then comparison=differential-script-clean-check-messages; fi
            "$LORRY_TEST_CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" --locked --offline -- \
                "$comparison" "$WORK/lorry-optimized.json" "$WORK/cargo-optimized.json"
            if [ "$command" = build ]; then
                profile=debug
                if [[ "$platform" = motor* ]]; then profile=x86_64-unknown-motor/debug; fi
                if [[ "$platform" = *-release ]]; then profile="${profile%debug}release"; fi
                cmp "target/$profile/app" "target/lorry/$profile/app"
                python3 - "$WORK/lorry-optimized.json" "$WORK/cargo-optimized.json" <<'PYMACRO'
import json, pathlib, sys
def macros(path):
    return sorted(pathlib.Path(file).read_bytes() for line in open(path) for event in [json.loads(line)]
                  if event['reason'] == 'compiler-artifact' and event['target']['kind'] == ['proc-macro']
                  for file in event['filenames'])
lorry, cargo = map(macros, sys.argv[1:])
assert lorry and lorry == cargo
PYMACRO
            fi
        done
    fi
    for selection in macro all; do
        packages=(-p derive)
        if [ "$selection" = all ]; then packages=(--workspace); fi
        env HOME="$WORK/home" "$LORRY" test "${packages[@]}" --no-run "${target[@]}" "${release[@]}" --message-format=json >"$WORK/lorry-test.json"
        "$LORRY_TEST_CARGO" test "${packages[@]}" --no-run "${target[@]}" "${release[@]}" --offline --message-format=json >"$WORK/cargo-test.json"
        "$LORRY_TEST_CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" --locked --offline -- \
            differential-script-clean-messages "$WORK/lorry-test.json" "$WORK/cargo-test.json"
        python3 - "$WORK/lorry-test.json" "$WORK/cargo-test.json" <<'PY'
import json, pathlib, sys
def harnesses(path):
    return [pathlib.Path(event['executable']).read_bytes() for line in open(path)
            for event in [json.loads(line)] if event['reason'] == 'compiler-artifact'
            and event['profile']['test']]
lorry, cargo = map(harnesses, sys.argv[1:])
assert lorry and len(lorry) == len(cargo) and sorted(lorry) == sorted(cargo)
PY
    done
done
env HOME="$WORK/home" "$LORRY" test -p derive
"$LORRY_TEST_CARGO" test -p derive --offline
cat >"$WORK/target-runner.sh" <<'EOF'
#!/usr/bin/env bash
exit 73
EOF
printf '\nrunner = ["bash", "%s"]\n' "$WORK/target-runner.sh" >>.cargo/config.toml
host_libdir="$("$RUSTC" --print target-libdir)"
env EXPECTED_HOST_LIBDIR="$host_libdir" "$LORRY_TEST_CARGO" test -p derive --target x86_64-unknown-motor --offline
env HOME="$WORK/home" EXPECTED_HOST_LIBDIR="$host_libdir" "$LORRY" test -p derive --target x86_64-unknown-motor
printf '\n[test]\nextraction-root = "%s"\n' "$WORK/extraction" >>lorry.toml
for target in native motor; do
    args=()
    if [ "$target" = motor ]; then args=(--target x86_64-unknown-motor); fi
    env HOME="$WORK/home" EXPECTED_HOST_LIBDIR="$host_libdir" "$LORRY" test -p derive --bundle "${args[@]}"
done
mkdir derive/tests
printf '#[test]\nfn imported_macro() { assert_eq!(derive::answer!(), 41); }\n' >derive/tests/imported.rs
if env HOME="$WORK/home" "$LORRY" test -p derive --bundle --no-run \
    --target x86_64-unknown-motor --target-dir "$WORK/mixed-bundle" \
    --message-format=json >"$WORK/mixed-bundle.json" 2>"$WORK/mixed-bundle.err"; then exit 1; fi
grep -F 'cannot bundle tests for `derive` across host' "$WORK/mixed-bundle.err" >/dev/null
grep -F -- '--lib or --test NAME, or omit --bundle' "$WORK/mixed-bundle.err" >/dev/null
python3 - "$WORK/mixed-bundle" "$WORK/mixed-bundle.json" <<'PYBUNDLE'
import json, pathlib, sys
assert not list(pathlib.Path(sys.argv[1]).rglob('*-test-bundle'))
assert [json.loads(line) for line in open(sys.argv[2])] == [
    {'reason': 'build-finished', 'success': False}]
PYBUNDLE
env HOME="$WORK/home" EXPECTED_HOST_LIBDIR="$host_libdir" "$LORRY" test -p derive --bundle
env HOME="$WORK/home" EXPECTED_HOST_LIBDIR="$host_libdir" "$LORRY" test -p derive --bundle --lib --target x86_64-unknown-motor
env HOME="$WORK/home" "$LORRY" test -p derive --bundle --test imported --no-run --target x86_64-unknown-motor
rm -rf derive/tests
mkdir derive/examples
printf 'fn main() { assert_eq!(derive::answer!(), 41); }\n' >derive/examples/selected.rs
for platform in native motor; do
    args=()
    if [ "$platform" = motor ]; then args=(--target x86_64-unknown-motor); fi
    for selection in --examples --all-targets; do
        env HOME="$WORK/home" "$LORRY" check -p derive "$selection" "${args[@]}" --message-format=json >"$WORK/lorry-example.json"
        "$LORRY_TEST_CARGO" check -p derive "$selection" "${args[@]}" --offline --message-format=json >"$WORK/cargo-example.json"
        "$LORRY_TEST_CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" --locked --offline -- \
            differential-script-clean-check-messages "$WORK/lorry-example.json" "$WORK/cargo-example.json"
        python3 - "$WORK/lorry-example.json" "$WORK/cargo-example.json" <<'PYEXAMPLE'
import json, pathlib, sys
def macros(path):
    return sorted(pathlib.Path(file).read_bytes() for line in open(path) for event in [json.loads(line)]
                  if event['reason'] == 'compiler-artifact' and event['target']['kind'] == ['proc-macro']
                  for file in event['filenames'] if pathlib.Path(file).suffix == '.so')
lorry, cargo = map(macros, sys.argv[1:])
assert lorry and lorry == cargo
PYEXAMPLE
    done
done

# A binary-only consumer must also put a dev-only, unselected macro on the host.
mkdir -p "$WORK/dev-only"/{app,derive,helper}/src "$WORK/dev-only/app/.cargo"
cp .cargo/config.toml "$WORK/dev-only/app/.cargo/config.toml"
cd "$WORK/dev-only/app"
cat >../Cargo.toml <<'EOF'
[workspace]
members = ["app", "derive", "helper"]
default-members = ["app"]
resolver = "3"
EOF
cat >Cargo.toml <<'EOF'
[package]
name = "dev-app"
version = "1.0.0"
edition = "2024"
[dev-dependencies]
derive = { path = "../derive" }
EOF
cat >src/main.rs <<'EOF'
fn main() {}
#[cfg(test)]
mod tests {
    #[test]
    fn dev_macro() { assert_eq!(derive::answer!(), 41); }
}
EOF
mkdir tests
printf '#[test]\nfn dev_macro() { assert_eq!(derive::answer!(), 41); }\n' >tests/integration.rs
cat >../derive/Cargo.toml <<'EOF'
[package]
name = "derive"
version = "1.0.0"
edition = "2024"
[lib]
proc-macro = true
[target.'cfg(unix)'.dependencies]
helper = { path = "../helper", features = ["host"] }
EOF
cp "$WORK/project/derive/src/lib.rs" ../derive/src/lib.rs
# This fixture needs only the expansion, with no member script or harness.
sed -i '/#\[test\]/,$d' ../derive/src/lib.rs
cat >../helper/Cargo.toml <<'EOF'
[package]
name = "helper"
version = "1.0.0"
edition = "2024"
[features]
host = []
EOF
cat >../helper/src/lib.rs <<'EOF'
#[cfg(not(feature = "host"))]
compile_error!("macro helper must activate its host feature");
pub fn expansion() -> &'static str { "41" }
EOF
printf 'config-version = 1\nuse-cargo-registry = false\n[policy]\npath-roots = ["%s"]\n[policy.rules.dev-macro]\naction = "allow"\nname = "derive"\nversion = "=1.0.0"\nsource = "path"\nallow-proc-macro = true\n' \
    "$WORK/dev-only" >../lorry.toml
"$LORRY_TEST_CARGO" generate-lockfile --offline
cp ../Cargo.lock "$WORK/dev-only.lock"
for platform in native motor; do
    args=()
    if [ "$platform" = motor ]; then args=(--target x86_64-unknown-motor); fi
    for command in test check; do
        selection=(--no-run)
        comparison=differential-workspace-messages
        if [ "$command" = check ]; then
            selection=(--all-targets)
            comparison=differential-workspace-check-messages
        fi
        env HOME="$WORK/home" "$LORRY" "$command" "${selection[@]}" "${args[@]}" --locked --offline \
            --message-format=json >"$WORK/dev-lorry.json"
        "$LORRY_TEST_CARGO" "$command" "${selection[@]}" "${args[@]}" --locked --offline \
            --message-format=json >"$WORK/dev-cargo.json"
        "$LORRY_TEST_CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" --locked --offline -- \
            "$comparison" "$WORK/dev-lorry.json" "$WORK/dev-cargo.json"
        if [ "$command" = test ]; then
            python3 - "$WORK/dev-lorry.json" "$WORK/dev-cargo.json" <<'PYDEV'
import json, pathlib, sys
def artifacts(path):
    return sorted(pathlib.Path(file).read_bytes() for line in open(path) for event in [json.loads(line)]
                  if event['reason'] == 'compiler-artifact' and
                     (event['profile']['test'] or event['target']['kind'] == ['proc-macro'])
                  for file in event['filenames'])
lorry, cargo = map(artifacts, sys.argv[1:])
assert len(lorry) == 3 and lorry == cargo
PYDEV
        fi
        cmp ../Cargo.lock "$WORK/dev-only.lock"
    done
done
env HOME="$WORK/home" "$LORRY" test --locked --offline
"$LORRY_TEST_CARGO" test --locked --offline
echo "PASS: selected member and dev-only macros match Cargo host/cross bytes and JSON"
