#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true
LORRY="$(realpath "${1:?usage: workspace-run-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
export RUSTC="$LORRY_TEST_RUSTC"
WORK="$(mktemp -d /tmp/lorry-workspace-run-XXXXXX)"
trap 'status=$?; if [ "$status" = 0 ]; then rm -rf "$WORK"; else echo "Retained run fixture: $WORK" >&2; fi' EXIT
mkdir -p "$WORK/home/.config/lorry" "$WORK/project"/{library,app,other}/src
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" >"$WORK/home/.config/lorry/lorry.toml"
cat >"$WORK/project/Cargo.toml" <<'EOF'
[workspace]
members = ["library", "app", "other"]
default-members = ["library", "app"]
resolver = "2"
EOF
for member in library app other; do
    cat >"$WORK/project/$member/Cargo.toml" <<EOF
[package]
name = "$member"
version = "1.0.0"
edition = "2024"
EOF
done
printf 'pub fn value() -> u32 { 42 }\n' >"$WORK/project/library/src/lib.rs"
for member in app other; do
    cat >"$WORK/project/$member/src/main.rs" <<'EOF'
fn main() {
    println!("{}|{}", env!("CARGO_PKG_NAME"), std::env::args().skip(1).collect::<Vec<_>>().join("|"));
}
EOF
done
cd "$WORK/project"
"$LORRY_TEST_CARGO" generate-lockfile --offline
compare_run() {
    env HOME="$WORK/home" "$LORRY" run --quiet --offline "$@" >"$WORK/lorry.out"
    "$LORRY_TEST_CARGO" run --quiet --offline "$@" >"$WORK/cargo.out"
    cmp "$WORK/lorry.out" "$WORK/cargo.out"
    test -s "$WORK/lorry.out"
}
reject_run() {
    local expected="$1"
    shift
    for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
        if env HOME="$WORK/home" "$builder" run --offline "$@" >"$WORK/rejected.out" 2>"$WORK/rejected.err"; then
            echo "run unexpectedly accepted $*: $builder" >&2
            exit 1
        fi
        grep -F "$expected" "$WORK/rejected.err"
    done
}
compare_run -- one 'two words'
compare_run --bin app -- explicit
compare_run -p other -- selected
reject_run 'no bin target named' --bin missing
reject_run 'a bin target must be available' -p library
# Two default members may have binaries; a unique explicit name disambiguates.
sed -i 's/default-members = .*/default-members = ["library", "app", "other"]/' Cargo.toml
reject_run 'could not determine which binary to run'
compare_run --bin app
cat >>app/Cargo.toml <<'EOF'
[[bin]]
name = "broken"
path = "src/broken.rs"
EOF
printf 'compile_error!("unselected binary must not compile");\nfn main() {}\n' >app/src/broken.rs
# Exactly one default-run across the selection filters all selected packages.
sed -i '/name = "app"/a default-run = "app"' app/Cargo.toml
compare_run
compare_run --bin other
# The same target name in two members remains ambiguous even with default-run.
cat >>other/Cargo.toml <<'EOF'
[[bin]]
name = "app"
path = "src/duplicate.rs"
EOF
cp other/src/main.rs other/src/duplicate.rs
reject_run 'can run at most one executable' --bin app
reject_run 'can run at most one executable'
compare_run -p app
# Several default-run keys do not arbitrarily choose the first member.
sed -i '/name = "other"/a default-run = "other"' other/Cargo.toml
reject_run 'could not determine which binary to run'
compare_run -p other
mkdir -p app/examples other/examples
cat >>app/Cargo.toml <<'EOF'
[dev-dependencies]
library = { path = "../library" }
[features]
example-feature = []
[[example]]
name = "demo"
required-features = ["example-feature"]
[[example]]
name = "archive"
crate-type = ["rlib"]
EOF
cat >app/examples/demo.rs <<'EOF'
fn main() {
    assert_eq!(library::value(), 42);
    println!("{}|{}", env!("CARGO_PKG_NAME"), std::env::args().skip(1).collect::<Vec<_>>().join("|"));
}
EOF
printf 'pub fn example() {}\n' >app/examples/archive.rs
"$LORRY_TEST_CARGO" generate-lockfile --offline
reject_run 'requires the features' --example demo
compare_run --example demo --features app/example-feature -- example 'two words'
compare_run -p app --example demo --features example-feature -- explicit
reject_run 'is a library and cannot be executed' --example archive
reject_run 'no example target named' --example missing
cp app/src/main.rs other/examples/demo.rs
reject_run 'can run at most one executable' --example demo --features app/example-feature
compare_run -p other --example demo -- other-example
echo 'PASS: Cargo default-member run selection, default-run, ambiguity, and selected runtime metadata'
