#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

LORRY="$(realpath "${1:?usage: workspace-metadata-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${LORRY_TEST_CARGO:-}" ]; then
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
WORK="$(mktemp -d /tmp/lorry-workspace-metadata-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
PROJECT="$WORK/project"
mkdir -p "$PROJECT/app/src" "$PROJECT/shared/src" "$WORK/home"
# Source metadata reads only membership. Build-only tables need no support.
cat >"$PROJECT/Cargo.toml" <<'EOF'
[workspace]
members = ["app", "shared"]
exclude = ["tools/excluded"]
resolver = "2"
[workspace.package]
version = "9.9.9"
[workspace.dependencies]
unprepared = "1"
[workspace.metadata]
title = "editor tools"
enabled = true
count = 7
ratio = 0.5
nan = nan
date = 2026-10-03
time = 12:34:56
timestamp = 2026-10-03T12:34:56Z
values = [1, "two", { three = false }]
[[workspace.metadata.commands]]
name = "check"
[[workspace.metadata.commands]]
name = "test"
[profile.custom]
inherits = "release"
debug = 1
EOF
cat >"$PROJECT/app/Cargo.toml" <<'EOF'
[package]
name = "app"
version = "0.1.0"
edition = "2021"
[package.metadata.editor]
name = "app"
values = ["build", "check"]
settings = { enabled = true, amount = 3 }
[dependencies]
shared = { path = "../shared" }
helper = { path = "../tools/helper" }
outside = { path = "../../outside" }
excluded = { path = "../tools/excluded" }
[dev-dependencies]
unprepared = "1"
[features]
extra = []
[[bin]]
name = "app"
path = "src/main.rs"
required-features = ["extra"]
doc = true
[badges]
maintenance = { status = "experimental" }
EOF
cat >"$PROJECT/shared/Cargo.toml" <<'EOF'
[package]
name = "shared"
version = "0.1.0"
edition = "2021"
resolver = "2"
keywords = ["motor", "source"]
categories = ["development-tools"]
[lib]
crate-type = ["staticlib"]
EOF
printf 'fn main() { shared::answer(); }\n' >"$PROJECT/app/src/main.rs"
printf 'pub fn answer() {}\n' >"$PROJECT/shared/src/lib.rs"
mkdir -p "$PROJECT/app/examples/group" "$PROJECT/app/benches/group"
printf 'fn main() {}\n' >"$PROJECT/app/examples/demo.rs"
printf 'fn main() {}\n' >"$PROJECT/app/examples/group/main.rs"
printf 'pub fn example() {}\n' >"$PROJECT/app/src/example.rs"
printf 'fn main() {}\n' >"$PROJECT/app/benches/speed.rs"
printf 'fn main() {}\n' >"$PROJECT/app/benches/group/main.rs"
cat >>"$PROJECT/app/Cargo.toml" <<'EOF'
[[example]]
name = "demo"
path = "src/example.rs"
crate-type = ["rlib"]
edition = "2021"
required-features = ["extra"]
test = true
doc = true
doc-scrape-examples = true
[[bench]]
name = "custom"
path = "benches/speed.rs"
harness = false
test = true
EOF
# Path dependencies below the root are implicit members, recursively and for
# every dependency kind. Excluded paths and paths outside the root are not.
package() {
    mkdir -p "$1/src"
    printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\n' \
        "$(basename "$1")" >"$1/Cargo.toml"
    printf 'pub fn answer() {}\n' >"$1/src/lib.rs"
}
for directory in "$PROJECT/tools/helper" "$PROJECT/tools/helper/nested" \
    "$PROJECT/tools/excluded" "$WORK/outside"; do
    package "$directory"
done

# Resolved metadata describes every member without admission or compilation.
RESOLVED="$WORK/resolved"
mkdir -p "$RESOLVED/.cargo"
cat >"$RESOLVED/Cargo.toml" <<'EOF'
[workspace]
members = ["app", "shared"]
exclude = ["windows-only"]
default-members = ["app"]
resolver = "2"
EOF
for member in app shared windows-only; do
    package "$RESOLVED/$member"
done
cat >>"$RESOLVED/app/Cargo.toml" <<'EOF'
[dependencies]
shared = { path = "../shared" }
[dev-dependencies]
shared = { path = "../shared", features = ["dev"] }
[target.'cfg(windows)'.dependencies]
shared = { path = "../shared", features = ["windows"] }
windows-only = { path = "../windows-only" }
[features]
default = ["shared/base"]
extra = ["shared/extra"]
EOF
cat >>"$RESOLVED/shared/Cargo.toml" <<'EOF'
[features]
base = []
extra = []
dev = []
windows = []
EOF
printf 'compile_error!("metadata must never compile this build script");\n' \
    >"$RESOLVED/shared/build.rs"
printf '[build]\ntarget = "x86_64-pc-windows-msvc"\n' >"$RESOLVED/.cargo/config.toml"
RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" generate-lockfile --offline \
    --manifest-path "$RESOLVED/Cargo.toml"
cp "$RESOLVED/Cargo.lock" "$WORK/resolved-lock-before"
resolved_agrees_with_cargo() {
    local name="$1" manifest="$2"
    shift 2
    (cd "$RESOLVED"; HOME="$WORK/home" RUSTC="$LORRY_TEST_RUSTC" "$LORRY" metadata \
        --locked --offline --format-version 1 --manifest-path "$manifest" "$@") \
        >"$WORK/$name.lorry.json"
    (cd "$RESOLVED"; RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" metadata \
        --locked --offline --format-version 1 --manifest-path "$manifest" "$@") \
        >"$WORK/$name.cargo.json"
    RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" run --quiet --locked --offline \
        --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" -- \
        compare "$WORK/$name.lorry.json" "$WORK/$name.cargo.json"
    cmp "$RESOLVED/Cargo.lock" "$WORK/resolved-lock-before"
    [ ! -e "$RESOLVED/.lorry" ]
    [ ! -e "$RESOLVED/target" ]
}
resolved_agrees_with_cargo resolved-default "$RESOLVED/Cargo.toml"
resolved_agrees_with_cargo resolved-feature "$RESOLVED/Cargo.toml" --features app/extra
resolved_agrees_with_cargo resolved-all "$RESOLVED/Cargo.toml" --all-features --no-default-features
resolved_agrees_with_cargo resolved-linux "$RESOLVED/Cargo.toml" \
    --filter-platform x86_64-unknown-linux-gnu
resolved_agrees_with_cargo resolved-member "$RESOLVED/app/Cargo.toml" --features extra
echo "PASS: resolved workspace metadata matches Cargo features and platforms without admission"
printf '[dev-dependencies]\nnested = { path = "nested" }\n' >>"$PROJECT/tools/helper/Cargo.toml"

# No compiler, configuration, lockfile, or admission is needed to describe
# source targets. This also proves the command cannot fetch dependencies.
source_metadata() {
    local manifest="$1"
    shift
    HOME="$WORK/home" RUSTC="$WORK/absent-rustc" "$LORRY" metadata \
        --format-version 1 --no-deps --locked \
        --filter-platform x86_64-unknown-motor --manifest-path "$manifest" "$@"
}
agrees_with_cargo() {
    local manifest="$1" name="$2"
    source_metadata "$manifest" >"$WORK/$name.json"
    RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" metadata --format-version 1 \
        --no-deps --offline --manifest-path "$manifest" >"$WORK/$name.cargo.json"
    RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" run --quiet --locked --offline \
        --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" -- \
        compare-projection "$WORK/$name.json" "$WORK/$name.cargo.json"
}
package "$WORK/renamed-binaries"
rm "$WORK/renamed-binaries/src/lib.rs"
printf 'fn main() { println!("renamed"); }\n' >"$WORK/renamed-binaries/src/main.rs"
cat >>"$WORK/renamed-binaries/Cargo.toml" <<'EOF'
[[bin]]
name = "command"
path = "src/main.rs"
EOF
agrees_with_cargo "$WORK/renamed-binaries/Cargo.toml" renamed-main
RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" generate-lockfile --offline \
    --manifest-path "$WORK/renamed-binaries/Cargo.toml"
for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
    HOME="$WORK/home" RUSTC="$LORRY_TEST_RUSTC" "$builder" run --offline \
        --manifest-path "$WORK/renamed-binaries/Cargo.toml" >"$WORK/renamed-run.out"
    grep -Fx renamed "$WORK/renamed-run.out"
done
mkdir "$WORK/renamed-binaries/src/bin"
printf 'fn main() {}\n' >"$WORK/renamed-binaries/src/bin/tool.rs"
cat >>"$WORK/renamed-binaries/Cargo.toml" <<'EOF'
[[bin]]
name = "renamed-tool"
path = "src/bin/tool.rs"
[[bin]]
name = "second-command"
path = "src/main.rs"
EOF
agrees_with_cargo "$WORK/renamed-binaries/Cargo.toml" renamed-and-shared-paths
echo "PASS: explicit binary names and paths suppress inferred targets"
package "$WORK/named-binaries"
mkdir -p "$WORK/named-binaries/src/bin/group"
printf 'fn main() {}\n' >"$WORK/named-binaries/src/bin/tool.rs"
printf 'fn main() {}\n' >"$WORK/named-binaries/src/bin/group/main.rs"
printf 'fn main() {}\n' >"$WORK/named-binaries/src/bin/.hidden.rs"
cat >>"$WORK/named-binaries/Cargo.toml" <<'EOF'
[[bin]]
name = "tool"
[[bin]]
name = "group"
EOF
cp "$WORK/named-binaries/Cargo.toml" "$WORK/named-binaries.baseline"
for automatic in true false; do
    sed "/^\[package\]$/a autobins = $automatic" "$WORK/named-binaries.baseline" \
        >"$WORK/named-binaries/Cargo.toml"
    agrees_with_cargo "$WORK/named-binaries/Cargo.toml" "named-binaries-$automatic"
done
printf '\n[badges]\nmaintenance = { status = "experimental" }\n' \
    >>"$WORK/named-binaries/Cargo.toml"
RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" generate-lockfile --offline \
    --manifest-path "$WORK/named-binaries/Cargo.toml"
for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
    HOME="$WORK/home" RUSTC="$LORRY_TEST_RUSTC" "$builder" build --offline \
        --manifest-path "$WORK/named-binaries/Cargo.toml"
done
package "$WORK/legacy-binaries"
printf 'fn main() {}\n' >"$WORK/legacy-binaries/src/main.rs"
mkdir "$WORK/legacy-binaries/src/bin"
printf 'compile_error!("edition 2015 must not infer this binary");\n' \
    >"$WORK/legacy-binaries/src/bin/unused.rs"
sed -i 's/edition = "2021"/edition = "2015"/' "$WORK/legacy-binaries/Cargo.toml"
cat >>"$WORK/legacy-binaries/Cargo.toml" <<'EOF'
[[bin]]
name = "legacy-command"
EOF
agrees_with_cargo "$WORK/legacy-binaries/Cargo.toml" legacy-binaries
RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" generate-lockfile --offline \
    --manifest-path "$WORK/legacy-binaries/Cargo.toml"
for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
    HOME="$WORK/home" RUSTC="$LORRY_TEST_RUSTC" "$builder" build --offline \
        --manifest-path "$WORK/legacy-binaries/Cargo.toml"
done
sed -i '/^\[package\]$/a autobins = true' "$WORK/legacy-binaries/Cargo.toml"
agrees_with_cargo "$WORK/legacy-binaries/Cargo.toml" legacy-opt-in
package "$WORK/linked-targets"
mkdir -p "$WORK/linked-targets/src/bin" "$WORK/linked-targets/examples"
printf 'fn main() {}\n' >"$WORK/linked-targets/program.rs"
ln -s ../../program.rs "$WORK/linked-targets/src/bin/linked.rs"
ln -s ../program.rs "$WORK/linked-targets/examples/linked.rs"
ln -s ../../program.rs "$WORK/linked-targets/src/bin/.hidden.rs"
agrees_with_cargo "$WORK/linked-targets/Cargo.toml" linked-targets
echo "PASS: named binary paths, legacy discovery, and symbolic target paths"
source_files=("$PROJECT/Cargo.toml" "$PROJECT/app/Cargo.toml" "$PROJECT/shared/Cargo.toml"
    "$PROJECT/app/src/main.rs" "$PROJECT/shared/src/lib.rs" "$PROJECT/tools/helper/Cargo.toml")
sha256sum "${source_files[@]}" >"$WORK/sources.before"
# A member, including an implicit one, describes the whole workspace and
# selects itself as the default member. An excluded package stands alone.
agrees_with_cargo "$PROJECT/Cargo.toml" root
agrees_with_cargo "$PROJECT/app/Cargo.toml" member
agrees_with_cargo "$PROJECT/tools/helper/Cargo.toml" implicit
agrees_with_cargo "$PROJECT/tools/excluded/Cargo.toml" excluded
cp "$PROJECT/app/Cargo.toml" "$WORK/target.baseline"
for edition in 2015 2024; do
    sed "s/edition = \"2021\"/edition = \"$edition\"/" "$WORK/target.baseline" >"$PROJECT/app/Cargo.toml"
    agrees_with_cargo "$PROJECT/Cargo.toml" "targets-$edition"
done
sed '/^\[package\]$/a autoexamples = false\nautobenches = false' "$WORK/target.baseline" >"$PROJECT/app/Cargo.toml"
agrees_with_cargo "$PROJECT/Cargo.toml" targets-explicit-only
cp "$WORK/target.baseline" "$PROJECT/app/Cargo.toml"
sed 's/doc-scrape-examples = true/doc-scrape-examples = "true"/' \
    "$WORK/target.baseline" >"$PROJECT/app/Cargo.toml"
for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
    if "$builder" metadata --no-deps --offline --format-version 1 \
        --manifest-path "$PROJECT/Cargo.toml" >"$WORK/invalid-scrape.json" 2>"$WORK/invalid-scrape.err"; then
        echo "workspace-metadata: accepted a nonboolean example doc-scrape-examples" >&2
        exit 1
    fi
done
cp "$WORK/target.baseline" "$PROJECT/app/Cargo.toml"
(
    cd "$PROJECT/app/src"
    HOME="$WORK/home" RUSTC="$WORK/absent-rustc" "$LORRY" metadata \
        --format-version 1 --no-deps >"$WORK/subdirectory.json"
    RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" metadata \
        --format-version 1 --no-deps --offline >"$WORK/subdirectory.cargo.json"
    RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" run --quiet --locked --offline \
        --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" -- \
        compare-projection "$WORK/subdirectory.json" "$WORK/subdirectory.cargo.json"
)
sha256sum "${source_files[@]}" >"$WORK/sources.after"
cmp "$WORK/sources.before" "$WORK/sources.after"
package "$WORK/automatic-library"
printf '\nautolib = false\n' >>"$WORK/automatic-library/Cargo.toml"
printf 'compile_error!("disabled automatic library compiled");\n' >"$WORK/automatic-library/src/lib.rs"
printf 'fn main() {}\n' >"$WORK/automatic-library/src/main.rs"
agrees_with_cargo "$WORK/automatic-library/Cargo.toml" disabled-library
RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" generate-lockfile --offline \
    --manifest-path "$WORK/automatic-library/Cargo.toml"
for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
    HOME="$WORK/home" RUSTC="$LORRY_TEST_RUSTC" "$builder" build --offline \
        --manifest-path "$WORK/automatic-library/Cargo.toml"
done
# An explicit library remains enabled even when automatic discovery is off.
printf '\n[lib]\n' >>"$WORK/automatic-library/Cargo.toml"
agrees_with_cargo "$WORK/automatic-library/Cargo.toml" explicit-library
sed 's/autolib = false/autolib = "false"/' "$WORK/automatic-library/Cargo.toml" \
    >"$WORK/invalid-autolib.toml"
cp "$WORK/invalid-autolib.toml" "$WORK/automatic-library/Cargo.toml"
for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
    if "$builder" metadata --no-deps --manifest-path "$WORK/automatic-library/Cargo.toml" \
        2>"$WORK/invalid-autolib.err"; then exit 1; fi
done
for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
    if "$builder" metadata --manifest-path "$PROJECT/Cargo.toml" --no-deps -p app \
        >"$WORK/selected.json" 2>"$WORK/selected.err"; then
        echo "workspace-metadata: metadata accepted a package selector" >&2
        exit 1
    fi
    grep -F "unexpected argument '-p'" "$WORK/selected.err" >/dev/null
done
[ ! -e "$PROJECT/Cargo.lock" ]
[ ! -e "$PROJECT/target" ]
[ ! -e "$PROJECT/.lorry" ]

# Existing, invalid lock bytes must survive editor discovery untouched.
printf 'not a Cargo lockfile\n' >"$PROJECT/Cargo.lock"
cp "$PROJECT/Cargo.lock" "$WORK/lock.before"
source_metadata "$PROJECT/Cargo.toml" >"$WORK/invalid-lock.json"
cmp "$WORK/root.json" "$WORK/invalid-lock.json"
cmp "$PROJECT/Cargo.lock" "$WORK/lock.before"
rm "$PROJECT/Cargo.lock"

# A root package has different Cargo default-member semantics.
cat >>"$PROJECT/Cargo.toml" <<'EOF'
[package]
name = "root"
version = "0.1.0"
edition = "2021"
EOF
mkdir "$PROJECT/src"
printf 'pub fn root() {}\n' >"$PROJECT/src/lib.rs"
agrees_with_cargo "$PROJECT/Cargo.toml" nonvirtual

# A root may list itself as ".", declare default-members, or use an empty
# `[workspace]` table. Its path dependencies are still implicit members.
for root in "$WORK/dot" "$WORK/empty"; do
    package "$root"
    package "$root/inner"
    package "$root/listed"
    printf '[dependencies]\ninner = { path = "inner" }\n[workspace]\n' >>"$root/Cargo.toml"
done
printf 'members = [".", "listed"]\ndefault-members = ["listed"]\n' >>"$WORK/dot/Cargo.toml"
agrees_with_cargo "$WORK/dot/Cargo.toml" dot
agrees_with_cargo "$WORK/empty/Cargo.toml" empty
agrees_with_cargo "$WORK/empty/inner/Cargo.toml" empty-inner

# All manifest modes use the same workspace discovery for inherited compiler
# identity fields, including implicit members in a root without members.
for root in "$WORK/dot" "$WORK/empty"; do
    printf '\n[workspace.package]\nversion = "1.2.3"\nedition = "2024"\nrust-version = "1.85.0"\n' \
        >>"$root/Cargo.toml"
    for package in "$root" "$root/inner" "$root/listed"; do
        sed -i 's/version = "0.1.0"/version.workspace = true/; s/edition = "2021"/edition.workspace = true/' \
            "$package/Cargo.toml"
        sed -i '/^name = /a rust-version.workspace = true' "$package/Cargo.toml"
    done
done
agrees_with_cargo "$WORK/dot/Cargo.toml" inherited-listed
agrees_with_cargo "$WORK/empty/inner/Cargo.toml" inherited-implicit

for root in "$WORK/dot" "$WORK/empty"; do
    cat >>"$root/Cargo.toml" <<'EOF'
authors = ["Motor OS"]
keywords = ["workspace"]
categories = ["development-tools"]
description = "inherited package description"
homepage = "https://example.test"
documentation = "https://example.test/docs"
repository = "https://example.test/repo"
license = "MIT"
EOF
    for package in "$root" "$root/inner" "$root/listed"; do
        for field in authors keywords categories description homepage documentation repository license; do
            sed -i "/^name = /a $field.workspace = true" "$package/Cargo.toml"
        done
    done
done
agrees_with_cargo "$WORK/dot/Cargo.toml" inherited-metadata-listed
agrees_with_cargo "$WORK/empty/inner/Cargo.toml" inherited-metadata-implicit
for root in "$WORK/dot" "$WORK/empty"; do
    mkdir -p "$root/docs"
    printf 'workspace README\n' >"$root/README.txt"
    printf 'license\n' >"$root/LICENSE"
    printf 'member README\n' >"$root/inner/README.md"
    cat >>"$root/Cargo.toml" <<'EOF'
license-file = "./docs/../LICENSE"
readme = "README.txt"
publish = false
include = ["src/**"]
exclude = ["ignored"]
EOF
    for package in "$root" "$root/inner" "$root/listed"; do
        for field in license-file readme publish include exclude; do
            sed -i "/^name = /a $field.workspace = true" "$package/Cargo.toml"
        done
    done
done
agrees_with_cargo "$WORK/dot/Cargo.toml" inherited-all-fields
agrees_with_cargo "$WORK/empty/inner/Cargo.toml" inherited-paths-implicit
# Cargo rejects inheriting a disabled workspace readme. When the workspace
# omits readme, inheritance discovers its default file, not the member's.
sed -i 's/readme = "README.txt"/readme = false/' "$WORK/dot/Cargo.toml"
for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
    if "$builder" metadata --no-deps --offline --format-version 1 \
        --manifest-path "$WORK/dot/Cargo.toml" >"$WORK/disabled.json" 2>"$WORK/disabled.err"; then
        echo "workspace-metadata: accepted inheriting a disabled workspace readme" >&2
        exit 1
    fi
    grep -F 'workspace.package.readme' "$WORK/disabled.err" >/dev/null
done
sed -i '/^readme = /d' "$WORK/dot/Cargo.toml"
agrees_with_cargo "$WORK/dot/Cargo.toml" inherited-default-readme
# Explicit false must suppress an existing README; true selects README.md.
sed -i 's/readme.workspace = true/readme = false/' "$WORK/dot/inner/Cargo.toml"
agrees_with_cargo "$WORK/dot/inner/Cargo.toml" readme-false
sed -i 's/readme = false/readme = true/' "$WORK/dot/inner/Cargo.toml"
agrees_with_cargo "$WORK/dot/inner/Cargo.toml" readme-true
sed -i 's/publish = false/publish = true/' "$WORK/dot/Cargo.toml"
agrees_with_cargo "$WORK/dot/Cargo.toml" publish-true
sed -i 's/publish = true/publish = ["crates-io"]/' "$WORK/dot/Cargo.toml"
agrees_with_cargo "$WORK/dot/Cargo.toml" publish-array
# Bad inherited values must name the workspace declaration's original line.
sed -i 's/authors = \["Motor OS"\]/authors = false/' "$WORK/empty/Cargo.toml"
if source_metadata "$WORK/empty/inner/Cargo.toml" >"$WORK/bad-inheritance.json" 2>"$WORK/bad-inheritance.err"; then
    echo "workspace-metadata: accepted a non-array inherited authors field" >&2
    exit 1
fi
line="$(awk '/^authors = false/ { print NR }' "$WORK/empty/Cargo.toml")"
grep -Fx "  --> $WORK/empty/Cargo.toml:$line" "$WORK/bad-inheritance.err" >/dev/null || {
    cat "$WORK/bad-inheritance.err" >&2
    exit 1
}

echo "PASS: unprepared workspace source metadata agrees with Cargo"

GLOB="$WORK/glob"
package "$GLOB"
for name in one two drop; do package "$GLOB/crates/$name"; done
printf 'ignored file\n' >"$GLOB/crates/README"
cp "$GLOB/Cargo.toml" "$WORK/glob.package"
for pattern in 'crates/*' 'crates/???' 'crates/[ot]*' 'crates/[!d]*' 'crates/[a-z]*'; do
    cp "$WORK/glob.package" "$GLOB/Cargo.toml"
    printf '[workspace]\nmembers = ["%s"]\nexclude = ["crates/drop"]\ndefault-members = ["crates/t?o"]\n' \
        "$pattern" >>"$GLOB/Cargo.toml"
    agrees_with_cargo "$GLOB/Cargo.toml" glob
done
# A glob does not override exclusion, while an explicit member path does.
printf 'members = ["crates/*", "crates/drop"]\n' >"$WORK/glob.members"
sed '/^members = /d' "$GLOB/Cargo.toml" >"$WORK/glob.manifest"
cat "$WORK/glob.manifest" "$WORK/glob.members" >"$GLOB/Cargo.toml"
agrees_with_cargo "$GLOB/Cargo.toml" explicit-excluded
cp "$WORK/glob.package" "$GLOB/Cargo.toml"
printf '[workspace]\nmembers = ["crates/README"]\n' >>"$GLOB/Cargo.toml"
agrees_with_cargo "$GLOB/Cargo.toml" file-match
mkdir "$GLOB/crates/missing"
for pattern in 'crates/*' 'crates/absent-*'; do
    cp "$WORK/glob.package" "$GLOB/Cargo.toml"
    printf '[workspace]\nmembers = ["%s"]\n' "$pattern" >>"$GLOB/Cargo.toml"
    for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
        if "$builder" metadata --no-deps --offline --format-version 1 \
            --manifest-path "$GLOB/Cargo.toml" >"$WORK/bad-glob.json" 2>"$WORK/bad-glob.err"; then
            echo "workspace-metadata: accepted a missing member manifest or unmatched glob" >&2
            exit 1
        fi
    done
done
cp "$WORK/glob.package" "$GLOB/Cargo.toml"
printf '[workspace]\nmembers = ["crates/**"]\n' >>"$GLOB/Cargo.toml"
if source_metadata "$GLOB/Cargo.toml" >"$WORK/recursive.json" 2>"$WORK/recursive.err"; then exit 1; fi
grep -F 'unsupported workspace member pattern' "$WORK/recursive.err" >/dev/null
mkdir "$WORK/empty-virtual"
printf '[workspace]\n' >"$WORK/empty-virtual/Cargo.toml"
printf '[workspace.metadata]\nempty = true\n' >>"$WORK/empty-virtual/Cargo.toml"
agrees_with_cargo "$WORK/empty-virtual/Cargo.toml" empty-virtual
echo "PASS: Cargo member globs, exclusions, file matches, and empty workspaces"

INHERIT="$WORK/dependencies"
package "$INHERIT/app"
package "$INHERIT/shared"
cat >>"$INHERIT/shared/Cargo.toml" <<'EOF'
[features]
default = ["default-on"]
default-on = []
base = []
extra = []
EOF
for defaults in unspecified true false; do
    cat >"$INHERIT/Cargo.toml" <<'EOF'
[workspace]
members = ["app"]
resolver = "2"
[workspace.dependencies]
renamed = { package = "shared", path = "shared", features = ["base"] }
[workspace.dependencies.shared]
path = "shared"
features = ["base"]
EOF
    if [ "$defaults" != unspecified ]; then
        printf 'default-features = %s\n' "$defaults" >>"$INHERIT/Cargo.toml"
    fi
    for edition in 2021 2024; do
        cat >"$INHERIT/app/Cargo.toml" <<EOF
[package]
name = "app"
version = "0.1.0"
edition = "$edition"
[dependencies]
shared = { workspace = true, features = ["extra"], default-features = false }
renamed = { workspace = true, optional = true }
[build-dependencies]
shared.workspace = true
[dev-dependencies]
shared = { workspace = true, default-features = true }
[target.'cfg(unix)'.dependencies]
shared.workspace = true
EOF
        agrees_with_cargo "$INHERIT/Cargo.toml" "dependencies-$defaults-$edition"
        source_metadata "$INHERIT/Cargo.toml" >"$WORK/inherited.json" 2>"$WORK/inherited.err"
        if [ "$edition" = 2021 ] && [ "$defaults" != false ]; then
            [ "$(grep -Fc 'default-features` is ignored for shared' "$WORK/inherited.err")" -eq 1 ]
            source_metadata "$INHERIT/Cargo.toml" --quiet >"$WORK/quiet.json" 2>"$WORK/quiet.err"
            [ ! -s "$WORK/quiet.err" ]
        else
            [ ! -s "$WORK/inherited.err" ]
        fi
    done
done
cp "$INHERIT/Cargo.toml" "$WORK/dependencies.valid"
for invalid in missing optional; do
    cp "$WORK/dependencies.valid" "$INHERIT/Cargo.toml"
    if [ "$invalid" = missing ]; then
        sed -i 's/shared.workspace = true/missing.workspace = true/' "$INHERIT/app/Cargo.toml"
    else
        printf '\n[workspace.dependencies.unused]\nversion = "1"\noptional = true\n' >>"$INHERIT/Cargo.toml"
    fi
    for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
        if "$builder" metadata --no-deps --offline --format-version 1 \
            --manifest-path "$INHERIT/Cargo.toml" >"$WORK/dependency-invalid.json" 2>"$WORK/dependency-invalid.err"; then
            echo "workspace-metadata: accepted an invalid inherited dependency" >&2
            exit 1
        fi
    done
    sed -i 's/missing.workspace = true/shared.workspace = true/' "$INHERIT/app/Cargo.toml"
done
echo "PASS: Cargo dependency inheritance, additive features, and edition-specific defaults"
cp "$WORK/dependencies.valid" "$INHERIT/Cargo.toml"
cp "$INHERIT/app/Cargo.toml" "$WORK/member.valid"
for setting in patch replace; do
    cp "$WORK/member.valid" "$INHERIT/app/Cargo.toml"
    if [ "$setting" = patch ]; then
        printf '\n[patch.crates-io]\nshared = { path = "../shared" }\n' >>"$INHERIT/app/Cargo.toml"
    else
        printf '\n[replace]\n"shared:0.1.0" = { path = "../shared" }\n' >>"$INHERIT/app/Cargo.toml"
    fi
    agrees_with_cargo "$INHERIT/Cargo.toml" "ignored-$setting"
    source_metadata "$INHERIT/Cargo.toml" >"$WORK/ignored.json" 2>"$WORK/ignored.err"
    [ "$(grep -Fc "$setting for the non root package will be ignored" "$WORK/ignored.err")" -eq 1 ]
done
cp "$WORK/member.valid" "$INHERIT/app/Cargo.toml"
sed -i '/resolver = "2"/d' "$INHERIT/Cargo.toml"
source_metadata "$INHERIT/Cargo.toml" >"$WORK/resolver.json" 2>"$WORK/resolver.err"
[ "$(grep -Fc 'virtual workspace defaulting to `resolver = "1"`' "$WORK/resolver.err")" -eq 1 ]
RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" metadata --no-deps --offline --format-version 1 \
    --manifest-path "$INHERIT/Cargo.toml" >"$WORK/resolver.cargo.json" 2>"$WORK/resolver.cargo.err"
grep -F 'virtual workspace defaulting to `resolver = "1"`' "$WORK/resolver.cargo.err" >/dev/null
echo "PASS: ignored member settings and virtual workspace resolver warnings"
printf '\n[workspace]\n' >>"$INHERIT/app/Cargo.toml"
for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
    if "$builder" metadata --no-deps --offline --format-version 1 \
        --manifest-path "$INHERIT/Cargo.toml" >"$WORK/nested.json" 2>"$WORK/nested.err"; then
        echo "workspace-metadata: accepted multiple workspace roots" >&2
        exit 1
    fi
done
