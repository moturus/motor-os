#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: workspace-contract.sh LORRY" >&2
    exit 1
fi

LORRY="$(realpath "$1")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${LORRY_TEST_RUSTC:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
export RUSTC="$LORRY_TEST_RUSTC"
WORK="$(mktemp -d /tmp/lorry-workspace-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME:?}/.rustup}"
export CARGO_HOME="${CARGO_HOME:-${HOME:?}/.cargo}"
mkdir -p "$WORK/home/.config/lorry" "$WORK/project/app/src" \
    "$WORK/project/tool/src" "$WORK/project/shared/src" "$WORK/project/scripted/src"
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" \
    >"$WORK/home/.config/lorry/lorry.toml"
export HOME="$WORK/home"

printf '%s\n' \
    '[workspace]' \
    'members = ["a[p]p", "to?l", "script*"]' \
    'default-members = ["tool"]' \
    'resolver = "2"' \
    '[workspace.package]' \
    'version = "0.1.0"' \
    'edition = "2024"' \
    'rust-version = "1.85.0"' \
    '[workspace.dependencies]' \
    'shared = { path = "shared" }' \
    '' \
    '[profile.dev]' \
    'panic = "abort"' >"$WORK/project/Cargo.toml"
printf '%s\n' \
    'version = 4' \
    '[[package]]' \
    'name = "app"' \
    'version = "0.1.0"' \
    '[[package]]' \
    'name = "tool"' \
    'version = "0.1.0"' \
    'dependencies = [' \
    ' "shared",' \
    ']' \
    '[[package]]' \
    'name = "shared"' \
    'version = "0.1.0"' \
    '[[package]]' \
    'name = "scripted"' \
    'version = "0.1.0"' >"$WORK/project/Cargo.lock"
for package in app tool; do
    printf '%s\n' \
        '[package]' \
        "name = \"$package\"" \
        'version.workspace = true' \
        'edition.workspace = true' \
        'rust-version.workspace = true' >"$WORK/project/$package/Cargo.toml"
    printf 'fn main() { println!("%s"); }\n' "$package" \
        >"$WORK/project/$package/src/main.rs"
done
cat >>"$WORK/project/app/Cargo.toml" <<'EOF'
resolver = "1"
[profile.dev]
opt-level = 3
[profile.release]
debug = true
EOF
printf '%s\n' \
    '[dependencies]' \
    'shared.workspace = true' >>"$WORK/project/tool/Cargo.toml"
printf 'fn main() { println!("{}", shared::VALUE); }\n' \
    >"$WORK/project/tool/src/main.rs"
printf '%s\n' \
    '[package]' \
    'name = "shared"' \
    'version.workspace = true' \
    'edition.workspace = true' \
    'rust-version.workspace = true' \
    '' \
    '[lib]' \
    'path = "src/lib.rs"' >"$WORK/project/shared/Cargo.toml"
printf 'pub const VALUE: &str = "tool";\n' >"$WORK/project/shared/src/lib.rs"
printf '%s\n' \
    '[package]' \
    'name = "scripted"' \
    'version = "0.1.0"' \
    'edition = "2024"' >"$WORK/project/scripted/Cargo.toml"
printf 'fn main() { println!("cargo:rustc-cfg=scripted"); }\n' \
    >"$WORK/project/scripted/build.rs"
printf 'fn main() {}\n' >"$WORK/project/scripted/src/main.rs"
mkdir "$WORK/project/app/examples"
printf 'fn main() {}\n' >"$WORK/project/app/examples/demo.rs"

(
    cd "$WORK/project"
    # Both readers discover shared through tool's path dependency, and the
    # singleton default selects tool without silently reducing a larger set.
    "$LORRY" metadata --no-deps --format-version 1 >"$WORK/members.lorry.json"
    "$LORRY_TEST_CARGO" metadata --no-deps --format-version 1 --offline >"$WORK/members.cargo.json"
    "$LORRY_TEST_CARGO" run --quiet --locked --offline \
        --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" -- compare-projection \
        "$WORK/members.lorry.json" "$WORK/members.cargo.json"
    "$LORRY" vendor -p app --accept-all
    "$LORRY" review -p app >/dev/null
    "$LORRY" -v build -j2 -p app 2>"$WORK/app-build.stderr"
    grep -F 'panic=abort' "$WORK/app-build.stderr" >/dev/null
    [ "$(grep -Fc 'profiles for the non root package will be ignored' "$WORK/app-build.stderr")" -eq 1 ]
    [ "$(grep -Fc 'resolver for the non root package will be ignored' "$WORK/app-build.stderr")" -eq 1 ]
    [ "$("$LORRY" run --jobs=default -p app)" = app ]
    "$LORRY" test -p app -- --quiet
    "$LORRY" check -p app --all-targets 2>"$WORK/all-targets.stderr"
    [ "$(grep -Fc 'note: --all-targets leaves out examples and benches' "$WORK/all-targets.stderr")" -eq 1 ]
    "$LORRY_TEST_CARGO" check -p app --all-targets --offline
    if "$LORRY" check -p app --examples 2>"$WORK/examples.stderr"; then exit 1; fi
    grep -F 'check --examples` is not supported' "$WORK/examples.stderr" >/dev/null
    "$LORRY" build --jobs=-1 -p app
    "$LORRY" build --jobs 1 -p tool 2>"$WORK/tool-build.stderr"
    [ "$("$LORRY" run)" = tool ]
    grep -F 'Verifying dependency state' "$WORK/tool-build.stderr" >/dev/null
    grep -F 'Preparing dependency graph' "$WORK/tool-build.stderr" >/dev/null
    grep -F 'Compiling shared v0.1.0' "$WORK/tool-build.stderr" >/dev/null
    grep -F '[library]' "$WORK/tool-build.stderr" >/dev/null
    grep -F 'Compiling tool v0.1.0' "$WORK/tool-build.stderr" >/dev/null
    grep -F '[binary `tool`]' "$WORK/tool-build.stderr" >/dev/null
    "$LORRY" clean -p tool
    "$LORRY" --quiet build -p tool 2>"$WORK/quiet-build.stderr"
    [ ! -s "$WORK/quiet-build.stderr" ]
)
[ -x "$WORK/project/target/lorry/debug/app" ]
[ -x "$WORK/project/target/lorry/debug/tool" ]
(
    cd "$WORK"
    manifest="$WORK/project/Cargo.toml"
    "$LORRY" vendor --manifest-path "$manifest" -p app --accept-all
    "$LORRY" review --manifest-path "$manifest" -p app >/dev/null
    "$LORRY" build --manifest-path "$manifest" -p app
    [ "$("$LORRY" run --manifest-path "$manifest" -p app)" = app ]
    "$LORRY" test --manifest-path "$manifest" -p app --no-run
    "$LORRY" clean --manifest-path "$manifest" -p app
    "$LORRY" build --manifest-path "$manifest" -p app
    host="$("$RUSTC" -vV | sed -n 's/^host: //p')"
    "$LORRY" rustc -Z unstable-options --print cfg --target "$host" \
        --manifest-path "$manifest" >"$WORK/query.lorry"
    "$RUSTC" --print cfg -O --target "$host" >"$WORK/query.rustc"
    cmp "$WORK/query.lorry" "$WORK/query.rustc"
)
(
    cd "$WORK/project/app"
    [ "$("$LORRY" run)" = app ]
)
(
    cd "$WORK/project/app/src"
    [ "$("$LORRY" run)" = app ]
    "$LORRY" locate-project --message-format plain >"$WORK/locate.lorry"
    "$LORRY_TEST_CARGO" locate-project --message-format plain >"$WORK/locate.cargo"
    cmp "$WORK/locate.lorry" "$WORK/locate.cargo"
    "$LORRY" check --manifest-path ../../Cargo.toml -p shared --lib
    "$LORRY_TEST_CARGO" check --manifest-path ../../Cargo.toml -p shared --lib --offline
    for selector in shared@0 shared@0.1 shared@0.1.0 'sha*' \
        "path+file://$WORK/project/shared#0.1.0" \
        "file://$WORK/project/shared#shared@0.1"; do
        "$LORRY" check -p "$selector" --lib
        "$LORRY_TEST_CARGO" check -p "$selector" --lib --offline
    done
    for selector in shared@9 '^shared' "path+file://$WORK/other#shared@0.1.0"; do
        for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
            if "$builder" check -p "$selector" --offline 2>"$WORK/selector.err"; then exit 1; fi
        done
    done
    if "$LORRY" check -p 's*' --offline 2>"$WORK/selector.err"; then exit 1; fi
    grep -F 'selects 2 packages; multi-package execution is not yet supported' "$WORK/selector.err" >/dev/null
    "$LORRY_TEST_CARGO" check -p 's*' --offline
    for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
        if "$builder" run -p 'a*' --offline 2>"$WORK/run-selector.err"; then exit 1; fi
    done
)
(
    cd "$WORK/project"
    "$LORRY" clean -p app
)
[ ! -e "$WORK/project/target/lorry/debug/app" ]
[ -x "$WORK/project/target/lorry/debug/tool" ]

# Unused profiles may contain valid Cargo settings that Lorry cannot yet
# compile. Those settings must fail when their profile becomes effective.
cp "$WORK/project/Cargo.toml" "$WORK/profiles.baseline"
cat >>"$WORK/project/Cargo.toml" <<'EOF'
[profile.release]
opt-level = 3
[profile.custom]
inherits = "release"
debug = true
EOF
(
    cd "$WORK/project"
    "$LORRY" check -p tool
    "$LORRY_TEST_CARGO" check -p tool --offline
    if "$LORRY" build -p tool --release 2>"$WORK/profile.err"; then exit 1; fi
    grep -F 'unsupported selected profile key `profile.release.opt-level`' "$WORK/profile.err" >/dev/null
    sed '/^\[profile.dev\]$/a opt-level = 3' "$WORK/profiles.baseline" >Cargo.toml
    "$LORRY" build -p tool --release
    "$LORRY_TEST_CARGO" build -p tool --release --offline
    if "$LORRY" check -p tool 2>"$WORK/profile.err"; then exit 1; fi
    grep -F 'unsupported selected profile key `profile.dev.opt-level`' "$WORK/profile.err" >/dev/null
    cp "$WORK/profiles.baseline" Cargo.toml
    printf '\n[profile.test]\nopt-level = 3\n' >>Cargo.toml
    "$LORRY" build -p tool
    "$LORRY_TEST_CARGO" test -p tool --no-run --offline
    if "$LORRY" test -p tool --no-run 2>"$WORK/profile.err"; then exit 1; fi
    grep -F 'unsupported selected profile key `profile.test.opt-level`' "$WORK/profile.err" >/dev/null
)
cp "$WORK/profiles.baseline" "$WORK/project/Cargo.toml"

# Runtime metadata comes from the selected member, while run keeps its caller.
cat >"$WORK/project/app/src/main.rs" <<'EOF'
fn environment() {
    assert_eq!(std::env::var_os("CARGO").unwrap(), std::env::var_os("LORRY_EXPECT_CARGO").unwrap());
    let libraries = std::env::split_paths(&std::env::var_os("LD_LIBRARY_PATH").unwrap()).collect::<Vec<_>>();
    for name in ["LORRY_EXPECT_PROFILE", "LORRY_EXPECT_SYSROOT_LIB", "LORRY_EXPECT_INHERITED_LIB"] {
        let expected = std::path::PathBuf::from(std::env::var_os(name).unwrap());
        assert!(libraries.contains(&expected), "{name}: {libraries:?}");
    }
    for (name, expected) in [
        ("CARGO_MANIFEST_DIR", env!("CARGO_MANIFEST_DIR")),
        ("CARGO_MANIFEST_PATH", env!("CARGO_MANIFEST_PATH")),
        ("CARGO_PKG_NAME", env!("CARGO_PKG_NAME")),
        ("CARGO_PKG_VERSION", env!("CARGO_PKG_VERSION")),
        ("CARGO_PKG_VERSION_MAJOR", env!("CARGO_PKG_VERSION_MAJOR")),
        ("CARGO_PKG_VERSION_MINOR", env!("CARGO_PKG_VERSION_MINOR")),
        ("CARGO_PKG_VERSION_PATCH", env!("CARGO_PKG_VERSION_PATCH")),
        ("CARGO_PKG_VERSION_PRE", env!("CARGO_PKG_VERSION_PRE")),
        ("CARGO_PKG_AUTHORS", env!("CARGO_PKG_AUTHORS")),
        ("CARGO_PKG_DESCRIPTION", env!("CARGO_PKG_DESCRIPTION")),
        ("CARGO_PKG_HOMEPAGE", env!("CARGO_PKG_HOMEPAGE")),
        ("CARGO_PKG_LICENSE", env!("CARGO_PKG_LICENSE")),
        ("CARGO_PKG_LICENSE_FILE", env!("CARGO_PKG_LICENSE_FILE")),
        ("CARGO_PKG_README", env!("CARGO_PKG_README")),
        ("CARGO_PKG_REPOSITORY", env!("CARGO_PKG_REPOSITORY")),
        ("CARGO_PKG_RUST_VERSION", env!("CARGO_PKG_RUST_VERSION")),
    ] {
        assert_eq!(std::env::var(name).unwrap(), expected, "{name}");
    }
}

fn main() {
    if std::env::args().any(|arg| arg == "--print-libraries") {
        println!("{}", std::env::var("LD_LIBRARY_PATH").unwrap());
        return;
    }
    if std::env::args().any(|arg| arg == "--environment") {
        environment();
        assert_eq!(std::env::current_dir().unwrap(), std::path::Path::new(&std::env::var_os("LORRY_EXPECT_CWD").unwrap()));
    }
    println!("app");
}

#[test]
fn harness_environment() {
    environment();
    assert_eq!(std::env::current_dir().unwrap(), std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
}
EOF
mkdir -p "$WORK/project/app/tests"
cat >"$WORK/project/app/tests/environment.rs" <<'EOF'
#[test]
fn integration_environment() {
    assert_eq!(std::env::current_dir().unwrap(), std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
    assert_eq!(std::env::var("CARGO_MANIFEST_PATH").unwrap(), env!("CARGO_MANIFEST_PATH"));
    assert_eq!(std::env::var("CARGO_BIN_EXE_app").unwrap(), env!("CARGO_BIN_EXE_app"));
    assert_eq!(std::env::var_os("CARGO").unwrap(), std::env::var_os("LORRY_EXPECT_CARGO").unwrap());
}
EOF
export LORRY_EXPECT_CARGO="$LORRY"
export LORRY_EXPECT_PROFILE="$WORK/project/target/lorry/debug"
export LORRY_EXPECT_SYSROOT_LIB="$("$RUSTC" --print target-libdir)"
export LORRY_EXPECT_INHERITED_LIB="$WORK/inherited-libraries"
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}$LORRY_EXPECT_INHERITED_LIB"
(
    cd "$WORK/project"
    export LORRY_EXPECT_CWD="$PWD"
    [ "$(CARGO_PKG_NAME=stale "$LORRY" run -p app -- --environment)" = app ]
    [ "$(CARGO_PKG_NAME=stale "$LORRY" run -p app -- --environment)" = app ]
    "$LORRY" test -p app -- --quiet
    libraries="$("$LORRY" run -p app -- --print-libraries)"
    inherited="$(LD_LIBRARY_PATH="$libraries" "$LORRY" run -p app -- --print-libraries)"
    [ "$inherited" = "$libraries" ] || {
        echo "workspace-contract: runtime search paths duplicated an inherited Cargo prefix" >&2
        exit 1
    }
)
(
    cd "$WORK/project/app"
    export LORRY_EXPECT_CWD="$PWD"
    [ "$("$LORRY" run -- --environment)" = app ]
)

# Cargo rejects force-warn in a manifest, in both supported lint forms.
cp "$WORK/project/app/Cargo.toml" "$WORK/app-baseline.toml"
for declaration in 'unused = "force-warn"' \
    'unused = { level = "force-warn" }'; do
    cp "$WORK/app-baseline.toml" "$WORK/project/app/Cargo.toml"
    printf '\n[lints.rust]\n%s\n' "$declaration" >>"$WORK/project/app/Cargo.toml"
    if (cd "$WORK/project" && "$LORRY" build -p app) \
        2>"$WORK/force-warn.stderr"; then
        echo "workspace-contract: accepted force-warn manifest lint" >&2
        exit 1
    fi
    grep -F 'unsupported rustc lint level `force-warn`' \
        "$WORK/force-warn.stderr" >/dev/null
done
cp "$WORK/app-baseline.toml" "$WORK/project/app/Cargo.toml"

# A selected member's build script is never silently skipped.
for command in build check test run; do
    if (cd "$WORK/project" && "$LORRY" "$command" -p scripted) \
        2>"$WORK/scripted.stderr"; then
        echo "workspace-contract: $command ignored a member build script" >&2
        exit 1
    fi
    grep -F 'package `scripted` has a build script' "$WORK/scripted.stderr" >/dev/null || {
        cat "$WORK/scripted.stderr" >&2
        exit 1
    }
done
[ ! -e "$WORK/project/target/lorry/debug/scripted" ]

# The package limit skips members by directory, not by name: a nonmember
# below the root that shares a member's name still counts.
LIMITED="$WORK/limited"
mkdir -p "$LIMITED/app/src" "$LIMITED/one/src" "$LIMITED/three/src" \
    "$LIMITED/vendored/one/src" "$LIMITED/two/src"
printf '%s\n' '[workspace]' 'members = ["app", "one", "three"]' 'resolver = "2"' \
    'exclude = ["vendored", "two"]' \
    >"$LIMITED/Cargo.toml"
printf '%s\n' '[package]' 'name = "app"' 'version = "0.1.0"' 'edition = "2024"' \
    '[dependencies]' 'one = { path = "../vendored/one" }' 'two = { path = "../two" }' \
    'three = { path = "../three" }' >"$LIMITED/app/Cargo.toml"
for package in one:0.3.0:one three:0.1.0:three one:0.1.0:vendored/one two:0.1.0:two; do
    IFS=: read -r name version directory <<<"$package"
    printf '[package]\nname = "%s"\nversion = "%s"\nedition = "2024"\n' \
        "$name" "$version" >"$LIMITED/$directory/Cargo.toml"
    printf 'pub fn value() {}\n' >"$LIMITED/$directory/src/lib.rs"
done
printf 'pub fn value() {}\n' >"$LIMITED/app/src/lib.rs"
printf '%s\n' 'version = 4' \
    '[[package]]' 'name = "app"' 'version = "0.1.0"' \
    'dependencies = [' ' "one 0.1.0",' ' "three",' ' "two",' ']' \
    '[[package]]' 'name = "one"' 'version = "0.1.0"' \
    '[[package]]' 'name = "one"' 'version = "0.3.0"' \
    '[[package]]' 'name = "three"' 'version = "0.1.0"' \
    '[[package]]' 'name = "two"' 'version = "0.1.0"' >"$LIMITED/Cargo.lock"
cp "$WORK/home/.config/lorry/lorry.toml" "$WORK/config.backup"
cp "$LIMITED/Cargo.toml" "$WORK/limited.manifest"
sed '/^exclude = /d' "$WORK/limited.manifest" >"$LIMITED/Cargo.toml"
for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
    if "$builder" metadata --no-deps --format-version 1 --offline \
        --manifest-path "$LIMITED/Cargo.toml" >"$WORK/duplicate.json" 2>"$WORK/duplicate.err"; then
        echo "workspace-contract: accepted duplicate implicit member names" >&2
        exit 1
    fi
    grep -E 'two packages named `one`|duplicate package name `one`' "$WORK/duplicate.err" >/dev/null
done
cp "$WORK/limited.manifest" "$LIMITED/Cargo.toml"
"$LORRY_TEST_CARGO" metadata --no-deps --format-version 1 --offline \
    --manifest-path "$LIMITED/Cargo.toml" >"$WORK/limited.cargo.json"
limited_vendor() {
    cp "$WORK/config.backup" "$WORK/home/.config/lorry/lorry.toml"
    printf '%s\n' '[policy.limits]' "max-packages = $1" >>"$WORK/home/.config/lorry/lorry.toml"
    (cd "$LIMITED" && "$LORRY" vendor -p app --accept-all) 2>"$WORK/limited.stderr"
}
if limited_vendor 1; then
    echo "workspace-contract: a member's namesake was exempt from the package limit" >&2
    exit 1
fi
grep -F 'than the limit of 1' "$WORK/limited.stderr" >/dev/null || {
    cat "$WORK/limited.stderr" >&2
    exit 1
}
limited_vendor 2 || {
    cat "$WORK/limited.stderr" >&2
    echo "workspace-contract: a member counted toward the package limit" >&2
    exit 1
}
cp "$WORK/config.backup" "$WORK/home/.config/lorry/lorry.toml"

echo "PASS: selected members build, run, test, and clean; unsupported lint levels and member build scripts fail; the package limit matches members by directory"
