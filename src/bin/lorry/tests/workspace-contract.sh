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
export PATH="$(dirname "$RUSTC"):$PATH"
WORK="$(mktemp -d /tmp/lorry-workspace-contract-XXXXXX)"
trap 'status=$?; if [ "$status" = 0 ]; then rm -rf "$WORK"; else echo "Retained failed fixture: $WORK" >&2; fi' EXIT
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
    # The root record must cover every member compiled below, while leaving
    # the scripted member outside this ordinary execution contract.
    "$LORRY" vendor -p app -p tool -p shared --accept-all
    "$LORRY" review >/dev/null
    "$LORRY" -v build -j2 -p app 2>"$WORK/app-build.stderr"
    grep -F 'panic=abort' "$WORK/app-build.stderr" >/dev/null
    [ "$(grep -Fc 'profiles for the non root package will be ignored' "$WORK/app-build.stderr")" -eq 1 ]
    [ "$(grep -Fc 'resolver for the non root package will be ignored' "$WORK/app-build.stderr")" -eq 1 ]
    [ "$("$LORRY" run --jobs=default -p app)" = app ]
    "$LORRY" test -p app -- --quiet
    "$LORRY" check -p app --all-targets 2>"$WORK/all-targets.stderr"
    ! grep -F 'note: --all-targets leaves out examples and benches' "$WORK/all-targets.stderr"
    "$LORRY_TEST_CARGO" check -p app --all-targets --offline
    "$LORRY" check -p app --examples
    "$LORRY_TEST_CARGO" check -p app --examples --offline
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
    cd "$WORK/project"
    for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
        "$builder" check -p app -p app@0.1 --offline
        "$builder" check --workspace --exclude app --exclude 's*' --offline
        "$builder" check --workspace -p missing --exclude app --exclude 's*' --offline
        "$builder" check --workspace --exclude app --exclude 's*' --exclude missing \
            --offline 2>"$WORK/exclude.err"
        [ "$(grep -Fc 'warning: excluded package' "$WORK/exclude.err")" -eq 1 ]
        "$builder" check --quiet --workspace --exclude app --exclude 's*' --exclude missing \
            --offline 2>"$WORK/exclude-quiet.err"
        [ ! -s "$WORK/exclude-quiet.err" ]
        for selectors in '--workspace -p missing' '--workspace --exclude *' '--exclude app'; do
            # The pattern remains literal, including in Cargo's opt-out case.
            read -r -a options <<<"$selectors"
            if "$builder" check "${options[@]}" --offline 2>"$WORK/selection.err"; then exit 1; fi
        done
        if "$builder" run -p app -p app --offline 2>"$WORK/selection.err"; then exit 1; fi
    done
    "$LORRY" build -p app -p app@0.1
    "$LORRY" test -p app -p app --no-run
    for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
        "$builder" metadata --no-deps --format-version 1 --features 'unused,app/unknown optional?/feature' \
            -F 'unused, other' --all-features --no-default-features >"$WORK/features.$(basename "$builder").json"
        for invalid in 'dep:optional' 'package/feature/other'; do
            if "$builder" metadata --no-deps --features "$invalid" 2>"$WORK/features.err"; then exit 1; fi
        done
    done
    "$LORRY_TEST_CARGO" run --quiet --locked --offline \
        --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" -- compare-projection \
        "$WORK/features.lorry.json" "$WORK/features.cargo.json"
    for command in check build; do
        "$LORRY" "$command" -p app --no-default-features
        "$LORRY_TEST_CARGO" "$command" -p app --no-default-features --offline
    done
    "$LORRY" test -p app --no-default-features
    "$LORRY_TEST_CARGO" test -p app --no-default-features --offline
    for selectors in '-p app -p tool' '--workspace -p app --exclude scripted'; do
        read -r -a options <<<"$selectors"
        for command in check build clippy; do
            "$LORRY" "$command" "${options[@]}"
            "$LORRY_TEST_CARGO" "$command" "${options[@]}" --offline
        done
    done
)
(
    cd "$WORK"
    manifest="$WORK/project/Cargo.toml"
    "$LORRY" vendor --manifest-path "$manifest" -p app -p tool -p shared --accept-all
    "$LORRY" review --manifest-path "$manifest" >/dev/null
    "$LORRY" build --manifest-path "$manifest" -p app
    [ "$("$LORRY" run --manifest-path "$manifest" -p app)" = app ]
    "$LORRY" test --manifest-path "$manifest" -p app --no-run
    "$LORRY" clean --manifest-path "$manifest" -p app
    "$LORRY" build --manifest-path "$manifest" -p app
    host="$("$RUSTC" -vV | sed -n 's/^host: //p')"
    "$LORRY" rustc -Z unstable-options --print cfg --target "$host" \
        --manifest-path "$manifest" -- -O >"$WORK/query.lorry"
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
    grep -F 'workspace admission does not cover the requested packages or features of `scripted`' "$WORK/selector.err" >/dev/null || {
        cat "$WORK/selector.err" >&2
        exit 1
    }
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
rpath = true
[profile.custom]
inherits = "release"
debug = true
EOF
(
    cd "$WORK/project"
    "$LORRY" check -p tool
    "$LORRY_TEST_CARGO" check -p tool --offline
    if "$LORRY" build -p tool --release 2>"$WORK/profile.err"; then exit 1; fi
    grep -F 'unsupported selected profile key `profile.release.rpath`' "$WORK/profile.err" >/dev/null
    sed '/^\[profile.dev\]$/a rpath = true' "$WORK/profiles.baseline" >Cargo.toml
    "$LORRY" build -p tool --release
    "$LORRY_TEST_CARGO" build -p tool --release --offline
    if "$LORRY" check -p tool 2>"$WORK/profile.err"; then exit 1; fi
    grep -F 'unsupported selected profile key `profile.dev.rpath`' "$WORK/profile.err" >/dev/null
    cp "$WORK/profiles.baseline" Cargo.toml
    printf '\n[profile.test]\nopt-level = 3\n' >>Cargo.toml
    "$LORRY" build -p tool
    "$LORRY_TEST_CARGO" test -p tool --no-run --offline --message-format=json >"$WORK/cargo-profile.json"
    "$LORRY" test -p tool --no-run --message-format=json >"$WORK/lorry-profile.json"
    python3 - "$WORK/lorry-profile.json" "$WORK/cargo-profile.json" <<'PY'
import json, pathlib, sys
def harnesses(path):
    events = [event for line in open(path) for event in [json.loads(line)]
              if event['reason'] == 'compiler-artifact' and event['profile']['test']]
    assert events and all(event['profile']['opt_level'] == '3' for event in events)
    return sorted(pathlib.Path(event['executable']).read_bytes() for event in events)
assert harnesses(sys.argv[1]) == harnesses(sys.argv[2])
PY
    printf 'rpath = true\n' >>Cargo.toml
    if "$LORRY" test -p tool --no-run 2>"$WORK/profile.err"; then exit 1; fi
    grep -F 'unsupported selected profile key `profile.test.rpath`' "$WORK/profile.err" >/dev/null
)
cp "$WORK/profiles.baseline" "$WORK/project/Cargo.toml"

# Editable members retain Cargo's external reads, symlinks, and package
# boundaries in both compiler caches and the completed-profile shortcut.
cp "$WORK/project/shared/src/lib.rs" "$WORK/shared-source.baseline"
cp "$WORK/project/tool/src/main.rs" "$WORK/tool-source.baseline"
cp "$WORK/home/.config/lorry/lorry.toml" "$WORK/user-config.baseline"
printf '%s\n' '[policy.limits]' 'max-package-files = 1' \
    'max-extracted-package-bytes = 65536' >>"$WORK/home/.config/lorry/lorry.toml"
mkdir -p "$WORK/project/shared/foreign/src"
printf 'not a manifest\n' >"$WORK/project/shared/foreign/Cargo.toml"
printf 'outside-before' >"$WORK/project/external.txt"
printf 'link-before' >"$WORK/project/link-first.txt"
printf 'link-after' >"$WORK/project/link-second.txt"
head -c 70000 /dev/zero >"$WORK/project/shared/large-editable-input"
ln -s ../link-first.txt "$WORK/project/shared/link.txt"
cat >"$WORK/project/shared/src/lib.rs" <<'EOF'
pub const VALUE: &str = include_str!("../../external.txt");
pub const LINK: &str = include_str!("../link.txt");
EOF
printf 'fn main() { println!("{}|{}", shared::VALUE, shared::LINK); }\n' \
    >"$WORK/project/tool/src/main.rs"
(
    cd "$WORK/project"
    for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
        [ "$("$builder" run --quiet -p tool --offline)" = 'outside-before|link-before' ]
    done
    "$LORRY" -v build -p tool 2>"$WORK/member-first-build.err"
    "$LORRY" -v build -p tool 2>"$WORK/member-warm.err"
    grep -F 'Verifying dependency state' "$WORK/member-warm.err" >/dev/null
    if grep -E 'Preparing dependency graph|Compiling ' "$WORK/member-warm.err"; then
        echo 'workspace-contract: unchanged member build missed completed-profile freshness' >&2
        exit 1
    fi
    printf 'outside-after' >external.txt
    for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
        [ "$("$builder" run --quiet -p tool --offline)" = 'outside-after|link-before' ]
    done
    rm shared/link.txt
    ln -s ../link-second.txt shared/link.txt
    [ "$("$LORRY" run --quiet -p tool --offline)" = 'outside-after|link-after' ]
    # Cargo's mtime check misses retargets to an older file. Keep Lorry's
    # retarget probe warm, then use a cold Cargo build as the content oracle.
    "$LORRY_TEST_CARGO" clean -p shared
    [ "$("$LORRY_TEST_CARGO" run --quiet -p tool --offline)" = 'outside-after|link-after' ]
    "$LORRY" build --strict-validation -p tool
    "$LORRY" check -p tool
    "$LORRY" clean -p tool
    "$LORRY" -v build -p tool 2>"$WORK/member-cache.err"
    grep -F 'Fresh shared v0.1.0' "$WORK/member-cache.err" >/dev/null
    printf 'another-value' >external.txt
    [ "$("$LORRY" run --quiet -p tool)" = 'another-value|link-after' ]
)
cp "$WORK/shared-source.baseline" "$WORK/project/shared/src/lib.rs"
cp "$WORK/tool-source.baseline" "$WORK/project/tool/src/main.rs"
cp "$WORK/user-config.baseline" "$WORK/home/.config/lorry/lorry.toml"
rm -rf "$WORK/project/shared/foreign" "$WORK/project/shared/large-editable-input" \
    "$WORK/project/shared/link.txt"

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
    case "$command" in
        build | check | test | run) expected='workspace admission does not cover the requested packages or features of `scripted`' ;;
    esac
    grep -F "$expected" "$WORK/scripted.stderr" >/dev/null || {
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

# Keep-going must finish an independent member after a deterministic failure.
mkdir -p "$WORK/keep-going/"{a-fails,b-good}/src
printf '[workspace]\nmembers = ["a-fails", "b-good"]\nresolver = "2"\n' \
    >"$WORK/keep-going/Cargo.toml"
for package in a-fails b-good; do
    printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2024"\n' \
        "$package" >"$WORK/keep-going/$package/Cargo.toml"
done
printf 'compile_error!("expected member failure");\n' >"$WORK/keep-going/a-fails/src/lib.rs"
printf 'pub fn value() -> u8 { 42 }\n' >"$WORK/keep-going/b-good/src/lib.rs"
(
    cd "$WORK/keep-going"
    "$LORRY_TEST_CARGO" generate-lockfile --offline
    for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
        label="$(basename "$builder")"
        if "$builder" build --workspace --keep-going -j1 --offline --message-format=json \
            >"$WORK/keep-going.$label.json" 2>"$WORK/keep-going.$label.err"; then
            echo 'workspace-contract: keep-going ignored a failed member' >&2
            exit 1
        fi
        grep -F 'expected member failure' "$WORK/keep-going.$label.json" >/dev/null
    done
)
python3 - "$WORK/keep-going.lorry.json" "$WORK/keep-going.cargo.json" <<'PY_KEEP_GOING'
import json, sys
for path in sys.argv[1:]:
    messages = [json.loads(line) for line in open(path)]
    good = [message for message in messages if message['reason'] == 'compiler-artifact'
            and message['target']['name'] == 'b_good']
    assert len(good) == 1, (path, messages)
    assert all(__import__('os').path.isfile(name) for name in good[0]['filenames'])
    if path.endswith('lorry.json'):
        failure = next(i for i, message in enumerate(messages)
                       if message['reason'] == 'compiler-message'
                       and 'expected member failure' in message['message']['message'])
        assert failure < messages.index(good[0]), messages
    assert messages[-1] == {'reason': 'build-finished', 'success': False}, messages[-1]
PY_KEEP_GOING

# Cargo warns about equal top-level binary names while compiling both owners.
mkdir -p "$WORK/collision/"{first,second}/src
printf '[workspace]\nmembers = ["first", "second"]\nresolver = "2"\n' \
    >"$WORK/collision/Cargo.toml"
for package in first second; do
    printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2024"\n[[bin]]\nname = "same"\npath = "src/main.rs"\n' \
        "$package" >"$WORK/collision/$package/Cargo.toml"
    printf 'fn main() { println!("%s"); }\n' "$package" >"$WORK/collision/$package/src/main.rs"
done
(
    cd "$WORK/collision"
    "$LORRY_TEST_CARGO" generate-lockfile --offline
    for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
        label="$(basename "$builder")"
        "$builder" build --workspace --offline --message-format=json \
            >"$WORK/collision.$label.json" 2>"$WORK/collision.$label.err"
        grep -F 'output filename collision' "$WORK/collision.$label.err" >/dev/null
        grep -F 'package `first v0.1.0' "$WORK/collision.$label.err" >/dev/null
        grep -F 'package `second v0.1.0' "$WORK/collision.$label.err" >/dev/null
        "$builder" build --workspace --offline --quiet 2>"$WORK/collision.quiet.err"
        test ! -s "$WORK/collision.quiet.err"
    done
)
python3 - "$WORK/collision.lorry.json" "$WORK/collision.cargo.json" <<'PY_COLLISION'
import json, os, sys
for path in sys.argv[1:]:
    messages = [json.loads(line) for line in open(path)]
    artifacts = [message for message in messages if message['reason'] == 'compiler-artifact']
    assert len(artifacts) == 2, (path, messages)
    assert len({message['package_id'] for message in artifacts}) == 2
    assert all(os.path.isfile(message['executable']) for message in artifacts)
    assert messages[-1] == {'reason': 'build-finished', 'success': True}
PY_COLLISION

mkdir -p "$WORK/examples-only/examples"
cat >"$WORK/examples-only/Cargo.toml" <<'EOF'
[package]
name = "examples-only"
version = "0.1.0"
edition = "2024"
EOF
printf 'fn main() {}\n' >"$WORK/examples-only/examples/demo.rs"
(
    cd "$WORK/examples-only"
    "$LORRY_TEST_CARGO" generate-lockfile --offline
    "$LORRY" check --examples --message-format=json >"$WORK/examples-only.lorry.json"
    "$LORRY_TEST_CARGO" check --examples --offline --message-format=json >"$WORK/examples-only.cargo.json"
    "$LORRY_TEST_CARGO" run --quiet --locked --offline \
        --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" -- differential-workspace-check-messages \
        "$WORK/examples-only.lorry.json" "$WORK/examples-only.cargo.json"
)

echo "PASS: selected members build, run, test, and clean; unsupported lint levels and member build scripts fail; the package limit matches members by directory"
