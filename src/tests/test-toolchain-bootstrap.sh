#!/usr/bin/env bash
# Offline checks of the release builder's Motor OS checkout and compiler handoff.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "${MOTOR_TOOLCHAIN_SOURCE:-$ROOT/../motor-os-toolchain}/build-toolchain.sh"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
fail() { echo "test-toolchain-bootstrap: $*" >&2; exit 1; }
log() { :; }
WORK="$temporary/build"
seed="$temporary/local Motor OS"
mkdir -p "$seed/src" "$WORK"
git init -q -b main "$seed"
cat > "$seed/src/build-motor-os.sh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$HANDOFF"
EOF
git -C "$seed" add src
git -C "$seed" -c user.name=Test -c user.email=test@example.com commit -qm fixture
MOTOR_OS_REPOSITORY="$seed"
MOTOR_OS_BRANCH=main
parse_options
fetch_motor_source
[ "$MOTOR_SOURCE" = "$WORK/motor-os" ] || fail 'default checkout is outside the build tree'
[ "$(git -C "$MOTOR_SOURCE" rev-parse HEAD)" = "$(git -C "$seed" rev-parse HEAD)" ] ||
    fail 'default checkout did not clone the selected branch'

# A local override uses the actual working tree, preserving uncommitted work.
printf 'local changes\n' > "$seed/uncommitted"
parse_options --motor-os "$seed" --dev
toolchain_fetch_branch() { fail 'local override unexpectedly fetched sources'; }
fetch_motor_source
[ "$MOTOR_SOURCE" = "$seed" ] && [ "$DEV" = true ] || fail 'local override was lost'
[ "$(cat "$seed/uncommitted")" = 'local changes' ] || fail 'local work was changed'
export HANDOFF="$temporary/handoff"
TOOLCHAIN_PREFIX="$temporary/new compiler"
TOOLCHAIN_IMAGES="$temporary/images"
build_motor_tools
printf '%s\n' --toolchain-overlays "$TOOLCHAIN_PREFIX" "$TOOLCHAIN_IMAGES" > "$temporary/expected"
cmp "$temporary/expected" "$HANDOFF" || fail 'build did not receive the new compiler and output paths'

if (parse_options --motor-os "$WORK/motor-os") > "$temporary/error" 2>&1; then
    fail 'accepted a local checkout that the build would delete'
fi
grep -q 'outside the disposable build directory' "$temporary/error" || fail 'wrong checkout diagnostic'
if (parse_options --motor-os) > "$temporary/error" 2>&1; then
    fail 'accepted --motor-os without a path'
fi

# The main checkout selects the compiler by path before running its overlay
# stage, even though rust-toolchain.toml names an older release. No VM or
# native archive is required for this mode.
(
    source "$ROOT/src/build-motor-os.sh"
    selected="$(rustc --print sysroot)"
    build_toolchain_overlays() {
        [ "$RUSTUP_TOOLCHAIN" = "$selected" ] || fail 'used the checkout toolchain selector'
        [ "$(rustc --print sysroot)" = "$selected" ] || fail 'rustup did not use the compiler directory'
        [ "$SYSROOT" = "$selected/lib/rustlib/x86_64-unknown-motor/sysroot" ] || fail 'wrong C sysroot'
        [ "$TOOLCHAIN_OVERLAY_OUTPUT" = "$temporary/overlays" ] || fail 'wrong overlay destination'
        select_external_sources toolchain
        [ "${#EXTERNAL_REPOS[@]}" -eq 4 ] || fail 'wrong development source set'
        case " ${EXTERNAL_REPOS[*]} " in
            *ripgrep:*|*motor-os-tar:*) fail 'selected unrelated image sources';;
        esac
        printf done > "$temporary/built"
    }
    NATIVE_ARCHIVE="$temporary/no-native-archive"
    main --toolchain-overlays "$selected" "$temporary/overlays"
    [ -f "$temporary/built" ] || fail 'overlay stage was skipped'
    if (main --javy-only --toolchain-overlays "$selected" "$temporary/overlays") > "$temporary/error" 2>&1; then
        fail 'accepted incompatible build modes'
    fi
)
echo 'test-toolchain-bootstrap PASS'
