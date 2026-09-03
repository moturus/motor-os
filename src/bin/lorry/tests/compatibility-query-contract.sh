#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: compatibility-query-contract.sh LORRY" >&2
    exit 1
fi

LORRY="$(realpath "$1")"
WORK="$(mktemp -d /tmp/lorry-compatibility-query-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
HOME_DIR="$WORK/home"
PROJECT="$WORK/project"
mkdir -p "$HOME_DIR" "$PROJECT/src" "$PROJECT/.cargo"

fail() {
    echo "compatibility-query-contract: $*" >&2
    exit 1
}

cat >"$PROJECT/Cargo.toml" <<'EOF'
[package]
name = "compatibility-query-fixture"
version = "0.1.0"
edition = "2024"
EOF
cat >"$PROJECT/src/lib.rs" <<'EOF'
pub fn answer() -> u32 { 42 }
EOF
cat >"$PROJECT/.cargo/config.toml" <<'EOF'
[build]
rustflags = ["--cfg=lorry_query_build"]
[target.x86_64-unknown-motor]
rustflags = ["--cfg=lorry_query_exact"]
[target.'cfg(target_pointer_width = "64")']
rustflags = ["--cfg=lorry_query_pointer"]
[target.'cfg(unix)']
rustflags = ["--cfg=lorry_query_unix"]
EOF
cp "$PROJECT/Cargo.toml" "$WORK/Cargo.toml.before"

RUSTC_LOG="$WORK/rustc.log"
cat >"$WORK/direct-rustc" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
: "${RUSTC_LOG:?}"
kind=target-cfg
for argument in "$@"; do
    [ "$argument" != "--version" ] || kind=version
    [ "$argument" != "-O" ] || kind=final-cfg
    [ "$argument" != "target-spec-json" ] || kind=final-target
done
{
    printf '%s' "$kind"
    for argument in "$@"; do printf '\t%s' "$argument"; done
    printf '\tENV:%s:%s:%s:%s\n' \
        "${RUSTUP_TOOLCHAIN-<unset>}" "${CARGO_LOG-<unset>}" \
        "${__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS-<unset>}" \
        "${RUSTC_BOOTSTRAP-<unset>}"
} >>"$RUSTC_LOG"
case "$kind" in
    version)
        printf 'rustc 1.99.0-dev\nrelease: 1.99.0-dev\nhost: x86_64-unknown-linux-gnu\n'
        ;;
    target-cfg)
        printf 'target_pointer_width="64"\nunix\n'
        ;;
    final-cfg)
        printf 'query_cfg_output\n'
        exit "${FAKE_CFG_STATUS:-0}"
        ;;
    final-target)
        printf '{"arch":"x86_64","os":"motor"}\n'
        ;;
esac
EOF
chmod +x "$WORK/direct-rustc"
: >"$RUSTC_LOG"

MANIFEST="$(realpath "$PROJECT/Cargo.toml")"
located="$(cd "$PROJECT" && HOME="$HOME_DIR" \
    "$LORRY" locate-project --workspace --manifest-path "$MANIFEST")"
[ "$located" = "{\"root\":\"$MANIFEST\"}" ] || fail "wrong locate-project output: $located"

mkdir -p "$WORK/workspace/app/src"
cat >"$WORK/workspace/Cargo.toml" <<'EOF'
[workspace]
members = ["app"]
resolver = "2"
EOF
cat >"$WORK/workspace/app/Cargo.toml" <<'EOF'
[package]
name = "selected-app"
version = "0.1.0"
edition = "2024"
EOF
cat >"$WORK/workspace/app/src/lib.rs" <<'EOF'
pub fn selected() {}
EOF
MEMBER_MANIFEST="$(realpath "$WORK/workspace/app/Cargo.toml")"
located="$(cd "$WORK/workspace/app" && HOME="$HOME_DIR" \
    "$LORRY" locate-project --workspace --manifest-path "$MEMBER_MANIFEST")"
[ "$located" = "{\"root\":\"$MEMBER_MANIFEST\"}" ] || \
    fail "locate-project did not preserve the selected member"
if (cd "$WORK/workspace" && HOME="$HOME_DIR" "$LORRY" locate-project \
    --workspace --manifest-path "$WORK/workspace/Cargo.toml") >/dev/null 2>&1; then
    fail "locate-project accepted a virtual workspace manifest"
fi

common_environment=(
    HOME="$HOME_DIR"
    RUSTC="$WORK/direct-rustc"
    RUSTC_LOG="$RUSTC_LOG"
    RUSTUP_TOOLCHAIN=ambient-toolchain
    CARGO_LOG=trace
    __CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS=nightly
    RUSTC_BOOTSTRAP=ambient-bootstrap
)
cfg="$(cd "$PROJECT" && env "${common_environment[@]}" "$LORRY" rustc \
    -Z unstable-options --print cfg --target x86_64-unknown-motor -- -O)"
[ "$cfg" = query_cfg_output ] || fail "cfg query did not copy rustc stdout"
target="$(cd "$PROJECT" && env "${common_environment[@]}" "$LORRY" rustc \
    -Z unstable-options --print target-spec-json --target x86_64-unknown-motor \
    -- -Z unstable-options)"
[ "$target" = '{"arch":"x86_64","os":"motor"}' ] || \
    fail "target-data query did not copy rustc stdout"

expected_flags=$'--cfg=lorry_query_exact\t--cfg=lorry_query_pointer\t--cfg=lorry_query_unix'
grep -F $'final-cfg\t--print\tcfg\t-O\t--target\tx86_64-unknown-motor\t'"$expected_flags" \
    "$RUSTC_LOG" >/dev/null || fail "cfg query rustc argv is wrong"
grep -F $'final-target\t--print\ttarget-spec-json\t--target\tx86_64-unknown-motor\t-Z\tunstable-options\t'"$expected_flags" \
    "$RUSTC_LOG" >/dev/null || fail "target-data query rustc argv is wrong"
if grep -v 'final-target' "$RUSTC_LOG" | grep -v 'ENV:<unset>:<unset>:<unset>:<unset>$' >/dev/null; then
    fail "Cargo client environment leaked into an ordinary rustc invocation"
fi
grep 'final-target' "$RUSTC_LOG" | grep 'ENV:<unset>:<unset>:<unset>:1$' >/dev/null || \
    fail "target-data query did not set only RUSTC_BOOTSTRAP=1"

set +e
failed="$(cd "$PROJECT" && env "${common_environment[@]}" FAKE_CFG_STATUS=7 \
    "$LORRY" rustc -Z unstable-options --print cfg \
    --target x86_64-unknown-motor -- -O)"
status=$?
set -e
[ "$status" -eq 7 ] || fail "cfg query status $status was not copied from rustc"
[ "$failed" = query_cfg_output ] || fail "failing cfg query lost rustc stdout"

before="$(wc -l <"$RUSTC_LOG")"
if (cd "$PROJECT" && env "${common_environment[@]}" "$LORRY" rustc \
    -Z unstable-options --print cfg --target x86_64-unknown-motor -- -g) \
    >/dev/null 2>&1; then
    fail "unsupported cargo rustc form succeeded"
fi
after="$(wc -l <"$RUSTC_LOG")"
[ "$before" -eq "$after" ] || fail "unsupported query invoked rustc"
if "$LORRY" -Z unstable-options config get --format toml --show-origin >/dev/null 2>&1; then
    fail "Cargo config probe unexpectedly succeeded"
fi

mkdir -p "$WORK/proxy"
cat >"$WORK/proxy/rustup" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s|%s\n' "$*" "${RUSTUP_TOOLCHAIN-<unset>}" >>"$RUSTUP_LOG"
[ "$*" = "which rustc" ] || exit 2
printf '%s\n' "$DIRECT_RUSTC"
EOF
chmod +x "$WORK/proxy/rustup"
ln -s rustup "$WORK/proxy/rustc"
: >"$WORK/rustup.log"
(cd "$PROJECT" && env -u RUSTC HOME="$HOME_DIR" PATH="$WORK/proxy:$PATH" \
    DIRECT_RUSTC="$WORK/direct-rustc" RUSTC_LOG="$RUSTC_LOG" \
    RUSTUP_LOG="$WORK/rustup.log" RUSTUP_TOOLCHAIN=proxy-toolchain \
    "$LORRY" rustc -Z unstable-options --print cfg \
    --target x86_64-unknown-motor -- -O) >/dev/null
grep -Fx 'which rustc|proxy-toolchain' "$WORK/rustup.log" >/dev/null || \
    fail "rustup proxy resolution did not receive RUSTUP_TOOLCHAIN"
tail -n 3 "$RUSTC_LOG" | grep -v 'ENV:<unset>:<unset>:<unset>:<unset>$' >/dev/null && \
    fail "resolved direct compiler received rustup proxy environment"

cmp "$WORK/Cargo.toml.before" "$PROJECT/Cargo.toml" || fail "query changed Cargo.toml"
[ ! -e "$PROJECT/target" ] || fail "read-only query created build artifacts"
echo "PASS: Lorry compatibility queries are exact and read-only"
