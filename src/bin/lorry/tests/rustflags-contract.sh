#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: rustflags-contract.sh LORRY" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LORRY="$(realpath "$1")"
if [ -z "${LORRY_TEST_CARGO:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
CARGO="$LORRY_TEST_CARGO"
REAL_RUSTC="$LORRY_TEST_RUSTC"
HOST="$($REAL_RUSTC -vV | sed -n 's/^host: //p')"
HOST_ENV="${HOST^^}"
HOST_ENV="${HOST_ENV//-/_}"
WORK="$(mktemp -d /tmp/lorry-rustflags-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
HOME_DIR="$WORK/home"
PROJECT="$WORK/project"
mkdir -p "$HOME_DIR/.config/lorry" "$PROJECT/src" "$PROJECT/.cargo" "$PROJECT/dep/src"

fail() {
    echo "rustflags-contract: $*" >&2
    exit 1
}

cat >"$HOME_DIR/.config/lorry/lorry.toml" <<EOF
config-version = 1
cargo-compat-version = "1.99"
[cache]
directory = "$WORK/cache"
[policy.rules.rustflags-build-script]
action = "allow"
name = "rustflags-dependency"
version = "=0.1.0"
source = "path"
allow-build-script = true
EOF
cat >"$PROJECT/Cargo.toml" <<'EOF'
[package]
name = "rustflags-fixture"
version = "0.1.0"
edition = "2024"

[dependencies]
rustflags-dependency = { path = "dep" }
EOF
cat >"$PROJECT/src/main.rs" <<'EOF'
fn main() {
    rustflags_dependency::dependency();
}
EOF
cat >"$PROJECT/dep/Cargo.toml" <<'EOF'
[package]
name = "rustflags-dependency"
version = "0.1.0"
edition = "2024"
build = "build.rs"
EOF
cat >"$PROJECT/dep/src/lib.rs" <<'EOF'
pub fn dependency() {}
EOF
cat >"$PROJECT/dep/build.rs" <<'EOF'
fn main() {
    let out = std::env::var_os("OUT_DIR").expect("output directory");
    let flags = std::env::var("CARGO_ENCODED_RUSTFLAGS").expect("encoded rustflags");
    std::fs::write(std::path::PathBuf::from(out).join("rustflags.seen"), flags)
        .expect("write rustflags evidence");
}
EOF
cat >"$WORK/rustc-trace" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
: "${REAL_RUSTC:?}"
: "${RUSTFLAGS_TRACE:?}"

kind=""
for argument in "$@"; do
    case "$argument" in
        build.rs | */build.rs) kind="build-script" ;;
        src/main.rs | */src/main.rs) kind="root" ;;
        dep/src/lib.rs | */dep/src/lib.rs) kind="dependency" ;;
    esac
done

if [ -n "$kind" ]; then
    {
        printf '%s' "$kind"
        for argument in "$@"; do
            case "$argument" in
                --cfg=lorry_rf_*)
                    printf '\t'
                    printf '%s' "$argument" | od -An -v -tx1 | tr -d ' \n'
                    ;;
            esac
        done
        printf '\n'
    } >>"$RUSTFLAGS_TRACE"
fi

filtered=()
for argument in "$@"; do
    case "$argument" in
        --cfg=lorry_rf_*) ;;
        *) filtered+=("$argument") ;;
    esac
done
exec "$REAL_RUSTC" "${filtered[@]}"
EOF
chmod +x "$WORK/rustc-trace"

write_config() {
    case "$1" in
        build)
            cat >"$PROJECT/.cargo/config.toml" <<'EOF'
[build]
rustflags = ["--cfg=lorry_rf_build"]
EOF
            ;;
        target | environment)
            cat >"$PROJECT/.cargo/config.toml" <<EOF
[build]
rustflags = ["--cfg=lorry_rf_build"]
[target.$HOST]
rustflags = ["--cfg=lorry_rf_exact"]
[target.'cfg(target_pointer_width = "64")']
rustflags = ["--cfg=lorry_rf_pointer"]
[target.'cfg(unix)']
rustflags = ["--cfg=lorry_rf_unix"]
EOF
            ;;
        *) fail "unknown configuration case '$1'" ;;
    esac
}

run_case() {
    local name="$1" configuration="$2" target_mode="$3" variable="$4" value="$5"
    local cargo_trace="$WORK/$name.cargo.trace"
    local lorry_trace="$WORK/$name.lorry.trace"
    local cargo_env="$WORK/$name.cargo.env"
    local lorry_env="$WORK/$name.lorry.env"
    local cargo_seen lorry_seen
    local -a target=() selected_env=()
    [ "$target_mode" = host ] && target=(--target "$HOST")
    [ -z "$variable" ] || selected_env+=("$variable=$value")
    write_config "$configuration"

    : >"$cargo_trace"
    (
        cd "$PROJECT"
        env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS \
            -u "CARGO_TARGET_${HOST_ENV}_RUSTFLAGS" \
            HOME="$HOME_DIR" CARGO_HOME="$HOME_DIR/.cargo" \
            REAL_RUSTC="$REAL_RUSTC" RUSTFLAGS_TRACE="$cargo_trace" \
            RUSTC="$WORK/rustc-trace" "${selected_env[@]}" \
            "$CARGO" build --locked --offline \
                --target-dir "$WORK/cargo-$name" "${target[@]}"
    )
    cargo_seen="$(find "$WORK/cargo-$name" -name rustflags.seen -print -quit)"
    [ -n "$cargo_seen" ] || fail "$name Cargo build-script evidence is absent"
    cp "$cargo_seen" "$cargo_env"

    (
        cd "$PROJECT"
        HOME="$HOME_DIR" RUSTC="$REAL_RUSTC" "$LORRY" clean >/dev/null
    )
    : >"$lorry_trace"
    (
        cd "$PROJECT"
        env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS \
            -u "CARGO_TARGET_${HOST_ENV}_RUSTFLAGS" \
            HOME="$HOME_DIR" CARGO_HOME="$HOME_DIR/.cargo" LORRY_JOBS=1 \
            REAL_RUSTC="$REAL_RUSTC" RUSTFLAGS_TRACE="$lorry_trace" \
            RUSTC="$WORK/rustc-trace" "${selected_env[@]}" \
            "$LORRY" build "${target[@]}"
    )
    lorry_seen="$(find "$PROJECT/target/lorry" -name rustflags.seen -print -quit)"
    [ -n "$lorry_seen" ] || fail "$name Lorry build-script evidence is absent"
    cp "$lorry_seen" "$lorry_env"

    diff -u "$cargo_trace" "$lorry_trace" >&2 || fail "$name rustc argv differs from Cargo"
    cmp "$cargo_env" "$lorry_env" || fail "$name build-script environment differs from Cargo"
}

write_config build
(
    cd "$PROJECT"
    HOME="$HOME_DIR" RUSTC="$REAL_RUSTC" "$LORRY" vendor --accept-all
)

PLAIN_FLAGS=$'  --cfg=lorry_rf_plain  --cfg=lorry_rf_quote"literal --cfg=lorry_rf_back\\slash --cfg=lorry_rf_tab\tinside  '
ENCODED_FLAGS=$'--cfg=lorry_rf_encoded one\x1f--cfg=lorry_rf_second'
run_case build build native "" ""
run_case build-env build native CARGO_BUILD_RUSTFLAGS \
    "--cfg=lorry_rf_build_env"
run_case target target host "" ""
run_case target-env target host "CARGO_TARGET_${HOST_ENV}_RUSTFLAGS" \
    "--cfg=lorry_rf_target_env"
run_case plain environment native RUSTFLAGS "$PLAIN_FLAGS"
run_case encoded-empty environment native CARGO_ENCODED_RUSTFLAGS ""
run_case encoded environment native CARGO_ENCODED_RUSTFLAGS "$ENCODED_FLAGS"

echo "PASS: Lorry rustflags argv and build-script environment match Cargo"
