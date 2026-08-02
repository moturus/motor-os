#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LORRY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$LORRY_DIR/../../.." && pwd)"
BOOTSTRAP="$LORRY_DIR/bootstrap"
CURL_DIR="$ROOT_DIR/src/bin/curl"
MOTO_RT_DIR="$ROOT_DIR/src/sys/lib/moto-rt"
MOTOR_TARGET="x86_64-unknown-motor"
MOTOR_TOOLCHAIN="${LORRY_MOTOR_TOOLCHAIN:-dev-x86_64-unknown-motor}"
MOTOR_LINKER="${LORRY_MOTOR_LINKER:-/home/posk/motor-dev/motor-sysroot/bin/motor-clang}"
MOTOR_SYSROOT="${LORRY_MOTOR_SYSROOT:-$ROOT_DIR/img_files/generated/rustc/sys/tools/rust}"
MOTOR_C_COMPILER="${LORRY_MOTOR_C_COMPILER:-/home/posk/motor-dev/llvm-project/build/bin/clang}"
MOTOR_C_SYSROOT="${LORRY_MOTOR_C_SYSROOT:-/home/posk/motor-dev/motor-sysroot}"
MOTOR_ARCHIVER="${LORRY_MOTOR_ARCHIVER:-/home/posk/motor-dev/llvm-project/build/bin/llvm-ar}"
BUILD_REPOSITORY="$ROOT_DIR/build/lorry/stage2/system-seed"
DOWNLOAD_CACHE="$ROOT_DIR/build/lorry/stage2/download-cache"

# Dated curl conversion of Mozilla's root store, licensed under MPL-2.0.
CA_URL="https://curl.se/ca/cacert-2026-07-16.pem"
CA_SHA256="3ff344e30b9b1ed2971044eabb438a08f2e2245ddb5f8ab1a3ad8b63ab4eaf91"
RING_SHA256="c05dbfa4d748bce2b66093633c0a644cc1e5f480d73f3b0a975e409f69386af6"
CC_SHA256="c4d4a87a32f84d17bfabe7dcaa0bbd75986053a18c97448aa80d394afce214b0"
MINIMAL_SEED_FINGERPRINT="32f6225b7a324eba5c1d69e1db894634e231b95eabc116c19944073a30c8eefe"
REMOTE_ROOT="/user/tmp/lorry-motor-crates-io"
REGISTRY_PREFIXES="13 3c 5b 61 68 76 8e 93 9f dc e1 f8 ff"
REGISTRY_IDENTITIES=(
    "cfg-if|1.0.4|9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801"
    "find-msvc-tools|0.1.9|5baebc0774151f905a1a2cc41989300b1e6fbb29aff0ceffa1064fdd3088d582"
    "getrandom|0.2.17|ff2abc00be7fca6ebc474524697ae276ad847ad0a6b3faa4bcb027e9a4614ad0"
    "libc|0.2.186|68ab91017fe16c622486840e4c83c9a37afeff978bd239b5293d61ece587de66"
    "once_cell|1.21.4|9f7c3e4beb33f85d45ae3e3a1792185706c8e16d043238c593331cc7cd313b50"
    "rustls|0.23.42|3c54fcab019b409d04215d3a17cb438fd7fbf192ee61461f20f4fe18704bc138"
    "rustls-pemfile|2.2.0|dce314e5fee3f39953d46bb63bb8a46d40c2f8fb7cc5a3b6cab2bde9721d6e50"
    "rustls-pki-types|1.15.0|764899a24af3980067ee14bc143654f297b22eaebfe3c7b6b211920a5a59b046"
    "rustls-webpki|0.103.13|61c429a8649f110dddef65e2a5ad240f747e85f7758a6bccc7e5777bd33f756e"
    "shlex|2.0.1|f8fadd59c855ef2080decdef8ff161eb6661b86933c9d82e5ba29dc602a55aba"
    "subtle|2.6.1|13c2bddecc57b384dee18652358fb23172facb8a2c51ccc10d74c157bdea3292"
    "untrusted|0.9.0|8ecb6da28b8a351d773b68d5825ac39017e680750f980f3a1a85cd8dd28a47c1"
    "zeroize|1.9.0|e13c156562582aa81c60cb29407084cdb54c4164760106ab78e6c5b0858cf64e"
)

if [ "${LORRY_TEST_MOTOR_CRATES_IO:-0}" != "1" ]; then
    echo "SKIP: set LORRY_TEST_MOTOR_CRATES_IO=1 to run Motor crates.io provisioning"
    exit 0
fi

BUILD="debug"
case "${1:-}" in
    "") ;;
    --release) BUILD="release" ;;
    *)
        echo "usage: motor-crates-io.sh [--release]" >&2
        exit 1
        ;;
esac

WORK="$(mktemp -d /tmp/lorry-motor-crates-io-XXXXXX)"
SCAFFOLD="$WORK/scaffold"
QEMU_LOG="$WORK/qemu.log"
VM_PID=""

fail() {
    echo "motor-crates-io: $*" >&2
    exit 1
}

cleanup() {
    local status="$?"
    trap - EXIT
    set +e
    if [ -n "$VM_PID" ]; then
        timeout 3 "${SSH[@]}" shutdown >/dev/null 2>&1
        for _ in $(seq 1 20); do
            kill -0 "$VM_PID" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$VM_PID" 2>/dev/null; then
            kill "$VM_PID" 2>/dev/null
        fi
        wait "$VM_PID" 2>/dev/null
    fi
    if [ "$status" -ne 0 ] && [ -s "$QEMU_LOG" ]; then
        tail -c 20000 "$QEMU_LOG" | tr '\r' '\n' | tail -80 >&2
    fi
    rm -rf "$WORK"
    exit "$status"
}
trap cleanup EXIT

require_program() {
    type -P "$1" || fail "required program '$1' was not found"
}

check_host_prerequisites() {
    [ -r /dev/kvm ] && [ -w /dev/kvm ] ||
        fail "/dev/kvm is not readable and writable; configure KVM access first"
    if pgrep -af qemu-system-x86_64 |
        grep -F -- 'hostfwd=tcp:127.0.0.1:10023-' >/dev/null; then
        fail "another QEMU VM already owns the lane's localhost port 10023"
    fi
}

copy_sources() {
    local destination="$1"
    local project="$destination/src/bin/curl"
    local moto_rt="$destination/src/sys/lib/moto-rt"
    local ssl="$destination/img_files/motor-os/sys/cfg/ssl"
    mkdir -p "$project" "$moto_rt" "$ssl"
    cp "$CURL_DIR/Cargo.toml" "$CURL_DIR/Cargo.lock" "$project/"
    cp -R "$CURL_DIR/src" "$CURL_DIR/tests" "$project/"
    cp "$MOTO_RT_DIR/Cargo.toml" "$MOTO_RT_DIR/LICENSE-APACHE" \
        "$MOTO_RT_DIR/LICENSE-MIT" "$MOTO_RT_DIR/README.md" "$moto_rt/"
    cp -R "$MOTO_RT_DIR/src" "$moto_rt/"
    cp "$ROOT_DIR/img_files/motor-os/sys/cfg/ssl/ssl-cert.pem" "$ssl/"
}

prepare_inputs() {
    local cargo
    local candidate
    local host_archiver
    local host_c_compiler
    local host_home="$WORK/host-home"
    local host_rustc
    local motor_rustc
    local project
    local test_harness
    local tls_server

    unset CARGO_TARGET_DIR RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
    unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
    cargo="$(rustup which cargo --toolchain nightly-2026-06-19)"
    host_rustc="$(rustup which rustc --toolchain nightly-2026-06-19)"
    motor_rustc="$(rustup which rustc --toolchain "$MOTOR_TOOLCHAIN")"
    host_c_compiler="$(require_program clang)"
    host_archiver="$(require_program ar)"

    [ -x "$MOTOR_LINKER" ] ||
        fail "Motor linker '$MOTOR_LINKER' is not executable"
    [ -d "$MOTOR_SYSROOT/lib/rustlib/$MOTOR_TARGET" ] ||
        fail "Motor Rust sysroot '$MOTOR_SYSROOT' is incomplete"
    [ -x "$MOTOR_C_COMPILER" ] ||
        fail "Motor C compiler '$MOTOR_C_COMPILER' is not executable"
    [ -d "$MOTOR_C_SYSROOT/sys/tools/llvm/include" ] ||
        fail "Motor C sysroot '$MOTOR_C_SYSROOT' is incomplete"
    [ -x "$MOTOR_ARCHIVER" ] ||
        fail "Motor archiver '$MOTOR_ARCHIVER' is not executable"
    [ -d "$BUILD_REPOSITORY/objects" ] ||
        fail "Stage 2 system seed is missing; run the repository build first"
    [ -d "$DOWNLOAD_CACHE" ] ||
        fail "Stage 2 download cache is missing; run the repository build first"

    echo "== Fetching the pinned curl/Mozilla CA bundle =="
    "$HOST_CURL" --disable --fail --silent --show-error \
        --proto '=https' --tlsv1.2 --output "$WORK/ca-certificates.crt" "$CA_URL"
    [ "$(sha256sum "$WORK/ca-certificates.crt" | awk '{print $1}')" = "$CA_SHA256" ] ||
        fail "downloaded CA bundle does not match the pinned SHA-256"

    echo "== Building the staged Motor Lorry =="
    CARGO_HOME="$HOST_CARGO_HOME" RUSTC="$motor_rustc" \
        RUSTFLAGS="--sysroot=$MOTOR_SYSROOT" \
        CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER="$MOTOR_LINKER" \
        "$cargo" build --manifest-path "$LORRY_DIR/Cargo.toml" \
        --locked --offline --release --target "$MOTOR_TARGET" \
        --target-dir "$WORK/cross-lorry"
    CARGO_HOME="$HOST_CARGO_HOME" RUSTC="$motor_rustc" \
        RUSTFLAGS="--sysroot=$MOTOR_SYSROOT" \
        CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER="$MOTOR_LINKER" \
        "$cargo" test --manifest-path "$LORRY_DIR/Cargo.toml" \
        --locked --offline --target "$MOTOR_TARGET" --no-run \
        --target-dir "$WORK/cross-lorry-tests"
    STAGED_LORRY="$WORK/cross-lorry/$MOTOR_TARGET/release/lorry"
    test_harness=""
    for candidate in \
        "$WORK"/cross-lorry-tests/"$MOTOR_TARGET"/debug/deps/lorry-*; do
        [ -f "$candidate" ] && [ -x "$candidate" ] || continue
        [ -z "$test_harness" ] ||
            fail "Cargo produced multiple Motor Lorry test executables"
        test_harness="$candidate"
    done
    [ -n "$test_harness" ] ||
        fail "Cargo did not produce the Motor Lorry test executable"
    STAGED_LORRY_TESTS="$test_harness"

    echo "== Building the staged Motor curl with Lorry =="
    CARGO_HOME="$HOST_CARGO_HOME" RUSTC="$host_rustc" \
        "$cargo" build --manifest-path "$LORRY_DIR/Cargo.toml" \
        --locked --offline --release --target-dir "$WORK/host-lorry"
    HOST_LORRY="$WORK/host-lorry/release/lorry"
    "$PYTHON" "$BOOTSTRAP/install_stage2_seed.py" \
        --manifest "$BOOTSTRAP/stage2-seed.toml" \
        --build-repository "$BUILD_REPOSITORY" \
        --host-repository "$host_home/.config/lorry/system/vendor" \
        --host-user-repository "$host_home/.config/lorry/vendor" \
        --host-config "$host_home/.config/lorry/lorry.toml" \
        --image-repository "$WORK/image/vendor" \
        --motor-config "$WORK/image/lorry.toml" \
        --cache "$DOWNLOAD_CACHE" --mode full --offline \
        --host-c-compiler "$host_c_compiler" --host-archiver "$host_archiver"

    copy_sources "$WORK/build-source"
    copy_sources "$WORK/guest-source"
    project="$WORK/build-source/src/bin/curl"
    mkdir "$project/.cargo"
    printf '[target.%s]\nlinker = "%s"\nrustflags = ["--sysroot=%s"]\n' \
        "$MOTOR_TARGET" "$MOTOR_LINKER" "$MOTOR_SYSROOT" \
        >"$project/.cargo/config.toml"
    printf 'config-version = 1\n\n[native-tools."%s".c-compiler]\n' \
        "$MOTOR_TARGET" >"$project/lorry.toml"
    printf 'program = "%s"\nprefix-args = []\n' "$MOTOR_C_COMPILER" \
        >>"$project/lorry.toml"
    printf 'flags = ["--no-default-config", "--target=%s", "--sysroot=%s", "-D_GNU_SOURCE", "-D_DEFAULT_SOURCE"]\n\n' \
        "$MOTOR_TARGET" "$MOTOR_C_SYSROOT" >>"$project/lorry.toml"
    printf '[native-tools."%s".archiver]\nprogram = "%s"\nprefix-args = []\nflags = []\n' \
        "$MOTOR_TARGET" "$MOTOR_ARCHIVER" >>"$project/lorry.toml"
    (
        cd "$project"
        HOME="$host_home" CARGO_HOME="$WORK/cargo-home" RUSTC="$motor_rustc" \
            RUSTUP_HOME="$HOST_RUSTUP_HOME" "$HOST_LORRY" test --release \
            --target "$MOTOR_TARGET" --no-run
    )
    STAGED_CURL="$project/target/lorry/$MOTOR_TARGET/release/curl"
    tls_server=""
    for candidate in \
        "$project"/target/lorry/"$MOTOR_TARGET"/release/deps/https-*; do
        [ -f "$candidate" ] && [ -x "$candidate" ] || continue
        [ -z "$tls_server" ] ||
            fail "Lorry produced multiple Motor HTTPS test executables"
        tls_server="$candidate"
    done
    [ -x "$STAGED_LORRY" ] || fail "cross-build did not produce Motor Lorry"
    [ -x "$STAGED_CURL" ] || fail "Lorry did not produce Motor curl"
    [ -n "$tls_server" ] ||
        fail "Lorry did not produce the Motor HTTPS test executable"
    STAGED_HTTPS_TESTS="$tls_server"
}

build_image() {
    local imager="$ROOT_DIR/src/imager/target/$BUILD/imager"
    local log="$WORK/image-build.log"
    [ -x "$imager" ] ||
        fail "the $BUILD imager is absent; run the repository build first"
    echo "== Building the dedicated patched-source Motor image =="
    if ! "$PYTHON" "$BOOTSTRAP/build_minimal_seed_image.py" \
        --mode "$BUILD" --scaffold "$SCAFFOLD" --imager "$imager" \
        --host-c-compiler "$CLANG" --host-archiver "$AR" >"$log" 2>&1; then
        tail -80 "$log" >&2
        fail "dedicated Motor image build failed"
    fi
    tail -2 "$log"
}

start_vm() {
    local deadline=$((SECONDS + 10))
    echo "== Starting the dedicated Motor VM =="
    MOTO_QEMU_USER_NET=1 "$SCAFFOLD/vm_images/$BUILD/run-qemu.sh" \
        >"$QEMU_LOG" 2>&1 &
    VM_PID="$!"
    until timeout 2 "${SSH[@]}" /bin/echo ready >/dev/null 2>&1; do
        kill -0 "$VM_PID" 2>/dev/null ||
            fail "dedicated Motor VM exited before SSH became ready"
        [ "$SECONDS" -lt "$deadline" ] ||
            fail "dedicated Motor VM did not become SSH-ready within 10 seconds"
        sleep 0.1
    done
}

expect_guest_layout() {
    local kind="$1"
    local path="$2"
    local predicate
    case "$kind" in
        directory) predicate="-d" ;;
        executable) predicate="-x" ;;
        file) predicate="-f" ;;
        *) fail "internal error: unknown guest artifact kind '$kind'" ;;
    esac
    if ! "${SSH[@]}" "[ $predicate $path ]"; then
        fail "Motor filesystem layout changed: expected $kind '$path' in the disposable image"
    fi
}

verify_guest_layout() {
    local path
    echo "== Verifying disposable-image filesystem layout =="
    for path in \
        /bin \
        /sys/cfg/ssl \
        /sys/tmp \
        /sys/tools/llvm/bin \
        /sys/tools/llvm/include \
        /sys/tools/llvm/lib \
        /sys/tools/rust/bin \
        /sys/tools/rust/cfg \
        /sys/tools/rust/lorry/vendor/objects \
        /user/cfg \
        /user/tmp; do
        expect_guest_layout directory "$path"
    done
    for path in \
        /bin/cc \
        /bin/cp \
        /bin/ls \
        /bin/mkdir \
        /bin/rush \
        /sys/tools/llvm/bin/llvm \
        /sys/tools/rust/bin/rustc; do
        expect_guest_layout executable "$path"
    done
    expect_guest_layout file /sys/cfg/ssl/ssl-cert.pem
    expect_guest_layout file /sys/tools/rust/cfg/lorry.toml
}

stage_inputs() {
    local batch="$WORK/upload.batch"
    local directory
    local file
    local relative

    echo "== Provisioning the dedicated guest through SFTP =="
    "${SSH[@]}" "[ -d /user/tmp ] || /bin/mkdir /user/tmp"
    "${SSH[@]}" \
        "/bin/mkdir $REMOTE_ROOT && /bin/mkdir $REMOTE_ROOT/bin && /bin/mkdir $REMOTE_ROOT/source && /bin/mkdir /user/lorry"
    : >"$batch"
    while IFS= read -r -d '' directory; do
        relative="${directory#"$WORK/guest-source"/}"
        case "$relative" in
            *[[:space:]]*) fail "source paths containing whitespace are unsupported" ;;
        esac
        "${SSH[@]}" "/bin/mkdir $REMOTE_ROOT/source/$relative"
    done < <(find "$WORK/guest-source" -mindepth 1 -type d -print0 | sort -z)
    while IFS= read -r -d '' file; do
        relative="${file#"$WORK/guest-source"/}"
        case "$relative" in
            *[[:space:]]*) fail "source paths containing whitespace are unsupported" ;;
        esac
        printf 'put %s %s/source/%s\nchmod 600 %s/source/%s\n' \
            "$file" "$REMOTE_ROOT" "$relative" "$REMOTE_ROOT" "$relative" >>"$batch"
    done < <(find "$WORK/guest-source" -type f -print0 | sort -z)
    printf 'put %s %s/bin/lorry\nchmod 700 %s/bin/lorry\n' \
        "$STAGED_LORRY" "$REMOTE_ROOT" "$REMOTE_ROOT" >>"$batch"
    printf 'put %s %s/bin/curl\nchmod 700 %s/bin/curl\n' \
        "$STAGED_CURL" "$REMOTE_ROOT" "$REMOTE_ROOT" >>"$batch"
    printf 'put %s %s/bin/lorry-tests\nchmod 700 %s/bin/lorry-tests\n' \
        "$STAGED_LORRY_TESTS" "$REMOTE_ROOT" "$REMOTE_ROOT" >>"$batch"
    printf 'put %s %s/bin/https-tests\nchmod 700 %s/bin/https-tests\n' \
        "$STAGED_HTTPS_TESTS" "$REMOTE_ROOT" "$REMOTE_ROOT" >>"$batch"
    printf 'put %s %s/test-ca.pem\nchmod 600 %s/test-ca.pem\n' \
        "$CURL_DIR/tests/test-ca.pem" "$REMOTE_ROOT" "$REMOTE_ROOT" >>"$batch"
    printf 'put %s %s/hostname-ca.pem\nchmod 600 %s/hostname-ca.pem\n' \
        "$CURL_DIR/tests/hostname-ca.pem" "$REMOTE_ROOT" "$REMOTE_ROOT" >>"$batch"
    printf 'put %s %s/ca-certificates.crt\nchmod 600 %s/ca-certificates.crt\n' \
        "$WORK/ca-certificates.crt" "$REMOTE_ROOT" "$REMOTE_ROOT" >>"$batch"
    printf 'config-version = 1\n\n[repositories]\nuser = "/user/lorry/vendor"\n\n' \
        >"$WORK/lorry.toml"
    printf '[network]\ncurl = "%s/bin/curl"\nca-bundle = "%s/ca-certificates.crt"\n' \
        "$REMOTE_ROOT" "$REMOTE_ROOT" >>"$WORK/lorry.toml"
    printf 'put %s /user/cfg/lorry.toml\nchmod 600 /user/cfg/lorry.toml\n' \
        "$WORK/lorry.toml" >>"$batch"
    timeout 60 sftp "${SFTP_OPTIONS[@]}" -b "$batch" motor@127.0.0.1
}

expect_listing() {
    local actual
    actual="$("${SSH[@]}" /bin/ls "$1")" ||
        fail "could not list repository path '$1'"
    actual="${actual//$'\033[1m'/}"
    actual="${actual//$'\033[34m'/}"
    actual="${actual//$'\033[0m'/}"
    actual="${actual% }"
    [ "$actual" = "$2" ] ||
        fail "unexpected repository listing at '$1': $actual"
}

verify_system_repository() {
    local objects="/sys/tools/rust/lorry/vendor/objects"
    echo "== Verifying the minimal system repository =="
    expect_listing "$objects" "seeded-git"
    expect_listing "$objects/seeded-git" "sha256"
    expect_listing "$objects/seeded-git/sha256" "c0 c4"
    expect_listing "$objects/seeded-git/sha256/c0" "$RING_SHA256"
    expect_listing "$objects/seeded-git/sha256/c4" "$CC_SHA256"
}

verify_guest() {
    local response
    verify_system_repository
    echo "== Verifying guest crates.io reachability =="
    if ! response="$("${SSH[@]}" \
        "$REMOTE_ROOT/bin/curl --disable --silent --show-error --globoff --http1.1 --proto =https --noproxy '*' --disallow-username-in-url --tlsv1.2 --tls-max 1.3 --connect-timeout 30 --max-time 300 --speed-limit 1 --speed-time 30 --user-agent lorry/0.1.0 --header 'Accept-Encoding: identity' --output - --cacert $REMOTE_ROOT/ca-certificates.crt --url https://index.crates.io/config.json" 2>&1)"; then
        printf '%s\n' "$response" >&2
        fail "the guest crates.io request failed; inspect the curl diagnostic above"
    fi
    printf '%s\n' "$response" | grep -F \
        '"dl": "https://static.crates.io/crates"' >/dev/null ||
        fail "crates.io returned an unexpected index configuration"
}

acquire_registry() {
    local batch="$WORK/download-registry.batch"
    local checksum
    local identity
    local metadata="$WORK/registry-metadata"
    local name
    local object_root="/user/lorry/vendor/objects/crates-io/sha256"
    local output
    local version

    echo "== Vendoring the reviewed curl graph natively =="
    if ! output="$(timeout 600 "${SSH[@]}" \
        "cd $REMOTE_ROOT/source/src/bin/curl && $REMOTE_ROOT/bin/lorry vendor --accept-all" \
        2>&1)"; then
        printf '%s\n' "$output" >&2
        fail "native curl vendoring failed; inspect the Lorry diagnostic above"
    fi
    printf '%s\n' "$output"
    grep -F "New crates.io packages (13):" <<<"$output" >/dev/null ||
        fail "native vendoring did not report the reviewed 13-package registry set"

    expect_listing "$object_root" "$REGISTRY_PREFIXES"
    expect_listing "/user/lorry/vendor/.staging" ""
    mkdir "$metadata"
    printf 'get %s/source/src/bin/curl/Cargo.lock %s/Cargo.lock\n' \
        "$REMOTE_ROOT" "$WORK" >"$batch"
    for identity in "${REGISTRY_IDENTITIES[@]}"; do
        IFS='|' read -r name version checksum <<<"$identity"
        expect_listing "$object_root/${checksum:0:2}" "$checksum"
        grep -F \
            "  $name $version: source=crates.io checksum=$checksum " \
            <<<"$output" >/dev/null ||
            fail "native approval omitted registry identity '$name $version $checksum'"
        printf 'get %s/%s/%s/package.toml %s/%s.toml\n' \
            "$object_root" "${checksum:0:2}" "$checksum" \
            "$metadata" "$checksum" >>"$batch"
    done
    timeout 60 sftp "${SFTP_OPTIONS[@]}" -b "$batch" motor@127.0.0.1

    cmp "$CURL_DIR/Cargo.lock" "$WORK/Cargo.lock" ||
        fail "native acquisition changed the reviewed curl lockfile"
    for identity in "${REGISTRY_IDENTITIES[@]}"; do
        IFS='|' read -r name version checksum <<<"$identity"
        grep -Fx "name = \"$name\"" "$metadata/$checksum.toml" >/dev/null &&
            grep -Fx "version = \"$version\"" "$metadata/$checksum.toml" >/dev/null &&
            grep -Fx \
                'source = "registry+https://github.com/rust-lang/crates.io-index"' \
                "$metadata/$checksum.toml" >/dev/null &&
            grep -Fx "checksum = \"$checksum\"" \
                "$metadata/$checksum.toml" >/dev/null ||
            fail "published metadata does not identify '$name $version $checksum'"
    done
}

rebuild_curl() {
    local batch="$WORK/download-native-curl.batch"
    local native_curl="$WORK/native-curl"
    local output
    local project="$REMOTE_ROOT/source/src/bin/curl"
    local remote_curl="$project/target/lorry/release/curl"

    echo "== Rebuilding release curl from the fresh repository =="
    if ! output="$(timeout 600 "${SSH[@]}" \
        "cd $project && $REMOTE_ROOT/bin/lorry build --release" 2>&1)"; then
        printf '%s\n' "$output" >&2
        fail "native curl rebuild failed; inspect the Lorry diagnostic above"
    fi
    printf '%s\n' "$output"

    printf 'get %s %s\n' "$remote_curl" "$native_curl" >"$batch"
    timeout 60 sftp "${SFTP_OPTIONS[@]}" -b "$batch" motor@127.0.0.1
    if ! cmp "$STAGED_CURL" "$native_curl"; then
        sha256sum "$STAGED_CURL" "$native_curl" >&2
        fail "native curl differs from the clean Linux-to-Motor Lorry build"
    fi
}

run_fixture() {
    local expected="$1"
    local label="$2"
    local command="$3"
    local output

    if ! output="$(timeout 60 "${SSH[@]}" "$command" 2>&1)"; then
        printf '%s\n' "$output" >&2
        fail "$label failed; inspect the diagnostic above"
    fi
    printf '%s\n' "$output"
    grep -F "test result: ok. $expected passed; 0 failed" <<<"$output" >/dev/null ||
        fail "$label did not report exactly $expected passing tests"
}

run_runtime_fixtures() {
    local native_curl="$REMOTE_ROOT/source/src/bin/curl/target/lorry/release/curl"

    echo "== Running Motor entropy and verified-HTTPS fixtures =="
    run_fixture 1 "Motor entropy fixture" \
        "$REMOTE_ROOT/bin/https-tests obtains_distinct_system_random_values --exact --quiet"
    run_fixture 1 "Motor verified-HTTPS fixture" \
        "MOTOR_CURL_TEST_FIXTURES=$REMOTE_ROOT $REMOTE_ROOT/bin/https-tests transfers_a_verified_https_response --exact --quiet"

    echo "== Running Lorry's boundary through the freshly native-built curl =="
    run_fixture 10 "Motor curl boundary fixture" \
        "LORRY_TEST_CURL=$native_curl LORRY_TEST_CA=$REMOTE_ROOT/test-ca.pem LORRY_TEST_HOSTNAME_CA=$REMOTE_ROOT/hostname-ca.pem LORRY_TEST_UNTRUSTED_CA=/sys/cfg/ssl/ssl-cert.pem LORRY_TEST_TLS_SERVER=$REMOTE_ROOT/bin/https-tests $REMOTE_ROOT/bin/lorry-tests selected_curl --quiet"
}

verify_unchanged_system_repository() {
    local actual
    local batch="$WORK/download-system-repository.batch"
    local repository="$WORK/system-repository-after"

    verify_system_repository
    echo "== Downloading and fingerprinting the unchanged system repository =="
    printf 'get -pR /sys/tools/rust/lorry/vendor %s\n' "$repository" >"$batch"
    timeout 120 sftp "${SFTP_OPTIONS[@]}" -b "$batch" motor@127.0.0.1
    [ ! -e "$repository/objects/crates-io" ] ||
        fail "downloaded minimal system repository contains crates.io objects"
    if ! actual="$(PYTHONPATH="$BOOTSTRAP" "$PYTHON" -c \
        'import sys; from pathlib import Path; from install_stage2_seed import repository_fingerprint; from seed_system_repository import load_seed_manifest; print(repository_fingerprint(Path(sys.argv[1]), load_seed_manifest(Path(sys.argv[2])), "minimal"))' \
        "$repository" "$BOOTSTRAP/stage2-seed.toml")"; then
        fail "downloaded system repository failed verification"
    fi
    [ "$actual" = "$MINIMAL_SEED_FINGERPRINT" ] ||
        fail "downloaded system repository fingerprint is $actual"
}

PYTHON="$(require_program python3)"
CLANG="$(require_program clang)"
AR="$(require_program ar)"
HOST_CURL="$(require_program curl)"
require_program pgrep >/dev/null
require_program qemu-system-x86_64 >/dev/null
require_program rustup >/dev/null
require_program sha256sum >/dev/null
require_program sftp >/dev/null
require_program ssh >/dev/null
HOST_CARGO_HOME="${CARGO_HOME:-${HOME:?}/.cargo}"
HOST_RUSTUP_HOME="${RUSTUP_HOME:-${HOME:?}/.rustup}"

check_host_prerequisites
prepare_inputs
build_image
SSH_OPTIONS=(
    -n -F /dev/null -p 10023
    -i "$SCAFFOLD/vm_images/$BUILD/test.key"
    -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
)
SSH=(ssh "${SSH_OPTIONS[@]}" motor@127.0.0.1)
SFTP_OPTIONS=(
    -F /dev/null -P 10023
    -i "$SCAFFOLD/vm_images/$BUILD/test.key"
    -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
)
start_vm
verify_guest_layout
stage_inputs
verify_guest
acquire_registry
rebuild_curl
run_runtime_fixtures
verify_unchanged_system_repository

echo
echo "PASS: Motor acquired curl, rebuilt it identically, and preserved its system seed"
