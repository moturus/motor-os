#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
TESTS_DIR="$ROOT_DIR/src/tests"
MOTOR_TARGET="x86_64-unknown-motor"
MOTOR_TOOLCHAIN="${LORRY_MOTOR_TOOLCHAIN:-dev-x86_64-unknown-motor}"
MOTOR_LINKER="${LORRY_MOTOR_LINKER:-/home/posk/motor-dev/motor-sysroot/bin/motor-clang}"
MOTOR_SYSROOT="${LORRY_MOTOR_SYSROOT:-$ROOT_DIR/img_files/generated/rustc/sys/tools/rust}"
MOTOR_C_COMPILER="${LORRY_MOTOR_C_COMPILER:-/home/posk/motor-dev/llvm-project/build/bin/clang}"
MOTOR_C_SYSROOT="${LORRY_MOTOR_C_SYSROOT:-/home/posk/motor-dev/motor-sysroot}"
MOTOR_ARCHIVER="${LORRY_MOTOR_ARCHIVER:-/home/posk/motor-dev/llvm-project/build/bin/llvm-ar}"
BUILD_REPOSITORY="$ROOT_DIR/build/lorry/stage2/system-seed"
DOWNLOAD_CACHE="$ROOT_DIR/build/lorry/stage2/download-cache"
REMOTE_BASE="/user/tmp/lorry"

MODE="smoke"
BUILD="debug"
REUSE_VM=0
KEEP=0

usage() {
    cat <<'EOF'
usage: test-native.sh [--full] [--release] [--reuse-running-vm] [--keep]

Runs the Stage-1 Motor-native acceptance gate. The default smoke gate owns a
debug VM. --full adds native self-build and second-generation checks.
--reuse-running-vm uses the VM already owned by src/tests/full-test.sh.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --full) MODE="full" ;;
        --release) BUILD="release" ;;
        --reuse-running-vm) REUSE_VM=1 ;;
        --keep) KEEP=1 ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "test-native: unknown option '$1'" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

case "$MODE" in
    smoke)
        PHASE_BUDGET="${LORRY_NATIVE_SMOKE_TIMEOUT:-300}"
        ;;
    full)
        PHASE_BUDGET="${LORRY_NATIVE_FULL_TIMEOUT:-1800}"
        ;;
esac
case "$PHASE_BUDGET" in
    '' | *[!0-9]* | 0)
        echo "test-native: native timeout must be a positive integer" >&2
        exit 1
        ;;
esac

RUN_ID="stage1-$(date -u +%Y%m%dT%H%M%SZ)-$$"
EVIDENCE_DIR="$SCRIPT_DIR/target/lorry/native-tests/$RUN_ID"
ARTIFACT_DIR="$EVIDENCE_DIR/artifacts"
WORK="$(mktemp -d /tmp/lorry-stage1-native-XXXXXX)"
HOST_STAGE="$WORK/stage"
REMOTE_ROOT="$REMOTE_BASE/$RUN_ID"
NATIVE_LOG="$EVIDENCE_DIR/native.log"
SFTP_LOG="$EVIDENCE_DIR/sftp.log"
HASH_LOG="$EVIDENCE_DIR/hashes.txt"
SUMMARY="$EVIDENCE_DIR/summary.txt"
COMMAND_LOG="$EVIDENCE_DIR/commands.txt"
QEMU_LOG="$EVIDENCE_DIR/qemu.log"
IMAGE_BUILD_LOG="$EVIDENCE_DIR/image-build.log"

mkdir -p "$ARTIFACT_DIR" "$HOST_STAGE"
: >"$NATIVE_LOG"
: >"$SFTP_LOG"
: >"$HASH_LOG"
: >"$COMMAND_LOG"

SSH_OPTIONS=(
    -n
    -F /dev/null
    -p 2222
    -i "$TESTS_DIR/test.key"
    -o IdentitiesOnly=yes
    -o BatchMode=yes
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR
)
SSH=(ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2)
SFTP_OPTIONS=(
    -F /dev/null
    -P 2222
    -i "$TESTS_DIR/test.key"
    -o IdentitiesOnly=yes
    -o BatchMode=yes
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR
)

VM_PID=""
VM_STARTED=0
REMOTE_CREATED=0
PHASE_DEADLINE_MS=0
BOOT_MILLISECONDS="not-ready"
NATIVE_MILLISECONDS=0

fail() {
    echo "test-native: $*" >&2
    exit 1
}

now_ms() {
    local seconds
    local nanoseconds
    read -r seconds nanoseconds < <(date '+%s %N')
    printf '%s\n' "$((seconds * 1000 + 10#$nanoseconds / 1000000))"
}

canonical_remote_child() {
    local path="$1"
    local component
    local -a components
    local -a stack=()

    [[ "$path" == /* ]] || return 1
    IFS='/' read -r -a components <<<"$path"
    for component in "${components[@]}"; do
        case "$component" in
            '' | .) ;;
            ..)
                [ "${#stack[@]}" -gt 0 ] || return 1
                unset 'stack[${#stack[@]}-1]'
                ;;
            *) stack+=("$component") ;;
        esac
    done

    local canonical=""
    for component in "${stack[@]}"; do
        canonical="$canonical/$component"
    done
    case "$canonical" in
        "$REMOTE_BASE"/*)
            [ "$canonical" != "$REMOTE_BASE/" ] || return 1
            printf '%s\n' "$canonical"
            ;;
        *) return 1 ;;
    esac
}

REMOTE_ROOT="$(canonical_remote_child "$REMOTE_ROOT")" ||
    fail "generated an unsafe remote run root"

duration_from_ms() {
    local milliseconds="$1"
    printf '%d.%03ds\n' "$((milliseconds / 1000))" "$((milliseconds % 1000))"
}

remaining_duration() {
    local remaining_ms=$((PHASE_DEADLINE_MS - $(now_ms)))
    [ "$remaining_ms" -gt 0 ] || fail "$MODE native phase exceeded ${PHASE_BUDGET}s"
    duration_from_ms "$remaining_ms"
}

native_command() {
    local command="$1"
    local duration
    local status
    duration="$(remaining_duration)"
    printf '+ %s\n' "$command" >>"$COMMAND_LOG"
    set +e
    timeout "$duration" "${SSH[@]}" "$command" 2>&1 | tee -a "$NATIVE_LOG"
    status="${PIPESTATUS[0]}"
    set -e
    [ "$status" -eq 0 ] ||
        fail "native command failed with status $status: $command"
}

native_capture() {
    local output="$1"
    local command="$2"
    local duration
    local status
    duration="$(remaining_duration)"
    printf '+ %s\n' "$command" >>"$COMMAND_LOG"
    set +e
    timeout "$duration" "${SSH[@]}" "$command" 2>&1 |
        tee -a "$NATIVE_LOG" "$output"
    status="${PIPESTATUS[0]}"
    set -e
    [ "$status" -eq 0 ] ||
        fail "native command failed with status $status: $command"
}

run_sftp_batch() {
    local batch="$1"
    local duration
    local status
    duration="$(remaining_duration)"
    set +e
    timeout "$duration" sftp "${SFTP_OPTIONS[@]}" -b "$batch" \
        motor@192.168.4.2 2>&1 | tee -a "$SFTP_LOG"
    status="${PIPESTATUS[0]}"
    set -e
    [ "$status" -eq 0 ] || fail "SFTP batch failed with status $status"
}

remote_mkdir() {
    local path
    path="$(canonical_remote_child "$1")" || fail "unsafe remote directory '$1'"
    native_command "/bin/mkdir $path"
}

remote_copy_tree() {
    local source
    local destination
    source="$(canonical_remote_child "$1")" ||
        fail "unsafe recursive-copy source '$1'"
    destination="$(canonical_remote_child "$2")" ||
        fail "unsafe recursive-copy destination '$2'"
    native_command "/bin/cp -r $source $destination"
}

upload_mode() {
    if [ -x "$1" ]; then
        printf '700\n'
    else
        printf '600\n'
    fi
}

upload_file() {
    local source="$1"
    local destination
    local mode
    local batch="$WORK/upload-file.batch"
    destination="$(canonical_remote_child "$2")" ||
        fail "unsafe upload destination '$2'"
    mode="$(upload_mode "$source")"
    printf 'put %s %s\nchmod %s %s\n' \
        "$source" "$destination" "$mode" "$destination" >"$batch"
    run_sftp_batch "$batch"
}

upload_tree() {
    local source="$1"
    local destination
    local directory
    local file
    local mode
    local relative
    local batch="$WORK/upload-tree.batch"
    destination="$(canonical_remote_child "$2")" ||
        fail "unsafe upload-tree destination '$2'"

    remote_mkdir "$destination"
    while IFS= read -r -d '' directory; do
        relative="${directory#"$source"/}"
        case "$relative" in
            *[[:space:]]*) fail "source paths containing whitespace are unsupported" ;;
        esac
        remote_mkdir "$destination/$relative"
    done < <(find "$source" -mindepth 1 -type d -print0 | sort -z)

    : >"$batch"
    while IFS= read -r -d '' file; do
        relative="${file#"$source"/}"
        case "$relative" in
            *[[:space:]]*) fail "source paths containing whitespace are unsupported" ;;
        esac
        mode="$(upload_mode "$file")"
        printf 'put %s %s/%s\nchmod %s %s/%s\n' \
            "$file" "$destination" "$relative" \
            "$mode" "$destination" "$relative" >>"$batch"
    done < <(find "$source" -type f -print0 | sort -z)
    run_sftp_batch "$batch"
}

download_artifact() {
    local remote_file
    local local_file="$2"
    local batch="$WORK/download.batch"
    remote_file="$(canonical_remote_child "$1")" ||
        fail "unsafe download source '$1'"
    printf 'get %s %s\n' "$remote_file" "$local_file" >"$batch"
    run_sftp_batch "$batch"
}

compare_artifact() {
    local label="$1"
    local remote_file="$2"
    local expected="$3"
    local downloaded="$ARTIFACT_DIR/$label"
    local hosted="$ARTIFACT_DIR/hosted-$label"
    cp "$expected" "$hosted"
    download_artifact "$remote_file" "$downloaded"
    cmp "$hosted" "$downloaded" ||
        fail "$label differs between Linux cross-build and native Motor"
    printf '%s %s\n' "$label" "$(sha256sum "$downloaded" | awk '{print $1}')" \
        >>"$HASH_LOG"
}

run_native_test() {
    local package="$1"
    local lorry="$2"
    local label="$3"
    local remote_log="$REMOTE_ROOT/$label.log"
    local local_log="$EVIDENCE_DIR/$label.log"

    native_command \
        "cd $package && $lorry test --release -- --quiet > $remote_log 2>&1"
    download_artifact "$remote_log" "$local_log"
    cat "$local_log" | tee -a "$NATIVE_LOG"
    grep -F "test result: ok." "$local_log" >/dev/null ||
        fail "$label did not report a successful test result"
}

copy_package() {
    local source="$1"
    local destination="$2"
    mkdir -p "$destination"
    cp "$source/Cargo.toml" "$source/Cargo.lock" "$destination/"
    cp -R "$source/src" "$destination/src"
}

copy_crate() {
    local source="$1"
    local destination="$2"
    mkdir -p "$destination"
    cp "$source/Cargo.toml" "$destination/"
    cp -R "$source/src" "$destination/src"
}

configure_motor_linker() {
    local package="$1"
    mkdir -p "$package/.cargo"
    cat >"$package/.cargo/config.toml" <<EOF
[target.$MOTOR_TARGET]
linker = "$MOTOR_LINKER"
rustflags = ["--sysroot=$MOTOR_SYSROOT"]
EOF
}

configure_motor_native_tools() {
    local package="$1"
    cat >"$package/lorry.toml" <<EOF
config-version = 1

[native-tools."$MOTOR_TARGET".c-compiler]
program = "$MOTOR_C_COMPILER"
prefix-args = []
flags = [
    "--no-default-config",
    "--target=$MOTOR_TARGET",
    "--sysroot=$MOTOR_C_SYSROOT",
    "-D_GNU_SOURCE",
    "-D_DEFAULT_SOURCE",
]

[native-tools."$MOTOR_TARGET".archiver]
program = "$MOTOR_ARCHIVER"
prefix-args = []
flags = []
EOF
}

prepare_host_gate() {
    local cargo
    local candidate
    local host_archiver
    local host_c_compiler
    local host_home
    local native_rustc
    local motor_rustc
    local python
    local rustup_home
    local test_harness
    local tls_server

    echo "== Preparing clean Linux-to-Motor Lorry artifacts =="
    cargo="$(rustup which cargo --toolchain nightly-2026-06-19)"
    native_rustc="$(rustup which rustc --toolchain nightly-2026-06-19)"
    motor_rustc="$(rustup which rustc --toolchain "$MOTOR_TOOLCHAIN")"
    rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
    unset CARGO_TARGET_DIR RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
    unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
    [ -x "$MOTOR_LINKER" ] ||
        fail "Motor cross-linker '$MOTOR_LINKER' is not executable"
    [ -d "$MOTOR_SYSROOT/lib/rustlib/$MOTOR_TARGET" ] ||
        fail "Motor image sysroot '$MOTOR_SYSROOT' is incomplete"
    [ -x "$MOTOR_C_COMPILER" ] ||
        fail "Motor C compiler '$MOTOR_C_COMPILER' is not executable"
    [ -x "$MOTOR_ARCHIVER" ] ||
        fail "Motor archiver '$MOTOR_ARCHIVER' is not executable"
    [ -d "$MOTOR_C_SYSROOT/sys/tools/llvm/include" ] ||
        fail "Motor C sysroot '$MOTOR_C_SYSROOT' is incomplete"
    [ -d "$BUILD_REPOSITORY/objects" ] ||
        fail "Stage 2 system seed '$BUILD_REPOSITORY' is missing"
    [ -d "$DOWNLOAD_CACHE" ] ||
        fail "Stage 2 download cache '$DOWNLOAD_CACHE' is missing"
    python="$(type -P python3)"
    host_c_compiler="$(type -P clang)"
    host_archiver="$(type -P ar)"

    # Stage 2 has reviewed registry dependencies, so its initial host and
    # cross-Motor test subjects are Cargo oracles. All guest work still uses
    # only the staged Lorry executables.
    RUSTC="$native_rustc" "$cargo" build \
        --manifest-path "$SCRIPT_DIR/Cargo.toml" --locked --offline --release
    RUSTC="$motor_rustc" RUSTFLAGS="--sysroot=$MOTOR_SYSROOT" \
        CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER="$MOTOR_LINKER" \
        "$cargo" build --manifest-path "$SCRIPT_DIR/Cargo.toml" \
        --locked --offline --release --target "$MOTOR_TARGET" \
        --target-dir "$WORK/cargo-lorry-motor"
    RUSTC="$motor_rustc" RUSTFLAGS="--sysroot=$MOTOR_SYSROOT" \
        CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER="$MOTOR_LINKER" \
        "$cargo" test --manifest-path "$SCRIPT_DIR/Cargo.toml" \
        --locked --offline --target "$MOTOR_TARGET" --no-run \
        --target-dir "$WORK/cargo-lorry-motor-tests"
    cp "$SCRIPT_DIR/target/release/lorry" "$WORK/lorry-seed"

    export RUSTUP_HOME="$rustup_home"
    export CARGO_HOME="$WORK/cargo-home"
    host_home="$WORK/host-home"
    "$python" "$SCRIPT_DIR/bootstrap/install_stage2_seed.py" \
        --manifest "$SCRIPT_DIR/bootstrap/stage2-seed.toml" \
        --build-repository "$BUILD_REPOSITORY" \
        --host-repository "$host_home/.config/lorry/system/vendor" \
        --host-user-repository "$host_home/.config/lorry/vendor" \
        --host-config "$host_home/.config/lorry/lorry.toml" \
        --image-repository "$WORK/image/vendor" \
        --motor-config "$WORK/image/lorry.toml" \
        --cache "$DOWNLOAD_CACHE" \
        --mode full --offline \
        --host-c-compiler "$host_c_compiler" \
        --host-archiver "$host_archiver"
    export HOME="$host_home"
    mkdir -p "$CARGO_HOME"

    if [ "$MODE" = "full" ]; then
        copy_package "$SCRIPT_DIR" "$HOST_STAGE/lorry-tree/src/bin/lorry"
        copy_crate "$ROOT_DIR/src/sys/lib/moto-rt" \
            "$HOST_STAGE/lorry-tree/src/sys/lib/moto-rt"
    fi
    copy_package "$ROOT_DIR/src/bin/red" "$HOST_STAGE/red-source"
    copy_package "$ROOT_DIR/src/bin/curl" \
        "$HOST_STAGE/curl-tree/src/bin/curl"
    cp -R "$ROOT_DIR/src/bin/curl/tests" \
        "$HOST_STAGE/curl-tree/src/bin/curl/tests"
    copy_crate "$ROOT_DIR/src/sys/lib/moto-rt" \
        "$HOST_STAGE/curl-tree/src/sys/lib/moto-rt"
    mkdir -p "$HOST_STAGE/curl-tree/img_files/motor-os/sys/cfg/ssl"
    cp "$ROOT_DIR/img_files/motor-os/sys/cfg/ssl/ssl-cert.pem" \
        "$HOST_STAGE/curl-tree/img_files/motor-os/sys/cfg/ssl/ssl-cert.pem"
    mkdir -p "$HOST_STAGE/simple-source/src"
    cat >"$HOST_STAGE/simple-source/Cargo.toml" <<'EOF'
[package]
name = "stage1-native-run"
version = "0.1.0"
edition = "2024"

[dependencies]
EOF
    cat >"$HOST_STAGE/simple-source/Cargo.lock" <<'EOF'
version = 4

[[package]]
name = "stage1-native-run"
version = "0.1.0"
EOF
    cat >"$HOST_STAGE/simple-source/src/main.rs" <<'EOF'
fn main() {
    println!("{}", std::env::args().skip(1).collect::<Vec<_>>().join("|"));
}

#[test]
fn native_unit_test() {
    assert_eq!(env!("CARGO_PKG_NAME"), "stage1-native-run");
}
EOF
    if [ "$MODE" = "full" ]; then
        configure_motor_linker "$HOST_STAGE/lorry-tree/src/bin/lorry"
    fi
    configure_motor_linker "$HOST_STAGE/red-source"
    configure_motor_linker "$HOST_STAGE/simple-source"
    configure_motor_linker "$HOST_STAGE/curl-tree/src/bin/curl"
    configure_motor_native_tools "$HOST_STAGE/curl-tree/src/bin/curl"

    (
        cd "$HOST_STAGE/red-source"
        RUSTC="$motor_rustc" "$WORK/lorry-seed" build --release \
            --target "$MOTOR_TARGET"
    )
    (
        cd "$HOST_STAGE/simple-source"
        RUSTC="$motor_rustc" "$WORK/lorry-seed" build --release \
            --target "$MOTOR_TARGET"
    )
    (
        cd "$HOST_STAGE/curl-tree/src/bin/curl"
        RUSTC="$motor_rustc" "$WORK/lorry-seed" test --release \
            --target "$MOTOR_TARGET" --no-run
    )
    if [ "$MODE" = "full" ]; then
        (
            cd "$HOST_STAGE/lorry-tree/src/bin/lorry"
            RUSTC="$motor_rustc" "$WORK/lorry-seed" build --release \
                --target "$MOTOR_TARGET"
        )
    fi

    mkdir -p "$WORK/cross"
    cp "$WORK/cargo-lorry-motor/$MOTOR_TARGET/release/lorry" \
        "$WORK/cross/lorry-bootstrap"
    if [ "$MODE" = "full" ]; then
        cp "$HOST_STAGE/lorry-tree/src/bin/lorry/target/lorry/$MOTOR_TARGET/release/lorry" \
            "$WORK/cross/lorry"
        CROSS_LORRY="$WORK/cross/lorry"
    fi
    cp "$HOST_STAGE/red-source/target/lorry/$MOTOR_TARGET/release/red" \
        "$WORK/cross/red"
    cp "$HOST_STAGE/simple-source/target/lorry/$MOTOR_TARGET/release/stage1-native-run" \
        "$WORK/cross/stage1-native-run"
    cp "$HOST_STAGE/curl-tree/src/bin/curl/target/lorry/$MOTOR_TARGET/release/curl" \
        "$WORK/cross/curl"
    test_harness=""
    for candidate in \
        "$WORK"/cargo-lorry-motor-tests/"$MOTOR_TARGET"/debug/deps/lorry-*; do
        [ -f "$candidate" ] && [ -x "$candidate" ] || continue
        [ -z "$test_harness" ] ||
            fail "Cargo produced multiple Motor Lorry test executables"
        test_harness="$candidate"
    done
    [ -n "$test_harness" ] ||
        fail "Cargo did not produce the Motor Lorry test executable"
    cp "$test_harness" "$WORK/cross/lorry-tests"
    tls_server=""
    for candidate in \
        "$HOST_STAGE"/curl-tree/src/bin/curl/target/lorry/"$MOTOR_TARGET"/release/deps/https-*; do
        [ -f "$candidate" ] && [ -x "$candidate" ] || continue
        [ -z "$tls_server" ] ||
            fail "Lorry produced multiple Motor HTTPS test executables"
        tls_server="$candidate"
    done
    [ -n "$tls_server" ] ||
        fail "Lorry did not produce the Motor HTTPS test executable"
    cp "$tls_server" "$WORK/cross/https-tests"
    cp "$ROOT_DIR/src/bin/curl/tests/test-ca.pem" "$WORK/cross/test-ca.pem"
    BOOTSTRAP_LORRY="$WORK/cross/lorry-bootstrap"
    CROSS_RED="$WORK/cross/red"
    CROSS_SIMPLE="$WORK/cross/stage1-native-run"
    CROSS_CURL="$WORK/cross/curl"
    CROSS_LORRY_TESTS="$WORK/cross/lorry-tests"
    CROSS_TLS_SERVER="$WORK/cross/https-tests"
    CROSS_TEST_CA="$WORK/cross/test-ca.pem"

    rm -rf "$HOST_STAGE/lorry-tree/src/bin/lorry/target"
    rm -rf "$HOST_STAGE/red-source/target"
    rm -rf "$HOST_STAGE/simple-source/target"
    rm -rf "$HOST_STAGE/curl-tree/src/bin/curl/target"
    rm -rf "$HOST_STAGE/lorry-tree/src/bin/lorry/.cargo"
    rm -rf "$HOST_STAGE/red-source/.cargo"
    rm -rf "$HOST_STAGE/simple-source/.cargo"
    rm -rf "$HOST_STAGE/curl-tree/src/bin/curl/.cargo"
    printf 'motor toolchain: %s\n' "$motor_rustc" >>"$COMMAND_LOG"
    printf 'motor linker: %s\n' "$MOTOR_LINKER" >>"$COMMAND_LOG"
    printf 'motor C compiler: %s\n' "$MOTOR_C_COMPILER" >>"$COMMAND_LOG"
    printf 'motor C sysroot: %s\n' "$MOTOR_C_SYSROOT" >>"$COMMAND_LOG"
    printf 'motor archiver: %s\n' "$MOTOR_ARCHIVER" >>"$COMMAND_LOG"
    printf 'motor image sysroot: %s\n' "$MOTOR_SYSROOT" >>"$COMMAND_LOG"
}

build_image() {
    if [ "$REUSE_VM" -eq 1 ]; then
        return 0
    fi
    echo "== Building the existing Motor $BUILD VM image =="
    if [ "$BUILD" = "release" ]; then
        if ! make -C "$ROOT_DIR" all BUILD=release -j"$(nproc)" \
            >"$IMAGE_BUILD_LOG" 2>&1; then
            tail -80 "$IMAGE_BUILD_LOG" >&2
            fail "Motor release VM image build failed"
        fi
    else
        if ! make -C "$ROOT_DIR" all -j"$(nproc)" >"$IMAGE_BUILD_LOG" 2>&1; then
            tail -80 "$IMAGE_BUILD_LOG" >&2
            fail "Motor debug VM image build failed"
        fi
    fi
    echo "Motor $BUILD VM image is ready"
}

start_vm() {
    local start
    local deadline
    local remaining
    local status

    if [ "$REUSE_VM" -eq 1 ]; then
        timeout 2 "${SSH[@]}" /bin/echo ready >/dev/null ||
            fail "--reuse-running-vm requested, but the VM is not SSH-ready"
        BOOT_MILLISECONDS="reused"
        return
    fi

    echo "== Starting Motor VM (SSH deadline: 10 seconds) =="
    start="$(now_ms)"
    deadline=$((start + 10000))
    "$ROOT_DIR/vm_images/$BUILD/run-qemu.sh" >"$QEMU_LOG" 2>&1 &
    VM_PID="$!"
    VM_STARTED=1

    while :; do
        remaining=$((deadline - $(now_ms)))
        [ "$remaining" -gt 0 ] ||
            fail "Motor VM did not become SSH-ready within 10 seconds"
        set +e
        timeout "$(duration_from_ms "$remaining")" "${SSH[@]}" -o ConnectTimeout=1 \
            /bin/echo ready >/dev/null 2>&1
        status="$?"
        set -e
        if [ "$status" -eq 0 ]; then
            break
        fi
        [ "$status" -ne 124 ] ||
            fail "Motor VM did not become SSH-ready within 10 seconds"
        sleep 0.1
    done
    BOOT_MILLISECONDS=$(($(now_ms) - start))
}

stage_native_inputs() {
    echo "== Staging pristine inputs through SFTP =="
    native_command "[ -d /user/tmp ] || /bin/mkdir /user/tmp"
    native_command "[ -d $REMOTE_BASE ] || /bin/mkdir $REMOTE_BASE"
    remote_mkdir "$REMOTE_ROOT"
    REMOTE_CREATED=1
    remote_mkdir "$REMOTE_ROOT/bin"
    remote_mkdir "$REMOTE_ROOT/home"
    upload_file "$BOOTSTRAP_LORRY" "$REMOTE_ROOT/bin/lorry-bootstrap"
    upload_file "$CROSS_CURL" "$REMOTE_ROOT/bin/curl"
    upload_file "$CROSS_LORRY_TESTS" "$REMOTE_ROOT/bin/lorry-tests"
    upload_file "$CROSS_TLS_SERVER" "$REMOTE_ROOT/bin/https-tests"
    upload_file "$CROSS_TEST_CA" "$REMOTE_ROOT/test-ca.pem"
    upload_tree "$HOST_STAGE/red-source" "$REMOTE_ROOT/red-source"
    upload_tree "$HOST_STAGE/simple-source" "$REMOTE_ROOT/simple-source"
    if [ "$MODE" = "full" ]; then
        upload_tree "$HOST_STAGE/lorry-tree" "$REMOTE_ROOT/lorry-tree"
    fi
}

run_smoke_gate() {
    local bootstrap="$REMOTE_ROOT/bin/lorry-bootstrap"
    local red_work="$REMOTE_ROOT/red-work"
    local simple_work="$REMOTE_ROOT/simple-work"
    local simple_output="$EVIDENCE_DIR/simple-run.txt"
    local curl_log="$EVIDENCE_DIR/native-curl.log"

    echo "== Running Motor-native build/run/test gate =="
    native_command "$bootstrap --version"
    remote_copy_tree "$REMOTE_ROOT/red-source" "$red_work"
    native_command "cd $red_work && $bootstrap build"
    native_command "cd $red_work && $bootstrap build --release"
    compare_artifact native-red \
        "$red_work/target/lorry/release/red" "$CROSS_RED"
    run_native_test "$red_work" "$bootstrap" red-test

    remote_copy_tree "$REMOTE_ROOT/simple-source" "$simple_work"
    native_capture "$simple_output" \
        "cd $simple_work && $bootstrap run --release -- native 'two words'"
    grep -Fx "native|two words" "$simple_output" >/dev/null ||
        fail "native run did not preserve its arguments"
    compare_artifact native-run \
        "$simple_work/target/lorry/release/stage1-native-run" "$CROSS_SIMPLE"

    echo "== Running Lorry's curl boundary through native Motor curl =="
    native_capture "$curl_log" \
        "LORRY_TEST_CURL=$REMOTE_ROOT/bin/curl LORRY_TEST_CA=$REMOTE_ROOT/test-ca.pem LORRY_TEST_UNTRUSTED_CA=/sys/cfg/ssl/ssl-cert.pem LORRY_TEST_TLS_SERVER=$REMOTE_ROOT/bin/https-tests $REMOTE_ROOT/bin/lorry-tests selected_curl --quiet"
    grep -F "test result: ok. 5 passed; 0 failed" "$curl_log" >/dev/null ||
        fail "native Motor curl fixture did not report exactly five passing tests"
}

run_full_gate() {
    local bootstrap="$REMOTE_ROOT/bin/lorry-bootstrap"
    local native_lorry="$REMOTE_ROOT/bin/lorry-native"
    local lorry_first_tree="$REMOTE_ROOT/lorry-first"
    local lorry_second_tree="$REMOTE_ROOT/lorry-second"
    local lorry_first="$lorry_first_tree/src/bin/lorry"
    local lorry_second="$lorry_second_tree/src/bin/lorry"
    local red_second="$REMOTE_ROOT/red-second"
    local simple_second="$REMOTE_ROOT/simple-second"
    local simple_output="$EVIDENCE_DIR/simple-run-generation-2.txt"

    echo "== Running Motor-native self-build and second-generation gate =="
    remote_copy_tree "$REMOTE_ROOT/lorry-tree" "$lorry_first_tree"
    native_command "cd $lorry_first && $bootstrap build --release"
    compare_artifact native-lorry-generation-1 \
        "$lorry_first/target/lorry/release/lorry" "$CROSS_LORRY"
    native_command "/bin/cp $lorry_first/target/lorry/release/lorry $native_lorry"

    remote_copy_tree "$REMOTE_ROOT/lorry-tree" "$lorry_second_tree"
    native_command "cd $lorry_second && $native_lorry build --release"
    compare_artifact native-lorry-generation-2 \
        "$lorry_second/target/lorry/release/lorry" "$CROSS_LORRY"

    remote_copy_tree "$REMOTE_ROOT/red-source" "$red_second"
    native_command "cd $red_second && $native_lorry build --release"
    compare_artifact native-red-generation-2 \
        "$red_second/target/lorry/release/red" "$CROSS_RED"
    run_native_test "$red_second" "$native_lorry" red-generation-2-test

    remote_copy_tree "$REMOTE_ROOT/simple-source" "$simple_second"
    native_capture "$simple_output" \
        "cd $simple_second && $native_lorry run --release -- second generation"
    grep -Fx "second|generation" "$simple_output" >/dev/null ||
        fail "second-generation native run did not preserve its arguments"
}

retrieve_failure_evidence() {
    local batch="$WORK/failure-download.batch"
    [ "$REMOTE_CREATED" -eq 1 ] || return
    mkdir -p "$ARTIFACT_DIR/failure"
    : >"$batch"
    printf -- '-get %s %s\n' \
        "$REMOTE_ROOT/red-work/target/lorry/release/red" \
        "$ARTIFACT_DIR/failure/red" >>"$batch"
    printf -- '-get %s %s\n' \
        "$REMOTE_ROOT/lorry-first/src/bin/lorry/target/lorry/release/lorry" \
        "$ARTIFACT_DIR/failure/lorry-first" >>"$batch"
    printf -- '-get %s %s\n' \
        "$REMOTE_ROOT/lorry-second/src/bin/lorry/target/lorry/release/lorry" \
        "$ARTIFACT_DIR/failure/lorry-second" >>"$batch"
    printf -- '-get %s %s\n' \
        "$REMOTE_ROOT/red-test.log" \
        "$ARTIFACT_DIR/failure/red-test.log" >>"$batch"
    printf -- '-get %s %s\n' \
        "$REMOTE_ROOT/red-generation-2-test.log" \
        "$ARTIFACT_DIR/failure/red-generation-2-test.log" >>"$batch"
    timeout 5 sftp "${SFTP_OPTIONS[@]}" -b "$batch" motor@192.168.4.2 \
        >>"$SFTP_LOG" 2>&1 || true
}

cleanup() {
    local status="$?"
    trap - EXIT
    set +e

    if [ "$status" -ne 0 ]; then
        retrieve_failure_evidence
        {
            echo "result: FAIL"
            echo "mode: $MODE"
            echo "boot_ms: $BOOT_MILLISECONDS"
            echo "evidence: $EVIDENCE_DIR"
        } >"$SUMMARY"
    fi

    if [ "$REMOTE_CREATED" -eq 1 ]; then
        case "$REMOTE_ROOT" in
            "$REMOTE_BASE"/*)
                timeout 5 "${SSH[@]}" "/bin/rm -r $REMOTE_ROOT" \
                    >>"$NATIVE_LOG" 2>&1
                ;;
        esac
    fi

    if [ "$VM_STARTED" -eq 1 ]; then
        timeout 3 "${SSH[@]}" shutdown >>"$NATIVE_LOG" 2>&1
        for _ in $(seq 1 20); do
            kill -0 "$VM_PID" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$VM_PID" 2>/dev/null; then
            kill "$VM_PID" 2>/dev/null
        fi
        wait "$VM_PID" 2>/dev/null
    fi

    rm -rf "$WORK"
    if [ "$status" -eq 0 ] && [ "$KEEP" -eq 0 ]; then
        rm -rf "$ARTIFACT_DIR"
        rm -f "$NATIVE_LOG" "$SFTP_LOG" "$COMMAND_LOG" "$QEMU_LOG" \
            "$IMAGE_BUILD_LOG" "$EVIDENCE_DIR/simple-run.txt" \
            "$EVIDENCE_DIR/simple-run-generation-2.txt" \
            "$EVIDENCE_DIR/native-curl.log" \
            "$EVIDENCE_DIR/red-test.log" \
            "$EVIDENCE_DIR/red-generation-2-test.log"
    fi
    if [ "$status" -ne 0 ]; then
        echo "test-native: evidence retained at $EVIDENCE_DIR" >&2
    fi
    exit "$status"
}
trap cleanup EXIT

echo "== Running Stage 2 seed fixture tests =="
(
    cd "$SCRIPT_DIR/bootstrap"
    python3 -m unittest discover -s tests -p 'test_*.py' -v
)

build_image
prepare_host_gate
start_vm

PHASE_START_MS="$(now_ms)"
PHASE_DEADLINE_MS=$((PHASE_START_MS + PHASE_BUDGET * 1000))
stage_native_inputs
run_smoke_gate
if [ "$MODE" = "full" ]; then
    run_full_gate
fi
NATIVE_MILLISECONDS=$(($(now_ms) - PHASE_START_MS))

{
    echo "result: PASS"
    echo "mode: $MODE"
    echo "vm: $BUILD"
    echo "boot_ms: $BOOT_MILLISECONDS"
    echo "native_phase_ms: $NATIVE_MILLISECONDS"
    echo "remote_cleanup: $REMOTE_ROOT"
    cat "$HASH_LOG"
} >"$SUMMARY"

echo
echo "PASS: Stage 1 Motor-native $MODE gate passed"
echo "boot: ${BOOT_MILLISECONDS}ms; native phase: ${NATIVE_MILLISECONDS}ms"
echo "summary: $SUMMARY"
