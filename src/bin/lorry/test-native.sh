#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
MOTOR_TARGET="x86_64-unknown-motor"
MOTOR_TOOLCHAIN="${LORRY_MOTOR_TOOLCHAIN:-dev-x86_64-unknown-motor}"
MOTOR_LINKER="${LORRY_MOTOR_LINKER:-/home/posk/motor-dev/motor-sysroot/bin/motor-clang}"
MOTOR_SYSROOT="${LORRY_MOTOR_SYSROOT:-$ROOT_DIR/img_files/generated/rustc/sys/tools/rust}"
BUILD_REPOSITORY="$ROOT_DIR/build/lorry/stage2/system-seed"
DOWNLOAD_CACHE="$ROOT_DIR/build/lorry/stage2/download-cache"
REMOTE_BASE="/user/tmp/lorry-self"

BUILD="debug"
FULL=0
KEEP=0
REUSE_VM=0

usage() {
    cat <<'EOF'
usage: test-native.sh [--full] [--release] [--reuse-running-vm] [--keep]

Runs Lorry's self-only Linux-to-Motor and Motor-to-Motor verification. The
repository integration driver owns tests of Red, Rush, curl, and other
downstream packages. --full adds a second Motor-native Lorry generation.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --full) FULL=1 ;;
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

RUN_ID="self-$(date -u +%Y%m%dT%H%M%SZ)-$$"
WORK="$(mktemp -d /tmp/lorry-native-self-XXXXXX)"
EVIDENCE_DIR="$SCRIPT_DIR/target/lorry/native-self-tests/$RUN_ID"
TIMING_LOG="$EVIDENCE_DIR/timings.tsv"
QEMU_LOG="$EVIDENCE_DIR/qemu.log"
NATIVE_LOG="$EVIDENCE_DIR/native.log"
SUMMARY="$EVIDENCE_DIR/summary.txt"
REMOTE_ROOT="$REMOTE_BASE/$RUN_ID"
SSH_KEY="$WORK/test.key"

# shellcheck source=tests/timing.sh
source "$SCRIPT_DIR/tests/timing.sh"

mkdir -p "$EVIDENCE_DIR"
: >"$NATIVE_LOG"
timing_init "$TIMING_LOG"

fail() {
    echo "test-native: $*" >&2
    exit 1
}

copy_package() {
    local source="$1"
    local destination="$2"
    mkdir -p "$destination"
    cp "$source/Cargo.toml" "$source/Cargo.lock" "$destination/"
    cp -R "$source/src" "$destination/src"
    if [ -d "$source/.lorry" ]; then
        cp -R "$source/.lorry" "$destination/.lorry"
    fi
}

remote_command() {
    local remaining=$((PHASE_DEADLINE_MS - $(timing_now_ms)))
    [ "$remaining" -gt 0 ] || fail "native self phase exceeded ${PHASE_BUDGET}s"
    timeout "$(awk -v ms="$remaining" 'BEGIN { printf "%.3f", ms / 1000 }')" \
        "${SSH[@]}" "$@" 2>&1 | tee -a "$NATIVE_LOG"
}

upload_tree() {
    local source="$1"
    local destination="$2"
    local batch="$WORK/upload.batch"
    printf 'put -pR %s %s\n' "$source" "$destination" >"$batch"
    timeout 120 sftp "${SFTP_OPTIONS[@]}" -b "$batch" motor@192.168.4.2 \
        >>"$NATIVE_LOG" 2>&1
}

upload_file() {
    local source="$1"
    local destination="$2"
    local batch="$WORK/upload.batch"
    printf 'put %s %s\nchmod 700 %s\n' \
        "$source" "$destination" "$destination" >"$batch"
    timeout 120 sftp "${SFTP_OPTIONS[@]}" -b "$batch" motor@192.168.4.2 \
        >>"$NATIVE_LOG" 2>&1
}

download_file() {
    local source="$1"
    local destination="$2"
    local batch="$WORK/download.batch"
    printf 'get %s %s\n' "$source" "$destination" >"$batch"
    timeout 60 sftp "${SFTP_OPTIONS[@]}" -b "$batch" motor@192.168.4.2 \
        >>"$NATIVE_LOG" 2>&1
}

build_image() {
    [ "$REUSE_VM" -eq 0 ] || return
    [ -x "$ROOT_DIR/vm_images/$BUILD/run-qemu.sh" ] ||
        fail "Motor $BUILD image is absent; build it before running Lorry tests"
}

prepare_host() {
    local cargo
    local host_archiver
    local host_c_compiler
    local host_home="$WORK/host-home"
    local host_rustc
    local motor_rustc
    local motor_toolchain_sysroot
    local profile_args=()
    local source="$WORK/source/src/bin/lorry"

    cargo="$(rustup which cargo --toolchain nightly-2026-06-19)"
    host_rustc="$(rustup which rustc --toolchain nightly-2026-06-19)"
    motor_rustc="$(rustup which rustc --toolchain "$MOTOR_TOOLCHAIN")"
    motor_toolchain_sysroot="$($motor_rustc --print sysroot)"
    host_c_compiler="$(type -P clang)"
    host_archiver="$(type -P ar)"
    [ "$BUILD" = "debug" ] || profile_args+=(--release)
    [ -x "$MOTOR_LINKER" ] || fail "Motor linker '$MOTOR_LINKER' is absent"
    [ -d "$MOTOR_SYSROOT/lib/rustlib/$MOTOR_TARGET" ] ||
        fail "Motor sysroot '$MOTOR_SYSROOT' is incomplete"
    diff -qr "$motor_toolchain_sysroot/lib/rustlib/$MOTOR_TARGET" \
        "$MOTOR_SYSROOT/lib/rustlib/$MOTOR_TARGET" >"$WORK/sysroot-diff" || {
        cat "$WORK/sysroot-diff" >&2
        fail "Linux and image Motor target sysroots differ"
    }
    [ -d "$BUILD_REPOSITORY/objects" ] || fail "Stage 2 repository is absent"
    [ -d "$DOWNLOAD_CACHE" ] || fail "Stage 2 download cache is absent"

    unset CARGO_TARGET_DIR RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
    unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
    CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTC="$host_rustc" \
        "$cargo" build --manifest-path "$SCRIPT_DIR/Cargo.toml" \
        --locked --offline --release
    cp "$SCRIPT_DIR/target/release/lorry" "$WORK/lorry-seed"

    python3 "$SCRIPT_DIR/bootstrap/install_stage2_seed.py" \
        --manifest "$SCRIPT_DIR/bootstrap/stage2-seed.toml" \
        --build-repository "$BUILD_REPOSITORY" \
        --host-repository "$host_home/.config/lorry/system/vendor" \
        --host-user-repository "$host_home/.config/lorry/vendor" \
        --host-config "$host_home/.config/lorry/lorry.toml" \
        --image-repository "$WORK/image/vendor" \
        --motor-config "$WORK/image/lorry.toml" \
        --cache "$DOWNLOAD_CACHE" --mode full --offline \
        --host-c-compiler "$host_c_compiler" --host-archiver "$host_archiver"

    copy_package "$SCRIPT_DIR" "$source"
    mkdir -p "$WORK/source/src/sys/lib/moto-rt"
    cp "$ROOT_DIR/src/sys/lib/moto-rt/Cargo.toml" \
        "$WORK/source/src/sys/lib/moto-rt/"
    cp -R "$ROOT_DIR/src/sys/lib/moto-rt/src" \
        "$WORK/source/src/sys/lib/moto-rt/src"
    mkdir -p "$source/.cargo"
    printf '[target.%s]\nlinker = "%s"\n' \
        "$MOTOR_TARGET" "$MOTOR_LINKER" \
        >"$source/.cargo/config.toml"

    (
        cd "$source"
        HOME="$host_home" RUSTC="$motor_rustc" "$WORK/lorry-seed" \
            build "${profile_args[@]}" --target "$MOTOR_TARGET"
    )
    CROSS_LORRY="$source/target/lorry/$MOTOR_TARGET/$BUILD/lorry"
    [ -f "$CROSS_LORRY" ] || fail "cross-build did not produce Lorry"
    cp "$CROSS_LORRY" "$WORK/lorry-cross"
    rm -rf "$source/target" "$source/.cargo"
}

start_vm() {
    if [ "$REUSE_VM" -eq 0 ]; then
        "$ROOT_DIR/vm_images/$BUILD/run-qemu.sh" -m 2048M >"$QEMU_LOG" 2>&1 &
        VM_PID="$!"
        VM_STARTED=1
    fi
    local deadline=$((SECONDS + 10))
    until timeout 2 "${SSH[@]}" /bin/echo ready >/dev/null 2>&1; do
        [ "$SECONDS" -lt "$deadline" ] || fail "Motor VM was not ready in 10 seconds"
        [ "$VM_STARTED" -eq 0 ] || kill -0 "$VM_PID" 2>/dev/null ||
            fail "Motor VM exited before SSH became ready"
        sleep 0.1
    done
}

run_native() {
    local first="$REMOTE_ROOT/lorry-first/src/bin/lorry"
    local second="$REMOTE_ROOT/lorry-second/src/bin/lorry"
    local build_command="build"
    if [ "$BUILD" = "release" ]; then
        build_command="build --release"
    fi

    remote_command "[ -d /user/tmp ] || /bin/mkdir /user/tmp"
    remote_command "[ -d $REMOTE_BASE ] || /bin/mkdir $REMOTE_BASE"
    remote_command "/bin/mkdir $REMOTE_ROOT"
    REMOTE_CREATED=1
    upload_tree "$WORK/source" "$REMOTE_ROOT/lorry-first"
    upload_tree "$WORK/source" "$REMOTE_ROOT/lorry-second"
    upload_file "$WORK/lorry-cross" "$REMOTE_ROOT/lorry-cross"

    remote_command "$REMOTE_ROOT/lorry-cross --version"
    remote_command "cd $first && $REMOTE_ROOT/lorry-cross $build_command"
    remote_command "$first/target/lorry/$BUILD/lorry --version"
    remote_command "/bin/cp $first/target/lorry/$BUILD/lorry $REMOTE_ROOT/lorry-native"

    if [ "$BUILD" = "release" ]; then
        download_file "$first/target/lorry/release/lorry" "$WORK/lorry-native"
        cmp "$WORK/lorry-cross" "$WORK/lorry-native" ||
            fail "Linux-to-Motor and Motor-native Lorry executables differ"
    fi
    if [ "$FULL" -eq 1 ]; then
        remote_command "cd $second && $REMOTE_ROOT/lorry-native $build_command"
        remote_command "$second/target/lorry/$BUILD/lorry --version"
        if [ "$BUILD" = "release" ]; then
            download_file "$second/target/lorry/release/lorry" "$WORK/lorry-native-2"
            cmp "$WORK/lorry-cross" "$WORK/lorry-native-2" ||
                fail "second-generation native Lorry differs from the cross-build"
        fi
    fi
}

cleanup() {
    local status="$?"
    trap - EXIT
    set +e
    timing_finish "$status"
    if [ "$REMOTE_CREATED" -eq 1 ]; then
        case "$REMOTE_ROOT" in
            "$REMOTE_BASE"/*) timeout 5 "${SSH[@]}" "/bin/rm -r $REMOTE_ROOT" >/dev/null 2>&1 ;;
        esac
    fi
    if [ "$VM_STARTED" -eq 1 ]; then
        timeout 3 "${SSH[@]}" shutdown >/dev/null 2>&1
        if kill -0 "$VM_PID" 2>/dev/null; then
            kill "$VM_PID" 2>/dev/null
        fi
        wait "$VM_PID" 2>/dev/null
    fi
    {
        [ "$status" -eq 0 ] && echo "result: PASS" || echo "result: FAIL"
        echo "profile: $BUILD"
        cat "$TIMING_LOG"
    } >"$SUMMARY"
    if [ "$status" -ne 0 ]; then
        for artifact in lorry-cross lorry-native lorry-native-2; do
            [ ! -f "$WORK/$artifact" ] ||
                cp "$WORK/$artifact" "$EVIDENCE_DIR/$artifact"
        done
    fi
    rm -rf "$WORK"
    if [ "$status" -eq 0 ] && [ "$KEEP" -eq 0 ]; then
        rm -f "$NATIVE_LOG" "$QEMU_LOG"
    fi
    [ "$status" -eq 0 ] || echo "test-native: evidence retained at $EVIDENCE_DIR" >&2
    exit "$status"
}

VM_PID=""
VM_STARTED=0
REMOTE_CREATED=0
default_phase_budget=3600
[ "$FULL" -eq 0 ] || default_phase_budget=5400
PHASE_BUDGET="${LORRY_NATIVE_SELF_TIMEOUT:-$default_phase_budget}"
PHASE_DEADLINE_MS=0
case "$PHASE_BUDGET" in
    '' | *[!0-9]* | 0) fail "native self timeout must be a positive integer" ;;
esac
trap cleanup EXIT

[ -f "$ROOT_DIR/src/tests/test.key" ] || fail "Motor test SSH key is absent"
cp "$ROOT_DIR/src/tests/test.key" "$SSH_KEY"
chmod 600 "$SSH_KEY"
SSH_OPTIONS=(-n -F /dev/null -p 2222 -i "$SSH_KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
SSH=(ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2)
SFTP_OPTIONS=(-F /dev/null -P 2222 -i "$SSH_KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

timing_start motor-image-prerequisite
build_image
timing_finish
timing_start lorry-host-preparation
prepare_host
timing_finish
timing_start vm-startup
start_vm
timing_finish
PHASE_DEADLINE_MS=$(($(timing_now_ms) + PHASE_BUDGET * 1000))
timing_start native-lorry-self-gate
run_native
timing_finish

echo "PASS: Lorry self-built from Linux for Motor and natively on Motor"
