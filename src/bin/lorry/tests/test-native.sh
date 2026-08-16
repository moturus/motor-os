#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LORRY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
MOTOR_TARGET="x86_64-unknown-motor"
MOTOR_TOOLCHAIN="${LORRY_MOTOR_TOOLCHAIN:-dev-x86_64-unknown-motor}"
MOTOR_LINKER="${LORRY_MOTOR_LINKER:-/home/posk/motor-dev/motor-sysroot/bin/motor-clang}"
MOTOR_SYSROOT="${LORRY_MOTOR_SYSROOT:-$ROOT_DIR/img_files/generated/rustc/sys/tools/rust}"
BUILD_REPOSITORY="$ROOT_DIR/build/lorry/stage2/system-seed"
DOWNLOAD_CACHE="$ROOT_DIR/build/lorry/stage2/download-cache"
REMOTE_BASE="/user/tmp/lorry-self"

IMAGE_NAME="motor-os-dev.img"
# Four vCPUs and 4 GiB are sufficient for the compact native fixture.
VM_SMP="${LORRY_VM_SMP:-4}"
VM_MEMORY="${LORRY_VM_MEMORY:-4096M}"
# Lorry's unit concurrency inside the guest. ssh carries no environment, so
# the only way to set it there is an explicit prefix on the remote command.
# Empty means the guest chooses its own default (its available parallelism).
JOBS_PREFIX=""
[ -z "${LORRY_JOBS:-}" ] || JOBS_PREFIX="LORRY_JOBS=$LORRY_JOBS "
KEEP=0
REUSE_VM=0
WARM=0

usage() {
    cat <<'EOF'
usage: test-native.sh [--reuse-running-vm] [--warm] [--keep]

Runs Lorry's release Linux-to-Motor and Motor-to-Motor verification in the
release developer image. It retains one native self-build, one compact
build/run/test fixture, and a debug incremental-state check. --warm preserves
host and guest targets for iteration.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --reuse-running-vm) REUSE_VM=1 ;;
        --warm) WARM=1 ;;
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
WORK_LOCK=""
release_work_lock() {
    [ -z "$WORK_LOCK" ] || rmdir "$WORK_LOCK" 2>/dev/null || true
}
if [ "$WARM" -eq 1 ]; then
    WORK="$ROOT_DIR/build/lorry/warm/native-self/release"
    WORK_LOCK="$WORK.lock"
    mkdir -p "$(dirname "$WORK")"
    mkdir "$WORK_LOCK" 2>/dev/null || {
        echo "test-native: warm release workspace is already in use" >&2
        exit 1
    }
    trap release_work_lock EXIT
    mkdir -p "$WORK"
else
    WORK="$(mktemp -d /tmp/lorry-native-self-XXXXXX)"
fi
EVIDENCE_DIR="$LORRY_DIR/target/lorry/native-self-tests/$RUN_ID"
TIMING_LOG="$EVIDENCE_DIR/timings.tsv"
QEMU_LOG="$EVIDENCE_DIR/qemu.log"
NATIVE_LOG="$EVIDENCE_DIR/native.log"
SUMMARY="$EVIDENCE_DIR/summary.txt"
if [ "$WARM" -eq 1 ]; then
    REMOTE_ROOT="$REMOTE_BASE/warm-release"
else
    REMOTE_ROOT="$REMOTE_BASE/$RUN_ID"
fi
SSH_KEY="$WORK/test.key"

# shellcheck source=timing.sh
source "$SCRIPT_DIR/timing.sh"

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
    rm -rf "$destination/src" "$destination/.lorry"
    cp "$source/Cargo.toml" "$source/Cargo.lock" "$destination/"
    cp -R "$source/src" "$destination/src"
    if [ -d "$source/.lorry" ]; then
        cp -R "$source/.lorry" "$destination/.lorry"
    fi
}

copy_native_fixture() {
    local destination="$1"
    local source="$SCRIPT_DIR/native-fixture"
    rm -rf "$destination"
    mkdir -p "$destination"
    cp "$source/Cargo.toml" "$source/Cargo.lock" "$source/lorry.toml" \
        "$destination/"
    cp -R "$source/.lorry" "$source/src" "$source/tests" \
        "$source/fixture-generated-dependency" \
        "$source/fixture-motor-target-dependency" "$destination/"
}

remote_command() {
    local remaining=$((PHASE_DEADLINE_MS - $(timing_now_ms)))
    [ "$remaining" -gt 0 ] || fail "native self phase exceeded ${PHASE_BUDGET}s"
    timeout "$(awk -v ms="$remaining" 'BEGIN { printf "%.3f", ms / 1000 }')" \
        "${SSH[@]}" "$@" 2>&1 | tee -a "$NATIVE_LOG"
}

remote_command_expect_failure() {
    if remote_command "$@"; then
        fail "remote command unexpectedly succeeded: $*"
    fi
}

upload_tree() {
    local source="$1"
    local destination="$2"
    local batch="$WORK/upload.batch"
    printf 'put -pR %s/. %s\n' "$source" "$destination" >"$batch"
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
    [ "$REUSE_VM" -eq 0 ] || return 0
    [ -x "$ROOT_DIR/vm_images/release/run-qemu.sh" ] ||
        fail "Motor release image is absent; build it before running Lorry tests"
    [ -f "$ROOT_DIR/vm_images/release/$IMAGE_NAME" ] ||
        fail "Motor developer image is absent; build it before running Lorry tests"
}

prepare_host() {
    local cargo
    local host_archiver
    local host_c_compiler
    local host_home="$WORK/host-home"
    local host_rustc
    local motor_rustc
    local motor_toolchain_sysroot
    local host_tree="$WORK/host-source"
    local guest_tree="$WORK/guest-source"
    local source="$host_tree/src/bin/lorry"

    cargo="$(rustup which cargo --toolchain nightly-2026-06-19)"
    host_rustc="$(rustup which rustc --toolchain nightly-2026-06-19)"
    motor_rustc="$(rustup which rustc --toolchain "$MOTOR_TOOLCHAIN")"
    motor_toolchain_sysroot="$($motor_rustc --print sysroot)"
    host_c_compiler="$(type -P clang)"
    host_archiver="$(type -P ar)"
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
        "$cargo" build --manifest-path "$LORRY_DIR/Cargo.toml" \
        --locked --offline --release
    cp "$LORRY_DIR/target/release/lorry" "$WORK/lorry-seed"

    python3 "$LORRY_DIR/bootstrap/install_stage2_seed.py" \
        --manifest "$LORRY_DIR/bootstrap/stage2-seed.toml" \
        --build-repository "$BUILD_REPOSITORY" \
        --host-repository "$host_home/.config/lorry/system/vendor" \
        --host-user-repository "$host_home/.config/lorry/vendor" \
        --host-config "$host_home/.config/lorry/lorry.toml" \
        --image-repository "$WORK/image/vendor" \
        --motor-config "$WORK/image/lorry.toml" \
        --cache "$DOWNLOAD_CACHE" --mode full --offline \
        --host-c-compiler "$host_c_compiler" --host-archiver "$host_archiver"

    for tree in "$host_tree" "$guest_tree"; do
        copy_package "$LORRY_DIR" "$tree/src/bin/lorry"
        mkdir -p "$tree/src/sys/lib/moto-rt"
        cp "$ROOT_DIR/src/sys/lib/moto-rt/Cargo.toml" \
            "$tree/src/sys/lib/moto-rt/"
        rm -rf "$tree/src/sys/lib/moto-rt/src"
        cp -R "$ROOT_DIR/src/sys/lib/moto-rt/src" \
            "$tree/src/sys/lib/moto-rt/src"
    done
    copy_native_fixture "$WORK/native-fixture"
    rm -rf "$WORK/proc-macro-fixture"
    cp -R "$SCRIPT_DIR/proc-macro-fixture" "$WORK/proc-macro-fixture"
    rm -rf "$guest_tree/src/bin/lorry/target" \
        "$guest_tree/src/bin/lorry/.cargo"
    mkdir -p "$source/.cargo"
    printf '[target.%s]\nlinker = "%s"\n' \
        "$MOTOR_TARGET" "$MOTOR_LINKER" \
        >"$source/.cargo/config.toml"

    (
        cd "$source"
        HOME="$host_home" RUSTC="$motor_rustc" "$WORK/lorry-seed" \
            build --release --target "$MOTOR_TARGET"
    )
    CROSS_LORRY="$source/target/lorry/$MOTOR_TARGET/release/lorry"
    [ -f "$CROSS_LORRY" ] || fail "cross-build did not produce Lorry"
    cp "$CROSS_LORRY" "$WORK/lorry-cross"
    rm -rf "$source/.cargo"
}

start_vm() {
    if [ "$REUSE_VM" -eq 0 ]; then
        # A VM leaked by an earlier run keeps answering on the tap, and every
        # ssh below would reach it rather than the guest this run starts --
        # testing an unknown image and reporting the result as this run's.
        if timeout 2 "${SSH[@]}" /bin/echo ready >/dev/null 2>&1; then
            fail "a VM is already answering on the tap; stop it before running"
        fi
        MOTO_IMAGE="$IMAGE_NAME" MOTO_SMP="$VM_SMP" \
            "$ROOT_DIR/vm_images/release/run-qemu.sh" \
            -m "$VM_MEMORY" >"$QEMU_LOG" 2>&1 &
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
    local fixture="$REMOTE_ROOT/native-fixture"
    local proc_macro_fixture="$REMOTE_ROOT/proc-macro-fixture"
    local destination="$REMOTE_ROOT/lorry-first"

    remote_command "[ -d /user/tmp ] || /bin/mkdir /user/tmp"
    remote_command "[ -d $REMOTE_BASE ] || /bin/mkdir $REMOTE_BASE"
    remote_command "[ -d $REMOTE_ROOT ] || /bin/mkdir $REMOTE_ROOT"
    REMOTE_CREATED=1
    upload_file "$WORK/lorry-cross" "$REMOTE_ROOT/lorry-cross"

    remote_command "$REMOTE_ROOT/lorry-cross --version"
    remote_command "[ -d $destination ] || /bin/mkdir $destination"
    if [ "$WARM" -eq 1 ]; then
        remote_command "[ ! -d $destination/src/bin/lorry/src ] || /bin/rm -r $destination/src/bin/lorry/src"
        remote_command "[ ! -d $destination/src/bin/lorry/.lorry ] || /bin/rm -r $destination/src/bin/lorry/.lorry"
        remote_command "[ ! -d $destination/src/sys/lib/moto-rt/src ] || /bin/rm -r $destination/src/sys/lib/moto-rt/src"
    fi
    upload_tree "$WORK/guest-source" "$destination"
    remote_command "[ -d $fixture ] || /bin/mkdir $fixture"
    if [ "$WARM" -eq 1 ]; then
        for path in .lorry src tests fixture-generated-dependency \
            fixture-motor-target-dependency; do
            remote_command "[ ! -d $fixture/$path ] || /bin/rm -r $fixture/$path"
        done
    fi
    upload_tree "$WORK/native-fixture" "$fixture"
    remote_command "[ -d $proc_macro_fixture ] || /bin/mkdir $proc_macro_fixture"
    upload_tree "$WORK/proc-macro-fixture" "$proc_macro_fixture"

    remote_command "cd $first && ${JOBS_PREFIX}$REMOTE_ROOT/lorry-cross build --release"
    remote_command "$first/target/lorry/release/lorry --version"
    remote_command "/bin/cp $first/target/lorry/release/lorry $REMOTE_ROOT/lorry-native"
    download_file "$first/target/lorry/release/lorry" "$WORK/lorry-native"
    cmp "$WORK/lorry-cross" "$WORK/lorry-native" ||
        fail "Linux-to-Motor and Motor-native Lorry executables differ"
    remote_command "cd $fixture && ${JOBS_PREFIX}$REMOTE_ROOT/lorry-native build --release"
    remote_command "cd $fixture && $REMOTE_ROOT/lorry-native run --release -- first 'two words'"
    remote_command "cd $fixture && $REMOTE_ROOT/lorry-native test --release -- --quiet"
    remote_command "cd $fixture && ${JOBS_PREFIX}$REMOTE_ROOT/lorry-native -v build"
    remote_command_expect_failure "cd $proc_macro_fixture && ${JOBS_PREFIX}$REMOTE_ROOT/lorry-native build --release"
    grep -F "native Motor OS procedural macros are not supported by this Rust compiler" \
        "$NATIVE_LOG" >/dev/null ||
        fail "native proc-macro rejection was not human-readable"
    remote_command "/bin/cp $fixture/src/main.rs $fixture/main.rs.copy && /bin/cp $fixture/main.rs.copy $fixture/src/main.rs && /bin/rm $fixture/main.rs.copy"
    remote_command "cd $fixture && ${JOBS_PREFIX}$REMOTE_ROOT/lorry-native -v build"
    local incremental="$fixture/target/lorry/.incremental/$MOTOR_TARGET"
    local incremental_lines="$WORK/motor-incremental-lines"
    grep -F "incremental=$incremental" "$NATIVE_LOG" >"$incremental_lines" ||
        fail "Motor debug rustc commands did not use persistent incremental state"
    [ "$(wc -l <"$incremental_lines")" -ge 2 ] ||
        fail "two Motor debug compilations did not reuse the same incremental root"
}

cleanup() {
    local status="$?"
    trap - EXIT
    set +e
    timing_finish "$status"
    if [ "$REMOTE_CREATED" -eq 1 ] && [ "$WARM" -eq 0 ]; then
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
        echo "profile: release"
        echo "image: release/$IMAGE_NAME"
        echo "vm: ${VM_SMP} vcpus, $VM_MEMORY"
        echo "mode: native-self"
        cat "$TIMING_LOG"
    } >"$SUMMARY"
    if [ "$status" -ne 0 ]; then
        for artifact in lorry-cross lorry-native; do
            [ ! -f "$WORK/$artifact" ] ||
                cp "$WORK/$artifact" "$EVIDENCE_DIR/$artifact"
        done
    fi
    if [ "$WARM" -eq 0 ]; then
        rm -rf "$WORK"
    elif [ -n "$WORK_LOCK" ]; then
        release_work_lock
    fi
    if [ "$status" -eq 0 ] && [ "$KEEP" -eq 0 ]; then
        rm -f "$NATIVE_LOG" "$QEMU_LOG"
    fi
    [ "$status" -eq 0 ] || echo "test-native: evidence retained at $EVIDENCE_DIR" >&2
    exit "$status"
}

VM_PID=""
VM_STARTED=0
REMOTE_CREATED=0
PHASE_BUDGET="${LORRY_NATIVE_SELF_TIMEOUT:-1200}"
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
