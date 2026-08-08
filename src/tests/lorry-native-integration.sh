#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
LORRY_DIR="$ROOT_DIR/src/bin/lorry"
TESTS_DIR="$SCRIPT_DIR"
MOTOR_TARGET="x86_64-unknown-motor"
MOTOR_TOOLCHAIN="${LORRY_MOTOR_TOOLCHAIN:-dev-x86_64-unknown-motor}"
MOTOR_LINKER="${LORRY_MOTOR_LINKER:-/home/posk/motor-dev/motor-sysroot/bin/motor-clang}"
MOTOR_SYSROOT="${LORRY_MOTOR_SYSROOT:-$ROOT_DIR/img_files/generated/rustc/sys/tools/rust}"
MOTOR_C_COMPILER="${LORRY_MOTOR_C_COMPILER:-/home/posk/motor-dev/llvm-project/build/bin/clang}"
MOTOR_C_SYSROOT="${LORRY_MOTOR_C_SYSROOT:-/home/posk/motor-dev/motor-sysroot}"
MOTOR_ARCHIVER="${LORRY_MOTOR_ARCHIVER:-/home/posk/motor-dev/llvm-project/build/bin/llvm-ar}"
BUILD_REPOSITORY="$ROOT_DIR/build/lorry/stage2/system-seed"
DOWNLOAD_CACHE="$ROOT_DIR/build/lorry/stage2/download-cache"
CACHE_CURL_SOURCE="$SCRIPT_DIR/lorry-cache-curl.rs"
POLICY_RENDERER="$SCRIPT_DIR/lorry-integration-policy.py"
REMOTE_BASE="/user/tmp/lorry"

MODE="smoke"
BUILD="debug"
REUSE_VM=0
KEEP=0
# Guest sizing. Eight vCPUs are the directed target, but the guest is not yet
# correct at that width; see "Guest concurrency ceiling" in
# src/bin/lorry/make-it-faster.md.
VM_SMP="${LORRY_VM_SMP:-4}"
VM_MEMORY="${LORRY_VM_MEMORY:-4096M}"

usage() {
    cat <<'EOF'
usage: lorry-native-integration.sh [--full] [--release] [--reuse-running-vm] [--keep]

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
            echo "lorry-native-integration: unknown option '$1'" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

case "$MODE" in
    smoke)
        smoke_budget=300
        [ "$BUILD" = "release" ] || smoke_budget=2700
        PHASE_BUDGET="${LORRY_NATIVE_SMOKE_TIMEOUT:-$smoke_budget}"
        ;;
    full)
        PHASE_BUDGET="${LORRY_NATIVE_FULL_TIMEOUT:-5400}"
        ;;
esac
case "$PHASE_BUDGET" in
    '' | *[!0-9]* | 0)
        echo "lorry-native-integration: native timeout must be a positive integer" >&2
        exit 1
        ;;
esac

RUN_ID="stage1-$(date -u +%Y%m%dT%H%M%SZ)-$$"
EVIDENCE_DIR="$LORRY_DIR/target/lorry/integration-native-tests/$RUN_ID"
ARTIFACT_DIR="$EVIDENCE_DIR/artifacts"
WORK="$(mktemp -d /tmp/lorry-stage1-native-XXXXXX)"
SSH_KEY="$WORK/test.key"
HOST_STAGE="$WORK/stage"
REMOTE_ROOT="$REMOTE_BASE/$RUN_ID"
NATIVE_LOG="$EVIDENCE_DIR/native.log"
SFTP_LOG="$EVIDENCE_DIR/sftp.log"
HASH_LOG="$EVIDENCE_DIR/hashes.txt"
SUMMARY="$EVIDENCE_DIR/summary.txt"
COMMAND_LOG="$EVIDENCE_DIR/commands.txt"
COMMAND_TIMING_LOG="$EVIDENCE_DIR/commands.tsv"
QEMU_LOG="$EVIDENCE_DIR/qemu.log"
IMAGE_BUILD_LOG="$EVIDENCE_DIR/image-build.log"
TIMING_LOG="$EVIDENCE_DIR/timings.tsv"

# shellcheck source=../bin/lorry/tests/timing.sh
source "$LORRY_DIR/tests/timing.sh"

mkdir -p "$ARTIFACT_DIR" "$HOST_STAGE"
timing_init "$TIMING_LOG"
: >"$NATIVE_LOG"
: >"$SFTP_LOG"
: >"$HASH_LOG"
: >"$COMMAND_LOG"
printf 'milliseconds\tstatus\tcommand\n' >"$COMMAND_TIMING_LOG"

SSH_OPTIONS=(
    -n
    -F /dev/null
    -p 2222
    -i "$SSH_KEY"
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
    -i "$SSH_KEY"
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
    echo "lorry-native-integration: $*" >&2
    exit 1
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
    local remaining_ms=$((PHASE_DEADLINE_MS - $(timing_now_ms)))
    [ "$remaining_ms" -gt 0 ] || fail "$MODE native phase exceeded ${PHASE_BUDGET}s"
    duration_from_ms "$remaining_ms"
}

record_command_timing() {
    local start_ms="$1"
    local status="$2"
    local command="$3"
    local elapsed_ms=$(($(timing_now_ms) - start_ms))
    printf '%s\t%s\t%s\n' "$elapsed_ms" "$status" "$command" \
        >>"$COMMAND_TIMING_LOG"
    printf 'timing: native command %s (%s): %s\n' \
        "$(timing_format_ms "$elapsed_ms")" "$status" "$command"
}

native_command() {
    local command="$1"
    local duration
    local status
    local start_ms
    duration="$(remaining_duration)"
    printf '+ %s\n' "$command" >>"$COMMAND_LOG"
    start_ms="$(timing_now_ms)"
    set +e
    timeout "$duration" "${SSH[@]}" "$command" 2>&1 | tee -a "$NATIVE_LOG"
    status="${PIPESTATUS[0]}"
    set -e
    record_command_timing "$start_ms" "$status" "$command"
    [ "$status" -eq 0 ] ||
        fail "native command failed with status $status: $command"
}

native_capture() {
    local output="$1"
    local command="$2"
    local duration
    local status
    local start_ms
    duration="$(remaining_duration)"
    printf '+ %s\n' "$command" >>"$COMMAND_LOG"
    start_ms="$(timing_now_ms)"
    set +e
    timeout "$duration" "${SSH[@]}" "$command" 2>&1 |
        tee -a "$NATIVE_LOG" "$output"
    status="${PIPESTATUS[0]}"
    set -e
    record_command_timing "$start_ms" "$status" "$command"
    [ "$status" -eq 0 ] ||
        fail "native command failed with status $status: $command"
}

run_sftp_batch() {
    local batch="$1"
    local duration
    local status
    local start_ms
    duration="$(remaining_duration)"
    start_ms="$(timing_now_ms)"
    set +e
    timeout "$duration" sftp "${SFTP_OPTIONS[@]}" -b "$batch" \
        motor@192.168.4.2 2>&1 | tee -a "$SFTP_LOG"
    status="${PIPESTATUS[0]}"
    set -e
    record_command_timing "$start_ms" "$status" "sftp-batch $(basename "$batch")"
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
    local batch="$WORK/upload-tree.batch"
    destination="$(canonical_remote_child "$2")" ||
        fail "unsafe upload-tree destination '$2'"
    [ -d "$source" ] || fail "upload-tree source '$source' is not a directory"
    case "$source" in
        *[[:space:]]*) fail "upload-tree roots containing whitespace are unsupported" ;;
    esac
    case "$destination" in
        *[[:space:]]*) fail "upload-tree roots containing whitespace are unsupported" ;;
    esac

    remote_mkdir "$destination"
    printf 'put -pR %s/. %s\n' "$source" "$destination" >"$batch"
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

capture_artifact() {
    local label="$1"
    local remote_file="$2"
    local expected="$3"
    local downloaded="$ARTIFACT_DIR/$label"
    local hosted="$ARTIFACT_DIR/hosted-$label"
    cp "$expected" "$hosted"
    download_artifact "$remote_file" "$downloaded"
    printf '%s %s\n' "$label" "$(sha256sum "$downloaded" | awk '{print $1}')" \
        >>"$HASH_LOG"
}

compare_artifact() {
    local label="$1"
    capture_artifact "$@"
    cmp "$ARTIFACT_DIR/hosted-$label" "$ARTIFACT_DIR/$label" ||
        fail "$label differs between Linux cross-build and native Motor"
}

verify_lorry_artifact() {
    local label="$1"
    local remote_file="$2"
    if [ "$BUILD" = "release" ]; then
        compare_artifact "$@"
    else
        capture_artifact "$@"
    fi
    native_command "$remote_file --version"
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
    if [ -d "$source/.lorry" ]; then
        cp -R "$source/.lorry" "$destination/.lorry"
    fi
}

copy_crate() {
    local source="$1"
    local destination="$2"
    mkdir -p "$destination"
    cp "$source/Cargo.toml" "$destination/"
    cp -R "$source/src" "$destination/src"
}

expect_vendor_required() {
    local home_dir="$1"
    local rustc="$2"
    local lorry="$3"
    local package="$4"
    local log="$5"
    local status

    set +e
    (
        cd "$package"
        HOME="$home_dir" RUSTC="$rustc" "$lorry" build --release
    ) >"$log" 2>&1
    status="$?"
    set -e
    [ "$status" -ne 0 ] || fail "Git-patched package built before vendoring"
    grep -F "lorry vendor" "$log" >/dev/null || {
        cat "$log" >&2
        fail "Git-patch rejection did not recommend lorry vendor"
    }
}

write_integration_host_config() {
    local destination="$1"
    local repository="$2"
    local host_c_compiler="$3"
    local host_archiver="$4"
    local cache_curl="$5"
    local policy_mode="$6"
    local evidence_repository="${7:-}"
    local red_lock="${8:-}"
    local red_state="${9:-}"
    local rush_lock="${10:-}"
    local rush_state="${11:-}"

    mkdir -p "$(dirname "$destination")"
    cat >"$destination" <<EOF
config-version = 1
cargo-compat-version = "1.99"

[repositories]
user = "$repository"

[vendor]
targets = ["$MOTOR_TARGET"]
include-host = true

[network]
curl = "$cache_curl"

[policy]
default = "allow"

[native-tools."x86_64-unknown-linux-gnu".c-compiler]
program = "$host_c_compiler"
prefix-args = []
flags = []

[native-tools."x86_64-unknown-linux-gnu".archiver]
program = "$host_archiver"
prefix-args = []
flags = []
EOF
    case "$policy_mode" in
        acquisition)
            cat >>"$destination" <<'EOF'

[policy.rules.allow-vendor-build-script-inspection]
action = "allow"
source = "crates.io"
allow-build-script = true
EOF
            ;;
        verified)
            [ -n "$evidence_repository" ] && [ -n "$red_lock" ] && \
                [ -n "$red_state" ] && [ -n "$rush_lock" ] && \
                [ -n "$rush_state" ] ||
                fail "verified host policy requires repository and admission evidence"
            "$POLICY_RENDERER" build-scripts "$evidence_repository" \
                --project "$red_lock" "$red_state" \
                --project "$rush_lock" "$rush_state" >>"$destination"
            ;;
        *) fail "unknown integration host policy mode '$policy_mode'" ;;
    esac
}

prepare_cache_curl() {
    local cargo_home="$1"
    local fixture="$2"
    shift 2
    local builder="$WORK/lorry-cache-curl"

    "$native_rustc" --edition=2024 -D warnings -O \
        "$CACHE_CURL_SOURCE" -o "$builder"
    "$builder" prepare "$cargo_home" "$fixture" "$@"
}

prepare_git_mock() {
    local cargo_home="$1"
    local manifest="$2"
    local lock="$3"
    local branch
    local candidate
    local commit
    local database=""
    local local_repository="$WORK/cargo-git-fixture.git"
    local real_git
    local url
    local wrapper_directory="$WORK/git-mock-bin"

    real_git="$(type -P git)"
    url="$(sed -n 's/.*git = "\([^"]*\)".*/\1/p' "$manifest")"
    branch="$(sed -n 's/.*branch = "\([^"]*\)".*/\1/p' "$manifest")"
    commit="$(sed -n 's/.*source = "git+[^#]*#\([0-9a-fA-F]\{40\}\)"/\1/p' "$lock")"
    [ -n "$url" ] && [ -n "$branch" ] && [ -n "$commit" ] ||
        fail "could not derive the Git patch URL, branch, and commit"
    case "$url$branch$commit$real_git$cargo_home" in
        *[!A-Za-z0-9_./:+@=-]*)
            fail "Cargo Git fixture paths or identities contain unsupported characters"
            ;;
    esac

    for candidate in "$cargo_home"/git/db/*; do
        [ -d "$candidate" ] || continue
        if "$real_git" --git-dir "$candidate" cat-file -e "$commit^{commit}" \
            2>/dev/null; then
            [ -z "$database" ] ||
                fail "multiple Cargo Git databases contain commit $commit"
            database="$candidate"
        fi
    done
    [ -n "$database" ] ||
        fail "Cargo Git cache does not contain locked commit $commit"

    "$real_git" init --bare "$local_repository" >/dev/null
    "$real_git" --git-dir "$local_repository" fetch --quiet "$database" \
        "refs/commit/$commit:refs/heads/$branch"
    mkdir -p "$wrapper_directory"
    printf '%s\n' \
        '#!/bin/sh' \
        "exec $real_git -c protocol.file.allow=always -c url.file://$local_repository.insteadOf=$url \"\$@\"" \
        >"$wrapper_directory/git"
    chmod 700 "$wrapper_directory/git"
    printf '%s\n' "$wrapper_directory"
}

write_integration_motor_config() {
    local destination="$1"
    local repository="$2"
    local evidence_repository="$3"
    local red_lock="$4"
    local red_state="$5"
    local rush_lock="$6"
    local rush_state="$7"

    cat >"$destination" <<EOF
config-version = 1
cargo-compat-version = "1.99"

[repositories]
user = "$repository"

[vendor]
targets = ["$MOTOR_TARGET"]
include-host = true
EOF
    "$POLICY_RENDERER" all "$evidence_repository" \
        --project "$red_lock" "$red_state" \
        --project "$rush_lock" "$rush_state" >>"$destination"
}

configure_motor_linker() {
    local package="$1"
    mkdir -p "$package/.cargo"
    cat >"$package/.cargo/config.toml" <<EOF
[target.$MOTOR_TARGET]
linker = "$MOTOR_LINKER"
EOF
}

configure_motor_native_tools() {
    local package="$1"
    cat >"$package/lorry.toml" <<EOF
config-version = 1
cargo-compat-version = "1.99"

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
    local host_cargo_home
    local host_c_compiler
    local host_home
    local integration_config
    local integration_home
    local integration_repository
    local crates_io_fixture
    local git_mock_directory
    local native_rustc
    local motor_rustc
    local motor_toolchain_sysroot
    local python
    local rustup_home
    local test_harness
    local tls_server

    echo "== Preparing clean Linux-to-Motor Lorry artifacts =="
    cargo="$(rustup which cargo --toolchain nightly-2026-06-19)"
    native_rustc="$(rustup which rustc --toolchain nightly-2026-06-19)"
    motor_rustc="$(rustup which rustc --toolchain "$MOTOR_TOOLCHAIN")"
    motor_toolchain_sysroot="$($motor_rustc --print sysroot)"
    rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
    host_cargo_home="${CARGO_HOME:-$HOME/.cargo}"
    unset CARGO_TARGET_DIR RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
    unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
    [ -x "$MOTOR_LINKER" ] ||
        fail "Motor cross-linker '$MOTOR_LINKER' is not executable"
    [ -d "$MOTOR_SYSROOT/lib/rustlib/$MOTOR_TARGET" ] ||
        fail "Motor image sysroot '$MOTOR_SYSROOT' is incomplete"
    [ -d "$motor_toolchain_sysroot/lib/rustlib/$MOTOR_TARGET" ] ||
        fail "Motor toolchain sysroot '$motor_toolchain_sysroot' is incomplete"
    # Lorry hashes rustflags into Cargo unit identities. Verify the implicit
    # Linux sysroot instead of adding a flag that native Motor does not need.
    diff -qr "$motor_toolchain_sysroot/lib/rustlib/$MOTOR_TARGET" \
        "$MOTOR_SYSROOT/lib/rustlib/$MOTOR_TARGET" >"$WORK/sysroot-diff" || {
        cat "$WORK/sysroot-diff" >&2
        fail "Linux and image Motor target sysroots differ"
    }
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
        --manifest-path "$LORRY_DIR/Cargo.toml" --locked --offline --release
    RUSTC="$motor_rustc" RUSTFLAGS="--sysroot=$MOTOR_SYSROOT" \
        CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER="$MOTOR_LINKER" \
        "$cargo" build --manifest-path "$LORRY_DIR/Cargo.toml" \
        --locked --offline --release --target "$MOTOR_TARGET" \
        --target-dir "$WORK/cargo-lorry-motor"
    RUSTC="$motor_rustc" RUSTFLAGS="--sysroot=$MOTOR_SYSROOT" \
        CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER="$MOTOR_LINKER" \
        "$cargo" test --manifest-path "$LORRY_DIR/Cargo.toml" \
        --locked --offline --target "$MOTOR_TARGET" --no-run \
        --target-dir "$WORK/cargo-lorry-motor-tests"
    cp "$LORRY_DIR/target/release/lorry" "$WORK/lorry-seed"

    export RUSTUP_HOME="$rustup_home"
    export CARGO_HOME="$WORK/cargo-home"
    host_home="$WORK/host-home"
    "$python" "$LORRY_DIR/bootstrap/install_stage2_seed.py" \
        --manifest "$LORRY_DIR/bootstrap/stage2-seed.toml" \
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

    integration_home="$WORK/integration-home"
    integration_repository="$WORK/integration-vendor"
    integration_config="$integration_home/.config/lorry/lorry.toml"
    crates_io_fixture="$WORK/crates-io-fixture"
    prepare_cache_curl "$host_cargo_home" "$crates_io_fixture" \
        "$ROOT_DIR/src/bin/red/Cargo.lock" \
        "$ROOT_DIR/src/bin/rush/Cargo.lock"
    git_mock_directory="$(prepare_git_mock "$host_cargo_home" \
        "$ROOT_DIR/src/bin/red/Cargo.toml" \
        "$ROOT_DIR/src/bin/red/Cargo.lock")"
    write_integration_host_config \
        "$integration_config" "$integration_repository" \
        "$host_c_compiler" "$host_archiver" "$crates_io_fixture/curl" \
        acquisition

    if [ "$MODE" = "full" ]; then
        copy_package "$LORRY_DIR" "$HOST_STAGE/lorry-tree/src/bin/lorry"
        copy_crate "$ROOT_DIR/src/sys/lib/moto-rt" \
            "$HOST_STAGE/lorry-tree/src/sys/lib/moto-rt"
    fi
    copy_package "$ROOT_DIR/src/bin/red" \
        "$HOST_STAGE/program-tree/src/bin/red"
    copy_package "$ROOT_DIR/src/bin/rush" \
        "$HOST_STAGE/program-tree/src/bin/rush"
    copy_crate "$ROOT_DIR/src/sys/lib/moto-rt" \
        "$HOST_STAGE/program-tree/src/sys/lib/moto-rt"
    copy_crate "$ROOT_DIR/src/sys/lib/moto-sys" \
        "$HOST_STAGE/program-tree/src/sys/lib/moto-sys"
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
    configure_motor_linker "$HOST_STAGE/program-tree/src/bin/red"
    configure_motor_linker "$HOST_STAGE/program-tree/src/bin/rush"
    configure_motor_linker "$HOST_STAGE/simple-source"
    configure_motor_linker "$HOST_STAGE/curl-tree/src/bin/curl"
    configure_motor_native_tools "$HOST_STAGE/curl-tree/src/bin/curl"

    expect_vendor_required "$integration_home" "$motor_rustc" \
        "$WORK/lorry-seed" "$HOST_STAGE/program-tree/src/bin/red" \
        "$WORK/red-needs-vendor.log"
    expect_vendor_required "$integration_home" "$motor_rustc" \
        "$WORK/lorry-seed" "$HOST_STAGE/program-tree/src/bin/rush" \
        "$WORK/rush-needs-vendor.log"
    for package in red rush; do
        (
            cd "$HOST_STAGE/program-tree/src/bin/$package"
            HOME="$integration_home" PATH="$git_mock_directory:$PATH" \
                GIT_ALLOW_PROTOCOL=file RUSTC="$motor_rustc" \
                "$WORK/lorry-seed" vendor --accept-all
        )
    done
    write_integration_host_config \
        "$integration_config" "$integration_repository" \
        "$host_c_compiler" "$host_archiver" "$crates_io_fixture/curl" \
        verified "$integration_repository" \
        "$HOST_STAGE/program-tree/src/bin/red/Cargo.lock" \
        "$HOST_STAGE/program-tree/src/bin/red/.lorry/dependencies-v2.toml" \
        "$HOST_STAGE/program-tree/src/bin/rush/Cargo.lock" \
        "$HOST_STAGE/program-tree/src/bin/rush/.lorry/dependencies-v2.toml"
    for package in red rush; do
        (
            cd "$HOST_STAGE/program-tree/src/bin/$package"
            HOME="$integration_home" RUSTC="$motor_rustc" \
                "$WORK/lorry-seed" build --release
            HOME="$integration_home" RUSTC="$motor_rustc" \
                "$WORK/lorry-seed" build --release --target "$MOTOR_TARGET"
        )
    done
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
            if [ "$BUILD" = "debug" ]; then
                RUSTC="$motor_rustc" "$WORK/lorry-seed" build \
                    --target "$MOTOR_TARGET"
            else
                RUSTC="$motor_rustc" "$WORK/lorry-seed" build --release \
                    --target "$MOTOR_TARGET"
            fi
        )
    fi

    mkdir -p "$WORK/cross"
    cp "$WORK/cargo-lorry-motor/$MOTOR_TARGET/release/lorry" \
        "$WORK/cross/lorry-bootstrap"
    if [ "$MODE" = "full" ]; then
        cp "$HOST_STAGE/lorry-tree/src/bin/lorry/target/lorry/$MOTOR_TARGET/$BUILD/lorry" \
            "$WORK/cross/lorry"
        CROSS_LORRY="$WORK/cross/lorry"
    fi
    cp "$HOST_STAGE/program-tree/src/bin/red/target/lorry/$MOTOR_TARGET/release/red" \
        "$WORK/cross/red"
    cp "$HOST_STAGE/program-tree/src/bin/rush/target/lorry/$MOTOR_TARGET/release/rush" \
        "$WORK/cross/rush"
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
    cp "$ROOT_DIR/src/bin/curl/tests/hostname-ca.pem" "$WORK/cross/hostname-ca.pem"
    BOOTSTRAP_LORRY="$WORK/cross/lorry-bootstrap"
    CROSS_RED="$WORK/cross/red"
    CROSS_RUSH="$WORK/cross/rush"
    CROSS_SIMPLE="$WORK/cross/stage1-native-run"
    CROSS_CURL="$WORK/cross/curl"
    CROSS_LORRY_TESTS="$WORK/cross/lorry-tests"
    CROSS_TLS_SERVER="$WORK/cross/https-tests"
    CROSS_TEST_CA="$WORK/cross/test-ca.pem"
    CROSS_HOSTNAME_CA="$WORK/cross/hostname-ca.pem"

    rm -rf "$HOST_STAGE/lorry-tree/src/bin/lorry/target"
    INTEGRATION_REPOSITORY="$integration_repository"
    INTEGRATION_MOTOR_CONFIG="$WORK/integration-motor-lorry.toml"
    write_integration_motor_config \
        "$INTEGRATION_MOTOR_CONFIG" "$REMOTE_ROOT/vendor" \
        "$INTEGRATION_REPOSITORY" \
        "$HOST_STAGE/program-tree/src/bin/red/Cargo.lock" \
        "$HOST_STAGE/program-tree/src/bin/red/.lorry/dependencies-v2.toml" \
        "$HOST_STAGE/program-tree/src/bin/rush/Cargo.lock" \
        "$HOST_STAGE/program-tree/src/bin/rush/.lorry/dependencies-v2.toml"

    rm -rf "$HOST_STAGE/program-tree/src/bin/red/target"
    rm -rf "$HOST_STAGE/program-tree/src/bin/rush/target"
    rm -rf "$HOST_STAGE/simple-source/target"
    rm -rf "$HOST_STAGE/curl-tree/src/bin/curl/target"
    rm -rf "$HOST_STAGE/lorry-tree/src/bin/lorry/.cargo"
    rm -rf "$HOST_STAGE/program-tree/src/bin/red/.cargo"
    rm -rf "$HOST_STAGE/program-tree/src/bin/rush/.cargo"
    rm -rf "$HOST_STAGE/simple-source/.cargo"
    rm -rf "$HOST_STAGE/curl-tree/src/bin/curl/.cargo"
    printf 'motor toolchain: %s\n' "$motor_rustc" >>"$COMMAND_LOG"
    printf 'motor toolchain sysroot: %s\n' "$motor_toolchain_sysroot" \
        >>"$COMMAND_LOG"
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

    # A VM leaked by an earlier run keeps answering on the tap, and every ssh
    # below would reach it instead of the guest this run starts -- measuring
    # and testing the wrong image without saying so. Refuse to start.
    if timeout 2 "${SSH[@]}" /bin/echo ready >/dev/null 2>&1; then
        fail "a VM is already answering on the tap; stop it before running"
    fi

    echo "== Starting Motor VM (SSH deadline: 10 seconds) =="
    start="$(timing_now_ms)"
    deadline=$((start + 10000))
    MOTO_SMP="$VM_SMP" "$ROOT_DIR/vm_images/$BUILD/run-qemu.sh" \
        -m "$VM_MEMORY" >"$QEMU_LOG" 2>&1 &
    VM_PID="$!"
    VM_STARTED=1

    while :; do
        remaining=$((deadline - $(timing_now_ms)))
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
    BOOT_MILLISECONDS=$(($(timing_now_ms) - start))
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
    upload_file "$CROSS_HOSTNAME_CA" "$REMOTE_ROOT/hostname-ca.pem"
    if [ "$MODE" = "full" ]; then
        upload_file "$CROSS_LORRY" "$REMOTE_ROOT/bin/lorry-cross-profile"
    fi
    upload_tree "$HOST_STAGE/program-tree" "$REMOTE_ROOT/program-tree"
    upload_tree "$INTEGRATION_REPOSITORY" "$REMOTE_ROOT/vendor"
    upload_file "$INTEGRATION_MOTOR_CONFIG" "$REMOTE_ROOT/user-config.toml"
    native_command "/bin/cp $REMOTE_ROOT/user-config.toml /user/cfg/lorry.toml"
    upload_tree "$HOST_STAGE/simple-source" "$REMOTE_ROOT/simple-source"
    if [ "$MODE" = "full" ]; then
        upload_tree "$HOST_STAGE/lorry-tree" "$REMOTE_ROOT/lorry-tree"
    fi
}

run_smoke_gate() {
    local bootstrap="$REMOTE_ROOT/bin/lorry-bootstrap"
    local pristine="$REMOTE_ROOT/git-probe"
    local red_work="$REMOTE_ROOT/program-tree/src/bin/red"
    local rush_work="$REMOTE_ROOT/program-tree/src/bin/rush"
    local simple_work="$REMOTE_ROOT/simple-work"
    local simple_output="$EVIDENCE_DIR/simple-run.txt"
    local entropy_log="$EVIDENCE_DIR/native-entropy.log"
    local https_log="$EVIDENCE_DIR/native-https.log"
    local curl_log="$EVIDENCE_DIR/native-curl.log"

    echo "== Running Motor-native build/run/test gate =="
    native_command "$bootstrap --version"
    remote_mkdir "$pristine"
    upload_file "$ROOT_DIR/src/bin/red/Cargo.toml" "$pristine/Cargo.toml"
    native_command "cd $pristine && if $bootstrap vendor --accept-all > $REMOTE_ROOT/git-unsupported.log 2>&1; then exit 1; fi"
    download_artifact "$REMOTE_ROOT/git-unsupported.log" \
        "$EVIDENCE_DIR/git-unsupported.log"
    grep -F "not supported" "$EVIDENCE_DIR/git-unsupported.log" >/dev/null ||
        fail "Motor Git-vendoring rejection was not informative"
    # Native builds require the Motor host's contexts to be reviewed; offline
    # vendoring on Motor records them while preserving the Linux review.
    native_command "cd $red_work && $bootstrap vendor"
    native_command "cd $rush_work && $bootstrap vendor"
    native_command "cd $red_work && $bootstrap build"
    native_command "cd $red_work && $bootstrap build --release"
    compare_artifact native-red \
        "$red_work/target/lorry/release/red" "$CROSS_RED"
    run_native_test "$red_work" "$bootstrap" red-test
    native_command "cd $rush_work && $bootstrap build"
    native_command "cd $rush_work && $bootstrap build --release"
    compare_artifact native-rush \
        "$rush_work/target/lorry/release/rush" "$CROSS_RUSH"

    remote_copy_tree "$REMOTE_ROOT/simple-source" "$simple_work"
    native_capture "$simple_output" \
        "cd $simple_work && $bootstrap run --release -- native 'two words'"
    grep -Fx "native|two words" "$simple_output" >/dev/null ||
        fail "native run did not preserve its arguments"
    compare_artifact native-run \
        "$simple_work/target/lorry/release/stage1-native-run" "$CROSS_SIMPLE"

    echo "== Running Motor entropy and verified-HTTPS fixtures =="
    native_capture "$entropy_log" \
        "$REMOTE_ROOT/bin/https-tests obtains_distinct_system_random_values --exact --quiet"
    grep -F "test result: ok. 1 passed; 0 failed" "$entropy_log" >/dev/null ||
        fail "native Motor entropy fixture did not report exactly one passing test"
    native_capture "$https_log" \
        "MOTOR_CURL_TEST_FIXTURES=$REMOTE_ROOT $REMOTE_ROOT/bin/https-tests transfers_a_verified_https_response --exact --quiet"
    grep -F "test result: ok. 1 passed; 0 failed" "$https_log" >/dev/null ||
        fail "native Motor verified-HTTPS fixture did not report exactly one passing test"

    echo "== Running Lorry's curl boundary through native Motor curl =="
    native_capture "$curl_log" \
        "LORRY_TEST_CURL=$REMOTE_ROOT/bin/curl LORRY_TEST_CA=$REMOTE_ROOT/test-ca.pem LORRY_TEST_HOSTNAME_CA=$REMOTE_ROOT/hostname-ca.pem LORRY_TEST_UNTRUSTED_CA=/sys/cfg/ssl/ssl-cert.pem LORRY_TEST_TLS_SERVER=$REMOTE_ROOT/bin/https-tests $REMOTE_ROOT/bin/lorry-tests selected_curl --include-ignored --quiet"
    grep -F "test result: ok. 10 passed; 0 failed" "$curl_log" >/dev/null ||
        fail "native Motor curl fixture did not report exactly ten passing tests"
}

run_full_gate() {
    local bootstrap="$REMOTE_ROOT/bin/lorry-bootstrap"
    local build_command="build"
    local native_lorry="$REMOTE_ROOT/bin/lorry-native"
    local lorry_first_tree="$REMOTE_ROOT/lorry-first"
    local lorry_second_tree="$REMOTE_ROOT/lorry-second"
    local lorry_first="$lorry_first_tree/src/bin/lorry"
    local lorry_second="$lorry_second_tree/src/bin/lorry"
    local red_second="$REMOTE_ROOT/red-second"
    local program_second="$REMOTE_ROOT/program-second"
    local rush_second="$program_second/src/bin/rush"
    local simple_second="$REMOTE_ROOT/simple-second"
    local simple_output="$EVIDENCE_DIR/simple-run-generation-2.txt"

    [ "$BUILD" = "debug" ] || build_command="build --release"

    echo "== Running Motor-native self-build and second-generation gate =="
    native_command "$REMOTE_ROOT/bin/lorry-cross-profile --version"
    remote_copy_tree "$REMOTE_ROOT/lorry-tree" "$lorry_first_tree"
    native_command "cd $lorry_first && $bootstrap $build_command"
    verify_lorry_artifact native-lorry-generation-1 \
        "$lorry_first/target/lorry/$BUILD/lorry" "$CROSS_LORRY"
    native_command "/bin/cp $lorry_first/target/lorry/$BUILD/lorry $native_lorry"

    remote_copy_tree "$REMOTE_ROOT/lorry-tree" "$lorry_second_tree"
    native_command "cd $lorry_second && $native_lorry $build_command"
    verify_lorry_artifact native-lorry-generation-2 \
        "$lorry_second/target/lorry/$BUILD/lorry" "$CROSS_LORRY"

    remote_copy_tree "$REMOTE_ROOT/program-tree/src/bin/red" "$red_second"
    native_command "cd $red_second && $native_lorry build --release"
    compare_artifact native-red-generation-2 \
        "$red_second/target/lorry/release/red" "$CROSS_RED"
    run_native_test "$red_second" "$native_lorry" red-generation-2-test

    remote_copy_tree "$REMOTE_ROOT/program-tree" "$program_second"
    native_command "cd $rush_second && $native_lorry build --release"
    compare_artifact native-rush-generation-2 \
        "$rush_second/target/lorry/release/rush" "$CROSS_RUSH"

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
        "$REMOTE_ROOT/program-tree/src/bin/red/target/lorry/release/red" \
        "$ARTIFACT_DIR/failure/red" >>"$batch"
    printf -- '-get %s %s\n' \
        "$REMOTE_ROOT/program-tree/src/bin/rush/target/lorry/release/rush" \
        "$ARTIFACT_DIR/failure/rush" >>"$batch"
    printf -- '-get %s %s\n' \
        "$REMOTE_ROOT/lorry-first/src/bin/lorry/target/lorry/$BUILD/lorry" \
        "$ARTIFACT_DIR/failure/lorry-first" >>"$batch"
    printf -- '-get %s %s\n' \
        "$REMOTE_ROOT/lorry-second/src/bin/lorry/target/lorry/$BUILD/lorry" \
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
    timing_finish "$status"

    if [ "$status" -ne 0 ]; then
        retrieve_failure_evidence
        {
            echo "result: FAIL"
            echo "mode: $MODE"
            echo "boot_ms: $BOOT_MILLISECONDS"
            echo "evidence: $EVIDENCE_DIR"
            cat "$TIMING_LOG"
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
            "$EVIDENCE_DIR/native-entropy.log" \
            "$EVIDENCE_DIR/native-https.log" \
            "$EVIDENCE_DIR/native-curl.log" \
            "$EVIDENCE_DIR/red-test.log" \
            "$EVIDENCE_DIR/red-generation-2-test.log"
    fi
    if [ "$status" -ne 0 ]; then
        echo "lorry-native-integration: evidence retained at $EVIDENCE_DIR" >&2
    fi
    exit "$status"
}
trap cleanup EXIT

[ -f "$TESTS_DIR/test.key" ] || fail "SSH key '$TESTS_DIR/test.key' is missing"
cp "$TESTS_DIR/test.key" "$SSH_KEY"
chmod 600 "$SSH_KEY"

echo "== Running Stage 2 seed fixture tests =="
timing_start stage2-seed-fixtures
(
    cd "$LORRY_DIR/bootstrap"
    python3 -m unittest discover -s tests -p 'test_*.py' -v
)
timing_finish

timing_start motor-image-build
build_image
timing_finish
timing_start host-preparation
prepare_host_gate
timing_finish
timing_start vm-startup
start_vm
timing_finish

PHASE_START_MS="$(timing_now_ms)"
PHASE_DEADLINE_MS=$((PHASE_START_MS + PHASE_BUDGET * 1000))
timing_start native-input-staging
stage_native_inputs
timing_finish
timing_start native-smoke-gate
run_smoke_gate
timing_finish
if [ "$MODE" = "full" ]; then
    timing_start native-full-gate
    run_full_gate
    timing_finish
fi
NATIVE_MILLISECONDS=$(($(timing_now_ms) - PHASE_START_MS))

{
    echo "result: PASS"
    echo "mode: $MODE"
    echo "vm: $BUILD"
    echo "boot_ms: $BOOT_MILLISECONDS"
    echo "native_phase_ms: $NATIVE_MILLISECONDS"
    echo "remote_cleanup: $REMOTE_ROOT"
    cat "$TIMING_LOG"
    cat "$HASH_LOG"
} >"$SUMMARY"

echo
echo "PASS: Stage 1 Motor-native $MODE gate passed"
echo "boot: ${BOOT_MILLISECONDS}ms; native phase: ${NATIVE_MILLISECONDS}ms"
echo "summary: $SUMMARY"
