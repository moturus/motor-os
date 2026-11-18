#!/bin/bash
# Build checks, native Linux tests, and a disposable standard-image gate.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT_DIR/src/tests/cross-test.sh"

full_options() {
  # The gate builds and boots the release image; --release selects the profile
  # of the native tests only. --all-debug (manual runs only, never automation)
  # builds and boots the debug image and runs every check in debug.
  BUILD=release
  TEST_BUILD=debug
  VMM=chv
  CPUS="${MOTO_SMP-4}"
  MEMORY_MIB="${MOTO_MEMORY_MIB-4096}"
  FULL=0
  local option value
  local -A seen=()
  while [ "$#" -gt 0 ]; do
    option="${1%%=*}"
    [ -z "${seen[$option]:-}" ] || { echo "duplicate option: $option" >&2; return 2; }
    seen[$option]=1
    case "$option" in
      --release) [ "$1" = --release ] || return 2; TEST_BUILD=release; shift ;;
      --all-debug) [ "$1" = --all-debug ] || return 2; BUILD=debug; shift ;;
      --full) [ "$1" = --full ] || return 2; FULL=1; shift ;;
      --vmm|--cpus|--memory)
        if [[ "$1" == *=* ]]; then value="${1#*=}"; shift
        else
          [ "$#" -ge 2 ] || { echo "$option requires a value" >&2; return 2; }
          value="$2"; shift 2
        fi
        case "$option" in --vmm) VMM="$value" ;; --cpus) CPUS="$value" ;; --memory) MEMORY_MIB="$value" ;; esac ;;
      *) echo "usage: $0 [--release | --all-debug] [--full] [--vmm chv|qemu|fc] [--cpus N] [--memory MIB]" >&2; return 2 ;;
    esac
  done
  if [ "$BUILD:$TEST_BUILD" = debug:release ]; then
    echo "--all-debug and --release are mutually exclusive" >&2; return 2
  fi
  case "$VMM" in chv|qemu|fc) ;; *) echo "unsupported VMM: $VMM" >&2; return 2 ;; esac
  for value in "$CPUS" "$MEMORY_MIB"; do
    case "$value" in ''|*[!0-9]*|0*) echo 'CPU and memory values must be positive integers' >&2; return 2 ;; esac
  done
  export MOTO_SMP="$CPUS" MOTO_MEMORY_MIB="$MEMORY_MIB"
  PROFILE_ARGS=()
  [ "$BUILD" != release ] || PROFILE_ARGS=(--release)
  NATIVE_ARGS=()
  [ "$TEST_BUILD" != release ] || NATIVE_ARGS=(--release)
  [ "$FULL" != 1 ] || NATIVE_ARGS+=(--full)
}

full_prepare() {
  local targets=(images raw.img systest crossterm-smoke wg-self-test rnetbench)
  local crate
  make -C "$ROOT_DIR" -j"$(nproc)" BUILD="$BUILD" "${targets[@]}"
  # Native development tools are distributed as release builds. Test harnesses
  # still use the gate's selected debug or release profile on both machines.
  if [ "$VMM" != fc ]; then
    make -C "$ROOT_DIR" -j"$(nproc)" BUILD=release toolchain-archive
  fi
  "$ROOT_DIR/src/build-scripts/native-test-inputs.sh" "${NATIVE_ARGS[@]}"
  for crate in src/imager src/sys/tools/wg/host-peer; do
    cargo fetch --locked --manifest-path "$ROOT_DIR/$crate/Cargo.toml"
  done
  host_sdk_package --prepare "${PROFILE_ARGS[@]}"
}

host_path_locks() {
  local crate metadata source= resolved
  for crate in curl lorry; do
    # --locked rejects a local package/version change before building anything.
    cargo metadata --manifest-path "$ROOT_DIR/src/bin/$crate/Cargo.toml" \
      --format-version 1 --locked --offline > /dev/null
  done
  for crate in gix lorry; do
    metadata="$(cargo metadata --manifest-path "$ROOT_DIR/src/bin/$crate/Cargo.toml" --format-version 1 --locked --offline)"
    resolved="$(jq -er '[.packages[].source // empty | select(startswith("git+https://github.com/moturus/gitoxide.git?"))] | unique | if length == 1 then .[0] else error("multiple gitoxide sources") end' <<< "$metadata")"
    [[ "$resolved" =~ ^git\+https://github.com/moturus/gitoxide.git\?branch=gix-moturus-cli#[0-9a-f]{40}$ ]] ||
      cross_fail "$crate does not pin the shared gitoxide branch"
    [ -z "$source" ] || [ "$source" = "$resolved" ] || cross_fail 'gix and Lorry resolve different gitoxide commits'
    source="$resolved"
  done
}

host_resolution_oracles() (
  local inputs
  inputs="$(mktemp -d "$ROOT_DIR/build/resolution-oracles.XXXXXX")"
  trap 'rm -r "$inputs"' EXIT
  cd "$ROOT_DIR/src/bin/lorry"
  LORRY_RESOLUTION_ORACLE_EXPORT="$inputs" cargo test --release --locked --offline \
    --bin lorry frozen_
  for directory in "$inputs"/*; do
    (cd "$directory/root" && cargo generate-lockfile --offline)
    cmp "$directory/expected.lock" "$directory/root/Cargo.lock"
  done
)

full_install_toolchain() {
  local version archive package
  version="$(sed -n 's/^channel = "\(.*\)"/\1/p' "$ROOT_DIR/rust-toolchain.toml")"
  package="motor-toolchain-$version"
  archive="$ROOT_DIR/build/toolchain/release/$package.tar.zst"
  [ -f "$archive" ] || cross_fail "missing toolchain archive: $archive"
  copy_test_image "$CROSS_IMAGE" installed
  FULL_IMAGE="$VM_DIR/$MOTO_IMAGE"
  boot_test_image install
  wait_vm_ssh
  check_guest_image_layout
  vm_ssh 'mkdir -p /none/dev/toolchain-install'
  printf 'put "%s" "/none/dev/toolchain-install/%s.tar.zst"\n' "$archive" "$package" | vm_sftp
  # Preserve archive permissions relative to the Interactive installer.
  vm_ssh "tar -xf /none/dev/toolchain-install/$package.tar.zst -C /none/dev/toolchain-install"
  full_check_installation "$package"
  shutdown_test_image
}

full_upload_native_inputs() {
  local inputs="$ROOT_DIR/build/native-test-inputs" directory path
  echo 'full-test: uploading native working-tree snapshot'
  vm_ssh 'MOTOR_OS_CAPS=0x204 mkdir -p /none/dev/motor-os'
  vm_ssh 'MOTOR_OS_CAPS=0x204 tar -xf - -C /none/dev/motor-os' < "$inputs/working-tree.tar"
  if [ "$FULL" = 1 ]; then
    vm_ssh 'MOTOR_OS_CAPS=0x204 tar -xf - -C /none/dev/motor-os' < "$inputs/helix-source.tar"
  fi
  # Git exports include executable source files. Extract as None so their
  # provenance hashes are identical to the verified sources on the host.
  while IFS= read -r manifest; do
    directory="${manifest%/Cargo.toml}"
    path="$directory/.lorry/vendor/git"
    if [ -d "$inputs/source/$path" ]; then
      echo "full-test: uploading Git dependencies for $directory"
      tar -C "$inputs/source" -cf - "$path" |
        vm_ssh 'MOTOR_OS_CAPS=0x204 tar -xf - -C /none/dev/motor-os'
    fi
  done < "$inputs/workspaces"
  echo 'full-test: uploading shared native dependencies'
  vm_ssh 'mkdir -p /user/dev/lorry'
  tar -C "$inputs" -cf - vendor | vm_ssh 'tar -xf - -C /user/dev/lorry'
  printf 'put "%s" "/none/dev/vendor-executables"\n' "$inputs/vendor-executables" | vm_sftp
  vm_ssh 'while IFS= read -r path; do chmod rwxr-xr-x "/user/dev/lorry/vendor/$path" || exit; done < /none/dev/vendor-executables'
  vm_ssh 'rm /none/dev/vendor-executables'
  guest_mode /user/dev/lorry drwxrwxr-x
  vm_ssh 'MOTOR_OS_CAPS=0x204 cat /user/dev/lorry/vendor/repository.toml' >/dev/null
  if vm_ssh "MOTOR_OS_CAPS=0x204 /user/bin/rush -c 'echo denied >>/user/dev/lorry/vendor/repository.toml'" >/dev/null 2>&1; then
    cross_fail 'None can modify the Interactive dependency repository'
  fi
  if [ "$TEST_BUILD" = release ]; then
    vm_ssh 'MOTOR_OS_CAPS=0x204 mkdir /none/dev/quickjs-test262'
    vm_ssh 'MOTOR_OS_CAPS=0x204 tar -xf - -C /none/dev/quickjs-test262' < "$inputs/quickjs-source.tar"
    vm_ssh 'MOTOR_OS_CAPS=0x204 tar -xf - -C /none/dev/quickjs-test262' < "$inputs/quickjs-test262.tar.zst"
  fi
}

full_native_guest() {
  copy_test_image "$FULL_IMAGE" native
  boot_test_image native
  wait_vm_ssh
  check_guest_image_layout
  full_upload_native_inputs
  cross_upload_wasm_inputs
  local caps
  for caps in 0x3ec 0x3a4; do
    echo "full-test: native Motor tests, capabilities=$caps"
    vm_ssh "MOTOR_OS_CAPS=$caps NATIVE_TEST_CAPS=$caps /user/bin/rush /none/dev/motor-os/src/tests/full-native-test.sh ${NATIVE_ARGS[*]}"
  done
  shutdown_test_image
}

full_host_checks() {
  (cd "$ROOT_DIR/src/imager" && cargo test --locked --offline "${PROFILE_ARGS[@]}")
  (cd "$ROOT_DIR/src/imager" && cargo test --locked --offline "${PROFILE_ARGS[@]}" resize -- --ignored)
  # The independent upstream WireGuard peer is a Linux-only cross-test tool.
  (cd "$ROOT_DIR/src/sys/tools/wg/host-peer" && cargo test --locked --offline "${PROFILE_ARGS[@]}")
  host_build_base_networking
  host_make_driver
  host_kloader_image "${PROFILE_ARGS[@]}"
  host_external_sources
  host_toolchain_archive
  host_toolchain_bootstrap
  host_net_contract
  host_vm_image_format
  host_vm_console_filter
  host_vm_vsock_backend
  host_full_options
  host_path_locks
  host_resolution_oracles
  host_sdk_package "${PROFILE_ARGS[@]}"
  host_tool_sizes
  host_unwind_elf
}

full_main() {
  full_options "$@"
  cd "$ROOT_DIR"
  full_prepare
  full_host_checks
  "$ROOT_DIR/src/tests/full-native-test.sh" "${NATIVE_ARGS[@]}"
  cross_options "${PROFILE_ARGS[@]}" --vmm "$VMM" --cpus "$CPUS" --memory "$MEMORY_MIB"
  cross_setup
  if [ "$VMM" = fc ]; then
    FULL_IMAGE="$CROSS_IMAGE"
    echo 'SKIP Firecracker: toolchain archive installation'
  else
    full_install_toolchain
  fi
  CROSS_IMAGE="$FULL_IMAGE"
  cross_run
  if [ "$VMM" = fc ]; then
    echo 'SKIP Firecracker: native Motor crate and installed-tool tests'
  else
    full_native_guest
  fi
  echo "full-test: PASS ($BUILD image, $TEST_BUILD tests, $VMM)"
}

host_build_base_networking() (

set -euo pipefail

. "$ROOT_DIR/src/build-scripts/build-base.sh"

fail_test() {
  echo "test-build-base-networking: $*" >&2
  exit 1
}

ipv4=1
ipv6=0
sudo_calls=()

cat() {
  if [ "$#" -eq 1 ] && [ "$1" = /proc/sys/net/ipv4/ip_forward ]; then
    printf '1\n'
  else
    command cat "$@"
  fi
}

ip() {
  case "$*" in
    '-o link show dev moto-tap')
      printf '4: moto-tap: <BROADCAST,MULTICAST,UP> mtu 1500\n'
      ;;
    'link show moto-tap')
      return 0
      ;;
    '-o -4 addr show dev moto-tap')
      if [ "$ipv4" -eq 1 ]; then
        printf '4: moto-tap inet 192.168.4.1/24 scope global moto-tap\n'
      fi
      ;;
    '-o -6 addr show dev moto-tap')
      if [ "$ipv6" -eq 1 ]; then
        printf '4: moto-tap inet6 2001:db8::1/64 scope global\n'
      fi
      ;;
    *)
      fail_test "unexpected ip command: $*"
      ;;
  esac
}

sudo() {
  sudo_calls+=("$*")
  case "$*" in
    'ip -6 addr add 2001:db8::1/64 dev moto-tap')
      ipv6=1
      ;;
    'sysctl -w net.ipv4.ip_forward=1')
      ;;
    'nft list table ip nat')
      ;;
    'nft list chain ip nat postrouting')
      printf 'ip saddr 192.168.4.0/24 masquerade\n'
      ;;
    *)
      fail_test "unexpected sudo command: $*"
      ;;
  esac
}

log() { :; }
skip() { :; }

if host_networking_ready; then
  fail_test "networking without the required IPv6 address was accepted"
fi

setup_host_networking
[ "$ipv6" -eq 1 ] || fail_test "setup did not add the IPv6 address"
host_networking_ready || fail_test "repaired networking was not accepted"

ipv6_adds=0
for call in "${sudo_calls[@]}"; do
  if [ "$call" = 'ip -6 addr add 2001:db8::1/64 dev moto-tap' ]; then
    ipv6_adds=$((ipv6_adds + 1))
  fi
done
[ "$ipv6_adds" -eq 1 ] || fail_test "IPv6 address was added $ipv6_adds times"

sudo_calls=()
setup_host_networking
[ "${#sudo_calls[@]}" -eq 0 ] || fail_test "ready networking was reconfigured"

echo "test-build-base-networking PASS"

)

host_make_driver() (
# A failed top-level make must end with a loud summary naming what failed.
set -euo pipefail
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
fail() { echo "test-make-driver: $*" >&2; exit 1; }

failing="$temporary/failing-build"
printf '%s\n' '#!/bin/bash' 'echo "the build says no" >&2' 'exit 3' > "$failing"
chmod +x "$failing"
export MOTOR_MAKE_LOG="$temporary/make.log"
run_make() {
  local status=0
  make -C "$ROOT_DIR" "$@" > "$temporary/out" 2> "$temporary/err" || status=$?
  echo "$status"
}
outputs=("BIN_DIR=$temporary/output" "OBJ_DIR=$temporary/objects")

# The failing recipe is named, its output is quoted, and the verdict is last.
status="$(run_make strobe "DO_BUILD=$failing" "${outputs[@]}")"
[ "$status" -ne 0 ] || fail 'a failing recipe left make successful'
grep -q 'strobe\] Error 3' "$temporary/err" || fail 'failed recipe not named'
grep -q 'the build says no' "$temporary/err" || fail 'recipe output not quoted'
grep -q "^Full log: $MOTOR_MAKE_LOG\$" "$temporary/err" || fail 'log path missing'
grep -q 'the build says no' "$MOTOR_MAKE_LOG" || fail 'log lacks the recipe output'
[ "$(tail -n 2 "$temporary/err" | head -n 1)" = \
  "BUILD FAILED: make BUILD=debug strobe (exit status 2)" ] ||
  fail "verdict is not the driver's last line: $(tail -n 2 "$temporary/err" | head -n 1)"
tail -n 1 "$temporary/err" | grep -q '^make: \*\*\* \[.*strobe\] Error' ||
  fail 'make did not report the top-level goal after the verdict'
! grep -q $'\033' "$temporary/err" || fail 'color escapes without a terminal'

status="$(FORCE_COLOR=1 run_make strobe "DO_BUILD=$failing" "${outputs[@]}")"
[ "$status" -ne 0 ] || fail 'colored run left make successful'
grep -q $'\033\\[1;31mBUILD FAILED\033\\[0m: make' "$temporary/err" || fail 'forced color missing'

# A passing build prints no verdict, and a dry run neither captures nor logs.
mkdir -p "$temporary/objects/strobe/x86_64-unknown-motor/debug"
cp /bin/true "$temporary/objects/strobe/x86_64-unknown-motor/debug/strobe"
status="$(run_make strobe DO_BUILD=true "${outputs[@]}")"
[ "$status" -eq 0 ] || fail 'a passing recipe failed'
! grep -q 'BUILD FAILED' "$temporary/err" "$temporary/out" || fail 'verdict printed on success'
rm -f "$MOTOR_MAKE_LOG"
status="$(run_make -n strobe mbr.bin "DO_BUILD=$failing" "${outputs[@]}")"
[ "$status" -eq 0 ] || fail 'dry run failed'
grep -qF -- "$failing" "$temporary/out" || fail 'dry run hides the first goal'
grep -q 'x64.mbr' "$temporary/out" || fail 'dry run hides the second goal'
[ ! -e "$MOTOR_MAKE_LOG" ] || fail 'dry run wrote a log'

# A fresh gix cache must be populated before the offline build starts. Stub
# Cargo so this also checks fetch failures without accessing the network.
mkdir -p "$temporary/bin"
export MOTOR_TEST_CARGO_LOG="$temporary/cargo.log"
export MOTOR_TEST_FETCH_STATUS=0
cat > "$temporary/bin/cargo" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" >> "$MOTOR_TEST_CARGO_LOG"
case "$1" in
  fetch) exit "$MOTOR_TEST_FETCH_STATUS" ;;
  build) exit 42 ;; # Stop before ELF validation and installation.
  *) exit 99 ;;
esac
EOF
chmod +x "$temporary/bin/cargo"
status="$(PATH="$temporary/bin:$PATH" run_make gix \
  "BIN_DIR=$temporary/output" "OBJ_DIR=$temporary/objects")"
[ "$status" -ne 0 ] || fail 'stub build unexpectedly succeeded'
printf '%s\n' 'fetch --locked' \
  'build --target x86_64-unknown-motor --locked --offline' > "$temporary/expected-cargo.log"
cmp -s "$temporary/expected-cargo.log" "$MOTOR_TEST_CARGO_LOG" ||
  fail 'gix did not fetch locked sources before its offline build'
grep -q 'gix\] Error 42' "$temporary/err" || fail 'gix did not reach the build'

: > "$MOTOR_TEST_CARGO_LOG"
export MOTOR_TEST_FETCH_STATUS=43
status="$(PATH="$temporary/bin:$PATH" run_make gix \
  "BIN_DIR=$temporary/output" "OBJ_DIR=$temporary/objects")"
[ "$status" -ne 0 ] || fail 'failed gix fetch left make successful'
printf '%s\n' 'fetch --locked' > "$temporary/expected-cargo.log"
cmp -s "$temporary/expected-cargo.log" "$MOTOR_TEST_CARGO_LOG" ||
  fail 'gix started building after a failed fetch'
grep -q 'gix\] Error 43' "$temporary/err" || fail 'gix did not report the fetch failure'
echo 'test-make-driver PASS'

)

host_kloader_image() (
set -euo pipefail

BUILD=debug
if [ "${1:-}" = --release ]; then
  BUILD=release
elif [ "$#" -ne 0 ]; then
  echo "usage: $0 [--release]" >&2
  exit 2
fi
BIN_DIR="$ROOT_DIR/build/bin/$BUILD"
TEST_DIR="$(mktemp -d)"
trap 'rm -r "$TEST_DIR"' EXIT

# The staged ELF must be stripped, including when Cargo retains debug info.
sections="$(readelf -SW "$BIN_DIR/kloader")"
if printf '%s\n' "$sections" | awk '
  /[[:space:]]\.(debug_[^[:space:]]*|symtab|strtab)[[:space:]]/ { found = 1 }
  END { exit !found }
'; then
  echo "test-kloader-image: staged ELF still contains debug information or symbols" >&2
  exit 1
fi

# Stripping must preserve the embedded kernel byte for byte.
objcopy -O binary --only-section=.kernel_image \
  "$BIN_DIR/kloader" "$TEST_DIR/kernel"
cmp "$BIN_DIR/kernel" "$TEST_DIR/kernel"

echo "test-kloader-image ($BUILD) PASS"

)

host_external_sources() (

# Offline checks of the external-source stage of src/build-motor-os.sh: the
# branch-following and revision-pinned checkouts, Helix staging and ELF
# validation, and the rule that every run builds each external source into an
# empty overlay.

set -euo pipefail
. "$ROOT_DIR/src/build-motor-os.sh"
fail() { echo "test-external-sources: $*" >&2; exit 1; }
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT

remote="$temporary/remote"
seed="$temporary/seed"
mkdir -p "$remote" "$seed"
git -C "$remote" init -q --bare
git -C "$seed" init -q
git -C "$seed" config user.email test@example.com
git -C "$seed" config user.name Test
printf fixture > "$seed/source"
git -C "$seed" add source
git -C "$seed" commit -qm fixture
git -C "$seed" branch -M helix-test
git -C "$seed" remote add origin "$remote"
git -C "$seed" push -q origin helix-test

# An external source follows one branch of its fork: no commit is declared anywhere.
EXTERNAL_SOURCES="$temporary/external-sources"
HELIX="$EXTERNAL_SOURCES/helix"
mkdir -p "$EXTERNAL_SOURCES"
log() { :; }
update_external_source helix "$HELIX" "$remote" helix-test >/dev/null 2>&1
[ "$(git -C "$HELIX" rev-parse HEAD)" = "$(git -C "$seed" rev-parse HEAD)" ] ||
	fail "the checkout did not select the branch head"
printf update > "$seed/source"
git -C "$seed" commit -qam update
git -C "$seed" push -q origin helix-test
update_external_source helix "$HELIX" "$remote" helix-test >/dev/null 2>&1
[ "$(git -C "$HELIX" rev-parse HEAD)" = "$(git -C "$seed" rev-parse HEAD)" ] ||
	fail "the checkout did not follow its branch"
[ -z "$(git -C "$HELIX" status --porcelain)" ] || fail "the checkout is dirty"
printf local > "$HELIX/source"
if (update_external_source helix "$HELIX" "$remote" helix-test) >/dev/null 2>&1; then
	fail "a dirty external source checkout was updated"
fi
git -C "$HELIX" checkout -q -- source
# The checkouts sit inside the Motor OS checkout: a directory there that is
# not a checkout of its own must not be taken for that one.
outer="$temporary/outer"
git init -q -b helix-test "$outer"
printf '/external-sources/\n' > "$outer/.gitignore"
git -C "$outer" add .gitignore
git -C "$outer" -c user.email=test@example.com -c user.name=Test commit -qm outer
mkdir -p "$outer/external-sources/helix"
if (update_external_source helix "$outer/external-sources/helix" "$remote" helix-test) >/dev/null 2>&1 ||
	[ -e "$outer/.git/FETCH_HEAD" ]; then
	fail "a directory inside another checkout was taken for an external source checkout"
fi

# A pinned external source is built at its declared revision: an older one detaches the
# checkout, a newer one fast-forwards the branch, a revision the branch does not
# reach yet is fetched by its hash, and commits that are not on the remote
# branch are never left behind.
git -C "$remote" config uploadpack.allowReachableSHA1InWant true
first="$(git -C "$seed" rev-parse HEAD~1)"
second="$(git -C "$seed" rev-parse HEAD)"
update_external_source helix "$HELIX" "$remote" helix-test "$first" >/dev/null 2>&1
[ "$(git -C "$HELIX" rev-parse HEAD)" = "$first" ] ||
	fail "the checkout did not select the declared revision"
[ -z "$(git -C "$HELIX" branch --show-current)" ] ||
	fail "an older declared revision did not detach the checkout"
update_external_source helix "$HELIX" "$remote" helix-test "$second" >/dev/null 2>&1
[ "$(git -C "$HELIX" rev-parse HEAD)" = "$second" ] ||
	fail "the checkout did not move to the newer declared revision"
git -C "$HELIX" checkout -q helix-test
git -C "$HELIX" reset -q --hard "$first"
update_external_source helix "$HELIX" "$remote" helix-test "$second" >/dev/null 2>&1
[ "$(git -C "$HELIX" branch --show-current)" = helix-test ] &&
	[ "$(git -C "$HELIX" rev-parse HEAD)" = "$second" ] ||
	fail "a newer declared revision did not fast-forward the branch"
printf third > "$seed/source"
git -C "$seed" commit -qam third
third="$(git -C "$seed" rev-parse HEAD)"
if (update_external_source helix "$HELIX" "$remote" helix-test "$third") >/dev/null 2>&1; then
	fail "an unpublished declared revision was accepted"
fi
git -C "$seed" checkout -q -b helix-other
printf fourth > "$seed/source"
git -C "$seed" commit -qam fourth
fourth="$(git -C "$seed" rev-parse HEAD)"
git -C "$seed" push -q origin helix-test helix-other
update_external_source helix "$HELIX" "$remote" helix-test "$fourth" >/dev/null 2>&1
[ "$(git -C "$HELIX" rev-parse HEAD)" = "$fourth" ] ||
	fail "a declared revision on another branch was not fetched"
update_external_source helix "$HELIX" "$remote" helix-test "$third" >/dev/null 2>&1
[ "$(git -C "$HELIX" rev-parse HEAD)" = "$third" ] || fail "the checkout did not return to the branch head"
git -C "$HELIX" checkout -q -B helix-test "$third"
printf local > "$HELIX/source"
git -C "$HELIX" -c user.email=test@example.com -c user.name=Test commit -qam local
local_head="$(git -C "$HELIX" rev-parse HEAD)"
if (update_external_source helix "$HELIX" "$remote" helix-test "$third") >/dev/null 2>&1; then
	fail "a checkout with local commits was moved to the declared revision"
fi
[ "$(git -C "$HELIX" rev-parse HEAD)" = "$local_head" ] || fail "local commits were left behind"
update_external_source helix "$HELIX" "$remote" helix-test "$local_head" >/dev/null 2>&1 ||
	fail "a pinned local commit was refused"
git -C "$HELIX" reset -q --hard "$third"
case "$(declare -f prepare_external_sources)" in
	*'IFS=: read -r repo branch revision <<< "$spec"'*'"$branch" "$revision"'*) ;;
	*) fail "external sources are not prepared at their declared revisions" ;;
esac
[[ "$MOTOR_JAVY_REV" =~ ^[0-9a-f]{40}$ ]] && [[ "$MOTOR_WASMTIME_REV" =~ ^[0-9a-f]{40}$ ]] ||
	fail "Javy and Wasmtime do not declare full fork revisions"

ASSEMBLY_ROOT="$temporary/assembly"
ASSEMBLY_BUILD_ROOT="$ASSEMBLY_ROOT/build"
ASSEMBLY_IMAGE_ROOT="$ASSEMBLY_ROOT/images"
LLVM_TOOLS="$temporary/llvm/bin"
HELIX_IMG="$ASSEMBLY_IMAGE_ROOT/helix"
HELIX_TARGET_DIR="$ASSEMBLY_BUILD_ROOT/helix"
TARGET=x86_64-unknown-motor
mkdir -p "$HELIX_TARGET_DIR/$TARGET/release" "$HELIX/runtime/queries/rust" \
	"$HELIX/runtime/themes" "$LLVM_TOOLS"
printf binary > "$HELIX_TARGET_DIR/$TARGET/release/hx"
chmod 755 "$HELIX_TARGET_DIR/$TARGET/release/hx"
printf query > "$HELIX/runtime/queries/rust/highlights.scm"
printf theme > "$HELIX/runtime/themes/default.toml"
printf tutor > "$HELIX/runtime/tutor"
mkdir -p "$HELIX/runtime/grammars/sources/rust"
printf source > "$HELIX/runtime/grammars/sources/rust/parser.c"
cat > "$LLVM_TOOLS/llvm-strip" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = -o ]; then cp "$3" "$2"; else exit 1; fi
EOF
chmod +x "$LLVM_TOOLS/llvm-strip"
saved_validator="$(declare -f validate_helix_elf)"
validate_helix_elf() { :; }
stage_helix
[ -x "$HELIX_IMG/user/lib/helix/hx" ] || fail "staged hx is not executable"
for component in queries themes tutor; do
	[ -e "$HELIX_IMG/user/lib/helix/runtime/$component" ] ||
		fail "runtime component was not staged: $component"
done
[ ! -e "$HELIX_IMG/user/lib/helix/runtime/grammars" ] ||
	fail "grammar sources were staged"

eval "$saved_validator"
elf_tools="$temporary/elf-tools"
mkdir -p "$elf_tools"
ln -s "$(command -v readelf)" "$elf_tools/llvm-readelf"
ln -s "$(command -v nm)" "$elf_tools/llvm-nm"
ln -s "$(command -v strip)" "$elf_tools/llvm-strip"
LLVM_TOOLS="$elf_tools"
printf 'int main(void) { return 0; }\n' > "$temporary/static.c"
cc -fPIE -ffreestanding -c "$temporary/static.c" -o "$temporary/static.o"
cc -nostdlib -static-pie -Wl,-e,main "$temporary/static.o" -o "$temporary/static-pie"
validate_helix_elf "$temporary/static-pie"
cc -fPIE -pie "$temporary/static.c" -o "$temporary/dynamic-pie"
if (validate_helix_elf "$temporary/dynamic-pie") 2>/dev/null; then
	fail "ELF validation accepted a dynamic library dependency"
fi
printf '_Thread_local int value; int main(void) { return value; }\n' > \
	"$temporary/tls.c"
cc -fPIE -ffreestanding -c "$temporary/tls.c" -o "$temporary/tls.o"
cc -nostdlib -static-pie -Wl,-e,main "$temporary/tls.o" -o "$temporary/tls-pie"
if (validate_helix_elf "$temporary/tls-pie") 2>/dev/null; then
	fail "ELF validation accepted a TLS segment"
fi

case "$(declare -f build_helix)" in
	*'fetch --locked'*'CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER="$SYSROOT/bin/motor-clang"'*\
*'build --target "$TARGET" --release --locked'*'--offline -p helix-term --bin hx'*) ;;
	*) fail "Helix build is not an explicit fetch followed by an offline locked build" ;;
esac
# QuickJS-NG is the pinned upstream tag plus a checked patch on a fresh copy.
[ -f "$QUICKJS_PATCH" ] || fail "QuickJS patch is missing: $QUICKJS_PATCH"
case "$(declare -f fetch_quickjs)" in
	*'"$QUICKJS_REV"'*'status --porcelain'*) ;;
	*) fail "QuickJS checkout is not checked against its pinned commit and cleanliness" ;;
esac
case "$(declare -f build_quickjs)" in
	*'fetch_quickjs'*'git apply --check "$QUICKJS_PATCH"'*'git apply "$QUICKJS_PATCH"'*) ;;
	*) fail "QuickJS is not built from the checked tag with its checked patch" ;;
esac
# The native toolchain is unpacked from its archive before the external sources
# are built, so a bad archive fails the build early; the images take both.
case "$(declare -f main)" in
	*'unpack_native_toolchain'*'build_external_sources'*'build_images'*) ;;
	*) fail "the images are not built after the native toolchain and the external sources" ;;
esac
sources="$(
	build_external_source() { echo "$1"; }
	ensure_wasm_guest_toolchain() { :; }
	ensure_wasi_sdk() { :; }
	build_external_sources
)"
[ "$sources" = $'lua\nquickjs\nhelix\nsed\njavy\nwasmtime\nripgrep\ntar' ] ||
	fail 'the image build does not include all external sources'
case "$(declare -f select_external_sources)" in
	*'"sed:$SED_BRANCH"'*) ;;
	*) fail "sed does not follow its fork branch" ;;
esac
case "$(declare -f build_sed)" in
	*'CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1'*'build --target "$TARGET" --release --locked'*\
*'"$SED_IMG/user/bin/dev/sed"'*) ;;
	*) fail "sed is not a single-codegen-unit locked release build staged as /user/bin/dev/sed" ;;
esac
case "$(declare -f select_external_sources)" in
	*'"motor-os-tar:$MOTOR_OS_TAR_BRANCH"'*) ;;
	*) fail "motor-os-tar does not follow its fork branch" ;;
esac
case "$(declare -f build_tar)" in
	*'build --target "$TARGET" --release --locked'*'for tool in tar zstd'*\
*'"$TAR_IMG/user/bin/$tool"'*) ;;
	*) fail "tar and zstd are not locked release builds staged in /user/bin" ;;
esac

# Every run builds each external source into an empty overlay, and a build
# that stages nothing fails.
builds=0
overlay="$ASSEMBLY_IMAGE_ROOT/external-test"
build_test_source() {
	builds=$((builds + 1))
	mkdir -p "$overlay/bin"
	printf '%s' "$builds" > "$overlay/bin/tool"
	chmod 755 "$overlay/bin/tool"
}
build_external_source test "$overlay" bin/tool build_test_source
: > "$overlay/stale"
build_external_source test "$overlay" bin/tool build_test_source
[ "$builds" -eq 2 ] || fail "an unchanged external source was not built again"
[ ! -e "$overlay/stale" ] || fail "an external source was staged over its previous overlay"
build_nothing() { :; }
if (build_external_source test "$overlay" bin/tool build_nothing) 2>/dev/null; then
	fail "an external source build that staged nothing was accepted"
fi

# Javy and Wasmtime build with the selected toolchain, which their provenance
# records.
case "$(declare -f build_development_sources)" in
	*'build_external_source javy'*'build_external_source wasmtime'*) ;;
	*) fail "Javy/Wasmi and Wasmtime are not both external sources" ;;
esac
javy_root="$temporary/javy"
javy_log="$javy_root/toolchains.log"
mkdir -p "$javy_root/external-sources/javy" "$javy_root/external-sources/wasmtime"
for tool in javy wasmtime; do
	cat > "$javy_root/external-sources/$tool/motor-build.sh" <<'EOF'
#!/usr/bin/env bash
printf 'build %s %s\n' "$RUSTUP_TOOLCHAIN" "$*" >> "$JAVY_TOOLCHAIN_LOG"
EOF
	chmod +x "$javy_root/external-sources/$tool/motor-build.sh"
done
for selection in first-probe second-probe; do
	(
		export RUSTUP_TOOLCHAIN="$selection" JAVY_TOOLCHAIN_LOG="$javy_log"
		EXTERNAL_SOURCES="$javy_root/external-sources"
		SYSROOT="$javy_root/sysroot"
		ASSEMBLY_BUILD_ROOT="$javy_root/build"
		JAVY_IMG="$javy_root/images/javy" JAVY_TESTS="$javy_root/tests/javy"
		WASMTIME_IMG="$javy_root/images/wasmtime" WASMTIME_TESTS="$javy_root/tests/wasmtime"
		JAVY_PLUGIN_SHA=plugin JAVY_TYPESCRIPT_SHA=typescript
		javy_source_manifest() { echo manifest; }
		wasmtime_source_manifest() { echo manifest; }
		javy_download() { : > "$3"; }
		cargo() {
			printf 'cargo %s %s %s\n' "$RUSTUP_TOOLCHAIN" "${PWD##*/}" "$*" >> "$JAVY_TOOLCHAIN_LOG"
			if [ "$1" = run ]; then
				mkdir -p "${@: -1}"
				printf 'generated workload\n' > "${@: -1}/typescript-workload.js"
			fi
		}
		gzip() { :; }
		tar() { :; }
		install() { :; }
		sha256sum() { cat > /dev/null; }
		build_wasmtime_fixtures() { printf 'fixtures %s\n' "$RUSTUP_TOOLCHAIN" >> "$JAVY_TOOLCHAIN_LOG"; }
		javy_linux_reference() { :; }
		build_javy_test_plugins() { :; }
		build_javy
		build_wasmtime
	) < /dev/null > /dev/null 2>&1 || fail "the Javy or Wasmtime build failed with selection $selection"
done
expected=""
for selection in first-probe second-probe; do
	expected+="cargo $selection ${PWD##*/} run --locked --offline --manifest-path $MOTOR/src/sys/tests/javy-smoke/Cargo.toml --bin prepare-inputs -- $javy_root/build/javy-inputs/source"$'\n'
	expected+="cargo $selection javy fetch --locked"$'\n'"build $selection "$'\n'
	expected+="cargo $selection wasmtime fetch --locked"$'\n'
	expected+="cargo $selection wasmtime fetch --locked --manifest-path motor-tests/Cargo.toml"$'\n'
	expected+="build $selection all"$'\n'"fixtures $selection"$'\n'
done
[ "$(cat "$javy_log")"$'\n' = "$expected" ] ||
	fail "Javy and Wasmtime did not fetch and build with the selected toolchain"
# The normal host CLI compiler uses the selected toolchain; guest programs use the
# pinned upstream one with wasm32 targets, which the Motor toolchain lacks.
case "$(declare -f build_wasmtime_fixtures)" in
	*'--bin wasmtime --no-default-features'*'--features compile,cranelift,'*'RUSTUP_TOOLCHAIN="$WASM_GUEST_TOOLCHAIN"'*\
*'--target wasm32-wasip2 -p test-programs --features motor'*) ;;
	*) fail "the Wasmtime fixtures are not built with the expected toolchains" ;;
esac
case "$(declare -f build_development_sources)" in
	*'ensure_wasm_guest_toolchain'*'ensure_wasi_sdk'*'build_external_source javy'*\
*'build_external_source wasmtime'*) ;;
	*) fail "the guest toolchain and wasi-sdk are not provided before Javy and Wasmtime" ;;
esac
# javy-smoke's test plugins are guests too, and their QuickJS C code is built
# with the pinned wasi-sdk, checked before it is unpacked.
case "$(declare -f build_javy_test_plugins)" in
	*'RUSTUP_TOOLCHAIN="$WASM_GUEST_TOOLCHAIN" WASI_SDK'*'--target wasm32-wasip1'*\
*'--target wasm32-wasip2'*) ;;
	*) fail "the Javy test plugins are not built with the guest toolchain and wasi-sdk" ;;
esac
case "$(declare -f ensure_wasi_sdk)" in
	*'"$WASI_SDK_SHA"'*'sha256sum -c'*'tar -xzf'*) ;;
	*) fail "wasi-sdk is not checked before it is unpacked" ;;
esac
javy_manifest() (
	RUSTUP_TOOLCHAIN="$1"
	local selected="$1" reported="${2:-$1}"
	rustc() {
		if [ "$RUSTUP_TOOLCHAIN" = "$selected" ]; then
			printf 'rustc for %s\n' "$reported"
		else
			printf 'rustc for %s\n' "$RUSTUP_TOOLCHAIN"
		fi
	}
	JAVY_SOURCES=()
	JAVY_PLUGIN_SHA=plugin
	JAVY_TYPESCRIPT_SHA=typescript
	javy_source_manifest
)
first_manifest="$(javy_manifest first-probe)"
second_manifest="$(javy_manifest second-probe)"
case "$second_manifest" in
	*'rustc=rustc for second-probe'*) ;;
	*) fail "the Javy manifest does not name the selected toolchain" ;;
esac
[ "$(javy_manifest "$temporary/compiler build" second-probe)" = "$second_manifest" ] ||
	fail "selecting the same compiler by path changes the shipped provenance"
# The Linux reference digests come from the pinned Linux Javy and the fixtures
# javy-smoke compiles, so the Javy provenance names each.
case "$first_manifest" in
	*'javy-smoke/src/inputs.rs'*"javy-linux=$JAVY_LINUX_SHA"*) ;;
	*) fail "the Javy manifest does not name the Linux reference inputs" ;;
esac
case "$first_manifest" in
	*'javy-smoke/src/inputs.rs'*'guest-toolchain=rustc for '"$WASM_GUEST_TOOLCHAIN"*\
*"wasi-sdk=$WASI_SDK_SHA"*) ;;
	*) fail "the Javy manifest does not name the test plugin inputs" ;;
esac

host_wasmtime_fetch
echo "test-external-sources PASS"

)

host_toolchain_archive() (
# Offline contracts for collecting and repackaging native development payloads.
set -euo pipefail
ROOT="$ROOT_DIR"
source "$ROOT/src/build-scripts/toolchain-overlays.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail() { echo "test-toolchain-archive: $*" >&2; exit 1; }
defaults="$WORK/repo/img_files/motor-toolchain"
mkdir -p "$defaults/user/bin/dev" "$defaults/user/lib/www" \
    "$defaults/user/cfg/cargo" "$defaults/none/cfg" "$WORK/bin"
for command in lorry gix mdbg imager; do
    printf '%s\n' "$command" > "$WORK/bin/$command"
done
printf 'launcher\n' > "$defaults/user/bin/dev/www"
printf 'documentation\n' > "$defaults/user/lib/www/index.html"
printf 'Cargo defaults\n' > "$defaults/user/cfg/cargo/config.toml"
printf 'user PATH\n' > "$defaults/user/cfg/profile"
printf 'SSH PATH\n' > "$defaults/user/cfg/sshd.toml"
printf 'None defaults\n' > "$defaults/none/cfg/lorry.toml"
for overlay in "${MOTOR_TOOLCHAIN_OVERLAYS[@]}"; do
    [ "$overlay" != motor ] || continue
    mkdir -p "$WORK/assembly/$overlay/user/lib/$overlay"
    printf '%s\n' "$overlay" > "$WORK/assembly/$overlay/user/lib/$overlay/payload"
done
toolchain_collect_overlays "$WORK/repo" "$WORK/bin" "$WORK/assembly" \
    "$WORK/bin/imager" "$WORK/current"
for path in user/bin/dev/lorry user/bin/dev/gix user/bin/dev/mdbg user/bin/dev/www \
    user/lib/www/index.html user/lib/imager/imager user/cfg/cargo/config.toml \
    none/cfg/lorry.toml; do
    [ -f "$WORK/current/motor/$path" ] || fail "missing $path"
done
for path in user/bin/dev/ar user/cfg/profile user/cfg/sshd.toml; do
    [ ! -e "$WORK/current/motor/$path" ] || fail "unexpected replacement of $path"
done
# Exercise the shared packager with real tar archives, including its standalone
# entry point. The fixture tools are inert files: no compiler or network is used.
toolchain_source="${MOTOR_TOOLCHAIN_SOURCE:-$ROOT/../motor-os-toolchain}"
package_script="$toolchain_source/lib/toolchain-package.sh"
images="$WORK/current"
mkdir -p "$images/libc/system/cfg/libc" "$WORK/host/bin"
for path in llvm/user/lib/llvm/bin/llvm rustc/user/lib/rust/bin/rustc \
    rustc/user/lib/rust/bin/rustfmt rustc/user/lib/rust/bin/clippy-driver \
    rust-analyzer/user/lib/rust/bin/rust-analyzer helix/user/lib/helix/hx \
    sed/user/bin/dev/sed lua/user/bin/dev/lua quickjs/user/bin/dev/qjs \
    quickjs/user/bin/dev/qjsc javy/user/bin/dev/javy javy/user/bin/dev/wasmi \
    wasmtime/user/bin/dev/wasmtime wasmtime/user/bin/dev/wasmtime-rt; do
    mkdir -p "$images/${path%/*}"
    printf '#!/user/bin/rush\nexit 0\n' > "$images/$path"
    chmod 755 "$images/$path"
done
printf 'host compiler\n' > "$WORK/host/bin/rustc"
# LLVM's Android linker names are unrelated to the retired Motor layout.
printf '/system/bin/linker64\0' >> "$images/llvm/user/lib/llvm/bin/llvm"
name=x86_64-unknown-motor-1.99.1-3
package="motor-toolchain-$name"
cp -a "$images" "$WORK/expected-images"
bash "$package_script" "$(command -v tar)" "$WORK/output" "$name" "$images" "$WORK/host"
(cd "$WORK/output" && sha256sum -c "$package.tar.zst.sha256" "$package-x86_64-linux.tar.zst.sha256")
mkdir "$WORK/extracted"
tar -xaf "$WORK/output/$package.tar.zst" -C "$WORK/extracted"
tar -xaf "$WORK/output/$package-x86_64-linux.tar.zst" -C "$WORK/extracted"
diff -r "$WORK/expected-images" "$WORK/extracted/$package/images"
[ "$(cat "$WORK/extracted/$package-x86_64-linux/toolchain/bin/rustc")" = 'host compiler' ] ||
    fail 'host payload changed'
grep -qx '#!/user/bin/rush' "$WORK/extracted/$package/install.sh" || fail 'wrong installer shell'
if grep -Eq '/devtools|/system/bin' "$WORK/extracted/$package/install.sh"; then
    fail 'installer contains an obsolete path'
fi
[ ! -e "$images" ] && [ ! -e "$WORK/host" ] || fail 'packaging did not consume its input trees'

# A failed validation leaves the previous archive intact.
before="$(sha256sum "$WORK/output/$package.tar.zst")"
cp -a "$WORK/extracted/$package/images" "$images"
ln -s payload "$images/quickjs/user/lib/quickjs/link"
if bash "$package_script" "$(command -v tar)" "$WORK/output" "$name" "$images" > "$WORK/error" 2>&1; then
    fail 'packager accepted a symlink'
fi
grep -q 'unsupported archive member' "$WORK/error" || fail 'wrong symlink diagnostic'
[ "$(sha256sum "$WORK/output/$package.tar.zst")" = "$before" ] || fail 'failed packaging changed the archive'
rm "$images/quickjs/user/lib/quickjs/link"
printf '/system/bin/sh\0' >> "$images/llvm/user/lib/llvm/bin/llvm"
if bash "$package_script" "$(command -v tar)" "$WORK/output" "$name" "$images" > "$WORK/error" 2>&1; then
    fail 'packager accepted an obsolete compiled shell path'
fi
grep -q 'obsolete compiled path' "$WORK/error" || fail 'wrong compiled-path diagnostic'
cp -a "$WORK/extracted/$package/images/llvm/user/lib/llvm/bin/llvm" "$images/llvm/user/lib/llvm/bin/llvm"
mkdir "$images/llvm/devtools"
if bash "$package_script" "$(command -v tar)" "$WORK/output" "$name" "$images" > "$WORK/error" 2>&1; then
    fail 'packager accepted the obsolete layout'
fi
grep -q 'obsolete image layout' "$WORK/error" || fail 'wrong legacy-layout diagnostic'

# Always repackage, including unchanged payloads, without modifying the release.
repo="$WORK/repo"
mkdir -p "$repo/src/build-scripts" "$repo/build/bin" "$repo/build/assembly/build/motor-os-tar-linux/release"
cp "$ROOT/src/build-scripts/"toolchain-{archive,overlays}.sh "$repo/src/build-scripts/"
cp -a "$WORK/bin" "$repo/build/bin/release"
cp -a "$WORK/extracted/$package/images" "$repo/build/assembly/"
ln -s "$(command -v tar)" "$repo/build/assembly/build/motor-os-tar-linux/release/tar"
printf '[toolchain]\nchannel = "%s"\n' "$name" > "$repo/rust-toolchain.toml"
repackage() {
    MOTORH="$WORK/output" MOTOR_TOOLCHAIN_SOURCE="$toolchain_source" \
        bash "$repo/src/build-scripts/toolchain-archive.sh" release
}
original="$WORK/output/$package.tar.zst"
[ "$(repackage)" = "$repo/build/toolchain/release/$package.tar.zst" ] ||
    fail 'unchanged payloads did not produce a local archive'
printf 'new host imager\n' >> "$repo/build/bin/release/imager"
printf 'new Lorry\n' >> "$repo/build/bin/release/lorry"
repacked="$(repackage)"
[ "$repacked" = "$repo/build/toolchain/release/$package.tar.zst" ] || fail 'repackaged archive is outside build/'
tar -xOf "$repacked" "$package/images/motor/user/bin/dev/lorry" > "$WORK/lorry"
cmp "$repo/build/bin/release/lorry" "$WORK/lorry" || fail 'repackaged archive has stale guest bytes'
tar -xOf "$repacked" "$package/images/motor/user/lib/imager/imager" > "$WORK/imager"
cmp "$repo/build/bin/release/imager" "$WORK/imager" || fail 'repackaged archive has a stale host imager'
[ "$(sha256sum "$original")" = "$before" ] || fail 'repackaging changed the original release'
echo 'test-toolchain-archive PASS'

)

host_toolchain_bootstrap() (
# Offline checks of the release builder's Motor OS checkout and compiler handoff.
set -euo pipefail
ROOT="$ROOT_DIR"
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

)

host_net_contract() (
set -euo pipefail


# Networking remains async-first; blocking policy belongs to the VDSO.
if matches=$(grep -RnE --include='*.rs' \
    'SysCpu::spawn|block_on_sync|SyncWaiter|thread::sleep|sched_yield' \
    "$ROOT_DIR/src/sys/lib/moto-sdk/src/io/net" | \
    grep -vE '^[^:]+:[0-9]+:[[:space:]]*//'); then
  echo "moto-sdk networking contains blocking operations:" >&2
  echo "$matches" >&2
  exit 1
fi

feature_graph() {
  cargo tree --manifest-path "$1" --target "$2" --locked --offline -p "$3" \
    -e normal,build --prefix none --format '{p} features=[{f}]'
}

no_test_support() {
  local graph matches
  graph=$(feature_graph "$@")
  if matches=$(printf '%s\n' "$graph" | \
      grep -E 'features=\[([^]]*,)?test-support(,|\])'); then
    echo "$3 enables test-support in production:" >&2
    echo "$matches" >&2
    exit 1
  fi
}

# Each production package builds independently, just as in the Makefile.
# Including systest here would unify its test features into the services.
MOTOR=x86_64-unknown-motor
for package in rt sys-io sys-init sys-tty strobe dns-resolver sysbox wg; do
  no_test_support "$ROOT_DIR/src/sys/Cargo.toml" "$MOTOR" "$package"
done
# Programs outside src/sys take the same SDK.
HOST="$(rustc -vV | sed -n 's/^host: //p')"
no_test_support "$ROOT_DIR/src/bin/russhd/Cargo.toml" "$MOTOR" russhd
no_test_support "$ROOT_DIR/src/bin/rmux/Cargo.toml" "$MOTOR" rmux
no_test_support "$ROOT_DIR/src/imager/Cargo.toml" "$HOST" imager

# rt.vdso builds with core and alloc only, so nothing may turn on the SDK's std.
if feature_graph "$ROOT_DIR/src/sys/Cargo.toml" "$MOTOR" rt | \
    grep -E '^moto-sdk .*features=\[([^]]*,)?std(,|\])' >&2; then
  echo "rt.vdso enables moto-sdk's std" >&2
  exit 1
fi
# The SDK's Unix slice takes no Motor OS crates.
if feature_graph "$ROOT_DIR/src/imager/Cargo.toml" "$HOST" imager | \
    grep -E '^moto-(rt|sys) ' >&2; then
  echo "the imager's SDK pulls in Motor OS crates on $HOST" >&2
  exit 1
fi

graph=$(feature_graph "$ROOT_DIR/src/sys/Cargo.toml" "$MOTOR" systest)
printf '%s\n' "$graph" | \
  grep -E '^moto-sdk .*features=\[([^]]*,)?test-support(,|\])' >/dev/null
echo "network async and production feature contracts PASS"

)

host_wasmtime_fetch() (
# Exercise the producer's fetch with an empty cache and a file-only registry.
set -euo pipefail
. "$ROOT_DIR/src/build-motor-os.sh"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
fail() { echo "test-wasmtime-fetch: $*" >&2; exit 1; }
export RUSTUP_TOOLCHAIN="$TOOLCHAIN"
export CARGO_HOME="$temporary/cargo-home"
export CARGO_TARGET_DIR="$temporary/target"
EXTERNAL_SOURCES="$temporary/external-sources"
SYSROOT="$temporary/sysroot"
ASSEMBLY_ROOT="$temporary/assembly"
ASSEMBLY_BUILD_ROOT="$temporary/build"
WASMTIME_IMG="$temporary/image"
WASMTIME_TESTS="$temporary/tests"
wasmtime_source_manifest() { echo fixture; }
registry="$temporary/registry"
runtime="$EXTERNAL_SOURCES/wasmtime"
mkdir -p "$registry/fe/tc" "$temporary/downloads" "$CARGO_HOME" \
	"$runtime/src" "$runtime/motor-tests/src" "$EXTERNAL_SOURCES/bridge/src"
for version in 1.0.0 2.0.0; do
	mkdir -p "$temporary/fetch-leaf-$version/src"
	cat > "$temporary/fetch-leaf-$version/Cargo.toml" <<EOF
[package]
name = "fetch-leaf"
version = "$version"
edition = "2024"
EOF
	: > "$temporary/fetch-leaf-$version/src/lib.rs"
	tar -czf "$temporary/downloads/fetch-leaf-$version.crate" -C "$temporary" "fetch-leaf-$version"
	checksum="$(sha256sum "$temporary/downloads/fetch-leaf-$version.crate" | cut -d' ' -f1)"
	printf '{"name":"fetch-leaf","vers":"%s","deps":[],"cksum":"%s","features":{},"yanked":false}\n' \
		"$version" "$checksum" >> "$registry/fe/tc/fetch-leaf"
done
printf '{"dl":"file://%s/downloads/{crate}-{version}.crate"}\n' "$temporary" > "$registry/config.json"
git -C "$registry" init -q
git -C "$registry" add .
git -C "$registry" -c user.name=Test -c user.email=test@example.com commit -qm fixture
cat > "$CARGO_HOME/config.toml" <<EOF
[source.crates-io]
replace-with = "fixture"
[source.fixture]
registry = "file://$registry"
EOF
cat > "$runtime/Cargo.toml" <<'EOF'
[package]
name = "fetch-runtime"
version = "1.0.0"
edition = "2024"
[workspace]
[target.'cfg(target_os = "motor")'.dependencies]
fetch-bridge = { path = "../bridge" }
EOF
cat > "$EXTERNAL_SOURCES/bridge/Cargo.toml" <<'EOF'
[package]
name = "fetch-bridge"
version = "1.0.0"
edition = "2024"
[workspace]
[target.'cfg(not(target_os = "motor"))'.dependencies]
fetch-leaf = "=1.0.0"
EOF
: > "$runtime/src/lib.rs"
: > "$EXTERNAL_SOURCES/bridge/src/lib.rs"
# An independent lockfile can select a version absent from the main workspace.
cat > "$runtime/motor-tests/Cargo.toml" <<'EOF'
[package]
name = "fetch-policy-tests"
version = "1.0.0"
edition = "2024"
[workspace]
[dependencies]
fetch-leaf = "=2.0.0"
EOF
: > "$runtime/motor-tests/src/lib.rs"
cat > "$EXTERNAL_SOURCES/wasmtime/motor-build.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "$CARGO_NET_OFFLINE" = true ]
manifest=Cargo.toml
[ "$1" != tests ] || manifest=motor-tests/Cargo.toml
cargo build --locked --manifest-path "$manifest" --target x86_64-unknown-motor --lib
EOF
chmod +x "$EXTERNAL_SOURCES/wasmtime/motor-build.sh"
(
	cd "$runtime"
	cargo generate-lockfile
	cp Cargo.lock "$temporary/original.lock"
	cargo generate-lockfile --manifest-path motor-tests/Cargo.toml
	cp motor-tests/Cargo.lock "$temporary/original-tests.lock"
)
# The registry leaf is still uncached. Separate target walks miss this host
# dependency below the Motor-only bridge; the producer must fetch it first.
# Run the real producer fetch and offline build; image staging is unrelated.
install() { :; }
sha256sum() { :; }
build_wasmtime_fixtures() {
	(cd "$runtime" && CARGO_NET_OFFLINE=true ./motor-build.sh tests)
}
build_wasmtime
cmp "$runtime/Cargo.lock" "$temporary/original.lock" || fail "the producer changed the lockfile"
cmp "$runtime/motor-tests/Cargo.lock" "$temporary/original-tests.lock" ||
	fail "the producer changed the test lockfile"
echo "test-wasmtime-fetch PASS"

)

host_vm_image_format() (
unset MOTO_IMAGE MOTO_SMP MOTO_MEMORY_MIB

set -euo pipefail

SCRIPT_DIR="$ROOT_DIR/src/tests"
VM_DIR="$ROOT_DIR/src/vm_scripts"
TEST_ROOT="$(mktemp -d /tmp/motor-image-format-test-XXXXXX)"
FAKE_BIN="$TEST_ROOT/bin"
ARG_LOG="$TEST_ROOT/args"
ERROR_LOG="$TEST_ROOT/error"

cleanup() {
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

fail() {
  echo "test-vm-image-format: $*" >&2
  exit 1
}

assert_arg() {
  local expected="$1"
  grep -Fxq -- "$expected" "$ARG_LOG" ||
    fail "missing VMM argument '$expected'"
}

assert_no_arg() {
  local unexpected="$1"
  if grep -Fxq -- "$unexpected" "$ARG_LOG"; then
    fail "unexpected VMM argument '$unexpected'"
  fi
}

mkdir -p "$FAKE_BIN"
cat > "$FAKE_BIN/fake-vmm" <<'EOF'
#!/bin/sh
: "${MOTOR_VM_ARG_LOG:?}"
if [ -n "${MOTOR_VM_EXPECT_LOCK:-}" ]; then
  exec 7> "$MOTOR_VM_EXPECT_LOCK"
  if flock -n 7; then
    echo "fake-vmm: runner lock was not held across exec" >&2
    exit 1
  fi
fi
printf '%s\n' "$@" > "$MOTOR_VM_ARG_LOG"
EOF
chmod +x "$FAKE_BIN/fake-vmm"
ln -s fake-vmm "$FAKE_BIN/qemu-system-x86_64"
ln -s fake-vmm "$FAKE_BIN/cloud-hypervisor-static"
ln -s fake-vmm "$FAKE_BIN/firecracker"

 # The raw standard image is opt-in. Exercise the inner make graph directly so
# this remains independent of the top-level logging wrapper.
make -n -C "$ROOT_DIR" MAKELEVEL=1 > "$TEST_ROOT/make-default"
for target in all images; do
  make -n -C "$ROOT_DIR" MAKELEVEL=1 "$target" > "$TEST_ROOT/make-$target"
done
for graph in default all images; do
  if grep -Fq -- '--raw-output' "$TEST_ROOT/make-$graph"; then
    fail "$graph make graph unexpectedly builds the raw standard image"
  fi
done
make -n -C "$ROOT_DIR" MAKELEVEL=1 raw.img > "$TEST_ROOT/make-raw"
grep -Fq -- 'motor-os.yaml --raw-output motor-os.img' "$TEST_ROOT/make-raw" ||
  fail "raw.img make graph does not request the raw standard image"

run_qemu() {
  PATH="$FAKE_BIN:$PATH" MOTOR_VM_ARG_LOG="$ARG_LOG" \
    MOTO_QEMU_LOCK="$TEST_ROOT/qemu.lock" "$VM_DIR/run-qemu.sh" "$@" \
    >/dev/null 2>&1
}

run_chv() {
  PATH="$FAKE_BIN:$PATH" MOTOR_VM_ARG_LOG="$ARG_LOG" \
    MOTO_QEMU_LOCK="$TEST_ROOT/qemu.lock" \
    MOTOR_VM_EXPECT_LOCK="$TEST_ROOT/qemu.lock" \
    MOTO_CHV_RUNTIME_DIR="$TEST_ROOT/chv" "$VM_DIR/run-chv.sh" "$@" \
    >/dev/null 2>&1
}

run_fc() {
  PATH="$FAKE_BIN:$PATH" MOTOR_VM_ARG_LOG="$ARG_LOG" \
    MOTO_QEMU_LOCK="${MOTO_QEMU_LOCK:-$TEST_ROOT/qemu.lock}" \
    MOTOR_VM_EXPECT_LOCK="${MOTO_QEMU_LOCK:-$TEST_ROOT/qemu.lock}" \
    MOTO_FC_RUNTIME_DIR="$TEST_ROOT/fc" "$VM_DIR/run-fc.sh" "$@"
}

MOTO_SHARED_MEM='' run_qemu
assert_arg "file=$VM_DIR/motor-os.qcow2,if=none,id=drive0,format=qcow2"
assert_no_arg "memory-backend-memfd,id=mem0,size=1024M,share=on"
assert_no_arg "memory-backend=mem0"

MOTO_MEMORY_MIB=1024 MOTO_HUGEPAGES=0 MOTO_SHARED_MEM=1 run_qemu
assert_arg "-object"
assert_arg "memory-backend-memfd,id=mem0,size=1024M,share=on"
assert_arg "-machine"
assert_arg "memory-backend=mem0"
assert_no_arg "-mem-path"

MOTO_IMAGE=motor-os-base.img run_qemu
assert_arg "file=$VM_DIR/motor-os-base.img,if=none,id=drive0,format=raw"

if MOTO_IMAGE=motor-os.bad run_qemu 2> "$ERROR_LOG"; then
  fail "QEMU accepted an unsupported image suffix"
fi

run_chv
assert_arg "path=$VM_DIR/motor-os.qcow2,image_type=qcow2"

MOTO_IMAGE=motor-os-base.img run_chv
assert_arg "path=$VM_DIR/motor-os-base.img,image_type=raw"


MOTO_FC_VSOCK_UDS='' run_fc >/dev/null 2>&1
grep -Fq '"path_on_host": "'"$VM_DIR"'/motor-os-base.img"' \
  "$TEST_ROOT/fc/fc-config.json" || fail "Firecracker did not select the raw base image"
if grep -Fq '"vsock"' "$TEST_ROOT/fc/fc-config.json"; then
  fail "Firecracker enabled vsock without MOTO_FC_VSOCK_UDS"
fi

MOTO_IMAGE=motor-os.img MOTO_FC_VSOCK_UDS='' run_fc >/dev/null 2>&1
grep -Fq '"path_on_host": "'"$VM_DIR"'/motor-os.img"' \
  "$TEST_ROOT/fc/fc-config.json" || fail "Firecracker did not select the raw standard image"

MOTO_FC_VSOCK_UDS="$TEST_ROOT/fc/vsock" run_fc >/dev/null 2>&1
grep -Fq '"guest_cid": 3' "$TEST_ROOT/fc/fc-config.json" ||
  fail "Firecracker vsock config lacks guest CID 3"
grep -Fq '"uds_path": "'"$TEST_ROOT"'/fc/vsock"' \
  "$TEST_ROOT/fc/fc-config.json" || fail "Firecracker vsock config lacks its UDS path"

rm -f "$ARG_LOG"
if MOTO_FC_VSOCK_UDS=relative/path run_fc 2> "$ERROR_LOG"; then
  fail "Firecracker accepted a relative vsock UDS path"
fi
grep -Fq "MOTO_FC_VSOCK_UDS must be an absolute path" "$ERROR_LOG" ||
  fail "Firecracker did not explain its invalid vsock UDS path"
[ ! -e "$ARG_LOG" ] || fail "Firecracker launched with an invalid vsock UDS path"

rm -f "$ARG_LOG"
if MOTO_FC_VSOCK_UDS="$TEST_ROOT/fc/vsock bad" run_fc 2> "$ERROR_LOG"; then
  fail "Firecracker accepted an unsafe vsock UDS path"
fi
grep -Fq "invalid MOTO_FC_VSOCK_UDS" "$ERROR_LOG" ||
  fail "Firecracker did not explain its unsafe vsock UDS path"
[ ! -e "$ARG_LOG" ] || fail "Firecracker launched with an unsafe vsock UDS path"

exec 8> "$TEST_ROOT/common-vm.lock"
flock -n 8
rm -f "$ARG_LOG"
if MOTO_QEMU_LOCK="$TEST_ROOT/common-vm.lock" run_fc 2> "$ERROR_LOG"; then
  fail "Firecracker ignored the common Motor OS VM lock"
fi
grep -Fq "another Motor OS VM owns $TEST_ROOT/common-vm.lock" "$ERROR_LOG" ||
  fail "Firecracker did not explain the common VM lock conflict"
[ ! -e "$ARG_LOG" ] || fail "Firecracker launched while the common VM lock was held"
exec 8>&-

if MOTO_IMAGE=motor-os.qcow2 run_fc > /dev/null 2> "$ERROR_LOG"; then
  fail "Firecracker accepted a qcow2 image"
fi
grep -Fq "Firecracker requires a raw image" "$ERROR_LOG" ||
  fail "Firecracker did not explain its raw-image requirement"


# Exercise all public launchers with fake VMMs, isolated from host resources.
(
  export PATH="$FAKE_BIN:$PATH" MOTOR_VM_ARG_LOG="$ARG_LOG"
  export MOTO_QEMU_LOCK="$TEST_ROOT/options.lock" MOTO_HUGEPAGES=0
  export MOTO_CHV_RUNTIME_DIR="$TEST_ROOT/chv" MOTO_FC_RUNTIME_DIR="$TEST_ROOT/fc"
  unset MOTO_IMAGE MOTO_CPU_AFFINITY MOTO_SHARED_MEM MOTO_FC_VSOCK_UDS

  run_options() {
    "$VM_DIR/run-$runner.sh" "$@" > /dev/null 2> "$ERROR_LOG"
  }

  assert_resources() {
    local cpus="$1" memory="$2"
    case "$runner" in
      fc)
        grep -Fxq "    \"vcpu_count\": $cpus," "$TEST_ROOT/fc/fc-config.json" ||
          fail "wrong Firecracker CPU count"
        grep -Fxq "    \"mem_size_mib\": $memory" "$TEST_ROOT/fc/fc-config.json" ||
          fail "wrong Firecracker memory size"
        ;;
      chv) assert_arg "boot=$cpus"; assert_arg "size=${memory}M" ;;
      *) assert_arg "-smp"; assert_arg "$cpus"; assert_arg "${memory}M" ;;
    esac
  }

  for runner in qemu qemu-echr chv fc; do
    unset MOTO_SMP MOTO_MEMORY_MIB
    run_options
    case "$runner" in
      fc) assert_resources 2 64 ;;
      *) assert_resources 4 1024 ;;
    esac
    export MOTO_SMP=6 MOTO_MEMORY_MIB=768
    run_options
    assert_resources 6 768
    run_options --cpus 3 --memory 512M
    assert_resources 3 512
    run_options --memory=2G --cpus=5 -- 'argument with spaces' --cpus=passthrough
    assert_resources 5 2048
    assert_arg 'argument with spaces'
    assert_arg --cpus=passthrough
    assert_no_arg --cpus=5
    assert_no_arg --memory=2G
    if [ "$runner" = qemu-echr ]; then
      assert_arg -echr
      assert_arg 0x14
    fi

    for option in --cpus --memory; do
      for value in '' 0 -1 1.5 01 invalid; do
        rm -f "$ARG_LOG"
        if run_options "$option=$value"; then
          fail "$runner accepted $option=$value"
        fi
        [ ! -e "$ARG_LOG" ] || fail "$runner launched with invalid options"
      done
      if run_options "$option"; then
        fail "$runner accepted a missing $option value"
      fi
    done
    for value in 512 0M 01G 1m 1g 1MB 1.5G 9000000000G 99999999999999999999M; do
      if run_options --memory "$value"; then
        fail "$runner accepted --memory $value"
      fi
    done
    rm -f "$ARG_LOG"
    run_options --help
    [ ! -e "$ARG_LOG" ] || fail "$runner launched for --help"
  done

  runner=chv
  run_options --cpus 3 --memory 1G
  assert_arg boot=3
  assert_arg size=1024M
  run_options -- --cpus boot=7 --memory size=3G
  assert_arg boot=7
  assert_arg size=3G

  runner=qemu
  MOTO_SHARED_MEM=1 run_options --memory 2G -monitor 'unix:monitor path,server'
  assert_arg 'memory-backend-memfd,id=mem0,size=2048M,share=on'
  assert_arg -monitor
  assert_arg 'unix:monitor path,server'

  for runner in qemu qemu-echr chv fc; do
    run_options
    case "$runner" in
      chv) assert_arg --net; assert_no_arg --cmdline ;;
      fc)
        grep -Fq '"host_dev_name": "moto-tap"' "$TEST_ROOT/fc/fc-config.json" ||
          fail 'Firecracker lost its default network device'
        default_boot_args="$(sed -n 's/.*"boot_args": "\(.*\)"/\1/p' "$TEST_ROOT/fc/fc-config.json")"
        ;;
      *) assert_arg -netdev ;;
    esac
    run_options --no-network
    assert_no_arg --no-network
    case "$runner" in
      chv) assert_no_arg --net ;;
      fc)
        if grep -Fq '"iface_id"' "$TEST_ROOT/fc/fc-config.json"; then
          fail 'Firecracker still has a network device'
        fi
        ;;
      *)
        assert_no_arg -netdev
        assert_no_arg virtio-net-pci,disable-legacy=on,mac=a4:a1:c2:00:00:01,netdev=nic0
        assert_arg -nic
        assert_arg none
        ;;
    esac
    case "$runner" in
      qemu*)
        rm -f "$ARG_LOG"
        if run_options --system-tty; then fail "$runner accepted --system-tty"; fi
        grep -Fq 'disk boot has no kernel command line' "$ERROR_LOG" ||
          fail "$runner did not explain --system-tty refusal"
        [ ! -e "$ARG_LOG" ] || fail "$runner launched with --system-tty"
        ;;
      *)
        run_options --system-tty --no-network
        assert_no_arg --system-tty
        assert_no_arg --no-network
        if [ "$runner" = chv ]; then
          assert_arg --cmdline
          assert_arg system-tty
          assert_no_arg --net
          for cmdline in '' 'console=ttyS0 test="two words" system-tty=0'; do
            run_options --system-tty -- --cmdline "$cmdline" --serial null
            assert_arg "${cmdline:+$cmdline }system-tty"
            assert_arg --serial
            assert_arg null
            run_options --system-tty -- "--cmdline=$cmdline"
            assert_arg "${cmdline:+$cmdline }system-tty"
          done
          run_options -- --cmdline 'no-system-tty system-tty-extra'
          assert_arg 'no-system-tty system-tty-extra'
          assert_no_arg system-tty
          if run_options --system-tty -- --cmdline; then fail 'missing command line accepted'; fi
        else
          grep -Fq "\"boot_args\": \"$default_boot_args system-tty\"" "$TEST_ROOT/fc/fc-config.json" ||
            fail 'Firecracker did not preserve its boot arguments with system-tty'
          if grep -Fq '"iface_id"' "$TEST_ROOT/fc/fc-config.json"; then
            fail 'Firecracker system-tty boot still has a network device'
          fi
        fi
        ;;
    esac
  done
)

for runner in qemu chv fc; do
  "run_$runner" --root-read-only --extra-disk first.img --extra-disk-ro second.raw >/dev/null 2>&1
  case "$runner" in
    qemu)
      assert_arg "file=$VM_DIR/motor-os.qcow2,if=none,id=drive0,format=qcow2,readonly=on"
      assert_arg "file=$VM_DIR/first.img,if=none,id=drive1,format=raw,readonly=off"
      assert_arg "file=$VM_DIR/second.raw,if=none,id=drive2,format=raw,readonly=on"
      ;;
    chv)
      assert_arg "path=$VM_DIR/motor-os.qcow2,image_type=qcow2,readonly=on"
      assert_arg "path=$VM_DIR/first.img,image_type=raw,readonly=off"
      assert_arg "path=$VM_DIR/second.raw,image_type=raw,readonly=on"
      ;;
    fc)
      grep -Fq '"is_read_only": true' "$TEST_ROOT/fc/fc-config.json" || fail 'root read-only flag missing'
      grep -Fq '"drive_id":"disk1","path_on_host":"'"$VM_DIR"'/first.img","is_root_device":false,"is_read_only":false' \
        "$TEST_ROOT/fc/fc-config.json" || fail 'first extra disk missing'
      grep -Fq '"drive_id":"disk2","path_on_host":"'"$VM_DIR"'/second.raw","is_root_device":false,"is_read_only":true' \
        "$TEST_ROOT/fc/fc-config.json" || fail 'read-only extra disk missing'
      ;;
  esac
  for bad in '' '../outside.img' 'data space.img' 'data,bad.img' 'data:bad.img' 'data.bad'; do
    rm -f "$ARG_LOG"
    if "run_$runner" --extra-disk "$bad" > "$ERROR_LOG" 2>&1; then
      fail "$runner accepted invalid extra disk '$bad'"
    fi
    [ ! -e "$ARG_LOG" ] || fail "$runner launched with an invalid extra disk"
  done
  if "run_$runner" --extra-disk > "$ERROR_LOG" 2>&1; then fail "$runner accepted a missing extra disk"; fi
done
run_qemu --extra-disk data.qcow2
assert_arg "file=$VM_DIR/data.qcow2,if=none,id=drive1,format=qcow2,readonly=off"
run_chv --extra-disk data.qcow2
assert_arg "path=$VM_DIR/data.qcow2,image_type=qcow2,readonly=off"
if run_fc --extra-disk data.qcow2 > "$ERROR_LOG" 2>&1; then fail 'Firecracker accepted qcow2 extra disk'; fi
PATH="$FAKE_BIN:$PATH" MOTOR_VM_ARG_LOG="$ARG_LOG" MOTO_QEMU_LOCK="$TEST_ROOT/qemu.lock" \
  "$VM_DIR/run-qemu-echr.sh" --root-read-only --extra-disk first.img >/dev/null 2>&1
assert_arg "file=$VM_DIR/first.img,if=none,id=drive1,format=raw,readonly=off"
assert_arg -echr

echo "test-vm-image-format: PASS"

)

host_vm_console_filter() (

set -euo pipefail

WD="$ROOT_DIR/src/tests"

input=$'before\033[6nafter\033[18tmode\033[?2048$penable\033[?2048hdisable\033[?2048lend\0337\033[9999;9999H\0338'
expected=$'beforeaftermodeenabledisableend\0337\033[9999;9999H\0338'
actual="$(printf '%s' "$input" | filter_vm_console)"

if [ "$actual" != "$expected" ]; then
  echo "test-vm-console-filter: unexpected filtered output" >&2
  printf 'expected: %q\nactual:   %q\n' "$expected" "$actual" >&2
  exit 1
fi

echo "test-vm-console-filter PASS"

)

host_vm_vsock_backend() (
# Hermetic checks of the vsock backend lookup and its one-time install: fake
# backends and a stub cargo stand in for the network install.

set -euo pipefail

WD="$ROOT_DIR/src/tests"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/test-vm-vsock-backend.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  echo "test-vm-vsock-backend: $*" >&2
  [ ! -s "$TMP/stderr" ] || cat "$TMP/stderr" >&2
  exit 1
}

# Create DIR/vhost-device-vsock, a fake backend that reports VERSION. The stub
# cargo calls this under a PATH that holds nothing else, hence `command -p`.
fake_backend() {
  command -p mkdir -p "$1"
  printf '#!/bin/sh\necho "vhost-device-vsock %s"\n' "$2" > "$1/vhost-device-vsock"
  command -p chmod +x "$1/vhost-device-vsock"
}
fake_backend "$TMP/pinned" "$VSOCK_BACKEND_VERSION"
fake_backend "$TMP/explicit" "$VSOCK_BACKEND_VERSION"
fake_backend "$TMP/stale" 0.2.0
mkdir "$TMP/empty"

# Look up with only SEARCH_PATH and EXPLICIT visible, so that a backend really
# installed on this host cannot affect the result. Prints the selected backend.
lookup() (
  PATH="$1"
  VHOST_DEVICE_VSOCK="$2"
  resolve_vsock_backend 2> "$TMP/stderr" && printf '%s\n' "$VHOST_DEVICE_VSOCK"
)

# A rejected lookup must name the remedy.
expect_hint() {
  grep -Fq -- "${VSOCK_BACKEND_INSTALL[*]}" "$TMP/stderr" ||
    fail "$1: the diagnostic does not give the install command"
}

[ "$(lookup "$TMP/pinned" "")" = "$TMP/pinned/vhost-device-vsock" ] ||
  fail "the pinned backend on PATH was not selected"
[ "$(lookup "$TMP/pinned" "$TMP/explicit/vhost-device-vsock")" = "$TMP/explicit/vhost-device-vsock" ] ||
  fail "an explicit VHOST_DEVICE_VSOCK did not take precedence over PATH"

if lookup "$TMP/empty" "" >/dev/null; then
  fail "a missing backend was accepted"
fi
grep -Fq 'is not installed' "$TMP/stderr" || fail "a missing backend was not reported as such"
expect_hint "missing backend"

if lookup "$TMP/stale" "" >/dev/null; then
  fail "a backend of another version was accepted"
fi
grep -Fq "expected vhost-device-vsock $VSOCK_BACKEND_VERSION, got 'vhost-device-vsock 0.2.0'" \
  "$TMP/stderr" || fail "a version mismatch was not reported as such"
expect_hint "version mismatch"

# A broken explicit choice is an error; it must not silently fall back to PATH.
if lookup "$TMP/pinned" "$TMP/empty/vhost-device-vsock" >/dev/null; then
  fail "a broken explicit VHOST_DEVICE_VSOCK fell back to PATH"
fi
expect_hint "broken explicit backend"

# The harness entry point installs the pinned backend once, from the checkout.
install_produces_backend=1
cargo() {
  printf '%s | %s\n' "$PWD" "$*" >> "$TMP/cargo.log"
  [ "$*" = "install --locked --version $VSOCK_BACKEND_VERSION vhost-device-vsock" ] ||
    fail "unexpected cargo command: $*"
  [ "$install_produces_backend" -eq 0 ] || fake_backend "$TMP/bin" "$VSOCK_BACKEND_VERSION"
}
# Run with BIN as the only PATH entry, holding the INITIAL backend version or none.
ensure() (
  rm -rf "$TMP/bin" "$TMP/cargo.log"
  mkdir -p "$TMP/bin"
  : > "$TMP/cargo.log"
  [ "$1" = none ] || fake_backend "$TMP/bin" "$1"
  cd "$TMP"
  PATH="$TMP/bin"
  VHOST_DEVICE_VSOCK="${2:-}"
  ensure_vsock_backend 2> "$TMP/stderr"
)
install="$VSOCK_BACKEND_CHECKOUT | install --locked --version $VSOCK_BACKEND_VERSION vhost-device-vsock"
expect_cargo_log() {
  [ "$(< "$TMP/cargo.log")" = "$1" ] || fail "$2: unexpected cargo calls: $(< "$TMP/cargo.log")"
}
ensure "$VSOCK_BACKEND_VERSION" || fail "an installed backend was rejected"
expect_cargo_log "" "installed backend"
ensure none || fail "a missing backend was not installed"
expect_cargo_log "$install" "missing backend"
ensure 0.2.0 || fail "a backend of another version was not replaced"
expect_cargo_log "$install" "stale backend"
if ensure none "$TMP/empty/vhost-device-vsock"; then
  fail "a broken explicit VHOST_DEVICE_VSOCK was accepted"
fi
expect_cargo_log "" "explicit backend"
install_produces_backend=0
if ensure none; then fail "an install that produced no usable backend was accepted"; fi
expect_cargo_log "$install" "fruitless install"

echo "test-vm-vsock-backend PASS"

)

host_sdk_package() (
# Test moto-sdk as crates.io would ship it.
# Packaging leaves the src/sys workspace behind: path dependencies become
# registry ones, and the workspace's [patch] no longer applies. This check
# packages moto-sdk, extracts the .crate under build/ and builds it on its own,
# against crates.io only: on Unix, where its tests run, and on Motor OS with
# std, with std and test-support, and with only core and alloc (as rt.vdso
# builds it). The Motor test binaries, the re-export check among them, only
# compile here; they run natively under full-native-test.sh.
#
# moto-sdk/tests/package.lock pins the build. Each direct dependency is locked at
# the lowest version the manifest allows, so the declared floors are what is
# tested. After moto-sdk's dependencies change, --update-lock writes a new
# lock; it needs the network.
#
# Testing is offline. full_prepare fetches and builds its inputs first.

set -euo pipefail

LOCK="$ROOT_DIR/src/sys/lib/moto-sdk/tests/package.lock"
OUT="$ROOT_DIR/build/sdk-package"
MOTOR=x86_64-unknown-motor

mode=test
profile_args=()
for arg in "$@"; do
  case "$arg" in
    --release) profile_args=(--release) ;;
    --prepare) mode=prepare ;;
    --update-lock) mode=update-lock ;;
    *) echo "usage: $0 [--release] [--prepare | --update-lock]" >&2; exit 2 ;;
  esac
done

fail() {
  echo "test-sdk-package: $*" >&2
  exit 1
}

network_args=(--offline)
[ "$mode" = test ] || network_args=()
verbosity_args=(--quiet)
if [ "$mode" = prepare ]; then
  verbosity_args=()
fi

progress() {
  if [ "$mode" = prepare ]; then
    echo "test-sdk-package: $*"
  fi
}

# The .crate a publish would upload.
progress "packaging moto-sdk"
rm -rf "$OUT/crate" "$OUT"/.staging.*
mkdir -p "$OUT"
(cd "$ROOT_DIR/src/sys" && CARGO_TARGET_DIR="$OUT/crate" cargo package "${verbosity_args[@]}" \
  --locked "${network_args[@]}" --no-verify --allow-dirty -p moto-sdk)
staging="$(mktemp -d "$OUT/.staging.XXXXXX")"
tar -xzf "$OUT"/crate/package/moto-sdk-*.crate -C "$staging" --strip-components=1 \
  --touch

if [ "$mode" = update-lock ]; then
  (cd "$staging" && cargo generate-lockfile --quiet -Zdirect-minimal-versions)
  cp "$staging/Cargo.lock" "$LOCK"
  rm -rf "$staging"
  echo "wrote $LOCK"
  exit 0
fi

# Cargo decides freshness by file dates, but stamps every packaged file with
# one fixed date. So the files are dated at extraction instead, and each
# distinct content keeps its directory: unchanged sources keep their dates,
# and changed ones postdate every earlier build.
cp "$LOCK" "$staging/Cargo.lock"
key="$(cd "$staging" && find . -type f ! -name .cargo_vcs_info.json -print0 |
  sort -z | xargs -0 sha256sum | sha256sum | cut -c1-16)"
SOURCE="$OUT/source-$key"
if [ -d "$SOURCE" ]; then
  rm -rf "$staging"
else
  mv "$staging" "$SOURCE"
fi
find "$OUT" -mindepth 1 -maxdepth 1 -name 'source-*' ! -name "source-$key" \
  -exec rm -rf {} +
cd "$SOURCE"

if [ "$mode" != test ]; then
  progress "fetching package-test dependencies"
  cargo fetch "${verbosity_args[@]}" --locked
fi

# Every dependency comes from crates.io: no path, Git or patched source.
packages="$(grep -c '^\[\[package\]\]$' Cargo.lock)"
registry="$(grep -c '^source = "registry+https://github.com/rust-lang/crates.io-index"$' Cargo.lock)"
[ "$registry" -eq $((packages - 1)) ] ||
  fail "$LOCK takes a dependency from outside crates.io"

# Each direct dependency is locked at the lowest version the manifest allows.
direct="$(cargo tree --locked --offline --target all -e normal,build,dev \
  --depth 1 --prefix none --format '{p}')" ||
  fail "$LOCK does not match moto-sdk's manifest; run $0 --update-lock"
checked=0
while read -r name requirement; do
  case "$requirement" in
    "" | *[!0-9.]*) fail "$name: cannot check requirement '$requirement'" ;;
    *.*.*) floor="$requirement" ;;
    *.*) floor="$requirement.0" ;;
    *) floor="$requirement.0.0" ;;
  esac
  printf '%s\n' "$direct" | grep -qxE "$name v${floor//./\\.}( \(proc-macro\))?" ||
    fail "$name is not locked at $floor, the lowest version allowed; run $0 --update-lock"
  checked=$((checked + 1))
done < <(awk '/^\[/ {
    dep = ""
    if (match($0, /dependencies\.[^]]+\]$/)) dep = substr($0, RSTART + 13, RLENGTH - 14)
  }
  dep != "" && /^version = / { v = $3; gsub(/"/, "", v); print dep, v; dep = "" }' Cargo.toml)
[ "$checked" -gt 0 ] || fail "found no dependency requirements in the packaged manifest"

test_args=()
[ "$mode" = test ] || test_args=(--no-run)
export CARGO_TARGET_DIR="$OUT/target"
progress "building host tests"
cargo test "${verbosity_args[@]}" --locked "${network_args[@]}" "${profile_args[@]}" "${test_args[@]}"
progress "building Motor OS tests"
cargo test "${verbosity_args[@]}" --locked "${network_args[@]}" "${profile_args[@]}" --target "$MOTOR" --no-run
progress "building Motor OS library with test-support"
cargo build "${verbosity_args[@]}" --locked "${network_args[@]}" "${profile_args[@]}" --target "$MOTOR" \
  --features test-support
progress "building Motor OS library without default features"
cargo build "${verbosity_args[@]}" --locked "${network_args[@]}" "${profile_args[@]}" --target "$MOTOR" \
  --no-default-features -Zbuild-std=core,alloc
if [ "$mode" = test ]; then
  echo "moto-sdk package PASS"
fi

)

host_tool_sizes() (
  [ "$BUILD" = release ] || return 0
  local assembly="$ROOT_DIR/build/assembly/images" imager="$ROOT_DIR/build/obj/release/imager/release/imager"
  local evidence variant overlay bytes_without bytes_with bytes
  check_size() {
    local label="$1" observed="$2" limit="$3"
    [[ "$observed" =~ ^[0-9]+$ ]] && [ "$observed" -le "$limit" ] || {
      echo "$label: observed=$observed bytes, approved maximum=$limit" >&2
      return 1
    }
  }
  for limit in 22020096 33554432 83886080 134217728; do
    check_size boundary "$((limit - 1))" "$limit"
    check_size boundary "$limit" "$limit"
    for bad in '' -1 not-a-number "$((limit + 1))"; do
      if check_size boundary "$bad" "$limit" 2>/dev/null; then
        cross_fail "size check accepted $bad with limit $limit"
      fi
    done
  done
  check_size rustfmt-binary "$(stat -c %s "$assembly/rustc/user/lib/rust/bin/rustfmt")" 22020096
  check_size analyzer-binary "$(stat -c %s "$assembly/rust-analyzer/user/lib/rust/bin/rust-analyzer")" 33554432
  bytes="$(find "$assembly/rust-analyzer/user/lib/rust/lib/rustlib/src/rust/library" -type f -printf '%s\n' |
    awk '{bytes += $1} END {printf "%.0f", bytes}')"
  check_size rust-src "$bytes" 83886080
  evidence="$(mktemp -d "$ROOT_DIR/build/tool-size.XXXXXX")"
  trap 'status=$?; if [ "$status" = 0 ]; then rm -r "$evidence"; else echo "Tool size evidence: $evidence" >&2; fi' EXIT
  # The input disks differ only by the measured tool. Hard links preserve all
  # other payload bytes without another compiler-tree copy.
  cp -al "$assembly" "$evidence/without-formatter"
  rm "$evidence/without-formatter/rustc/user/bin/dev/rustfmt" \
    "$evidence/without-formatter/rustc/user/lib/rust/bin/rustfmt"
  for variant in rustc analyzer without-formatter; do
    awk -v variant="$variant" -v destination="$evidence/$variant.qcow2" \
      -v policy="$ROOT_DIR/src/imager/motor-os-permissions.yaml" '
      /^permission_policy:/ {print "permission_policy: \"" policy "\""; next}
      /^img_name:/ {print "img_name: \"" destination "\""; next}
      /^assembly_dirs:/ {
        print; print "  - \"rustc\""
        if (variant == "analyzer") print "  - \"rust-analyzer\""
        next
      }
      {print}
    ' "$ROOT_DIR/src/imager/motor-os.yaml" > "$evidence/$variant.yaml"
    overlay="$assembly"
    [ "$variant" != without-formatter ] || overlay="$evidence/without-formatter"
    flock "$ROOT_DIR/build/imager.lock" env MOTOR_ASSEMBLY_IMAGE_ROOT="$overlay" \
      "$imager" "$ROOT_DIR" release "$evidence/$variant.yaml" > "$evidence/$variant.log" 2>&1
  done
  bytes_without="$(stat -c %s "$evidence/rustc.qcow2")"
  bytes_with="$(stat -c %s "$evidence/analyzer.qcow2")"
  check_size analyzer-qcow2-growth "$((bytes_with - bytes_without))" 134217728
  bytes_with="$bytes_without"
  bytes_without="$(stat -c %s "$evidence/without-formatter.qcow2")"
  check_size rustfmt-qcow2-growth "$((bytes_with - bytes_without))" 22020096
  echo 'tool size contracts: PASS'
)

host_full_options() (
  unset MOTO_SMP MOTO_MEMORY_MIB
  local value
  invalid() {
    local status=0
    (full_options "$@") > /dev/null 2>&1 || status=$?
    [ "$status" = 2 ] || cross_fail "accepted invalid full-test options: $*"
  }
  for value in '' 0 01 -1 abc; do
    invalid --cpus "$value"
    invalid --memory="$value"
    (export MOTO_SMP="$value"; invalid)
    (export MOTO_MEMORY_MIB="$value"; invalid)
  done
  for option in --cpus --memory --vmm; do invalid "$option"; done
  invalid --cpus 1 --cpus=2
  invalid --memory 256 --memory=512
  invalid --vmm qemu --vmm chv
  invalid --vmm unknown
  invalid --release=bogus
  invalid --all-debug=bogus
  invalid --release --all-debug
  invalid --all-debug --release
  full_options
  [ "$BUILD:$TEST_BUILD:${NATIVE_ARGS[*]}" = 'release:debug:' ]
  full_options --release
  [ "$CPUS:$MEMORY_MIB:$BUILD:$TEST_BUILD:${NATIVE_ARGS[*]}:$VMM" = '4:4096:release:release:--release:chv' ]
  full_options --all-debug
  [ "$BUILD:$TEST_BUILD:${PROFILE_ARGS[*]}:${NATIVE_ARGS[*]}" = 'debug:debug::' ]
  MOTO_SMP=2 MOTO_MEMORY_MIB=512 full_options --full --vmm qemu
  [ "$CPUS:$MEMORY_MIB:$FULL:$VMM" = '2:512:1:qemu' ]
  MOTO_SMP=bad MOTO_MEMORY_MIB=bad full_options --cpus=1 --memory 128
  [ "$CPUS:$MEMORY_MIB" = '1:128' ]
  echo 'full-test options: PASS'
)

full_check_installation() {
  local guest=/none/dev/toolchain-install
  local package="$guest/$1" VM_RUNTIME_DIR="$RUN_DIR/install-checks"
  local curl_version
  mkdir "$VM_RUNTIME_DIR"
  # An additional library exercises discovery, permissions, and stale-file
  # removal independently of the known compiler and tool library names.
  vm_ssh "/user/bin/mkdir -p $package/images/motor/user/lib/install-probe /user/lib/install-keep"
  vm_ssh "echo payload > $package/images/motor/user/lib/install-probe/data"
  vm_ssh "/user/bin/chmod rwxrw---- $package/images/motor/user/lib/install-probe/data"

  # The installer extends PATH in /user/cfg/profile only: the SSH configuration,
  # which holds the host key, stays byte for byte. Never print it on failure.
  vm_ssh '/user/bin/cat /user/cfg/sshd.toml' > "$VM_RUNTIME_DIR/sshd-before.toml"
  [ "$(vm_ssh /user/bin/printenv PATH)" = 'PATH=/user/bin' ] || cross_fail 'wrong SSH PATH before installation'
  check_ssh_config() {
    vm_ssh '/user/bin/cat /user/cfg/sshd.toml' > "$VM_RUNTIME_DIR/sshd-after.toml"
    cmp -s "$VM_RUNTIME_DIR/sshd-before.toml" "$VM_RUNTIME_DIR/sshd-after.toml" ||
      cross_fail 'installation changed the SSH configuration'
    [ "$(vm_ssh '/user/bin/cat /user/cfg/profile' | grep -cx '# Motor toolchain PATH')" = 1 ] ||
      cross_fail 'installation did not extend the profile PATH exactly once'
    # Each SSH session starts a login shell, so no reboot is needed.
    [ "$(vm_ssh /user/bin/printenv PATH)" = 'PATH=/user/bin:/user/bin/dev' ] ||
      cross_fail 'a new SSH session did not get the development PATH'
    if vm_ssh 'MOTOR_OS_CAPS=0x204 /user/bin/cat /user/cfg/sshd.toml' > /dev/null 2>&1; then
      cross_fail 'None can read the SSH configuration'
    fi
  }
  vm_ssh "$package/install.sh"
  check_ssh_config
  guest_mode /user/lib/install-probe/data -rwxrw-r--
  for source in hello.c hello.cpp hello.rs; do
    guest_mode "/none/dev/hello-world/$source" -rwxrw-rw-
  done
  # Reinstallation removes stale libraries and preserves local configuration.
  vm_ssh 'echo stale > /user/lib/llvm/stale-install && echo stale > /user/lib/rust/stale-install && echo stale > /user/lib/install-probe/stale-install'
  vm_ssh "/user/bin/rush -c 'echo \"# installer-preservation-probe\" >> /user/cfg/cargo/config.toml'"
  vm_ssh '/user/bin/chmod rwxr-xr-x /user/cfg/cargo && /user/bin/chmod rwxr-x--- /user/cfg/helix'
  vm_ssh "$package/install.sh"
  check_ssh_config
  guest_mode /user/cfg/cargo drwxr-xr-x
  guest_mode /user/cfg/helix drwxr-x---
  # Restore shared settings for the following None-role compiler/editor checks.
  vm_ssh '/user/bin/chmod rwxrwxr-x /user/cfg/cargo /user/cfg/helix'
  if ! vm_ssh '[ ! -e /user/lib/llvm/stale-install ] && [ ! -e /user/lib/rust/stale-install ] && [ ! -e /user/lib/install-probe/stale-install ]'; then
    cross_fail "install.sh left stale files in the toolchain directories"
  fi
  vm_ssh '[ -d /user/lib/install-keep ]' || cross_fail 'installation removed an unrelated library'
  vm_ssh '/user/bin/cat /user/cfg/cargo/config.toml' | grep -qx '# installer-preservation-probe' ||
    cross_fail "reinstallation replaced user configuration"

  # Replace an actual shipped command, including the immutable image-built case.
  printf 'put "%s" "%s/curl"\n' "$ROOT_DIR/build/bin/$BUILD/curl" "$guest" |
    vm_sftp > /dev/null
  vm_ssh "/user/bin/cp $guest/curl /user/bin/.curl-new &&
    /user/bin/chmod rwxrwxr-x /user/bin/.curl-new &&
    /user/bin/mv /user/bin/.curl-new /user/bin/curl"
  curl_version="$(vm_ssh /user/bin/curl --version)"
  case "$curl_version" in 'curl '*) ;; *) cross_fail 'replacement curl did not run' ;; esac
  vm_ssh "/user/bin/rm -r $guest"
}

host_unwind_elf() (
  local sysroot motor llvm mode profile target binary
  sysroot="$(cd "$ROOT_DIR" && rustc --print sysroot)"
  motor="$sysroot/lib/rustlib/x86_64-unknown-motor/sysroot"
  llvm="$sysroot/lib/rustlib/x86_64-unknown-linux-gnu/bin"
  local c_environment=("MOTOR_TEST_CXX=$motor/bin/motor-clang++"
    "MOTOR_TEST_AR=$llvm/llvm-ar" "MOTOR_TEST_CXX_LIB=$motor/user/lib/llvm/lib"
    "CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER=$motor/bin/motor-clang"
    'CARGO_TARGET_X86_64_UNKNOWN_MOTOR_RUSTFLAGS=-C link-self-contained=no -C default-linker-libraries=yes')
  cd "$ROOT_DIR/src/sys/tests/unwind"
  for mode in pure cxx; do
    target="$ROOT_DIR/build/unwind-$mode"
    for profile in release release-lto release-abort; do
      if [ "$mode" = pure ]; then
        cargo test --no-run --locked --offline --target x86_64-unknown-motor --profile "$profile" --target-dir "$target"
      else
        env "${c_environment[@]}" cargo test --no-run --locked --offline --features cxx \
          --target x86_64-unknown-motor --profile "$profile" --target-dir "$target"
      fi
      binary="$target/x86_64-unknown-motor/$profile/motor-unwind-test"
      if [ "$mode:$profile" = pure:release-abort ]; then
        "$ROOT_DIR/src/build-scripts/validate-native-elf.sh" "$binary"
      else
        "$ROOT_DIR/src/build-scripts/validate-native-elf.sh" "$binary" "$binary"
      fi
    done
  done
)

if [ "${BASH_SOURCE[0]}" = "$0" ]; then full_main "$@"; fi
