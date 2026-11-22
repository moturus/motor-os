#!/bin/bash
# Host/guest checks and VM ownership shared with full-test.sh.
set -euo pipefail

cross_fail() { echo "cross-test: $*" >&2; exit 1; }

cross_options() {
  ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  BUILD=debug
  VMM=chv
  CPUS="${MOTO_SMP-4}"
  MEMORY_MIB="${MOTO_MEMORY_MIB-1024}"
  CROSS_IMAGE=
  CROSS_IMAGE_EXPLICIT=0
  BENCHMARK=
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --release) BUILD=release; shift ;;
      --vmm|--image|--cpus|--memory|--benchmark)
        [ "$#" -ge 2 ] || cross_fail "$1 requires a value"
        case "$1" in
          --vmm) VMM="$2" ;;
          --image) CROSS_IMAGE="$(realpath -e -- "$2")"; CROSS_IMAGE_EXPLICIT=1 ;;
          --cpus) CPUS="$2" ;;
          --memory) MEMORY_MIB="$2" ;;
          --benchmark) BENCHMARK="$2" ;;
        esac
        shift 2 ;;
      *) cross_fail "unknown option: $1" ;;
    esac
  done
  case "$VMM" in qemu|chv|fc) ;; *) cross_fail "unsupported VMM: $VMM" ;; esac
  case "$BENCHMARK" in
    '') ;;
    physical|plain|wireguard) BUILD=release ;;
    *) cross_fail 'benchmark must be physical, plain, or wireguard' ;;
  esac
  for number in "$CPUS" "$MEMORY_MIB"; do
    case "$number" in ''|*[!0-9]*|0*) cross_fail 'CPU and memory values must be positive integers' ;; esac
  done
  export MOTO_SMP="$CPUS" MOTO_MEMORY_MIB="$MEMORY_MIB"
  if [ -z "$CROSS_IMAGE" ]; then
    CROSS_IMAGE="$ROOT_DIR/vm_images/$BUILD/motor-os.qcow2"
    [ "$VMM" != fc ] || CROSS_IMAGE="$ROOT_DIR/vm_images/$BUILD/motor-os.img"
  fi
}

cross_setup() {
  [ -f "$CROSS_IMAGE" ] || cross_fail "missing standard image: $CROSS_IMAGE"
  RUN_DIR="$(mktemp -d "$ROOT_DIR/build/cross-test-$BUILD.XXXXXX")"
  cp "$ROOT_DIR/src/vm_scripts/test.key" "$RUN_DIR/test.key"
  chmod 600 "$RUN_DIR/test.key"
  TEST_KEY="$RUN_DIR/test.key"
  ALT_TEST_KEY="$RUN_DIR/alternate.key"
  ssh-keygen -q -t ed25519 -N '' -f "$ALT_TEST_KEY"
  KNOWN_HOSTS="$RUN_DIR/known-hosts"
  printf '%s\n' '[192.168.4.2]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII4vmwh+7C/lNpLiI15zZOU8nl+jD/WcRBBUjL54uT3T' > "$KNOWN_HOSTS"
  SSH_OPTIONS=(-F /dev/null -p 2222 -o IdentitiesOnly=yes -o BatchMode=yes
    -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN_HOSTS" -i "$TEST_KEY")
  SFTP_OPTIONS=(-F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes
    -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN_HOSTS" -i "$TEST_KEY")
  VMM_PID=
  VM_CHILD_PID=
  VM_SERIAL_FD=
  VM_BOOT_COUNT=0
  CROSS_BACKEND_PID=
  CROSS_PEER_PID=
  CROSS_KEY_SOCKETS=()
  CROSS_KEY_LOGINS=()
  CROSS_KEY_DIR=
  trap cross_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

vm_ssh() { ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2 "$@"; }
vm_sftp() { sftp "${SFTP_OPTIONS[@]}" -b - motor@192.168.4.2; }

copy_test_image() {
  local source="$1" name="$2"
  VM_DIR="$RUN_DIR/$name"
  mkdir "$VM_DIR"
  cp "$ROOT_DIR/src/vm_scripts/"*.sh "$VM_DIR/"
  cp "$ROOT_DIR/vm_images/$BUILD/kloader" "$ROOT_DIR/vm_images/$BUILD/initrd" "$VM_DIR/"
  MOTO_IMAGE="${source##*/}"
  cp --reflink=auto --sparse=always "$source" "$VM_DIR/$MOTO_IMAGE"
  export MOTO_IMAGE
}

filter_vm_console() {
  LC_ALL=C sed -u -e $'s/\033\\[6n//g' -e $'s/\033\\[18t//g' \
    -e $'s/\033\\[?2048$p//g' -e $'s/\033\\[?2048h//g' -e $'s/\033\\[?2048l//g'
}

boot_test_image() {
  local name="$1" command pid_file
  shift
  [ -z "$VMM_PID" ] || cross_fail 'a VM is already running'
  CONSOLE_LOG="$RUN_DIR/$name.console.log"
  # Unix socket paths cannot accommodate the longer rejection-case names.
  VM_BOOT_COUNT=$((VM_BOOT_COUNT + 1))
  export MOTO_CHV_RUNTIME_DIR="$RUN_DIR/chv-$VM_BOOT_COUNT"
  export MOTO_FC_RUNTIME_DIR="$RUN_DIR/fc-$VM_BOOT_COUNT"
  mkfifo "$RUN_DIR/$name.stdin"
  exec {VM_SERIAL_FD}<> "$RUN_DIR/$name.stdin"
  if [ "$VMM" = chv ]; then
    # A rejected guest can exit between host polls. Have the PTY child record
    # its PID before exec so the caller can still check its console and status.
    pid_file="$MOTO_CHV_RUNTIME_DIR.pid"
    printf -v command '%q ' "$VM_DIR/run-$VMM.sh" "$@"
    printf -v command 'echo $$ > %q && exec %s' "$pid_file" "$command"
    script -qef -E never -c "$command" /dev/null <&"$VM_SERIAL_FD" > "$CONSOLE_LOG" 2>&1 &
    VMM_PID=$!
    for _ in $(seq 1 100); do
      [ ! -s "$pid_file" ] && kill -0 "$VMM_PID" 2>/dev/null || break
      sleep 0.1
    done
    [ -s "$pid_file" ] && read -r VM_CHILD_PID < "$pid_file" ||
      cross_fail "CHV wrapper did not report its child; see $CONSOLE_LOG"
  else
    "$VM_DIR/run-$VMM.sh" "$@" <&"$VM_SERIAL_FD" > "$CONSOLE_LOG" 2>&1 &
    VMM_PID=$!
  fi
}

vm_alive() {
  kill -0 "$VMM_PID" 2>/dev/null || return 1
  [ -z "$VM_CHILD_PID" ] || kill -0 "$VM_CHILD_PID" 2>/dev/null
}

wait_vm_ssh() {
  local deadline=$((SECONDS + 120))
  until ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=5 -o ConnectionAttempts=1 \
      motor@192.168.4.2 /user/bin/rush -c true >/dev/null 2>&1; do
    vm_alive || { cat "$CONSOLE_LOG" >&2; cross_fail 'VM exited before SSH was ready'; }
    [ "$SECONDS" -lt "$deadline" ] || cross_fail "SSH was not ready; see $CONSOLE_LOG"
    sleep 1
  done
  vm_alive || cross_fail 'SSH reached a VM other than the owned process'
}

wait_vm_exit() {
  local seconds="$1" deadline=$((SECONDS + $1))
  while kill -0 "$VMM_PID" 2>/dev/null; do
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 0.1
  done
}

shutdown_test_image() {
  vm_ssh shutdown
  finish_test_image 20
}

finish_test_image() {
  local status=0
  wait_vm_exit "$1" || cross_fail "VM did not shut down; see $CONSOLE_LOG"
  wait "$VMM_PID" || status=$?
  VMM_PID=
  if [ -n "$VM_CHILD_PID" ]; then
    ! kill -0 "$VM_CHILD_PID" 2>/dev/null || cross_fail 'VMM child survived shutdown'
    VM_CHILD_PID=
  fi
  exec {VM_SERIAL_FD}>&-
  VM_SERIAL_FD=
  case "${2:-shutdown}:$VMM:$status" in
    shutdown:qemu:33|shutdown:chv:0|shutdown:fc:0|stopped:*:0|stopped:*:143) ;;
    *) cross_fail "unexpected $VMM shutdown status: $status" ;;
  esac
}

# Ends the logins the sshd keys checks left pending and the sessions they hold
# open: with its VM gone, an ssh client would wait for hours. The sockets are
# in a directory outside the run's own, where a socket's path would be too long.
close_sshd_key_sessions() {
  local login socket
  for login in "${CROSS_KEY_LOGINS[@]}"; do
    kill "${login##*:}" 2>/dev/null || true
    wait "${login##*:}" 2>/dev/null || true
  done
  CROSS_KEY_LOGINS=()
  for socket in "${CROSS_KEY_SOCKETS[@]}"; do
    ssh "${SSH_OPTIONS[@]}" -S "$socket" -O exit motor@192.168.4.2 >/dev/null 2>&1 || true
  done
  CROSS_KEY_SOCKETS=()
  [ -z "$CROSS_KEY_DIR" ] || rm -r -- "$CROSS_KEY_DIR"
  CROSS_KEY_DIR=
}

cross_cleanup() {
  local status=$? signal_pid
  trap - EXIT
  set +e
  close_sshd_key_sessions
  for signal_pid in "${CROSS_PEER_PID:-}" "${CROSS_BACKEND_PID:-}"; do
    if [ -n "$signal_pid" ]; then
      kill "$signal_pid" 2>/dev/null
      wait "$signal_pid"
    fi
  done
  if [ -n "$VMM_PID" ]; then
    signal_pid="${VM_CHILD_PID:-$VMM_PID}"
    kill "$signal_pid" 2>/dev/null
    if ! wait_vm_exit 10; then
      kill -KILL "$signal_pid" 2>/dev/null
    fi
    wait "$VMM_PID"
    [ -z "$VM_CHILD_PID" ] || ! kill -0 "$VM_CHILD_PID" 2>/dev/null || status=1
  fi
  [ -z "$VM_SERIAL_FD" ] || exec {VM_SERIAL_FD}>&-
  if [ "$status" = 0 ]; then rm -rf -- "$RUN_DIR"; else echo "Test evidence retained: $RUN_DIR" >&2; fi
  exit "$status"
}

prepare_identity_workspace() {
  IDENTITY="$RUN_DIR/identity"
  mkdir -p "$IDENTITY"/{app/src,app/tests,second/src,shared/src,.cargo}
  cat > "$IDENTITY/Cargo.toml" <<'EOF'
[workspace]
members = ["app", "second", "shared"]
default-members = ["app", "second"]
resolver = "2"
[profile.release]
panic = "abort"
lto = "fat"
strip = true
codegen-units = 1
EOF
  cat > "$IDENTITY/Cargo.lock" <<'EOF'
version = 4
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["shared"]
[[package]]
name = "second"
version = "0.1.0"
dependencies = ["shared"]
[[package]]
name = "shared"
version = "0.1.0"
EOF
  local member feature
  for member in app second shared; do
    printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2024"\n' "$member" > "$IDENTITY/$member/Cargo.toml"
  done
  for member in app second; do
    feature=red
    [ "$member" != second ] || feature=blue
    printf '[dependencies]\nshared = { path = "../shared", features = ["%s"] }\n' "$feature" >> "$IDENTITY/$member/Cargo.toml"
  done
  printf '[features]\nred = []\nblue = []\n' >> "$IDENTITY/shared/Cargo.toml"
  cat > "$IDENTITY/shared/src/lib.rs" <<'EOF'
pub fn source() -> &'static str { file!() }
pub fn features() -> (bool, bool) { (cfg!(feature = "red"), cfg!(feature = "blue")) }
EOF
  printf "pub fn source() -> &'static str { file!() }\n" > "$IDENTITY/app/src/lib.rs"
  cat > "$IDENTITY/app/src/main.rs" <<'EOF'
fn main() { println!("{} {} {}", file!(), app::source(), shared::source()); }
EOF
  cat > "$IDENTITY/second/src/main.rs" <<'EOF'
fn main() {
    let (red, blue) = shared::features();
    println!("{} {} {red} {blue}", file!(), shared::source());
}
EOF
  cat > "$IDENTITY/app/tests/integration.rs" <<'EOF'
#[test]
fn library_source_is_workspace_relative() { assert_eq!(app::source(), "app/src/lib.rs"); }
EOF
  cat > "$IDENTITY/.cargo/config.toml" <<'EOF'
[target.x86_64-unknown-motor]
rustflags = ["-Clink-self-contained=no", "-Cdefault-linker-libraries=yes"]
EOF
  mkdir -p "$RUN_DIR/identity-home/.config/lorry"
  printf 'config-version = 1\nuse-cargo-registry = false\n[cache]\ndirectory = "%s/identity-cache"\n' "$RUN_DIR" \
    > "$RUN_DIR/identity-home/.config/lorry/lorry.toml"
  IDENTITY_RUSTC="$(cd "$ROOT_DIR" && rustup which rustc)"
  IDENTITY_RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
  IDENTITY_LORRY="$ROOT_DIR/src/bin/lorry/target/release/lorry"
}

identity_lorry() {
  env HOME="$RUN_DIR/identity-home" RUSTUP_HOME="$IDENTITY_RUSTUP_HOME" \
    RUSTC="$IDENTITY_RUSTC" "$IDENTITY_LORRY" "$@"
}

identity_selection() {
  case "$1" in
    default) IDENTITY_SELECTION=() ;;
    packages) IDENTITY_SELECTION=(-p app -p second) ;;
    all) IDENTITY_SELECTION=(--workspace) ;;
    exclude) IDENTITY_SELECTION=(--workspace --exclude second) ;;
  esac
}

test_host_identity() (
  local platform selection member suffix
  local target_args=()
  cd "$IDENTITY"
  export CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER
  CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER="$("$IDENTITY_RUSTC" --print sysroot)/lib/rustlib/x86_64-unknown-motor/sysroot/bin/motor-clang"
  identity_lorry vendor --locked --offline --workspace --accept-all
  for platform in linux motor; do
    target_args=()
    suffix=release
    if [ "$platform" = motor ]; then
      target_args=(--target x86_64-unknown-motor)
      suffix=x86_64-unknown-motor/release
    fi
    for selection in default packages all exclude; do
      identity_selection "$selection"
      cargo build --release --locked --offline "${target_args[@]}" "${IDENTITY_SELECTION[@]}" --target-dir "$RUN_DIR/identity-cargo-$platform"
      identity_lorry build --release --locked --offline "${target_args[@]}" "${IDENTITY_SELECTION[@]}" --target-dir "$RUN_DIR/identity-lorry-$platform"
      for member in app second; do
        if [ "$selection" = exclude ] && [ "$member" = second ]; then continue; fi
        cmp "$RUN_DIR/identity-cargo-$platform/$suffix/$member" \
          "$RUN_DIR/identity-lorry-$platform/lorry/$suffix/$member"
        cp "$RUN_DIR/identity-cargo-$platform/$suffix/$member" "$RUN_DIR/identity-$platform-$selection-$member"
      done
    done
  done
)

test_guest_identity() {
  if [ "$VMM" = fc ]; then
    echo 'SKIP Firecracker: guest Lorry/Cargo byte comparison (development tools unavailable)'
    return
  fi
  local guest=/none/dev/cargo-identity selection member arguments
  vm_ssh "MOTOR_OS_CAPS=0x204 mkdir -p $guest"
  tar -C "$IDENTITY" -cf - Cargo.toml Cargo.lock .cargo app second shared |
    vm_ssh "MOTOR_OS_CAPS=0x204 tar -xf - -C $guest"
  vm_ssh "cd $guest && /user/bin/dev/lorry vendor --locked --offline --workspace --accept-all"
  for selection in default packages all exclude; do
    identity_selection "$selection"
    arguments="${IDENTITY_SELECTION[*]}"
    vm_ssh "cd $guest && /user/bin/dev/lorry build --release --locked --offline --target x86_64-unknown-motor $arguments"
    for member in app second; do
      if [ "$selection" = exclude ] && [ "$member" = second ]; then continue; fi
      printf 'get "%s/target/lorry/x86_64-unknown-motor/release/%s" "%s/identity-native-%s"\n' "$guest" "$member" "$RUN_DIR" "$member" | vm_sftp
      cmp "$RUN_DIR/identity-motor-$selection-$member" "$RUN_DIR/identity-native-$member"
    done
  done
  vm_ssh "$guest/target/lorry/x86_64-unknown-motor/release/second" > "$RUN_DIR/identity-features"
  [ "$(cat "$RUN_DIR/identity-features")" = 'second/src/main.rs shared/src/lib.rs true true' ] ||
    cross_fail 'workspace feature unification changed'
  vm_ssh "rm -r $guest"
}
# Locate the vhost-device-vsock backend that QEMU's vsock device needs, and
# install it once when the host has none. It is a test dependency, not a part
# of the toolchain build. Sourced by the vsock harnesses. Not executable.

VSOCK_BACKEND_VERSION=0.3.0
VSOCK_BACKEND_INSTALL=(cargo install --locked --version "$VSOCK_BACKEND_VERSION" vhost-device-vsock)
# Cargo runs in the checkout, where rustup selects the Motor host toolchain.
VSOCK_BACKEND_CHECKOUT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Tell the user how to obtain the backend after a failed lookup.
vsock_backend_hint() {
  echo "vsock-backend: install it from the checkout (needs network access):" >&2
  echo "  ${VSOCK_BACKEND_INSTALL[*]}" >&2
}

# Set VHOST_DEVICE_VSOCK to an installed backend of the pinned version. The
# caller's own VHOST_DEVICE_VSOCK wins, and is never replaced by one on PATH.
resolve_vsock_backend() {
  local version
  if [ -z "${VHOST_DEVICE_VSOCK:-}" ]; then
    VHOST_DEVICE_VSOCK="$(command -v vhost-device-vsock || true)"
    [ -n "$VHOST_DEVICE_VSOCK" ] || {
      echo "vsock-backend: vhost-device-vsock is not installed (it is not on PATH)" >&2
      vsock_backend_hint
      return 1
    }
  fi
  command -v "$VHOST_DEVICE_VSOCK" >/dev/null 2>&1 || {
    echo "vsock-backend: VHOST_DEVICE_VSOCK is not an executable: $VHOST_DEVICE_VSOCK" >&2
    vsock_backend_hint
    return 1
  }
  version="$("$VHOST_DEVICE_VSOCK" --version)"
  [ "$version" = "vhost-device-vsock $VSOCK_BACKEND_VERSION" ] || {
    echo "vsock-backend: expected vhost-device-vsock $VSOCK_BACKEND_VERSION, got '$version' from $VHOST_DEVICE_VSOCK" >&2
    vsock_backend_hint
    return 1
  }
}

# Resolve the backend for a vsock harness. A host without one gets the pinned
# version installed first, once; a caller's own VHOST_DEVICE_VSOCK is only checked.
ensure_vsock_backend() {
  if [ -z "${VHOST_DEVICE_VSOCK:-}" ] && ! (resolve_vsock_backend) >/dev/null 2>&1; then
    echo "vsock-backend: installing vhost-device-vsock $VSOCK_BACKEND_VERSION" >&2
    (cd "$VSOCK_BACKEND_CHECKOUT" && "${VSOCK_BACKEND_INSTALL[@]}") || {
      echo "vsock-backend: cargo could not install vhost-device-vsock $VSOCK_BACKEND_VERSION" >&2
      return 1
    }
  fi
  resolve_vsock_backend
}

check_guest_image_layout() (
  remote() { vm_ssh "$@"; }
  root_entries="$(vm_ssh '/user/bin/ls -al /' | awk '{ print $NF }')"
  [ "$root_entries" = "$(printf 'none\nsystem\nuser')" ] ||
    cross_fail "unexpected image root: $root_entries"
  fail() { echo "test-image-layout: $*" >&2; exit 1; }
  denied() {
    if remote "$@" > /dev/null 2>&1; then
      fail "unexpected success: $*"
    fi
  }
  mode() {
    local path="$1" expected="$2" actual
    actual="$(remote "/user/bin/ls -l ${path%/*}" | awk -v name="${path##*/}" '$NF == name { print $1 }')"
    [ "$actual" = "$expected" ] || fail "$path has mode '$actual', expected '$expected'"
  }
  
  remote '[ ! -e /system/bin ]'
  remote '/user/bin/rush -c "echo migrated-shell"' | grep -qx migrated-shell
  mode /user/bin drwxrwxr-x
  mode /user/bin/rush -r-xr-xr-x
  mode /user/bin/sh -rwxrwxr-x
  mode /none/dev drwxrwxrwx
  mode /user/cfg drwxrwxr-x
  mode /user/cfg/profile -rwxrw-r--
  mode /user/cfg/rush.toml -rwxrw-r--
  mode /user/cfg/sshd.toml -rwxrw----
  for path in /user/cfg/profile /user/cfg/rush.toml; do
    remote "MOTOR_OS_CAPS=0x204 /user/bin/cat $path" > /dev/null
    # Opening a readable file alone need not check write access; send bytes.
    denied "MOTOR_OS_CAPS=0x204 /user/bin/rush -c 'echo denied >>$path'"
  done
  for path in /user/cfg/sshd.toml /user/cfg/russhd/users.toml /user/cfg/ssh/authorized_keys.motor; do
    denied "MOTOR_OS_CAPS=0x204 /user/bin/cat $path"
  done
  for path in /system /user /user/bin /user/cfg; do
    denied "MOTOR_OS_CAPS=0x204 /user/bin/mkdir $path/.image-layout-denied"
  done
  remote 'MOTOR_OS_CAPS=0x204 /user/bin/mkdir /none/.image-layout-none && MOTOR_OS_CAPS=0x204 /user/bin/rmdir /none/.image-layout-none'
  remote '[ ! -e /system/cfg/profile ] && [ ! -e /user/cfg/rush.cfg ] && [ ! -e /system/cfg/sshd.toml ]'
  
  # An Interactive installer can replace its own prior output. The shipped ELF
  # remains immutable; a copied ELF and script use the runtime installation modes.
  probe=/user/bin/.image-layout-probe
  data=/user/cfg/.image-layout-data
  directory=/user/bin/.image-layout-directory
  cleanup() {
    local status=$? path
    for path in "$probe" "$probe.tmp" "$data"; do
      remote "if [ -e $path ]; then /user/bin/rm $path; fi" || status=1
    done
    remote "if [ -d $directory ]; then /user/bin/rmdir $directory; fi" || status=1
    exit "$status"
  }
  remote "[ ! -e $probe ] && [ ! -e $probe.tmp ] && [ ! -e $data ] && [ ! -e $directory ]"
  trap cleanup EXIT
  remote "/user/bin/mkdir $directory"
  mode "$directory" drwxrwxr-x
  remote "MOTOR_OS_CAPS=0x204 /user/bin/ls $directory" > /dev/null
  denied "MOTOR_OS_CAPS=0x204 /user/bin/mkdir $directory/denied"
  for pass in 1 2; do
    remote "/user/bin/cp /user/bin/sysbox $probe.tmp && /user/bin/chmod rwxrwxr-x $probe.tmp && /user/bin/mv $probe.tmp $probe"
    mode "$probe" -rwxrwxr-x
    remote "MOTOR_OS_CAPS=0x204 $probe echo installed-elf" | grep -qx installed-elf
    denied "MOTOR_OS_CAPS=0x204 /user/bin/rush -c 'echo denied >>$probe'"
  done
  remote "/user/bin/rm $probe && /user/bin/cp /user/bin/echo $probe.tmp && /user/bin/chmod rwxr-xr-x $probe.tmp && /user/bin/chmod rwxrwxr-x $probe.tmp && /user/bin/mv $probe.tmp $probe"
  mode "$probe" -rwxrwxr-x
  remote "MOTOR_OS_CAPS=0x204 $probe installed-script" | grep -qx installed-script
  remote "/user/bin/cp /user/cfg/rush.toml $data && /user/bin/chmod rwxrw-r-- $data"
  mode "$data" -rwxrw-r--
  remote "MOTOR_OS_CAPS=0x204 /user/bin/cat $data" > /dev/null
  denied "MOTOR_OS_CAPS=0x204 /user/bin/rush -c 'echo denied >>$data'"
  
  if remote '[ -e /user/bin/dev/lorry ]'; then
    mode /user/bin/dev drwxrwxr-x
    mode /user/lib drwxrwxr-x
    mode /user/cfg/lorry.toml -rwxrw-r--
    mode /user/cfg/helix drwxrwxr-x
    mode /user/cfg/helix/languages.toml -rwxrw-r--
    for path in /user/cfg/lorry.toml /user/cfg/helix/languages.toml; do
      remote "MOTOR_OS_CAPS=0x204 /user/bin/cat $path" > /dev/null
      denied "MOTOR_OS_CAPS=0x204 /user/bin/rush -c 'echo denied >>$path'"
    done
    remote '[ ! -e /devtools/src ] && [ ! -e /devtools/lorry ] && [ -f /user/lib/imager/imager ]'
    for tool in lorry gix mdbg sed lua www hx javy wasmi wasmtime wasmtime-rt qjs qjsc; do
      remote "[ -x /user/bin/dev/$tool ] && [ ! -e /devtools/bin/$tool ]"
    done
  fi
  echo "test-image-layout PASS"
)

guest_mode() {
  local path="$1" expected="$2" actual
  actual="$(vm_ssh "/user/bin/ls -l ${path%/*}" | awk -v name="${path##*/}" '$NF == name { print $1 }')"
  [ "$actual" = "$expected" ] || cross_fail "$path has mode '$actual', expected '$expected'"
}

check_installed_tools() {
  [ "$(vm_ssh /user/bin/printenv PATH)" = 'PATH=/user/bin:/user/bin/dev' ] || cross_fail 'SSH PATH was not extended once'
  [ "$(vm_ssh rustc --print sysroot)" = /user/lib/rust ] || cross_fail 'wrong native Rust sysroot'
  local path command host_sysroot
  for path in /user/bin/curl /user/bin/dev/ar /user/bin/dev/lorry /user/bin/dev/rustc \
      /user/bin/dev/rust-analyzer /user/lib/llvm/bin/llvm /user/lib/rust/bin/rustc /user/lib/helix/hx; do
    guest_mode "$path" -rwxrwxr-x
    if vm_ssh "MOTOR_OS_CAPS=0x204 /user/bin/rush -c 'echo denied >>$path'" >/dev/null 2>&1; then
      cross_fail "None can write $path"
    fi
  done
  guest_mode /user/cfg/cargo/config.toml -rwxrw-r--
  guest_mode /user/lib/llvm/include/stdio.h -rwxrw-r--
  guest_mode /none/dev/hello-world drwxrwxrwx
  guest_mode /none/dev/hello-world/hello.rs -rwxrw-rw-
  vm_ssh 'MOTOR_OS_CAPS=0x204 /user/bin/cat /user/cfg/cargo/config.toml' >/dev/null
  host_sysroot="$(cd "$ROOT_DIR" && rustc --print sysroot)"
  for command in rustfmt rust-analyzer; do
    [ "$(vm_ssh /user/bin/dev/$command --version)" = "$("$host_sysroot/bin/$command" --version)" ] ||
      cross_fail "$command version differs from the selected host toolchain"
  done
}

# Private moto-tap SSH compatibility cases for the Motor client.

SSH_CLIENT_HOST_PROCESS=""
SSH_CLIENT_HOST_OUTPUT_FD=""
SSH_CLIENT_HOST_BASE=""
SSH_CLIENT_HOST_ROOT=""
SSH_CLIENT_HOST_PORT=""
SSH_CLIENT_HOST_PUBLIC_KEY=""
SSH_CLIENT_HOST_IDENTITY_INSTALLED=0
SSH_CLIENT_HOST_GUEST_KEY=/user/cfg/ssh/id_ed25519
SSH_CLIENT_HOST_GUEST_KNOWN=/user/cfg/ssh/known_hosts

stop_ssh_client_host() {
  if [ -n "$SSH_CLIENT_HOST_PROCESS" ]; then
    kill "$SSH_CLIENT_HOST_PROCESS" 2>/dev/null || true
    wait "$SSH_CLIENT_HOST_PROCESS" 2>/dev/null || true
    SSH_CLIENT_HOST_PROCESS=""
  fi
  if [ -n "$SSH_CLIENT_HOST_OUTPUT_FD" ]; then
    local output_fd="$SSH_CLIENT_HOST_OUTPUT_FD"
    exec {output_fd}<&-
    SSH_CLIENT_HOST_OUTPUT_FD=""
  fi
}

remove_ssh_client_host_identity() {
  local status=0 guest_file
  if [ "$SSH_CLIENT_HOST_IDENTITY_INSTALLED" -eq 1 ]; then
    for guest_file in "$SSH_CLIENT_HOST_GUEST_KEY" \
      "$SSH_CLIENT_HOST_GUEST_KEY.pub" "$SSH_CLIENT_HOST_GUEST_KNOWN"; do
      vm_ssh "/user/bin/rm $guest_file" >/dev/null || status=1
    done
    [ "$status" -ne 0 ] || SSH_CLIENT_HOST_IDENTITY_INSTALLED=0
  fi
  return "$status"
}

cleanup_ssh_client_host() {
  stop_ssh_client_host
  remove_ssh_client_host_identity >/dev/null 2>&1 || true
  if [ -n "$SSH_CLIENT_HOST_ROOT" ]; then
    case "$SSH_CLIENT_HOST_ROOT" in
      "$SSH_CLIENT_HOST_BASE"/ssh-client-host.*)
        rm -rf "$SSH_CLIENT_HOST_ROOT"
        ;;
      *)
        printf 'refusing to remove unexpected SSH fixture path: %s\n' \
          "$SSH_CLIENT_HOST_ROOT" >&2
        ;;
    esac
    SSH_CLIENT_HOST_ROOT=""
  fi
}

prepare_ssh_client_host() {
  local host_key="$1" public_file repo_root guest_file
  repo_root="$(cd "$ROOT_DIR" && pwd)"
  SSH_CLIENT_HOST_BASE="$repo_root/build/host-tests"
  mkdir -p "$SSH_CLIENT_HOST_BASE"
  SSH_CLIENT_HOST_ROOT="$(mktemp -d "$SSH_CLIENT_HOST_BASE/ssh-client-host.XXXXXX")"
  public_file="$SSH_CLIENT_HOST_ROOT/id_ed25519.pub"
  SSH_CLIENT_HOST_PUBLIC_KEY="$(ssh-keygen -y -f "$host_key")"
  printf '%s\n' "$SSH_CLIENT_HOST_PUBLIC_KEY" > "$public_file"

  SSH_CLIENT_HOST_IDENTITY_INSTALLED=1
  for guest_file in "$SSH_CLIENT_HOST_GUEST_KEY" \
    "$SSH_CLIENT_HOST_GUEST_KEY.pub" "$SSH_CLIENT_HOST_GUEST_KNOWN"; do
    vm_ssh "/user/bin/rm $guest_file" >/dev/null 2>&1 || true
  done
  printf 'put %s %s\nchmod 600 %s\nput %s %s\nchmod 644 %s\n' \
    "$host_key" "$SSH_CLIENT_HOST_GUEST_KEY" "$SSH_CLIENT_HOST_GUEST_KEY" \
    "$public_file" "$SSH_CLIENT_HOST_GUEST_KEY.pub" "$SSH_CLIENT_HOST_GUEST_KEY.pub" |
    sftp -b - -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
      -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS" \
      -i "$TEST_KEY" motor@192.168.4.2 >/dev/null
}

trust_ssh_client_host() {
  local port="$1" host=192.168.4.1 output known
  output="$(vm_ssh "/user/bin/ssh -F /dev/null -p $port -o BatchMode=yes -o StrictHostKeyChecking=accept-new motor@$host /bin/echo unknown-ok")" ||
    fail "Motor client rejected an unknown host under accept-new"
  [ "$output" = unknown-ok ] || fail "unknown-host command returned '$output'"
  output="$(vm_ssh "/user/bin/ssh -F /dev/null -p $port -o BatchMode=yes -o StrictHostKeyChecking=yes motor@$host /bin/echo matching-ok")" ||
    fail "Motor client rejected its recorded host key"
  [ "$output" = matching-ok ] || fail "matching-host command returned '$output'"
  known="$(vm_ssh /user/bin/cat "$SSH_CLIENT_HOST_GUEST_KNOWN")"
  [ "$known" = "[$host]:$port $SSH_CLIENT_HOST_PUBLIC_KEY" ] ||
    fail "known_hosts contains an unexpected record: '$known'"
}

write_ssh_client_host_config() {
  local path="$1"
  local address="$2"
  local host_key="$3"
  local credentials="$SSH_CLIENT_HOST_ROOT/credentials"
  mkdir -m 700 -p "$credentials"
  {
    printf "version = 2\nlisten_on = '%s'\n" "$address"
    printf 'allow_tcp_forwarding = true\n'
    printf 'host_key = """%s"""\n\n' "$(cat "$host_key")"
    printf "users_file = '%s'\nauthorized_keys_dir = '%s'\n" \
      "$credentials/users.toml" "$credentials"
  } > "$path"
  (umask 077
    cp "$ROOT_DIR/img_files/motor-os-base/user/cfg/russhd/users.toml" "$credentials/users.toml"
    cp "$ROOT_DIR/img_files/motor-os-base/user/cfg/ssh/authorized_keys.motor" \
      "$credentials/authorized_keys.motor")
}

start_ssh_client_host() {
  local host_key="$1"
  local requested_port="$2"
  local command_path="${3:-/bin:/usr/bin}"
  local listen_host="${4:-192.168.4.1}"
  local repo_root
  repo_root="$(cd "$ROOT_DIR" && pwd)"
  local host_bin="$repo_root/src/bin/russhd/target/$BUILD/russhd"
  local config="$SSH_CLIENT_HOST_ROOT/sshd.toml"
  local input_fd
  local startup_log=""
  local deadline

  [ -x "$host_bin" ] || fail "host russhd is missing at $host_bin"
  write_ssh_client_host_config "$config" "$listen_host:$requested_port" "$host_key"
  coproc SSH_CLIENT_HOST_SERVER {
    cd "$SSH_CLIENT_HOST_ROOT"
    # Linux SSH sessions inherit PATH, including the Git helpers in the gix test.
    exec env HOME="$SSH_CLIENT_HOST_ROOT" PATH="$command_path" "$host_bin" "$config" </dev/null 2>&1
  }
  SSH_CLIENT_HOST_PROCESS="$SSH_CLIENT_HOST_SERVER_PID"
  exec {SSH_CLIENT_HOST_OUTPUT_FD}<&"${SSH_CLIENT_HOST_SERVER[0]}"
  input_fd="${SSH_CLIENT_HOST_SERVER[1]}"
  exec {input_fd}>&-

  SSH_CLIENT_HOST_PORT=""
  deadline=$((SECONDS + 5))
  while [ "$SECONDS" -lt "$deadline" ]; do
    local remaining=$((deadline - SECONDS))
    local line
    if ! IFS= read -r -t "$remaining" line <&"$SSH_CLIENT_HOST_OUTPUT_FD"; then
      break
    fi
    startup_log="$startup_log$line
"
    case "$line" in
      *"Listening on "*)
        local address="${line##*Listening on }"
        SSH_CLIENT_HOST_PORT="${address##*:}"
        break
        ;;
    esac
  done
  case "$SSH_CLIENT_HOST_PORT" in
    ""|*[!0-9]*)
      printf '%s' "$startup_log" >&2
      stop_ssh_client_host
      fail "host russhd did not report a valid listening address"
      ;;
  esac
  if [ "$requested_port" != 0 ] && [ "$SSH_CLIENT_HOST_PORT" != "$requested_port" ]; then
    stop_ssh_client_host
    fail "host russhd listened on $SSH_CLIENT_HOST_PORT, expected $requested_port"
  fi
}

test_ssh_client_host() {
  local guest_key=/user/cfg/ssh/id_ed25519
  local guest_wrong=/user/cfg/ssh/wrong_ed25519
  local guest_known=/user/cfg/ssh/known_hosts
  local guest_executable="$TEST_TMP/ssh-client-host-executable"
  local guest_transfer_root="$TEST_TMP/ssh-client-host-transfer"
  local host=192.168.4.1
  local first_key="$TEST_KEY"
  local second_key="$ALT_TEST_KEY"
  local public_key
  local known
  local output
  local port
  local guest_file

  echo "-- Motor SSH client private-network compatibility --"
  prepare_ssh_client_host "$first_key"
  public_key="$SSH_CLIENT_HOST_PUBLIC_KEY"
  for guest_file in "$guest_wrong" "$guest_executable"; do
    vm_ssh "/user/bin/rm $guest_file" >/dev/null 2>&1 || true
  done
  vm_ssh "/user/bin/rm -r $guest_transfer_root" >/dev/null 2>&1 || true
  printf 'put %s %s\nchmod 600 %s\n' "$second_key" "$guest_wrong" "$guest_wrong" |
    sftp -b - -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
      -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS" \
      -i "$TEST_KEY" motor@192.168.4.2 >/dev/null

  start_ssh_client_host "$first_key" 0
  port="$SSH_CLIENT_HOST_PORT"
  trust_ssh_client_host "$port"
  known="$(vm_ssh /user/bin/cat "$guest_known")"

  local host_executable="$SSH_CLIENT_HOST_ROOT/executable"
  local returned_executable="$SSH_CLIENT_HOST_ROOT/returned-executable"
  printf '#!/bin/sh\necho executable-download\n' > "$host_executable"
  chmod 755 "$host_executable"
  local native_scp="/user/bin/scp -P $port -i $guest_key -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$guest_known"
  vm_ssh "$native_scp motor@$host:$host_executable $guest_executable" ||
    fail "Motor client could not download a 0755 Unix file"
  vm_ssh "$native_scp $guest_executable motor@$host:$returned_executable" ||
    fail "Motor client could not return the downloaded executable"
  [ "$(stat -c %a "$returned_executable")" = 555 ] ||
    fail "Motor client did not normalize a downloaded 0755 file to 0555"
  chmod 600 "$returned_executable"
  printf 'stale destination\n' > "$returned_executable"
  vm_ssh "$native_scp $guest_executable motor@$host:$returned_executable" ||
    fail "Motor client could not replace an existing Unix file"
  cmp -s "$host_executable" "$returned_executable" ||
    fail "Motor client overwrite did not replace the existing Unix file"
  [ "$(stat -c %a "$returned_executable")" = 600 ] ||
    fail "Motor client overwrite did not preserve the destination's mode"

  local host_source_tree="$SSH_CLIENT_HOST_ROOT/source-tree"
  local host_upload_parent="$SSH_CLIENT_HOST_ROOT/upload-parent"
  local guest_download_parent="$guest_transfer_root/download"
  mkdir -p "$host_source_tree/nested" "$host_source_tree/empty" "$host_upload_parent"
  printf 'first recursive payload\n' > "$host_source_tree/nested/file"
  vm_ssh "/user/bin/rush -c '/user/bin/mkdir $guest_transfer_root && /user/bin/mkdir $guest_download_parent'" ||
    fail "could not create the guest recursive-transfer directories"
  vm_ssh "$native_scp -r motor@$host:$host_source_tree $guest_download_parent" ||
    fail "Motor client could not download a Unix directory"
  printf 'updated recursive payload\n' > "$host_source_tree/nested/file"
  vm_ssh "$native_scp -r motor@$host:$host_source_tree $guest_download_parent" ||
    fail "Motor client could not download into an existing directory"
  [ "$(vm_ssh /user/bin/cat "$guest_download_parent/source-tree/nested/file")" = \
      "updated recursive payload" ] ||
    fail "recursive re-download did not replace an existing local file"

  vm_ssh "$native_scp -r $guest_download_parent/source-tree motor@$host:$host_upload_parent" ||
    fail "Motor client could not upload a directory"
  printf 'stale recursive destination\n' > "$host_upload_parent/source-tree/nested/file"
  chmod 775 "$host_upload_parent/source-tree"
  vm_ssh "$native_scp -r $guest_download_parent/source-tree motor@$host:$host_upload_parent" ||
    fail "Motor client could not upload into an existing directory"
  cmp -s "$host_source_tree/nested/file" "$host_upload_parent/source-tree/nested/file" ||
    fail "recursive re-upload did not replace an existing remote file"
  [ -d "$host_upload_parent/source-tree/empty" ] ||
    fail "recursive re-upload did not preserve an empty directory"
  [ "$(stat -c %a "$host_upload_parent/source-tree")" = 775 ] ||
    fail "recursive re-upload changed the mode of an existing directory"

  local password_command="/user/bin/ssh -F /dev/null -p $port -i $guest_wrong -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes motor@$host /bin/echo password-ok"
  local password_stderr="$TEST_TMP/ssh-client-host-password.stderr"
  local password_status=0
  # Keep the PTY on stdin/stdout, but retain client diagnostics separately:
  # a stderr debug record can split the password-ok line being asserted.
  # The wrapper also gives the client's runtime inherited, pipe-relayed stderr.
  output="$(printf 'vroomvroom\n' | ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
    "/user/bin/rush -c '$password_command' 2>$password_stderr" 2>&1)" || password_status=$?
  vm_ssh "/user/bin/cat $password_stderr" >&2 || fail "could not read password-auth diagnostics"
  [ "$password_status" -eq 0 ] || fail "Motor client password fallback failed: $password_status"
  printf '%s\n' "$output" | tr -d '\r' | grep -qx password-ok ||
    fail "password-auth command returned '$output'"

  local prompt_known="$TEST_TMP/ssh-client-host-prompts.known"
  local terminal_dump
  terminal_dump="$(command -v od)"
  password_command="/user/bin/ssh -T -F /dev/null -p $port -i $guest_wrong -o IdentitiesOnly=yes -o StrictHostKeyChecking=ask -o UserKnownHostsFile=$prompt_known motor@$host $terminal_dump -An -tx1"
  password_status=0
  # One CRLF is one Enter, including between host-key/password prompts and
  # between the password prompt and forwarded terminal input.
  output="$(printf 'yes\r\nvroomvroom\r\nfirst\r\nsecond\r\n' |
    ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
      "/user/bin/rush -c '$password_command' 2>$password_stderr" 2>&1)" || password_status=$?
  vm_ssh "/user/bin/cat $password_stderr" >&2 || fail "could not read CRLF-auth diagnostics"
  [ "$password_status" -eq 0 ] || fail "CRLF host-key/password prompts failed: $password_status"
  printf '%s\n' "$output" | tr -d '\r' | grep -qx ' 66 69 72 73 74 0d 73 65 63 6f 6e 64 0d' ||
    fail "terminal Enter was not forwarded once: '$output'"
  vm_ssh "/user/bin/rm $prompt_known" || fail "could not remove prompt known-hosts fixture"

  MOTOR_SSH_TARGET_PORT="$port" MOTOR_SSH_BUILD="$BUILD" cross_ssh_config

  local copy_id="/user/bin/ssh-copy-id -F /dev/null -p $port -o BatchMode=yes -o StrictHostKeyChecking=yes -i $guest_key.pub motor@$host"
  vm_ssh "$copy_id" >/dev/null || fail "ssh-copy-id failed"
  [ "$(stat -c %a "$SSH_CLIENT_HOST_ROOT/.ssh")" = 700 ] ||
    fail "ssh-copy-id did not create .ssh with mode 0700"
  [ "$(stat -c %a "$SSH_CLIENT_HOST_ROOT/.ssh/authorized_keys")" = 600 ] ||
    fail "ssh-copy-id did not create authorized_keys with mode 0600"
  printf '# preserved\n' >> "$SSH_CLIENT_HOST_ROOT/.ssh/authorized_keys"
  vm_ssh "$copy_id" >/dev/null || fail "duplicate ssh-copy-id failed"
  [ "$(grep -Fxc "$public_key" "$SSH_CLIENT_HOST_ROOT/.ssh/authorized_keys")" = 1 ] ||
    fail "ssh-copy-id did not install exactly one key"
  grep -Fqx '# preserved' "$SSH_CLIENT_HOST_ROOT/.ssh/authorized_keys" ||
    fail "ssh-copy-id discarded an unrecognized authorized_keys line"

  stop_ssh_client_host
  start_ssh_client_host "$second_key" "$port"
  if vm_ssh "/user/bin/ssh -F /dev/null -p $port -o BatchMode=yes -o StrictHostKeyChecking=yes motor@$host /bin/true"; then
    fail "Motor client accepted a changed host key"
  else
    local status=$?
    [ "$status" -eq 255 ] || fail "changed host key returned status $status"
  fi
  [ "$(vm_ssh /user/bin/cat "$guest_known")" = "$known" ] ||
    fail "changed host key modified known_hosts"

  stop_ssh_client_host
  remove_ssh_client_host_identity || fail "failed to remove the guest SSH identity fixture"
  for guest_file in "$guest_wrong" "$guest_executable"; do
    vm_ssh "/user/bin/rm $guest_file" >/dev/null ||
      fail "failed to remove guest SSH fixture $guest_file"
  done
  vm_ssh "/user/bin/rm -r $guest_transfer_root" >/dev/null ||
    fail "failed to remove the guest recursive-transfer fixture"
  cleanup_ssh_client_host
  echo "-- Motor SSH client private-network compatibility PASS"
}

cross_ssh_client() (
# Motor SSH client integration against the VM's own russhd over loopback.

set -euo pipefail

HOST="${RUSSHD_HOST:-192.168.4.2}"
PORT="${RUSSHD_PORT:-2222}"
USER="${RUSSHD_USER:-motor}"
KEY="${RUSSHD_KEY:-$TEST_KEY}"
TEST_TMP="${MOTOR_TEST_TMP:-/user/tmp/motor-tests}"
GUEST_KEY="/user/cfg/ssh/id_ed25519"
GUEST_KNOWN="/user/cfg/ssh/known_hosts"
SOURCE="$TEST_TMP/ssh-client-source"
UPLOAD="$TEST_TMP/ssh-client-upload"
DOWNLOAD="$TEST_TMP/ssh-client-download"
SFTP_DOWNLOAD="$TEST_TMP/ssh-client-sftp-download"
GENERATED="$TEST_TMP/ssh-client-generated"
RENAME_SOURCE="$TEST_TMP/ssh-client-rename-source"
RENAME_TARGET="$TEST_TMP/ssh-client-rename-target"
TREE_SOURCE="$TEST_TMP/ssh-client-tree-source"
TREE_UPLOAD_PARENT="$TEST_TMP/ssh-client-tree-upload"
TREE_DOWNLOAD_PARENT="$TEST_TMP/ssh-client-tree-download"

HOST_SSH=(
  ssh -F /dev/null -p "$PORT" -i "$KEY"
  -o IdentitiesOnly=yes -o BatchMode=yes
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS"
  "$USER@$HOST"
)
HOST_SFTP=(
  sftp -F /dev/null -P "$PORT" -i "$KEY"
  -o IdentitiesOnly=yes -o BatchMode=yes
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS"
  -b - "$USER@$HOST"
)
GUEST_CONNECTION="-p 2222 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$GUEST_KNOWN -i $GUEST_KEY"
GUEST_SCP_CONNECTION="-P 2222 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$GUEST_KNOWN -i $GUEST_KEY"
GUEST_SFTP_CONNECTION="-P 2222 -b - -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$GUEST_KNOWN -i $GUEST_KEY"

fail() {
  echo "test-ssh-client: $*" >&2
  exit 1
}

for option in --help -h; do
  out="$("${HOST_SSH[@]}" "/user/bin/ssh $option")" ||
    fail "ssh $option did not exit successfully"
  for expected in 'Usage: ssh' /user/cfg/ssh/config \
    /user/cfg/ssh/id_ed25519 /user/cfg/ssh/known_hosts; do
    case "$out" in
      *"$expected"*) ;;
      *) fail "ssh $option did not explain '$expected': '$out'" ;;
    esac
  done
done

cleanup() {
  # sysbox rm takes exactly one operand, so remove the fixtures one by one
  # inside a single guest shell.
  "${HOST_SSH[@]}" "/user/bin/rush -c ' \
    /user/bin/rm $GUEST_KEY; /user/bin/rm $GUEST_KEY.pub; \
    /user/bin/rm $GUEST_KNOWN; /user/bin/rm $SOURCE; \
    /user/bin/rm $UPLOAD; /user/bin/rm $DOWNLOAD; \
    /user/bin/rm $SFTP_DOWNLOAD; /user/bin/rm $GENERATED; \
    /user/bin/rm $GENERATED.pub; /user/bin/rm $RENAME_SOURCE; \
    /user/bin/rm $RENAME_TARGET; /user/bin/rm -r $TREE_SOURCE; \
    /user/bin/rm -r $TREE_UPLOAD_PARENT; \
    /user/bin/rm -r $TREE_DOWNLOAD_PARENT'" \
    >/dev/null 2>&1 || true
}
trap cleanup EXIT

printf 'put %s %s\nchmod 600 %s\n' "$KEY" "$GUEST_KEY" "$GUEST_KEY" |
  "${HOST_SFTP[@]}" >/dev/null || fail "could not stage the loopback identity"

out="$(printf 'loopback stdin\n' | "${HOST_SSH[@]}" \
  "/user/bin/ssh $GUEST_CONNECTION motor@127.0.0.1 /user/bin/cat")" ||
  fail "scripted loopback ssh failed"
[ "$out" = "loopback stdin" ] || fail "scripted ssh returned '$out'"

expected="$(printf 'loopback\r\n\r\npayload\r\nend')"
out="$(printf '%s' "$expected" | "${HOST_SSH[@]}" \
  "/user/bin/ssh $GUEST_CONNECTION motor@127.0.0.1 /user/bin/cat")" ||
  fail "scripted loopback ssh with CRLF data failed"
[ "$out" = "$expected" ] || fail "ssh changed CRLF bytes in piped stdin"

if "${HOST_SSH[@]}" \
  "/user/bin/ssh $GUEST_CONNECTION motor@127.0.0.1 '/user/bin/rush -c \"exit 7\"'"; then
  fail "ssh lost the remote nonzero status"
else
  status=$?
  [ "$status" -eq 7 ] || fail "ssh mapped remote status 7 to $status"
fi

# This exercises the abbreviated form with the default identity and known-hosts
# paths. The shipped russhd listens on 2222, so only its nonstandard port is
# explicit; parser tests separately prove that `ssh user@host` defaults to 22.
if ! printf 'exit\n' | ssh -tt -F /dev/null -p "$PORT" -i "$KEY" \
  -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$KNOWN_HOSTS" "$USER@$HOST" \
  "/user/bin/ssh -p 2222 motor@127.0.0.1" >/dev/null 2>&1; then
  fail "interactive 'ssh -p 2222 motor@127.0.0.1' failed"
fi

"${HOST_SSH[@]}" "/user/bin/rush -c 'echo loopback-copy > $SOURCE'"
"${HOST_SSH[@]}" \
  "/user/bin/scp $GUEST_SCP_CONNECTION $SOURCE motor@127.0.0.1:$UPLOAD" ||
  fail "loopback scp upload failed"
"${HOST_SSH[@]}" \
  "/user/bin/scp $GUEST_SCP_CONNECTION motor@127.0.0.1:$UPLOAD $DOWNLOAD" ||
  fail "loopback scp download failed"
out="$("${HOST_SSH[@]}" "/user/bin/cat $DOWNLOAD")"
[ "$out" = "loopback-copy" ] || fail "scp round trip returned '$out'"

"${HOST_SSH[@]}" "/user/bin/rush -c 'echo source > $RENAME_SOURCE; echo target > $RENAME_TARGET'"
if printf 'rename -l %s %s\n' "$RENAME_SOURCE" "$RENAME_TARGET" |
  "${HOST_SSH[@]}" "/user/bin/sftp $GUEST_SFTP_CONNECTION motor@127.0.0.1" >/dev/null 2>&1; then
  fail "plain SFTP rename replaced an existing destination"
fi
out="$("${HOST_SSH[@]}" "/user/bin/cat $RENAME_SOURCE")"
[ "$out" = "source" ] || fail "failed plain rename changed its source"
out="$("${HOST_SSH[@]}" "/user/bin/cat $RENAME_TARGET")"
[ "$out" = "target" ] || fail "failed plain rename changed its destination"
printf 'rename %s %s\n' "$RENAME_SOURCE" "$RENAME_TARGET" |
  "${HOST_SSH[@]}" "/user/bin/sftp $GUEST_SFTP_CONNECTION motor@127.0.0.1" >/dev/null 2>&1 ||
  fail "replacing rename through the sftp applet failed"
out="$("${HOST_SSH[@]}" "/user/bin/cat $RENAME_TARGET")"
[ "$out" = "source" ] || fail "sftp applet rename did not replace the destination"
if "${HOST_SSH[@]}" "/user/bin/ls $RENAME_SOURCE" >/dev/null 2>&1; then
  fail "sftp applet rename left its source reachable"
fi

"${HOST_SSH[@]}" "/user/bin/rush -c ' \
  /user/bin/mkdir $TREE_SOURCE && /user/bin/mkdir $TREE_SOURCE/nested && \
  /user/bin/mkdir $TREE_SOURCE/empty && /user/bin/mkdir $TREE_UPLOAD_PARENT && \
  /user/bin/mkdir $TREE_DOWNLOAD_PARENT'" ||
  fail "could not create the recursive-transfer fixtures"
"${HOST_SSH[@]}" "/user/bin/rush -c 'echo recursive-upload > $TREE_SOURCE/nested/file'"
"${HOST_SSH[@]}" \
  "/user/bin/scp -r $GUEST_SCP_CONNECTION $TREE_SOURCE motor@127.0.0.1:$TREE_UPLOAD_PARENT" ||
  fail "loopback recursive upload failed"
"${HOST_SSH[@]}" "/user/bin/rush -c 'echo stale > $TREE_UPLOAD_PARENT/ssh-client-tree-source/nested/file'"
"${HOST_SSH[@]}" \
  "/user/bin/scp -r $GUEST_SCP_CONNECTION $TREE_SOURCE motor@127.0.0.1:$TREE_UPLOAD_PARENT" ||
  fail "loopback recursive re-upload failed"
out="$("${HOST_SSH[@]}" "/user/bin/cat $TREE_UPLOAD_PARENT/ssh-client-tree-source/nested/file")"
[ "$out" = "recursive-upload" ] || fail "recursive re-upload did not replace an existing file"

"${HOST_SSH[@]}" \
  "/user/bin/scp -r $GUEST_SCP_CONNECTION motor@127.0.0.1:$TREE_UPLOAD_PARENT/ssh-client-tree-source $TREE_DOWNLOAD_PARENT" ||
  fail "loopback recursive download failed"
"${HOST_SSH[@]}" "/user/bin/rush -c 'echo recursive-download > $TREE_UPLOAD_PARENT/ssh-client-tree-source/nested/file'"
"${HOST_SSH[@]}" \
  "/user/bin/scp -r $GUEST_SCP_CONNECTION motor@127.0.0.1:$TREE_UPLOAD_PARENT/ssh-client-tree-source $TREE_DOWNLOAD_PARENT" ||
  fail "loopback recursive re-download failed"
out="$("${HOST_SSH[@]}" "/user/bin/cat $TREE_DOWNLOAD_PARENT/ssh-client-tree-source/nested/file")"
[ "$out" = "recursive-download" ] || fail "recursive re-download did not replace an existing file"
"${HOST_SSH[@]}" "[ -d $TREE_UPLOAD_PARENT/ssh-client-tree-source/empty ]" ||
  fail "recursive re-upload did not preserve an empty directory"
"${HOST_SSH[@]}" "[ -d $TREE_DOWNLOAD_PARENT/ssh-client-tree-source/empty ]" ||
  fail "recursive re-download did not preserve an empty directory"

printf 'pwd\nls %s\nget %s %s\n' "$TEST_TMP" "$UPLOAD" "$SFTP_DOWNLOAD" |
  "${HOST_SSH[@]}" "/user/bin/sftp $GUEST_SFTP_CONNECTION motor@127.0.0.1" \
    >/dev/null || fail "loopback batch sftp failed"
out="$("${HOST_SSH[@]}" "/user/bin/cat $SFTP_DOWNLOAD")"
[ "$out" = "loopback-copy" ] || fail "sftp download returned '$out'"

"${HOST_SSH[@]}" "/user/bin/ssh-keygen -q -t ed25519 -N '' -f $GENERATED" ||
  fail "ssh-keygen failed"
public="$("${HOST_SSH[@]}" "/user/bin/cat $GENERATED.pub")"
derived="$("${HOST_SSH[@]}" "/user/bin/ssh-keygen -y -f $GENERATED")"
[ "$public" = "$derived" ] || fail "ssh-keygen -y did not reproduce the public key"

echo "test-ssh-client: PASS"
)

cross_sftp() (
#
# Integration test for russhd's SFTP directory, download, and upload support.
#
# Exercises the realpath / opendir / readdir / lstat / open / read / write
# handlers in src/bin/russhd/src/sftp_session.rs by listing a remote directory,
# downloading a file, and round-tripping uploads.
#
# Requires a running Motor OS VM with russhd reachable and OpenSSH `sftp` and
# `scp` clients. Connection details can be overridden via the environment, e.g.:
#
#   RUSSHD_HOST=192.168.4.2 RUSSHD_KEY=test.key ./test_sftp.sh
#
set -u


# Accept an optional --release flag for a uniform invocation with the other
# test scripts. This test connects to an already-running VM, so the flag does
# not select a run-qemu.sh; it is accepted (and otherwise ignored) here.
if [ "${1:-}" = "--release" ]; then
    shift
fi

HOST="${RUSSHD_HOST:-192.168.4.2}"
PORT="${RUSSHD_PORT:-2222}"
USER="${RUSSHD_USER:-motor}"
# Interactive scratch, and scratch that None-role children can reach.
TEST_TMP="${MOTOR_TEST_TMP:-/user/tmp}"
NONE_TEST_TMP="${MOTOR_NONE_TEST_TMP:-/none/tmp}"
# Use the runner's private copy of the canonical VM key.
KEY="${RUSSHD_KEY:-$TEST_KEY}"
REMOTE_DIR="${RUSSHD_REMOTE_DIR:-/user/bin}"
REMOTE_FILE="${RUSSHD_REMOTE_FILE:-/system/logs/sys-init.log}"
REMOTE_UPLOAD_FILE="${RUSSHD_REMOTE_UPLOAD_FILE:-$TEST_TMP/russhd-sftp-upload-test.bin}"
# Permission fixtures sit where None could read them but for their own modes.
REMOTE_PRIVATE_FILE="$NONE_TEST_TMP/russhd-sftp-private-test.bin"
EXPECTED_FILES=(rush sysbox)

SSH_OPTS=(
    -F /dev/null
    -P "$PORT"
    -i "$KEY"
    -o IdentitiesOnly=yes
    -o BatchMode=yes              # never prompt; fail fast if the key is wrong
    -o StrictHostKeyChecking=no   # the VM's host key is ephemeral in testing
    -o UserKnownHostsFile=/dev/null
)

REMOTE_PHASE0_PARENT="$TEST_TMP/source-staging"
REMOTE_PHASE0_ROOT="${RUSSHD_PHASE0_ROOT:-$REMOTE_PHASE0_PARENT/sftp-prerequisite-$$}"

WORK="$(mktemp -d)"
ABANDONED_PID=""
PROTECTED_PARENT="$TEST_TMP/sftp-protected-$$"
PUBLIC_FILE="$TEST_TMP/sftp-public-$$"
MODE_ROOT="$NONE_TEST_TMP/sftp-modes-$$"

run_ssh() {
    ssh \
        -F /dev/null \
        -p "$PORT" \
        -i "$KEY" \
        -o IdentitiesOnly=yes \
        -o BatchMode=yes \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        "$USER@$HOST" \
        "$@"
}

# A None-role child must fail on cat's own read error (exit 1); a failed ssh
# session or shell would pass a plain "did not succeed" check.
none_read_denied() {
    local output status=0
    output="$(run_ssh "MOTOR_OS_CAPS=0x304 /user/bin/sysbox cat $1" 2>&1)" || status=$?
    [ "$status" -eq 1 ] && printf '%s\n' "$output" | grep -q "cat: error reading file"
}

cleanup() {
    if [ -n "$ABANDONED_PID" ]; then
        kill "$ABANDONED_PID" 2>/dev/null || true
        wait "$ABANDONED_PID" 2>/dev/null || true
    fi
    remove_permission_fixtures
    for mode_parent in "$MODE_ROOT/mode-9" "$MODE_ROOT/mode-10"; do
        run_ssh /user/bin/sysbox chmod rwxrwxr-x "$mode_parent" >/dev/null 2>&1 || true
    done
    run_ssh /user/bin/rm -r "$MODE_ROOT" >/dev/null 2>&1 || true
    run_ssh /user/bin/sysbox chmod rwxrwxr-x "$PROTECTED_PARENT" >/dev/null 2>&1 || true
    run_ssh /user/bin/rm -r "$PROTECTED_PARENT" >/dev/null 2>&1 || true
    run_ssh /user/bin/rm "$PUBLIC_FILE" >/dev/null 2>&1 || true
    run_ssh /user/bin/rm -r "$REMOTE_PHASE0_ROOT" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

command -v sftp >/dev/null 2>&1 || fail "no 'sftp' client found in PATH"
command -v scp >/dev/null 2>&1 || fail "no 'scp' client found in PATH"
command -v cmp >/dev/null 2>&1 || fail "no 'cmp' command found in PATH"
command -v dd >/dev/null 2>&1 || fail "no 'dd' command found in PATH"
[ -r "$KEY" ] || fail "key file '$KEY' not found or not readable"

# Run a batch of sftp commands (passed on stdin) against the VM. Stderr is
# captured so we can surface it only on failure.
run_sftp() {
    sftp "${SSH_OPTS[@]}" -b - "$USER@$HOST" >"$WORK/out" 2>"$WORK/err"
}

run_scp() {
    scp "${SSH_OPTS[@]}" "$@" >"$WORK/out" 2>"$WORK/err"
}

# Step 4 leaves an executable (555) and a read-only (444) fixture that a later
# `put` is refused on, so a rerun against the same VM would fail on its own
# leftovers. Remove them before step 4 and on exit; `-rm` ignores a missing file.
remove_permission_fixtures() {
    run_sftp <<EOF || true
-rm $REMOTE_PRIVATE_FILE.plain
-rm $REMOTE_PRIVATE_FILE.exec
-rm $REMOTE_PRIVATE_FILE.readonly
-rm $REMOTE_PRIVATE_FILE.abandoned
-rm $REMOTE_PRIVATE_FILE.public
EOF
}

echo "== russhd SFTP test against $USER@$HOST:$PORT =="

# Raw protocol requests cover clients that set the mode after OPEN, as well as
# the usual OpenSSH creation hints exercised below. This uses only Rust std.
cp "$ROOT_DIR/src/bin/russhd/target/$BUILD/sftp-permissions" "$WORK/sftp-permissions" ||
    fail "SFTP permission probe compilation failed"
run_ssh /user/bin/mkdir "$MODE_ROOT" || fail "SFTP mode fixture creation failed"
"$WORK/sftp-permissions" "$KEY" "$USER" "$HOST" "$PORT" "$MODE_ROOT" ||
    fail "SFTP permission requests failed"

# ---------------------------------------------------------------------------
# 1. Directory listing: `ls -1` makes the client call realpath, opendir and
#    readdir on the server. A plain `ls` on the file would only hit lstat/stat.
# ---------------------------------------------------------------------------
echo "-- listing $REMOTE_DIR --"
run_sftp <<EOF || { cat "$WORK/err" >&2; fail "sftp 'ls $REMOTE_DIR' failed"; }
ls -1 $REMOTE_DIR
EOF

# sftp may print entries as bare names or as "<dir>/<name>"; strip any prefix.
listing="$(sed 's#.*/##' "$WORK/out")"
echo "$listing" | sed 's/^/    /'

for name in "${EXPECTED_FILES[@]}"; do
    if echo "$listing" | grep -qx "$name"; then
        echo "  ok: '$REMOTE_DIR' contains '$name'"
    else
        fail "expected '$name' in '$REMOTE_DIR' listing, but it is missing"
    fi
done

# ---------------------------------------------------------------------------
# 2. File download: confirms open + read still work end-to-end.
# ---------------------------------------------------------------------------
echo "-- downloading $REMOTE_FILE --"
run_sftp <<EOF || { cat "$WORK/err" >&2; fail "sftp 'get $REMOTE_FILE' failed"; }
get $REMOTE_FILE $WORK/
EOF

got="$WORK/$(basename "$REMOTE_FILE")"
[ -s "$got" ] || fail "downloaded file '$got' is missing or empty"
echo "  ok: downloaded $(wc -c < "$got") bytes from $REMOTE_FILE"

# ---------------------------------------------------------------------------
# 3. Multi-packet upload: put a binary payload larger than OpenSSH's normal
#    SFTP write packet, fetch it back, and compare every byte. This exercises
#    CREATE, TRUNCATE, and multiple offset-based WRITE requests.
# ---------------------------------------------------------------------------
upload_source="$WORK/upload-source.bin"
upload_roundtrip="$WORK/upload-roundtrip.bin"
dd if=/dev/urandom of="$upload_source" bs=1024 count=384 status=none

echo "-- uploading $(wc -c < "$upload_source") bytes to $REMOTE_UPLOAD_FILE --"
run_sftp <<EOF || { cat "$WORK/err" >&2; fail "large SFTP upload failed"; }
put $upload_source $REMOTE_UPLOAD_FILE
get $REMOTE_UPLOAD_FILE $upload_roundtrip
EOF

[ -s "$upload_roundtrip" ] ||
    fail "round-tripped upload '$upload_roundtrip' is missing or empty"
cmp -s "$upload_source" "$upload_roundtrip" ||
    fail "large upload differs after downloading it again"
echo "  ok: multi-packet upload round-tripped byte-for-byte"

# ---------------------------------------------------------------------------
# 4. Preserve the SFTP owner/public distinction through Motor role modes.
# ---------------------------------------------------------------------------
permission_source="$WORK/permission-source.bin"
plain_permission_roundtrip="$WORK/plain-permission-roundtrip.bin"
exec_permission_roundtrip="$WORK/exec-permission-roundtrip.bin"
readonly_permission_roundtrip="$WORK/readonly-permission-roundtrip.bin"
remote_plain_permission_file="$REMOTE_PRIVATE_FILE.plain"
remote_exec_permission_file="$REMOTE_PRIVATE_FILE.exec"
remote_readonly_permission_file="$REMOTE_PRIVATE_FILE.readonly"
printf '#!/user/bin/rush\nexit 0\n' >"$permission_source"
chmod 600 "$permission_source"

echo "-- setting and reading back SFTP permissions --"
remove_permission_fixtures
run_sftp <<EOF || { cat "$WORK/err" >&2; fail "plain SFTP permission update failed"; }
put $permission_source $remote_plain_permission_file
chmod 600 $remote_plain_permission_file
get -p $remote_plain_permission_file $plain_permission_roundtrip
EOF
chmod 700 "$permission_source"
run_sftp <<EOF || { cat "$WORK/err" >&2; fail "executable SFTP permission update failed"; }
put $permission_source $remote_exec_permission_file
get -p $remote_exec_permission_file $exec_permission_roundtrip
EOF
run_ssh "$remote_exec_permission_file" || fail "uploaded executable did not run"
if run_sftp <<EOF
put $permission_source $remote_exec_permission_file
EOF
then
    fail "put unexpectedly overwrote an existing executable"
fi
chmod 400 "$permission_source"
run_sftp <<EOF || { cat "$WORK/err" >&2; fail "read-only SFTP permission update failed"; }
put $permission_source $remote_readonly_permission_file
get -p $remote_readonly_permission_file $readonly_permission_roundtrip
EOF

plain_mode="$(stat -c %a "$plain_permission_roundtrip")"
exec_mode="$(stat -c %a "$exec_permission_roundtrip")"
readonly_mode="$(stat -c %a "$readonly_permission_roundtrip")"
[ "$plain_mode" = 600 ] ||
    fail "non-executable permission round-trip returned mode $plain_mode"
[ "$exec_mode" = 500 ] ||
    fail "executable permission round-trip returned mode $exec_mode"
[ "$readonly_mode" = 400 ] ||
    fail "read-only permission round-trip returned mode $readonly_mode"

permission_listing="$(run_ssh /user/bin/ls -l "$NONE_TEST_TMP")"
plain_motor_mode="$(printf '%s\n' "$permission_listing" | awk -v name="$(basename "$remote_plain_permission_file")" '$NF == name { print $1; exit }')"
exec_motor_mode="$(printf '%s\n' "$permission_listing" | awk -v name="$(basename "$remote_exec_permission_file")" '$NF == name { print $1; exit }')"
readonly_motor_mode="$(printf '%s\n' "$permission_listing" | awk -v name="$(basename "$remote_readonly_permission_file")" '$NF == name { print $1; exit }')"
[ "$plain_motor_mode" = -rwxrw---- ] ||
    fail "private upload has Motor mode $plain_motor_mode"
[ "$exec_motor_mode" = -rwxr-x--- ] ||
    fail "executable upload has Motor mode $exec_motor_mode"
[ "$readonly_motor_mode" = -rwxr----- ] ||
    fail "read-only upload has Motor mode $readonly_motor_mode"
# Positive control: a None-role child reads a public file beside the uploads.
run_ssh "/user/bin/rush -c 'echo public > $REMOTE_PRIVATE_FILE.public'"
[ "$(run_ssh "MOTOR_OS_CAPS=0x304 /user/bin/sysbox cat $REMOTE_PRIVATE_FILE.public")" = public ] ||
    fail "None-role child could not read a public file beside the SFTP uploads"
none_read_denied "$remote_plain_permission_file" ||
    fail "None-role child read a private SFTP upload"
echo "  ok: SFTP permission updates preserved owner/public role distinctions"

# A throttled upload keeps its handle open long enough to inspect the staging
# permissions, then an intentional client termination exercises connection-drop
# cleanup. The file must never become readable by the None role.
abandoned_source="$WORK/abandoned-source.bin"
abandoned_batch="$WORK/abandoned.batch"
remote_abandoned_file="$REMOTE_PRIVATE_FILE.abandoned"
dd if=/dev/urandom of="$abandoned_source" bs=1024 count=256 status=none
printf 'put %s %s\n' "$abandoned_source" "$remote_abandoned_file" >"$abandoned_batch"
sftp "${SSH_OPTS[@]}" -l 64 -b "$abandoned_batch" "$USER@$HOST" \
    >"$WORK/abandoned.out" 2>"$WORK/abandoned.err" &
abandoned_pid=$!
ABANDONED_PID="$abandoned_pid"
abandoned_created=0
for _ in $(seq 1 50); do
    if run_ssh /user/bin/ls "$remote_abandoned_file" >/dev/null 2>&1; then
        abandoned_created=1
        break
    fi
    sleep 0.1
done
if [ "$abandoned_created" != 1 ]; then
    kill "$abandoned_pid" 2>/dev/null || true
    wait "$abandoned_pid" 2>/dev/null || true
    cat "$WORK/abandoned.err" >&2
    fail "throttled SFTP upload did not create its destination"
fi
if ! none_read_denied "$remote_abandoned_file"; then
    kill "$abandoned_pid" 2>/dev/null || true
    wait "$abandoned_pid" 2>/dev/null || true
    fail "None-role child read an in-progress SFTP upload"
fi
kill "$abandoned_pid"
wait "$abandoned_pid" 2>/dev/null || true
ABANDONED_PID=""
abandoned_motor_mode="$(run_ssh /user/bin/ls -l "$NONE_TEST_TMP" | awk -v name="$(basename "$remote_abandoned_file")" '$NF == name { print $1; exit }')"
[ "$abandoned_motor_mode" = -rwxrw---- ] ||
    fail "abandoned upload has Motor mode $abandoned_motor_mode"
none_read_denied "$remote_abandoned_file" ||
    fail "None-role child read an abandoned SFTP upload"
echo "  ok: in-progress and abandoned uploads stayed private"

# ---------------------------------------------------------------------------
# 5. Overwrite with a shorter file. A server that opens for writing without
#    honoring TRUNCATE would leave bytes from the previous large payload.
# ---------------------------------------------------------------------------
overwrite_source="$WORK/overwrite-source.bin"
overwrite_roundtrip="$WORK/overwrite-roundtrip.bin"
printf 'russhd SFTP overwrite test\nshort payload\n' >"$overwrite_source"
# The upload sends the local mode; a private one (umask 077) would make the
# protected-parent overwrite below a refused private-data upload.
chmod 644 "$overwrite_source"

echo "-- overwriting $REMOTE_UPLOAD_FILE with a shorter file --"
run_sftp <<EOF || { cat "$WORK/err" >&2; fail "SFTP overwrite upload failed"; }
put $overwrite_source $REMOTE_UPLOAD_FILE
get $REMOTE_UPLOAD_FILE $overwrite_roundtrip
EOF

cmp -s "$overwrite_source" "$overwrite_roundtrip" ||
    fail "short overwrite differs after downloading it again"
echo "  ok: upload truncated and replaced the existing remote file"

# Existing content can be overwritten even when its parent forbids chmod.
# OPEN's mode is a creation hint: the existing file keeps its installed mode.
protected_file="$PROTECTED_PARENT/existing"
protected_roundtrip="$WORK/protected-roundtrip.bin"
echo "-- overwriting an executable under a protected parent --"
run_ssh /user/bin/mkdir "$PROTECTED_PARENT" || fail "protected SFTP directory creation failed"
run_sftp <<EOF || { cat "$WORK/err" >&2; fail "protected SFTP fixture upload failed"; }
put $upload_source $protected_file
EOF
run_ssh /user/bin/sysbox chmod rwxr-xr-x "$protected_file" ||
    fail "protected SFTP fixture executable setup failed"
run_ssh /user/bin/sysbox chmod rwxrwxr-x "$protected_file" ||
    fail "protected SFTP fixture mode setup failed"
run_ssh /user/bin/sysbox chmod rwxr-xr-x "$PROTECTED_PARENT" ||
    fail "protected SFTP parent mode setup failed"
run_sftp <<EOF || { cat "$WORK/err" >&2; fail "protected-parent SFTP overwrite failed"; }
put $overwrite_source $protected_file
get $protected_file $protected_roundtrip
EOF
cmp -s "$overwrite_source" "$protected_roundtrip" ||
    fail "protected-parent SFTP overwrite differed"
protected_mode="$(run_ssh /user/bin/ls -l "$PROTECTED_PARENT" | awk '$NF == "existing" { print $1; exit }')"
[ "$protected_mode" = -rwxrwxr-x ] ||
    fail "protected-parent SFTP overwrite changed mode to $protected_mode"
private_source="$WORK/private-source.bin"
printf 'private payload must not replace the public file\n' >"$private_source"
chmod 600 "$private_source"
if run_sftp <<EOF
put $private_source $protected_file
EOF
then
    fail "private-mode upload over a public protected file unexpectedly succeeded"
fi
grep -qi 'permission denied' "$WORK/err" ||
    fail "private-mode upload did not report permission denied"
if run_sftp <<EOF
put -p $overwrite_source $protected_file
EOF
then
    fail "put -p over a protected file unexpectedly succeeded"
fi
grep -qi 'permission denied' "$WORK/err" ||
    fail "put -p did not report permission denied"
if run_scp -p "$overwrite_source" "$USER@$HOST:$protected_file"; then
    fail "scp -p over a protected file unexpectedly succeeded"
fi
grep -qi 'permission denied' "$WORK/err" ||
    fail "scp -p did not report permission denied"
run_sftp <<EOF || { cat "$WORK/err" >&2; fail "protected file verification failed"; }
get $protected_file $protected_roundtrip.after
EOF
cmp -s "$overwrite_source" "$protected_roundtrip.after" ||
    fail "rejected private or preserve-mode upload changed the protected file"
run_ssh /user/bin/sysbox chmod rwxrwxr-x "$PROTECTED_PARENT" ||
    fail "protected SFTP parent mode restoration failed"
run_ssh /user/bin/rm -r "$PROTECTED_PARENT" || fail "protected SFTP fixture cleanup failed"
echo "  ok: protected-parent upload preserved the executable mode"

# A private executable uploaded over a public file in a writable directory:
# lower roles lose access before the contents change, while the uploader's own
# byte keeps its installed mode, so the in-place write still succeeds.
exec_source="$WORK/exec-source.bin"
exec_roundtrip="$WORK/exec-roundtrip.bin"
printf '#!/user/bin/rush\nexit 0\n' >"$exec_source"
chmod 700 "$exec_source"
echo "-- uploading a private executable over a public file --"
run_sftp <<EOF || { cat "$WORK/err" >&2; fail "public fixture upload failed"; }
put $overwrite_source $PUBLIC_FILE
EOF
run_ssh /user/bin/sysbox chmod rwxrw-r-- "$PUBLIC_FILE" ||
    fail "public fixture mode setup failed"
run_sftp <<EOF || { cat "$WORK/err" >&2; fail "private upload over a public file failed"; }
put $exec_source $PUBLIC_FILE
get $PUBLIC_FILE $exec_roundtrip
EOF
cmp -s "$exec_source" "$exec_roundtrip" ||
    fail "private upload over a public file differed"
public_mode="$(run_ssh /user/bin/ls -l "$TEST_TMP" | awk -v name="$(basename "$PUBLIC_FILE")" '$NF == name { print $1; exit }')"
[ "$public_mode" = -rwxrw---- ] ||
    fail "private upload over a public file left mode $public_mode"
# put -p installs the local mode at close, after the contents.
run_sftp <<EOF || { cat "$WORK/err" >&2; fail "put -p over the hidden file failed"; }
put -p $exec_source $PUBLIC_FILE
EOF
public_mode="$(run_ssh /user/bin/ls -l "$TEST_TMP" | awk -v name="$(basename "$PUBLIC_FILE")" '$NF == name { print $1; exit }')"
[ "$public_mode" = -rwxr-x--- ] ||
    fail "put -p over the hidden file left mode $public_mode"
run_ssh "$PUBLIC_FILE" || fail "the uploaded executable did not run"
echo "  ok: private executable replaced a public file; put -p set its mode at close"

# ---------------------------------------------------------------------------
# 6. OpenSSH scp uses SFTP in-place uploads and finishes every file with a
#    size-only FSETSTAT. Verify recursive scp accepts that request and the files.
# ---------------------------------------------------------------------------
scp_tree="$WORK/scp-tree"
mkdir -p "$scp_tree/nested"
printf 'top-level scp file\n' >"$scp_tree/top"
printf 'nested scp file\n' >"$scp_tree/nested/file"

run_ssh /user/bin/mkdir "$REMOTE_PHASE0_PARENT" >/dev/null 2>&1 || true
run_ssh /user/bin/mkdir "$REMOTE_PHASE0_ROOT" ||
    fail "could not create the fixture run root"

echo "-- recursively copying a directory with scp --"
run_scp -r "$scp_tree" "$USER@$HOST:$REMOTE_PHASE0_ROOT/" || {
    cat "$WORK/err" >&2
    fail "recursive scp upload failed"
}
if grep -F "remote fsetstat" "$WORK/err" >&2; then
    fail "recursive scp reported an fsetstat error"
fi
run_sftp <<EOF || { cat "$WORK/err" >&2; fail "scp round-trip failed"; }
get $REMOTE_PHASE0_ROOT/scp-tree/top $WORK/scp-top
get $REMOTE_PHASE0_ROOT/scp-tree/nested/file $WORK/scp-nested
EOF
cmp -s "$scp_tree/top" "$WORK/scp-top" || fail "top-level scp file changed"
cmp -s "$scp_tree/nested/file" "$WORK/scp-nested" || fail "nested scp file changed"
echo "  ok: recursive scp completed without fsetstat errors"

# ---------------------------------------------------------------------------
# 7. Recursively stage a representative source tree through one SFTP session,
#    copy it in the guest, and remove only the selected copy. This also verifies
#    empty directories and preserved modes.
# ---------------------------------------------------------------------------
source_tree="$WORK/source"
mkdir -p "$source_tree/src/nested" "$source_tree/empty"
printf '[package]\nname = "phase0-fixture"\nversion = "0.1.0"\n' \
    >"$source_tree/Cargo.toml"
printf 'fn main() { println!("nested fixture"); }\n' \
    >"$source_tree/src/main.rs"
chmod 644 "$source_tree/Cargo.toml"
chmod 700 "$source_tree/src/main.rs"
dd if=/dev/urandom of="$source_tree/src/nested/payload.bin" \
    bs=1024 count=96 status=none
printf 'must survive copy cleanup\n' >"$WORK/outside-sentinel"

remote_source="$REMOTE_PHASE0_ROOT/source"
remote_copy="$REMOTE_PHASE0_ROOT/copy"
remote_outside="$REMOTE_PHASE0_ROOT/outside-sentinel"
remote_operations="$REMOTE_PHASE0_ROOT/operations"

echo "-- staging a nested source fixture under $REMOTE_PHASE0_ROOT --"
run_ssh /user/bin/mkdir "$remote_source" ||
    fail "could not create the fixture source root"

run_sftp <<EOF || { cat "$WORK/err" >&2; fail "recursive SFTP upload failed"; }
put -pR $source_tree/. $remote_source
put $WORK/outside-sentinel $remote_outside
EOF

run_ssh /user/bin/cp -r "$remote_source" "$remote_copy" ||
    fail "guest 'cp -r' rejected the representative source tree"

if run_ssh /user/bin/cp -r "$remote_source" "$remote_source/inside-source"; then
    fail "guest 'cp -r' accepted a destination inside its source"
fi

if run_ssh /user/bin/rm "$remote_copy"; then
    fail "guest 'rm' removed a directory without -r"
fi

run_sftp <<EOF || { cat "$WORK/err" >&2; fail "copied-tree SFTP round-trip failed"; }
ls -1 $remote_copy/empty
get -p $remote_copy/Cargo.toml $WORK/copied-Cargo.toml
get -p $remote_copy/src/main.rs $WORK/copied-main.rs
get $remote_copy/src/nested/payload.bin $WORK/copied-payload.bin
EOF

cmp -s "$source_tree/Cargo.toml" "$WORK/copied-Cargo.toml" ||
    fail "Cargo.toml changed during nested upload/copy"
cmp -s "$source_tree/src/main.rs" "$WORK/copied-main.rs" ||
    fail "main.rs changed during nested upload/copy"
cmp -s "$source_tree/src/nested/payload.bin" "$WORK/copied-payload.bin" ||
    fail "binary payload changed during nested upload/copy"
plain_copy_mode="$(stat -c %a "$WORK/copied-Cargo.toml")"
exec_copy_mode="$(stat -c %a "$WORK/copied-main.rs")"
[ "$plain_copy_mode" = 644 ] ||
    fail "cp -r changed a non-executable file to mode $plain_copy_mode"
[ "$exec_copy_mode" = 500 ] ||
    fail "cp -r changed an executable file to mode $exec_copy_mode"

run_ssh /user/bin/rm -r "$remote_copy" ||
    fail "guest 'rm -r' could not remove the selected copied tree"

if run_sftp <<EOF
get $remote_copy/Cargo.toml $WORK/removed-Cargo.toml
EOF
then
    fail "guest 'rm -r' left the selected copied tree reachable"
fi

run_sftp <<EOF || { cat "$WORK/err" >&2; fail "cleanup damaged an outside sentinel"; }
get $remote_outside $WORK/outside-roundtrip
EOF
cmp -s "$WORK/outside-sentinel" "$WORK/outside-roundtrip" ||
    fail "recursive cleanup changed the outside sentinel"

printf 'replacement source\n' > "$WORK/rename-source"
printf 'replacement target\n' > "$WORK/rename-target"
run_sftp <<EOF || { cat "$WORK/err" >&2; fail "SFTP filesystem commands failed"; }
mkdir $remote_operations
mkdir $remote_operations/dir-target
rename $remote_outside $remote_operations/sentinel
get $remote_operations/sentinel $WORK/renamed-roundtrip
put $WORK/rename-source $remote_operations/rename-source
put $WORK/rename-target $remote_operations/rename-target
EOF
cmp -s "$WORK/outside-sentinel" "$WORK/renamed-roundtrip" ||
    fail "SFTP rename changed the outside sentinel"

# The plain (legacy) rename must not replace an existing destination, and
# posix-rename must not replace a directory with a file.
if run_sftp <<EOF
rename -l $remote_operations/rename-source $remote_operations/rename-target
EOF
then
    fail "plain SFTP rename replaced an existing destination"
fi
if run_sftp <<EOF
rename $remote_operations/rename-source $remote_operations/dir-target
EOF
then
    fail "posix-rename replaced a directory with a file"
fi

# The rmdir doubles as proof that the refused rename left the directory alone.
run_sftp <<EOF || { cat "$WORK/err" >&2; fail "SFTP replacing rename failed"; }
rename $remote_operations/rename-source $remote_operations/rename-target
get $remote_operations/rename-target $WORK/replaced-roundtrip
rmdir $remote_operations/dir-target
EOF
cmp -s "$WORK/rename-source" "$WORK/replaced-roundtrip" ||
    fail "posix-rename did not replace the existing destination"
if run_ssh /user/bin/ls "$remote_operations/rename-source" >/dev/null 2>&1; then
    fail "posix-rename left its source path reachable"
fi
run_sftp <<EOF || { cat "$WORK/err" >&2; fail "SFTP rename cleanup failed"; }
rm $remote_operations/sentinel
rm $remote_operations/rename-target
rmdir $remote_operations
EOF
echo "  ok: recursive upload, preserved modes, and SFTP filesystem commands passed"

echo
echo "PASS: all checks succeeded"
)

cross_ssh_config() (
# Config aliases and TCP forwarding in both directions across the private tap.
set -euo pipefail
TEST_TMP="${MOTOR_TEST_TMP:-/user/tmp/motor-tests}"
target_port="$MOTOR_SSH_TARGET_PORT"
BUILD="$MOTOR_SSH_BUILD"
mkdir -p "$ROOT_DIR/build/host-tests"
fixture="$(mktemp -d "$ROOT_DIR/build/host-tests/ssh-config.XXXXXX")"
guest="$TEST_TMP/ssh-config"
config=/user/cfg/ssh/config
staged=0
loopback_log_pid="" shell_pid="" gateway_pid="" gateway_log_pid="" sockets=""
SSH=(ssh -F /dev/null -p 2222 -i "$TEST_KEY" -o IdentitiesOnly=yes -o BatchMode=yes
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS" motor@192.168.4.2)
SFTP=(sftp -F /dev/null -P 2222 -i "$TEST_KEY" -o IdentitiesOnly=yes -o BatchMode=yes
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS" -b - motor@192.168.4.2)
fail() { echo "test-ssh-config: $* (logs: $fixture)" >&2; exit 1; }
cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if [ -n "$shell_pid" ]; then kill "$shell_pid" 2>/dev/null; wait "$shell_pid"; fi
  if [ -n "$gateway_pid" ]; then kill "$gateway_pid" 2>/dev/null; wait "$gateway_pid"; fi
  if [ -n "$gateway_log_pid" ]; then wait "$gateway_log_pid" || status=1; fi
  stop_ssh_client_host
  if [ -n "$loopback_log_pid" ]; then wait "$loopback_log_pid" || status=1; fi
  if [ -n "$sockets" ]; then rm -rf "$sockets" || status=1; fi
  if [ "$staged" -eq 1 ]; then
    "${SSH[@]}" "/user/bin/rm $config" || status=1
    "${SSH[@]}" "/user/bin/rm -r $guest" || status=1
  fi
  if [ "$status" -eq 0 ]; then rm -rf "$fixture"; fi
  exit "$status"
}
# The owning full-test harness supplies a fresh guest, never a personal config.
if "${SSH[@]}" "[ -e $config ]"; then fail "config fixture path already exists"; fi
trap cleanup EXIT
sockets="$(mktemp -d "${TMPDIR:-/tmp}/ssh-config-sockets.XXXXXX")"
SSH_CLIENT_HOST_ROOT="$fixture/loopback"
mkdir -m 700 "$SSH_CLIENT_HOST_ROOT"
start_ssh_client_host "$TEST_KEY" 0 /bin:/usr/bin 127.0.0.1
loopback_port="$SSH_CLIENT_HOST_PORT"
cat <&"$SSH_CLIENT_HOST_OUTPUT_FD" > "$fixture/loopback.log" &
loopback_log_pid="$!"
cat > "$fixture/client.cfg" <<EOF
Host moto-hi
  HostName 192.168.4.1
  User motor
  Port $target_port
  IdentityFile $guest/key
Host jumped
  HostName 127.0.0.1
  User motor
  Port $loopback_port
  IdentityFile $guest/key
  ProxyJump moto-hi
Host password-target
  HostName 127.0.0.1
  User motor
  Port $loopback_port
  IdentityFile none
  ProxyJump moto-hi
  BatchMode no
  StrictHostKeyChecking ask
  UserKnownHostsFile $guest/password_hosts
Host *
  UserKnownHostsFile $guest/known_hosts
  StrictHostKeyChecking accept-new
  BatchMode yes
  ConnectTimeout 5
EOF
printf 'mkdir %s\nput %s %s/key\nchmod 600 %s/key\nput %s %s\nput %s %s/alternate\n' \
  "$guest" "$TEST_KEY" "$guest" "$guest" "$fixture/client.cfg" "$config" \
  "$fixture/client.cfg" "$guest" | "${SFTP[@]}" >/dev/null
staged=1
echo '-- Motor client through a host jump --'
out="$("${SSH[@]}" /user/bin/ssh moto-hi /bin/echo direct-alias)"
[ "$out" = direct-alias ] || fail "direct alias returned '$out'"
out="$("${SSH[@]}" /user/bin/ssh jumped /bin/echo jumped-alias)"
[ "$out" = jumped-alias ] || fail "jump alias returned '$out'"
out="$("${SSH[@]}" /user/bin/ssh -F "$guest/alternate" jumped /bin/echo alternate-config)"
[ "$out" = alternate-config ] || fail "alternate config returned '$out'"
out="$("${SSH[@]}" /user/bin/ssh -F none -p "$target_port" -i "$guest/key" \
  -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$guest/known_hosts" \
  motor@192.168.4.1 /bin/echo no-config)"
[ "$out" = no-config ] || fail "-F none returned '$out'"

# This target is on the host's loopback, reachable from the guest only via the jump.
out="$("${SSH[@]}" /user/bin/ssh -J moto-hi -o ProxyJump=none jumped /bin/echo cli-jump)"
[ "$out" = cli-jump ] || fail "-J override returned '$out'"

if "${SSH[@]}" /user/bin/ssh jumped exit 7; then fail "remote status was lost"; else
  [ "$?" -eq 7 ] || fail "remote status was not 7"
fi
dd if=/dev/urandom of="$fixture/payload" bs=1M count=4 status=none
"${SSH[@]}" /user/bin/ssh jumped /bin/cat < "$fixture/payload" > "$fixture/returned"
cmp "$fixture/payload" "$fixture/returned" || fail "jump stream changed data"
printf 'put %s %s/source\n' "$fixture/payload" "$guest" | "${SFTP[@]}" >/dev/null
"${SSH[@]}" /user/bin/scp "$guest/source" "jumped:$fixture/upload"
"${SSH[@]}" /user/bin/scp "jumped:$fixture/upload" "$guest/download"
printf 'get %s %s/sftp-download\n' "$fixture/upload" "$guest" |
  "${SSH[@]}" /user/bin/sftp -b - jumped >/dev/null
printf 'get %s/download %s/download\n' "$guest" "$fixture" | "${SFTP[@]}" >/dev/null
cmp "$fixture/payload" "$fixture/download" || fail "jump scp changed data"
printf 'get %s/sftp-download %s/sftp-download\n' "$guest" "$fixture" | "${SFTP[@]}" >/dev/null
cmp "$fixture/payload" "$fixture/sftp-download" || fail "jump sftp changed data"

out="$(printf 'yes\r\nvroomvroom\r\n' | ssh -F /dev/null -tt -p 2222 -i "$TEST_KEY" \
  -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$KNOWN_HOSTS" motor@192.168.4.2 \
  '/user/bin/ssh -T password-target /bin/echo jump-password-ok')"
printf '%s\n' "$out" | tr -d '\r' | grep -qx jump-password-ok || fail "password through jump failed: '$out'"

cat > "$fixture/host.cfg" <<EOF
Host guest
  HostName 192.168.4.2
  Port 2222
Host tap
  HostName 192.168.4.1
  Port $target_port
Host *
  User motor
  IdentityFile $TEST_KEY
  IdentitiesOnly yes
  UserKnownHostsFile $fixture/host_known
  StrictHostKeyChecking accept-new
  BatchMode yes
  LogLevel ERROR
EOF
echo '-- OpenSSH through the Motor jump --'
out="$(ssh -F "$fixture/host.cfg" -J guest tap /bin/echo guest-jump-ok)"
[ "$out" = guest-jump-ok ] || fail "Motor jump returned '$out'"

# The local Unix socket avoids reserving a host TCP port. The remote side is
# TCP: the guest resolves localhost. from its hosts file and dials port 2222.
echo '-- 100 forwards, local resolution and shell EOF --'
cp "$ROOT_DIR/src/bin/russhd/target/$BUILD/ssh-forwarding-probe" "$fixture/probe"
mkfifo "$fixture/shell.input" "$fixture/shell.output"
exec {shell_input}<>"$fixture/shell.input"
exec {shell_output}<>"$fixture/shell.output"
(
  exec {shell_input}>&-
  exec {shell_output}>&-
  exec ssh -F "$fixture/host.cfg" -T -o ExitOnForwardFailure=yes \
    -L "$sockets/forward.sock:localhost.:2222" guest \
    'read before && echo "$before" && read after && echo "$after"' \
    < "$fixture/shell.input" > "$fixture/shell.output"
) 2>"$fixture/shell.log" &
shell_pid="$!"
printf 'before-forwards\n' >&"$shell_input"
IFS= read -r -t 5 out <&"$shell_output" || fail "forwarding shell did not start"
[ "$out" = before-forwards ] || fail "unexpected initial shell output '$out'"
timeout 10s "$fixture/probe" "$sockets/forward.sock"
printf 'after-forwards\n' >&"$shell_input"
IFS= read -r -t 5 out <&"$shell_output" || fail "forwarding EOF closed shell input"
[ "$out" = after-forwards ] || fail "unexpected later shell output '$out'"
exec {shell_input}>&-
wait "$shell_pid" || fail "forwarding shell failed"
shell_pid=""
exec {shell_output}>&-

echo '-- Motor local TCP forwarding --'
mkfifo "$fixture/local.input" "$fixture/local.output"
exec {local_input}<>"$fixture/local.input"
exec {local_output}<>"$fixture/local.output"
(
  exec {local_input}>&-
  exec {local_output}>&-
  exec "${SSH[@]}" "/user/bin/ssh -L 127.0.0.1:34307:127.0.0.1:$loopback_port \
    -o ExitOnForwardFailure=yes moto-hi \
    'read before && echo \"\$before\" && read after && echo \"\$after\"'" \
    < "$fixture/local.input" > "$fixture/local.output"
) 2>"$fixture/local.log" &
shell_pid="$!"
printf 'local-ready\n' >&"$local_input"
IFS= read -r -t 5 out <&"$local_output" || fail "Motor local-forward session did not start"
[ "$out" = local-ready ] || fail "unexpected local-forward session output '$out'"
# The Motor listener connects through the host peer to its loopback-only server.
out="$("${SSH[@]}" "/user/bin/ssh -p 34307 -i $guest/key \
  -o UserKnownHostsFile=$guest/known_hosts -o StrictHostKeyChecking=accept-new \
  -o BatchMode=yes motor@127.0.0.1 /bin/echo motor-local-forward-ok")"
[ "$out" = motor-local-forward-ok ] || fail "Motor local forward returned '$out'"
printf 'local-still-alive\n' >&"$local_input"
IFS= read -r -t 5 out <&"$local_output" || fail "local-forward EOF stopped the session"
[ "$out" = local-still-alive ] || fail "unexpected later local-forward output '$out'"
exec {local_input}>&-
wait "$shell_pid" || fail "Motor local-forward session failed"
shell_pid=""
exec {local_output}>&-
echo '-- Motor SOCKS forwarding --'
cp "$ROOT_DIR/src/bin/russhd/target/x86_64-unknown-motor/$BUILD/ssh-socks-probe" "$fixture/socks-probe"
printf 'put %s %s/socks-probe\nchmod 700 %s/socks-probe\n' \
  "$fixture/socks-probe" "$guest" "$guest" | "${SFTP[@]}" >/dev/null
mkfifo "$fixture/socks.input" "$fixture/socks.output"
exec {socks_input}<>"$fixture/socks.input"
exec {socks_output}<>"$fixture/socks.output"
(
  exec {socks_input}>&-
  exec {socks_output}>&-
  exec "${SSH[@]}" "/user/bin/ssh -D 127.0.0.1:34308 \
    -o ExitOnForwardFailure=yes moto-hi \
    'read before && echo \"\$before\" && read after && echo \"\$after\"'" \
    < "$fixture/socks.input" > "$fixture/socks.output"
) 2>"$fixture/socks.log" &
shell_pid="$!"
printf 'socks-ready\n' >&"$socks_input"
IFS= read -r -t 5 out <&"$socks_output" || fail "Motor SOCKS session did not start"
[ "$out" = socks-ready ] || fail "unexpected SOCKS session output '$out'"
out="$("${SSH[@]}" "$guest/socks-probe 127.0.0.1:34308 $loopback_port")"
[ "$out" = 'SOCKS forwarding PASS' ] || fail "Motor SOCKS probe returned '$out'"
printf 'socks-still-alive\n' >&"$socks_input"
IFS= read -r -t 5 out <&"$socks_output" || fail "SOCKS EOF stopped the session"
[ "$out" = socks-still-alive ] || fail "unexpected later SOCKS output '$out'"
exec {socks_input}>&-
wait "$shell_pid" || fail "Motor SOCKS session failed"
shell_pid=""
exec {socks_output}>&-
echo '-- Motor server remote TCP forwarding --'
mkfifo "$fixture/server-remote.input" "$fixture/server-remote.output"
exec {remote_input}<>"$fixture/server-remote.input"
exec {remote_output}<>"$fixture/server-remote.output"
(
  exec {remote_input}>&-
  exec {remote_output}>&-
  exec ssh -F "$fixture/host.cfg" -T -o ExitOnForwardFailure=yes \
    -R "127.0.0.1:34309:127.0.0.1:$loopback_port" guest \
    'read before && echo "$before" && read after && echo "$after"' \
    < "$fixture/server-remote.input" > "$fixture/server-remote.output"
) 2>"$fixture/server-remote.log" &
shell_pid="$!"
printf 'server-remote-ready\n' >&"$remote_input"
IFS= read -r -t 5 out <&"$remote_output" || fail "Motor remote listener did not start"
[ "$out" = server-remote-ready ] || fail "unexpected remote-forward session output '$out'"
out="$("${SSH[@]}" "/user/bin/ssh -p 34309 -i $guest/key \
  -o UserKnownHostsFile=$guest/known_hosts -o StrictHostKeyChecking=accept-new \
  -o BatchMode=yes motor@127.0.0.1 /bin/echo motor-server-remote-ok")"
[ "$out" = motor-server-remote-ok ] || fail "Motor server remote forward returned '$out'"
printf 'server-remote-still-alive\n' >&"$remote_input"
IFS= read -r -t 5 out <&"$remote_output" || fail "remote-forward EOF stopped the session"
[ "$out" = server-remote-still-alive ] || fail "unexpected later remote-forward output '$out'"
exec {remote_input}>&-
wait "$shell_pid" || fail "Motor server remote-forward session failed"
shell_pid=""
exec {remote_output}>&-
echo '-- Motor gateway remote forwarding with an allocated port --'
# A separate guest daemon exercises wildcard port allocation without changing
# the shipped loopback policy. Its terminal provides the readiness event.
"${SSH[@]}" /user/bin/cat /user/cfg/sshd.toml |
  sed -e "s/^listen_on = .*/listen_on = '0.0.0.0:34310'/" \
    -e 's/^gateway_ports = .*/gateway_ports = true/' > "$fixture/gateway.toml"
grep -qx 'gateway_ports = true' "$fixture/gateway.toml" || fail "gateway fixture was not enabled"
printf 'put %s %s/gateway.toml\n' "$fixture/gateway.toml" "$guest" | "${SFTP[@]}" >/dev/null
mkfifo "$fixture/gateway.daemon"
"${SSH[@]}" -tt "/system/services/russhd $guest/gateway.toml" \
  < /dev/null > "$fixture/gateway.daemon" 2>&1 &
gateway_pid="$!"
exec {gateway_output}<"$fixture/gateway.daemon"
gateway_ready=0
gateway_deadline=$((SECONDS + 5))
while [ "$SECONDS" -lt "$gateway_deadline" ]; do
  gateway_remaining=$((gateway_deadline - SECONDS))
  IFS= read -r -t "$gateway_remaining" line <&"$gateway_output" || break
  printf '%s\n' "$line" >> "$fixture/gateway-daemon.log"
  case "$line" in
    *'Listening on 0.0.0.0:34310'*) gateway_ready=1; break ;;
  esac
done
[ "$gateway_ready" -eq 1 ] || fail "gateway daemon did not report readiness"
cat <&"$gateway_output" >> "$fixture/gateway-daemon.log" &
gateway_log_pid="$!"
exec {gateway_output}<&-
mkfifo "$fixture/gateway.input" "$fixture/gateway.output"
exec {gateway_input}<>"$fixture/gateway.input"
exec {gateway_result}<>"$fixture/gateway.output"
(
  exec {gateway_input}>&-
  exec {gateway_result}>&-
  exec ssh -F "$fixture/host.cfg" -p 34310 -T -o LogLevel=INFO \
    -o ExitOnForwardFailure=yes -R "0:127.0.0.1:$loopback_port" guest \
    'read before && echo "$before" && read after && echo "$after"' \
    < "$fixture/gateway.input" > "$fixture/gateway.output"
) 2>"$fixture/gateway.log" &
shell_pid="$!"
printf 'gateway-ready\n' >&"$gateway_input"
IFS= read -r -t 5 out <&"$gateway_result" || fail "gateway forwarding session did not start"
[ "$out" = gateway-ready ] || fail "unexpected gateway session output '$out'"
gateway_port="$(sed -n 's/^Allocated port \([0-9][0-9]*\) for remote forward to .*$/\1/p' "$fixture/gateway.log")"
[[ "$gateway_port" =~ ^[0-9]+$ ]] || fail "missing allocated gateway port"
[ "$gateway_port" -ge 49152 ] && [ "$gateway_port" -le 65535 ] ||
  fail "allocated gateway port is outside the selected range"
# Reaching the guest from the tap proves this listener is a wildcard bind.
out="$(ssh -F /dev/null -p "$gateway_port" -i "$TEST_KEY" -o IdentitiesOnly=yes \
  -o UserKnownHostsFile="$fixture/gateway-known" -o StrictHostKeyChecking=accept-new \
  -o BatchMode=yes -o LogLevel=ERROR motor@192.168.4.2 /bin/echo motor-gateway-ok)"
[ "$out" = motor-gateway-ok ] || fail "gateway forward returned '$out'"
out="$("${SSH[@]}" "/user/bin/ssh -p $gateway_port -i $guest/key \
  -o UserKnownHostsFile=$guest/known_hosts -o StrictHostKeyChecking=accept-new \
  -o BatchMode=yes 'motor@[::1]' /bin/echo motor-gateway-ipv6-ok")"
[ "$out" = motor-gateway-ipv6-ok ] || fail "gateway IPv6 forward returned '$out'"
printf 'gateway-still-alive\n' >&"$gateway_input"
IFS= read -r -t 5 out <&"$gateway_result" || fail "gateway-forward EOF stopped the session"
[ "$out" = gateway-still-alive ] || fail "unexpected later gateway output '$out'"
exec {gateway_input}>&-
wait "$shell_pid" || fail "gateway-forward session failed"
shell_pid=""
exec {gateway_result}>&-
echo '-- Motor client remote TCP forwarding --'
mkfifo "$fixture/client-remote.input" "$fixture/client-remote.output"
exec {remote_input}<>"$fixture/client-remote.input"
exec {remote_output}<>"$fixture/client-remote.output"
(
  exec {remote_input}>&-
  exec {remote_output}>&-
  exec "${SSH[@]}" "/user/bin/ssh -R 127.0.0.1:34311:localhost.:2222 \
    -o ExitOnForwardFailure=yes moto-hi \
    'read before && echo \"\$before\" && read after && echo \"\$after\"'" \
    < "$fixture/client-remote.input" > "$fixture/client-remote.output"
) 2>"$fixture/client-remote.log" &
shell_pid="$!"
printf 'client-remote-ready\n' >&"$remote_input"
IFS= read -r -t 5 out <&"$remote_output" || fail "Motor remote-forward session did not start"
[ "$out" = client-remote-ready ] || fail "unexpected remote-forward session output '$out'"
# The host listener reaches the guest's SSH server through the Motor client.
out="$(ssh -F /dev/null -p 34311 -i "$TEST_KEY" -o IdentitiesOnly=yes \
  -o UserKnownHostsFile="$fixture/client-remote-known" -o StrictHostKeyChecking=accept-new \
  -o BatchMode=yes -o LogLevel=ERROR motor@127.0.0.1 /user/bin/echo motor-client-remote-ok)"
[ "$out" = motor-client-remote-ok ] || fail "Motor remote forward returned '$out'"
printf 'client-remote-still-alive\n' >&"$remote_input"
IFS= read -r -t 5 out <&"$remote_output" || fail "remote-forward EOF stopped the session"
[ "$out" = client-remote-still-alive ] || fail "unexpected later remote-forward output '$out'"
exec {remote_input}>&-
wait "$shell_pid" || fail "Motor remote-forward session failed"
shell_pid=""
exec {remote_output}>&-
echo "test-ssh-config: PASS"
)

cross_prepare_programs() {
  local profile=()
  [ "$BUILD" != release ] || profile=(--release)
  [ "$VMM" != qemu ] || ensure_vsock_backend
  (cd "$ROOT_DIR/src/bin/russhd" && cargo build --locked --offline "${profile[@]}" --features cross-test-support --bins)
  (cd "$ROOT_DIR/src/bin/russhd" && cargo build --locked --offline "${profile[@]}" --features cross-test-support --target x86_64-unknown-motor --bin ssh-socks-probe)
  (cd "$ROOT_DIR/src/bin/rnetbench" && cargo build --release --locked --offline)
  (cd "$ROOT_DIR/src/sys/tools/wg/host-peer" && cargo build --release --locked --offline)
  cross_prepare_console_programs
  if [ "$VMM" != fc ]; then
    for crate in javy-smoke wasmtime-smoke; do
      (cd "$ROOT_DIR/src/sys/tests/$crate" && cargo build --release --locked --offline \
        --target x86_64-unknown-motor --bin "$crate")
    done
  fi
}

# The programs cross_upload_programs and cross_system_console need.
cross_prepare_console_programs() {
  local profile=()
  [ "$BUILD" != release ] || profile=(--release)
  (cd "$ROOT_DIR/src/sys/tests/cross-peer" && cargo build --locked --offline "${profile[@]}")
  (cd "$ROOT_DIR/src/bin/rush" && cargo test --no-run --locked --offline "${profile[@]}" \
    --target x86_64-unknown-motor --test motor_caps --message-format=json) > "$RUN_DIR/rush-caps.json"
  RUSH_CAPS_PROBE="$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "motor_caps") | .executable' "$RUN_DIR/rush-caps.json")"
  [ -x "$RUSH_CAPS_PROBE" ] || cross_fail 'Rush capability probe was not built'
  cargo test --manifest-path "$ROOT_DIR/src/sys/tools/sysbox/Cargo.toml" --no-run --locked --offline \
    "${profile[@]}" --target x86_64-unknown-motor --test commands --message-format=json > "$RUN_DIR/sysbox-commands.json"
  SYSBOX_COMMAND_PROBE="$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "commands") | .executable' "$RUN_DIR/sysbox-commands.json")"
  [ -x "$SYSBOX_COMMAND_PROBE" ] || cross_fail 'sysbox command harness was not built'
}

cross_upload_programs() {
  TEST_TMP=/user/tmp/motor-tests
  NONE_TEST_ROOT=/none/tmp/motor-tests
  NONE_TEST_TMP="$NONE_TEST_ROOT/tmp"
  TEST_BIN="$NONE_TEST_ROOT/tests"
  MOTOR_TEST_ROOT="$NONE_TEST_ROOT"
  export MOTOR_TEST_ROOT MOTOR_TEST_TMP="$TEST_TMP" MOTOR_NONE_TEST_TMP="$NONE_TEST_TMP"
  vm_ssh "mkdir -p $TEST_TMP $NONE_TEST_TMP $TEST_BIN"
  local name
  for name in systest crossterm-smoke wg-self-test rnetbench; do
    printf 'put "%s" "%s/%s"\nchmod 755 "%s/%s"\n' \
      "$ROOT_DIR/build/bin/$BUILD/$name" "$TEST_BIN" "$name" "$TEST_BIN" "$name" | vm_sftp
  done
  printf 'put "%s" "%s/rush-caps"\nchmod 755 "%s/rush-caps"\n' \
    "$RUSH_CAPS_PROBE" "$TEST_BIN" "$TEST_BIN" | vm_sftp
}

cross_ssh_checks() (
  fail() { cross_fail "$@"; }
  trap 'stop_ssh_client_host' EXIT
  cross_ssh_client
  cross_sftp
  test_ssh_client_host
  [ "$(vm_ssh 'pwd')" = /user ] || cross_fail 'SSH session started in the wrong directory'
  [ "$(vm_ssh /user/bin/printenv HOME)" = HOME=/user ] || cross_fail 'SSH HOME is wrong'
  [ "$(vm_ssh /user/bin/printenv TMPDIR)" = TMPDIR=/user/tmp ] || cross_fail 'SSH TMPDIR is wrong'
  [ "$(vm_ssh 'TMPDIR=/chosen/tmp printenv TMPDIR')" = TMPDIR=/chosen/tmp ] || cross_fail 'explicit TMPDIR was replaced'
  local status=0
  vm_ssh 'echo ssh-stdout; echo ssh-stderr >&2; exit 7' > "$RUN_DIR/ssh.stdout" 2> "$RUN_DIR/ssh.stderr" || status=$?
  [ "$status" = 7 ] || cross_fail 'SSH lost command exit status'
  [ "$(cat "$RUN_DIR/ssh.stdout")" = ssh-stdout ] || cross_fail 'SSH stdout was not separate'
  grep -qx ssh-stderr "$RUN_DIR/ssh.stderr" || cross_fail 'SSH stderr was not separate'
)

cross_system_console() {
  if [ "$VMM" = qemu ]; then
    echo 'SKIP QEMU: System console, System capabilities, MMIO and System OOM tests'
    return
  fi
  copy_test_image "$CROSS_IMAGE" system
  boot_test_image system --system-tty
  wait_vm_ssh
  cross_upload_programs
  if [ "$BUILD" = debug ]; then
    vm_ssh "$TEST_BIN/systest live-filesystem-tests"
    console_status "MOTOR_OS_CAPS=0x5 $TEST_BIN/systest live-filesystem-tests" FS_WITHOUT_WRITE_STATUS
    console_status "MOTOR_OS_CAPS=0x205 $TEST_BIN/systest live-filesystem-tests" LIVE_FS_STATUS
  fi
  printf 'put "%s" "%s/sysbox-commands"\n' "$SYSBOX_COMMAND_PROBE" "$TEST_BIN" | vm_sftp
  local CHECK_STDERR="$ROOT_DIR/src/sys/tests/cross-peer/target/$BUILD/console-stderr"
  wait_guest_file() {
    local path="$1"
    for _ in $(seq 1 120); do
      if vm_ssh "[ -e $path ]" >/dev/null 2>&1; then
        return
      fi
      if ! vm_alive; then
        cat "$CONSOLE_LOG" >&2
        cross_fail "$VMM exited while waiting for '$path'"
      fi
      sleep 0.5
    done
    cross_fail "console did not create '$path' (log: $CONSOLE_LOG)"
  }
  
  run_console() {
    local marker="$1"
    local command="$2"
    printf '%s; echo done > %s\r' "$command" "$marker" >&"$VM_SERIAL_FD"
    wait_guest_file "$marker"
  }
  
  has_system_process() {
    local process="$1"
    awk -v process="$process" '
      $1 ~ /\*$/ {
        for (i = 1; i <= NF; i++) {
          if ($i == process) {
            found = 1
          }
        }
      }
      END { exit !found }
    '
  }
  
  run_console /user/tmp/system-tty-ps-done \
    '/user/bin/sysbox ps > /user/tmp/system-tty-ps'
  run_console /user/tmp/system-tty-shim-done \
    'echo shim > /user/tmp/system-tty-shim; chmod r-xr-xr-- /user/tmp/system-tty-shim'
  run_console /user/tmp/system-tty-direct-done \
    'echo direct > /user/tmp/system-tty-direct; /user/bin/sysbox chmod r-xr--r-- /user/tmp/system-tty-direct'
  run_console /user/tmp/system-tty-defaults-done \
    'echo default > /user/tmp/system-tty-default-file; /user/bin/mkdir /user/tmp/system-tty-default-dir'
  run_console /user/tmp/system-tty-script-v1-done \
    "echo '#!/user/bin/rush' > /user/tmp/system-tty-script; echo 'echo V1 > /user/tmp/system-tty-script-v1' >> /user/tmp/system-tty-script; chmod r-xr--r-- /user/tmp/system-tty-script; /user/tmp/system-tty-script"
  run_console /user/tmp/system-tty-script-edit-done \
    "echo 'echo EDITED > /user/tmp/system-tty-edit-succeeded' >> /user/tmp/system-tty-script; chmod rw-r--r-- /user/tmp/system-tty-script; /user/tmp/system-tty-script; /user/bin/rm /user/tmp/system-tty-script"
  run_console /user/tmp/system-tty-script-done \
    "echo '#!/user/bin/rush' > /user/tmp/system-tty-script; echo 'echo V2 > /user/tmp/system-tty-script-v2' >> /user/tmp/system-tty-script; chmod r-xr--r-- /user/tmp/system-tty-script; /user/tmp/system-tty-script"
  
  # The ordinary SSH shell cannot grant System authority.
  # The binary goes in /none/tmp so that its None-role children can run it.
  run_console /user/tmp/capability-mode-done \
    'chmod r-xr-xr-x /none/tmp/motor-tests/tests/systest /none/tmp/motor-tests/tests/sysbox-commands'
  run_console /user/tmp/findmnt-done \
    'MOTOR_OS_CAPS=0x205 /none/tmp/motor-tests/tests/sysbox-commands findmnt /user/bin/sysbox > /user/tmp/findmnt.log; echo $? > /user/tmp/findmnt.status'
  test "$(ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2 'cat /user/tmp/findmnt.status')" = 0 ||
    cross_fail "System findmnt tests failed"
  # CAP_SYS does not substitute for the sys-io bits: a System parent without
  # CAP_NET cannot grant it, a System child without CAP_FS_WRITE is refused
  # writes, and the System process itself is refused network access.
  run_console /user/tmp/system-caps-done \
    'MOTOR_OS_CAPS=0x20d /none/tmp/motor-tests/tests/systest system-caps-tests > /user/tmp/system-caps.log 2> /user/tmp/system-caps.err; echo $? > /user/tmp/system-caps.status'
  system_caps_status="$(vm_ssh /user/bin/cat /user/tmp/system-caps.status)"
  system_caps_output="$(vm_ssh /user/bin/cat /user/tmp/system-caps.log)"
  # Debug runtimes log to stderr, so it is kept apart from the verdict.
  [ "$system_caps_status" = "0" ] ||
    cross_fail "System capability tests exited $system_caps_status: '$system_caps_output' $(vm_ssh /user/bin/cat /user/tmp/system-caps.err)"
  [ "$system_caps_output" = $'kernel command-line query PASS\nspawn_wait_kill::test_system_parent_cannot_grant_unheld PASS\nfs_permissions::test_write_capability(System) PASS\nnet_caps::check_denied(System) PASS' ] ||
    cross_fail "System capability tests did not finish: '$system_caps_output'"
  printf '%s\n' "$system_caps_output"
  
  # Prepare through SSH, then observe serial output without starting SSH commands
  # during pressure. The helper needs System authority and preallocates its tests.
  printf '/none/tmp/motor-tests/tests/systest system-oom-tests; echo OOM_TEST_STATUS=$?\r' >&"$VM_SERIAL_FD"
  oom_done=0
  for _ in $(seq 1 120); do
    if grep -aq 'oom::run_all_tests PASS' "$CONSOLE_LOG"; then
      oom_done=1
      break
    fi
    if grep -aqE 'OOM_TEST_STATUS=(-[0-9]|[1-9])' "$CONSOLE_LOG"; then
      tail -80 "$CONSOLE_LOG" >&2
      cross_fail "OOM helper failed (log: $CONSOLE_LOG)"
    fi
    vm_alive || cross_fail "$VMM exited during OOM tests (log: $CONSOLE_LOG)"
    sleep 0.25
  done
  [ "$oom_done" = 1 ] || cross_fail "OOM tests did not finish (log: $CONSOLE_LOG)"
  echo 'oom::run_all_tests PASS'
  
  # WireGuard derives roles from the complete capability word, including when
  # CAP_SYS and CAP_INTERACTIVE are both present. This needs the System console.
  run_console /user/tmp/wg-role-done \
    'MOTOR_OS_CAPS=0x365 /none/tmp/motor-tests/tests/wg-self-test system > /user/tmp/wg-role.log 2> /user/tmp/wg-role.err; echo $? > /user/tmp/wg-role.status'
  wg_role_status="$(vm_ssh /user/bin/cat /user/tmp/wg-role.status)"
  wg_role_output="$(vm_ssh /user/bin/cat /user/tmp/wg-role.log)"
  [ "$wg_role_status" = 0 ] ||
    cross_fail "WireGuard role tests exited $wg_role_status: '$wg_role_output' $(vm_ssh /user/bin/cat /user/tmp/wg-role.err)"
  [ "$wg_role_output" = 'wg-tool System role and permission preservation PASS' ] ||
    cross_fail "WireGuard role tests did not finish: '$wg_role_output'"
  printf '%s\n' "$wg_role_output"
  
  # An exported mask wins over Rush's ordinary System grant, even when it omits
  # CAP_NET; without one, the grant keeps the console's own bits.
  run_console /user/tmp/rush-caps-done \
    '/user/bin/rush -c "export MOTOR_OS_CAPS=0x205; /none/tmp/motor-tests/tests/rush-caps print-caps exported > /user/tmp/rush-caps.log"; /none/tmp/motor-tests/tests/rush-caps print-caps ordinary >> /user/tmp/rush-caps.log'
  rush_caps="$(vm_ssh /user/bin/cat /user/tmp/rush-caps.log)"
  [ "$rush_caps" = $'exported=0x205\nordinary=0x38d' ] ||
    cross_fail "System Rush capability precedence: '$rush_caps'"
  printf 'System Rush capability precedence: %s\n' "${rush_caps//$'\n'/ }"
  
  # The checker distinguishes an unfinished live log from an ordering failure.
  # A complete prompt before the expected tail fails immediately.
  wait_console_burst() {
    local offset="$1" burst="$2" phase="$3" status
    for _ in $(seq 1 100); do
      if "$CHECK_STDERR" "$CONSOLE_LOG" "$offset" "$burst" "$phase"; then
        return
      else
        status=$?
        [ "$status" -eq 2 ] || cross_fail "stderr burst $burst failed (log: $CONSOLE_LOG)"
      fi
      vm_alive || cross_fail "$VMM exited during stderr burst $burst"
      sleep 0.1
    done
    cross_fail "stderr burst $burst did not reach $phase (log: $CONSOLE_LOG)"
  }
  
  run_console /user/tmp/stderr-burst-save-prompt 'tty_saved_ps1="$PS1"'
  for burst in $(seq 1 11); do
    lines=24
    [ "$burst" -ne 11 ] || lines=512 # Exceeds the old 16 KiB backlog.
    offset="$(wc -c < "$CONSOLE_LOG")"
    # Adjacent quoted words keep the full prompt token out of the command echo.
    printf "PS1='[TTY-BURST-''%s] '; /none/tmp/motor-tests/tests/systest stderr-burst %s %s\r" \
      "$burst" "$burst" "$lines" >&"$VM_SERIAL_FD"
    wait_console_burst "$offset" "$burst" ready
    printf '!' >&"$VM_SERIAL_FD"
    wait_console_burst "$offset" "$burst" "$lines"
    echo "console stderr burst $burst: $lines intact lines before the prompt"
  done
  run_console /user/tmp/stderr-burst-restore-prompt 'PS1="$tty_saved_ps1"'
  
  ps_output="$(vm_ssh /user/bin/cat /user/tmp/system-tty-ps)"
  listing="$(vm_ssh /user/bin/ls -l /user/tmp)"
  printf '%s\n' "$ps_output" | has_system_process /system/services/sys-tty ||
    cross_fail "sys-tty is not System: '$ps_output'"
  printf '%s\n' "$ps_output" | has_system_process /user/bin/rush ||
    cross_fail "the console shell is not System: '$ps_output'"
  printf '%s\n' "$ps_output" | has_system_process /user/bin/sysbox ||
    cross_fail "an ordinary external command did not retain System: '$ps_output'"
  
  # Only a System parent may grant CAP_IO_MANAGER. The ordinary SSH shell
  # deliberately cannot launch this test with its required 0x24e mask.
  # The child is Interactive, so its redirected output must be writable by
  # that role, not just by the System shell creating the redirection.
  vm_ssh 'echo -n > /user/tmp/mmio-validation.log'
  run_console /user/tmp/mmio-validation-done \
    'MOTOR_OS_CAPS=0x24e /none/tmp/motor-tests/tests/systest mmio-validation-tests > /user/tmp/mmio-validation.log 2>&1; echo $? > /user/tmp/mmio-validation.status'
  mmio_status="$(vm_ssh /user/bin/cat /user/tmp/mmio-validation.status)"
  mmio_output="$(vm_ssh /user/bin/cat /user/tmp/mmio-validation.log)"
  [ "$mmio_status" = "0" ] || cross_fail "MMIO validation exited $mmio_status: '$mmio_output'"
  [ "$mmio_output" = "mmio::validation_tests PASS" ] ||
    cross_fail "MMIO validation did not finish: '$mmio_output'"
  printf '%s\n' "$mmio_output"
  
  for mmio_case in mmio-unmap-suite mmio-unmap-fault; do
    vm_ssh "echo -n > /user/tmp/$mmio_case.log"
    run_console "/user/tmp/$mmio_case-done" \
      "MOTOR_OS_CAPS=0x24e /none/tmp/motor-tests/tests/systest $mmio_case > /user/tmp/$mmio_case.log 2>&1; echo \$? > /user/tmp/$mmio_case.status"
    mmio_status="$(vm_ssh /user/bin/cat /user/tmp/$mmio_case.status)"
    mmio_output="$(vm_ssh /user/bin/cat /user/tmp/$mmio_case.log)"
    if [ "$mmio_case" = mmio-unmap-suite ]; then
      [ "$mmio_status" = 0 ] && [ "$mmio_output" = 'mmio::ownership_tests PASS' ] ||
        cross_fail "MMIO ownership: status=$mmio_status output='$mmio_output'"
    else
      [ "$mmio_status" = -1 ] && [ "$mmio_output" = 'mmio::unmap_fault READY' ] ||
        cross_fail "MMIO fault: status=$mmio_status output='$mmio_output'"
    fi
    printf '%s: status=%s %s\n' "$mmio_case" "$mmio_status" "$mmio_output"
  done
  
  printf '%s\n' "$listing" |
    grep -aqE -- '-r-xr-xr--[[:space:]]+[0-9]+[[:space:]]+system-tty-shim$' ||
    cross_fail "the chmod shim did not install the exact mode"
  printf '%s\n' "$listing" |
    grep -aqE -- '-r-xr--r--[[:space:]]+[0-9]+[[:space:]]+system-tty-direct$' ||
    cross_fail "sysbox chmod did not install the exact mode"
  printf '%s\n' "$listing" |
    grep -aqE -- '-rw-r--r--[[:space:]]+[0-9]+[[:space:]]+system-tty-default-file$' ||
    cross_fail "System-created file did not use the creator-relative default"
  printf '%s\n' "$listing" |
    grep -aqE -- 'drwxr-xr-x[[:space:]]+system-tty-default-dir$' ||
    cross_fail "System-created directory did not use the creator-relative default"
  vm_ssh '[ -e /user/tmp/system-tty-script-v1 ]' ||
    cross_fail "the finalized System-role script did not run"
  vm_ssh '[ -e /user/tmp/system-tty-script-v2 ]' ||
    cross_fail "the replacement System-role script did not run"
  if vm_ssh '[ -e /user/tmp/system-tty-edit-succeeded ]'; then
    cross_fail "the finalized System-role script remained writable"
  fi
  printf '%s\n' "$listing" |
    grep -aqE -- '-r-xr--r--[[:space:]]+[0-9]+[[:space:]]+system-tty-script$' ||
    cross_fail "the finalized System-role script regained write permission"
  
  # A copied capability probe uses the configured pass-list name. Its output
  # checks Rush's System grant without running a terminal application here.
  vm_ssh "mkdir $TEST_TMP/pass-list && cp $TEST_BIN/rush-caps $TEST_TMP/pass-list/rmux"
  run_console /user/tmp/pass-list-done \
    "$TEST_TMP/pass-list/rmux print-caps passlisted > /user/tmp/pass-list.log"
  [ "$(vm_ssh cat /user/tmp/pass-list.log)" = passlisted=0x3ad ] ||
    cross_fail 'Rush did not preserve System while granting detached spawn'
  shutdown_test_image
}

# Shared deterministic local-tap fragmentation regression.

UDP_FRAGMENT_ECHO_PROCESS=""

stop_udp_fragment_echo() {
  if [ -n "$UDP_FRAGMENT_ECHO_PROCESS" ]; then
    kill "$UDP_FRAGMENT_ECHO_PROCESS" 2>/dev/null || true
    wait "$UDP_FRAGMENT_ECHO_PROCESS" 2>/dev/null || true
    UDP_FRAGMENT_ECHO_PROCESS=""
  fi
}

test_udp_fragmentation() {
  local echo_bin="$ROOT_DIR/src/sys/tests/cross-peer/target/$BUILD/udp-fragment-echo"
  local test_binary="$MOTOR_TEST_ROOT/tests/systest"
  local port
  local status=0

  echo "-- local-tap UDP fragmentation --"

  coproc UDP_FRAGMENT_ECHO { exec "$echo_bin"; }
  UDP_FRAGMENT_ECHO_PROCESS="$UDP_FRAGMENT_ECHO_PID"
  if ! read -r -t 5 port <&"${UDP_FRAGMENT_ECHO[0]}"; then
    stop_udp_fragment_echo
    fail "host UDP fragmentation echo did not become ready"
  fi
  case "$port" in
    ""|*[!0-9]*) fail "host UDP fragmentation echo returned bad port '$port'" ;;
  esac

  vm_ssh "$test_binary test-tap-udp-fragmentation 192.168.4.1:$port"
  vm_ssh "$test_binary test-tap-udp-fragmentation [2001:db8::1]:$port"

  wait "$UDP_FRAGMENT_ECHO_PROCESS" || status="$?"
  UDP_FRAGMENT_ECHO_PROCESS=""
  [ "$status" -eq 0 ] || fail "host UDP fragmentation echo failed (status $status)"
  echo "-- local-tap UDP fragmentation PASS"
}

# Sourced by full-test.sh with its existing VM, SSH helper and test directories.
test_wireguard_case() (
  set -euo pipefail
  umask 077
  local work peer_pid="" wg_pid="" stale_pid="" peer_in peer_out wg_in wg_out
  local stale_in stale_out guest_pid="" line provider_id learned_endpoint=""
  local name="wg_gate_${BASHPID}" config uploaded=0
  local peer_binary="${WG_PEER_BINARY:-$ROOT_DIR/src/sys/tools/wg/host-peer/target/release/wg-peer}"
  local bind=192.168.4.1:0 roam='[2001:db8::1]:0'
  local roam_endpoint='[2001:db8::2]:51820'
  local guest_endpoint=192.168.4.2:51820 role="$2"
  if [ "$1" = ipv6 ]; then
    bind='[2001:db8::1]:0'
    roam=192.168.4.1:0
    roam_endpoint=192.168.4.2:51820
    guest_endpoint='[2001:db8::2]:51820'
  fi
  local peer_args=()
  [ "$role" != host ] || peer_args=(--endpoint "$guest_endpoint")
  work="$(mktemp -d /tmp/test-wireguard.XXXXXX)"
  config="/user/cfg/wireguard/$name.toml"
  [ "$role" != managed ] || config="/user/cfg/wireguard/$name-office.toml"
  cleanup_wireguard() {
    local status=$?
    trap - EXIT
    if [ -n "$stale_pid" ]; then
      kill "$stale_pid" 2>/dev/null || true
      wait "$stale_pid" 2>/dev/null || true
    fi
    if [ -n "$wg_pid" ]; then
      kill "$wg_pid" 2>/dev/null || true
      wait "$wg_pid" 2>/dev/null || true
    fi
    if [ "$role" = managed ] && [ -n "$guest_pid" ]; then
      vm_ssh "/user/bin/wg-tool down $name" || true
    fi
    if [ -n "$peer_pid" ]; then
      kill "$peer_pid" 2>/dev/null || true
      wait "$peer_pid" 2>/dev/null || true
    fi
    if [ "$uploaded" = 1 ]; then
      vm_ssh "/user/bin/rm $config" || true
    fi
    rm -rf "$work"
    exit "$status"
  }
  trap cleanup_wireguard EXIT

  if [ "$role" = plain ]; then
    peer_args=(--plain --endpoint "$guest_endpoint")
    name=wg_plain
  else
    "$peer_binary" keygen "$work/host.key" "$work/host.pub"
    if [ "$role" = managed ]; then
      local created
      created="$(printf '%s\n' "$name" "$config" 51820 '10.250.20.2/24, fd50:20::2/64' \
        '192.168.4.2, 2001:db8::2' yes | vm_ssh '/user/bin/wg-tool new')"
      uploaded=1
      printf '%s\n' "$created"
      printf '%s\n' "$created" | awk '/^Public key: / {print $3}' > "$work/guest.pub"
      [ "$(wc -c < "$work/guest.pub")" = 45 ] || fail 'wg-tool new omitted the public key'
      vm_ssh "[ ! -e /user/cfg/wireguard/$name-office.key ]" || fail 'wg-tool created a key sidecar'
    else
      "$peer_binary" keygen "$work/guest.key" "$work/guest.pub"
    fi
    peer_args+=(--private-key "$work/host.key" --peer-key "$work/guest.pub")
  fi
  coproc WG_GATE_PEER {
    exec "$peer_binary" serve --bind "$bind" \
      --address 10.250.20.1/24 --address fd50:20::1/64 \
      "${peer_args[@]}"
  }
  peer_pid="$WG_GATE_PEER_PID"
  exec {peer_in}>&"${WG_GATE_PEER[1]}"
  exec {peer_out}<&"${WG_GATE_PEER[0]}"
  local banner endpoint
  IFS= read -r -t 5 banner <&"$peer_out" || fail "WireGuard host peer did not become ready"
  case "$banner" in
    "READY "*) endpoint="${banner#READY }" ;;
    *) fail "unexpected WireGuard peer banner: $banner" ;;
  esac
  local guest_command="$TEST_BIN/systest ip-device-plain $guest_endpoint $endpoint"
  if [ "$role" = managed ]; then
    printf '%s\n' 'hermetic host' "$(cat "$work/host.pub")" "$endpoint" \
      '10.250.20.0/24, fd50:20::/64' 0 '' yes | vm_ssh "/user/bin/wg-tool add-peer $config"
  elif [ "$role" != plain ]; then
    guest_command="/user/bin/wg $config"
    cat > "$work/config.toml" <<EOF
name = "$name"
private_key = "$(cat "$work/guest.key")"
transport_addresses = ["192.168.4.2", "2001:db8::2"]
listen_port = 51820
cidrs = ["10.250.20.2/24", "fd50:20::2/64"]
[[peers]]
public_key = "$(cat "$work/host.pub")"
allowed_ips = ["10.250.20.0/24", "fd50:20::/64"]
EOF
    if [ "$role" = guest ]; then
      printf 'endpoint = "%s"\n' "$endpoint" >> "$work/config.toml"
    fi
    vm_ssh "/user/bin/rush -c 'if [ ! -d /user/cfg/wireguard ]; then mkdir /user/cfg/wireguard; chmod rwxrwx--- /user/cfg/wireguard; fi'"
    printf 'put %s %s\nchmod 660 %s\n' "$work/config.toml" "$config" "$config" > "$work/upload"
    uploaded=1
    sftp -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
      -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS" \
      -i "$TEST_KEY" -b "$work/upload" motor@192.168.4.2
  fi
  if [ "$role" != plain ]; then
    vm_ssh "$TEST_BIN/systest wireguard-permissions $config"
    vm_ssh "$TEST_BIN/systest wireguard-readable-secrets $config"
  fi
  vm_ssh "$TEST_BIN/systest wireguard-cleanup"

  mkfifo "$work/wg.in" "$work/wg.out"
  exec {wg_in}<>"$work/wg.in"
  start_wireguard() {
    if [ "$role" = managed ]; then
      line="$(vm_ssh "/user/bin/wg-tool up $config")"
      printf '%s\n' "$line"
      [[ "$line" =~ pid=([0-9]+) ]] || fail 'wg-tool up omitted its process id'
      guest_pid="${BASH_REMATCH[1]}"
      # The launcher and its SSH session have both exited before any traffic.
      vm_ssh '/user/bin/wg-tool status'
      return
    fi
    ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 "$guest_command" \
      < "$work/wg.in" > "$work/wg.out" 2>&1 &
    wg_pid="$!"
    exec {wg_out}<"$work/wg.out"
    local deadline=$((SECONDS + 5)) active=0
    while [ "$SECONDS" -lt "$deadline" ]; do
      IFS= read -r -t "$((deadline - SECONDS))" line <&"$wg_out" || break
      printf '%s\n' "$line"
      case "$line" in *"$name: active"*) active=1; break ;; esac
    done
    [ "$active" = 1 ] || fail "WireGuard did not activate"
    [[ "$line" =~ pid=([0-9]+) ]] || fail "WireGuard omitted its process id"
    guest_pid="${BASH_REMATCH[1]}"
  }
  stop_wireguard() {
    if [ "$role" = managed ]; then
      vm_ssh "/user/bin/wg-tool down $name"
      guest_pid=""
      vm_ssh "$TEST_BIN/systest wireguard-cleanup"
      return
    fi
    printf '\003' >&"$wg_in"
    cat <&"$wg_out"
    exec {wg_out}<&-
    local status=0
    wait "$wg_pid" || status="$?"
    wg_pid=""
    [ "$status" = 130 ] || fail "WireGuard exited with status $status"
    vm_ssh "$TEST_BIN/systest wireguard-cleanup"
  }
  start_wireguard

  peer_ping() {
    local address="$1" response
    printf 'ping %s\n' "$address" >&"$peer_in"
    IFS= read -r -t 5 response <&"$peer_out" || fail "peer ping did not start"
    [ "$response" = "PING-START $address" ] || fail "unexpected peer response: $response"
    IFS= read -r -t 5 response <&"$peer_out" || fail "peer ping did not finish"
    [ "$response" = "PING OK" ] || fail "peer could not ping the guest: $response"
  }
  if [ "$role" = host ]; then
    peer_ping 10.250.20.2
  fi
  if [ "$role" != plain ] && [ "${WG_BENCHMARK:-0}" != 1 ]; then
    printf 'padding on\n' >&"$peer_in"
    IFS= read -r -t 5 line <&"$peer_out" || fail "peer did not enable padding"
    [ "$line" = 'PADDING ON' ] || fail "unexpected peer response: $line"
  fi
  for inner in 10.250.20.1 fd50:20::1; do
    vm_ssh "/user/bin/ping -c 1 $inner"
  done
  vm_ssh "$TEST_BIN/systest wireguard-client 10.250.20.1 10.250.20.2"
  if [ "$1" = ipv6 ] && [ "$role" != plain ] && [ "${WG_BENCHMARK:-0}" != 1 ]; then
    vm_ssh "$TEST_BIN/systest wireguard-fragmented-reply"
  else
    vm_ssh "$TEST_BIN/systest wireguard-client fd50:20::1 fd50:20::2"
  fi
  peer_ping 10.250.20.2
  peer_ping fd50:20::2

  if [ "${WG_BENCHMARK:-0}" = 1 ]; then
    vm_ssh "$TEST_BIN/systest wireguard-measure $guest_pid 10.250.20.1:40000"
    if [ "$role" != plain ]; then
      provider_id="$(vm_ssh '/user/bin/sysbox stats providers' |
        awk -v name="wg:$guest_pid" '$2 == name {print $1}')"
      [ -n "$provider_id" ] || fail "WireGuard statistics provider is missing"
      vm_ssh "/user/bin/sysbox stats get $provider_id"
    fi
    vm_ssh '/user/bin/sysbox stats get 2'
    printf 'stats\n' >&"$peer_in"
    IFS= read -r -t 5 line <&"$peer_out" || fail "peer did not report benchmark counters"
    case "$line" in STATS\ *) printf 'host peer %s\n' "$line" ;; *) fail "unexpected peer counters: $line" ;; esac
  elif [ "$role" != plain ]; then
    # Invalid traffic from a new outer address cannot authenticate a move.
    printf 'roam %s %s\n' "$roam" "$roam_endpoint" >&"$peer_in"
    IFS= read -r -t 5 line <&"$peer_out" || fail "peer did not change transport"
    case "$line" in "ROAM "*) ;; *) fail "unexpected peer response: $line" ;; esac
    learned_endpoint="${line#ROAM }"
    for invalid in replay tamper malformed; do
      printf '%s\n' "$invalid" >&"$peer_in"
      IFS= read -r -t 5 line <&"$peer_out" || fail "peer did not send $invalid"
      [ "$line" = "SENT $invalid" ] || fail "unexpected peer response: $line"
    done
    vm_ssh "$TEST_BIN/systest wireguard-rejections $guest_pid"
    printf 'keepalive\n' >&"$peer_in"
    IFS= read -r -t 5 line <&"$peer_out" || fail "peer did not send keepalive"
    [ "$line" = KEEPALIVE ] || fail "unexpected peer response: $line"
    peer_ping fd50:20::2
    vm_ssh "$TEST_BIN/systest wireguard-client 10.250.20.1 10.250.20.2"
    vm_ssh "$TEST_BIN/systest wireguard-client fd50:20::1 fd50:20::2"
    # The load test (`systest wireguard-load <wg pid>`) is disabled in the gate:
    # its single ICMP probe inside the UDP flood is lost at the host tap while
    # sys-io is off-CPU under full load; see "WireGuard load test flakes" in
    # docs/plans/future-work.md. Run it by hand when working on that.
    if [ "$role" = managed ]; then
      # Status snapshots refresh once per 250 ms tick, and a release build
      # finishes the exchanges above within one: read the snapshot published
      # after them.
      vm_ssh "$TEST_BIN/systest wireguard-await-tick $guest_pid"
      local live_status
      live_status="$(vm_ssh '/user/bin/wg-tool status')"
      printf '%s\n' "$live_status"
      [[ "$live_status" == *"endpoint: $learned_endpoint"* ]] || fail 'status did not report the authenticated roaming endpoint'
      [[ "$live_status" != *'handshake: none'* ]] || fail 'status omitted the active session'
      [[ "$live_status" != *'transfer: 0 bytes received'* ]] || fail 'status omitted received tunnel data'
    fi
  fi

  if [ "${WG_BENCHMARK:-0}" = 1 ]; then
    stop_wireguard
  else
    mkfifo "$work/stale.in" "$work/stale.out"
    exec {stale_in}<>"$work/stale.in"
    # Debug runtimes log to stderr; merged into stdout, a chunk of such a line
    # can split around a protocol line and hide it from the exact match below.
    ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2 "$TEST_BIN/systest wireguard-stale-sockets" \
      < "$work/stale.in" > "$work/stale.out" 2> "$work/stale.err" &
    stale_pid="$!"
    exec {stale_out}<"$work/stale.out"
    stale_phase() {
      local deadline=$((SECONDS + 5))
      while [ "$SECONDS" -lt "$deadline" ]; do
        IFS= read -r -t "$((deadline - SECONDS))" line <&"$stale_out" || break
        printf '%s\n' "$line"
        [ "$line" != "$1" ] || return 0
      done
      cat "$work/stale.err" >&2
      fail "stale sockets did not reach $1"
    }
    stale_phase 'STALE READY'
    stop_wireguard
    stale_phase 'STALE INVALIDATED'
    start_wireguard
    if [ "$role" != plain ]; then
      printf 'handshake\n' >&"$peer_in"
      IFS= read -r -t 5 line <&"$peer_out" || fail "peer did not initiate a fresh handshake"
      [ "$line" = HANDSHAKE ] || fail "unexpected peer response: $line"
      IFS= read -r -t 5 line <&"$peer_out" || fail "peer did not complete the fresh handshake"
      [ "$line" = 'HANDSHAKE OK' ] || fail "unexpected peer response: $line"
    fi
    peer_ping 10.250.20.2
    printf 'x' >&"$stale_in"
    cat <&"$stale_out"
    wait "$stale_pid"
    stale_pid=""
    cat "$work/stale.err" >&2
    vm_ssh "$TEST_BIN/systest wireguard-client 10.250.20.1 10.250.20.2"
    vm_ssh "$TEST_BIN/systest wireguard-client fd50:20::1 fd50:20::2"
    stop_wireguard
  fi
  printf 'quit\n' >&"$peer_in"
  wait "$peer_pid"
  peer_pid=""
  echo "WireGuard VM integration $1 initiator=$role PASS"
)

test_wireguard() {
  vm_ssh "MOTOR_OS_CAPS=0x364 $TEST_BIN/wg-self-test tool"
  for family in ipv4 ipv6; do
    for initiator in guest host plain managed; do
      test_wireguard_case "$family" "$initiator"
    done
  done
}


ping_external() {
  local host="$1"
  local output

  if output="$(vm_ssh /user/bin/ping -c 1 "$host" 2>&1)"; then
    printf '%s\n' "$output"
    return
  fi
  printf '%s\n' "$output"
  if [ "$EXTERNAL_ICMP" = "0" ]; then
    case "$output" in
      *"Request timeout"*)
        echo "NOTE: '$host' resolved; echo reply skipped (host has no external ICMP)"
        return
        ;;
    esac
  fi
  fail "ping '$host' failed"
}

expect_ping_error() {
  local host="$1"
  local expected="$2"
  local output

  if output="$(vm_ssh /user/bin/ping -c 1 "$host" 2>&1)"; then
    printf '%s\n' "$output"
    fail "ping unexpectedly resolved '$host'"
  fi
  printf '%s\n' "$output"
  case "$output" in
    *"$expected"*) ;;
    *) fail "ping '$host' did not report '$expected'" ;;
  esac
}

wait_for_ping_error() {
  local host="$1"
  local expected="$2"
  local output=""

  for _ in $(seq 1 20); do
    if output="$(vm_ssh /user/bin/ping -c 1 "$host" 2>&1)"; then
      printf '%s\n' "$output"
      fail "ping unexpectedly resolved '$host'"
    fi
    case "$output" in
      *"$expected"*)
        printf '%s\n' "$output"
        return
        ;;
    esac
    sleep 0.1
  done

  printf '%s\n' "$output"
  fail "ping '$host' did not settle on '$expected'"
}

read_udp_socket_count() {
  local expected="${1:-1}"
  local output=""
  local count=""
  local last_count=""

  for _ in $(seq 1 20); do
    count=""
    if output="$(vm_ssh /user/bin/stats get 2 2>&1)"; then
      count="$(printf '%s\n' "$output" |
        awk '$2 == "net.udp_sockets" { print $3 }')"
      if [ "$count" = "$expected" ]; then
        printf '%s\n' "$expected"
        return
      fi
      [ -z "$count" ] || last_count="$count"
    fi
    sleep 0.1
  done

  if [ -n "$last_count" ]; then
    printf '%s\n' "$last_count"
    return
  fi

  printf '%s\n' "$output" >&2
  fail "stats did not report net.udp_sockets"
}


cross_network_checks() (
  fail() { cross_fail "$@"; }
  SSH=(ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2)
  DNS_RESOLVER_SSH_PID= DNS_PORT_HOLDER_SSH_PID= RNETBENCH_SSH_PID=
  cleanup_network_peers() {
    local status=$? pid
    trap - EXIT
    set +e
    stop_udp_fragment_echo
    for pid in "$DNS_RESOLVER_SSH_PID" "$DNS_PORT_HOLDER_SSH_PID" "$RNETBENCH_SSH_PID"; do
      [ -z "$pid" ] || { kill "$pid" 2>/dev/null; wait "$pid"; }
    done
    exit "$status"
  }
  trap cleanup_network_peers EXIT
  EXTERNAL_ICMP=1
  ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 || EXTERNAL_ICMP=0
  ping -c 1 -W 2 192.168.4.2
  ping -c 1 -W 2 2001:db8::2
  for address in 192.168.4.1 2001:db8::1 127.0.0.1 localhost; do
    vm_ssh /user/bin/ping -c 1 "$address"
  done
  test_udp_fragmentation
  test_wireguard
  for address in 192.168.4.2 2001:db8::2; do vm_ssh "$TEST_BIN/wg-self-test $address"; done
  coproc RNETBENCH_SERVER {
    exec ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 "TMPDIR=$TEST_TMP $TEST_BIN/rnetbench --server" 2>&1
  }
  RNETBENCH_SSH_PID=$!
  local rnet_in rnet_out banner server_output server_status=0
  exec {rnet_in}>&"${RNETBENCH_SERVER[1]}" {rnet_out}<&"${RNETBENCH_SERVER[0]}"
  # The pty merges both streams, and on a debug image a session starts with
  # the runtime's DEBUG records: the banner is the first line that is not one.
  # russhd ends a pty line with "\n\r", so a later line starts with the "\r".
  while IFS= read -r banner <&"$rnet_out"; do
    banner="${banner#$'\r'}"
    [[ "$banner" =~ ^\ *[0-9]+:[0-9]{3}:\ DEBUG\  ]] || break
  done
  [ "$banner" = 'rnetbench server: listening on 0.0.0.0:40000' ] || fail "rnetbench readiness: $banner"
  for pass in 1 2; do
    timeout 20s "$ROOT_DIR/src/bin/rnetbench/target/release/rnetbench" -c 192.168.4.2:40000 -P 4 -t 1
  done
  printf '\003' >&"$rnet_in"
  server_output="$(cat <&"$rnet_out")"
  wait "$RNETBENCH_SSH_PID" || server_status=$?
  RNETBENCH_SSH_PID=
  exec {rnet_in}>&- {rnet_out}<&-
  [ "$server_status" = 130 ] || fail "rnetbench server status $server_status: $server_output"
  vm_ssh /system/services/strobe --self-test
  vm_ssh /system/services/dns-resolver --self-test
  ping_external google.com
  expect_ping_error does-not-exist.motor.invalid NotFound
  [ "$(read_udp_socket_count)" = 1 ] || fail 'DNS tests leaked UDP sockets'
  guest_pid() {
    vm_ssh /user/bin/ps | awk -v program="$1" '$NF == program { gsub(/[+*?]/, "", $1); print $1; exit }'
  }
  # Verify that numeric lookup is independent of the service, lookup failure is
  # defined, and a later per-call client reconnects after the service restarts.
  resolver_pid="$(guest_pid /system/services/dns-resolver)"
  [ -n "$resolver_pid" ] || fail "could not find the dns-resolver process"
  vm_ssh "/user/bin/rush -c 'kill $resolver_pid'"
  vm_ssh /user/bin/ping -c 1 127.0.0.1
  wait_for_ping_error google.com NotConnected
  
  # A loopback listener that cannot bind must leave native resolution running.
  # Hold port 53 first; check IPC lookups and the logged startup failure.
  : > $RUN_DIR/dns-port-holder.log
  "${SSH[@]}" MOTOR_OS_CAPS=0x140 "$TEST_BIN/systest" hold-dns-port \
    >> $RUN_DIR/dns-port-holder.log 2>&1 &
  DNS_PORT_HOLDER_SSH_PID="$!"
  holder_pid=""
  for _ in $(seq 1 100); do
    holder_pid="$(awk '/^holding 127.0.0.1:53 as pid / { print $NF; exit }' \
      $RUN_DIR/dns-port-holder.log)"
    [ -z "$holder_pid" ] || break
    sleep 0.1
  done
  [ -n "$holder_pid" ] || fail "systest did not take the loopback DNS port"
  "${SSH[@]}" MOTOR_OS_CAPS=0x148 /system/services/dns-resolver \
    >> $RUN_DIR/dns-resolver.log 2>&1 &
  DNS_RESOLVER_SSH_PID="$!"
  # Wait only for service discovery; a failed lookup must fail the test.
  vm_ssh /system/services/dns-resolver --test-service-ready
  vm_ssh "$TEST_BIN/systest" dns-lookup motor-dns-test ||
    fail "native resolution failed while the loopback DNS port was held"
  logged=0
  for _ in $(seq 1 50); do
    if vm_ssh cat /system/logs/dns-resolver.log | grep -Fq 'loopback DNS startup incomplete'; then
      logged=1
      break
    fi
    sleep 0.1
  done
  [ "$logged" = "1" ] || fail "dns-resolver did not report its loopback DNS startup failure"
  resolver_pid="$(guest_pid /system/services/dns-resolver)"
  [ -n "$resolver_pid" ] || fail "could not find the IPC-only dns-resolver process"
  vm_ssh "/user/bin/rush -c 'kill $resolver_pid'"
  vm_ssh "/user/bin/rush -c 'kill $holder_pid'"
  wait_for_ping_error google.com NotConnected
  udp_sockets="$(read_udp_socket_count 0)"
  [ "$udp_sockets" = "0" ] ||
    fail "the held DNS port and the IPC-only resolver left $udp_sockets UDP socket(s)"
  # Each SSH session ends with the status of its killed command.
  for pid in "$DNS_PORT_HOLDER_SSH_PID" "$DNS_RESOLVER_SSH_PID"; do
    wait "$pid" || true
  done
  DNS_PORT_HOLDER_SSH_PID=""
  
  "${SSH[@]}" MOTOR_OS_CAPS=0x148 /system/services/dns-resolver \
    >> $RUN_DIR/dns-resolver.log 2>&1 &
  DNS_RESOLVER_SSH_PID="$!"
  
  # The self-test waits for service discovery itself. Run assertions once so
  # a later success cannot hide a transport failure or a panic.
  vm_ssh /system/services/dns-resolver --self-test
  ping_external google.com
  
  udp_sockets="$(read_udp_socket_count)"
  [ "$udp_sockets" = "1" ] ||
    fail "restarted DNS service left $udp_sockets active UDP socket(s), expected one DNS listener"
  
  vm_ssh "$TEST_BIN/systest unresolved-neighbor"
)

wait_console_line() {
  local offset="$1" pattern="$2" deadline=$((SECONDS + 60))
  until tail -c "+$offset" "$CONSOLE_LOG" | filter_vm_console | tr -d '\r' | grep -aE "$pattern" >/dev/null; do
    vm_alive || cross_fail "VM exited waiting for $pattern; see $CONSOLE_LOG"
    [ "$SECONDS" -lt "$deadline" ] || cross_fail "console did not emit $pattern; see $CONSOLE_LOG"
    sleep 0.1
  done
}

console_status() {
  local command="$1" marker="$2" offset
  offset=$(( $(wc -c < "$CONSOLE_LOG") + 1 ))
  printf '%s; echo %s=$?\r' "$command" "$marker" >&"$VM_SERIAL_FD"
  wait_console_line "$offset" "^$marker=-?[0-9]+$"
  tail -c "+$offset" "$CONSOLE_LOG" | filter_vm_console | tr -d '\r' | grep -ax "$marker=0" >/dev/null ||
    cross_fail "$command failed; see $CONSOLE_LOG"
}

stop_test_image() {
  # The no-IP and no-network guests have no SSH shutdown request. Stop the
  # owned VMM after their assertions, keeping CHV's wrapper alive to reap it.
  vm_alive || cross_fail 'VM exited before teardown'
  kill "${VM_CHILD_PID:-$VMM_PID}"
  finish_test_image 10 stopped
}

prepare_vsock_backend() {
  local name="$1" runtime="$RUN_DIR/$1.vsock"
  mkdir "$runtime"
  VSOCK_BASE="$runtime/vsock"
  VSOCK_ARGS=()
  absent_peer_behavior=refused
  export MOTO_FC_VSOCK_UDS=''
  case "$VMM" in
    qemu)
      resolve_vsock_backend
      absent_peer_behavior=silent
      export MOTO_SHARED_MEM=1
      "$VHOST_DEVICE_VSOCK" --guest-cid 3 --socket "$runtime/vhost" \
        --uds-path "$VSOCK_BASE" --queue-size 256 > "$runtime/backend.log" 2>&1 &
      CROSS_BACKEND_PID=$!
      for _ in $(seq 1 100); do
        [ ! -S "$runtime/vhost" ] || break
        kill -0 "$CROSS_BACKEND_PID" 2>/dev/null || cross_fail 'vsock backend exited before readiness'
        sleep 0.1
      done
      [ -S "$runtime/vhost" ] || cross_fail 'vsock backend did not become ready'
      VSOCK_ARGS=(-chardev "socket,id=vsock,path=$runtime/vhost" -device vhost-user-vsock-pci,chardev=vsock)
      ;;
    chv) VSOCK_ARGS=(--vsock "cid=3,socket=$VSOCK_BASE") ;;
    fc) export MOTO_FC_VSOCK_UDS="$VSOCK_BASE" ;;
  esac
}

stop_vsock_backend() {
  local status=0
  if [ -n "$CROSS_BACKEND_PID" ]; then
    kill "$CROSS_BACKEND_PID"
    wait "$CROSS_BACKEND_PID" || status=$?
    CROSS_BACKEND_PID=
    case "$status" in 0|143) ;; *) cross_fail "vsock backend failed: $status" ;; esac
  fi
  unset MOTO_SHARED_MEM
  export MOTO_FC_VSOCK_UDS=''
}

cross_vsock_outgoing() {
  copy_test_image "$CROSS_IMAGE" vsock-outgoing
  prepare_vsock_backend outgoing
  boot_test_image vsock-outgoing "${VSOCK_ARGS[@]}"
  wait_vm_ssh
  cross_upload_programs
  local PEER_BIN="$ROOT_DIR/src/sys/tests/cross-peer/target/$BUILD/vsock-peer"
  local LOG_DIR="$RUN_DIR/vsock-outgoing" GUEST_BIN="$TEST_BIN/systest" GUEST_TMP="$NONE_TEST_TMP"
  run_outgoing_case() {
    local action="$1"
    shift
    local case_name="$action"
    local verdict="$action"
    if [ "$#" -gt 0 ]; then
      case_name="$action-$(printf '%s-' "$@" | sed 's/-$//')"
      verdict="$action $*"
    fi
    local peer_log="$LOG_DIR/peer-$case_name.log"
    local guest_log="$LOG_DIR/guest-$case_name.log"
    local peer_status=0
  
    "$PEER_BIN" "$VSOCK_BASE" "$action" "$@" > "$peer_log" 2>&1 &
    CROSS_PEER_PID="$!"
    for _ in $(seq 1 100); do
      grep -Fx "READY ${VSOCK_BASE}_70000" "$peer_log" >/dev/null && break
      kill -0 "$CROSS_PEER_PID" 2>/dev/null || cross_fail "owned host peer exited before readiness"
      sleep 0.1
    done
    grep -Fx "READY ${VSOCK_BASE}_70000" "$peer_log" >/dev/null ||
      cross_fail "host peer did not become ready"
  
    vm_ssh "TMPDIR=$GUEST_TMP MOTOR_OS_CAPS=0x3cc $GUEST_BIN test-vsock-outgoing 2 70000 $absent_peer_behavior $action $*" |
      tee "$guest_log"
    grep -Fx "vsock outgoing: $verdict PASS" "$guest_log" >/dev/null ||
      cross_fail "guest PASS marker missing for $verdict"
    if [ "$verdict" = "echo 0" ]; then
      grep -Fx "vsock connect errors: PASS" "$guest_log" >/dev/null ||
        cross_fail "guest connect-error PASS marker missing"
      grep -Fx "vsock pending accept dispatch: PASS" "$guest_log" >/dev/null ||
        cross_fail "pending accept dispatch PASS marker missing"
    fi
    if [ "$verdict" = native-accept ]; then
      grep -Fx "vsock accept owner disconnect: PASS" "$guest_log" >/dev/null ||
        cross_fail "accept owner disconnect PASS marker missing"
      grep -Fx "vsock pending shutdown dispatch: PASS" "$guest_log" >/dev/null ||
        cross_fail "pending shutdown dispatch PASS marker missing"
      grep -Fx "vsock accept reply disconnect: PASS" "$guest_log" >/dev/null ||
        cross_fail "accept reply disconnect PASS marker missing"
      grep -Fx "vsock idle client cleanup: PASS" "$guest_log" >/dev/null ||
        cross_fail "idle client cleanup PASS marker missing"
    fi
  
    wait "$CROSS_PEER_PID" || peer_status=$?
    CROSS_PEER_PID=""
    [ "$peer_status" -eq 0 ] || cross_fail "host peer failed for $action (status $peer_status)"
    grep -Fx "DONE $verdict" "$peer_log" >/dev/null || cross_fail "host peer DONE marker missing for $verdict"
    kill -0 "$VMM_PID" 2>/dev/null || cross_fail "owned $VMM exited after $action"
    if [ -n "$CROSS_BACKEND_PID" ]; then
      kill -0 "$CROSS_BACKEND_PID" 2>/dev/null || cross_fail "owned backend exited after $action"
    fi
  }
  
  # Run the global-capacity case first: its exact 64-stream count assumes no
  # stream from an earlier case is still in its close budget.
  run_outgoing_case global-stream-capacity
  run_outgoing_case echo 0
  run_outgoing_case echo 1
  run_outgoing_case echo 4095
  run_outgoing_case echo 4096
  run_outgoing_case echo 4097
  run_outgoing_case echo 65536
  run_outgoing_case duplex 1048576 1048576
  run_outgoing_case local-send-shutdown 4096 4096
  run_outgoing_case local-receive-shutdown 4096 4096
  run_outgoing_case unix-peer-close 4096
  run_outgoing_case cancel-read 257
  run_outgoing_case cancel-write 16384
  run_outgoing_case cancel-before-poll-drop
  run_outgoing_case cancel-queued-connect
  run_outgoing_case stalled-reader 1048576
  run_outgoing_case coexistence
  run_outgoing_case incoming-backlog
  run_outgoing_case incoming-owner-drop
  run_outgoing_case native-accept
  
  shutdown_test_image
  stop_vsock_backend
}

cross_vsock_discovery() {
  local mode imager="$ROOT_DIR/build/obj/$BUILD/imager/$BUILD/imager"
  for mode in present disabled; do
    copy_test_image "$CROSS_IMAGE" "vsock-$mode"
    printf 'auto_icmp_echo_reply = false\nloopback = false\n\n[devices]\n' > "$RUN_DIR/no-ip.toml"
    printf 'tty:/system/services/sys-tty\nstrobe:/system/services/strobe\n' > "$RUN_DIR/no-ip-init.cfg"
    "$imager" put --mode r--r--r-- "$VM_DIR/$MOTO_IMAGE" "$RUN_DIR/no-ip.toml" /system/cfg/sys-net.toml
    "$imager" put --mode r--r--r-- "$VM_DIR/$MOTO_IMAGE" "$RUN_DIR/no-ip-init.cfg" /system/cfg/sys-init.cfg
    "$imager" mkdir "$VM_DIR/$MOTO_IMAGE" /user/test-tmp
    "$imager" put --mode r-xr-xr-x "$VM_DIR/$MOTO_IMAGE" "$ROOT_DIR/build/bin/$BUILD/systest" /user/test-tmp/systest
    VSOCK_ARGS=()
    if [ "$mode" = present ]; then prepare_vsock_backend discovery; fi
    boot_test_image "vsock-$mode" "${VSOCK_ARGS[@]}"
    wait_console_line 1 '/user\$'
    console_status "MOTOR_OS_CAPS=0x3cc /user/test-tmp/systest test-vsock-discovery $mode" VSOCK_DISCOVERY_STATUS
    filter_vm_console < "$CONSOLE_LOG" | tr -d '\r' | grep -ax "vsock discovery: $mode PASS"
    stop_test_image
    stop_vsock_backend
  done
}

cross_oom_abort() {
  if [ "$VMM" = qemu ]; then
    echo 'SKIP QEMU: victimless System OOM abort'
    return
  fi
  copy_test_image "$CROSS_IMAGE" oom-abort
  MOTO_MEMORY_MIB=256 boot_test_image oom-abort --system-tty
  wait_vm_ssh
  printf 'put "%s" /none/tmp/oom-abort\nchmod 755 /none/tmp/oom-abort\n' \
    "$ROOT_DIR/build/bin/$BUILD/systest" | vm_sftp
  printf '/none/tmp/oom-abort system-oom-abort\r' >&"$VM_SERIAL_FD"
  finish_test_image 30
  tr -d '\r' < "$CONSOLE_LOG" | awk '
    /^oom-abort: READY pid=[0-9]+$/ { split($3, field, "="); pid = field[2] }
    /^OOM: remaining processes, [0-9]+ free physical pages$/ {
      if (!pid || $4 >= 512) bad = 1
      report = 1
    }
    /^OOM: .* pid=[0-9]+ kernel_pid=[0-9]+ user_bytes=[0-9]+ kernel_bytes=[0-9]+$/ {
      if (report && index($0, " pid=" pid " ")) own_memory = 1
    }
    /^OOM: .* free pages, kill / { bad = 1 }
    /KERNEL PANIC/ { panics++; if (!own_memory) bad = 1 }
    /^OOM: no eligible victims or pending reclamation below 512 free pages$/ {
      if (panics == 1) expected = 1
    }
    /vm_exit: bye\./ { exited = 1 }
    END { exit !(pid && report && own_memory && panics == 1 && expected && exited && !bad) }
  ' || cross_fail "missing or incorrect victimless OOM report/panic"
  echo 'victimless OOM abort: PASS'
}

cross_boot_options() {
  local selected="$VMM" VMM CROSS_IMAGE tool
  for VMM in qemu chv fc; do
    case "$VMM" in
      qemu) tool=qemu-system-x86_64 ;;
      chv) tool=cloud-hypervisor-static ;;
      fc) tool=firecracker ;;
    esac
    if ! command -v "$tool" >/dev/null; then
      [ "$VMM" != "$selected" ] || cross_fail "missing selected VMM: $tool"
      echo "SKIP $VMM boot options: $tool is unavailable"
      continue
    fi
    CROSS_IMAGE="$ROOT_DIR/vm_images/$BUILD/motor-os.qcow2"
    [ "$VMM" != fc ] || CROSS_IMAGE="$ROOT_DIR/vm_images/$BUILD/motor-os.img"
    cross_boot_options_for_vmm
  done
}

cross_boot_options_for_vmm() {
  local label system cmdline imager="$ROOT_DIR/build/obj/$BUILD/imager/$BUILD/imager"
  local args=()
  for label in default empty lookalikes system no-network; do
    case "$VMM:$label" in
      qemu:empty|qemu:lookalikes|qemu:system|fc:empty|fc:lookalikes) continue ;;
    esac
    copy_test_image "$CROSS_IMAGE" "boot-$VMM-$label"
    "$imager" mkdir "$VM_DIR/$MOTO_IMAGE" /user/test-tmp
    "$imager" put --mode r-xr-xr-x "$VM_DIR/$MOTO_IMAGE" "$ROOT_DIR/build/bin/$BUILD/systest" /user/test-tmp/boot-options
    args=(); system=false; cmdline=
    case "$label" in
      empty) args=(-- --cmdline '') ;;
      lookalikes) args=(-- --cmdline 'system-tty=1 no-system-tty system-tty-extra --system-tty') ;;
      system)
        system=true
        args=(--system-tty)
        if [ "$VMM" = chv ]; then
          cmdline='unrelated=1  system-tty=1   system-tty'
          args+=(-- --cmdline 'unrelated=1  system-tty=1  ')
        else
          cmdline='console=ttyS0 reboot=k panic=1 pci=off ip=192.168.4.2:::255.255.255.0::eth0:off system-tty'
        fi ;;
      no-network) args=(--no-network) ;;
    esac
    boot_test_image "boot-$VMM-$label" "${args[@]}"
    wait_console_line 1 '/user\$'
    if [ "$label" = no-network ]; then
      console_status '/user/test-tmp/boot-options boot-no-network' BOOT_NETWORK_STATUS
      filter_vm_console < "$CONSOLE_LOG" | tr -d '\r' | grep -ax 'boot without network device PASS'
      stop_test_image
    else
      wait_vm_ssh
      vm_ssh "/user/test-tmp/boot-options boot-console $system"
      if [ "$system" = true ]; then
        console_status "/user/test-tmp/boot-options boot-cmdline '$cmdline'" BOOT_CMDLINE_STATUS
        filter_vm_console < "$CONSOLE_LOG" | tr -d '\r' | grep -ax 'kernel command-line query PASS'
      fi
      if [ "$BUILD" = debug ]; then
        grep -Fq 'kernel command-line tests PASS' "$CONSOLE_LOG" || cross_fail 'kernel command-line tests did not run'
      fi
      shutdown_test_image
    fi
  done
  echo "boot options: PASS ($VMM)"
}

cross_block_mounts() {
  # Native compilation needs more RAM, but the memfs capacity regression only
  # runs when its mount is at most 1 GiB. Keep that coverage in this boot phase.
  local MOTO_MEMORY_MIB="$MOTO_MEMORY_MIB"
  [ "$MOTO_MEMORY_MIB" -le 1024 ] || MOTO_MEMORY_MIB=1024
  local imager="$ROOT_DIR/build/obj/$BUILD/imager/$BUILD/imager"
  local SCRATCH="$RUN_DIR/block-inputs" image baseline BLOCK_BOOT=0
  mkdir "$SCRATCH"
  # Start with the standard raw image. No fixture image is built or published.
  copy_test_image "$ROOT_DIR/vm_images/$BUILD/motor-os.img" block
  image="$VM_DIR/$MOTO_IMAGE"
  cat > "$SCRATCH/read-only-small-tmp.toml" <<'TOML'
[root]
read_only = true
[[mount]]
path = "/none/tmp"
type = "memfs"
max_size = "16K"
[[mount]]
path = "/system/tmp"
type = "memfs"
[[mount]]
path = "/user/tmp"
type = "memfs"
[[mount]]
path = "/system/logs"
type = "memfs"
max_size = "16M"
TOML
  printf 'read-only fixture\n' > "$SCRATCH/ro-probe"
  "$imager" put --mode rw-rw-rw- "$image" "$SCRATCH/ro-probe" /none/cfg/ro-probe
  "$imager" mkdir "$image" /user/test-tmp
  "$imager" put --mode r-xr-xr-x "$image" "$ROOT_DIR/build/bin/$BUILD/systest" /user/test-tmp/systest
  "$imager" block-mount-fixture config "$image" "$SCRATCH/read-only-small-tmp.toml"
  baseline="$(sha256sum "$image")"
  block_start() {
    local name="$1"; shift
    BLOCK_BOOT=$((BLOCK_BOOT + 1))
    local flags=()
    [ "$VMM" = qemu ] || flags+=(--system-tty)
    boot_test_image "block-$BLOCK_BOOT-$name" "${flags[@]}" "$@"
    wait_vm_ssh
  }
for boot in 1 2; do
  block_start "ro-root-$boot"
  if [ "$boot" = 1 ]; then
    vm_ssh '/system/services/strobe --self-test'
    vm_ssh '/system/services/dns-resolver --self-test-local'
  fi
  vm_ssh 'MOTOR_OS_CAPS=0x244 /user/test-tmp/systest block-ro-root'
  vm_ssh 'MOTOR_OS_CAPS=0x204 /user/test-tmp/systest block-ro-root'
  if [ "$VMM" != qemu ]; then
    console_status 'MOTOR_OS_CAPS=0x20d /user/test-tmp/systest block-ro-root' BLOCK_SYSTEM_STATUS
  else
    echo 'SKIP QEMU: System read-only root checks'
  fi
  vm_ssh 'findmnt' | awk '$2 == "/none/tmp" && $4 == "memfs" && $5 == "rw" && $7 == 16384 {found=1} END {exit !found}'
  # Require a guest-requested exit; forced cleanup is not a successful reboot.
  shutdown_test_image
  [ "$(sha256sum "$image")" = "$baseline" ] || cross_fail "read-only root changed its backing image"
done
# The small mount exercises ordinary boot. Later fixtures use the default size.
sed '/^max_size = "16K"$/d' "$SCRATCH/read-only-small-tmp.toml" > "$SCRATCH/read-only.toml"
"$imager" block-mount-fixture config "$image" "$SCRATCH/read-only.toml"
# An actual DHCP ACK must reach the snapshot and resolver on a read-only root.
# QEMU supplies DHCP locally; these checks send no Internet traffic.
if [ "$VMM" = qemu ] || [ "$VMM" = chv ]; then
  local selected_vmm="$VMM"
  local saved_ssh=("${SSH_OPTIONS[@]}")
  VMM=qemu
  cp --sparse=always "$image" "$VM_DIR/dhcp.img"
  cat > "$SCRATCH/sys-net-dhcp.toml" <<'TOML'
auto_icmp_echo_reply = true
loopback = true
[devices.net0]
dhcp = true
TOML
  "$imager" block-mount-fixture net-config "$VM_DIR/dhcp.img" "$SCRATCH/sys-net-dhcp.toml"
  dhcp_before="$(sha256sum "$VM_DIR/dhcp.img")"
  export MOTO_IMAGE=dhcp.img MOTO_QEMU_USER_NET=1
  sed 's/^\[192.168.4.2\]:2222/[127.0.0.1]:10023/' "$KNOWN_HOSTS" > "$SCRATCH/known-hosts"
  SSH_OPTIONS=(-F /dev/null -p 10023 -o HostName=127.0.0.1
    -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="$SCRATCH/known-hosts" -i "$TEST_KEY")
  block_start dhcp
  vm_ssh '/system/services/dns-resolver --test-dhcp'
  vm_ssh '/system/services/dns-resolver --self-test-local'
  shutdown_test_image
  [ "$(sha256sum "$VM_DIR/dhcp.img")" = "$dhcp_before" ] || cross_fail "DHCP wrote to the root image"
  unset MOTO_QEMU_USER_NET
  SSH_OPTIONS=("${saved_ssh[@]}")
  VMM="$selected_vmm"
fi
"$imager" block-mount-fixture create "$image" "$SCRATCH/partitions"
cp --sparse=always "$SCRATCH/partitions/root.img" "$VM_DIR/partitions.img"
export MOTO_IMAGE=partitions.img
block_start unconfigured
vm_ssh '/user/test-tmp/systest block-partition unconfigured'
shutdown_test_image
sed 's/read_only = true/read_only = false/' \
  "$SCRATCH/read-only.toml" > "$SCRATCH/partitions.toml"
cat >> "$SCRATCH/partitions.toml" <<'TOML'

[[mount]]
path = "/user/data"
type = "motor-fs"
device = 0
partition = 4
TOML
"$imager" block-mount-fixture config "$VM_DIR/$MOTO_IMAGE" "$SCRATCH/partitions.toml"
block_start partition-write
vm_ssh '/user/test-tmp/systest block-partition write'
shutdown_test_image
echo 'read_only = true' >> "$SCRATCH/partitions.toml"
"$imager" block-mount-fixture config "$VM_DIR/$MOTO_IMAGE" "$SCRATCH/partitions.toml"
block_start partition-read
vm_ssh '/user/test-tmp/systest block-partition read-only'
shutdown_test_image

for disk in parted bare unused; do
  cp --sparse=always "$SCRATCH/partitions/$disk.img" "$VM_DIR/$disk.img"
done
sed 's/read_only = true/read_only = false/' "$SCRATCH/partitions.toml" > "$SCRATCH/devices.toml"
cat >> "$SCRATCH/devices.toml" <<'TOML'

[[mount]]
path = "/user/data/nested"
type = "motor-fs"
device = 1
partition = 1
cache_mb = 2

[[mount]]
path = "/user/bare"
type = "motor-fs"
device = 2
TOML
"$imager" block-mount-fixture config "$VM_DIR/$MOTO_IMAGE" "$SCRATCH/devices.toml"
block_start devices-write --extra-disk parted.img --extra-disk bare.img --extra-disk unused.img
vm_ssh '/user/test-tmp/systest block-devices write'
deadline=$((SECONDS + 10))
until vm_ssh 'stats providers' | awk '$1 == 2 && $2 == "sys-io" { ready=1 } END { exit !ready }'; do
  vm_alive || cross_fail 'guest exited before stats registration'
  [ "$SECONDS" -lt "$deadline" ] || cross_fail 'sys-io did not register its stats provider'
  sleep 0.1
done
vm_ssh '/user/test-tmp/systest block-stress'
shutdown_test_image
echo 'read_only = true' >> "$SCRATCH/devices.toml"
"$imager" block-mount-fixture config "$VM_DIR/$MOTO_IMAGE" "$SCRATCH/devices.toml"
bare_before="$(sha256sum "$VM_DIR/bare.img")"
block_start devices-read --extra-disk parted.img --extra-disk-ro bare.img --extra-disk unused.img
vm_ssh '/user/test-tmp/systest block-devices read-only'
vm_ssh findmnt
shutdown_test_image
[ "$(sha256sum "$VM_DIR/bare.img")" = "$bare_before" ] || cross_fail 'read-only bare device changed'

reject_guest() {
  local name="$1" diagnostic="$2"
  shift 2
  BLOCK_BOOT=$((BLOCK_BOOT + 1))
  boot_test_image "block-reject-$BLOCK_BOOT-$name" "$@"
  local deadline=$((SECONDS + 30))
  until grep -Fq "$diagnostic" "$CONSOLE_LOG"; do
    if ! vm_alive; then
      grep -Fq "$diagnostic" "$CONSOLE_LOG" || cross_fail "guest exited without expected diagnostic: $diagnostic"
      break
    fi
    [ "$SECONDS" -lt "$deadline" ] || cross_fail "missing rejection: $diagnostic"
    sleep 0.1
  done
  ! grep -Fq 'most services up' "$CONSOLE_LOG" || cross_fail 'failed configuration published services'
  # An exited guest cannot accept clients; avoid probing its now-absent network.
  if vm_alive && ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=2 -o ConnectionAttempts=1 \
      motor@192.168.4.2 /user/bin/rush -c true >/dev/null 2>&1; then
    cross_fail 'rejected configuration accepted a filesystem client'
  fi
  # Signal only the owned VMM; CHV's PTY wrapper reaps its child normally.
  local signal_pid="$VMM_PID" status=0
  [ "$VMM" != chv ] || signal_pid="$VM_CHILD_PID"
  if kill -0 "$signal_pid" 2>/dev/null; then
    kill "$signal_pid" 2>/dev/null || ! kill -0 "$signal_pid" 2>/dev/null ||
      cross_fail 'could not terminate rejected guest'
  fi
  wait_vm_exit 10 || cross_fail 'rejected guest did not terminate'
  wait "$VMM_PID" || status=$?
  if [ -n "$VM_CHILD_PID" ] && kill -0 "$VM_CHILD_PID" 2>/dev/null; then
    cross_fail 'VMM child survived rejected boot'
  fi
  VMM_PID=''
  VM_CHILD_PID=''
  case "$VMM:$status" in
    qemu:0|qemu:33|qemu:143|chv:0|chv:143|fc:0|fc:143) ;;
    *) cross_fail "rejected boot exit status $status" ;;
  esac
  exec {VM_SERIAL_FD}>&-
  VM_SERIAL_FD=
}

skip_mount_boot() {
  local name="$1" diagnostic="$2"
  shift 2
  block_start "$name" "$@"
  grep -F 'Ignoring mount in /system/cfg/sys-fs.toml:' "$CONSOLE_LOG" |
    grep -F "$diagnostic" >/dev/null || cross_fail "missing mount diagnostic: $diagnostic"
}

# Both data-only MBR disks and whole-device files must obey the backing flag.
for format in parted bare; do
  cp --sparse=always "$SCRATCH/partitions/root.img" "$VM_DIR/recovery-root.img"
  cp --sparse=always "$SCRATCH/partitions/$format.img" "$VM_DIR/recovery-data.img"
  cp "$SCRATCH/read-only.toml" "$SCRATCH/recovery.toml"
  cat >> "$SCRATCH/recovery.toml" <<'TOML'

[[mount]]
path = "/user/data"
type = "motor-fs"
device = 1
TOML
  [ "$format" != parted ] || echo 'partition = 1' >> "$SCRATCH/recovery.toml"
  cp "$SCRATCH/recovery.toml" "$SCRATCH/recovery-writable.toml"
  echo 'read_only = true' >> "$SCRATCH/recovery.toml"
  export MOTO_IMAGE=recovery-root.img
  "$imager" block-mount-fixture config "$VM_DIR/$MOTO_IMAGE" "$SCRATCH/recovery.toml"
  data_before="$(sha256sum "$VM_DIR/recovery-data.img")"
  block_start "$format-clean-ro" --extra-disk-ro recovery-data.img
  vm_ssh 'cat /user/data/label'
  shutdown_test_image
  [ "$(sha256sum "$VM_DIR/recovery-data.img")" = "$data_before" ] || cross_fail 'clean read-only data changed'
  "$imager" block-mount-fixture config "$VM_DIR/$MOTO_IMAGE" "$SCRATCH/recovery-writable.toml"
  skip_mount_boot "$format-writable-on-ro" 'writable mount on read-only device' --extra-disk-ro recovery-data.img
  vm_ssh '[ ! -e /user/data/label ]'
  shutdown_test_image
  [ "$(sha256sum "$VM_DIR/recovery-data.img")" = "$data_before" ] || cross_fail 'rejected writable data changed'
  "$imager" block-mount-fixture config "$VM_DIR/$MOTO_IMAGE" "$SCRATCH/recovery.toml"
  "$imager" block-mount-fixture dirty "$VM_DIR/recovery-data.img"
  dirty_before="$(sha256sum "$VM_DIR/recovery-data.img")"
  skip_mount_boot "$format-dirty-ro" 'Motor FS journal recovery required on read-only backing' --extra-disk-ro recovery-data.img
  vm_ssh '[ ! -e /user/data/label ]'
  shutdown_test_image
  [ "$(sha256sum "$VM_DIR/recovery-data.img")" = "$dirty_before" ] || cross_fail 'dirty read-only data changed'
  block_start "$format-recover-ro-mount" --extra-disk recovery-data.img
  vm_ssh '[ -d /user/data/recovery-probe ] && cat /user/data/label'
  shutdown_test_image
  "$imager" block-mount-fixture check-recovery "$VM_DIR/recovery-data.img"
done

root_formats=(mbr)
[ "$VMM" = qemu ] || root_formats+=(bare)
for format in "${root_formats[@]}"; do
  root="$VM_DIR/recovery-root-$format.img"
  if [ "$format" = mbr ]; then
    cp --sparse=always "$image" "$root"
  else
    "$imager" block-mount-fixture extract-root "$image" "$root"
  fi
  export MOTO_IMAGE="${root##*/}"
  root_before="$(sha256sum "$root")"
  block_start "root-$format-clean-ro" --root-read-only
  vm_ssh '/user/test-tmp/systest block-ro-root'
  shutdown_test_image
  [ "$(sha256sum "$root")" = "$root_before" ] || cross_fail 'clean read-only root changed'
  sed 's/read_only = true/read_only = false/' \
    "$SCRATCH/read-only.toml" > "$SCRATCH/root-writable.toml"
  "$imager" block-mount-fixture config "$root" "$SCRATCH/root-writable.toml"
  root_before="$(sha256sum "$root")"
  reject_guest "root-$format-writable-on-ro" 'writable mount on read-only device' --root-read-only
  [ "$(sha256sum "$root")" = "$root_before" ] || cross_fail 'rejected writable root changed'
  "$imager" block-mount-fixture config "$root" "$SCRATCH/read-only.toml"
  "$imager" block-mount-fixture dirty "$root"
  root_before="$(sha256sum "$root")"
  reject_guest "root-$format-dirty-ro" 'Motor FS journal recovery required on read-only backing' --root-read-only
  [ "$(sha256sum "$root")" = "$root_before" ] || cross_fail 'dirty read-only root changed'
  block_start "root-$format-recover-ro-mount"
  vm_ssh '[ -d /recovery-probe ] && /user/test-tmp/systest block-ro-root'
  shutdown_test_image
  "$imager" block-mount-fixture check-recovery "$root"
done

"$imager" resize -i "$image" -o "$VM_DIR/resized-root.img" --size 320M
export MOTO_IMAGE=resized-root.img
resized_before="$(sha256sum "$VM_DIR/$MOTO_IMAGE")"
block_start resized-root
vm_ssh '/user/test-tmp/systest block-ro-root'
shutdown_test_image
[ "$(sha256sum "$VM_DIR/$MOTO_IMAGE")" = "$resized_before" ] || cross_fail 'resized read-only root changed'

cp --sparse=always "$SCRATCH/partitions/root.img" "$VM_DIR/rejection-root.img"
cp --sparse=always "$SCRATCH/partitions/bare.img" "$VM_DIR/rejection-data.img"
export MOTO_IMAGE=rejection-root.img

cat > "$SCRATCH/mixed.toml" <<'TOML'
mount = [
  {path = "/user/bare", type = "memfs"},
  {path = "/user/data", type = "invalid"},
  {path = "/user/test-tmp", type = "motor-fs", device = 9},
  {path = "/none/cfg/ro-probe", type = "memfs"},
  {path = "/user/data", type = "motor-fs", device = 1},
]
TOML
"$imager" block-mount-fixture config "$VM_DIR/$MOTO_IMAGE" "$SCRATCH/mixed.toml"
skip_mount_boot mixed 'entry 2' --extra-disk rejection-data.img
grep -Fq 'entry 3, path "/user/test-tmp", source virtio9' "$CONSOLE_LOG"
grep -Fq 'entry 4, path "/none/cfg/ro-probe", source memfs' "$CONSOLE_LOG"
vm_ssh findmnt | awk '
  $2 == "/user/bare" && $4 == "memfs" { memfs = 1 }
  $2 == "/user/data" && $3 == "virtio1" && $4 == "motor-fs" { motorfs = 1 }
  $1 ~ /^[0-9]+$/ { count++ }
  END { exit !(memfs && motorfs && count == 3) }'
shutdown_test_image

reject_config() {
  local name="$1" diagnostic="$2"
  cat > "$SCRATCH/rejected.toml"
  "$imager" block-mount-fixture config "$VM_DIR/$MOTO_IMAGE" "$SCRATCH/rejected.toml"
  if [ "${3:-}" = fatal ]; then
    reject_guest "$name" "$diagnostic" --extra-disk rejection-data.img
  else
    skip_mount_boot "$name" "$diagnostic" --extra-disk rejection-data.img
    shutdown_test_image
  fi
}
entry=$'[[mount]]\npath="/user/data"\ntype="motor-fs"\ndevice=1'
while IFS='|' read -r name field diagnostic; do
  reject_config "$name" "$diagnostic" <<< "$entry"$'\n'"$field"
done <<'CASES'
slot-zero|partition=0|partition must be an MBR slot
slot-five|partition=5|partition must be an MBR slot
slot-negative|partition=-1|entry 1, device 1
slot-float|partition=1.0|entry 1, device 1
cache-zero|cache_mb=0|cache must contain at least 1 MiB
cache-negative|cache_mb=-1|entry 1, device 1
cache-string|cache_mb="1"|entry 1, device 1
cache-float|cache_mb=1.0|entry 1, device 1
cache-overflow|cache_mb=9223372036854775807|cache_mb overflow
motor-max-size|max_size="1M"|unknown field
motor-mode|mode="rwxrwxrwx"|unknown field
motor-unknown|unknown=true|unknown field
motor-ro-type|read_only=1|entry 1, device 1
CASES
reject_config missing-device 'missing field `device`' <<< $'[[mount]]\npath="/user/data"\ntype="motor-fs"'
reject_config root-key 'unknown field' fatal <<< $'[root]\ncache_mb=4'
reject_config root-ro-type 'read_only' fatal <<< $'[root]\nread_only="true"'
reject_config root-needs-logs 'read-only root requires a writable mount' fatal <<< $'[root]\nread_only=true'
reject_config root-logs-read-only 'read-only root requires a writable mount' fatal \
  <<< $'[root]\nread_only=true\n[[mount]]\npath="/system/logs"\ntype="motor-fs"\ndevice=1\nread_only=true'
reject_config root-logs-unavailable 'read-only root requires a writable mount' fatal \
  <<< $'[root]\nread_only=true\n[[mount]]\npath="/system/logs"\ntype="motor-fs"\ndevice=9'
for field in 'device=1' 'partition=1' 'cache_mb=1' 'read_only=false'; do
  reject_config "memfs-${field%%=*}" 'unknown field' <<< $'[[mount]]\npath="/user/data"\ntype="memfs"\n'"$field"
done
for path in / relative /user/data/ /user/./data /user/../data //user/data; do
  reject_config noncanonical 'mount path is not canonical' <<< "${entry/\/user\/data/$path}"
done
for path in /system /system/cfg /system/cfg/child; do
  reject_config protected 'mount hides system configuration' <<< "${entry/\/user\/data/$path}"
done
for path in /user/data /user/data/nested; do
  reject_config hidden-mount 'mount hides an earlier mount' <<TOML
[[mount]]
path="$path"
type="memfs"
[[mount]]
path="/user/data"
type="memfs"
TOML
done
reject_config duplicate-root 'repeated source or whole-device/partition conflict' <<< $'[[mount]]\npath="/user/data"\ntype="motor-fs"\ndevice=0\npartition=3'
reject_config whole-root 'repeated source or whole-device/partition conflict' <<< "${entry/device=1/device=0}"
other="${entry/\/user\/data/\/user\/bare}"
for extra in '' 'partition=1'; do
  reject_config duplicate-source 'repeated source or whole-device/partition conflict' <<< "$entry"$'\n'"$other"$'\n'"$extra"
done
reject_config whole-after-partition 'repeated source or whole-device/partition conflict' <<< "$entry"$'\npartition=1\n'"$other"
reject_config missing-device-index 'virtio9' <<< "${entry/device=1/device=9}"
reject_config missing-target 'path "/user/absent"' <<< "${entry/\/user\/data/\/user\/absent}"
reject_config file-target 'path "/none/cfg/ro-probe"' <<< "${entry/\/user\/data/\/none\/cfg\/ro-probe}"
reject_config bad-toml 'Cannot apply /system/cfg/sys-fs.toml' fatal <<< '[['
printf '%65537s' ' ' > "$SCRATCH/too-long.toml"
reject_config too-long 'configuration must be a file of at most 64 KiB' fatal < "$SCRATCH/too-long.toml"
for index in $(seq 1 256); do
  printf '[[mount]]\npath="/m%s"\ntype="memfs"\n' "$index"
done > "$SCRATCH/too-many.toml"
reject_config too-many 'more than 255 mounts' fatal < "$SCRATCH/too-many.toml"
if [ "$MOTO_MEMORY_MIB" = 128 ]; then
  for index in 1 2 3 4 5; do
    printf '[[mount]]\npath="/m%s"\ntype="motor-fs"\ndevice=%s\n' "$index" "$index"
  done > "$SCRATCH/five-caches.toml"
  reject_config five-caches 'cache must contain at least 1 MiB' < "$SCRATCH/five-caches.toml"
fi
for format in bare parted; do
  config="$entry"
  kinds=(magic version count)
  if [ "$format" = parted ]; then
    config+=$'\npartition=1'
    kinds+=(mbr-signature mbr-start mbr-length mbr-outside mbr-unaligned mbr-type mbr-empty mbr-overlap)
  else
    kinds+=(short unaligned resized)
  fi
  for kind in "${kinds[@]}"; do
    cp --sparse=always "$SCRATCH/partitions/$format.img" "$VM_DIR/rejection-data.img"
    "$imager" block-mount-fixture corrupt "$VM_DIR/rejection-data.img" "$kind"
    diagnostic='invalid data'
    case "$kind" in
      mbr-start|mbr-length|mbr-outside|mbr-overlap) diagnostic='invalid or overlapping MBR extent' ;;
      mbr-unaligned|mbr-type|mbr-empty) diagnostic='invalid Motor FS partition in MBR slot 1' ;;
    esac
    reject_config "$format-$kind" "$diagnostic" <<< "$config"
    grep -Eq '"/user/data".*virtio1' "$CONSOLE_LOG" || cross_fail 'rejection omitted source identity'
  done
done
cp --sparse=always "$SCRATCH/partitions/bare.img" "$VM_DIR/rejection-data.img"
reject_config bare-is-not-mbr 'virtio1' <<< "$entry"$'\npartition=1'
cp --sparse=always "$SCRATCH/partitions/parted.img" "$VM_DIR/rejection-data.img"
reject_config mbr-is-not-bare 'virtio1' <<< "$entry"
echo 'cross-test: block mounts PASS'
}

cross_tui() {
  local GUEST_KEY="$TEST_TMP/tui.key" GUEST_KNOWN="$TEST_TMP/tui-known-hosts"
  local GUEST_STREAM_HELPER="$TEST_TMP/tui-stream.sh"
  local GUEST_SSH="/user/bin/ssh -p 2222 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$GUEST_KNOWN -i $GUEST_KEY"
  local PTY_IN_FD= PTY_OUT_FD= PTY_OUTPUT=
  cat > "$RUN_DIR/ssh-terminal-child.sh" <<'SH'
#!/user/bin/rush
echo STREAM_READY
read -r value
printf 'STREAM_ONE=<%s>\n' "$value"
read -r value
printf 'STREAM_TWO=<%s>\n' "$value"
SH
  printf 'put "%s" "%s"\nchmod 600 "%s"\nput "%s" "%s"\n' \
    "$TEST_KEY" "$GUEST_KEY" "$GUEST_KEY" "$RUN_DIR/ssh-terminal-child.sh" "$GUEST_STREAM_HELPER" | vm_sftp
strip_escapes() {
  sed -e $'s/\033\\[[0-9;?$]*[a-zA-Z]//g' -e $'s/\033[78]//g'
}

report_field() {
  local text="$1"
  local key="$2"
  local cleaned

  cleaned="$(printf '%s\n' "$text" | strip_escapes)"
  if [ "$key" = "set" ]; then
    cleaned="${cleaned//unset=/}"
  fi
  printf '%s\n' "$cleaned" | grep -aoE "$key=[0-9]+" | tail -1 |
    sed "s/.*$key=//"
}

# The three-bit masks and the duplicate answers all follow one bit -- whether
# the queried context is a terminal endpoint -- and set=/unset= must equal
# self= (a started process's environment cannot change an open descriptor),
# while key= must be 0 (the launch hint is consumed, never live state).
check_report() {
  local label="$1"
  local text="$2"
  local mask="$3"
  local dup="$4"
  local tail_text
  local key
  local got

  # Enough context to diagnose without dumping a whole console log.
  tail_text="$(printf '%s' "$text" | tail -c 800)"
  for key in self set unset; do
    got="$(report_field "$text" "$key")"
    [ "$got" = "$mask" ] ||
      cross_fail "$label: $key=$got, want $mask, in: '$tail_text'"
  done
  got="$(report_field "$text" key)"
  [ "$got" = "0" ] ||
    cross_fail "$label: launch hint visible in environment: '$tail_text'"
  for key in duporig dupnew; do
    got="$(report_field "$text" "$key")"
    [ "$got" = "$dup" ] ||
      cross_fail "$label: $key=$got, want $dup, in: '$tail_text'"
  done
}

wait_console() {
  local pattern="$1"

  for _ in $(seq 1 60); do
    if grep -aq "$pattern" "$CONSOLE_LOG"; then
      return
    fi
    sleep 0.5
  done
  cross_fail "console did not print '$pattern' (log: $CONSOLE_LOG)"
}

# Run one command behind a forced SSH terminal and interact only after markers
# from the process under test. Duplicating coproc's descriptors keeps them
# valid after Bash notices that ssh has exited.
start_pty() {
  local command="$1"

  PTY_OUTPUT=""
  coproc CTRL_C_PTY {
    exec ssh "${SSH_OPTIONS[@]}" -e none -tt motor@192.168.4.2 "$command" 2>&1
  }
  CROSS_PEER_PID="$!"
  exec {PTY_OUT_FD}<&"${CTRL_C_PTY[0]}"
  exec {PTY_IN_FD}>&"${CTRL_C_PTY[1]}"
}

wait_pty_output() {
  local pattern="$1"
  local label="$2"
  local byte
  local deadline=$((SECONDS + 20))
  local remaining

  while [ "$SECONDS" -lt "$deadline" ]; do
    remaining=$((deadline - SECONDS))
    if ! IFS= read -r -t "$remaining" -n 1 byte <&"$PTY_OUT_FD"; then
      break
    fi
    PTY_OUTPUT+="$byte"
    if [[ "$PTY_OUTPUT" == *"$pattern"* ]]; then
      return
    fi
  done
  cross_fail "$label did not print '$pattern': '$(printf '%s' "$PTY_OUTPUT" | tail -c 800)'"
}

# Like wait_pty_output, for an extended regex; BASH_REMATCH holds the match.
wait_pty_regex() {
  local regex="$1"
  local label="$2"
  local byte
  local deadline=$((SECONDS + 20))
  local remaining

  until [[ "$PTY_OUTPUT" =~ $regex ]]; do
    remaining=$((deadline - SECONDS))
    if [ "$remaining" -le 0 ] ||
      ! IFS= read -r -t "$remaining" -n 1 byte <&"$PTY_OUT_FD"; then
      cross_fail "$label did not print '$regex': '$(printf '%s' "$PTY_OUTPUT" | tail -c 800)'"
    fi
    PTY_OUTPUT+="$byte"
  done
}

# Kills a guest process and returns once the guest no longer lists it. A
# process's executable mappings retire before it leaves the list, so its
# executable can be deleted afterwards.
end_guest_process() {
  local pid="$1"
  local label="$2"
  local deadline=$((SECONDS + 10))
  local out

  out="$(vm_ssh "/user/bin/rush -c 'kill $pid'" 2>&1)" ||
    [[ "$out" == *"no such process"* ]] ||
    cross_fail "$label: cannot kill guest process $pid: '$out'"
  while out="$(vm_ssh "/user/bin/sysbox caps $pid" 2>&1)"; do
    [ "$SECONDS" -lt "$deadline" ] ||
      cross_fail "$label: guest process $pid is still running after kill"
    sleep 0.1
  done
  [[ "$out" == *"no such process: $pid"* || "$out" == *"process $pid has exited"* ]] ||
    cross_fail "$label: cannot check guest process $pid: '$out'"
}

finish_pty() {
  local expected="$1"
  local label="$2"
  local remainder
  local read_status
  local status

  exec {PTY_IN_FD}>&-
  set +e
  remainder="$(cat <&"$PTY_OUT_FD")"
  read_status="$?"
  wait "$CROSS_PEER_PID"
  status="$?"
  set -e
  PTY_OUTPUT+="$remainder"
  exec {PTY_OUT_FD}<&-
  CROSS_PEER_PID=""

  [ "$read_status" -eq 0 ] || cross_fail "$label output ended with status $read_status"
  [ "$status" -eq "$expected" ] ||
    cross_fail "$label exited with status $status, want $expected: '$(printf '%s' "$PTY_OUTPUT" | tail -c 800)'"
}

# Run a nested Motor ssh command, then ask the outer russhd pty which mode the
# client left behind. The query and its reply are consumed by russhd; the
# marker orders the host's newline after that reply has reached rush's stdin.
start_nested_pty() {
  local command="$1"

  start_pty "$command; nested_status=\$?; printf '\\033[?2048\\044p'; printf MODE_QUERY_READY; read -r mode_state; printf '\\nMODE_STATE=%s NESTED_STATUS=%s\\n' \"\$mode_state\" \"\$nested_status\"; exit \"\$nested_status\""
}

finish_nested_pty() {
  local expected="$1"
  local label="$2"

  wait_pty_output "MODE_QUERY_READY" "$label mode query"
  printf '\n' >&"$PTY_IN_FD"
  wait_pty_output $'MODE_STATE=\033[?2048;2$y' "$label mode restoration"
  wait_pty_output "NESTED_STATUS=$expected" "$label nested status"
  finish_pty "$expected" "$label"
}

# The console shell is a child of sys-tty, the serial-console terminal
# provider. Waiting for the report's last field before typing "exit" is the
# ordering: input typed earlier would reach the shell's line editor instead.
echo "-- sys-tty console child --"
wait_console "motor-os"
printf 'if [ "$PWD" = /user ] && [ "$HOME" = /user ]; then echo CONSOLE_"HOME_OK"; else echo CONSOLE_"HOME_BAD"; fi\r' >&"$VM_SERIAL_FD"
wait_console "CONSOLE_HOME_"
if grep -aq "CONSOLE_HOME_BAD" "$CONSOLE_LOG"; then
  cross_fail "sys-tty did not start the console shell with HOME and PWD set to /user"
fi
printf 'TMPDIR=%s %s/systest stdio-terminal-report-child\r' "$TEST_TMP" "$TEST_BIN" >&"$VM_SERIAL_FD"
wait_console "dupnew="
printf 'exit\r' >&"$VM_SERIAL_FD"
check_report "sys-tty console child" "$(cat "$CONSOLE_LOG")" 111 1

# A non-pty ssh session: russhd removes the terminal hint, so the command and
# everything it spawns with inherited stdio answers non-terminal.
echo "-- non-pty ssh session --"
out="$(printf 'mask inherit\nexit\n' |
  vm_ssh "TMPDIR=$TEST_TMP $TEST_BIN/systest stdio-terminal-report-child")"
check_report "non-pty ssh child" "$out" 000 0
[ "$(report_field "$out" mask)" = "000" ] ||
  cross_fail "non-pty ssh grandchild is a terminal: '$out'"

# A forced-pty ssh session is a terminal; a descendant inheriting all three
# streams stays one, and capturing its stdout flips exactly that bit (the
# "> file" row of docs/tui.md's mask table, live against a real provider).
echo "-- russhd pty session --"
out="$(printf 'mask inherit\nmask outpiped\nexit\n' |
  ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
    "TMPDIR=$TEST_TMP $TEST_BIN/systest stdio-terminal-report-child" 2>/dev/null)"
check_report "ssh pty child" "$out" 111 1
masks="$(printf '%s\n' "$out" | strip_escapes |
  grep -aoE 'mask=[01]+' | sed 's/.*mask=//' | tr '\n' ' ')"
[ "$masks" = "111 101 " ] ||
  cross_fail "ssh pty descendant masks: got '$masks', want '111 101 ', in: '$out'"

echo "-- Ctrl+C Default and handler leaves --"
start_pty "TMPDIR=$TEST_TMP $TEST_BIN/systest ctrl-c-default-child"
wait_pty_output "CTRL_C_DEFAULT_READY" "terminal-stdin Default leaf"
printf '\003' >&"$PTY_IN_FD"
finish_pty 130 "terminal-stdin Default leaf"

# stdin is a pipe, so Ctrl+C reaches the leaf through its reserved terminal fd
# and a terminal-backed non-interactive rush remains Default between routes.
start_pty "/user/bin/rush -c 'echo | TMPDIR=$TEST_TMP $TEST_BIN/systest ctrl-c-default-child'"
wait_pty_output "CTRL_C_DEFAULT_READY" "terminal-fd3 Default leaf"
printf '\003' >&"$PTY_IN_FD"
finish_pty 130 "terminal-fd3 Default leaf"

start_pty "TMPDIR=$TEST_TMP $TEST_BIN/systest ctrl-c-handler-child"
wait_pty_output "CTRL_C_HANDLER_READY" "handler leaf"
printf '\003' >&"$PTY_IN_FD"
wait_pty_output "CTRL_C_HANDLER_CALLED" "handler leaf"
finish_pty 0 "handler leaf"

echo "-- Ctrl+C forwarding and route teardown --"
start_pty "TMPDIR=$TEST_TMP $TEST_BIN/systest ctrl-c-route-parent"
wait_pty_output "CTRL_C_NORMAL_CHILD_READY" "route normal child"
printf 'n' >&"$PTY_IN_FD"
wait_pty_output "CTRL_C_NORMAL_RESTORED" "route after normal child"
printf '\003' >&"$PTY_IN_FD"
wait_pty_output "CTRL_C_PARENT_AFTER_NORMAL" "route parent after normal child"
wait_pty_output "CTRL_C_SPIN_CHILD_READY" "route spinning child"
printf '\003x' >&"$PTY_IN_FD"
wait_pty_output "CTRL_C_SPIN_STATUS_130" "route interrupted child"
wait_pty_output "CTRL_C_TYPEAHEAD_X" "route type-ahead"
wait_pty_output "CTRL_C_KILL_RESTORED" "route after interrupted child"
printf '\003' >&"$PTY_IN_FD"
wait_pty_output "CTRL_C_PARENT_AFTER_KILL" "route parent after interrupted child"
finish_pty 0 "route parent"

echo "-- crossterm Ctrl+C adapter --"
start_pty "TMPDIR=$TEST_TMP $TEST_BIN/crossterm-smoke keys"
wait_pty_output "ready" "crossterm handler"
printf '\003' >&"$PTY_IN_FD"
wait_pty_output "key=Char('c')+KeyModifiers(CONTROL)" "crossterm handler"
printf 'q' >&"$PTY_IN_FD"
wait_pty_output "end=quit" "crossterm handler"
finish_pty 0 "crossterm handler"

echo "-- rush read builtin interruption --"
start_pty "/user/bin/rush -i -c \"trap 'echo READ_TRAP' INT; echo READ_READY; for i in 1 2; do read foo; echo READ_FINISHED; done; echo LIST_FINISHED\""
wait_pty_output "READ_READY" "rush read builtin"
printf '\003' >&"$PTY_IN_FD"
wait_pty_output "READ_TRAP" "rush interrupted read trap"
finish_pty 130 "rush read builtin"
case "$PTY_OUTPUT" in
  *READ_FINISHED*|*LIST_FINISHED*) cross_fail "rush continued after interrupted read: '$PTY_OUTPUT'" ;;
esac

start_pty "/user/bin/rush -i -c 'echo READ_DATA_READY; IFS= read -r foo; printf \"READ_DATA=[%s]\\n\" \"\$foo\"'"
wait_pty_output "READ_DATA_READY" "rush read data"
printf '  one\tbad\177\\two  \r' >&"$PTY_IN_FD"
wait_pty_output $'READ_DATA=[  one\tba\\two  ]' "rush read tabs and backspace"
finish_pty 0 "rush read data"

start_pty "/user/bin/rush -i -c 'echo READ_EOF_READY; read foo; printf \"\\nREAD_EOF=%s:%s\\n\" \"\$?\" \"\$foo\"'"
wait_pty_output "READ_EOF_READY" "rush read EOF"
printf 'partial\004\004' >&"$PTY_IN_FD"
wait_pty_output "READ_EOF=1:partial" "rush read partial EOF"
finish_pty 0 "rush read EOF"

echo "-- Motor ssh terminal size and normal restoration --"
start_nested_pty "COLUMNS=100 LINES=30 $GUEST_SSH -t motor@127.0.0.1 TMPDIR=$TEST_TMP $TEST_BIN/crossterm-smoke keys"
wait_pty_output "ready" "nested ssh terminal"
wait_pty_output "resize=100x30" "nested ssh initial size"
printf '\033[48;20;60;0;0t' >&"$PTY_IN_FD"
wait_pty_output "resize=60x20" "nested ssh resize"
printf 'x' >&"$PTY_IN_FD"
wait_pty_output "key=Char('x')" "nested ssh input"
printf '\n~~q' >&"$PTY_IN_FD"
wait_pty_output "key=Char('~')" "nested ssh literal escape"
wait_pty_output "end=quit" "nested ssh normal exit"
finish_nested_pty 0 "nested ssh normal exit"

echo "-- Motor ssh byte stream, prefix expiry, and local escape --"
start_nested_pty "COLUMNS=100 LINES=30 $GUEST_SSH -t motor@127.0.0.1 /user/bin/rush $GUEST_STREAM_HELPER"
wait_pty_output "STREAM_READY" "nested ssh byte stream"
printf 'byte-transparent-x~.y\n' >&"$PTY_IN_FD"
wait_pty_output "STREAM_ONE=<byte-transparent-x~.y>" "nested ssh byte stream"
printf '~~literal\n' >&"$PTY_IN_FD"
wait_pty_output "STREAM_TWO=<~literal>" "nested ssh doubled escape"
finish_nested_pty 0 "nested ssh byte stream"

start_nested_pty "COLUMNS=100 LINES=30 $GUEST_SSH -t motor@127.0.0.1 TMPDIR=$TEST_TMP $TEST_BIN/crossterm-smoke keys"
wait_pty_output "ready" "nested ssh prefix expiry"
# A lone Escape is also a possible terminal-reply prefix. It must be released
# by the 50 ms idle deadline without another byte making it impossible.
printf '\033' >&"$PTY_IN_FD"
wait_pty_output "key=Esc" "nested ssh 50 ms prefix expiry"
printf '\n~.' >&"$PTY_IN_FD"
finish_nested_pty 255 "nested ssh local escape"

echo "-- Motor ssh remote failure restoration --"
start_nested_pty "$GUEST_SSH -t motor@127.0.0.1 '/user/bin/rush -c \"exit 7\"'"
finish_nested_pty 7 "nested ssh remote failure"

echo "-- Motor ssh Ctrl+C routing --"
start_pty "$GUEST_SSH -t motor@127.0.0.1 TMPDIR=$TEST_TMP $TEST_BIN/systest ctrl-c-default-child"
wait_pty_output "CTRL_C_DEFAULT_READY" "nested ssh pty Ctrl+C"
printf '\003' >&"$PTY_IN_FD"
finish_pty 130 "nested ssh pty Ctrl+C"

# Without a pty, Ctrl+C ends only the local client: the guest-side child keeps
# spinning and keeps systest locked against deletion, so end it explicitly.
start_pty "$GUEST_SSH -T motor@127.0.0.1 'TMPDIR=$TEST_TMP $TEST_BIN/systest ctrl-c-default-child & echo CTRL_C_CHILD_PID=\$!; wait'"
wait_pty_output "CTRL_C_DEFAULT_READY" "nested ssh non-pty Ctrl+C"
wait_pty_regex 'CTRL_C_CHILD_PID=([0-9]+)[^0-9]' "nested ssh non-pty Ctrl+C"
nested_child_pid="${BASH_REMATCH[1]}"
printf '\003' >&"$PTY_IN_FD"
finish_pty 130 "nested ssh non-pty Ctrl+C"
end_guest_process "$nested_child_pid" "nested ssh non-pty Ctrl+C"

  vm_ssh "rm $GUEST_KEY && rm $GUEST_KNOWN && rm $GUEST_STREAM_HELPER"
  echo 'cross-test: SSH terminal and Ctrl+C checks PASS'
}

cross_terminal_size() {
  local SCRATCH="$RUN_DIR/geometry" RMUX_STDERR_LOG="$RUN_DIR/geometry.stderr"
  local SSH_OPTIONS=("${SSH_OPTIONS[@]}")
  mkdir "$SCRATCH"
  ssh "${SSH_OPTIONS[@]}" -M -S "$SCRATCH/ssh-control" -fN motor@192.168.4.2
  SSH_OPTIONS+=(-S "$SCRATCH/ssh-control" -o ControlMaster=no)
  start_red() {
    printf '/user/bin/rush -c red 2>%s/red-%s.stderr\r' "$TEST_TMP" "$1"
  }
red_bars() {
  LC_ALL=C grep -ao $'\033\\[[0-9]*;1H'"$1"$' \\[1\\] \\[No Name\\][^\033]*NORMAL | [0-9][0-9]*:[0-9][0-9]* ' |
    LC_ALL=C awk -F$'\033' '{
      row = $2; sub(/^\[/, "", row); sub(/;.*/, "", row)
      bar = $NF; sub(/^\[[0-9;]*m/, "", bar)
      printf "%s:%s ", row, length(bar)
    }'
}
RED_GROUND=$'\033\\[0m\033\\[38;5;233m\033\\[48;5;222m'

# Poll only while the expected output is absent. A deadline diagnoses a missing
# event; successful steps advance as soon as their output arrives.
wait_for() {
  local deadline=$((SECONDS + 5))
  until "$@"; do
    [ "$SECONDS" -lt "$deadline" ] || cross_fail "timed out: $*"
    sleep 0.01
  done
}

since() { tail -c "+$(($2 + 1))" "$1"; }
mark() { wc -c < "$1"; }
has() { since "$1" "$2" | LC_ALL=C grep -aFq -- "$3"; }
wait_text() { wait_for has "$@"; }
prompt() { wait_text "$1" "$2" $'\033[?25h'; }
console_since() { since "$CONSOLE_LOG" "$1"; }

console_command() {
  local at
  at="$(mark "$CONSOLE_LOG")"
  printf '%s\r' "$1" >&"$VM_SERIAL_FD"
  wait_text "$CONSOLE_LOG" "$at" "$2"
  wait_text "$CONSOLE_LOG" "$at" $'\033[?2048h'
  prompt "$CONSOLE_LOG" "$at"
}

bars_are() {
  [ "$(since "$1" "$2" | red_bars "$RED_GROUND")" = "$3 " ]
}
wait_bars() { wait_for bars_are "$@"; }

# A persistent input FIFO keeps script(1) from injecting EOF. The controller
# resizes its actual PTY; there is no second script coordinating by sleeps.
start_session() {
  local name="$1" terminal="$2" command tty_path
  shift 2
  SESSION_LOG="$SCRATCH/$name.log"
  : > "$SESSION_LOG"
  rm -f "$SCRATCH/session-in" "$SCRATCH/session-tty"
  mkfifo "$SCRATCH/session-in"
  exec 4<> "$SCRATCH/session-in"
  if [ "$terminal" = pty ]; then
    printf -v command '%q ' ssh "${SSH_OPTIONS[@]}" -e none -tt motor@192.168.4.2 "$@"
    printf -v tty_path '%q' "$SCRATCH/session-tty"
    script -qef -E never -c "stty rows 30 cols 100; tty > $tty_path; exec $command" \
      "$SESSION_LOG" < "$SCRATCH/session-in" > /dev/null 2>> "$RMUX_STDERR_LOG" &
  else
    ssh "${SSH_OPTIONS[@]}" -e none motor@192.168.4.2 "$@" \
      < "$SCRATCH/session-in" > "$SESSION_LOG" 2>> "$RMUX_STDERR_LOG" &
  fi
  CROSS_PEER_PID="$!"
}
resize_session() {
  stty -F "$(cat "$SCRATCH/session-tty")" rows "$1" cols "$2"
}
finish_session() {
  wait_for session_finished
  wait "$CROSS_PEER_PID" || cross_fail "terminal session failed ($SESSION_LOG)"
  CROSS_PEER_PID=""
  exec 4>&-
}
session_finished() { ! kill -0 "$CROSS_PEER_PID" 2>/dev/null; }
shell_exit() {
  local at
  at="$(mark "$1")"
  printf ':q\r' >&"$2"
  wait_text "$1" "$at" $'\033[?1049l'
  prompt "$1" "$at"
}

echo "-- serial console --"
prompt "$CONSOLE_LOG" 0
console_command 'echo PROMPT_WIDTH=$COLUMNS' 'PROMPT_WIDTH=80'
at="$(mark "$CONSOLE_LOG")"
printf '\033[?2048;1$y\033[48;30;100;0;0t' >&"$VM_SERIAL_FD"
prompt "$CONSOLE_LOG" "$at"
console_command 'echo PROMPT_WIDTH=$COLUMNS' 'PROMPT_WIDTH=100'
at="$(mark "$CONSOLE_LOG")"
printf 'echo RESIZE-ME' >&"$VM_SERIAL_FD"
wait_text "$CONSOLE_LOG" "$at" 'echo RESIZE-ME'
at="$(mark "$CONSOLE_LOG")"
printf '\033[48;20;60;0;0t' >&"$VM_SERIAL_FD"
wait_text "$CONSOLE_LOG" "$at" 'echo RESIZE-ME'
prompt "$CONSOLE_LOG" "$at"
console_command '' $'\r\n'
console_command 'echo PROMPT_WIDTH=$COLUMNS; echo COLS=$COLUMNS,$LINES' 'COLS=60,20'
console_command 'echo PROMPT_WIDTH=$COLUMNS' 'PROMPT_WIDTH=60'
widths="$(grep -aoE 'PROMPT_WIDTH=[0-9]+' "$CONSOLE_LOG" | tr '\n' ' ')"
[ "$widths" = 'PROMPT_WIDTH=80 PROMPT_WIDTH=100 PROMPT_WIDTH=60 PROMPT_WIDTH=60 ' ] ||
  cross_fail "console widths: $widths"

echo "-- red on the serial console --"
red_at="$(mark "$CONSOLE_LOG")"
start_red console >&"$VM_SERIAL_FD"
wait_bars "$CONSOLE_LOG" "$red_at" '23:80'
printf '\033[?2048;1$y\033[48;20;60;0;0t' >&"$VM_SERIAL_FD"
wait_bars "$CONSOLE_LOG" "$red_at" '23:80 19:60'
printf '\033[48;30;100;0;0t' >&"$VM_SERIAL_FD"
wait_bars "$CONSOLE_LOG" "$red_at" '23:80 19:60 29:100'
shell_exit "$CONSOLE_LOG" "$VM_SERIAL_FD"

echo "-- russhd pty session --"
start_session rush-ssh pty
prompt "$SESSION_LOG" 0
at="$(mark "$SESSION_LOG")"
printf 'echo PROMPT_WIDTH=$COLUMNS\r' >&4
wait_text "$SESSION_LOG" "$at" 'PROMPT_WIDTH=100'
prompt "$SESSION_LOG" "$at"
at="$(mark "$SESSION_LOG")"
printf 'echo RESIZE-ME' >&4
wait_text "$SESSION_LOG" "$at" 'echo RESIZE-ME'
at="$(mark "$SESSION_LOG")"
resize_session 20 60
wait_text "$SESSION_LOG" "$at" 'echo RESIZE-ME'
prompt "$SESSION_LOG" "$at"
at="$(mark "$SESSION_LOG")"
printf '\r' >&4
prompt "$SESSION_LOG" "$at"
at="$(mark "$SESSION_LOG")"
printf 'echo PROMPT_WIDTH=$COLUMNS; echo COLS=$COLUMNS,$LINES\r' >&4
wait_text "$SESSION_LOG" "$at" 'COLS=60,20'
prompt "$SESSION_LOG" "$at"
at="$(mark "$SESSION_LOG")"
printf 'echo PROMPT_WIDTH=$COLUMNS\r' >&4
wait_text "$SESSION_LOG" "$at" 'PROMPT_WIDTH=60'
prompt "$SESSION_LOG" "$at"
printf 'exit\r' >&4
finish_session
widths="$(grep -aoE 'PROMPT_WIDTH=[0-9]+' "$SESSION_LOG" | tr '\n' ' ')"
[ "$widths" = 'PROMPT_WIDTH=100 PROMPT_WIDTH=60 PROMPT_WIDTH=60 ' ] ||
  cross_fail "SSH widths: $widths"

echo "-- red in a russhd pty session --"
start_session red-ssh pty
prompt "$SESSION_LOG" 0
red_at="$(mark "$SESSION_LOG")"
start_red ssh >&4
wait_bars "$SESSION_LOG" "$red_at" '29:100'
resize_session 20 60
wait_bars "$SESSION_LOG" "$red_at" '29:100 19:60'
shell_exit "$SESSION_LOG" 4
printf 'exit\r' >&4
finish_session

  vm_ssh "cat $TEST_TMP/red-*.stderr" > "$SCRATCH/red.stderr"
  ssh "${SSH_OPTIONS[@]}" -O exit motor@192.168.4.2
  echo 'cross-test: console and SSH terminal size PASS'
}

# Login names and their credential files, through real logins. The rules for
# those files are tested where a check costs nothing: src/bin/russhd/tests
# (auth_store.rs, client_protocol.rs and, for the None role, motor_trust.rs)
# and src/imager/tests/set.rs.
cross_sshd_keys() {
  local IMAGER="$ROOT_DIR/build/obj/$BUILD/imager/$BUILD/imager"
  local HOST=192.168.4.2 USERS=/user/cfg/russhd/users.toml KEYS=/user/cfg/ssh
  local GUEST_TMP=/user/tmp/sshd-keys FIXTURE="$RUN_DIR/sshd-keys-data"
  local SOCKETS ADMIN KEYS_HOME LOGIN key standard copy
  SOCKETS="$(mktemp -d /tmp/motor-keys.XXXXXX)"
  CROSS_KEY_DIR="$SOCKETS"
  ADMIN="$SOCKETS/admin"
  KEYS_HOME="$SOCKETS/home"
  mkdir -p "$FIXTURE" "$KEYS_HOME/.ssh"
  chmod 700 "$KEYS_HOME" "$KEYS_HOME/.ssh"
  local USER_OPTIONS=(-F /dev/null -p 2222 -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes
    -o "UserKnownHostsFile=$KNOWN_HOSTS" -o ConnectTimeout=20)
  case "$(ssh-copy-id -h 2>&1 || true)" in
    *target_path*) ;;
    *) cross_fail 'ssh-copy-id -t requires OpenSSH 9.4 or newer' ;;
  esac

  # The shipped key opens one connection that outlives every credential change
  # below: russhd checks credentials when a connection authenticates, not
  # after, and a multiplexed session needs no new authentication.
  admin() {
    ssh "${SSH_OPTIONS[@]}" -S "$ADMIN" -o ControlMaster=no "motor@$HOST" "$@"
  }
  put() { admin "/user/bin/cat > $1"; }
  get() { admin "/user/bin/cat $1"; }
  public() { cat "$FIXTURE/$1.pub"; }

  expect_mode() {
    local mode
    mode="$(admin "/user/bin/ls -l ${1%/*}" | awk -v name="${1##*/}" '$NF == name { print $1 }')"
    [ "$mode" = "$2" ] || cross_fail "$1 has mode '$mode', want '$2'"
  }

  expect_lines() {
    local path="$1" actual expected
    shift
    actual="$(get "$path")"
    expected="$(printf '%s\n' "$@")"
    [ "$actual" = "$expected" ] || cross_fail "$path holds '$actual', want '$expected'"
  }

  # A login is one command, so that a pending one is a process to stop.
  key_login() {
    LOGIN=(ssh "${USER_OPTIONS[@]}" -o BatchMode=yes -o PreferredAuthentications=publickey
      -i "$FIXTURE/$2" "$1@$HOST" "${3:-/user/bin/rush -c true}")
  }

  password_login() {
    LOGIN=(env "SSHD_KEYS_PASSWORD=$2" "SSH_ASKPASS=$FIXTURE/askpass" SSH_ASKPASS_REQUIRE=force
      ssh "${USER_OPTIONS[@]}" -o BatchMode=no -o PreferredAuthentications=password
      -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 "$1@$HOST" /user/bin/rush -c true)
  }

  works() {
    "$@"
    "${LOGIN[@]}" 2> "$FIXTURE/last.err" || cross_fail "$* failed: $(cat "$FIXTURE/last.err")"
  }

  # russhd answers a refused login after 3 s. Refusals start here, wait side by
  # side, and are all checked by `refused`.
  refuse() {
    local label="$1"
    shift
    "$@"
    "${LOGIN[@]}" > /dev/null 2> "$FIXTURE/refused-$label.err" &
    CROSS_KEY_LOGINS+=("$label:$!")
  }

  # Only a refusal counts: a dead VM must not read as a passing negative check.
  refused() {
    local login label status
    for login in "${CROSS_KEY_LOGINS[@]}"; do
      label="${login%%:*}"
      status=0
      wait "${login##*:}" || status=$?
      if [ "$status" != 255 ] || ! grep -q 'Permission denied' "$FIXTURE/refused-$label.err"; then
        cross_fail "the $label login was not refused: status $status: $(cat "$FIXTURE/refused-$label.err")"
      fi
    done
    CROSS_KEY_LOGINS=()
  }

  cat > "$FIXTURE/askpass" <<'SH'
#!/bin/sh
printf '%s\n' "$SSHD_KEYS_PASSWORD"
SH
  chmod 700 "$FIXTURE/askpass"
  for key in alice bob carol installed; do
    ssh-keygen -q -t ed25519 -N '' -C "$key" -f "$FIXTURE/$key"
  done

  echo "-- names set by the imager log in --"
  standard="$ROOT_DIR/vm_images/$BUILD/motor-os.qcow2"
  [ "$VMM" != fc ] || standard="$ROOT_DIR/vm_images/$BUILD/motor-os.img"
  copy_test_image "$standard" sshd-keys
  copy="$VM_DIR/$MOTO_IMAGE"
  "$IMAGER" set --ssh-new-user alice --ssh-password alice-password -i "$copy"
  "$IMAGER" set --ssh-user alice --ssh-key "$FIXTURE/alice.pub" -i "$copy"
  "$IMAGER" set --ssh-new-user bob --ssh-key "$FIXTURE/bob.pub" -i "$copy"
  "$IMAGER" set --ssh-new-user carol --ssh-password carol-password -i "$copy"
  boot_test_image sshd-keys
  wait_vm_ssh
  CROSS_KEY_SOCKETS+=("$ADMIN")
  ssh "${SSH_OPTIONS[@]}" -M -S "$ADMIN" -N -f "motor@$HOST" || cross_fail "cannot open the admin connection"
  works key_login alice alice
  works key_login bob bob
  works password_login alice alice-password

  echo "-- Motor ssh-copy-id -t gives a name its first key --"
  admin "/user/bin/mkdir $GUEST_TMP"
  put "$GUEST_TMP/bob" < "$FIXTURE/bob"
  admin "/user/bin/chmod rwxrw---- $GUEST_TMP/bob"
  put "$GUEST_TMP/carol.pub" < "$FIXTURE/carol.pub"
  admin "/user/bin/ssh-copy-id -F /dev/null -p 2222 -o IdentityFile=$GUEST_TMP/bob \
    -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile=$GUEST_TMP/known_hosts -i $GUEST_TMP/carol.pub \
    -t $KEYS/authorized_keys.carol bob@127.0.0.1" > /dev/null ||
    cross_fail "Motor ssh-copy-id -t failed"
  expect_lines "$KEYS/authorized_keys.carol" "$(public carol)"
  expect_mode "$KEYS/authorized_keys.carol" -rwxrw----
  # This session is held open: it has to outlive its name.
  CROSS_KEY_SOCKETS+=("$SOCKETS/carol")
  ssh "${USER_OPTIONS[@]}" -o BatchMode=yes -i "$FIXTURE/carol" -M -S "$SOCKETS/carol" -N -f "carol@$HOST" ||
    cross_fail "carol cannot log in with the key Motor ssh-copy-id installed"

  echo "-- refused logins, and OpenSSH ssh-copy-id -s -t --"
  # carol's record goes, as docs/ssh-client.md says to edit the registry: a
  # whole new file, closed to None, renamed into place.
  get "$USERS" | awk '/^\[/ { skip = ($0 == "[users.carol]") } !skip' > "$FIXTURE/users.toml"
  if grep -q carol "$FIXTURE/users.toml" || ! grep -qx '\[users\.alice\]' "$FIXTURE/users.toml"; then
    cross_fail "the registry without carol is wrong: $(cat "$FIXTURE/users.toml")"
  fi
  put "$USERS.new" < "$FIXTURE/users.toml"
  admin "/user/bin/chmod rwxrw---- $USERS.new"
  admin "/user/bin/mv $USERS.new $USERS"
  refuse another-names-key key_login alice bob
  refuse wrong-password password_login alice wrong-password
  refuse unknown-name key_login nobody alice
  refuse path-as-name password_login ../ssh/authorized_keys.alice alice-password
  refuse removed-name key_login carol carol
  # OpenSSH's installer first tries the new key, and would call it installed
  # if an identity it was given logged in. It gets none: that login is refused
  # along with those above, and the password then installs the key.
  SSHD_KEYS_PASSWORD=alice-password SSH_ASKPASS="$FIXTURE/askpass" SSH_ASKPASS_REQUIRE=force \
    env HOME="$KEYS_HOME" ssh-copy-id -s -t "$KEYS/authorized_keys.alice" -i "$FIXTURE/installed.pub" \
    -p 2222 -F /dev/null -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$KNOWN_HOSTS" -o PreferredAuthentications=password \
    "alice@$HOST" < /dev/null > "$FIXTURE/openssh-copy-id.log" 2>&1 ||
    cross_fail "ssh-copy-id -s -t failed: $(cat "$FIXTURE/openssh-copy-id.log")"
  refused
  expect_lines "$KEYS/authorized_keys.alice" "$(public alice)" "$(public installed)"
  expect_mode "$KEYS/authorized_keys.alice" -rwxrw----
  # The installer also runs `chmod 700` on the directory, whose mode must stay.
  expect_mode "$KEYS" drwxrwx---
  [ "$(ssh "${USER_OPTIONS[@]}" -S "$SOCKETS/carol" -o ControlMaster=no "carol@$HOST" /user/bin/echo still-here)" = still-here ] ||
    cross_fail "removing a name ended its established session"

  echo "-- ssh, scp and sftp under another name --"
  [ "$(works key_login alice installed '/user/bin/echo as-alice')" = as-alice ] ||
    cross_fail "ssh as alice returned the wrong output"
  printf 'payload\n' > "$FIXTURE/payload"
  scp -F /dev/null -P 2222 -q -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$KNOWN_HOSTS" -i "$FIXTURE/alice" \
    "$FIXTURE/payload" "alice@$HOST:$GUEST_TMP/payload" || cross_fail "scp as alice failed"
  printf 'get %s/payload %s/returned\n' "$GUEST_TMP" "$FIXTURE" |
    sftp -q -b - -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
      -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS" \
      -i "$FIXTURE/alice" "alice@$HOST" > /dev/null || cross_fail "sftp as alice failed"
  cmp -s "$FIXTURE/payload" "$FIXTURE/returned" || cross_fail "the transfers changed the data"

  admin shutdown
  finish_test_image 20
  close_sshd_key_sessions
  echo "test-sshd-keys: PASS"
}

cross_upload_wasm_inputs() {
  local name inputs="$ROOT_DIR/build/assembly/tests"
  vm_ssh 'MOTOR_OS_CAPS=0x204 mkdir -p /none/dev/wasm-tests'
  for name in javy wasmtime; do
    (cd "$inputs/$name" && sha256sum --quiet -c SHA256SUMS)
    vm_ssh "MOTOR_OS_CAPS=0x204 mkdir /none/dev/wasm-tests/$name-tests"
    tar -C "$inputs/$name" -cf - . |
      vm_ssh "MOTOR_OS_CAPS=0x204 tar -xf - -C /none/dev/wasm-tests/$name-tests"
  done
}

cross_wasm() {
  if [ "$VMM" = fc ]; then
    echo 'SKIP Firecracker: Javy and Wasmtime host/guest byte comparisons'
    echo 'SKIP Firecracker: installed Wasm tools at 256 MiB and Wasm boot services'
    return
  fi
  local MOTO_MEMORY_MIB=256 MOTO_SMP=2
  export MOTO_MEMORY_MIB MOTO_SMP
  local imager="$ROOT_DIR/build/obj/$BUILD/imager/$BUILD/imager" name tool
  copy_test_image "$CROSS_IMAGE" wasm-small
  boot_test_image wasm-small
  wait_vm_ssh
  cross_upload_wasm_inputs
  for name in javy-smoke wasmtime-smoke; do
    printf 'put "%s" "/none/dev/wasm-tests/%s"\nchmod 755 "/none/dev/wasm-tests/%s"\n' \
      "$ROOT_DIR/src/sys/tests/$name/target/x86_64-unknown-motor/release/$name" "$name" "$name" | vm_sftp
  done
  # The installed programs must be the release payloads the gate just packaged.
  for tool in javy wasmi wasmtime wasmtime-rt; do
    name=javy
    case "$tool" in wasmtime*) name=wasmtime ;; esac
    printf 'get "/user/bin/dev/%s" "%s/installed-%s"\n' "$tool" "$RUN_DIR" "$tool" | vm_sftp
    cmp "$ROOT_DIR/build/assembly/images/$name/user/bin/dev/$tool" "$RUN_DIR/installed-$tool"
  done
  vm_ssh '/none/dev/wasm-tests/javy-smoke --linux-identity'
  vm_ssh 'MOTOR_OS_CAPS=0x200 /user/bin/dev/wasmtime compile --target x86_64-unknown-motor /none/dev/wasm-tests/wasmtime-tests/lifecycle.wat -o /none/dev/wasm-tests/native.cwasm'
  printf 'get /none/dev/wasm-tests/native.cwasm "%s/wasmtime-native.cwasm"\n' "$RUN_DIR" | vm_sftp
  cmp "$ROOT_DIR/build/assembly/tests/wasmtime/lifecycle.cwasm" "$RUN_DIR/wasmtime-native.cwasm"
  # This second execution qualifies the same native cases at the supported
  # memory floor; ordinary Cargo runs above use the selected full-gate memory.
  for name in javy-smoke wasmtime-smoke; do
    vm_ssh "/none/dev/wasm-tests/$name" | tee "$RUN_DIR/$name-256.log"
  done
  vm_ssh 'MOTOR_OS_CAPS=0x204 mkdir /none/dev/wasm-services'
  vm_ssh 'for input in /none/dev/wasm-tests/wasmtime-tests/p2_cli_serve_hello_world.cwasm /none/dev/wasm-tests/wasmtime-tests/p3_cli_serve_hello_world.cwasm /none/dev/wasm-tests/wasmtime-tests/p2_cli_serve_hello_world.wasm /none/dev/wasm-tests/wasmtime-tests/engine-tests /none/dev/wasm-tests/javy-tests/plugin-p1.wasm; do cp "$input" /none/dev/wasm-services/ || exit; done'
  shutdown_test_image
  cp "$ROOT_DIR/img_files/motor-os/system/cfg/sys-init.cfg" "$RUN_DIR/wasm-init.cfg"
  cat >> "$RUN_DIR/wasm-init.cfg" <<'CFG'
svc:256:/user/bin/dev/wasmtime-rt serve --allow-precompiled -S cli --addr 127.0.0.1:18180 --shutdown-addr 127.0.0.1:18181 --max-concurrent-requests 2 /none/dev/wasm-services/p2_cli_serve_hello_world.cwasm
svc:256:/user/bin/dev/wasmtime-rt serve --allow-precompiled -W component-model-async -S p3,cli --addr 127.0.0.1:18182 --shutdown-addr 127.0.0.1:18183 --max-concurrent-requests 2 /none/dev/wasm-services/p3_cli_serve_hello_world.cwasm
CFG
  "$imager" put "$VM_DIR/$MOTO_IMAGE" "$RUN_DIR/wasm-init.cfg" /system/cfg/sys-init.cfg
  if [ "$VMM" = qemu ]; then
    boot_test_image wasm-services
    wait_vm_ssh
    echo 'SKIP QEMU: System Wasm role matrix'
    vm_ssh '/none/dev/wasm-tests/wasmtime-smoke --boot-services'
  else
    boot_test_image wasm-services --system-tty
    wait_vm_ssh
    wait_console_line 1 '/user\$'
    printf 'MOTOR_OS_CAPS=0x34d /none/dev/wasm-tests/wasmtime-smoke --roles &\r' >&"$VM_SERIAL_FD"
    vm_ssh '/none/dev/wasm-tests/wasmtime-smoke --services' | tee "$RUN_DIR/wasm-services.log"
    for name in none none-extra interactive system; do
      grep -Eq "^PASS $name-serve-runtime: exit=0 elapsed_ms=[0-9]+ sampled_vm_peak_bytes=[1-9][0-9]* max_gap_us=[0-9]+$" "$RUN_DIR/wasm-services.log"
    done
    grep -Eq '^wasm-roles: [1-9][0-9]* commands PASS$' "$RUN_DIR/wasm-services.log"
  fi
  shutdown_test_image
}

cross_gix() (
  if [ "$VMM" = fc ]; then
    echo 'SKIP Firecracker: installed gix HTTPS/SSH transports and Git format comparisons'
    exit
  fi
  local APP_DIR="$ROOT_DIR/src/bin/gix" temporary="$RUN_DIR/gix" guest_root=/none/tmp/gix-cross
  local guest_created=0 https_pid= https_out_fd= gix_pty_pid= gix_pty_out= gix_pty_in=
  local native_port_binary https_server guest_gix=/user/bin/dev/gix
  mkdir "$temporary"
  fail() { cross_fail "gix: $*"; }
  cleanup_gix() {
    local status=$? pid
    trap - EXIT
    set +e
    for pid in "$gix_pty_pid" "$https_pid"; do
      [ -z "$pid" ] || { kill "$pid"; wait "$pid"; }
    done
    cleanup_ssh_client_host
    [ "$guest_created" = 0 ] || vm_ssh "rm -r $guest_root"
    exit "$status"
  }
  trap cleanup_gix EXIT
  unset GIT_INDEX_FILE GIT_AUTHOR_DATE GIT_COMMITTER_DATE
wait_https_line() {
  local expected="$1" line remaining deadline=$((SECONDS + 20))
  while [ "$SECONDS" -lt "$deadline" ]; do
    remaining=$((deadline - SECONDS))
    IFS= read -r -t "$remaining" line <&"$https_out_fd" || break
    printf '%s\n' "$line" >> "$temporary/https-server.stdout"
    [[ "$line" == "$expected"* ]] && { HTTPS_LINE="$line"; return; }
  done
  fail "HTTPS server did not print '$expected': $(cat "$temporary/https-server.stderr")"
}
# Each argument is the start of the fixture's next request line, in order.
expect_https_requests() {
  local expected line
  for expected in "$@"; do
    IFS= read -r -t 20 line <&"$https_out_fd" ||
      fail "HTTPS server logged no request; want '$expected'"
    printf '%s\n' "$line" >> "$temporary/https-server.stdout"
    [[ "$line" == "$expected"* ]] || fail "HTTPS server logged '$line', want '$expected'"
  done
}
start_https_server() {
  local bind="$1" name="$2"
  coproc HTTPS_SERVER {
    exec "$https_server" "$https_remote" "$https_push_remote" \
      "$temporary/https-server-work" "$bind" </dev/null 2> "$temporary/https-server.stderr"
  }
  https_pid="$HTTPS_SERVER_PID"
  exec {https_out_fd}<&"${HTTPS_SERVER[0]}"
  wait_https_line HTTPS_READY=
  https_port="${HTTPS_LINE#HTTPS_READY=}"
  case "$https_port" in "" | *[!0-9]*) fail "invalid HTTPS server port: $https_port" ;; esac
  [ "$https_port" -ge 1 ] && [ "$https_port" -le 65535 ] ||
    fail "invalid HTTPS server port: $https_port"
  https_origin="https://$name:$https_port"
}
stop_https_server() {
  local spontaneous=0 server_status=0
  kill -0 "$https_pid" 2>/dev/null || spontaneous=1
  [ "$spontaneous" -eq 1 ] || kill "$https_pid"
  set +e
  wait "$https_pid"
  server_status=$?
  set -e
  exec {https_out_fd}<&-
  https_pid=
  [ "$spontaneous" -eq 0 ] || fail "HTTPS server exited spontaneously"
  [ "$server_status" -eq 143 ] || fail "HTTPS server stopped with status $server_status"
  [ ! -s "$temporary/https-server.stderr" ] ||
    fail "HTTPS server wrote stderr: $(cat "$temporary/https-server.stderr")"
  rm -r "$temporary/https-server-work"
}

fixture="$temporary/fixture"
mkdir -p "$temporary/home" "$temporary/xdg" "$temporary/template"
clean_git() {
  local git_env=(
    env -i "PATH=$PATH" "HOME=$temporary/home"
    "XDG_CONFIG_HOME=$temporary/xdg" GIT_CONFIG_NOSYSTEM=1
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
    "GIT_TEMPLATE_DIR=$temporary/template"
  )
  if [ -n "${GIT_AUTHOR_DATE:-}" ]; then
    git_env+=("GIT_AUTHOR_DATE=$GIT_AUTHOR_DATE" "GIT_COMMITTER_DATE=$GIT_COMMITTER_DATE")
  fi
  if [ -n "${GIT_INDEX_FILE:-}" ]; then
    git_env+=("GIT_INDEX_FILE=$GIT_INDEX_FILE")
  fi
  "${git_env[@]}" git -c core.hooksPath=/dev/null "$@"
}
git_fixture() {
  clean_git -C "$fixture" "$@"
}
advance_remote() {
  local remote="$1" update="$2" content="$3"
  clean_git clone -q --no-hardlinks "$remote" "$update"
  clean_git -C "$update" config user.name "Motor Test"
  clean_git -C "$update" config user.email motor-test@example.invalid
  printf '%s\n' "$content" > "$update/remote-only"
  clean_git -C "$update" add remote-only
  GIT_AUTHOR_DATE=2001-01-03T00:00:00Z GIT_COMMITTER_DATE=2001-01-03T00:00:00Z \
    clean_git -C "$update" commit -qm remote-update
  clean_git -C "$update" push -q origin main
}
verify_network_clone() {
  local before="$1" after="$2" remote_repo="$3" initial_head="$4" label="$5"
  local initial remote initial_index
  initial="$(clean_git -C "$before" rev-parse HEAD)"
  remote="$(clean_git --git-dir="$remote_repo" rev-parse refs/heads/main)"
  [ "$initial" = "$initial_head" ] || fail "initial $label clone has the wrong HEAD"
  [ "$(clean_git -C "$before" rev-parse refs/remotes/origin/main)" = "$initial_head" ] ||
    fail "initial $label clone has the wrong tracking ref"
  initial_index="$(sha256sum "$before/.git/index")"
  clean_git -C "$before" -c core.symlinks=false diff-index --cached --quiet \
    --ignore-submodules=all "$initial_head" -- || fail "initial $label index differs from HEAD"
  # Copying changes stat data; inspect Git's content/mode diff without refreshing the index.
  clean_git -C "$before" -c core.symlinks=false -c core.fileMode=true \
    diff-files -p --no-ext-diff --no-textconv --ignore-submodules=all -- \
    > "$temporary/network-worktree.diff"
  [ ! -s "$temporary/network-worktree.diff" ] || fail "initial $label worktree differs from the index"
  [ "$(sha256sum "$before/.git/index")" = "$initial_index" ] ||
    fail "host Git verification modified the initial $label index"
  [ "$remote" != "$initial" ] || fail "$label remote did not advance"
  [ "$(clean_git -C "$after" rev-parse HEAD)" = "$initial" ] ||
    fail "fetch changed the checked-out $label branch"
  [ "$(clean_git -C "$after" rev-parse refs/remotes/origin/main)" = "$remote" ] ||
    fail "fetch did not advance $label origin/main"
  cmp "$before/.git/index" "$after/.git/index" >/dev/null || fail "fetch changed the $label index"
  diff -r --exclude=.git "$before" "$after" >/dev/null || fail "fetch changed the $label worktree"
  clean_git -C "$after" fsck --strict
}
wait_ssh_fixture_closed() {
  local name="$1" pid deadline=$((SECONDS + 20))
  wait_ssh_fixture_file "$SSH_CLIENT_HOST_ROOT/$name.closed" "$name-closed"
  pid="$(cat "$SSH_CLIENT_HOST_ROOT/$name.pid")"
  case "$pid" in ""|*[!0-9]*) fail "SSH fixture returned an invalid child pid" ;; esac
  while kill -0 "$pid" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ]; do
    sleep 0.05
  done
  ! kill -0 "$pid" 2>/dev/null || fail "SSH fixture $name process survived completion"
}
wait_ssh_fixture_file() {
  local path="$1" label="$2" deadline=$((SECONDS + 20))
  while [ ! -e "$path" ] && [ "$SECONDS" -lt "$deadline" ]; do
    kill -0 "$SSH_CLIENT_HOST_PROCESS" 2>/dev/null || fail "host russhd exited while waiting for $label"
    sleep 0.05
  done
  [ -e "$path" ] || fail "SSH fixture did not create $label"
}

# Run guest command $1 on a terminal; its output collects in $terminal_output.
start_guest_terminal() {
  coproc GIX_PTY {
    exec ssh "${SSH_OPTIONS[@]}" -e none -tt motor@192.168.4.2 "$1" 2>&1
  }
  gix_pty_pid="$GIX_PTY_PID"
  exec {gix_pty_out}<&"${GIX_PTY[0]}"
  exec {gix_pty_in}>&"${GIX_PTY[1]}"
  terminal_output=
}
wait_terminal_text() {
  local char deadline=$((SECONDS + 20))
  while [[ "$terminal_output" != *"$1"* ]]; do
    [ "$SECONDS" -lt "$deadline" ] || fail "terminal never showed '$1': $terminal_output"
    IFS= read -r -N 1 -t 20 char <&"$gix_pty_out" ||
      fail "terminal closed before showing '$1': $terminal_output"
    terminal_output+="$char"
  done
}
# Collect the rest of the output and the exit status in $terminal_status.
finish_guest_terminal() {
  set +e
  terminal_output+="$(cat <&"$gix_pty_out")"
  wait "$gix_pty_pid"
  terminal_status=$?
  set -e
  gix_pty_pid=
  exec {gix_pty_in}>&-
  exec {gix_pty_out}<&-
  gix_pty_in=
  gix_pty_out=
}
# Answer gix's questions on the terminal of guest command $1 with token $2.
answer_credentials() {
  start_guest_terminal "$1"
  wait_terminal_text "Username for '$https_origin': "
  printf 'fixture-user\r' >&"$gix_pty_in"
  wait_terminal_text "Password or token for 'https://fixture-user@${https_origin#https://}': "
  printf '%s\r' "$2" >&"$gix_pty_in"
  finish_guest_terminal
}

build_fixture() {
  local initial_id link_id utf8_name
  utf8_name=$'caf\xc3\xa9'
  clean_git init -q --initial-branch=main "$fixture"
  git_fixture config user.name "Motor Test"
  git_fixture config user.email motor-test@example.invalid
  printf 'first\n' > "$fixture/editable"
  printf 'utf8\n' > "$fixture/$utf8_name"
  git_fixture add editable "$utf8_name"
  git_fixture update-index --chmod=+x editable
  link_id="$(printf editable | git_fixture hash-object -w --stdin)"
  git_fixture update-index --add --cacheinfo "120000,$link_id,link"
  GIT_AUTHOR_DATE=2001-01-01T00:00:00Z GIT_COMMITTER_DATE=2001-01-01T00:00:00Z git_fixture commit -qm initial
  initial_id="$(git_fixture rev-parse HEAD)"
  git_fixture commit-graph write --reachable --split=no-merge
  printf 'other\n' > "$fixture/editable"
  git_fixture add editable
  git_fixture update-index --chmod=+x editable
  git_fixture update-index --add --cacheinfo "160000,$initial_id,nested"
  GIT_AUTHOR_DATE=2001-01-02T00:00:00Z GIT_COMMITTER_DATE=2001-01-02T00:00:00Z git_fixture commit -qm second
  git_fixture commit-graph write --reachable --split=no-merge
  [ "$(wc -l < "$fixture/.git/objects/info/commit-graphs/commit-graph-chain")" -eq 2 ] ||
    fail "fixture does not contain a two-file commit-graph chain"
  git_fixture pack-refs --all
  git_fixture repack -adq
  git_fixture prune-packed
  git_fixture fsck --strict
  [ "$(git_fixture count-objects -v | sed -n 's/^count: //p')" = 0 ] ||
    fail "fixture contains loose objects"
  # Motor represents indexed symlinks as ordinary files containing the link text.
  printf editable > "$fixture/link"
}
build_fixture
https_remote="$temporary/https-remote.git"
clean_git clone -q --bare --no-hardlinks "$fixture" "$https_remote"
https_initial_head="$(clean_git --git-dir="$https_remote" rev-parse refs/heads/main)"
https_push_remote="$temporary/https-push.git"
clean_git init --bare -q "$https_push_remote"
verify_index() {
  local actual expected
  expected="$(git_fixture rev-parse 'HEAD^{tree}')"
  actual="$(GIT_INDEX_FILE="$1" git_fixture write-tree)"
  [ "$actual" = "$expected" ] || fail "written index does not reproduce fixture tree"
}

verify_add_repository() {
  local repository="$1" listing="$temporary/add-index" tree
  clean_git -C "$repository" ls-files --stage > "$listing"
  [ "$(wc -l < "$listing")" -eq 12 ] || fail "add fixture index has the wrong entry count"
  grep -Eq '^100755 [0-9a-f]{40} 0[[:space:]]+executable$' "$listing" ||
    fail "add did not preserve executable mode"
  grep -Eq '^120000 [0-9a-f]{40} 0[[:space:]]+link-preserved$' "$listing" ||
    fail "add did not preserve symlink mode"
  for path in gitlink missing-gitlink blocked-parent/nested; do
    grep -Eq "^160000 [0-9a-f]{40} 0[[:space:]]+$path$" "$listing" ||
      fail "add did not preserve gitlink $path"
  done
  [ -z "$(clean_git -C "$repository" ls-files --unmerged)" ] ||
    fail "add did not resolve the regular-file conflict"
  for path in deleted ignored-new file-parent directory/old gitlink/untracked-child; do
    ! grep -Eq "[[:space:]]$path$" "$listing" || fail "add retained forbidden path $path"
  done
  [ "$(clean_git -C "$repository" show :modified)" = new ] ||
    fail "add staged the wrong modified content"
  [ "$(clean_git -C "$repository" show :ignored-tracked)" = 'new ignored' ] ||
    fail "add did not update a tracked ignored path"
  [ "$(clean_git -C "$repository" show :conflict)" = resolved ] ||
    fail "add staged the wrong conflict resolution"
  [ "$(clean_git -C "$repository" show :file-parent/child)" = child ] ||
    fail "add did not replace an indexed file with a child"
  [ "$(clean_git -C "$repository" show :directory)" = 'now a file' ] ||
    fail "add did not replace an indexed directory with a file"
  tree="$(clean_git -C "$repository" write-tree)"
  clean_git -C "$repository" cat-file -e "$tree^{tree}"
  clean_git -C "$repository" fsck --strict --no-dangling >/dev/null
}

# Branch and remote listings must print exactly what Git prints for the same
# repository. $2 holds one gix output file per command, named by listing_file.
# clean_git ignores the user configuration that gix reads, so both sides get
# the same explicit abbreviation length.
listing_commands=("branch" "branch -a" "branch -v" "branch -a -v" "remote" "remote -v")
listing_file() { printf '%s' "${1// /_}"; }
verify_listings() {
  local repository="$1" outputs="$2" command
  for command in "${listing_commands[@]}"; do
    # shellcheck disable=SC2086 # the command is a fixed word list
    clean_git -C "$repository" -c core.abbrev=12 $command > "$temporary/expected-listing"
    cmp "$temporary/expected-listing" "$outputs/$(listing_file "$command")" >/dev/null ||
      fail "gix $command differs from git: $(cat "$outputs/$(listing_file "$command")")"
  done
  grep -Fq '[behind 1]' "$outputs/$(listing_file "branch -v")" ||
    fail "gix branch -v did not report the fetched upstream commit"
}

# The checkout sequence both flows run on their HTTPS clone, whose main is one
# commit behind origin/main: a tracked branch at another commit, back to main,
# then a branch at the same commit that must keep a local edit to `editable`.
# $1 is the repository as Git sees it, $2 holds the captured gix output.
verify_checkout() {
  local repository="$1" outputs="$2" expected
  while IFS='|' read -r file expected; do
    grep -Fqx -- "$expected" "$outputs/$file" ||
      fail "gix checkout $file lacks '$expected': $(cat "$outputs/$file")"
  done <<'EOF_EXPECTED'
tracked.out|branch 'cli-tracked' set up to track 'origin/main'.
tracked.err|Switched to a new branch 'cli-tracked'
main.out|Your branch is behind 'origin/main' by 1 commit, and can be fast-forwarded.
main.err|Switched to branch 'main'
again.err|Already on 'main'
local.out|branch 'cli-local' set up to track 'main'.
local.err|Switched to a new branch 'cli-local'
EOF_EXPECTED
  [ "$(clean_git -C "$repository" symbolic-ref HEAD)" = refs/heads/cli-local ] ||
    fail "gix checkout left the wrong branch checked out"
  [ "$(clean_git -C "$repository" rev-parse cli-tracked)" = \
    "$(clean_git -C "$repository" rev-parse origin/main)" ] ||
    fail "gix checkout -b started at the wrong commit"
  [ "$(clean_git -C "$repository" rev-parse cli-local)" = \
    "$(clean_git -C "$repository" rev-parse main)" ] ||
    fail "gix checkout --track -b started at the wrong commit"
  expected="origin refs/heads/main . refs/heads/main"
  [ "$(clean_git -C "$repository" config branch.cli-tracked.remote) $(
    clean_git -C "$repository" config branch.cli-tracked.merge) $(
    clean_git -C "$repository" config branch.cli-local.remote) $(
    clean_git -C "$repository" config branch.cli-local.merge)" = "$expected" ] ||
    fail "gix checkout recorded the wrong upstream"
  # As in verify_network_clone: compare content, since stat data alone may look stale to Git.
  [ "$(clean_git -C "$repository" -c core.symlinks=false -c core.fileMode=true \
    diff-files -p --no-ext-diff --no-textconv --ignore-submodules=all -- |
    grep '^diff --git')" = "diff --git a/editable b/editable" ] ||
    fail "gix checkout -b at the same commit did not keep exactly the local edit"
  [ ! -e "$repository/remote-only" ] || fail "gix checkout main kept a file of origin/main"
  clean_git -C "$repository" fsck --strict --no-dangling >/dev/null
}

verify_pack() {
  local indices=("$1"/*.idx)
  [ "${#indices[@]}" -eq 1 ] && [ -f "${indices[0]}" ] ||
    fail "rewritten fixture pack index was not found exactly once"
  clean_git verify-pack -- "${indices[0]}"
}

verify_push_pack() {
  local fixture="$1" receiver="$2" c0 merge
  read -r c0 < "$fixture/C0"
  read -r merge < "$fixture/M"
  [[ "$c0" =~ ^[0-9a-f]{40}$ ]] || fail "push fixture has an invalid C0"
  [[ "$merge" =~ ^[0-9a-f]{40}$ ]] || fail "push fixture has an invalid M"
  [ "$(clean_git -C "$fixture/source" rev-parse refs/heads/main)" = "$merge" ] ||
    fail "push source main does not name M"

  clean_git init --bare -q "$receiver"
  clean_git -C "$receiver" index-pack --strict --stdin < "$fixture/initial.pack" >/dev/null
  clean_git -C "$receiver" cat-file -e "$c0^{commit}"
  if clean_git -C "$receiver" cat-file -e "$merge^{commit}" 2>/dev/null; then
    fail "initial push pack already contains M"
  fi
  clean_git -C "$receiver" update-ref refs/heads/main "$c0"
  clean_git -C "$receiver" index-pack --strict --stdin < "$fixture/incremental.pack" >/dev/null
  clean_git -C "$receiver" update-ref refs/heads/main "$merge" "$c0"
  [ "$(clean_git -C "$receiver" show main:conflict)" = resolved ] ||
    fail "incremental push pack has the wrong merge resolution"
  [ "$(clean_git -C "$receiver" show main:unchanged)" = unchanged ] ||
    fail "incremental push pack lost baseline content"
  [ "$(clean_git -C "$receiver" show main:side-one)" = one ] ||
    fail "incremental push pack lost the first parent content"
  [ "$(clean_git -C "$receiver" show main:side-two)" = two ] ||
    fail "incremental push pack lost the second parent content"
  clean_git -C "$receiver" fsck --strict --no-dangling >/dev/null
}

# Anonymous push through the fixture's receive-pack routes. $1 runs gix on the
# push-pack source with the fixture CA; $2 and $3 are that fixture's C0 and M.
verify_https_push() {
  local gix="$1" c0="$2" m="$3" url="$https_origin/push.git" output
  local get="GET /push.git/info/refs?service=git-receive-pack -> 200"
  local post="POST /push.git/git-receive-pack -> 200"
  output="$("$gix" push "$url" "$c0:refs/heads/main")" || fail "HTTPS push failed"
  [ "$output" = "remote accepted: refs/heads/main -> $c0" ] ||
    fail "HTTPS push output differs: $output"
  expect_https_requests "$get" "$post"
  output="$("$gix" push --dry-run "$url" HEAD:refs/heads/main)" || fail "HTTPS dry run failed"
  [ "$output" = "would update: refs/heads/main -> $m" ] ||
    fail "HTTPS dry run output differs: $output"
  expect_https_requests "$get"
  output="$("$gix" push "$url" HEAD:refs/heads/main)" || fail "HTTPS fast-forward failed"
  [ "$output" = "remote accepted: refs/heads/main -> $m" ] ||
    fail "HTTPS fast-forward output differs: $output"
  expect_https_requests "$get" "$post"
  output="$("$gix" push "$url" HEAD:refs/heads/main)" || fail "HTTPS no-op push failed"
  [ "$output" = "up to date: refs/heads/main -> $m" ] ||
    fail "HTTPS no-op output differs: $output"
  expect_https_requests "$get"
  if "$gix" push "--force-with-lease=refs/heads/main:$c0" "$url" HEAD:refs/heads/main \
    > /dev/null 2> "$temporary/https-stale.err"; then
    fail "HTTPS push accepted a stale lease"
  fi
  grep -F 'push lease does not match the advertised destination' \
    "$temporary/https-stale.err" > /dev/null || fail "stale HTTPS lease was not reported"
  expect_https_requests "$get"
  if "$gix" push "--force-with-lease=refs/heads/main:$m" \
    "$https_origin/fast-forward-only/push.git" "$c0:refs/heads/main" \
    > /dev/null 2> "$temporary/https-rejected.err"; then
    fail "HTTPS push succeeded where the server refuses rewrites"
  fi
  grep -F 'remote rejected the update: non-fast-forward' "$temporary/https-rejected.err" \
    > /dev/null || fail "HTTPS remote rejection was not reported: $(cat "$temporary/https-rejected.err")"
  expect_https_requests "GET /fast-forward-only/push.git/info/refs?service=git-receive-pack -> 200" \
    "POST /fast-forward-only/push.git/git-receive-pack -> 200"
  output="$("$gix" -c "remote.fixture.url=$https_origin/repo.git" \
    -c "remote.fixture.pushUrl=$url" push fixture "$c0:refs/tags/published")" ||
    fail "HTTPS push to a configured pushUrl failed"
  [ "$output" = "remote accepted: refs/tags/published -> $c0" ] ||
    fail "HTTPS pushUrl output differs: $output"
  expect_https_requests "$get" "$post"
  [ "$(clean_git --git-dir="$https_push_remote" rev-parse refs/heads/main)" = "$m" ] ||
    fail "HTTPS push left main at the wrong commit"
  [ "$(clean_git --git-dir="$https_push_remote" rev-parse refs/tags/published)" = "$c0" ] ||
    fail "HTTPS pushUrl push wrote the wrong tag"
  clean_git --git-dir="$https_push_remote" fsck --strict --no-dangling > /dev/null
}
  local profile=()
  [ "$BUILD" != release ] || profile=(--release)
  cargo build --manifest-path "$APP_DIR/Cargo.toml" --locked --offline "${profile[@]}" \
    --test https-server --message-format=json > "$temporary/host-artifacts.json"
  https_server="$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "https-server") | .executable' "$temporary/host-artifacts.json")"
  cargo build --manifest-path "$APP_DIR/Cargo.toml" --locked --offline "${profile[@]}" \
    --features native-test-support --target x86_64-unknown-motor \
    --test native-port --message-format=json > "$temporary/motor-artifacts.json"
  native_port_binary="$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "native-port") | .executable' "$temporary/motor-artifacts.json")"
  [ -x "$native_port_binary" ] && [ -x "$https_server" ] || fail 'transport helpers were not built'
  vm_ssh "mkdir -p $guest_root/fixture $guest_root/home $guest_root/xdg"
  guest_created=1
  sftp_command=(sftp "${SFTP_OPTIONS[@]}" -b - motor@192.168.4.2)
  {
    printf 'put "%s" "%s/native-port"\nchmod 755 "%s/native-port"\n' "$native_port_binary" "$guest_root" "$guest_root"
    printf 'put "%s" "%s/test-ca.pem"\n' "$APP_DIR/tests/https-test-ca.pem" "$guest_root"
    printf 'put -r "%s" "%s/fixture"\n' "$fixture/.git" "$guest_root"
  } | "${sftp_command[@]}"
vm_ssh "$guest_root/native-port" --export-wire-data "$guest_root/fixture" "$guest_root/output"
printf 'get "%s" "%s"\n' "$guest_root/output/written.index" "$temporary/guest.index" |
  "${sftp_command[@]}"
verify_index "$temporary/guest.index"
printf 'get -r "%s" "%s"\n' "$guest_root/output/pack-roundtrip" "$temporary/guest-pack" |
  "${sftp_command[@]}"
verify_pack "$temporary/guest-pack"
printf 'get -r "%s" "%s"\n' "$guest_root/output/pack-thin" "$temporary/guest-thin-pack" |
  "${sftp_command[@]}"
verify_pack "$temporary/guest-thin-pack"
printf 'get -r "%s" "%s"\n' "$guest_root/output/push-pack" "$temporary/guest-push-pack" |
  "${sftp_command[@]}"
verify_push_pack "$temporary/guest-push-pack" "$temporary/guest-push-receiver"

printf 'get -r "%s" "%s"\n' "$guest_root/output/add-repository" "$temporary/guest-add" |
  "${sftp_command[@]}"
verify_add_repository "$temporary/guest-add"

start_https_server 192.168.4.1 192.168.4.1
guest_clone="$guest_root/https-clone"
vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -c http.sslCAInfo=$guest_root/test-ca.pem clone $https_origin/redirect/repo.git $guest_clone"
printf 'get -r "%s" "%s"\n' "$guest_clone" "$temporary/guest-clone-before" |
  "${sftp_command[@]}"
advance_remote "$https_remote" "$temporary/https-update" "remote update"
vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_clone -c http.sslCAInfo=$guest_root/test-ca.pem fetch"
printf 'get -r "%s" "%s"\n' "$guest_clone" "$temporary/guest-clone-after" |
  "${sftp_command[@]}"
verify_network_clone "$temporary/guest-clone-before" "$temporary/guest-clone-after" "$https_remote" "$https_initial_head" HTTPS
mkdir "$temporary/guest-listings"
for command in "${listing_commands[@]}"; do
  vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_clone -c core.abbrev=12 $command" \
    > "$temporary/guest-listings/$(listing_file "$command")"
done
verify_listings "$temporary/guest-clone-after" "$temporary/guest-listings"
guest_checkout() {
  local name="$1"
  shift
  vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_clone checkout $*" \
    > "$temporary/guest-checkout/$name.out" 2> "$temporary/guest-checkout/$name.err"
}
mkdir "$temporary/guest-checkout"
guest_checkout tracked -b cli-tracked origin/main
guest_checkout main main
guest_checkout again main
printf 'other\nlocal edit\n' > "$temporary/guest-editable"
printf 'put "%s" "%s"\n' "$temporary/guest-editable" "$guest_clone/editable" | "${sftp_command[@]}"
guest_checkout local --track -b cli-local main
printf 'get -r "%s" "%s"\n' "$guest_clone" "$temporary/guest-clone-checkout" |
  "${sftp_command[@]}"
verify_checkout "$temporary/guest-clone-checkout" "$temporary/guest-checkout"

coproc GIX_PTY {
  exec ssh "${SSH_OPTIONS[@]}" -e none -tt motor@192.168.4.2 \
    "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -c http.sslCAInfo=$guest_root/test-ca.pem clone $https_origin/stall/repo.git $guest_root/stalled-clone" 2>&1
}
gix_pty_pid="$GIX_PTY_PID"
exec {gix_pty_out}<&"${GIX_PTY[0]}"
exec {gix_pty_in}>&"${GIX_PTY[1]}"
wait_https_line STALL_READY
printf '\003' >&"$gix_pty_in"
exec {gix_pty_in}>&-
gix_pty_in=
set +e
gix_pty_output="$(cat <&"$gix_pty_out")"
gix_pty_read_status=$?
wait "$gix_pty_pid"
gix_pty_status=$?
gix_pty_pid=
set -e
exec {gix_pty_out}<&-
gix_pty_out=
[ "$gix_pty_read_status" -eq 0 ] || fail "cancelled clone PTY output failed"
[ "$gix_pty_status" -eq 130 ] ||
  fail "cancelled clone exited $gix_pty_status, want 130: $gix_pty_output"
wait_https_line STALL_CLOSED
printf 'get "%s" "%s"\n' \
  "$guest_root/stalled-clone/.git/gix-incomplete-clone" "$temporary/native-incomplete-clone" |
  "${sftp_command[@]}"
[ ! -s "$temporary/native-incomplete-clone" ] ||
  fail "cancelled native clone marker was not empty"
stop_https_server

start_https_server 192.168.4.1 192.168.4.1
guest_https_gix() {
  vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_root/output/push-pack/source -c http.sslCAInfo=$guest_root/test-ca.pem $*"
}
read -r push_c0 < "$temporary/guest-push-pack/C0"
read -r push_m < "$temporary/guest-push-pack/M"
verify_https_push guest_https_gix "$push_c0" "$push_m"

auth_url="$https_origin/auth/push.git"
auth_get="GET /auth/push.git/info/refs?service=git-receive-pack"
auth_post="POST /auth/push.git/git-receive-pack"
guest_auth_push="HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_root/output/push-pack/source -c http.sslCAInfo=$guest_root/test-ca.pem push $auth_url"
# A plain SSH command has no terminal to ask on.
if guest_https_gix push "$auth_url" "$push_c0:refs/heads/auth" \
  > /dev/null 2> "$temporary/guest-auth.err"; then
  fail "HTTPS push succeeded without a terminal"
fi
grep -F "$https_origin wants a user name and password" "$temporary/guest-auth.err" > /dev/null ||
  fail "missing credentials were not reported: $(cat "$temporary/guest-auth.err")"
expect_https_requests "$auth_get -> 401 anonymous"

answer_credentials "$guest_auth_push $push_c0:refs/heads/auth" fixture-token
[ "$terminal_status" -eq 0 ] ||
  fail "authenticated HTTPS push exited $terminal_status: $terminal_output"
[[ "$terminal_output" == *"Username for '$https_origin': fixture-user"* ]] ||
  fail "the terminal did not show the user name: $terminal_output"
[[ "$terminal_output" != *fixture-token* ]] || fail "the terminal showed the token"
[[ "$terminal_output" == *"remote accepted: refs/heads/auth -> $push_c0"* ]] ||
  fail "authenticated HTTPS push output differs: $terminal_output"
expect_https_requests "$auth_get -> 401 anonymous" "$auth_get -> 200 good-credentials" \
  "$auth_post -> 200 good-credentials"
[ "$(clean_git --git-dir="$https_push_remote" rev-parse refs/heads/auth)" = "$push_c0" ] ||
  fail "authenticated HTTPS push wrote the wrong ref"

answer_credentials "$guest_auth_push HEAD:refs/heads/auth" wrong-token
[ "$terminal_status" -eq 1 ] || fail "a refused token exited $terminal_status: $terminal_output"
[[ "$terminal_output" == *"the server refused the credentials"* ]] ||
  fail "the refused token was not reported: $terminal_output"
expect_https_requests "$auth_get -> 401 anonymous" "$auth_get -> 401 bad-credentials"

start_guest_terminal "$guest_auth_push HEAD:refs/heads/auth"
wait_terminal_text "Username for '$https_origin': "
printf 'fixture-user\r' >&"$gix_pty_in"
wait_terminal_text "Password or token for "
printf '\003' >&"$gix_pty_in"
finish_guest_terminal
[ "$terminal_status" -eq 130 ] ||
  fail "Ctrl+C at the password question exited $terminal_status: $terminal_output"
expect_https_requests "$auth_get -> 401 anonymous"
[ "$(clean_git --git-dir="$https_push_remote" rev-parse refs/heads/auth)" = "$push_c0" ] ||
  fail "an unanswered HTTPS push changed the remote"

answer_credentials "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -c http.sslCAInfo=$guest_root/test-ca.pem clone $https_origin/auth/repo.git $guest_root/auth-clone" fixture-token
[ "$terminal_status" -eq 0 ] ||
  fail "authenticated HTTPS clone exited $terminal_status: $terminal_output"
auth_clone_get="GET /auth/repo.git/info/refs?service=git-upload-pack"
expect_https_requests "$auth_clone_get -> 401 anonymous" "$auth_clone_get -> 200 good-credentials" \
  "POST /auth/repo.git/git-upload-pack -> 200 good-credentials" \
  "POST /auth/repo.git/git-upload-pack -> 200 good-credentials"
printf 'get -r "%s" "%s"\n' "$guest_root/auth-clone" "$temporary/guest-auth-clone" |
  "${sftp_command[@]}"
[ "$(clean_git -C "$temporary/guest-auth-clone" rev-parse HEAD)" = \
  "$(clean_git --git-dir="$https_remote" rev-parse refs/heads/main)" ] ||
  fail "authenticated HTTPS clone checked out the wrong commit"
clean_git -C "$temporary/guest-auth-clone" fsck --strict > /dev/null
stop_https_server

prepare_ssh_client_host "$TEST_KEY"
ssh_bin="$SSH_CLIENT_HOST_ROOT/gix-bin"
ssh_remote="$SSH_CLIENT_HOST_ROOT/repo name's.git"
ssh_push_remote="$SSH_CLIENT_HOST_ROOT/push.git"
mkdir -p "$ssh_bin"
clean_git clone -q --bare --no-hardlinks "$fixture" "$ssh_remote"
clean_git init --bare -q "$ssh_push_remote"
mkdir -p "$ssh_push_remote/hooks"
ssh_initial_head="$(clean_git --git-dir="$ssh_remote" rev-parse refs/heads/main)"
cat > "$ssh_bin/git-upload-pack" <<'SH'
#!/bin/sh
root=${0%/gix-bin/git-upload-pack}
case "${1:-}" in
"$root/repo name's.git")
  printf 'GIX_SSH_SUCCESS_STDERR\n' >&2
  exec /usr/bin/git-upload-pack "$@"
  ;;
"$root/stderr.git")
  trap ': > "$root/stderr.closed"' EXIT
  printf '%s\n' "$$" > "$root/stderr.pid"
  : > "$root/stderr.ready"
  /usr/bin/head -c 65537 /dev/zero | /usr/bin/tr '\000' E >&2
  while IFS= read -r line; do :; done
  ;;
"$root/stall.git")
  trap ': > "$root/stall.closed"' EXIT
  printf '%s\n' "$$" > "$root/stall.pid"
  : > "$root/stall.ready"
  while IFS= read -r line; do :; done
  ;;
*)
  printf 'unexpected upload-pack path: %s\n' "${1:-}" >&2
  exit 97
  ;;
esac
SH
cat > "$ssh_bin/git-receive-pack" <<'SH'
#!/bin/sh
root=${0%/gix-bin/git-receive-pack}
case "${1:-}" in
"$root/push.git") exec /usr/bin/git-receive-pack "$@" ;;
*) printf 'unexpected receive-pack path: %s\n' "${1:-}" >&2; exit 97 ;;
esac
SH
cat > "$ssh_push_remote/hooks/pre-receive" <<'SH'
#!/bin/sh
cat >/dev/null
if [ -e hooks/reject ]; then
  printf 'fixture hook rejection\n' >&2
  exit 1
fi
SH
chmod 755 "$ssh_bin/git-upload-pack" "$ssh_bin/git-receive-pack" \
  "$ssh_push_remote/hooks/pre-receive"
start_ssh_client_host "$TEST_KEY" 0 "$ssh_bin:/bin:/usr/bin"
ssh_base="ssh://motor@192.168.4.1:$SSH_CLIENT_HOST_PORT$SSH_CLIENT_HOST_ROOT"
ssh_repo_url="$ssh_base/repo%20name%27s.git"

ssh_rejected="$guest_root/ssh-unknown-host"
set +e
vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix clone $ssh_repo_url $ssh_rejected" \
  > "$temporary/ssh-unknown.stdout" 2> "$temporary/ssh-unknown.stderr"
ssh_status=$?
set -e
[ "$ssh_status" -eq 1 ] || fail "unknown-host SSH clone exited $ssh_status, want 1"
grep -F 'Unknown server key' "$temporary/ssh-unknown.stderr" >/dev/null ||
  fail "unknown-host SSH clone lacked the host-key diagnostic: $(cat "$temporary/ssh-unknown.stderr")"
vm_ssh "[ ! -e $SSH_CLIENT_HOST_GUEST_KNOWN ]" || fail "strict SSH clone recorded an unknown host"
printf 'get "%s" "%s"\n' \
  "$ssh_rejected/.git/gix-incomplete-clone" "$temporary/ssh-unknown-marker" |
  "${sftp_command[@]}"
[ ! -s "$temporary/ssh-unknown-marker" ] || fail "unknown-host clone marker was not empty"

trust_ssh_client_host "$SSH_CLIENT_HOST_PORT"

guest_push_source="$guest_root/output/push-pack/source"
guest_push_app="HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_push_source push"
ssh_push_url="$ssh_base/push.git"
guest_named_push_app="HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_push_source -c remote.fixture.url=$ssh_base/not-push.git -c remote.fixture.pushUrl=$ssh_push_url push"
read -r push_c0 < "$temporary/guest-push-pack/C0"
read -r push_m < "$temporary/guest-push-pack/M"
expect_guest_push() {
  local expected="$1" actual
  shift
  actual="$(vm_ssh "$guest_push_app $*")" || fail "SSH push failed: $*"
  [ "$actual" = "$expected" ] ||
    fail "SSH push output differs: got '$actual', want '$expected'"
}
expect_guest_push_failure() {
  local name="$1" expected="$2" status
  shift 2
  set +e
  vm_ssh "$guest_push_app $*" > "$temporary/$name.stdout" 2> "$temporary/$name.stderr"
  status=$?
  set -e
  [ "$status" -eq 1 ] || fail "$name push exited $status, want 1"
  grep -F "$expected" "$temporary/$name.stderr" >/dev/null ||
    fail "$name push lacked '$expected': $(cat "$temporary/$name.stderr")"
}
push_remote_snapshot() {
  (
    cd "$ssh_push_remote"
    while IFS= read -r -d '' file; do sha256sum "$file"; done \
      < <(find . -type f -print0 | sort -z)
  )
}
verify_read_only_push() {
  local name="$1" before="$2" after
  after="$temporary/$name-remote-after"
  push_remote_snapshot > "$after"
  cmp "$before" "$after" >/dev/null || fail "$name push changed the remote"
  printf 'get -r "%s" "%s"\n' "$guest_push_source" "$temporary/$name-source" |
    "${sftp_command[@]}"
  diff -qr "$temporary/guest-push-pack/source" "$temporary/$name-source" >/dev/null ||
    fail "$name push changed the source repository"
  vm_ssh "[ ! -e $guest_push_source/.git/index.lock ] && [ ! -e $guest_push_source/.git/gix-operation ] && [ ! -e $guest_push_source/.git/packed-refs.lock ]" ||
    fail "$name push left a source lock"
  [ -z "$(find "$ssh_push_remote" -name '*.lock' -print -quit)" ] ||
    fail "$name push left a remote lock"
}

push_output="$(vm_ssh "$guest_named_push_app fixture $push_c0:refs/heads/main")" ||
  fail "configured-remote SSH push failed"
[ "$push_output" = "remote accepted: refs/heads/main -> $push_c0" ] ||
  fail "configured-remote SSH push output differs: $push_output"
[ "$(clean_git -C "$ssh_push_remote" rev-parse refs/heads/main)" = "$push_c0" ] ||
  fail "initial SSH push wrote the wrong main"
if clean_git -C "$ssh_push_remote" cat-file -e "$push_m^{commit}" 2>/dev/null; then
  fail "initial SSH push sent the incremental commit"
fi

push_remote_snapshot > "$temporary/push-dry-remote-before"
expect_guest_push "would update: refs/heads/main -> $push_m" \
  --dry-run "$ssh_push_url" "HEAD:refs/heads/main"
verify_read_only_push push-dry "$temporary/push-dry-remote-before"

expect_guest_push "remote accepted: refs/heads/main -> $push_m" \
  "$ssh_push_url" "HEAD:refs/heads/main"
[ "$(clean_git -C "$ssh_push_remote" show main:conflict)" = resolved ] ||
  fail "incremental SSH push has the wrong merge resolution"
[ "$(clean_git -C "$ssh_push_remote" show main:unchanged)" = unchanged ] ||
  fail "incremental SSH push lost baseline content"
clean_git -C "$ssh_push_remote" fsck --strict --no-dangling >/dev/null

expect_guest_push_failure push-stale-lease \
  'push lease does not match the advertised destination' \
  "--force-with-lease=refs/heads/main:$push_c0" "$ssh_push_url" "HEAD:refs/heads/main"
push_remote_snapshot > "$temporary/push-noop-remote-before"
expect_guest_push "up to date: refs/heads/main -> $push_m" \
  "$ssh_push_url" "HEAD:refs/heads/main"
verify_read_only_push push-noop "$temporary/push-noop-remote-before"

expect_guest_push_failure push-non-ff \
  'push is not a fast-forward; an explicit matching lease is required' \
  "$ssh_push_url" "$push_c0:refs/heads/main"
expect_guest_push "remote accepted: refs/heads/main -> $push_c0" \
  "--force-with-lease=refs/heads/main:$push_m" "$ssh_push_url" "$push_c0:refs/heads/main"
expect_guest_push "remote accepted: refs/heads/main -> $push_m" \
  "--force-with-lease=refs/heads/main:$push_c0" "$ssh_push_url" "$push_m:refs/heads/main"

expect_guest_push "remote accepted: refs/tags/published -> $push_c0" \
  "$ssh_push_url" "$push_c0:refs/tags/published"
expect_guest_push_failure push-tag-replace \
  'replacing an existing tag requires an explicit matching lease' \
  "$ssh_push_url" "$push_m:refs/tags/published"
expect_guest_push "remote accepted: refs/tags/published -> $push_m" \
  "--force-with-lease=refs/tags/published:$push_c0" "$ssh_push_url" "$push_m:refs/tags/published"

# M is already advertised, so this successful new-ref update carries the valid empty pack.
expect_guest_push "remote accepted: refs/heads/copy -> $push_m" \
  "$ssh_push_url" "$push_m:refs/heads/copy"
touch "$ssh_push_remote/hooks/reject"
expect_guest_push_failure push-hook-reject \
  'remote rejected the update: pre-receive hook declined' \
  "$ssh_push_url" "$push_m:refs/heads/rejected"
rm "$ssh_push_remote/hooks/reject"
if clean_git -C "$ssh_push_remote" rev-parse --verify refs/heads/rejected >/dev/null 2>&1; then
  fail "rejected SSH push created its destination"
fi
[ "$(clean_git -C "$ssh_push_remote" rev-parse refs/heads/main)" = "$push_m" ] ||
  fail "SSH push lifecycle left main at the wrong commit"
[ "$(clean_git -C "$ssh_push_remote" rev-parse refs/heads/copy)" = "$push_m" ] ||
  fail "empty-pack SSH push wrote the wrong ref"
[ "$(clean_git -C "$ssh_push_remote" rev-parse refs/tags/published)" = "$push_m" ] ||
  fail "leased SSH tag replacement wrote the wrong ref"
clean_git -C "$ssh_push_remote" fsck --strict --no-dangling >/dev/null

ssh_clone="$guest_root/ssh-clone"
vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix clone $ssh_repo_url $ssh_clone" \
  > "$temporary/ssh-clone.stdout" 2> "$temporary/ssh-clone.stderr" ||
  fail "native SSH clone failed: $(cat "$temporary/ssh-clone.stderr")"
[ "$(grep -Fxc GIX_SSH_SUCCESS_STDERR "$temporary/ssh-clone.stderr")" -eq 1 ] ||
  fail "successful SSH clone did not forward stderr exactly once"
printf 'get -r "%s" "%s"\n' "$ssh_clone" "$temporary/ssh-clone-before" |
  "${sftp_command[@]}"
advance_remote "$ssh_remote" "$temporary/ssh-update" "SSH remote update"
vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $ssh_clone fetch" \
  > "$temporary/ssh-fetch.stdout" 2> "$temporary/ssh-fetch.stderr" ||
  fail "native SSH fetch failed: $(cat "$temporary/ssh-fetch.stderr")"
[ "$(grep -Fxc GIX_SSH_SUCCESS_STDERR "$temporary/ssh-fetch.stderr")" -eq 1 ] ||
  fail "successful SSH fetch did not forward stderr exactly once"
printf 'get -r "%s" "%s"\n' "$ssh_clone" "$temporary/ssh-clone-after" |
  "${sftp_command[@]}"
verify_network_clone "$temporary/ssh-clone-before" "$temporary/ssh-clone-after" \
  "$ssh_remote" "$ssh_initial_head" SSH

set +e
vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix clone $ssh_base/stderr.git $guest_root/ssh-stderr-clone" \
  > "$temporary/ssh-stderr.stdout" 2> "$temporary/ssh-stderr.stderr"
ssh_status=$?
set -e
[ "$ssh_status" -eq 1 ] || fail "oversized-stderr SSH clone exited $ssh_status, want 1"
grep -F 'SSH stderr exceeded the 65536-byte limit' "$temporary/ssh-stderr.stderr" >/dev/null ||
  fail "oversized-stderr SSH clone lacked the limit diagnostic: $(cat "$temporary/ssh-stderr.stderr")"
wait_ssh_fixture_file "$SSH_CLIENT_HOST_ROOT/stderr.ready" stderr-ready
wait_ssh_fixture_closed stderr
printf 'get "%s" "%s"\n' \
  "$guest_root/ssh-stderr-clone/.git/gix-incomplete-clone" "$temporary/ssh-stderr-marker" |
  "${sftp_command[@]}"
[ ! -s "$temporary/ssh-stderr-marker" ] || fail "oversized-stderr clone marker was not empty"

coproc GIX_PTY {
  exec ssh "${SSH_OPTIONS[@]}" -e none -tt motor@192.168.4.2 \
    "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix clone $ssh_base/stall.git $guest_root/ssh-stalled-clone" 2>&1
}
gix_pty_pid="$GIX_PTY_PID"
exec {gix_pty_out}<&"${GIX_PTY[0]}"
exec {gix_pty_in}>&"${GIX_PTY[1]}"
wait_ssh_fixture_file "$SSH_CLIENT_HOST_ROOT/stall.ready" stall-ready
printf '\003' >&"$gix_pty_in"
exec {gix_pty_in}>&-
gix_pty_in=
set +e
gix_pty_output="$(cat <&"$gix_pty_out")"
gix_pty_read_status=$?
wait "$gix_pty_pid"
gix_pty_status=$?
gix_pty_pid=
set -e
exec {gix_pty_out}<&-
gix_pty_out=
[ "$gix_pty_read_status" -eq 0 ] || fail "cancelled SSH clone PTY output failed"
[ "$gix_pty_status" -eq 130 ] ||
  fail "cancelled SSH clone exited $gix_pty_status, want 130: $gix_pty_output"
wait_ssh_fixture_closed stall
printf 'get "%s" "%s"\n' \
  "$guest_root/ssh-stalled-clone/.git/gix-incomplete-clone" "$temporary/ssh-stall-marker" |
  "${sftp_command[@]}"
[ ! -s "$temporary/ssh-stall-marker" ] || fail "cancelled SSH clone marker was not empty"
kill -0 "$SSH_CLIENT_HOST_PROCESS" 2>/dev/null || fail "host russhd exited during SSH lifecycle tests"
stop_ssh_client_host
remove_ssh_client_host_identity || fail "failed to remove the gix SSH identity fixture"
cleanup_ssh_client_host
  echo 'gix cross transport and Git format checks: PASS'
)

cross_crossterm() (
  fail() { cross_fail "crossterm: $*"; }
crossterm_readings() {
  printf '%s\n' "$1" | grep -Eao 'key=.*|end=.*|size=[0-9]+x[0-9]+|resize=[0-9]+x[0-9]+|size-after=[0-9]+x[0-9]+'
}
# A forced SSH pty is a terminal, and russhd is the one on the far end of it:
# it answers the DECRQM itself and takes the mode sequences out of the stream
# rather than letting them through to the client's own terminal, which would
# then answer as well and with a size of its own. So none of them arrive here.
# Nor does any probe: a session whose provider has answered is not measured
# again, by `ESC[18t` or by parking the cursor in the corner.
#
# This client has no terminal of its own -- stdin is a pipe -- so the size it
# asks for is zeroes and russhd has none to report. That is the point of the
# resize check below, which gives it one.
out="$(printf 'q' | ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
  "TMPDIR=$TEST_TMP $TEST_BIN/crossterm-smoke keys" 2>/dev/null)"
case "$out" in
  *$'\033[?2048'*) fail "russhd passed a mode 2048 sequence to the client: '$out'" ;;
esac
case "$out" in
  *$'\033[18t'*|*$'\033[9999;9999H'*)
    fail "crossterm probed a session russhd had answered: '$out'"
    ;;
esac
[ "$(crossterm_readings "$out")" = "key=Char('q')
end=quit" ] || fail "crossterm pty mode check decoded '$(crossterm_readings "$out")'"

# Type-ahead through Rush over a forced pty: a key typed after a command's Enter
# is the command's, not the start of the next command line. The Enter is a
# lone CR, as an SSH client sends it: one host write is not guaranteed to be
# one guest write, and an LF that arrives after its CR is the command's anyway.
out="$(printf '%s\rq' "TMPDIR=$TEST_TMP $TEST_BIN/crossterm-smoke keys" |
  ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 /user/bin/rush 2>/dev/null)"
[ "$(crossterm_readings "$out")" = "key=Char('q')
end=quit" ] || fail "Rush kept its command's type-ahead: '$(crossterm_readings "$out")'"
case "$out" in
  *"not found"*) fail "Rush ran its command's type-ahead: '$out'" ;;
esac

# Ctrl+C remains fatal unless a TUI explicitly installs crossterm's adapter.
# The adapter owns the process handler for life, so a second call must fail.
out="$(printf '' | ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
  "TMPDIR=$TEST_TMP $TEST_BIN/crossterm-smoke ctrl-c" 2>/dev/null)"
case "$out" in
  *"ctrl-c=enabled"*"ctrl-c=already-enabled"*) ;;
  *) fail "crossterm did not register exactly one Ctrl+C handler: '$out'" ;;
esac

# The whole chain, end to end, driven the way a user drives it: a terminal on
# this side, a resize of it, a `window-change` on the wire, and the report
# russhd writes into the stdin of the child that subscribed. `script` is what
# gives the ssh client a terminal at all -- without one it reads no size to send
# and never notices a resize -- and `stty` resizing that terminal is the
# `SIGWINCH` the client turns into the request. The client runs in the
# background so that the same terminal is free to be resized under it.
#
# `sleep` holds `script`'s own stdin open: at EOF it types the terminal's EOF
# character into the session, and a keystroke nobody pressed has no business in
# a test of what the terminal reports.
ssh_pty_keys="$(printf '%q ' ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
  "TMPDIR=$TEST_TMP $TEST_BIN/crossterm-smoke keys")"
out="$(sleep 8 | script -qc "stty rows 30 cols 100
$ssh_pty_keys </dev/tty 2>/dev/null &
sleep 2
stty rows 20 cols 60
wait" /dev/null)"
readings="$(crossterm_readings "$out")"
case "$readings" in
  *"resize=100x30"*"resize=60x20"*) ;;
  *) fail "russhd did not report the pty size and its change: '$readings'" ;;
esac

)

cross_base() {
  copy_test_image "$ROOT_DIR/vm_images/$BUILD/motor-os-base.img" base
  boot_test_image base
  wait_vm_ssh
  check_guest_image_layout
  vm_ssh '[ ! -e /user/bin/dev ] && [ ! -e /system/services/dns-resolver ]'
  vm_ssh /user/bin/rush -c true
  shutdown_test_image
  echo 'base image boot and layout: PASS'
}

# Boots a copy of the standard image and runs the checks that need a fresh
# boot. The VM keeps running, with the test programs uploaded.
cross_fresh_boot() {
  copy_test_image "$CROSS_IMAGE" standard
  # A private disk marker verifies that the fresh RAM mount hides its backing
  # directory. No marker is present in either published image.
  printf 'hidden by memfs\n' > "$RUN_DIR/memfs-marker"
  "$ROOT_DIR/build/obj/$BUILD/imager/$BUILD/imager" put "$VM_DIR/$MOTO_IMAGE" \
    "$RUN_DIR/memfs-marker" /none/tmp/.shadowed-by-memfs
  boot_test_image standard
  wait_vm_ssh
  [ -z "$(vm_ssh 'ls /none/tmp')" ] || cross_fail 'fresh memfs is not empty'
  vm_ssh '[ ! -e /none/tmp/.shadowed-by-memfs ]'
  cross_upload_programs
  # This allocation check requires a fresh boot, before other tests fragment
  # the physical block pool; the rest of systest runs in its native harness.
  vm_ssh "$TEST_BIN/systest mem-placement" | tee "$RUN_DIR/memory-placement.log"
  grep -qx 'mem_blocks: placement PASS' "$RUN_DIR/memory-placement.log"
  if [ "$BUILD" = release ]; then
    vm_ssh "MOTOR_OS_CAPS=0x3ec $TEST_BIN/systest kernel-log-boot"
  fi
  check_guest_image_layout
}

cross_run() {
  cross_prepare_programs
  prepare_identity_workspace
  test_host_identity
  cross_base
  cross_fresh_boot
  if [ "$VMM" != fc ]; then check_installed_tools; fi
  test_guest_identity
  cross_network_checks
  cross_ssh_checks
  cross_crossterm
  cross_tui
  cross_terminal_size
  cross_gix
  shutdown_test_image
  cross_system_console
  cross_boot_options
  cross_block_mounts
  cross_vsock_discovery
  cross_vsock_outgoing
  cross_sshd_keys
  cross_wasm
  cross_oom_abort
  echo "cross-test: PASS ($BUILD, $VMM)"
}

cross_main() {
  cross_options "$@"
  if [ "$VMM" != fc ] && [ "$CROSS_IMAGE_EXPLICIT" = 0 ] && [ -z "$BENCHMARK" ]; then
    cross_fail '--image must name a standard image with the toolchain installed; full-test.sh prepares one automatically'
  fi
  cd "$ROOT_DIR"
  make -j"$(nproc)" BUILD="$BUILD" images raw.img systest crossterm-smoke wg-self-test rnetbench
  cross_setup
  if [ -n "$BENCHMARK" ]; then cross_benchmark; else cross_run; fi
}

cross_benchmark() {
  fail() { cross_fail "$@"; }
  local host_binary="${WG_RNETBENCH_BINARY:-$ROOT_DIR/src/bin/rnetbench/target/release/rnetbench}"
  local banner host_output reader_pid role
  cargo build --release --locked --offline --manifest-path "$ROOT_DIR/src/sys/tools/wg/host-peer/Cargo.toml"
  if [ "$BENCHMARK" = physical ] && [ -z "${WG_RNETBENCH_BINARY:-}" ]; then
    cargo build --release --locked --offline --manifest-path "$ROOT_DIR/src/bin/rnetbench/Cargo.toml"
  fi
  copy_test_image "$CROSS_IMAGE" benchmark
  boot_test_image benchmark
  wait_vm_ssh
  TEST_BIN=/none/tmp/wg-benchmark
  vm_ssh "mkdir $TEST_BIN"
  for binary in systest rnetbench; do
    printf 'put "%s" "%s/%s"\nchmod 755 "%s/%s"\n' \
      "$ROOT_DIR/build/bin/release/$binary" "$TEST_BIN" "$binary" "$TEST_BIN" "$binary" | vm_sftp
  done
  if [ "$BENCHMARK" = physical ]; then
    coproc WG_BENCH_SERVER { exec "$host_binary" --server --port 40000; }
    CROSS_PEER_PID="$WG_BENCH_SERVER_PID"
    exec {host_output}<&"${WG_BENCH_SERVER[0]}"
    IFS= read -r -t 5 banner <&"$host_output" || cross_fail 'benchmark server did not become ready'
    case "$banner" in *'listening on 0.0.0.0:40000'*) ;; *) cross_fail "unexpected benchmark banner: $banner" ;; esac
    cat <&"$host_output" &
    reader_pid=$!
    vm_ssh "$TEST_BIN/systest wireguard-measure 0 192.168.4.1:40000"
    kill "$CROSS_PEER_PID"
    wait "$CROSS_PEER_PID" || [ "$?" = 143 ]
    CROSS_PEER_PID=
    wait "$reader_pid"
    exec {host_output}<&-
  else
    role=guest
    [ "$BENCHMARK" != plain ] || role=plain
    WG_BENCHMARK=1 test_wireguard_case ipv4 "$role"
  fi
  shutdown_test_image
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then cross_main "$@"; fi
