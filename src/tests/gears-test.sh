#!/bin/bash
#
# Direct hermetic gate for Gears. This script owns the profile-matched host
# suite and the Gears-specific Motor VM scenarios. The mock-provider and full
# agent-loop scenarios will be added here as they land.

if [ "${GEARS_TEST_TIMEOUT_ACTIVE:-0}" != "1" ]; then
  export GEARS_TEST_TIMEOUT_ACTIVE=1
  set -m
  timeout 600s "$0" "$@" < /dev/null
  status=$?
  set +m
  if [ "$status" -eq 124 ]; then
    echo "gears-test: timed out after 600 seconds" >&2
  fi
  exit "$status"
fi

set -euo pipefail

WD="$(dirname "$0")"
ROOT_DIR="$WD/../.."
BUILD="debug"
profile_args=()

case "${1:-}" in
  "") ;;
  --release)
    BUILD="release"
    profile_args+=(--release)
    ;;
  *)
    echo "usage: $0 [--release]" >&2
    exit 2
    ;;
esac

required_image_executables=(
  img_files/generated/llvm/bin/cc
  img_files/generated/llvm/bin/c++
  img_files/generated/llvm/sys/tools/llvm/bin/llvm
  img_files/generated/rustc/sys/tools/rust/bin/rustc
  img_files/generated/rg/bin/rg
)
missing_prerequisite=0
for relative_path in "${required_image_executables[@]}"; do
  if [ ! -x "$ROOT_DIR/$relative_path" ]; then
    echo "gears-test: required executable is absent or not executable: $relative_path" >&2
    missing_prerequisite=1
  fi
done
if [ "$missing_prerequisite" -ne 0 ]; then
  echo "gears-test: generate the development-image toolchains with src/build-motor-os.sh" >&2
  exit 1
fi

echo "gears-test: running $BUILD host suite"
(
  cd "$ROOT_DIR/src/bin/gears"
  cargo test "${profile_args[@]}" --locked --offline
)

echo "gears-test: building $BUILD development image"
if [ "$BUILD" = "release" ]; then
  make -C "$ROOT_DIR" dev.img BUILD=release -j"$(nproc)"
else
  make -C "$ROOT_DIR" dev.img -j"$(nproc)"
fi

chmod 600 "$WD/test.key"
IMG_DIR="$ROOT_DIR/vm_images/$BUILD"
export MOTO_IMAGE=motor-os-dev.img
SSH_OPTIONS=(
  -F /dev/null
  -p 2222
  -o IdentitiesOnly=yes
  -o BatchMode=yes
  -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile="$WD/test-known-hosts"
  -i "$WD/test.key"
)
SSH=(ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2)

. "$WD/vm-cleanup.sh"

fail() {
  echo "gears-test: $*" >&2
  exit 1
}

SCRATCH="$(mktemp -d)"
CONSOLE_LOG="$SCRATCH/console.log"
VMM_PID=""

cleanup() {
  set +e
  stop_vm "$VMM_PID"
  VMM_PID=""
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

echo "gears-test: starting $BUILD Motor VM"
"$IMG_DIR/run-qemu.sh" > "$CONSOLE_LOG" 2>&1 &
VMM_PID="$!"

until ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=5 -o ConnectionAttempts=1 \
  motor@192.168.4.2 /bin/echo " " > /dev/null; do
  if ! kill -0 "$VMM_PID" 2>/dev/null; then
    vmm_status=0
    wait "$VMM_PID" || vmm_status="$?"
    VMM_PID=""
    cat "$CONSOLE_LOG" >&2
    fail "QEMU exited before SSH became ready (status $vmm_status)"
  fi
  sleep 1
done

echo "gears-test: checking packaged prerequisites"
"${SSH[@]}" '[ -x /bin/gears ] && [ -x /bin/rg ]' ||
  fail "development image is missing /bin/gears or /bin/rg"
version="$("${SSH[@]}" /bin/gears --version)"
case "$version" in
  "gears "*) ;;
  *) fail "unexpected gears version output: '$version'" ;;
esac

echo "gears-test: checking russhd PTY carrier"
pty_version="$(ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
  /bin/gears --version 2>/dev/null)"
case "$pty_version" in
  "gears "*) ;;
  *) fail "Gears did not run through a russhd PTY: '$pty_version'" ;;
esac

stop_vm "$VMM_PID"
VMM_PID=""
echo "-------- GEARS TEST PASS ($BUILD) --------"
