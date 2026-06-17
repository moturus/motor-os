#!/bin/bash

# abort on error
set -e

WD="$(dirname "$0")"

# Select the VM image build: debug by default, release with --release.
# run-qemu.sh lives in vm_images/<build>/, two levels up from src/tests/.
BUILD="debug"
if [ "${1:-}" = "--release" ]; then
  BUILD="release"
fi
# The repo root is two levels up from src/tests/.
ROOT_DIR="$WD/../.."
IMG_DIR="$WD/../../vm_images/$BUILD"

# Build everything before running the tests.
if [ "$BUILD" = "release" ]; then
  make -C "$ROOT_DIR" all BUILD=release -j"$(nproc)"
else
  make -C "$ROOT_DIR" all -j"$(nproc)"
fi

# cleanup routine
stop_vmm() {
  ssh -p 2222 -o IdentitiesOnly=yes -i "$WD/test.key" motor@192.168.4.2 shutdown
}

# set the trap to call cleanup on exit
trap stop_vmm EXIT

echo "Starting Motor OS test."
echo "Console output is redirected to /tmp/full-test.log."
echo ""
echo ""


"$IMG_DIR/run-qemu.sh" &> /tmp/full-test.log &

# It takes some time to start sshd, especially with a debug build, so we
# have a large timeout and several retries. And the first "test" is just an empty echo.

ssh -p 2222 -o IdentitiesOnly=yes -o ConnectTimeout=30 -o ConnectionAttempts=10 -i "$WD/test.key" motor@192.168.4.2 /bin/echo " "

ssh -p 2222 -o IdentitiesOnly=yes -i "$WD/test.key" motor@192.168.4.2 sys/tests/systest

# SFTP integration test against the running VM (before the trap shuts it down).
"$WD/test-sftp.sh"

ssh -p 2222 -o IdentitiesOnly=yes -i "$WD/test.key" motor@192.168.4.2 sys/tests/mio-test

ssh -p 2222 -o IdentitiesOnly=yes -i "$WD/test.key" motor@192.168.4.2 sys/tests/tokio-tests

