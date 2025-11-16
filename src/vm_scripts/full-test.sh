#!/bin/bash

# abort on error
set -e

# cleanup routine
stop_vmm() {
  ssh -p 2222 -o IdentitiesOnly=yes -i test.key motor@192.168.4.2 shutdown
}

# set the trap to call cleanup on exit
trap stop_vmm EXIT

echo "Starting Motor OS test."
echo "Console output is redirected to /tmp/full-test.log."
echo ""
echo ""

./run-qemu.sh &> /tmp/full-test.log &

# It takes some time to start sshd, especially with a debug build, so we
# have a large timeout and several retries. And the first "test" is just an empty echo.

ssh -p 2222 -o IdentitiesOnly=yes -o ConnectTimeout=30 -o ConnectionAttempts=10 -i test.key motor@192.168.4.2 /bin/echo " "

ssh -p 2222 -o IdentitiesOnly=yes -i test.key motor@192.168.4.2 sys/tests/systest

ssh -p 2222 -o IdentitiesOnly=yes -i test.key motor@192.168.4.2 sys/tests/mio-test

ssh -p 2222 -o IdentitiesOnly=yes -i test.key motor@192.168.4.2 sys/tests/tokio-tests

