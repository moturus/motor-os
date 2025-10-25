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

sleep 1

ssh -p 2222 -o IdentitiesOnly=yes -i test.key motor@192.168.4.2 sys/tests/systest

ssh -p 2222 -o IdentitiesOnly=yes -i test.key motor@192.168.4.2 sys/tests/mio-test

ssh -p 2222 -o IdentitiesOnly=yes -i test.key motor@192.168.4.2 sys/tests/tokio-tests

