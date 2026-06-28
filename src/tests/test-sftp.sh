#!/usr/bin/env bash
#
# Integration test for russhd's SFTP directory + file support.
#
# Exercises the realpath / opendir / readdir / lstat handlers in
# src/sftp_session.rs by listing a remote directory over SFTP and checking its
# contents, then downloading a file to confirm open / read still work.
#
# Requires a running Motor OS VM with russhd reachable and an OpenSSH `sftp`
# client. Connection details can be overridden via the environment, e.g.:
#
#   RUSSHD_HOST=192.168.4.2 RUSSHD_KEY=test.key ./test_sftp.sh
#
set -u

WD="$(dirname "$0")"

# Accept an optional --release flag for a uniform invocation with the other
# test scripts. This test connects to an already-running VM, so the flag does
# not select a run-qemu.sh; it is accepted (and otherwise ignored) here.
if [ "${1:-}" = "--release" ]; then
    shift
fi

HOST="${RUSSHD_HOST:-192.168.4.2}"
PORT="${RUSSHD_PORT:-2222}"
USER="${RUSSHD_USER:-motor}"
# Default the key to the one next to this script so it works from src/tests/
# regardless of the current working directory.
KEY="${RUSSHD_KEY:-$WD/test.key}"
REMOTE_DIR="${RUSSHD_REMOTE_DIR:-/bin}"
REMOTE_FILE="${RUSSHD_REMOTE_FILE:-/sys/logs/sys-init.log}"
EXPECTED_FILES=(russhd rush)

SSH_OPTS=(
    -P "$PORT"
    -i "$KEY"
    -o IdentitiesOnly=yes
    -o BatchMode=yes              # never prompt; fail fast if the key is wrong
    -o StrictHostKeyChecking=no   # the VM's host key is ephemeral in testing
    -o UserKnownHostsFile=/dev/null
)

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

command -v sftp >/dev/null 2>&1 || fail "no 'sftp' client found in PATH"
[ -r "$KEY" ] || fail "key file '$KEY' not found or not readable"

# Run a batch of sftp commands (passed on stdin) against the VM. Stderr is
# captured so we can surface it only on failure.
run_sftp() {
    sftp "${SSH_OPTS[@]}" "$USER@$HOST" >"$WORK/out" 2>"$WORK/err"
}

echo "== russhd SFTP test against $USER@$HOST:$PORT =="

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

echo
echo "PASS: all checks succeeded"
