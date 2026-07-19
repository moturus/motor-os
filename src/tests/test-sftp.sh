#!/usr/bin/env bash
#
# Integration test for russhd's SFTP directory, download, and upload support.
#
# Exercises the realpath / opendir / readdir / lstat / open / read / write
# handlers in src/bin/russhd/src/sftp_session.rs by listing a remote directory,
# downloading a file, and round-tripping uploads.
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
REMOTE_UPLOAD_FILE="${RUSSHD_REMOTE_UPLOAD_FILE:-/sys/tmp/russhd-sftp-upload-test.bin}"
EXPECTED_FILES=(russhd rush)

SSH_OPTS=(
    -F /dev/null
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
command -v cmp >/dev/null 2>&1 || fail "no 'cmp' command found in PATH"
command -v dd >/dev/null 2>&1 || fail "no 'dd' command found in PATH"
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
# 4. Overwrite with a shorter file. A server that opens for writing without
#    honoring TRUNCATE would leave bytes from the previous large payload.
# ---------------------------------------------------------------------------
overwrite_source="$WORK/overwrite-source.bin"
overwrite_roundtrip="$WORK/overwrite-roundtrip.bin"
printf 'russhd SFTP overwrite test\nshort payload\n' >"$overwrite_source"

echo "-- overwriting $REMOTE_UPLOAD_FILE with a shorter file --"
run_sftp <<EOF || { cat "$WORK/err" >&2; fail "SFTP overwrite upload failed"; }
put $overwrite_source $REMOTE_UPLOAD_FILE
get $REMOTE_UPLOAD_FILE $overwrite_roundtrip
EOF

cmp -s "$overwrite_source" "$overwrite_roundtrip" ||
    fail "short overwrite differs after downloading it again"
echo "  ok: upload truncated and replaced the existing remote file"

echo
echo "PASS: all checks succeeded"
