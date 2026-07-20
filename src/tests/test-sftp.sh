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

REMOTE_PHASE0_ROOT="${RUSSHD_PHASE0_ROOT:-/user/tmp/lorry/sftp-prerequisite-$$}"

WORK="$(mktemp -d)"

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

cleanup() {
    run_ssh /bin/rm -r "$REMOTE_PHASE0_ROOT" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

command -v sftp >/dev/null 2>&1 || fail "no 'sftp' client found in PATH"
command -v cmp >/dev/null 2>&1 || fail "no 'cmp' command found in PATH"
command -v dd >/dev/null 2>&1 || fail "no 'dd' command found in PATH"
[ -r "$KEY" ] || fail "key file '$KEY' not found or not readable"

# Run a batch of sftp commands (passed on stdin) against the VM. Stderr is
# captured so we can surface it only on failure.
run_sftp() {
    sftp "${SSH_OPTS[@]}" -b - "$USER@$HOST" >"$WORK/out" 2>"$WORK/err"
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

# ---------------------------------------------------------------------------
# 5. Lorry's native harness prerequisite: stage a representative nested source
#    tree through SFTP, copy it recursively in the guest, and remove only the
#    selected copy. Directory creation is deliberately performed through SSH:
#    the prerequisite is SFTP file upload, while sysbox supplies mkdir/cp/rm.
# ---------------------------------------------------------------------------
source_tree="$WORK/source"
mkdir -p "$source_tree/src/nested" "$source_tree/empty"
printf '[package]\nname = "phase0-fixture"\nversion = "0.1.0"\n' \
    >"$source_tree/Cargo.toml"
printf 'fn main() { println!("nested fixture"); }\n' \
    >"$source_tree/src/main.rs"
dd if=/dev/urandom of="$source_tree/src/nested/payload.bin" \
    bs=1024 count=96 status=none
printf 'must survive copy cleanup\n' >"$WORK/outside-sentinel"

remote_source="$REMOTE_PHASE0_ROOT/source"
remote_copy="$REMOTE_PHASE0_ROOT/copy"
remote_outside="$REMOTE_PHASE0_ROOT/outside-sentinel"

echo "-- staging a nested Lorry source fixture under $REMOTE_PHASE0_ROOT --"
run_ssh /bin/mkdir /user/tmp >/dev/null 2>&1 || true
run_ssh /bin/mkdir /user/tmp/lorry >/dev/null 2>&1 || true
run_ssh /bin/mkdir "$REMOTE_PHASE0_ROOT" ||
    fail "could not create the fixture run root"
run_ssh /bin/mkdir "$remote_source" ||
    fail "could not create the fixture source root"
run_ssh /bin/mkdir "$remote_source/src" ||
    fail "could not create the fixture src directory"
run_ssh /bin/mkdir "$remote_source/src/nested" ||
    fail "could not create the fixture nested directory"
run_ssh /bin/mkdir "$remote_source/empty" ||
    fail "could not create the fixture empty directory"

run_sftp <<EOF || { cat "$WORK/err" >&2; fail "nested SFTP upload failed"; }
put $source_tree/Cargo.toml $remote_source/Cargo.toml
put $source_tree/src/main.rs $remote_source/src/main.rs
put $source_tree/src/nested/payload.bin $remote_source/src/nested/payload.bin
put $WORK/outside-sentinel $remote_outside
EOF

run_ssh /bin/cp -r "$remote_source" "$remote_copy" ||
    fail "guest 'cp -r' rejected the representative source tree"

if run_ssh /bin/cp -r "$remote_source" "$remote_source/inside-source"; then
    fail "guest 'cp -r' accepted a destination inside its source"
fi

if run_ssh /bin/rm "$remote_copy"; then
    fail "guest 'rm' removed a directory without -r"
fi

run_sftp <<EOF || { cat "$WORK/err" >&2; fail "copied-tree SFTP round-trip failed"; }
get $remote_copy/Cargo.toml $WORK/copied-Cargo.toml
get $remote_copy/src/main.rs $WORK/copied-main.rs
get $remote_copy/src/nested/payload.bin $WORK/copied-payload.bin
EOF

cmp -s "$source_tree/Cargo.toml" "$WORK/copied-Cargo.toml" ||
    fail "Cargo.toml changed during nested upload/copy"
cmp -s "$source_tree/src/main.rs" "$WORK/copied-main.rs" ||
    fail "main.rs changed during nested upload/copy"
cmp -s "$source_tree/src/nested/payload.bin" "$WORK/copied-payload.bin" ||
    fail "binary payload changed during nested upload/copy"

run_ssh /bin/rm -r "$remote_copy" ||
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
echo "  ok: nested SFTP upload, cp -r, safe errors, and selected rm -r passed"

echo
echo "PASS: all checks succeeded"
