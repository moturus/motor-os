#!/usr/bin/env bash
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
MOTOR_TEST_ROOT="${MOTOR_TEST_ROOT:-/devtools}"
TEST_TMP="$MOTOR_TEST_ROOT/tmp"
# Default the key to the one next to this script so it works from src/tests/
# regardless of the current working directory.
KEY="${RUSSHD_KEY:-$WD/test.key}"
REMOTE_DIR="${RUSSHD_REMOTE_DIR:-/system/bin}"
REMOTE_FILE="${RUSSHD_REMOTE_FILE:-/system/logs/sys-init.log}"
REMOTE_UPLOAD_FILE="${RUSSHD_REMOTE_UPLOAD_FILE:-$TEST_TMP/russhd-sftp-upload-test.bin}"
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

REMOTE_PHASE0_PARENT="$TEST_TMP/lorry"
REMOTE_PHASE0_ROOT="${RUSSHD_PHASE0_ROOT:-$REMOTE_PHASE0_PARENT/sftp-prerequisite-$$}"

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
    remove_permission_fixtures
    run_ssh /system/bin/rm -r "$REMOTE_PHASE0_ROOT" >/dev/null 2>&1 || true
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
-rm $REMOTE_UPLOAD_FILE.plain
-rm $REMOTE_UPLOAD_FILE.exec
-rm $REMOTE_UPLOAD_FILE.readonly
EOF
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
# 4. Preserve permission classes explicitly. Motor has one R/W/X class rather
#    than POSIX owner/group/other classes, so SFTP folds each class by union.
# ---------------------------------------------------------------------------
permission_source="$WORK/permission-source.bin"
plain_permission_roundtrip="$WORK/plain-permission-roundtrip.bin"
exec_permission_roundtrip="$WORK/exec-permission-roundtrip.bin"
readonly_permission_roundtrip="$WORK/readonly-permission-roundtrip.bin"
remote_plain_permission_file="$REMOTE_UPLOAD_FILE.plain"
remote_exec_permission_file="$REMOTE_UPLOAD_FILE.exec"
remote_readonly_permission_file="$REMOTE_UPLOAD_FILE.readonly"
printf '#!/system/bin/rush\nexit 0\n' >"$permission_source"
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
[ "$plain_mode" = 666 ] ||
    fail "non-executable permission round-trip returned mode $plain_mode"
[ "$exec_mode" = 555 ] ||
    fail "executable permission round-trip returned mode $exec_mode"
[ "$readonly_mode" = 444 ] ||
    fail "read-only permission round-trip returned mode $readonly_mode"
echo "  ok: SFTP permission updates preserved executable-bit distinctions"

# ---------------------------------------------------------------------------
# 5. Overwrite with a shorter file. A server that opens for writing without
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
# 6. OpenSSH scp uses SFTP in-place uploads and finishes every file with a
#    size-only FSETSTAT. Verify recursive scp accepts that request and the files.
# ---------------------------------------------------------------------------
scp_tree="$WORK/scp-tree"
mkdir -p "$scp_tree/nested"
printf 'top-level scp file\n' >"$scp_tree/top"
printf 'nested scp file\n' >"$scp_tree/nested/file"

run_ssh /system/bin/mkdir "$REMOTE_PHASE0_PARENT" >/dev/null 2>&1 || true
run_ssh /system/bin/mkdir "$REMOTE_PHASE0_ROOT" ||
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
# 7. Lorry's native harness prerequisite: recursively stage a representative
#    source tree through one SFTP session, copy it in the guest, and remove only
#    the selected copy. This also verifies empty directories and preserved modes.
# ---------------------------------------------------------------------------
source_tree="$WORK/source"
mkdir -p "$source_tree/src/nested" "$source_tree/empty"
printf '[package]\nname = "phase0-fixture"\nversion = "0.1.0"\n' \
    >"$source_tree/Cargo.toml"
printf 'fn main() { println!("nested fixture"); }\n' \
    >"$source_tree/src/main.rs"
chmod 700 "$source_tree/src/main.rs"
dd if=/dev/urandom of="$source_tree/src/nested/payload.bin" \
    bs=1024 count=96 status=none
printf 'must survive copy cleanup\n' >"$WORK/outside-sentinel"

remote_source="$REMOTE_PHASE0_ROOT/source"
remote_copy="$REMOTE_PHASE0_ROOT/copy"
remote_outside="$REMOTE_PHASE0_ROOT/outside-sentinel"
remote_operations="$REMOTE_PHASE0_ROOT/operations"

echo "-- staging a nested Lorry source fixture under $REMOTE_PHASE0_ROOT --"
run_ssh /system/bin/mkdir "$remote_source" ||
    fail "could not create the fixture source root"

run_sftp <<EOF || { cat "$WORK/err" >&2; fail "recursive SFTP upload failed"; }
put -pR $source_tree/. $remote_source
put $WORK/outside-sentinel $remote_outside
EOF

run_ssh /system/bin/cp -r "$remote_source" "$remote_copy" ||
    fail "guest 'cp -r' rejected the representative source tree"

if run_ssh /system/bin/cp -r "$remote_source" "$remote_source/inside-source"; then
    fail "guest 'cp -r' accepted a destination inside its source"
fi

if run_ssh /system/bin/rm "$remote_copy"; then
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
[ "$plain_copy_mode" = 666 ] ||
    fail "cp -r changed a non-executable file to mode $plain_copy_mode"
[ "$exec_copy_mode" = 555 ] ||
    fail "cp -r changed an executable file to mode $exec_copy_mode"

run_ssh /system/bin/rm -r "$remote_copy" ||
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

run_sftp <<EOF || { cat "$WORK/err" >&2; fail "SFTP filesystem commands failed"; }
mkdir $remote_operations
rename $remote_outside $remote_operations/sentinel
get $remote_operations/sentinel $WORK/renamed-roundtrip
rm $remote_operations/sentinel
rmdir $remote_operations
EOF
cmp -s "$WORK/outside-sentinel" "$WORK/renamed-roundtrip" ||
    fail "SFTP rename changed the outside sentinel"
echo "  ok: recursive upload, preserved modes, and SFTP filesystem commands passed"

echo
echo "PASS: all checks succeeded"
