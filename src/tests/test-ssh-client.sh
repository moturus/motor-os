#!/usr/bin/env bash
# Motor SSH client integration against the VM's own russhd over loopback.

set -euo pipefail

WD="$(dirname "$0")"
HOST="${RUSSHD_HOST:-192.168.4.2}"
PORT="${RUSSHD_PORT:-2222}"
USER="${RUSSHD_USER:-motor}"
KEY="${RUSSHD_KEY:-$WD/test.key}"
TEST_TMP="${MOTOR_TEST_ROOT:-/user/tmp/motor-tests}/tmp"
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
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts"
  "$USER@$HOST"
)
HOST_SFTP=(
  sftp -F /dev/null -P "$PORT" -i "$KEY"
  -o IdentitiesOnly=yes -o BatchMode=yes
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts"
  -b - "$USER@$HOST"
)
GUEST_CONNECTION="-p 2222 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$GUEST_KNOWN -i $GUEST_KEY"
GUEST_SCP_CONNECTION="-P 2222 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$GUEST_KNOWN -i $GUEST_KEY"
GUEST_SFTP_CONNECTION="-P 2222 -b - -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$GUEST_KNOWN -i $GUEST_KEY"

fail() {
  echo "test-ssh-client: $*" >&2
  exit 1
}

cleanup() {
  # sysbox rm takes exactly one operand, so remove the fixtures one by one
  # inside a single guest shell.
  "${HOST_SSH[@]}" "/system/bin/rush -c ' \
    /system/bin/rm $GUEST_KEY; /system/bin/rm $GUEST_KEY.pub; \
    /system/bin/rm $GUEST_KNOWN; /system/bin/rm $SOURCE; \
    /system/bin/rm $UPLOAD; /system/bin/rm $DOWNLOAD; \
    /system/bin/rm $SFTP_DOWNLOAD; /system/bin/rm $GENERATED; \
    /system/bin/rm $GENERATED.pub; /system/bin/rm $RENAME_SOURCE; \
    /system/bin/rm $RENAME_TARGET; /system/bin/rm -r $TREE_SOURCE; \
    /system/bin/rm -r $TREE_UPLOAD_PARENT; \
    /system/bin/rm -r $TREE_DOWNLOAD_PARENT'" \
    >/dev/null 2>&1 || true
}
trap cleanup EXIT

printf 'put %s %s\nchmod 600 %s\n' "$KEY" "$GUEST_KEY" "$GUEST_KEY" |
  "${HOST_SFTP[@]}" >/dev/null || fail "could not stage the loopback identity"

out="$(printf 'loopback stdin\n' | "${HOST_SSH[@]}" \
  "/user/bin/ssh $GUEST_CONNECTION motor@127.0.0.1 /system/bin/cat")" ||
  fail "scripted loopback ssh failed"
[ "$out" = "loopback stdin" ] || fail "scripted ssh returned '$out'"

if "${HOST_SSH[@]}" \
  "/user/bin/ssh $GUEST_CONNECTION motor@127.0.0.1 '/system/bin/rush -c \"exit 7\"'"; then
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
  -o UserKnownHostsFile="$WD/test-known-hosts" "$USER@$HOST" \
  "/user/bin/ssh -p 2222 motor@127.0.0.1" >/dev/null 2>&1; then
  fail "interactive 'ssh -p 2222 motor@127.0.0.1' failed"
fi

"${HOST_SSH[@]}" "/system/bin/rush -c 'echo loopback-copy > $SOURCE'"
"${HOST_SSH[@]}" \
  "/user/bin/scp $GUEST_SCP_CONNECTION $SOURCE motor@127.0.0.1:$UPLOAD" ||
  fail "loopback scp upload failed"
"${HOST_SSH[@]}" \
  "/user/bin/scp $GUEST_SCP_CONNECTION motor@127.0.0.1:$UPLOAD $DOWNLOAD" ||
  fail "loopback scp download failed"
out="$("${HOST_SSH[@]}" "/system/bin/cat $DOWNLOAD")"
[ "$out" = "loopback-copy" ] || fail "scp round trip returned '$out'"

"${HOST_SSH[@]}" "/system/bin/rush -c 'echo source > $RENAME_SOURCE; echo target > $RENAME_TARGET'"
if printf 'rename -l %s %s\n' "$RENAME_SOURCE" "$RENAME_TARGET" |
  "${HOST_SSH[@]}" "/user/bin/sftp $GUEST_SFTP_CONNECTION motor@127.0.0.1" >/dev/null 2>&1; then
  fail "plain SFTP rename replaced an existing destination"
fi
out="$("${HOST_SSH[@]}" "/system/bin/cat $RENAME_SOURCE")"
[ "$out" = "source" ] || fail "failed plain rename changed its source"
out="$("${HOST_SSH[@]}" "/system/bin/cat $RENAME_TARGET")"
[ "$out" = "target" ] || fail "failed plain rename changed its destination"
printf 'rename %s %s\n' "$RENAME_SOURCE" "$RENAME_TARGET" |
  "${HOST_SSH[@]}" "/user/bin/sftp $GUEST_SFTP_CONNECTION motor@127.0.0.1" >/dev/null 2>&1 ||
  fail "replacing rename through the sftp applet failed"
out="$("${HOST_SSH[@]}" "/system/bin/cat $RENAME_TARGET")"
[ "$out" = "source" ] || fail "sftp applet rename did not replace the destination"
if "${HOST_SSH[@]}" "/system/bin/ls $RENAME_SOURCE" >/dev/null 2>&1; then
  fail "sftp applet rename left its source reachable"
fi

"${HOST_SSH[@]}" "/system/bin/rush -c ' \
  /system/bin/mkdir $TREE_SOURCE && /system/bin/mkdir $TREE_SOURCE/nested && \
  /system/bin/mkdir $TREE_SOURCE/empty && /system/bin/mkdir $TREE_UPLOAD_PARENT && \
  /system/bin/mkdir $TREE_DOWNLOAD_PARENT'" ||
  fail "could not create the recursive-transfer fixtures"
"${HOST_SSH[@]}" "/system/bin/rush -c 'echo recursive-upload > $TREE_SOURCE/nested/file'"
"${HOST_SSH[@]}" \
  "/user/bin/scp -r $GUEST_SCP_CONNECTION $TREE_SOURCE motor@127.0.0.1:$TREE_UPLOAD_PARENT" ||
  fail "loopback recursive upload failed"
"${HOST_SSH[@]}" "/system/bin/rush -c 'echo stale > $TREE_UPLOAD_PARENT/ssh-client-tree-source/nested/file'"
"${HOST_SSH[@]}" \
  "/user/bin/scp -r $GUEST_SCP_CONNECTION $TREE_SOURCE motor@127.0.0.1:$TREE_UPLOAD_PARENT" ||
  fail "loopback recursive re-upload failed"
out="$("${HOST_SSH[@]}" "/system/bin/cat $TREE_UPLOAD_PARENT/ssh-client-tree-source/nested/file")"
[ "$out" = "recursive-upload" ] || fail "recursive re-upload did not replace an existing file"

"${HOST_SSH[@]}" \
  "/user/bin/scp -r $GUEST_SCP_CONNECTION motor@127.0.0.1:$TREE_UPLOAD_PARENT/ssh-client-tree-source $TREE_DOWNLOAD_PARENT" ||
  fail "loopback recursive download failed"
"${HOST_SSH[@]}" "/system/bin/rush -c 'echo recursive-download > $TREE_UPLOAD_PARENT/ssh-client-tree-source/nested/file'"
"${HOST_SSH[@]}" \
  "/user/bin/scp -r $GUEST_SCP_CONNECTION motor@127.0.0.1:$TREE_UPLOAD_PARENT/ssh-client-tree-source $TREE_DOWNLOAD_PARENT" ||
  fail "loopback recursive re-download failed"
out="$("${HOST_SSH[@]}" "/system/bin/cat $TREE_DOWNLOAD_PARENT/ssh-client-tree-source/nested/file")"
[ "$out" = "recursive-download" ] || fail "recursive re-download did not replace an existing file"
"${HOST_SSH[@]}" "[ -d $TREE_UPLOAD_PARENT/ssh-client-tree-source/empty ]" ||
  fail "recursive re-upload did not preserve an empty directory"
"${HOST_SSH[@]}" "[ -d $TREE_DOWNLOAD_PARENT/ssh-client-tree-source/empty ]" ||
  fail "recursive re-download did not preserve an empty directory"

printf 'pwd\nls %s\nget %s %s\n' "$TEST_TMP" "$UPLOAD" "$SFTP_DOWNLOAD" |
  "${HOST_SSH[@]}" "/user/bin/sftp $GUEST_SFTP_CONNECTION motor@127.0.0.1" \
    >/dev/null || fail "loopback batch sftp failed"
out="$("${HOST_SSH[@]}" "/system/bin/cat $SFTP_DOWNLOAD")"
[ "$out" = "loopback-copy" ] || fail "sftp download returned '$out'"

"${HOST_SSH[@]}" "/user/bin/ssh-keygen -q -t ed25519 -N '' -f $GENERATED" ||
  fail "ssh-keygen failed"
public="$("${HOST_SSH[@]}" "/system/bin/cat $GENERATED.pub")"
derived="$("${HOST_SSH[@]}" "/user/bin/ssh-keygen -y -f $GENERATED")"
[ "$public" = "$derived" ] || fail "ssh-keygen -y did not reproduce the public key"

echo "test-ssh-client: PASS"
