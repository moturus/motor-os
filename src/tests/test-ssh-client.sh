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

fail() {
  echo "test-ssh-client: $*" >&2
  exit 1
}

cleanup() {
  "${HOST_SSH[@]}" "/system/bin/rm $GUEST_KEY $GUEST_KEY.pub $GUEST_KNOWN $SOURCE $UPLOAD $DOWNLOAD $SFTP_DOWNLOAD $GENERATED $GENERATED.pub" \
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
  "/user/bin/scp -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$GUEST_KNOWN -i $GUEST_KEY $SOURCE motor@127.0.0.1:$UPLOAD" ||
  fail "loopback scp upload failed"
"${HOST_SSH[@]}" \
  "/user/bin/scp -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$GUEST_KNOWN -i $GUEST_KEY motor@127.0.0.1:$UPLOAD $DOWNLOAD" ||
  fail "loopback scp download failed"
out="$("${HOST_SSH[@]}" "/system/bin/cat $DOWNLOAD")"
[ "$out" = "loopback-copy" ] || fail "scp round trip returned '$out'"

printf 'pwd\nls %s\nget %s %s\n' "$TEST_TMP" "$UPLOAD" "$SFTP_DOWNLOAD" |
  "${HOST_SSH[@]}" \
    "/user/bin/sftp -P 2222 -b - -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$GUEST_KNOWN -i $GUEST_KEY motor@127.0.0.1" \
    >/dev/null || fail "loopback batch sftp failed"
out="$("${HOST_SSH[@]}" "/system/bin/cat $SFTP_DOWNLOAD")"
[ "$out" = "loopback-copy" ] || fail "sftp download returned '$out'"

"${HOST_SSH[@]}" "/user/bin/ssh-keygen -q -t ed25519 -N '' -f $GENERATED" ||
  fail "ssh-keygen failed"
public="$("${HOST_SSH[@]}" "/system/bin/cat $GENERATED.pub")"
derived="$("${HOST_SSH[@]}" "/user/bin/ssh-keygen -y -f $GENERATED")"
[ "$public" = "$derived" ] || fail "ssh-keygen -y did not reproduce the public key"

echo "test-ssh-client: PASS"
