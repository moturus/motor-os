#!/usr/bin/env bash
# Config aliases and ProxyJump from Motor OS through a private OpenSSH fixture.
set -euo pipefail
WD="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$WD/../.." && pwd)"
TEST_TMP="${MOTOR_TEST_TMP:-/user/tmp/motor-tests}"
SSHD="$(command -v sshd)"
mkdir -p "$ROOT_DIR/build/host-tests"
fixture="$(mktemp -d "$ROOT_DIR/build/host-tests/ssh-config.XXXXXX")"
guest="$TEST_TMP/ssh-config"
config=/user/cfg/ssh/config
target_pid="" jump_pid="" target_fd="" jump_fd=""
staged=0
SSH=(ssh -F /dev/null -p 2222 -i "$WD/test.key" -o IdentitiesOnly=yes -o BatchMode=yes
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" motor@192.168.4.2)
SFTP=(sftp -F /dev/null -P 2222 -i "$WD/test.key" -o IdentitiesOnly=yes -o BatchMode=yes
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" -b - motor@192.168.4.2)
fail() { echo "test-ssh-config: $* (logs: $fixture)" >&2; exit 1; }
cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if [ -n "$jump_fd" ]; then printf 'stop\n' >&"$jump_fd"; wait "$jump_pid" || status=1; fi
  if [ -n "$target_fd" ]; then printf 'stop\n' >&"$target_fd"; wait "$target_pid" || status=1; fi
  if [ "$staged" -eq 1 ]; then
    "${SSH[@]}" "/system/bin/rm $config" || status=1
    "${SSH[@]}" "/system/bin/rm -r $guest" || status=1
  fi
  if [ "$status" -eq 0 ]; then rm -rf "$fixture"; fi
  exit "$status"
}
# The owning full-test harness supplies a fresh guest, never a personal config.
if "${SSH[@]}" "[ -e $config ]"; then fail "config fixture path already exists"; fi
trap cleanup EXIT
rustc --edition=2024 "$WD/ssh-openssh-fixture.rs" -o "$fixture/inetd"
ssh-keygen -q -t ed25519 -N '' -f "$fixture/target-key"
ssh-keygen -q -t ed25519 -N '' -f "$fixture/jump-key"
ssh-keygen -y -f "$WD/test.key" > "$fixture/authorized_keys"
host_user="$(id -un)"
write_server_config() {
  local name="$1"
  cat > "$fixture/$name.cfg" <<EOF
HostKey $fixture/$name-key
PidFile $fixture/$name.pid
AuthorizedKeysFile $fixture/authorized_keys
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
AllowUsers $host_user
AllowTcpForwarding local
Subsystem sftp internal-sftp
LogLevel VERBOSE
EOF
}
write_server_config target
"$SSHD" -t -f "$fixture/target.cfg"
mkfifo "$fixture/target.input" "$fixture/target.output"
exec {target_fd}<>"$fixture/target.input"
exec {target_output}<>"$fixture/target.output"
"$fixture/inetd" "$SSHD" "$fixture/target.cfg" 127.0.0.1 <&"$target_fd" >&"$target_output" 2>"$fixture/target.log" &
target_pid="$!"
IFS= read -r -t 5 address <&"$target_output" || fail "target did not report its port"
target_port="${address#PORT=}"
case "$target_port" in ''|*[!0-9]*) fail "invalid target port: $address" ;; esac
write_server_config jump
printf 'PermitOpen 127.0.0.1:%s' "$target_port" >> "$fixture/jump.cfg"
if [ -n "${MOTOR_SSH_PASSWORD_TARGET_PORT:-}" ]; then
  printf ' 192.168.4.1:%s' "$MOTOR_SSH_PASSWORD_TARGET_PORT" >> "$fixture/jump.cfg"
fi
printf '\n' >> "$fixture/jump.cfg"
"$SSHD" -t -f "$fixture/jump.cfg"
mkfifo "$fixture/jump.input" "$fixture/jump.output"
exec {jump_fd}<>"$fixture/jump.input"
exec {jump_output}<>"$fixture/jump.output"
"$fixture/inetd" "$SSHD" "$fixture/jump.cfg" 192.168.4.1 <&"$jump_fd" >&"$jump_output" 2>"$fixture/jump.log" &
jump_pid="$!"
IFS= read -r -t 5 address <&"$jump_output" || fail "jump did not report its port"
jump_port="${address#PORT=}"
case "$jump_port" in ''|*[!0-9]*) fail "invalid jump port: $address" ;; esac
cat > "$fixture/client.cfg" <<EOF
Host moto-hi
  HostName 192.168.4.1
  User $host_user
  Port $jump_port
  IdentityFile $guest/key
Host posk-dt
  HostName 127.0.0.1
  User $host_user
  Port $target_port
  IdentityFile $guest/key
  ProxyJump moto-hi
EOF
if [ -n "${MOTOR_SSH_PASSWORD_TARGET_PORT:-}" ]; then
  cat >> "$fixture/client.cfg" <<EOF
Host password-target
  HostName 192.168.4.1
  User motor
  Port $MOTOR_SSH_PASSWORD_TARGET_PORT
  IdentityFile none
  ProxyJump moto-hi
  BatchMode no
  StrictHostKeyChecking ask
EOF
fi
cat >> "$fixture/client.cfg" <<EOF
Host *
  UserKnownHostsFile $guest/known_hosts
  StrictHostKeyChecking accept-new
  BatchMode yes
  ConnectTimeout 5
EOF
printf 'mkdir %s\nput %s %s/key\nchmod 600 %s/key\nput %s %s\nput %s %s/alternate\n' \
  "$guest" "$WD/test.key" "$guest" "$guest" "$fixture/client.cfg" "$config" \
  "$fixture/client.cfg" "$guest" | "${SFTP[@]}" >/dev/null
staged=1
out="$("${SSH[@]}" /user/bin/ssh moto-hi /bin/echo direct-alias)"
[ "$out" = direct-alias ] || fail "direct alias returned '$out'"
out="$("${SSH[@]}" /user/bin/ssh posk-dt /bin/echo jumped-alias)"
[ "$out" = jumped-alias ] || fail "jump alias returned '$out'"
out="$("${SSH[@]}" /user/bin/ssh -F "$guest/alternate" posk-dt /bin/echo alternate-config)"
[ "$out" = alternate-config ] || fail "alternate config returned '$out'"
out="$("${SSH[@]}" /user/bin/ssh -F none -p "$jump_port" -i "$guest/key" \
  -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$guest/known_hosts" \
  "$host_user@192.168.4.1" /bin/echo no-config)"
[ "$out" = no-config ] || fail "-F none returned '$out'"
# 127.0.0.1 here is the host's loopback; the guest cannot dial this target directly.
out="$("${SSH[@]}" /user/bin/ssh -J moto-hi -o ProxyJump=none posk-dt /bin/echo cli-jump)"
[ "$out" = cli-jump ] || fail "-J override returned '$out'"
if "${SSH[@]}" /user/bin/ssh posk-dt exit 7; then fail "remote status was lost"; else
  [ "$?" -eq 7 ] || fail "remote status was not 7"
fi
dd if=/dev/urandom of="$fixture/payload" bs=1M count=4 status=none
"${SSH[@]}" /user/bin/ssh posk-dt /bin/cat < "$fixture/payload" > "$fixture/returned"
cmp "$fixture/payload" "$fixture/returned" || fail "jump stream changed data"
printf 'put %s %s/source\n' "$fixture/payload" "$guest" | "${SFTP[@]}" >/dev/null
"${SSH[@]}" /user/bin/scp "$guest/source" "posk-dt:$fixture/upload"
"${SSH[@]}" /user/bin/scp "posk-dt:$fixture/upload" "$guest/download"
printf 'get %s %s/sftp-download\n' "$fixture/upload" "$guest" |
  "${SSH[@]}" /user/bin/sftp -b - posk-dt >/dev/null
printf 'get %s/download %s/download\n' "$guest" "$fixture" | "${SFTP[@]}" >/dev/null
cmp "$fixture/payload" "$fixture/download" || fail "jump scp changed data"
printf 'get %s/sftp-download %s/sftp-download\n' "$guest" "$fixture" | "${SFTP[@]}" >/dev/null
cmp "$fixture/payload" "$fixture/sftp-download" || fail "jump sftp changed data"
if [ -n "${MOTOR_SSH_PASSWORD_TARGET_PORT:-}" ]; then
  out="$(printf 'yes\r\nvroomvroom\r\n' | ssh -F /dev/null -tt -p 2222 -i "$WD/test.key" \
    -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$WD/test-known-hosts" motor@192.168.4.2 \
    "/user/bin/ssh -T password-target /bin/echo jump-password-ok")"
  printf '%s\n' "$out" | tr -d '\r' | grep -qx jump-password-ok || fail "password through jump failed: '$out'"
fi
echo "test-ssh-config: PASS"
