#!/usr/bin/env bash
# Config aliases and TCP forwarding in both directions across the private tap.
set -euo pipefail
WD="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$WD/../.." && pwd)"
TEST_TMP="${MOTOR_TEST_TMP:-/user/tmp/motor-tests}"
target_port="$MOTOR_SSH_TARGET_PORT"
BUILD="$MOTOR_SSH_BUILD"
. "$WD/test-ssh-client-host.sh"
mkdir -p "$ROOT_DIR/build/host-tests"
fixture="$(mktemp -d "$ROOT_DIR/build/host-tests/ssh-config.XXXXXX")"
guest="$TEST_TMP/ssh-config"
config=/user/cfg/ssh/config
staged=0
loopback_log_pid="" shell_pid="" gateway_pid="" gateway_log_pid=""
SSH=(ssh -F /dev/null -p 2222 -i "$WD/test.key" -o IdentitiesOnly=yes -o BatchMode=yes
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" motor@192.168.4.2)
SFTP=(sftp -F /dev/null -P 2222 -i "$WD/test.key" -o IdentitiesOnly=yes -o BatchMode=yes
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" -b - motor@192.168.4.2)
fail() { echo "test-ssh-config: $* (logs: $fixture)" >&2; exit 1; }
cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if [ -n "$shell_pid" ]; then kill "$shell_pid" 2>/dev/null; wait "$shell_pid"; fi
  if [ -n "$gateway_pid" ]; then kill "$gateway_pid" 2>/dev/null; wait "$gateway_pid"; fi
  if [ -n "$gateway_log_pid" ]; then wait "$gateway_log_pid" || status=1; fi
  stop_ssh_client_host
  if [ -n "$loopback_log_pid" ]; then wait "$loopback_log_pid" || status=1; fi
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
SSH_CLIENT_HOST_ROOT="$fixture/loopback"
mkdir -m 700 "$SSH_CLIENT_HOST_ROOT"
start_ssh_client_host "$WD/test.key" 0 /bin:/usr/bin 127.0.0.1
loopback_port="$SSH_CLIENT_HOST_PORT"
cat <&"$SSH_CLIENT_HOST_OUTPUT_FD" > "$fixture/loopback.log" &
loopback_log_pid="$!"
cat > "$fixture/client.cfg" <<EOF
Host moto-hi
  HostName 192.168.4.1
  User motor
  Port $target_port
  IdentityFile $guest/key
Host jumped
  HostName 127.0.0.1
  User motor
  Port $loopback_port
  IdentityFile $guest/key
  ProxyJump moto-hi
Host password-target
  HostName 127.0.0.1
  User motor
  Port $loopback_port
  IdentityFile none
  ProxyJump moto-hi
  BatchMode no
  StrictHostKeyChecking ask
  UserKnownHostsFile $guest/password_hosts
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
echo '-- Motor client through a host jump --'
out="$("${SSH[@]}" /user/bin/ssh moto-hi /bin/echo direct-alias)"
[ "$out" = direct-alias ] || fail "direct alias returned '$out'"
out="$("${SSH[@]}" /user/bin/ssh jumped /bin/echo jumped-alias)"
[ "$out" = jumped-alias ] || fail "jump alias returned '$out'"
out="$("${SSH[@]}" /user/bin/ssh -F "$guest/alternate" jumped /bin/echo alternate-config)"
[ "$out" = alternate-config ] || fail "alternate config returned '$out'"
out="$("${SSH[@]}" /user/bin/ssh -F none -p "$target_port" -i "$guest/key" \
  -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$guest/known_hosts" \
  motor@192.168.4.1 /bin/echo no-config)"
[ "$out" = no-config ] || fail "-F none returned '$out'"

# This target is on the host's loopback, reachable from the guest only via the jump.
out="$("${SSH[@]}" /user/bin/ssh -J moto-hi -o ProxyJump=none jumped /bin/echo cli-jump)"
[ "$out" = cli-jump ] || fail "-J override returned '$out'"

if "${SSH[@]}" /user/bin/ssh jumped exit 7; then fail "remote status was lost"; else
  [ "$?" -eq 7 ] || fail "remote status was not 7"
fi
dd if=/dev/urandom of="$fixture/payload" bs=1M count=4 status=none
"${SSH[@]}" /user/bin/ssh jumped /bin/cat < "$fixture/payload" > "$fixture/returned"
cmp "$fixture/payload" "$fixture/returned" || fail "jump stream changed data"
printf 'put %s %s/source\n' "$fixture/payload" "$guest" | "${SFTP[@]}" >/dev/null
"${SSH[@]}" /user/bin/scp "$guest/source" "jumped:$fixture/upload"
"${SSH[@]}" /user/bin/scp "jumped:$fixture/upload" "$guest/download"
printf 'get %s %s/sftp-download\n' "$fixture/upload" "$guest" |
  "${SSH[@]}" /user/bin/sftp -b - jumped >/dev/null
printf 'get %s/download %s/download\n' "$guest" "$fixture" | "${SFTP[@]}" >/dev/null
cmp "$fixture/payload" "$fixture/download" || fail "jump scp changed data"
printf 'get %s/sftp-download %s/sftp-download\n' "$guest" "$fixture" | "${SFTP[@]}" >/dev/null
cmp "$fixture/payload" "$fixture/sftp-download" || fail "jump sftp changed data"

out="$(printf 'yes\r\nvroomvroom\r\n' | ssh -F /dev/null -tt -p 2222 -i "$WD/test.key" \
  -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$WD/test-known-hosts" motor@192.168.4.2 \
  '/user/bin/ssh -T password-target /bin/echo jump-password-ok')"
printf '%s\n' "$out" | tr -d '\r' | grep -qx jump-password-ok || fail "password through jump failed: '$out'"

cat > "$fixture/host.cfg" <<EOF
Host guest
  HostName 192.168.4.2
  Port 2222
Host tap
  HostName 192.168.4.1
  Port $target_port
Host *
  User motor
  IdentityFile $WD/test.key
  IdentitiesOnly yes
  UserKnownHostsFile $fixture/host_known
  StrictHostKeyChecking accept-new
  BatchMode yes
  LogLevel ERROR
EOF
echo '-- OpenSSH through the Motor jump --'
out="$(ssh -F "$fixture/host.cfg" -J guest tap /bin/echo guest-jump-ok)"
[ "$out" = guest-jump-ok ] || fail "Motor jump returned '$out'"

# The local Unix socket avoids reserving a host TCP port. The remote side is
# TCP: the guest resolves localhost. from its hosts file and dials port 2222.
echo '-- 100 forwards, local resolution and shell EOF --'
rustc --edition=2024 -D warnings "$WD/ssh-forwarding-probe.rs" -o "$fixture/probe"
mkfifo "$fixture/shell.input" "$fixture/shell.output"
exec {shell_input}<>"$fixture/shell.input"
exec {shell_output}<>"$fixture/shell.output"
(
  exec {shell_input}>&-
  exec {shell_output}>&-
  exec ssh -F "$fixture/host.cfg" -T -o ExitOnForwardFailure=yes \
    -L "$fixture/forward.sock:localhost.:2222" guest \
    'read before && echo "$before" && read after && echo "$after"' \
    < "$fixture/shell.input" > "$fixture/shell.output"
) 2>"$fixture/shell.log" &
shell_pid="$!"
printf 'before-forwards\n' >&"$shell_input"
IFS= read -r -t 5 out <&"$shell_output" || fail "forwarding shell did not start"
[ "$out" = before-forwards ] || fail "unexpected initial shell output '$out'"
timeout 10s "$fixture/probe" "$fixture/forward.sock"
printf 'after-forwards\n' >&"$shell_input"
IFS= read -r -t 5 out <&"$shell_output" || fail "forwarding EOF closed shell input"
[ "$out" = after-forwards ] || fail "unexpected later shell output '$out'"
exec {shell_input}>&-
wait "$shell_pid" || fail "forwarding shell failed"
shell_pid=""
exec {shell_output}>&-

echo '-- Motor local TCP forwarding --'
mkfifo "$fixture/local.input" "$fixture/local.output"
exec {local_input}<>"$fixture/local.input"
exec {local_output}<>"$fixture/local.output"
(
  exec {local_input}>&-
  exec {local_output}>&-
  exec "${SSH[@]}" "/user/bin/ssh -L 127.0.0.1:34307:127.0.0.1:$loopback_port \
    -o ExitOnForwardFailure=yes moto-hi \
    'read before && echo \"\$before\" && read after && echo \"\$after\"'" \
    < "$fixture/local.input" > "$fixture/local.output"
) 2>"$fixture/local.log" &
shell_pid="$!"
printf 'local-ready\n' >&"$local_input"
IFS= read -r -t 5 out <&"$local_output" || fail "Motor local-forward session did not start"
[ "$out" = local-ready ] || fail "unexpected local-forward session output '$out'"
# The Motor listener connects through the host peer to its loopback-only server.
out="$("${SSH[@]}" "/user/bin/ssh -p 34307 -i $guest/key \
  -o UserKnownHostsFile=$guest/known_hosts -o StrictHostKeyChecking=accept-new \
  -o BatchMode=yes motor@127.0.0.1 /bin/echo motor-local-forward-ok")"
[ "$out" = motor-local-forward-ok ] || fail "Motor local forward returned '$out'"
printf 'local-still-alive\n' >&"$local_input"
IFS= read -r -t 5 out <&"$local_output" || fail "local-forward EOF stopped the session"
[ "$out" = local-still-alive ] || fail "unexpected later local-forward output '$out'"
exec {local_input}>&-
wait "$shell_pid" || fail "Motor local-forward session failed"
shell_pid=""
exec {local_output}>&-
echo '-- Motor SOCKS forwarding --'
rustc --edition=2024 --target x86_64-unknown-motor -D warnings \
  "$WD/ssh-socks-probe.rs" -o "$fixture/socks-probe"
printf 'put %s %s/socks-probe\nchmod 700 %s/socks-probe\n' \
  "$fixture/socks-probe" "$guest" "$guest" | "${SFTP[@]}" >/dev/null
mkfifo "$fixture/socks.input" "$fixture/socks.output"
exec {socks_input}<>"$fixture/socks.input"
exec {socks_output}<>"$fixture/socks.output"
(
  exec {socks_input}>&-
  exec {socks_output}>&-
  exec "${SSH[@]}" "/user/bin/ssh -D 127.0.0.1:34308 \
    -o ExitOnForwardFailure=yes moto-hi \
    'read before && echo \"\$before\" && read after && echo \"\$after\"'" \
    < "$fixture/socks.input" > "$fixture/socks.output"
) 2>"$fixture/socks.log" &
shell_pid="$!"
printf 'socks-ready\n' >&"$socks_input"
IFS= read -r -t 5 out <&"$socks_output" || fail "Motor SOCKS session did not start"
[ "$out" = socks-ready ] || fail "unexpected SOCKS session output '$out'"
out="$("${SSH[@]}" "$guest/socks-probe 127.0.0.1:34308 $loopback_port")"
[ "$out" = 'SOCKS forwarding PASS' ] || fail "Motor SOCKS probe returned '$out'"
printf 'socks-still-alive\n' >&"$socks_input"
IFS= read -r -t 5 out <&"$socks_output" || fail "SOCKS EOF stopped the session"
[ "$out" = socks-still-alive ] || fail "unexpected later SOCKS output '$out'"
exec {socks_input}>&-
wait "$shell_pid" || fail "Motor SOCKS session failed"
shell_pid=""
exec {socks_output}>&-
echo '-- Motor server remote TCP forwarding --'
mkfifo "$fixture/server-remote.input" "$fixture/server-remote.output"
exec {remote_input}<>"$fixture/server-remote.input"
exec {remote_output}<>"$fixture/server-remote.output"
(
  exec {remote_input}>&-
  exec {remote_output}>&-
  exec ssh -F "$fixture/host.cfg" -T -o ExitOnForwardFailure=yes \
    -R "127.0.0.1:34309:127.0.0.1:$loopback_port" guest \
    'read before && echo "$before" && read after && echo "$after"' \
    < "$fixture/server-remote.input" > "$fixture/server-remote.output"
) 2>"$fixture/server-remote.log" &
shell_pid="$!"
printf 'server-remote-ready\n' >&"$remote_input"
IFS= read -r -t 5 out <&"$remote_output" || fail "Motor remote listener did not start"
[ "$out" = server-remote-ready ] || fail "unexpected remote-forward session output '$out'"
out="$("${SSH[@]}" "/user/bin/ssh -p 34309 -i $guest/key \
  -o UserKnownHostsFile=$guest/known_hosts -o StrictHostKeyChecking=accept-new \
  -o BatchMode=yes motor@127.0.0.1 /bin/echo motor-server-remote-ok")"
[ "$out" = motor-server-remote-ok ] || fail "Motor server remote forward returned '$out'"
printf 'server-remote-still-alive\n' >&"$remote_input"
IFS= read -r -t 5 out <&"$remote_output" || fail "remote-forward EOF stopped the session"
[ "$out" = server-remote-still-alive ] || fail "unexpected later remote-forward output '$out'"
exec {remote_input}>&-
wait "$shell_pid" || fail "Motor server remote-forward session failed"
shell_pid=""
exec {remote_output}>&-
echo '-- Motor gateway remote forwarding with an allocated port --'
# A separate guest daemon exercises wildcard port allocation without changing
# the shipped loopback policy. Its terminal provides the readiness event.
"${SSH[@]}" /system/bin/cat /system/cfg/sshd.toml |
  sed -e "s/^listen_on = .*/listen_on = '0.0.0.0:34310'/" \
    -e 's/^gateway_ports = .*/gateway_ports = true/' > "$fixture/gateway.toml"
grep -qx 'gateway_ports = true' "$fixture/gateway.toml" || fail "gateway fixture was not enabled"
printf 'put %s %s/gateway.toml\n' "$fixture/gateway.toml" "$guest" | "${SFTP[@]}" >/dev/null
mkfifo "$fixture/gateway.daemon"
"${SSH[@]}" -tt "/system/services/russhd $guest/gateway.toml" \
  < /dev/null > "$fixture/gateway.daemon" 2>&1 &
gateway_pid="$!"
exec {gateway_output}<"$fixture/gateway.daemon"
gateway_ready=0
gateway_deadline=$((SECONDS + 5))
while [ "$SECONDS" -lt "$gateway_deadline" ]; do
  gateway_remaining=$((gateway_deadline - SECONDS))
  IFS= read -r -t "$gateway_remaining" line <&"$gateway_output" || break
  printf '%s\n' "$line" >> "$fixture/gateway-daemon.log"
  case "$line" in
    *'Listening on 0.0.0.0:34310'*) gateway_ready=1; break ;;
  esac
done
[ "$gateway_ready" -eq 1 ] || fail "gateway daemon did not report readiness"
cat <&"$gateway_output" >> "$fixture/gateway-daemon.log" &
gateway_log_pid="$!"
exec {gateway_output}<&-
mkfifo "$fixture/gateway.input" "$fixture/gateway.output"
exec {gateway_input}<>"$fixture/gateway.input"
exec {gateway_result}<>"$fixture/gateway.output"
(
  exec {gateway_input}>&-
  exec {gateway_result}>&-
  exec ssh -F "$fixture/host.cfg" -p 34310 -T -o LogLevel=INFO \
    -o ExitOnForwardFailure=yes -R "0:127.0.0.1:$loopback_port" guest \
    'read before && echo "$before" && read after && echo "$after"' \
    < "$fixture/gateway.input" > "$fixture/gateway.output"
) 2>"$fixture/gateway.log" &
shell_pid="$!"
printf 'gateway-ready\n' >&"$gateway_input"
IFS= read -r -t 5 out <&"$gateway_result" || fail "gateway forwarding session did not start"
[ "$out" = gateway-ready ] || fail "unexpected gateway session output '$out'"
gateway_port="$(sed -n 's/^Allocated port \([0-9][0-9]*\) for remote forward to .*$/\1/p' "$fixture/gateway.log")"
[[ "$gateway_port" =~ ^[0-9]+$ ]] || fail "missing allocated gateway port"
[ "$gateway_port" -ge 49152 ] && [ "$gateway_port" -le 65535 ] ||
  fail "allocated gateway port is outside the selected range"
# Reaching the guest from the tap proves this listener is a wildcard bind.
out="$(ssh -F /dev/null -p "$gateway_port" -i "$WD/test.key" -o IdentitiesOnly=yes \
  -o UserKnownHostsFile="$fixture/gateway-known" -o StrictHostKeyChecking=accept-new \
  -o BatchMode=yes -o LogLevel=ERROR motor@192.168.4.2 /bin/echo motor-gateway-ok)"
[ "$out" = motor-gateway-ok ] || fail "gateway forward returned '$out'"
out="$("${SSH[@]}" "/user/bin/ssh -p $gateway_port -i $guest/key \
  -o UserKnownHostsFile=$guest/known_hosts -o StrictHostKeyChecking=accept-new \
  -o BatchMode=yes 'motor@[::1]' /bin/echo motor-gateway-ipv6-ok")"
[ "$out" = motor-gateway-ipv6-ok ] || fail "gateway IPv6 forward returned '$out'"
printf 'gateway-still-alive\n' >&"$gateway_input"
IFS= read -r -t 5 out <&"$gateway_result" || fail "gateway-forward EOF stopped the session"
[ "$out" = gateway-still-alive ] || fail "unexpected later gateway output '$out'"
exec {gateway_input}>&-
wait "$shell_pid" || fail "gateway-forward session failed"
shell_pid=""
exec {gateway_result}>&-
echo "test-ssh-config: PASS"
