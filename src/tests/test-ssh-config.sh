#!/usr/bin/env bash
# Config aliases from Motor OS, against the host russhd of test-ssh-client-host.sh.
# russhd forwards nothing, so ProxyJump goes as far as the jump's refusal here;
# client_protocol.rs carries it through a real jump.
set -euo pipefail
WD="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$WD/../.." && pwd)"
TEST_TMP="${MOTOR_TEST_TMP:-/user/tmp/motor-tests}"
target_port="$MOTOR_SSH_TARGET_PORT"
mkdir -p "$ROOT_DIR/build/host-tests"
fixture="$(mktemp -d "$ROOT_DIR/build/host-tests/ssh-config.XXXXXX")"
guest="$TEST_TMP/ssh-config"
config=/user/cfg/ssh/config
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
cat > "$fixture/client.cfg" <<EOF
Host moto-hi
  HostName 192.168.4.1
  User motor
  Port $target_port
  IdentityFile $guest/key
Host jumped
  HostName 192.0.2.1
  User motor
  IdentityFile $guest/key
  ProxyJump moto-hi
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
out="$("${SSH[@]}" /user/bin/ssh -F "$guest/alternate" moto-hi /bin/echo alternate-config)"
[ "$out" = alternate-config ] || fail "alternate config returned '$out'"
out="$("${SSH[@]}" /user/bin/ssh -F none -p "$target_port" -i "$guest/key" \
  -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$guest/known_hosts" \
  motor@192.168.4.1 /bin/echo no-config)"
[ "$out" = no-config ] || fail "-F none returned '$out'"

# The route reached the jump: the target itself is an address nothing answers on.
refused_by_jump() {
  local output status=0
  output="$("${SSH[@]}" /user/bin/ssh "$@" /bin/echo unreachable 2>&1)" || status=$?
  [ "$status" -eq 255 ] || fail "'$*' returned status $status: '$output'"
  case "$output" in
    *AdministrativelyProhibited*) ;;
    *) fail "'$*' was not refused by the jump: '$output'" ;;
  esac
}
refused_by_jump jumped
refused_by_jump -J moto-hi -o ProxyJump=none jumped

if "${SSH[@]}" /user/bin/ssh moto-hi exit 7; then fail "remote status was lost"; else
  [ "$?" -eq 7 ] || fail "remote status was not 7"
fi
dd if=/dev/urandom of="$fixture/payload" bs=1M count=4 status=none
"${SSH[@]}" /user/bin/ssh moto-hi /bin/cat < "$fixture/payload" > "$fixture/returned"
cmp "$fixture/payload" "$fixture/returned" || fail "alias stream changed data"
printf 'put %s %s/source\n' "$fixture/payload" "$guest" | "${SFTP[@]}" >/dev/null
"${SSH[@]}" /user/bin/scp "$guest/source" "moto-hi:$fixture/upload"
"${SSH[@]}" /user/bin/scp "moto-hi:$fixture/upload" "$guest/download"
printf 'get %s %s/sftp-download\n' "$fixture/upload" "$guest" |
  "${SSH[@]}" /user/bin/sftp -b - moto-hi >/dev/null
printf 'get %s/download %s/download\n' "$guest" "$fixture" | "${SFTP[@]}" >/dev/null
cmp "$fixture/payload" "$fixture/download" || fail "alias scp changed data"
printf 'get %s/sftp-download %s/sftp-download\n' "$guest" "$fixture" | "${SFTP[@]}" >/dev/null
cmp "$fixture/payload" "$fixture/sftp-download" || fail "alias sftp changed data"
echo "test-ssh-config: PASS"
