# Sourced by full-test.sh with its existing VM, SSH helper and test directories.
test_wireguard() (
  set -euo pipefail
  umask 077
  local work peer_pid="" wg_pid="" peer_in peer_out wg_in wg_out
  local name="wg_gate_${BASHPID}" config uploaded=0
  local peer_binary="${WG_PEER_BINARY:-$ROOT_DIR/src/tests/wg-peer/target/$BUILD/wg-peer}"
  work="$(mktemp -d /tmp/test-wireguard.XXXXXX)"
  config="/user/cfg/wireguard/$name.toml"
  cleanup_wireguard() {
    local status=$?
    trap - EXIT
    if [ -n "$wg_pid" ]; then
      kill "$wg_pid" 2>/dev/null || true
      wait "$wg_pid" 2>/dev/null || true
    fi
    if [ -n "$peer_pid" ]; then
      kill "$peer_pid" 2>/dev/null || true
      wait "$peer_pid" 2>/dev/null || true
    fi
    if [ "$uploaded" = 1 ]; then
      vm_ssh "/system/bin/rm $config" || true
      vm_ssh "/system/bin/rm /user/cfg/wireguard/$name.key" || true
    fi
    rm -rf "$work"
    exit "$status"
  }
  trap cleanup_wireguard EXIT

  "$peer_binary" keygen "$work/host.key" "$work/host.pub"
  "$peer_binary" keygen "$work/guest.key" "$work/guest.pub"
  coproc WG_GATE_PEER {
    exec "$peer_binary" serve --bind 192.168.4.1:0 \
      --address 10.250.20.1/24 --address fd50:20::1/64 \
      --private-key "$work/host.key" --peer-key "$work/guest.pub"
  }
  peer_pid="$WG_GATE_PEER_PID"
  exec {peer_in}>&"${WG_GATE_PEER[1]}"
  exec {peer_out}<&"${WG_GATE_PEER[0]}"
  local banner endpoint
  IFS= read -r -t 5 banner <&"$peer_out" || fail "WireGuard host peer did not become ready"
  case "$banner" in
    "READY 192.168.4.1:"*) endpoint="${banner#READY }" ;;
    *) fail "unexpected WireGuard peer banner: $banner" ;;
  esac
  cat > "$work/config.toml" <<EOF
transport_addresses = ["192.168.4.2"]
listen_port = 51820
cidrs = ["10.250.20.2/24", "fd50:20::2/64"]
[[peers]]
public_key = "$(cat "$work/host.pub")"
endpoint = "$endpoint"
allowed_ips = ["10.250.20.0/24", "fd50:20::/64"]
EOF
  vm_ssh "/system/bin/rush -c '[ -d /user/cfg/wireguard ] || mkdir /user/cfg/wireguard'"
  printf 'put %s %s\nput %s %s\nchmod 660 %s\nchmod 660 %s\n' \
    "$work/config.toml" "$config" "$work/guest.key" "/user/cfg/wireguard/$name.key" \
    "$config" "/user/cfg/wireguard/$name.key" > "$work/upload"
  uploaded=1
  sftp -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" \
    -i "$WD/test.key" -b "$work/upload" motor@192.168.4.2
  vm_ssh "$TEST_BIN/systest wireguard-permissions $config /user/cfg/wireguard/$name.key"
  vm_ssh "$TEST_BIN/systest wireguard-cleanup"

  mkfifo "$work/wg.in" "$work/wg.out"
  exec {wg_in}<>"$work/wg.in"
  ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 "/system/bin/wg $config" \
    < "$work/wg.in" > "$work/wg.out" 2>&1 &
  wg_pid="$!"
  exec {wg_out}<"$work/wg.out"
  local deadline=$((SECONDS + 5)) active=0 line
  while [ "$SECONDS" -lt "$deadline" ]; do
    IFS= read -r -t "$((deadline - SECONDS))" line <&"$wg_out" || break
    printf '%s\n' "$line"
    case "$line" in *"$name: active"*) active=1; break ;; esac
  done
  [ "$active" = 1 ] || fail "WireGuard did not activate"

  for inner in 10.250.20.1 fd50:20::1; do
    vm_ssh "/system/bin/ping -c 1 $inner"
  done
  vm_ssh "$TEST_BIN/systest wireguard-client 10.250.20.1 10.250.20.2"
  vm_ssh "$TEST_BIN/systest wireguard-client fd50:20::1 fd50:20::2"
  printf 'ping 10.250.20.2\n' >&"$peer_in"
  IFS= read -r -t 5 line <&"$peer_out" || fail "peer ping did not start"
  [ "$line" = "PING-START 10.250.20.2" ] || fail "unexpected peer response: $line"
  IFS= read -r -t 5 line <&"$peer_out" || fail "peer ping did not finish"
  [ "$line" = "PING OK" ] || fail "peer could not ping the guest: $line"

  printf '\003' >&"$wg_in"
  cat <&"$wg_out"
  local status=0
  wait "$wg_pid" || status="$?"
  wg_pid=""
  [ "$status" = 130 ] || fail "WireGuard exited with status $status"
  vm_ssh "$TEST_BIN/systest wireguard-cleanup"
  printf 'quit\n' >&"$peer_in"
  wait "$peer_pid"
  peer_pid=""
  echo "WireGuard VM integration PASS"
)
