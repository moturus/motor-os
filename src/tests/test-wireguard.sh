# Sourced by full-test.sh with its existing VM, SSH helper and test directories.
test_wireguard_case() (
  set -euo pipefail
  umask 077
  local work peer_pid="" wg_pid="" stale_pid="" peer_in peer_out wg_in wg_out
  local stale_in stale_out guest_pid line provider_id
  local name="wg_gate_${BASHPID}" config uploaded=0
  local peer_binary="${WG_PEER_BINARY:-$ROOT_DIR/src/tests/wg-peer/target/$BUILD/wg-peer}"
  local bind=192.168.4.1:0 roam='[2001:db8::1]:0'
  local roam_endpoint='[2001:db8::2]:51820'
  local guest_endpoint=192.168.4.2:51820 role="$2"
  if [ "$1" = ipv6 ]; then
    bind='[2001:db8::1]:0'
    roam=192.168.4.1:0
    roam_endpoint=192.168.4.2:51820
    guest_endpoint='[2001:db8::2]:51820'
  fi
  local peer_args=()
  [ "$role" != host ] || peer_args=(--endpoint "$guest_endpoint")
  work="$(mktemp -d /tmp/test-wireguard.XXXXXX)"
  config="/user/cfg/wireguard/$name.toml"
  cleanup_wireguard() {
    local status=$?
    trap - EXIT
    if [ -n "$stale_pid" ]; then
      kill "$stale_pid" 2>/dev/null || true
      wait "$stale_pid" 2>/dev/null || true
    fi
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

  if [ "$role" = plain ]; then
    peer_args=(--plain --endpoint "$guest_endpoint")
    name=wg_plain
  else
    "$peer_binary" keygen "$work/host.key" "$work/host.pub"
    "$peer_binary" keygen "$work/guest.key" "$work/guest.pub"
    peer_args+=(--private-key "$work/host.key" --peer-key "$work/guest.pub")
  fi
  coproc WG_GATE_PEER {
    exec "$peer_binary" serve --bind "$bind" \
      --address 10.250.20.1/24 --address fd50:20::1/64 \
      "${peer_args[@]}"
  }
  peer_pid="$WG_GATE_PEER_PID"
  exec {peer_in}>&"${WG_GATE_PEER[1]}"
  exec {peer_out}<&"${WG_GATE_PEER[0]}"
  local banner endpoint
  IFS= read -r -t 5 banner <&"$peer_out" || fail "WireGuard host peer did not become ready"
  case "$banner" in
    "READY "*) endpoint="${banner#READY }" ;;
    *) fail "unexpected WireGuard peer banner: $banner" ;;
  esac
  local guest_command="$TEST_BIN/systest ip-device-plain $guest_endpoint $endpoint"
  if [ "$role" != plain ]; then
    guest_command="/system/bin/wg $config"
    cat > "$work/config.toml" <<EOF
transport_addresses = ["192.168.4.2", "2001:db8::2"]
listen_port = 51820
cidrs = ["10.250.20.2/24", "fd50:20::2/64"]
[[peers]]
public_key = "$(cat "$work/host.pub")"
allowed_ips = ["10.250.20.0/24", "fd50:20::/64"]
EOF
    if [ "$role" = guest ]; then
      printf 'endpoint = "%s"\n' "$endpoint" >> "$work/config.toml"
    fi
    vm_ssh "/system/bin/rush -c '[ -d /user/cfg/wireguard ] || mkdir /user/cfg/wireguard'"
    printf 'put %s %s\nput %s %s\nchmod 660 %s\nchmod 660 %s\n' \
      "$work/config.toml" "$config" "$work/guest.key" "/user/cfg/wireguard/$name.key" \
      "$config" "/user/cfg/wireguard/$name.key" > "$work/upload"
    uploaded=1
    sftp -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
      -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" \
      -i "$WD/test.key" -b "$work/upload" motor@192.168.4.2
    vm_ssh "$TEST_BIN/systest wireguard-permissions $config /user/cfg/wireguard/$name.key"
    vm_ssh "$TEST_BIN/systest wireguard-readable-secrets $config /user/cfg/wireguard/$name.key"
  fi
  vm_ssh "$TEST_BIN/systest wireguard-cleanup"

  mkfifo "$work/wg.in" "$work/wg.out"
  exec {wg_in}<>"$work/wg.in"
  start_wireguard() {
    ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 "$guest_command" \
      < "$work/wg.in" > "$work/wg.out" 2>&1 &
    wg_pid="$!"
    exec {wg_out}<"$work/wg.out"
    local deadline=$((SECONDS + 5)) active=0
    while [ "$SECONDS" -lt "$deadline" ]; do
      IFS= read -r -t "$((deadline - SECONDS))" line <&"$wg_out" || break
      printf '%s\n' "$line"
      case "$line" in *"$name: active"*) active=1; break ;; esac
    done
    [ "$active" = 1 ] || fail "WireGuard did not activate"
    [[ "$line" =~ pid=([0-9]+) ]] || fail "WireGuard omitted its process id"
    guest_pid="${BASH_REMATCH[1]}"
  }
  stop_wireguard() {
    printf '\003' >&"$wg_in"
    cat <&"$wg_out"
    exec {wg_out}<&-
    local status=0
    wait "$wg_pid" || status="$?"
    wg_pid=""
    [ "$status" = 130 ] || fail "WireGuard exited with status $status"
    vm_ssh "$TEST_BIN/systest wireguard-cleanup"
  }
  start_wireguard

  peer_ping() {
    local address="$1" response
    printf 'ping %s\n' "$address" >&"$peer_in"
    IFS= read -r -t 5 response <&"$peer_out" || fail "peer ping did not start"
    [ "$response" = "PING-START $address" ] || fail "unexpected peer response: $response"
    IFS= read -r -t 5 response <&"$peer_out" || fail "peer ping did not finish"
    [ "$response" = "PING OK" ] || fail "peer could not ping the guest: $response"
  }
  if [ "$role" = host ]; then
    peer_ping 10.250.20.2
  fi
  if [ "$role" != plain ] && [ "${WG_BENCHMARK:-0}" != 1 ]; then
    printf 'padding on\n' >&"$peer_in"
    IFS= read -r -t 5 line <&"$peer_out" || fail "peer did not enable padding"
    [ "$line" = 'PADDING ON' ] || fail "unexpected peer response: $line"
  fi
  for inner in 10.250.20.1 fd50:20::1; do
    vm_ssh "/system/bin/ping -c 1 $inner"
  done
  vm_ssh "$TEST_BIN/systest wireguard-client 10.250.20.1 10.250.20.2"
  if [ "$1" = ipv6 ] && [ "$role" != plain ] && [ "${WG_BENCHMARK:-0}" != 1 ]; then
    vm_ssh "$TEST_BIN/systest wireguard-fragmented-reply"
  else
    vm_ssh "$TEST_BIN/systest wireguard-client fd50:20::1 fd50:20::2"
  fi
  peer_ping 10.250.20.2
  peer_ping fd50:20::2

  if [ "${WG_BENCHMARK:-0}" = 1 ]; then
    vm_ssh "$TEST_BIN/systest wireguard-measure $guest_pid 10.250.20.1:40000"
    if [ "$role" != plain ]; then
      provider_id="$(vm_ssh '/system/bin/sysbox stats providers' |
        awk -v name="wg:$guest_pid" '$2 == name {print $1}')"
      [ -n "$provider_id" ] || fail "WireGuard statistics provider is missing"
      vm_ssh "/system/bin/sysbox stats get $provider_id"
    fi
    vm_ssh '/system/bin/sysbox stats get 2'
    printf 'stats\n' >&"$peer_in"
    IFS= read -r -t 5 line <&"$peer_out" || fail "peer did not report benchmark counters"
    case "$line" in STATS\ *) printf 'host peer %s\n' "$line" ;; *) fail "unexpected peer counters: $line" ;; esac
  elif [ "$role" != plain ]; then
    # Invalid traffic from a new outer address cannot authenticate a move.
    printf 'roam %s %s\n' "$roam" "$roam_endpoint" >&"$peer_in"
    IFS= read -r -t 5 line <&"$peer_out" || fail "peer did not change transport"
    case "$line" in "ROAM "*) ;; *) fail "unexpected peer response: $line" ;; esac
    for invalid in replay tamper malformed; do
      printf '%s\n' "$invalid" >&"$peer_in"
      IFS= read -r -t 5 line <&"$peer_out" || fail "peer did not send $invalid"
      [ "$line" = "SENT $invalid" ] || fail "unexpected peer response: $line"
    done
    vm_ssh "$TEST_BIN/systest wireguard-rejections $guest_pid"
    printf 'keepalive\n' >&"$peer_in"
    IFS= read -r -t 5 line <&"$peer_out" || fail "peer did not send keepalive"
    [ "$line" = KEEPALIVE ] || fail "unexpected peer response: $line"
    peer_ping fd50:20::2
    vm_ssh "$TEST_BIN/systest wireguard-client 10.250.20.1 10.250.20.2"
    vm_ssh "$TEST_BIN/systest wireguard-client fd50:20::1 fd50:20::2"
    vm_ssh "$TEST_BIN/systest wireguard-load $guest_pid"
  fi

  if [ "${WG_BENCHMARK:-0}" = 1 ]; then
    stop_wireguard
  else
    mkfifo "$work/stale.in" "$work/stale.out"
    exec {stale_in}<>"$work/stale.in"
    ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2 "$TEST_BIN/systest wireguard-stale-sockets" \
      < "$work/stale.in" > "$work/stale.out" 2>&1 &
    stale_pid="$!"
    exec {stale_out}<"$work/stale.out"
    stale_phase() {
      local deadline=$((SECONDS + 5))
      while [ "$SECONDS" -lt "$deadline" ]; do
        IFS= read -r -t "$((deadline - SECONDS))" line <&"$stale_out" || break
        printf '%s\n' "$line"
        [ "$line" != "$1" ] || return 0
      done
      fail "stale sockets did not reach $1"
    }
    stale_phase 'STALE READY'
    stop_wireguard
    stale_phase 'STALE INVALIDATED'
    start_wireguard
    if [ "$role" != plain ]; then
      printf 'handshake\n' >&"$peer_in"
      IFS= read -r -t 5 line <&"$peer_out" || fail "peer did not initiate a fresh handshake"
      [ "$line" = HANDSHAKE ] || fail "unexpected peer response: $line"
      IFS= read -r -t 5 line <&"$peer_out" || fail "peer did not complete the fresh handshake"
      [ "$line" = 'HANDSHAKE OK' ] || fail "unexpected peer response: $line"
    fi
    peer_ping 10.250.20.2
    printf 'x' >&"$stale_in"
    cat <&"$stale_out"
    wait "$stale_pid"
    stale_pid=""
    vm_ssh "$TEST_BIN/systest wireguard-client 10.250.20.1 10.250.20.2"
    vm_ssh "$TEST_BIN/systest wireguard-client fd50:20::1 fd50:20::2"
    stop_wireguard
  fi
  printf 'quit\n' >&"$peer_in"
  wait "$peer_pid"
  peer_pid=""
  echo "WireGuard VM integration $1 initiator=$role PASS"
)

test_wireguard() {
  for family in ipv4 ipv6; do
    for initiator in guest host plain; do
      test_wireguard_case "$family" "$initiator"
    done
  done
}
