# Shared deterministic local-tap fragmentation regression.

UDP_FRAGMENT_ECHO_PROCESS=""

stop_udp_fragment_echo() {
  if [ -n "$UDP_FRAGMENT_ECHO_PROCESS" ]; then
    kill "$UDP_FRAGMENT_ECHO_PROCESS" 2>/dev/null || true
    wait "$UDP_FRAGMENT_ECHO_PROCESS" 2>/dev/null || true
    UDP_FRAGMENT_ECHO_PROCESS=""
  fi
}

test_udp_fragmentation() {
  local echo_bin="$ROOT_DIR/build/host-tests/udp-fragment-echo"
  local port
  local status=0

  echo "-- local-tap UDP fragmentation --"
  mkdir -p "$(dirname "$echo_bin")"
  rustc --edition 2024 -D warnings "$WD/udp-fragment-echo.rs" -o "$echo_bin"

  coproc UDP_FRAGMENT_ECHO { "$echo_bin"; }
  UDP_FRAGMENT_ECHO_PROCESS="$UDP_FRAGMENT_ECHO_PID"
  if ! read -r -t 5 port <&"${UDP_FRAGMENT_ECHO[0]}"; then
    stop_udp_fragment_echo
    fail "host UDP fragmentation echo did not become ready"
  fi
  case "$port" in
    ""|*[!0-9]*) fail "host UDP fragmentation echo returned bad port '$port'" ;;
  esac

  vm_ssh "/devtools/tests/systest test-tap-udp-fragmentation 192.168.4.1:$port"
  vm_ssh "/devtools/tests/systest test-tap-udp-fragmentation [2001:db8::1]:$port"

  wait "$UDP_FRAGMENT_ECHO_PROCESS" || status="$?"
  UDP_FRAGMENT_ECHO_PROCESS=""
  [ "$status" -eq 0 ] || fail "host UDP fragmentation echo failed (status $status)"
  echo "-- local-tap UDP fragmentation PASS"
}
