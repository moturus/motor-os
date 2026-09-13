#!/bin/bash
# Guest curl and Gears against the host mock's HTTP endpoint on the TAP
# address. Runs against an already booted development image.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
WD="$ROOT_DIR/src/tests"
PROFILE=debug
case "${1:-}" in
  "") ;;
  --release) PROFILE=release ;;
  *) echo "usage: test-gears-http-vm.sh [--release]" >&2; exit 2 ;;
esac
MOCK="$ROOT_DIR/src/bin/gears-mock-provider/target/$PROFILE/gears-mock-provider"
[ -x "$MOCK" ] || { echo "run test-gears-http.sh first to build $MOCK" >&2; exit 1; }
chmod 600 "$WD/test.key"
WORK="$(mktemp -d /tmp/gears-http-vm.XXXXXX)"
GUEST_DIR="/user/tmp/$(basename "$WORK")"
SSH=(ssh -F /dev/null -p 2222 -o IdentitiesOnly=yes -o BatchMode=yes
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts"
  -i "$WD/test.key" motor@192.168.4.2)
MOCK_PID=""

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if [ -n "$MOCK_PID" ]; then
    kill "$MOCK_PID" 2>/dev/null
    wait "$MOCK_PID" 2>/dev/null
  fi
  if [ "$status" = 0 ]; then
    rm -r "$WORK"
  else
    echo "gears HTTP failure logs retained in $WORK" >&2
    tail -n +1 "$WORK"/*.log >&2
  fi
  exit "$status"
}
trap cleanup EXIT

vm_ssh() { timeout 30s "${SSH[@]}" "$@"; }
fail() { echo "$CASE: $*" >&2; exit 1; }

# The mock serves one request and exits; the timeout bounds a client that
# never connects.
start_mock() {
  timeout 60s "$MOCK" --addr 192.168.4.1:0 --plain --allow-non-loopback \
    --scenario streamed-text --expect-model test/model \
    >"$WORK/$CASE.mock.log" 2>"$WORK/$CASE.mock-stderr.log" &
  MOCK_PID=$!
  local ready="" _
  for _ in $(seq 50); do
    ready="$(grep -m 1 '^GEARS_MOCK_READY' "$WORK/$CASE.mock.log" || true)"
    [ -n "$ready" ] && break
    kill -0 "$MOCK_PID" 2>/dev/null || fail "mock provider exited before becoming ready"
    sleep 0.1
  done
  [[ "$ready" =~ ^GEARS_MOCK_READY\ base_url=http://192\.168\.4\.1:([0-9]+)/v1\ scenario=streamed-text$ ]] \
    || fail "mock provider did not report a host HTTP endpoint: '$ready'"
  MOCK_PORT="${BASH_REMATCH[1]}"
  BASE_URL="http://192.168.4.1:$MOCK_PORT/v1"
}

finish_mock() {
  wait "$MOCK_PID" || fail "mock provider failed"
  MOCK_PID=""
  grep -q "^GEARS_MOCK_REQUEST index=1 destination=192.168.4.1:$MOCK_PORT " "$WORK/$CASE.mock.log" \
    || fail "mock provider did not record the guest request on the TAP address"
  grep -qx 'GEARS_MOCK_DONE requests_complete' "$WORK/$CASE.mock.log" \
    || fail "mock provider did not complete the scenario"
}

vm_ssh "/system/bin/mkdir $GUEST_DIR"

CASE=curl
start_mock
vm_ssh "/system/bin/curl --proto =http --data-binary '{\"model\":\"test/model\",\"stream\":true,\"messages\":[]}' $BASE_URL/chat/completions" \
  >"$WORK/curl.stdout.log" 2>"$WORK/curl.stderr.log"
grep -Fq 'hello ' "$WORK/curl.stdout.log"
grep -Fq 'from the mock' "$WORK/curl.stdout.log"
grep -Fq '[DONE]' "$WORK/curl.stdout.log"
finish_mock

CASE=gears
start_mock
cat >"$WORK/gears.toml" <<EOT
version = 1
[provider]
base_url = "$BASE_URL"
model = "test/model"
key_file = "$GUEST_DIR/local.key"
[net]
egress_allowlist = ["192.168.4.1"]
EOT
vm_ssh "/system/bin/rush -c 'cat >$GUEST_DIR/gears.toml'" <"$WORK/gears.toml"
vm_ssh "/system/bin/rush -c 'echo fixture-local-key >$GUEST_DIR/local.key'"
# A configured HTTP URL and key still need the separate plaintext grant.
if vm_ssh "/system/bin/rush -c 'unset OPENROUTER_API_KEY; /devtools/bin/gears --config $GUEST_DIR/gears.toml ask hello'" \
  >"$WORK/refusal.stdout.log" 2>"$WORK/refusal.stderr.log"; then
  fail "Gears accepted an HTTP host without a plaintext grant"
fi
grep -Fq 'plain HTTP is not allowed' "$WORK/refusal.stderr.log"
printf 'plain_http_allowlist = ["192.168.4.1"]\n' >>"$WORK/gears.toml"
vm_ssh "/system/bin/rush -c 'cat >$GUEST_DIR/gears.toml'" <"$WORK/gears.toml"
vm_ssh "/system/bin/rush -c 'unset OPENROUTER_API_KEY; /devtools/bin/gears --config $GUEST_DIR/gears.toml ask hello'" \
  >"$WORK/gears.stdout.log" 2>"$WORK/gears.stderr.log"
[ "$(cat "$WORK/gears.stdout.log")" = "hello from the mock" ]
finish_mock

vm_ssh "/system/bin/rm -r $GUEST_DIR"
echo "test-gears-http-vm.sh ALL PASS"
