#!/bin/bash
# Guest curl and Gears against the host mock's HTTP endpoint on the TAP
# address. Runs against an already booted development image.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../../.." && pwd)"
WD="$ROOT_DIR/src/tests"
PROFILE=debug
case "${1:-}" in
  "") ;;
  --release) PROFILE=release ;;
  *) echo "usage: test-gears-http-vm.sh [--release]" >&2; exit 2 ;;
esac
MOCK="$ROOT_DIR/src/bin/gears/target/$PROFILE/examples/mock-provider"
[ -x "$MOCK" ] || { echo "run test-gears-http.sh first to build $MOCK" >&2; exit 1; }
chmod 600 "$WD/test.key"
WORK="$(mktemp -d /tmp/gears-http-vm.XXXXXX)"
GUEST_DIR="/user/tmp/$(basename "$WORK")"
SSH=(ssh -F /dev/null -p 2222 -o IdentitiesOnly=yes -o BatchMode=yes
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts"
  -i "$WD/test.key" motor@192.168.4.2)
MOCK_PID=""
PERMISSIONS_ISOLATED=0

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if [ "$PERMISSIONS_ISOLATED" = 1 ]; then restore_permissions; fi
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
  local scenario="${1:-streamed-text}"
  timeout 60s "$MOCK" --addr 192.168.4.1:0 --plain --allow-non-loopback \
    --scenario "$scenario" --expect-model test/model \
    >"$WORK/$CASE.mock.log" 2>"$WORK/$CASE.mock-stderr.log" &
  MOCK_PID=$!
  local ready="" _
  for _ in $(seq 50); do
    ready="$(grep -m 1 '^GEARS_MOCK_READY' "$WORK/$CASE.mock.log" || true)"
    [ -n "$ready" ] && break
    kill -0 "$MOCK_PID" 2>/dev/null || fail "mock provider exited before becoming ready"
    sleep 0.1
  done
  [[ "$ready" =~ ^GEARS_MOCK_READY\ base_url=http://192\.168\.4\.1:([0-9]+)/v1\ scenario=$scenario$ ]] \
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

# The installed configuration and manifests are the same files tested on Linux.
CASE=shipped-tools
vm_ssh "OPENROUTER_API_KEY=fixture-child-key ${GEARS_VM_TEST_DIR:-/user/tmp/gears-tests}/tool-smoke /user/cfg/gears" \
  >"$WORK/tools.stdout.log" 2>"$WORK/tools.stderr.log"
grep -qx 'gears shipped tools ALL PASS' "$WORK/tools.stdout.log"

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
api_key_file = "$GUEST_DIR/local.key"
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

# Exercise every line-UI choice and its next-call behavior on the guest.
# Preserve existing global state, including on a failed case.
restore_permissions() {
  vm_ssh "if [ -f /user/cfg/gears/permissions.toml ]; then /system/bin/rm /user/cfg/gears/permissions.toml; fi; if [ -f $GUEST_DIR/permissions.original ]; then /system/bin/mv $GUEST_DIR/permissions.original /user/cfg/gears/permissions.toml; fi"
  PERMISSIONS_ISOLATED=0
}
vm_ssh "if [ -f /user/cfg/gears/permissions.toml ]; then /system/bin/mv /user/cfg/gears/permissions.toml $GUEST_DIR/permissions.original; fi"
PERMISSIONS_ISOLATED=1
# Count actual tool launches: debug runtime logs can interleave with the line
# renderer's stderr. Keep the shipped manifest and shell implementation.
vm_ssh "/system/bin/mkdir $GUEST_DIR/sh"
for file in tool.toml parameters.json; do
  vm_ssh "/system/bin/cp /user/cfg/gears/tools/sh/$file $GUEST_DIR/sh/$file"
done
vm_ssh "/system/bin/rush -c 'cat >$GUEST_DIR/sh/run.sh'" <<'EOF'
printf 'run\n' >> "$GEARS_WORKSPACE/runs"
. /user/cfg/gears/tools/sh/run.sh
EOF
for choice in y n s g S G; do
  CASE="approval-$choice"
  start_mock sh-round-twice
  cat >"$WORK/approval.toml" <<EOT
version = 1
[provider]
base_url = "$BASE_URL"
model = "test/model"
api_key_file = "$GUEST_DIR/local.key"
[net]
egress_allowlist = ["192.168.4.1"]
plain_http_allowlist = ["192.168.4.1"]
[[tools]]
directory = "$GUEST_DIR/sh"
enabled = true
EOT
  vm_ssh "/system/bin/rush -c 'cat >$GUEST_DIR/approval.toml'" <"$WORK/approval.toml"
  vm_ssh "/system/bin/rush -c ': >$GUEST_DIR/runs'"
  {
    printf 'first\n%s\nsecond\n' "$choice"
    case "$choice" in y|n) printf 'y\n' ;; esac
    printf '/permissions\n/quit\n'
  } | vm_ssh "/system/bin/rush -c 'unset OPENROUTER_API_KEY; /devtools/bin/gears --ui line --ephemeral --config $GUEST_DIR/approval.toml --workspace $GUEST_DIR'" \
    >"$WORK/$CASE.stdout.log" 2>"$WORK/$CASE.stderr.log"
  finish_mock
  expected_prompts=1
  case "$choice" in y|n) expected_prompts=2 ;; esac
  [ "$(grep -oF '[y allow once / s session / g global / n deny once / S session / G global]' "$WORK/$CASE.stdout.log" | wc -l)" = "$expected_prompts" ] || fail "wrong approval prompt count"
  expected_runs=2
  case "$choice" in n) expected_runs=1 ;; S|G) expected_runs=0 ;; esac
  runs="$(vm_ssh "/system/bin/cat $GUEST_DIR/runs")"
  [ "$(printf '%s' "$runs" | grep -c '^run$' || true)" = "$expected_runs" ] || fail "wrong execution count"
  case "$choice" in
    s) grep -Fq 'sh: session allow' "$WORK/$CASE.stderr.log" ;;
    g) grep -Fq 'sh: global allow' "$WORK/$CASE.stderr.log" ;;
    S) grep -Fq 'sh: session deny' "$WORK/$CASE.stderr.log" ;;
    G) grep -Fq 'sh: global deny' "$WORK/$CASE.stderr.log" ;;
  esac
  vm_ssh "if [ -f /user/cfg/gears/permissions.toml ]; then /system/bin/rm /user/cfg/gears/permissions.toml; fi"
done
restore_permissions

# A first run in a terminal: the setup questions and then the session TUI.
# Motor OS allows one Ctrl+C registration per process, so the second screen
# must not register again.
CASE=first-run-tui
FIRST="$GUEST_DIR/first-run"
vm_ssh "/system/bin/mkdir $FIRST; /system/bin/mkdir $FIRST/ws"
vm_ssh "/system/bin/rush -c 'cat >$FIRST/gears.toml'" <<'EOF'
version = 1
default_provider = "local"
[providers.local]
base_url = "http://127.0.0.1:8080/v1"
models = ["small"]
[net]
egress_allowlist = ["127.0.0.1"]
plain_http_allowlist = ["127.0.0.1"]
EOF
# Provider, address and model pickers, then /exit in the session.
printf '\r\r\r/exit\r' | vm_ssh -tt "GEARS_DIRECTORY=$FIRST /devtools/bin/gears --workspace $FIRST/ws" \
  >"$WORK/$CASE.log" 2>&1 || fail "gears failed: $(tr -d '\r' <"$WORK/$CASE.log" | tail -c 300)"
grep -q 'Gears session .* exited\.' "$WORK/$CASE.log" || fail "the session TUI did not start"
vm_ssh "/system/bin/cat $FIRST/provider.toml" >"$WORK/$CASE.provider.log"
grep -qx 'provider = "local"' "$WORK/$CASE.provider.log" || fail "provider not saved"
grep -qx 'model = "small"' "$WORK/$CASE.provider.log" || fail "model not saved"

vm_ssh "/system/bin/rm -r $GUEST_DIR"
echo "test-gears-http-vm.sh ALL PASS"
