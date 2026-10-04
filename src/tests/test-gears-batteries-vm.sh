#!/bin/bash
# Native policy input and a hermetic real-tool workflow with a compiler check.
set -euo pipefail
WD="$(cd "$(dirname "$0")" && pwd)"
case "${1:-}" in
  ""|--release) ;;
  *) echo "usage: test-gears-batteries-vm.sh [--release]" >&2; exit 2 ;;
esac
chmod 600 "$WD/test.key"
SSH=(ssh -F /dev/null -p 2222 -o IdentitiesOnly=yes -o BatchMode=yes
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts"
  -i "$WD/test.key" motor@192.168.4.2)
BATTERIES_BIN="${GEARS_BATTERIES_VM_BIN:-/devtools/bin/gears-batteries}"
EVENT='{"protocol_version":1,"event":"permission","workspace":"/user","session":{"id":"fixture"}}'
OUTPUT="$(printf '%s' "$EVENT" | "${SSH[@]}" "$BATTERIES_BIN" hook)"
python3 -c 'import json, sys; reply = json.load(sys.stdin); assert reply["decision"] == "deny"; assert "invalid permission call" in reply["notice"]' <<< "$OUTPUT"
EVENT='{"protocol_version":1,"event":"permission","workspace":"/user","session":{"id":"fixture"},"payload":{"tool_call":{"id":"c1","name":"todo","arguments":"{}"}}}'
OUTPUT="$(printf '%s' "$EVENT" | "${SSH[@]}" "$BATTERIES_BIN" hook)"
[ "$OUTPUT" = '{"decision":"allow"}' ]
EVENT='{"protocol_version":1,"event":"permission","workspace":"/user","session":{"id":"fixture"},"payload":{"tool_call":{"id":"c1","name":"sh","arguments":"{\"command\":\"rush -c '"'"'cd /user; sysbox rm -rf cfg'"'"'\"}"}}}'
OUTPUT="$(printf '%s' "$EVENT" | "${SSH[@]}" "$BATTERIES_BIN" hook)"
[ "$OUTPUT" = '{"decision":"deny"}' ]
if printf '{}' | "${SSH[@]}" "$BATTERIES_BIN" hook; then
  echo "batteries accepted malformed hook input" >&2
  exit 1
fi
"${SSH[@]}" "${GEARS_BATTERIES_VM_SMOKE:-/devtools/tests/gears/gears-batteries-smoke}" \
  "$BATTERIES_BIN" /devtools/bin/rustc
# No chat prompt: load the installed config and its sibling hook without a
# provider request or a persistent session. The key is a fixture placeholder.
OUTPUT="$(printf '/tools\n/quit\n' | "${SSH[@]}" \
  'OPENROUTER_API_KEY=fixture-local /devtools/bin/gears --ui line --ephemeral --config /user/cfg/gears/gears-batteries.toml --provider local --model fixture --workspace /user/tmp' 2>&1)"
# /tools lists directory tools; hook setup failures appear as gears: notices.
python3 -c 'import sys; output = sys.stdin.read(); assert "read_file: enabled (config)" in output and "check: enabled (config)" in output, output; assert "gears:" not in output, output' <<< "$OUTPUT"
echo "test-gears-batteries-vm.sh ALL PASS"
