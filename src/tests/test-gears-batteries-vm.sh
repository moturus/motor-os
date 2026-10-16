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
[[ "$OUTPUT" == '{"decision":"deny",'* && "$OUTPUT" == *"invalid permission call"* ]] ||
  { echo "unexpected malformed-call reply: $OUTPUT" >&2; exit 1; }
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
[[ "$OUTPUT" == *"read_file: enabled (config)"* && "$OUTPUT" == *"check: enabled (config)"* &&
  "$OUTPUT" != *"gears:"* ]] || { echo "unexpected /tools output: $OUTPUT" >&2; exit 1; }
echo "test-gears-batteries-vm.sh ALL PASS"
