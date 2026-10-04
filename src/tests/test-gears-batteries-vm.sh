#!/bin/bash
# The installed batteries binary against native command-hook input.
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
echo "test-gears-batteries-vm.sh ALL PASS"
