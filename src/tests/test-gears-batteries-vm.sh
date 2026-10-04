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
EVENT='{"protocol_version":1,"event":"permission","workspace":"/user","session":{"id":"fixture"}}'
OUTPUT="$(printf '%s' "$EVENT" | "${SSH[@]}" /devtools/bin/gears-batteries hook)"
[ "$OUTPUT" = '{"decision":"deny"}' ]
if printf '{}' | "${SSH[@]}" /devtools/bin/gears-batteries hook; then
  echo "batteries accepted malformed hook input" >&2
  exit 1
fi
echo "test-gears-batteries-vm.sh ALL PASS"
