# Native stdlib error propagation. Sourced by full-test.sh.
test_stdio_errors() {
  local binary="${1:-}" temporary="" status=0
  local guest="$TEST_TMP/stdio-errors"
  if [ -z "$binary" ]; then
    temporary="$(mktemp -d)"
    binary="$temporary/stdio-errors"
    rustc --edition=2024 --target x86_64-unknown-motor -D warnings \
      "$WD/stdio-errors.rs" -o "$binary" || {
      rm -rf "$temporary"
      return 1
    }
  fi
  printf 'put "%s" "%s"\n' "$binary" "$guest" |
    sftp -b - -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
      -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" \
      -i "$WD/test.key" motor@192.168.4.2 || status=$?
  if [ "$status" -eq 0 ]; then
    vm_ssh "TMPDIR=$TEST_TMP $guest" || status=$?
    vm_ssh "/system/bin/rm $guest" || status=$?
  fi
  if [ -n "$temporary" ]; then rm -rf "$temporary"; fi
  return "$status"
}
