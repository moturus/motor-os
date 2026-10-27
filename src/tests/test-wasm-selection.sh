#!/usr/bin/env bash
# Exercise suite selection and timeout forwarding without building or booting.
set -euo pipefail
WD="$(cd "$(dirname "$0")" && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
mkdir -p "$temporary/src/tests" "$temporary/bin"
cp "$WD/test-wasm.sh" "$temporary/src/tests/"
export WASM_SELECTION_LOG="$temporary/calls"
export PATH="$temporary/bin:$PATH"
export WASM_TEST_TIMED=0
for tool in make cargo timeout; do
  cat > "$temporary/bin/$tool" <<'SH'
#!/usr/bin/env bash
printf '%s %s\n' "${0##*/}" "$*" >> "$WASM_SELECTION_LOG"
SH
  chmod +x "$temporary/bin/$tool"
done
runner="$temporary/src/tests/test-wasm.sh"
fail() { echo "test-wasm-selection: $*" >&2; exit 1; }
for selection in default both javy wasmtime; do
  : > "$WASM_SELECTION_LOG"
  args=()
  [ "$selection" = default ] || args=(--suite "$selection")
  "$runner" --prepare --vm wasm:224 --vm dev:256 "${args[@]}"
  expected=(javy-smoke wasmtime-smoke)
  case "$selection" in
    javy) expected=(javy-smoke);;
    wasmtime) expected=(wasmtime-smoke);;
  esac
  mapfile -t built < <(sed -n 's|^cargo .*src/tests/\([^/]*\)/Cargo.toml$|\1|p' "$WASM_SELECTION_LOG")
  [ "${built[*]}" = "${expected[*]}" ] || fail "$selection built ${built[*]}"
  grep -q '^make .* wasm.img dev.img BUILD=release ' "$WASM_SELECTION_LOG" ||
    fail "$selection lost image selection"

  for name in "${expected[@]}"; do
    dir="$temporary/build/obj/release/$name/x86_64-unknown-motor/release"
    mkdir -p "$dir"
    cp "$temporary/bin/cargo" "$dir/$name"
  done
  : > "$WASM_SELECTION_LOG"
  "$runner" --vm wasm:224 --vmm chv "${args[@]}"
  mode="$selection"
  [ "$mode" != default ] || mode=both
  [ "$(cat "$WASM_SELECTION_LOG")" = \
    "timeout 600s env WASM_TEST_TIMED=1 $runner --suite $mode --vmm chv --vm wasm:224" ] ||
    fail "$selection was not forwarded through timeout"
done
: > "$WASM_SELECTION_LOG"
status=0
"$runner" --prepare --suite missing > "$temporary/invalid.log" 2>&1 || status=$?
[ "$status" = 2 ] && [ ! -s "$WASM_SELECTION_LOG" ] || fail "invalid suite started work"
echo "test-wasm-selection PASS"
