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
"$runner" --services --suite wasmtime --vm wasm:224 --vmm chv
[ "$(cat "$WASM_SELECTION_LOG")" = \
  "timeout 600s env WASM_TEST_TIMED=1 $runner --suite wasmtime --vmm chv --services --vm wasm:224" ] ||
  fail 'service mode was not forwarded through timeout'
cat > "$temporary/src/tests/wasm-service-images.sh" <<'SH'
prepare_wasm_service_images() { printf 'services %s\n' "$*" >> "$WASM_SELECTION_LOG"; }
SH
: > "$WASM_SELECTION_LOG"
"$runner" --prepare --services --suite wasmtime --vm wasm:224 --vm wasm:256 --vm dev:256
grep -qxF "services $temporary wasm dev" "$WASM_SELECTION_LOG" || fail 'service images lost VM selection'
: > "$WASM_SELECTION_LOG"
status=0
"$runner" --prepare --services --suite javy > "$temporary/invalid-service.log" 2>&1 || status=$?
[ "$status" = 2 ] && [ ! -s "$WASM_SELECTION_LOG" ] || fail 'invalid service suite started work'
: > "$WASM_SELECTION_LOG"
status=0
"$runner" --prepare --suite missing > "$temporary/invalid.log" 2>&1 || status=$?
[ "$status" = 2 ] && [ ! -s "$WASM_SELECTION_LOG" ] || fail "invalid suite started work"

# Exercise the real test-image builder: every generated image must carry the
# System role launcher and its fixtures, without changing the production config.
cp "$WD/wasm-service-images.sh" "$temporary/src/tests/"
mkdir -p "$temporary/src/imager" "$temporary/img_files/motor-os/system/cfg" \
  "$temporary/build/obj/release/imager/release" \
  "$temporary/build/assembly/tests/wasmtime" "$temporary/build/assembly/tests/javy"
cp "$WD/../imager/"motor-os-{wasm,dev}.yaml "$temporary/src/imager/"
printf 'tty:/system/services/sys-tty\n' > "$temporary/img_files/motor-os/system/cfg/sys-init.cfg"
cp "$temporary/bin/cargo" "$temporary/build/obj/release/imager/release/imager"
for file in p2_cli_serve_hello_world.cwasm p3_cli_serve_hello_world.cwasm \
  p2_cli_serve_hello_world.wasm engine-tests; do
  printf 'fixture %s\n' "$file" > "$temporary/build/assembly/tests/wasmtime/$file"
done
printf 'plugin fixture\n' > "$temporary/build/assembly/tests/javy/plugin-p1.wasm"
: > "$WASM_SELECTION_LOG"
"$runner" --prepare --services --suite wasmtime --vm wasm:224 --vm dev:256
overlay="$temporary/build/wasm-service-images/overlay"
role_caps="$(sed -n 's|^svc:\([0-9]*\):/none/wasm-services/wasmtime-smoke --roles$|\1|p' \
  "$overlay/system/cfg/sys-init.cfg")"
[ -n "$role_caps" ] && [ "$((role_caps & 1))" = 1 ] || fail 'role launcher lacks System authority'
cmp "$temporary/build/obj/release/wasmtime-smoke/x86_64-unknown-motor/release/wasmtime-smoke" \
  "$overlay/none/wasm-services/wasmtime-smoke"
for file in "$temporary/build/assembly/tests/wasmtime/"* \
  "$temporary/build/assembly/tests/javy/plugin-p1.wasm"; do
  cmp "$file" "$overlay/none/wasm-services/${file##*/}"
done
for variant in wasm dev; do
  config="$temporary/build/wasm-service-images/$variant.yaml"
  grep -qF "  - \"$overlay\"" "$config" || fail "$variant lost the test overlay"
  grep -qF "motor-os-$variant-wasm-services.qcow2" "$config" || fail "$variant lost image isolation"
  grep -qxF "imager $temporary release $config" "$WASM_SELECTION_LOG" || fail "$variant was not built"
done
[ "$(cat "$temporary/img_files/motor-os/system/cfg/sys-init.cfg")" = \
  'tty:/system/services/sys-tty' ] || fail 'test services changed the production config'
echo "test-wasm-selection PASS"
