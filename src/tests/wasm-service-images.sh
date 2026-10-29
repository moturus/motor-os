#!/usr/bin/env bash
# Sourced by test-wasm.sh: add services and a role probe to separate test images.
prepare_wasm_service_images() {
  local root="$1" variant overlay config image imager
  shift
  imager="$root/build/obj/release/imager/release/imager"
  overlay="$root/build/wasm-service-images/overlay"
  mkdir -p "$overlay/system/cfg" "$overlay/none/wasm-services"
  cp "$root/img_files/motor-os/system/cfg/sys-init.cfg" "$overlay/system/cfg/"
  cat >> "$overlay/system/cfg/sys-init.cfg" <<'EOF'

# Test-only Wasmtime services: decimal 256 is CAP_NET, without CAP_LOG.
svc:256:/devtools/bin/wasmtime-rt serve --allow-precompiled -S cli --addr 127.0.0.1:18180 --shutdown-addr 127.0.0.1:18181 --max-concurrent-requests 2 /none/wasm-services/p2_cli_serve_hello_world.cwasm
svc:256:/devtools/bin/wasmtime-rt serve --allow-precompiled -W component-model-async -S p3,cli --addr 127.0.0.1:18182 --shutdown-addr 127.0.0.1:18183 --max-concurrent-requests 2 /none/wasm-services/p3_cli_serve_hello_world.cwasm

# System launcher: SYS | SPAWN | LOG | INTERACTIVE | NET | FS_WRITE (0x34d).
svc:845:/none/wasm-services/wasmtime-smoke --roles
EOF
  cp "$root/build/assembly/tests/wasmtime/"p{2,3}_cli_serve_hello_world.cwasm \
    "$overlay/none/wasm-services/"
  cp "$root/build/assembly/tests/wasmtime/p2_cli_serve_hello_world.wasm" \
    "$root/build/assembly/tests/wasmtime/engine-tests" \
    "$root/build/assembly/tests/javy/plugin-p1.wasm" \
    "$root/build/obj/release/wasmtime-smoke/x86_64-unknown-motor/release/wasmtime-smoke" \
    "$overlay/none/wasm-services/"
  for variant in "$@"; do
    config="$root/build/wasm-service-images/$variant.yaml"
    image="motor-os-$variant-wasm-services.qcow2"
    # Both production recipes finish their static overlays at assembly_dirs.
    # Add ours last, so the test configuration replaces only sys-init.cfg.
    awk -v overlay="$overlay" -v image="$image" \
      -v policy="$root/src/imager/motor-os-permissions.yaml" '
      /^permission_policy:/ {print "permission_policy: \"" policy "\""; next}
      /^img_name:/ {print "img_name: \"" image "\""; next}
      /^assembly_dirs:/ {print "  - \"" overlay "\""; added++}
      {print}
      END {if (added != 1) exit 1}
    ' "$root/src/imager/motor-os-$variant.yaml" > "$config"
    flock "$root/build/imager.lock" env MOTOR_ASSEMBLY_IMAGE_ROOT="$root/build/assembly/images" \
      "$imager" "$root" release "$config"
  done
}
