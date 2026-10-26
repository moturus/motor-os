#!/bin/bash
# Matched guest-client/host-server measurements, with one fresh VM per mode.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
WD="$ROOT_DIR/src/tests"
BUILD=release
mode="${1:-}"
case "$mode" in physical|plain|wireguard) ;; *) echo "usage: $0 physical|plain|wireguard" >&2; exit 2 ;; esac
make -C "$ROOT_DIR" -j"$(nproc)" BUILD=release main.img systest rnetbench
cargo build --release --locked --manifest-path "$ROOT_DIR/src/tests/wg-peer/Cargo.toml"
host_binary="${WG_RNETBENCH_BINARY:-$ROOT_DIR/build/host-tests/rnetbench/release/rnetbench}"
if [ "$mode" = physical ] && [ -z "${WG_RNETBENCH_BINARY:-}" ]; then
  CARGO_TARGET_DIR="$ROOT_DIR/build/host-tests/rnetbench" cargo build --release --locked \
    --manifest-path "$ROOT_DIR/src/bin/rnetbench/Cargo.toml"
fi
work="$(mktemp -d /tmp/bench-wireguard.XXXXXX)"
TEST_BIN=/user/tmp/wg-bench
VMM_PID=""
host_pid=""
. "$WD/vm-console-filter.sh"
. "$WD/vm-test-boot.sh"
. "$WD/vm-cleanup.sh"
. "$WD/test-wireguard.sh"
fail() { echo "$*" >&2; exit 1; }
cleanup() {
  local status=$?
  trap - EXIT
  if [ -n "$host_pid" ]; then
    kill "$host_pid" 2>/dev/null || true
    wait "$host_pid" 2>/dev/null || true
  fi
  stop_vm "$VMM_PID"
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
test_vm_configure_ssh
echo "WireGuard benchmark: mode=$mode cpus=${MOTO_SMP:-4} memory=${MOTO_MEMORY_MIB:-1024} MiB"
start_test_vm "$ROOT_DIR/vm_images/release/run-qemu.sh" QEMU "$work/console.log" -snapshot
printf 'mkdir %s\n' "$TEST_BIN" > "$work/upload"
for binary in systest rnetbench; do
  printf 'put %s %s/%s\nchmod 700 %s/%s\n' \
    "$ROOT_DIR/build/bin/release/$binary" "$TEST_BIN" "$binary" \
    "$TEST_BIN" "$binary" >> "$work/upload"
done
sftp -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" \
  -i "$WD/test.key" -b "$work/upload" motor@192.168.4.2
if [ "$mode" = physical ]; then
  coproc WG_BENCH_SERVER { exec "$host_binary" --server --port 40000; }
  host_pid="$WG_BENCH_SERVER_PID"
  exec {host_output}<&"${WG_BENCH_SERVER[0]}"
  IFS= read -r -t 5 banner <&"$host_output" || fail "rnetbench server did not become ready"
  case "$banner" in *"listening on 0.0.0.0:40000"*) ;; *) fail "unexpected server banner: $banner" ;; esac
  # Drain server output throughout the run so its pipe cannot stall a phase.
  cat <&"$host_output" &
  reader_pid="$!"
  vm_ssh "$TEST_BIN/systest wireguard-measure 0 192.168.4.1:40000"
  kill "$host_pid"
  wait "$host_pid" || [ "$?" = 143 ]
  host_pid=""
  wait "$reader_pid"
else
  role=guest
  [ "$mode" != plain ] || role=plain
  WG_BENCHMARK=1 test_wireguard_case ipv4 "$role"
fi
