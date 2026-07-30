#!/bin/bash
#
# Motor OS multi-subsystem stress soak.
#
# Boots ONE long-lived VM and drives it with concurrent, continuously-looping
# workloads spanning the VM-side coverage in full-test.sh (fs, DNS/networking,
# tokio/mio, process/stdio, rmux, russhd), while a foreground monitor scans for
# crash markers, detects stalls, and -- on the first anomaly -- captures full
# forensics (ps / stats x2 / mdbg
# print-stacks / qemu-monitor vCPU dump / console tail) BEFORE tearing the VM
# down.
#
# Usage:
#   bash src/tests/stress-soak.sh [debug|release] [duration-sec] [run-tag]
#
# Environment overrides:
#   MOTOR_STRESS_OUT   base dir for run output (default /tmp/motor-stress).
#   MOTO_SMP           guest vCPU count (default 4). Read by run-qemu.sh.
#   MOTO_CPU_AFFINITY  host cpuset to pin qemu to via taskset (default: no pin).
#                      Read by run-qemu.sh; each run stamps its config as the
#                      first console.log line ("run-qemu: -smp N ...").
#
# The bugs this soak hunts are client<->sys-io concurrency races (io_channel
# ring/page-bitmap double-free; net-path lost-wake freeze). The 4-vCPU-on-a-
# 24-core KVM default gives each vCPU a near-dedicated core = least-perturbed
# timing, so races are rare. Vary the CPU config to flush them out (x86+KVM is
# strong-ordered/TSO, so this fuzzes INTERLEAVINGS, not memory reorderings):
#
#   # Oversubscribe: 8 vCPUs multiplexed onto 2 host cores (4:1) -- widens the
#   # scheduling windows lost-wakes and the ring race need (sharpest trigger).
#   MOTO_SMP=8 MOTO_CPU_AFFINITY=0,1 \
#     bash src/tests/stress-soak.sh release 7200 oversub1
#
#   # Classifier: 1 vCPU kills true parallelism -- a bug that still fires is a
#   # logic/ordering bug, not a cross-core data race.
#   MOTO_SMP=1 bash src/tests/stress-soak.sh release 3600 smp1
#
#   # More contention, still 1:1 on the 24-core host (stays fast):
#   MOTO_SMP=16 bash src/tests/stress-soak.sh release 7200 smp16
#
# Paths are derived from this script's location ($ROOT = repo root), so it can
# be run from anywhere. Run output goes OUTSIDE the repo (see MOTOR_STRESS_OUT)
# so a soak never dirties the working tree.
#
# NOTE: run this via `bash stress-soak.sh` in the BACKGROUND. Its own command
# line is "bash .../stress-soak.sh", so the char-class pkill patterns below do
# not self-match (an inline command containing "qemu-system"/"run-qemu" would
# SIGKILL its own wrapper).
set -u

# ------------------------------------------------------------------ config
BUILD="${1:-release}"
DURATION="${2:-7200}"
RUN_TAG="${3:-$(date +%m%d-%H%M%S)}"

case "$BUILD" in debug|release) ;; *) echo "build must be debug or release" >&2; exit 2 ;; esac
[[ "$DURATION" =~ ^[1-9][0-9]*$ ]] ||
  { echo "duration-sec must be a positive integer" >&2; exit 2; }
[[ "$RUN_TAG" =~ ^[A-Za-z0-9._-]+$ ]] ||
  { echo "run-tag may contain only letters, digits, '.', '_', and '-'" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"        # repo root: src/tests -> ../..
OUT_BASE="${MOTOR_STRESS_OUT:-/tmp/motor-stress}"
OUT="$OUT_BASE/run-$RUN_TAG"
mkdir -p "$OUT_BASE"
mkdir "$OUT" || { echo "run output already exists: $OUT" >&2; exit 2; }

VM_IP=192.168.4.2
SSH_PORT=2222
KEY="$ROOT/src/tests/test.key"
IMG_DIR="$ROOT/vm_images/$BUILD"
HOST_RNET="$ROOT/src/bin/rnetbench/target/release/rnetbench"
# qemu monitor over TCP: a unix-socket path under a deep scratch dir exceeds the
# 108-byte sun_path limit, and TCP is what the watchdog settled on anyway.
MON_HOST=127.0.0.1
MON_PORT=45454
CONSOLE="$OUT/console.log"

RNET_PORT=40000
HTTP_STD_PORT=8080
HTTP_AXUM_PORT=8081
SERVE_DIR=/www

MON_INTERVAL=20          # monitor tick, seconds
LIVENESS_FAILS_MAX=3     # consecutive ssh liveness failures => vm-unreachable

echo "building host-side rnetbench (release)"
(cd "$ROOT/src/bin/rnetbench" && cargo build --release) ||
  { echo "failed to build host-side rnetbench" >&2; exit 1; }

SSH_OPTS=(-F /dev/null -p "$SSH_PORT" -o IdentitiesOnly=yes
          -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o BatchMode=yes -i "$KEY")
# short-timeout ssh for control/monitor probes
vssh() { timeout "${VSSH_TMO:-20}" ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 motor@"$VM_IP" "$@"; }

log() { echo "[$(date +%H:%M:%S) +$(( $(date +%s) - START ))s] $*" | tee -a "$OUT/soak.log"; }

START=$(date +%s)
SOAK_START=""
SOAK_END=""
declare -a WL_PIDS=()
declare -a WL_NAMES=()
declare -a SERVER_PIDS=()
STOP_REASON=""
DNS_RESOLVER_SSH_PID=""
QEMU_WRAPPER_PID=""

# Dry-run (STRESS_DRYRUN=1): resolve every derived path through the real config
# above and confirm the host-side prerequisites exist, then exit before booting.
# This validates the script is runnable from any working directory (paths derive
# from $SCRIPT_DIR, not $PWD) without paying for a full soak. Placed before the
# EXIT trap is installed, so exiting here does not run teardown.
if [ "${STRESS_DRYRUN:-0}" = 1 ]; then
  echo "stress-soak dry-run:"
  echo "  invoked as : ${BASH_SOURCE[0]}"
  echo "  cwd        : $(pwd)"
  echo "  SCRIPT_DIR : $SCRIPT_DIR"
  echo "  ROOT       : $ROOT"
  echo "  KEY        : $KEY"
  echo "  IMG_DIR    : $IMG_DIR"
  echo "  HOST_RNET  : $HOST_RNET"
  rc=0
  [ -f "$KEY" ]                 && echo "  [ok]      ssh key present"        || { echo "  [MISSING] ssh key"; rc=1; }
  [ -x "$IMG_DIR/run-qemu.sh" ] && echo "  [ok]      run-qemu.sh present"    || { echo "  [MISSING] $IMG_DIR/run-qemu.sh (run: make BUILD=$BUILD all)"; rc=1; }
  [ -x "$HOST_RNET" ]           && echo "  [ok]      host rnetbench present" || { echo "  [MISSING] $HOST_RNET"; rc=1; }
  [ "$rc" = 0 ] && echo "  DRY-RUN OK" || echo "  DRY-RUN FOUND MISSING PREREQS"
  exit "$rc"
fi

# ------------------------------------------------------------------ forensics
mon_cmd() { { printf '%s\n' "$1"; sleep 1; } | timeout 8 nc "$MON_HOST" "$MON_PORT" 2>/dev/null; }

capture_forensics() {
  local reason="$1"; local f="$OUT/ANOMALY.txt"
  {
    echo "================================================================"
    echo "ANOMALY: $reason"
    echo "at $(date) (soak uptime $(( $(date +%s) - START ))s)"
    echo "================================================================"
    echo "--- host: qemu alive? ---"; pgrep -af 'qemu-system-x86_6[4]|[r]un-qemu.sh' 2>&1
    echo "--- per-workload stat files ---"; for s in "$OUT"/*.stat; do [ -f "$s" ] && { echo "  $(basename "$s"): $(cat "$s")"; }; done
    echo "--- ssh: /bin/ps ---"; VSSH_TMO=25 vssh /bin/ps 2>&1
    echo "--- ssh: stats get 1 (kernel), pass 1 ---"; VSSH_TMO=25 vssh /bin/stats get 1 2>&1
    echo "--- ssh: stats get 2 (net), pass 1 ---";    VSSH_TMO=25 vssh /bin/stats get 2 2>&1
    sleep 3
    echo "--- ssh: stats get 1 (kernel), pass 2 (3s later; counters moving?) ---"; VSSH_TMO=25 vssh /bin/stats get 1 2>&1
    echo "--- ssh: stats get 2 (net), pass 2 ---";    VSSH_TMO=25 vssh /bin/stats get 2 2>&1
    echo "--- mdbg print-stacks for every listed pid ---"
    local pids
    pids="$(VSSH_TMO=25 vssh /bin/ps 2>/dev/null | awk 'NR>1{gsub(/\*/,"",$1); if($1 ~ /^[0-9]+$/) print $1}')"
    for p in $pids; do
      echo "### print-stacks pid $p ###"
      VSSH_TMO=30 vssh /sys/mdbg print-stacks "$p" 2>&1
    done
    echo "--- qemu monitor: info cpus (pass 1) ---"; mon_cmd "info cpus"
    echo "--- qemu monitor: info registers -a (pass 1) ---"; mon_cmd "info registers -a"
    sleep 3
    echo "--- qemu monitor: info cpus (pass 2; vCPUs progressing?) ---"; mon_cmd "info cpus"
    echo "--- console tail (last 120 lines) ---"; tail -120 "$CONSOLE" 2>/dev/null
  } >> "$f" 2>&1
  log "FORENSICS captured -> $f  (reason: $reason)"
}

# ------------------------------------------------------------------ teardown
teardown() {
  local load_time=0
  set +e
  [ -n "$SOAK_END" ] || SOAK_END=$(date +%s)
  [ -z "$SOAK_START" ] || load_time=$(( SOAK_END - SOAK_START ))
  log "teardown: reason='${STOP_REASON:-duration-elapsed}'"
  # Kill only processes created by this run. Workload descendants are stopped
  # before their loop shell so none can be orphaned and hit a later VM.
  for p in "${WL_PIDS[@]}"; do
    pkill -TERM -P "$p" 2>/dev/null
    kill "$p" 2>/dev/null
  done
  for p in "${SERVER_PIDS[@]}"; do kill "$p" 2>/dev/null; done
  # best-effort graceful VM shutdown
  VSSH_TMO=15 vssh shutdown 2>/dev/null
  sleep 2
  if [ -n "$DNS_RESOLVER_SSH_PID" ]; then
    kill "$DNS_RESOLVER_SSH_PID" 2>/dev/null
    wait "$DNS_RESOLVER_SSH_PID" 2>/dev/null
  fi
  if kill -0 "$QEMU_WRAPPER_PID" 2>/dev/null; then
    kill -TERM -- "-$QEMU_WRAPPER_PID" 2>/dev/null
  fi
  sleep 2
  if kill -0 "$QEMU_WRAPPER_PID" 2>/dev/null; then
    kill -KILL -- "-$QEMU_WRAPPER_PID" 2>/dev/null
  fi
  wait "$QEMU_WRAPPER_PID" 2>/dev/null
  # final summary
  {
    echo "==== STRESS SOAK SUMMARY ($RUN_TAG, build=$BUILD) ===="
    echo "stress target   : ${DURATION}s ; actual load time : ${load_time}s"
    echo "result          : ${STOP_REASON:-CLEAN (duration elapsed, no anomaly)}"
    echo "--- per-workload totals ---"
    for s in "$OUT"/*.stat; do [ -f "$s" ] && printf '  %-12s %s\n' "$(basename "${s%.stat}")" "$(cat "$s")"; done
    [ -f "$OUT/ANOMALY.txt" ] && echo "ANOMALY forensics: $OUT/ANOMALY.txt"
  } | tee "$OUT/RESULT.txt"
  log "teardown complete."
}
trap teardown EXIT
trap 'STOP_REASON="INTERRUPTED: SIGINT"; exit 130' INT
trap 'STOP_REASON="INTERRUPTED: SIGTERM"; exit 143' TERM
trap 'STOP_REASON="INTERRUPTED: SIGHUP"; exit 129' HUP

# ------------------------------------------------------------------ boot
log "=== stress soak start: build=$BUILD duration=${DURATION}s out=$OUT ==="
[ -x "$IMG_DIR/run-qemu.sh" ] || { STOP_REASON="BOOT-FAILED: no image at $IMG_DIR (run: make all BUILD=$BUILD)"; log "$STOP_REASON"; exit 1; }
[ -x "$HOST_RNET" ] || { STOP_REASON="BOOT-FAILED: missing $HOST_RNET"; log "$STOP_REASON"; exit 1; }
chmod 600 "$KEY"

log "booting VM ($IMG_DIR/run-qemu.sh) with TCP monitor $MON_HOST:$MON_PORT"
setsid "$IMG_DIR/run-qemu.sh" -monitor "tcp:$MON_HOST:$MON_PORT,server,nowait" &> "$CONSOLE" &
QEMU_WRAPPER_PID=$!

log "waiting for ssh ..."
up=0
for _ in $(seq 1 40); do
  if ! kill -0 "$QEMU_WRAPPER_PID" 2>/dev/null; then
    STOP_REASON="BOOT-FAILED: qemu exited during boot"; log "$STOP_REASON"
    echo "---- console.log ----" | tee -a "$OUT/soak.log"; tail -20 "$CONSOLE" | tee -a "$OUT/soak.log"
    exit 1
  fi
  if timeout 12 ssh "${SSH_OPTS[@]}" -o ConnectTimeout=8 -o ConnectionAttempts=1 \
       motor@"$VM_IP" /bin/echo alive >/dev/null 2>&1; then up=1; break; fi
  sleep 3
done
[ "$up" = 1 ] || { STOP_REASON="BOOT-FAILED: VM never reachable over ssh"; log "$STOP_REASON"; exit 1; }
log "VM is up."

# ------------------------------------------------------------------ VM gate
# Run every guest-side assertion from full-test.sh before adding stress load.
# Host-only cargo/rmux tests and the build itself deliberately remain outside
# this harness.
GATE_LOG="$OUT/vm-gate.log"

gate_fail() {
  STOP_REASON="VALIDATION-FAILED: $*"
  log "$STOP_REASON"
  capture_forensics "$STOP_REASON"
  exit 2
}

gate_ssh() { # timeout description command...
  local tmo="$1" desc="$2" rc
  shift 2
  log "VM gate: $desc"
  timeout "$tmo" ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 motor@"$VM_IP" "$@" \
    2>&1 | tee -a "$GATE_LOG"
  rc=${PIPESTATUS[0]}
  [ "$rc" -eq 0 ] || gate_fail "$desc (rc=$rc)"
}

EXTERNAL_ICMP=1
ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 || EXTERNAL_ICMP=0

gate_ping_external() {
  local host="$1" output rc=0
  output="$(timeout 30 ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 \
    motor@"$VM_IP" /bin/ping -c 1 "$host" 2>&1)" || rc=$?
  printf '%s\n' "$output" | tee -a "$GATE_LOG"
  [ "$rc" -eq 0 ] && return
  if [ "$EXTERNAL_ICMP" = 0 ]; then
    case "$output" in
      *"Request timeout"* | *"NotConnected"*)
        log "VM gate: '$host' resolved; host has no external ICMP"
        return
        ;;
    esac
  fi
  gate_fail "ping '$host' failed (rc=$rc)"
}

gate_expect_ping_error() {
  local host="$1" expected="$2" output rc=0
  output="$(timeout 30 ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 \
    motor@"$VM_IP" /bin/ping -c 1 "$host" 2>&1)" || rc=$?
  printf '%s\n' "$output" | tee -a "$GATE_LOG"
  [ "$rc" -ne 0 ] || gate_fail "ping unexpectedly resolved '$host'"
  case "$output" in
    *"$expected"*) ;;
    *) gate_fail "ping '$host' did not report '$expected'" ;;
  esac
}

gate_wait_for_ping_error() {
  local host="$1" expected="$2" output="" rc
  for _ in $(seq 1 20); do
    rc=0
    output="$(timeout 30 ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 \
      motor@"$VM_IP" /bin/ping -c 1 "$host" 2>&1)" || rc=$?
    [ "$rc" -ne 0 ] || gate_fail "ping unexpectedly resolved '$host'"
    case "$output" in
      *"$expected"*)
        printf '%s\n' "$output" | tee -a "$GATE_LOG"
        return
        ;;
    esac
    sleep 0.1
  done
  printf '%s\n' "$output" | tee -a "$GATE_LOG"
  gate_fail "ping '$host' did not settle on '$expected'"
}

gate_udp_socket_count() {
  local output="" count="" last_count=""
  GATE_UDP_SOCKET_COUNT=""
  for _ in $(seq 1 20); do
    count=""
    if output="$(vssh /bin/stats get 2 2>&1)"; then
      count="$(printf '%s\n' "$output" |
        awk '$2 == "net.udp_sockets" { print $3 }')"
      [ "$count" = 0 ] && { GATE_UDP_SOCKET_COUNT=0; return; }
      [ -z "$count" ] || last_count="$count"
    fi
    sleep 0.1
  done
  [ -n "$last_count" ] && { GATE_UDP_SOCKET_COUNT="$last_count"; return; }
  printf '%s\n' "$output" >>"$GATE_LOG"
  gate_fail "stats did not report net.udp_sockets"
}

gate_rmux_copy_keys() {
  printf 'for I in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do echo LINE$I; done\n'
  sleep 5
  printf '\001[g'
  sleep 2
  printf 'q'
  sleep 1
  printf 'exit\n'
}

log "running mandatory VM-side full-test gate"
gate_ssh 30 "ping 127.0.0.1" /bin/ping -c 1 127.0.0.1
gate_ssh 30 "ping localhost" /bin/ping -c 1 localhost
gate_ssh 60 "DNS resolver self-test" /sys/dns-resolver --self-test
gate_ping_external google.com
gate_expect_ping_error does-not-exist.motor.invalid NotFound
gate_udp_socket_count
[ "$GATE_UDP_SOCKET_COUNT" = 0 ] ||
  gate_fail "DNS tests left $GATE_UDP_SOCKET_COUNT UDP socket(s)"

resolver_pid="$(vssh /bin/ps |
  awk '$NF == "/sys/dns-resolver" { gsub(/\*/, "", $1); print $1; exit }')"
[ -n "$resolver_pid" ] || gate_fail "could not find dns-resolver"
gate_ssh 30 "stop DNS resolver" /bin/kill "$resolver_pid"
gate_ssh 30 "numeric ping without DNS" /bin/ping -c 1 127.0.0.1
gate_wait_for_ping_error google.com NotConnected
ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 motor@"$VM_IP" /sys/dns-resolver \
  >>"$GATE_LOG" 2>&1 &
DNS_RESOLVER_SSH_PID=$!
resolver_restarted=0
for _ in $(seq 1 20); do
  if vssh /sys/dns-resolver --self-test >>"$GATE_LOG" 2>&1; then
    resolver_restarted=1
    break
  fi
  sleep 0.1
done
[ "$resolver_restarted" = 1 ] || gate_fail "dns-resolver did not restart"
gate_ping_external google.com
gate_udp_socket_count
[ "$GATE_UDP_SOCKET_COUNT" = 0 ] ||
  gate_fail "restarted DNS left $GATE_UDP_SOCKET_COUNT UDP socket(s)"

log "VM gate: systest"
timeout 900 ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 motor@"$VM_IP" \
  /sys/tests/systest 2>&1 | tee -a "$GATE_LOG" "$OUT/gate-systest.log"
gate_rc=${PIPESTATUS[0]}
[ "$gate_rc" -eq 0 ] || gate_fail "systest (rc=$gate_rc)"
[ "$(tail -n 1 "$OUT/gate-systest.log")" = PASS ] ||
  gate_fail "systest did not finish with PASS"

out="$(printf 'relay-smoke\n' |
  vssh "/bin/rush -c 'read X && echo GOT=\$X'")"
[ "$out" = "GOT=relay-smoke" ] || gate_fail "stdin relay smoke: got '$out'"
out="$(vssh "/bin/rush -c 'echo tail-smoke'")"
[ "$out" = tail-smoke ] || gate_fail "relay tail smoke: got '$out'"

out="$(printf 'echo $((21+21))\nexit\n' | vssh /bin/rmux 2>&1)"
case "$out" in *42*) ;; *) gate_fail "rmux command output missing" ;; esac
case "$out" in *rush*) ;; *) gate_fail "rmux shell was not interactive" ;; esac
case "$out" in *$'\033'"[?1049h"*) ;; *) gate_fail "rmux did not take alternate screen" ;; esac
case "$out" in *$'\033'"[?1049l"*) ;; *) gate_fail "rmux did not restore screen" ;; esac

out="$(gate_rmux_copy_keys | vssh /bin/rmux 2>&1)"
indicator="$(printf '%s' "$out" |
  grep -ao 'copy mode -- \[[0-9]*/[0-9]*\]' | tail -1)"
[ -n "$indicator" ] || gate_fail "rmux copy mode did not open"
counts="${indicator##*[}"; above="${counts%%/*}"
total="${counts%]}"; total="${total##*/}"
[ "$total" -gt 0 ] || gate_fail "rmux pane kept no scrollback"
[ "$above" = "$total" ] || gate_fail "rmux copy mode did not reach oldest line"

log "VM gate: SFTP integration"
RUSSHD_HOST="$VM_IP" RUSSHD_PORT="$SSH_PORT" RUSSHD_KEY="$KEY" \
  timeout 300 "$SCRIPT_DIR/test-sftp.sh" 2>&1 | tee -a "$GATE_LOG"
gate_rc=${PIPESTATUS[0]}
[ "$gate_rc" -eq 0 ] || gate_fail "SFTP integration (rc=$gate_rc)"
gate_ssh 300 "mio-test" /sys/tests/mio-test
gate_ssh 300 "tokio-tests" /sys/tests/tokio-tests
log "mandatory VM-side full-test gate passed"

# ------------------------------------------------------------------ binaries + fetch target (from src/imager/motor-os.yaml)
RNETBENCH=/sys/tests/rnetbench
TOKIO=/sys/tests/tokio-tests
MIO=/sys/tests/mio-test
HTTPD=/bin/httpd
HTTPD_AXUM=/bin/httpd-axum
log "binaries: httpd=$HTTPD httpd-axum=$HTTPD_AXUM"

# httpd/-axum serve --dir /www; every GET reads a static file from fs.
FETCH_URLPATH="/motor-os-256.png"    # 108776-byte asset => real fs read per GET
log "http fetch target: $SERVE_DIR$FETCH_URLPATH"

# ------------------------------------------------------------------ start servers (one persistent ssh each)
log "starting in-VM servers"
ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 motor@"$VM_IP" "$RNETBENCH --server -p $RNET_PORT" \
    >"$OUT/srv-rnetbench.log" 2>&1 &
SERVER_PIDS+=($!)
spawn_server() { # tag cmd
  local tag="$1" cmd="$2"
  ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 motor@"$VM_IP" "$cmd" \
    >"$OUT/srv-$tag.log" 2>&1 &
  SERVER_PIDS+=($!)
}
spawn_server httpd      "$HTTPD --addr $VM_IP:$HTTP_STD_PORT --dir $SERVE_DIR"
spawn_server httpd-axum "$HTTPD_AXUM --addr $VM_IP:$HTTP_AXUM_PORT --dir $SERVE_DIR"
sleep 6

FETCH_SIZE_STD=0; FETCH_SIZE_AXUM=0
code=$(curl -s -o /dev/null -m 15 -w '%{http_code}' "http://$VM_IP:$HTTP_STD_PORT$FETCH_URLPATH" 2>/dev/null)
if [ "$code" = 200 ]; then
  FETCH_SIZE_STD=$(curl -s -o /dev/null -m 20 -w '%{size_download}' "http://$VM_IP:$HTTP_STD_PORT$FETCH_URLPATH" 2>/dev/null)
  log "httpd(std) OK, fetch size=$FETCH_SIZE_STD"
else gate_fail "httpd(std) did not start (code='$code')"; fi
code=$(curl -s -o /dev/null -m 15 -w '%{http_code}' "http://$VM_IP:$HTTP_AXUM_PORT$FETCH_URLPATH" 2>/dev/null)
if [ "$code" = 200 ]; then
  FETCH_SIZE_AXUM=$(curl -s -o /dev/null -m 20 -w '%{size_download}' "http://$VM_IP:$HTTP_AXUM_PORT$FETCH_URLPATH" 2>/dev/null)
  log "httpd-axum(tokio) OK, fetch size=$FETCH_SIZE_AXUM"
else gate_fail "httpd-axum did not start (code='$code')"; fi
if ! timeout 20 stdbuf -oL -eL "$HOST_RNET" --client "$VM_IP:$RNET_PORT" -t 2 \
  >"$OUT/rnet-probe.log" 2>&1; then
  gate_fail "rnetbench client probe failed (see rnet-probe.log)"
fi

# ------------------------------------------------------------------ workload primitives
# each workload rewrites <name>.stat every iteration: "iters=N fails=M last_rc=R beat=EPOCH last=STR"
write_stat() { # name iters fails rc last
  # Record every failing rc (in order) to <name>.failrcs so the monitor can
  # classify a NEW failure by the rc that actually failed. last_rc in the .stat
  # is the most recent iteration -- usually a later success (0) -- so it cannot
  # be trusted to hold the failing code.
  [ "$4" -ne 0 ] && echo "$4" >> "$OUT/$1.failrcs"
  printf 'iters=%d fails=%d last_rc=%d beat=%d last=%s\n' "$2" "$3" "$4" "$(date +%s)" "$5" > "$OUT/$1.stat"
}
# Pace the loops: a small gap between healthy iterations, and a HARD backoff on
# failure so a broken/failing workload cannot spin at thousands of iters/sec and
# self-amplify the load into a connection-refused cascade.
pace() { if [ "${1:-0}" -ne 0 ]; then sleep "${PACE_FAIL:-3}"; else sleep "${PACE_OK:-0.3}"; fi; }

w_net_rr() {
  local n=0 f=0 rc; while :; do
    n=$((n+1))
    timeout 60 stdbuf -oL -eL "$HOST_RNET" --client "$VM_IP:$RNET_PORT" \
      -t 12 -P 4 >>"$OUT/net-rr.log" 2>&1; rc=$?
    [ "$rc" -ne 0 ] && f=$((f+1)); write_stat net-rr "$n" "$f" "$rc" "rr"; pace "$rc"; done
}
w_net_bulk() {
  local n=0 f=0 rc; while :; do
    n=$((n+1))
    timeout 60 stdbuf -oL -eL "$HOST_RNET" --client "$VM_IP:$RNET_PORT" \
      -t 12 -P 4 -b 65536 >>"$OUT/net-bulk.log" 2>&1; rc=$?
    [ "$rc" -ne 0 ] && f=$((f+1)); write_stat net-bulk "$n" "$f" "$rc" "bulk"; pace "$rc"; done
}
http_hammer() { # name port expected_size ; 8 concurrent GETs/iter
  local name="$1" port="$2" exp="$3" n=0 f=0 j sz rc bad
  while :; do
    n=$((n+1)); bad=0; rc=0
    for j in $(seq 1 8); do
      sz=$(curl -s -o /dev/null -m 25 -w '%{size_download}:%{http_code}' \
            "http://$VM_IP:$port$FETCH_URLPATH" 2>>"$OUT/$name.log")
      cc=$?
      if [ "$cc" -ne 0 ]; then bad=1; [ "$rc" = 0 ] && rc=$cc
        echo "iter=$n curl exit=$cc" >>"$OUT/$name.log"
      else
        case "$sz" in
          "$exp:200") ;;
          *:200) bad=1; rc=97; echo "iter=$n WRONG-SIZE $sz (want $exp:200)" >>"$OUT/$name.log";;  # 200 but truncated/oversized => corruption
          *)     bad=1; [ "$rc" = 0 ] && rc=1; echo "iter=$n bad-status $sz" >>"$OUT/$name.log";;
        esac
      fi
    done
    [ "$bad" -ne 0 ] && f=$((f+1)); write_stat "$name" "$n" "$f" "$rc" "http"; pace "$rc"
  done
}
w_suites() {  # cycle suites that are safe alongside unrelated network traffic
  local n=0 f=0 rc s; local -a suites=("$TOKIO" "$MIO")
  while :; do
    for s in "${suites[@]}"; do
      n=$((n+1))
      # Full systest runs in the mandatory gate. It samples global socket
      # counters and cannot soundly run beside the network generators here.
      timeout 240 ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 motor@"$VM_IP" "$s" \
        >>"$OUT/suites.log" 2>&1; rc=$?
      echo "iter=$n suite=$(basename "$s") rc=$rc" >>"$OUT/suites.log"
      [ "$rc" -ne 0 ] && f=$((f+1)); write_stat suites "$n" "$f" "$rc" "$(basename "$s")"; pace "$rc"
    done
  done
}
# Repeat the same directory, download, upload/overwrite, recursive-copy, and
# cleanup assertions used by full-test.sh.
w_fs_sftp() {
  local n=0 f=0 rc
  while :; do
    n=$((n+1))
    RUSSHD_HOST="$VM_IP" RUSSHD_PORT="$SSH_PORT" RUSSHD_KEY="$KEY" \
      timeout 300 "$SCRIPT_DIR/test-sftp.sh" >>"$OUT/fs-sftp.log" 2>&1
    rc=$?
    [ "$rc" -ne 0 ] && f=$((f+1))
    write_stat fs-sftp "$n" "$f" "$rc" "sftp-integration"
    pace "$rc"
  done
}
# In-VM fs write/read churn + process spawn: cp /www asset -> / -> /, rm. Motor's
# image has no /tmp or /sys/tmp dir, but root (/) is writable (systest drops its
# flush_stress_* files there). /bin/sh forwards to rush (&& chaining); /sys/sysbox
# is the multicall binary.
w_fs_write() {
  local n=0 f=0 rc a b
  while :; do
    n=$((n+1)); a="/strw-a.$((n%6)).bin"; b="/strw-b.$((n%6)).bin"
    timeout 45 ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 motor@"$VM_IP" \
      "/bin/sh -c '/sys/sysbox cp /www/motor-os-256.png $a && /sys/sysbox cp $a $b && /sys/sysbox rm $a && /sys/sysbox rm $b'" \
      >>"$OUT/fs-write.log" 2>&1; rc=$?
    echo "iter=$n rc=$rc" >>"$OUT/fs-write.log"
    [ "$rc" -ne 0 ] && f=$((f+1)); write_stat fs-write "$n" "$f" "$rc" "cp-churn"; pace "$rc"; done
}

# ------------------------------------------------------------------ launch workloads
log "launching workloads"
start_workload() { # name function [args...]
  local name="$1"
  shift
  "$@" &
  WL_NAMES+=("$name")
  WL_PIDS+=($!)
}
start_workload suites w_suites
start_workload fs-sftp w_fs_sftp
start_workload fs-write w_fs_write
start_workload net-rr w_net_rr
start_workload net-bulk w_net_bulk
start_workload http-std http_hammer http-std "$HTTP_STD_PORT" "$FETCH_SIZE_STD"
start_workload http-axum http_hammer http-axum "$HTTP_AXUM_PORT" "$FETCH_SIZE_AXUM"
log "workload pids: ${WL_PIDS[*]}"
SOAK_START=$(date +%s)

# ------------------------------------------------------------------ monitor (foreground)
declare -A PREV_FAILS=()
consec_liveness_fail=0
STALL_SEC=360      # heartbeat older than this while VM alive => stall (hang)
while :; do
  now=$(date +%s); up=$(( now - SOAK_START ))

  # 1. VM liveness
  if ! kill -0 "$QEMU_WRAPPER_PID" 2>/dev/null; then
    STOP_REASON="ANOMALY qemu-exited"
    capture_forensics "$STOP_REASON"; break
  fi
  for i in "${!WL_PIDS[@]}"; do
    if ! kill -0 "${WL_PIDS[$i]}" 2>/dev/null; then
      STOP_REASON="ANOMALY workload-exited:${WL_NAMES[$i]}"
      capture_forensics "$STOP_REASON"; break 2
    fi
    if [ "$up" -gt "$STALL_SEC" ] &&
       [ ! -f "$OUT/${WL_NAMES[$i]}.stat" ]; then
      STOP_REASON="ANOMALY workload-never-started:${WL_NAMES[$i]}"
      capture_forensics "$STOP_REASON"; break 2
    fi
  done
  if VSSH_TMO=15 vssh /bin/echo mon >/dev/null 2>&1; then
    consec_liveness_fail=0
  else
    consec_liveness_fail=$((consec_liveness_fail+1))
    log "liveness probe FAILED ($consec_liveness_fail/$LIVENESS_FAILS_MAX)"
    if [ "$consec_liveness_fail" -ge "$LIVENESS_FAILS_MAX" ]; then
      STOP_REASON="ANOMALY vm-unreachable (net wedge?): ssh dead ${consec_liveness_fail}x"
      capture_forensics "$STOP_REASON"; break
    fi
  fi

  # 2. crash markers on the pure VM console. Match only KERNEL-fatal prints
  #    (the panic handler and the exception handlers' kernel branches), NOT the
  #    kernel's INFO-level logging of a *userspace* fault. A line like
  #    "INFO kernel::uspace::process ... #PF: thread ... killed" is a normal
  #    process death (memory pressure, a userspace bug, ...) handled by the
  #    per-workload policy below; it must not hard-stop the soak. Hence the
  #    "(kernel)"/"in kernel"/"KERNEL" qualifiers rather than a bare "#PF".
  KCRASH='KERNEL PANIC|KERNEL EXCEPTION|#PF \(kernel\)|#GPF.*in kernel|INVALID OPCODE in kernel|EXCEPTION: (DOUBLE FAULT|SEGMENT NOT PRESENT|STACK SEGMENT FAULT|GENERIC3)|TLB shootdown hung|0xbadc0de'
  if grep -aqE "$KCRASH" "$CONSOLE" 2>/dev/null; then
    STOP_REASON="ANOMALY crash-marker in VM console"
    log "$STOP_REASON"; grep -anE "$KCRASH" "$CONSOLE" | tail -8 | tee -a "$OUT/soak.log"
    capture_forensics "$STOP_REASON"; break
  fi

  # 3. Per-workload failures. The first failed iteration stops the soak.
  anomaly=""
  for s in "$OUT"/*.stat; do
    [ -f "$s" ] || continue
    name=$(basename "${s%.stat}")
    line=$(cat "$s")
    fails=$(sed -n 's/.*fails=\([0-9]*\).*/\1/p'   <<<"$line"); fails=${fails:-0}
    beat=$(sed -n 's/.*beat=\([0-9]*\).*/\1/p'      <<<"$line"); beat=${beat:-$now}
    prev=${PREV_FAILS[$name]:-0}
    newf=$(( fails - prev )); PREV_FAILS[$name]=$fails

    if [ $(( now - beat )) -gt "$STALL_SEC" ] && [ "$consec_liveness_fail" = 0 ]; then
      anomaly="workload-stall:$name (no progress $(( now - beat ))s; $line)"; break; fi
    if [ "$newf" -gt 0 ]; then
      # Classify by the rc(s) that actually failed this tick (last_rc in the
      # .stat is the most recent iteration, usually a later success == 0).
      newrcs=$(tail -n "$newf" "$OUT/$name.failrcs" 2>/dev/null)
      newrcs1=$(echo $newrcs | tr '\n' ' ')
      # Deterministic counts over this tick's new failing rc(s) -- grep -c always
      # consumes all input (a negated grep -q all-match test proved flaky here).
      n_corrupt=$(printf '%s\n' "$newrcs" | grep -cE '^(97|98|99)$')
      echo "[$(date +%H:%M:%S) +$((now-START))s] NEW-FAIL $name newf=$newf rcs=[$newrcs1] $line" >> "$OUT/failures.log"
      if [ "$n_corrupt" -gt 0 ]; then
        anomaly="data-corruption:$name (rcs [$newrcs1]; $line)"; break; fi
      if [ "$name" = suites ]; then
        anomaly="suite-failure:$name ($line)"; break
      fi
      anomaly="workload-failure:$name (rcs [$newrcs1]; $line)"; break
    fi
  done
  if [ -n "$anomaly" ]; then
    STOP_REASON="ANOMALY $anomaly"
    log "$STOP_REASON"; capture_forensics "$STOP_REASON"; break
  fi

  # 4. rolling status
  {
    echo "=== stress status  uptime=${up}s / ${DURATION}s   $(date +%H:%M:%S) ==="
    for s in "$OUT"/*.stat; do [ -f "$s" ] && printf '  %-12s %s\n' "$(basename "${s%.stat}")" "$(cat "$s")"; done
    echo "  liveness_fail=$consec_liveness_fail"
  } > "$OUT/status.txt"

  if [ "$up" -ge "$DURATION" ]; then
    SOAK_END=$now
    log "duration reached, finishing clean"
    break
  fi
  remaining=$(( DURATION - up ))
  if [ "$remaining" -lt "$MON_INTERVAL" ]; then
    sleep "$remaining"
  else
    sleep "$MON_INTERVAL"
  fi
done

log "monitor loop exited; STOP_REASON='${STOP_REASON:-none}'"
# teardown runs via EXIT trap
[ -n "$STOP_REASON" ] && exit 2 || exit 0
