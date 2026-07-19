#!/bin/bash
#
# Motor OS multi-subsystem stress soak.
#
# Boots ONE long-lived VM and drives it with concurrent, continuously-looping
# workloads spanning every subsystem exercised by the vdso rewrite (fs,
# networking, tokio/mio, process/stdio, russhd), while a foreground monitor
# classifies each iteration, scans for crash markers, detects stalls, and -- on
# the first real anomaly -- captures full forensics (ps / stats x2 / mdbg
# print-stacks / qemu-monitor vCPU dump / console tail) BEFORE tearing the VM
# down.
#
# Usage:
#   bash src/tests/stress-soak.sh [debug|release] [duration-sec] [run-tag]
#
# Environment overrides:
#   RESILIENT=1        auto-relaunch the HTTP servers on death and tolerate
#                      their (and the suites') known-transient flakes, so the
#                      load generator keeps running; still hard-stops on a
#                      kernel crash marker, data corruption, a stall, or a
#                      "connect to sys-io failed" regression.
#   MOTOR_STRESS_OUT   base dir for run output (default /tmp/motor-stress).
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"        # repo root: src/tests -> ../..
OUT_BASE="${MOTOR_STRESS_OUT:-/tmp/motor-stress}"
OUT="$OUT_BASE/run-$RUN_TAG"
mkdir -p "$OUT"

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

SSH_OPTS=(-F /dev/null -p "$SSH_PORT" -o IdentitiesOnly=yes
          -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o BatchMode=yes -i "$KEY")
SFTP_OPTS=(-F /dev/null -P "$SSH_PORT" -o IdentitiesOnly=yes
           -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
           -o BatchMode=yes -i "$KEY")

# short-timeout ssh for control/monitor probes
vssh() { timeout "${VSSH_TMO:-20}" ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 motor@"$VM_IP" "$@"; }

log() { echo "[$(date +%H:%M:%S) +$(( $(date +%s) - START ))s] $*" | tee -a "$OUT/soak.log"; }

START=$(date +%s)
declare -a WL_PIDS=()
STOP_REASON=""
QEMU_STARTED=0

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
  set +e
  log "teardown: reason='${STOP_REASON:-duration-elapsed}'"
  # stop the resilient server relaunch loops (if any) before killing ssh
  touch "$OUT/.stop" 2>/dev/null
  for p in "${SERVER_LOOP_PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  # kill workload loops
  for p in "${WL_PIDS[@]}"; do kill "$p" 2>/dev/null; done
  # best-effort graceful VM shutdown
  VSSH_TMO=15 vssh shutdown 2>/dev/null
  sleep 2
  # char-class patterns => safe inside a script FILE
  pkill -f '[m]otor@192.168.4.2'    2>/dev/null   # all ssh/sftp to the VM
  pkill -f '[r]netbench --client'   2>/dev/null   # host rnetbench clients
  pkill -f '[c]url.*192.168.4.2'    2>/dev/null   # host http hammers
  pkill -f '[r]un-qemu.sh'          2>/dev/null
  pkill -f 'qemu-system-x86_6[4]'   2>/dev/null
  sleep 2
  # final summary
  {
    echo "==== STRESS SOAK SUMMARY ($RUN_TAG, build=$BUILD) ===="
    echo "duration target : ${DURATION}s ; actual uptime : $(( $(date +%s) - START ))s"
    echo "result          : ${STOP_REASON:-CLEAN (duration elapsed, no anomaly)}"
    echo "--- per-workload totals ---"
    for s in "$OUT"/*.stat; do [ -f "$s" ] && printf '  %-12s %s\n' "$(basename "${s%.stat}")" "$(cat "$s")"; done
    [ -f "$OUT/ANOMALY.txt" ] && echo "ANOMALY forensics: $OUT/ANOMALY.txt"
  } | tee "$OUT/RESULT.txt"
  log "teardown complete."
}
trap teardown EXIT

# ------------------------------------------------------------------ boot
log "=== stress soak start: build=$BUILD duration=${DURATION}s out=$OUT ==="
[ -x "$IMG_DIR/run-qemu.sh" ] || { STOP_REASON="BOOT-FAILED: no image at $IMG_DIR (run: make all BUILD=$BUILD)"; log "$STOP_REASON"; exit 1; }
chmod 600 "$KEY"

log "booting VM ($IMG_DIR/run-qemu.sh) with TCP monitor $MON_HOST:$MON_PORT"
"$IMG_DIR/run-qemu.sh" -monitor "tcp:$MON_HOST:$MON_PORT,server,nowait" &> "$CONSOLE" &
QEMU_WRAPPER_PID=$!
QEMU_STARTED=1

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

# ------------------------------------------------------------------ binaries + fetch target (from src/imager/motor-os.yaml)
RNETBENCH=/sys/tests/rnetbench
SYSTEST=/sys/tests/systest
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
# In RESILIENT mode each HTTP server is auto-relaunched on death. Both can die
# under transient allocation pressure -- the std (thread-per-conn) panics on a
# thread-spawn OOM, the tokio server aborts on a failed heap alloc -- which is a
# known fragility, not a subsystem bug; keep the load on regardless.
SERVER_LOOP_PIDS=()
spawn_server() { # tag cmd
  local tag="$1" cmd="$2"
  if [ "${RESILIENT:-0}" = 1 ]; then
    ( while [ ! -f "$OUT/.stop" ]; do
        ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 motor@"$VM_IP" "$cmd" >>"$OUT/srv-$tag.log" 2>&1
        echo "[$(date +%T)] srv-$tag exited; relaunching" >>"$OUT/srv-$tag.log"
        sleep 1
      done ) &
    SERVER_LOOP_PIDS+=($!)
  else
    ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 motor@"$VM_IP" "$cmd" >"$OUT/srv-$tag.log" 2>&1 &
  fi
}
spawn_server httpd      "$HTTPD --addr $VM_IP:$HTTP_STD_PORT --dir $SERVE_DIR"
spawn_server httpd-axum "$HTTPD_AXUM --addr $VM_IP:$HTTP_AXUM_PORT --dir $SERVE_DIR"
sleep 6

# validate servers; disable a workload whose server did not come up
HTTP_STD_OK=1; HTTP_AXUM_OK=1; RNET_OK=1
FETCH_SIZE_STD=0; FETCH_SIZE_AXUM=0
code=$(curl -s -o /dev/null -m 15 -w '%{http_code}' "http://$VM_IP:$HTTP_STD_PORT$FETCH_URLPATH" 2>/dev/null)
if [ "$code" = 200 ]; then
  FETCH_SIZE_STD=$(curl -s -o /dev/null -m 20 -w '%{size_download}' "http://$VM_IP:$HTTP_STD_PORT$FETCH_URLPATH" 2>/dev/null)
  log "httpd(std) OK, fetch size=$FETCH_SIZE_STD"
else HTTP_STD_OK=0; log "WARNING: httpd(std) not serving (code='$code') -> http-std workload DISABLED"; fi
code=$(curl -s -o /dev/null -m 15 -w '%{http_code}' "http://$VM_IP:$HTTP_AXUM_PORT$FETCH_URLPATH" 2>/dev/null)
if [ "$code" = 200 ]; then
  FETCH_SIZE_AXUM=$(curl -s -o /dev/null -m 20 -w '%{size_download}' "http://$VM_IP:$HTTP_AXUM_PORT$FETCH_URLPATH" 2>/dev/null)
  log "httpd-axum(tokio) OK, fetch size=$FETCH_SIZE_AXUM"
else HTTP_AXUM_OK=0; log "WARNING: httpd-axum not serving (code='$code') -> http-axum workload DISABLED"; fi
if ! timeout 20 "$HOST_RNET" --client "$VM_IP:$RNET_PORT" -t 2 >/dev/null 2>&1; then
  RNET_OK=0; log "WARNING: host rnetbench client failed a probe -> net-rr/net-bulk may be degraded"; fi

# ------------------------------------------------------------------ workload primitives
# each workload rewrites <name>.stat every iteration: "iters=N fails=M last_rc=R beat=EPOCH last=STR"
write_stat() { # name iters fails rc last
  printf 'iters=%d fails=%d last_rc=%d beat=%d last=%s\n' "$2" "$3" "$4" "$(date +%s)" "$5" > "$OUT/$1.stat"
}
# Pace the loops: a small gap between healthy iterations, and a HARD backoff on
# failure so a broken/failing workload cannot spin at thousands of iters/sec and
# self-amplify the load into a connection-refused cascade.
pace() { if [ "${1:-0}" -ne 0 ]; then sleep "${PACE_FAIL:-3}"; else sleep "${PACE_OK:-0.3}"; fi; }

w_net_rr() {
  local n=0 f=0 rc; while :; do
    n=$((n+1)); timeout 60 "$HOST_RNET" --client "$VM_IP:$RNET_PORT" -t 12 -P 4 >>"$OUT/net-rr.log" 2>&1; rc=$?
    [ "$rc" -ne 0 ] && f=$((f+1)); write_stat net-rr "$n" "$f" "$rc" "rr"; pace "$rc"; done
}
w_net_bulk() {
  local n=0 f=0 rc; while :; do
    n=$((n+1)); timeout 60 "$HOST_RNET" --client "$VM_IP:$RNET_PORT" -t 12 -P 4 -b 65536 >>"$OUT/net-bulk.log" 2>&1; rc=$?
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
w_suites() {  # cycle the three heavy suites; classify on exit code (block-buffer-safe)
  local n=0 f=0 rc s; local -a suites=("$SYSTEST" "$TOKIO" "$MIO")
  while :; do
    for s in "${suites[@]}"; do
      n=$((n+1))
      timeout 240 ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 motor@"$VM_IP" "$s" \
        >>"$OUT/suites.log" 2>&1; rc=$?
      echo "iter=$n suite=$(basename "$s") rc=$rc" >>"$OUT/suites.log"
      [ "$rc" -ne 0 ] && f=$((f+1)); write_stat suites "$n" "$f" "$rc" "$(basename "$s")"; pace "$rc"
    done
  done
}
# russhd's SFTP is READ-ONLY (open() accepts only OpenFlags::READ), so this is
# a download workload: fs-read + russhd(tokio) + net, byte-compared to a
# reference to catch truncation/corruption (rc=98).
w_fs_sftp() {
  local n=0 f=0 rc sz; local ref="$OUT/sftp-ref.bin" refsz
  timeout 60 sftp "${SFTP_OPTS[@]}" motor@"$VM_IP" >>"$OUT/fs-sftp.log" 2>&1 <<EOF
get /www/motor-os-256.png $ref
EOF
  refsz=$(stat -c %s "$ref" 2>/dev/null || echo 0)
  echo "fs-sftp reference size=$refsz" >>"$OUT/fs-sftp.log"
  while :; do
    n=$((n+1)); rm -f "$OUT/sftp-back.bin"
    timeout 60 sftp "${SFTP_OPTS[@]}" motor@"$VM_IP" >>"$OUT/fs-sftp.log" 2>&1 <<EOF
get /www/motor-os-256.png $OUT/sftp-back.bin
EOF
    rc=$?
    if [ "$rc" -eq 0 ]; then
      sz=$(stat -c %s "$OUT/sftp-back.bin" 2>/dev/null || echo 0)
      if [ "$refsz" -le 0 ] || [ "$sz" != "$refsz" ] || ! cmp -s "$ref" "$OUT/sftp-back.bin"; then
        rc=98; echo "iter=$n CORRUPT download sz=$sz ref=$refsz" >>"$OUT/fs-sftp.log"; fi
    fi
    [ "$rc" -ne 0 ] && f=$((f+1)); write_stat fs-sftp "$n" "$f" "$rc" "sftp-get"; pace "$rc"; done
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
w_suites &   WL_PIDS+=($!)
w_fs_sftp &  WL_PIDS+=($!)
w_fs_write & WL_PIDS+=($!)
[ "$RNET_OK" = 1 ] && { w_net_rr &   WL_PIDS+=($!); w_net_bulk & WL_PIDS+=($!); }
[ "$HTTP_STD_OK"  = 1 ] && { http_hammer http-std  "$HTTP_STD_PORT"  "$FETCH_SIZE_STD"  & WL_PIDS+=($!); }
[ "$HTTP_AXUM_OK" = 1 ] && { http_hammer http-axum "$HTTP_AXUM_PORT" "$FETCH_SIZE_AXUM" & WL_PIDS+=($!); }
log "workload pids: ${WL_PIDS[*]}"

# ------------------------------------------------------------------ monitor (foreground)
declare -A PREV_FAILS=()
consec_liveness_fail=0
STALL_SEC=360      # heartbeat older than this while VM alive => stall (hang)
BURST_FAILS=3      # >= this many NEW failures for one workload in a single tick => stop
CHRONIC_FAILS=8    # cumulative failures for one workload over the whole run => stop
while :; do
  now=$(date +%s); up=$(( now - START ))
  [ "$up" -ge "$DURATION" ] && { log "duration reached, finishing clean"; break; }

  # 1. VM liveness
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

  # 3. per-workload: tiered anomaly policy.
  #    immediate stop: stall, data corruption (rc 97/98/99), any suite failure.
  #    burst stop    : >=BURST_FAILS new failures in one tick (fast-failing path).
  #    chronic stop  : cumulative fails >= CHRONIC_FAILS (slow-bleeding path).
  #    else          : log to failures.log and keep soaking (transient noise).
  anomaly=""
  for s in "$OUT"/*.stat; do
    [ -f "$s" ] || continue
    name=$(basename "${s%.stat}")
    line=$(cat "$s")
    fails=$(sed -n 's/.*fails=\([0-9]*\).*/\1/p'   <<<"$line"); fails=${fails:-0}
    lastrc=$(sed -n 's/.*last_rc=\([0-9]*\).*/\1/p' <<<"$line"); lastrc=${lastrc:-0}
    beat=$(sed -n 's/.*beat=\([0-9]*\).*/\1/p'      <<<"$line"); beat=${beat:-$now}
    prev=${PREV_FAILS[$name]:-0}
    newf=$(( fails - prev )); PREV_FAILS[$name]=$fails

    if [ $(( now - beat )) -gt "$STALL_SEC" ] && [ "$consec_liveness_fail" = 0 ]; then
      anomaly="workload-stall:$name (no progress $(( now - beat ))s; $line)"; break; fi
    if [ "$newf" -gt 0 ]; then
      echo "[$(date +%H:%M:%S) +$((now-START))s] NEW-FAIL $name newf=$newf $line" >> "$OUT/failures.log"
      case "$lastrc" in
        97|98|99) anomaly="data-corruption:$name ($line)"; break;;
      esac
      if [ "$name" = suites ]; then
        # RESILIENT: tolerate suites' own intermittent flakes (e.g. the udp
        # AlreadyInUse port-reuse race) so the load generator keeps running --
        # but STILL hard-stop if the connect-to-sys-io panic regresses, since
        # that is the specific fix this soak is guarding.
        if [ "${RESILIENT:-0}" = 1 ] && ! grep -q "connect to sys-io failed" "$OUT/suites.log" 2>/dev/null; then
          continue
        fi
        anomaly="suite-failure:$name ($line)"; break
      fi
      # In RESILIENT mode, both HTTP servers' fails are the known allocation-
      # pressure fragility (auto-restarted), not a subsystem defect: log-only,
      # do not abort. Corruption (rc 97/98/99) and stall above still stop.
      if [ "${RESILIENT:-0}" = 1 ]; then
        case "$name" in http-std|http-axum) continue;; esac
      fi
      if [ "$newf" -ge "$BURST_FAILS" ]; then anomaly="burst-fail:$name ($newf new; $line)"; break; fi
      if [ "$fails" -ge "$CHRONIC_FAILS" ]; then anomaly="chronic-fail:$name ($fails total; $line)"; break; fi
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

  sleep "$MON_INTERVAL"
done

log "monitor loop exited; STOP_REASON='${STOP_REASON:-none}'"
# teardown runs via EXIT trap
[ -n "$STOP_REASON" ] && exit 2 || exit 0
