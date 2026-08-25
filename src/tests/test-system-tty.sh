#!/bin/bash

if [ "${TEST_SYSTEM_TTY_TIMEOUT_ACTIVE:-0}" != "1" ]; then
  export TEST_SYSTEM_TTY_TIMEOUT_ACTIVE=1
  set -m
  timeout 300s "$0" "$@" < /dev/null
  status=$?
  set +m
  if [ "$status" -eq 124 ]; then
    echo "test-system-tty: timed out after 300 seconds" >&2
  fi
  exit "$status"
fi

set -e

WD="$(dirname "$0")"
ROOT_DIR="$WD/../.."
BUILD=debug
if [ "${1:-}" = "--release" ]; then
  BUILD=release
fi
IMG_DIR="$ROOT_DIR/vm_images/$BUILD"
export MOTO_IMAGE=motor-os-system-tty.img

if [ "$BUILD" = release ]; then
  make -C "$ROOT_DIR" system-tty.img BUILD=release -j"$(nproc)"
else
  make -C "$ROOT_DIR" system-tty.img -j"$(nproc)"
fi

chmod 600 "$WD/test.key"
SSH_OPTIONS=(
  -F /dev/null
  -p 2222
  -o IdentitiesOnly=yes
  -o BatchMode=yes
  -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile="$WD/test-known-hosts"
  -i "$WD/test.key"
)

. "$WD/vm-cleanup.sh"

fail() {
  echo "test-system-tty: $*" >&2
  exit 1
}

CONSOLE_LOG=/tmp/test-system-tty.log
SCRATCH="$(mktemp -d)"
VMM_PID=""

cleanup() {
  set +e
  stop_vm "$VMM_PID"
  VMM_PID=""
  exec 3>&-
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

strip_console() {
  sed -e $'s/\033\\[[0-9;?$]*[a-zA-Z]//g' -e $'s/\033[78]//g' | tr -d '\r'
}

wait_console() {
  local pattern="$1"
  for _ in $(seq 1 120); do
    if grep -aq "$pattern" "$CONSOLE_LOG"; then
      return
    fi
    if ! kill -0 "$VMM_PID" 2>/dev/null; then
      cat "$CONSOLE_LOG" >&2
      fail "QEMU exited while waiting for '$pattern'"
    fi
    sleep 0.5
  done
  fail "console did not print '$pattern' (log: $CONSOLE_LOG)"
}

has_system_process() {
  local process="$1"
  awk -v process="$process" '
    $1 ~ /\*$/ {
      for (i = 1; i <= NF; i++) {
        if ($i == process) {
          found = 1
        }
      }
    }
    END { exit !found }
  '
}

mkfifo "$SCRATCH/console-in"
echo "test-system-tty: starting a $BUILD VM; console log in $CONSOLE_LOG"
"$IMG_DIR/run-qemu.sh" < "$SCRATCH/console-in" > "$CONSOLE_LOG" 2>&1 &
VMM_PID="$!"
exec 3> "$SCRATCH/console-in"

until ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=5 -o ConnectionAttempts=1 \
  motor@192.168.4.2 /system/bin/rush -c true >/dev/null; do
  if ! kill -0 "$VMM_PID" 2>/dev/null; then
    cat "$CONSOLE_LOG" >&2
    fail "QEMU exited before SSH became ready"
  fi
  sleep 1
done

wait_console "motor-os"
printf '%s\n' \
  'echo SYSTEM_TTY_PS_BEGIN; /system/bin/sysbox ps; echo SYSTEM_TTY_PS_END' >&3
wait_console "SYSTEM_TTY_PS_END"
printf '%s\n' \
  'echo shim > /user/tmp/system-tty-shim; chmod rwxr-xr-- /user/tmp/system-tty-shim; /system/bin/ls -l /user/tmp; echo SYSTEM_TTY_SHIM_DONE' >&3
wait_console "SYSTEM_TTY_SHIM_DONE"
printf '%s\n' \
  'echo direct > /user/tmp/system-tty-direct; /system/bin/sysbox chmod rwxr--r-- /user/tmp/system-tty-direct; /system/bin/sysbox ls -l /user/tmp; echo SYSTEM_TTY_CHMOD_DONE' >&3
wait_console "SYSTEM_TTY_CHMOD_DONE"

console="$(strip_console < "$CONSOLE_LOG")"
ps_output="$console"
printf '%s\n' "$ps_output" | has_system_process /system/services/sys-tty ||
  fail "sys-tty is not System: '$ps_output'"
printf '%s\n' "$ps_output" | has_system_process /system/bin/rush ||
  fail "the console shell is not System: '$ps_output'"
printf '%s\n' "$ps_output" | has_system_process /system/bin/sysbox ||
  fail "an ordinary external command did not retain System: '$ps_output'"
printf '%s\n' "$console" |
  grep -aqE -- '-rwxr-xr--[[:space:]]+[0-9]+[[:space:]]+system-tty-shim$' ||
  fail "the chmod shim did not install the exact mode"
printf '%s\n' "$console" |
  grep -aqE -- '-rwxr--r--[[:space:]]+[0-9]+[[:space:]]+system-tty-direct$' ||
  fail "sysbox chmod did not install the exact mode"

# The foreground rmux client remains observable while its detached server and
# pane are alive. Two rmux processes prove the detached spawn succeeded; the
# starred client proves Rush's pass-listed grant preserved System authority.
printf '/user/bin/rmux new -s system-role\n' >&3
rmux_ok=0
for _ in $(seq 1 40); do
  rmux_ps="$(ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2 /system/bin/sysbox ps)"
  rmux_count="$(printf '%s\n' "$rmux_ps" |
    awk '
      {
        for (i = 1; i <= NF; i++) {
          if ($i == "/user/bin/rmux") {
            count++
          }
        }
      }
      END { print count + 0 }
    ')"
  if [ "$rmux_count" -ge 2 ] &&
    printf '%s\n' "$rmux_ps" | has_system_process /user/bin/rmux; then
    rmux_ok=1
    break
  fi
  sleep 0.25
done
[ "$rmux_ok" = 1 ] ||
  fail "pass-listed rmux did not retain System and launch its detached server: '$rmux_ps'"

stop_vm "$VMM_PID"
VMM_PID=""
echo "-------- TEST-SYSTEM-TTY PASS ---------"
