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

vm_ssh() {
  ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2 "$@"
}

wait_guest_file() {
  local path="$1"
  for _ in $(seq 1 120); do
    if vm_ssh "[ -e $path ]" >/dev/null 2>&1; then
      return
    fi
    if ! kill -0 "$VMM_PID" 2>/dev/null; then
      cat "$CONSOLE_LOG" >&2
      fail "QEMU exited while waiting for '$path'"
    fi
    sleep 0.5
  done
  fail "console did not create '$path' (log: $CONSOLE_LOG)"
}

run_console() {
  local marker="$1"
  local command="$2"
  printf '%s; echo done > %s\n' "$command" "$marker" >&3
  wait_guest_file "$marker"
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

run_console /user/tmp/system-tty-ps-done \
  '/system/bin/sysbox ps > /user/tmp/system-tty-ps'
run_console /user/tmp/system-tty-shim-done \
  'echo shim > /user/tmp/system-tty-shim; chmod r-xr-xr-- /user/tmp/system-tty-shim'
run_console /user/tmp/system-tty-direct-done \
  'echo direct > /user/tmp/system-tty-direct; /system/bin/sysbox chmod r-xr--r-- /user/tmp/system-tty-direct'
run_console /user/tmp/system-tty-defaults-done \
  'echo default > /user/tmp/system-tty-default-file; /system/bin/mkdir /user/tmp/system-tty-default-dir'
run_console /user/tmp/system-tty-script-done \
  "echo '#!/system/bin/rush' > /user/tmp/system-tty-script; echo 'echo V1 > /user/tmp/system-tty-script-v1' >> /user/tmp/system-tty-script; chmod r-xr--r-- /user/tmp/system-tty-script; /user/tmp/system-tty-script; echo 'echo EDITED > /user/tmp/system-tty-edit-succeeded' >> /user/tmp/system-tty-script; chmod rw-r--r-- /user/tmp/system-tty-script; /user/tmp/system-tty-script; /system/bin/rm /user/tmp/system-tty-script; echo '#!/system/bin/rush' > /user/tmp/system-tty-script; echo 'echo V2 > /user/tmp/system-tty-script-v2' >> /user/tmp/system-tty-script; chmod r-xr--r-- /user/tmp/system-tty-script; /user/tmp/system-tty-script"

ps_output="$(vm_ssh /system/bin/cat /user/tmp/system-tty-ps)"
listing="$(vm_ssh /system/bin/ls -l /user/tmp)"
printf '%s\n' "$ps_output" | has_system_process /system/services/sys-tty ||
  fail "sys-tty is not System: '$ps_output'"
printf '%s\n' "$ps_output" | has_system_process /system/bin/rush ||
  fail "the console shell is not System: '$ps_output'"
printf '%s\n' "$ps_output" | has_system_process /system/bin/sysbox ||
  fail "an ordinary external command did not retain System: '$ps_output'"
printf '%s\n' "$listing" |
  grep -aqE -- '-r-xr-xr--[[:space:]]+[0-9]+[[:space:]]+system-tty-shim$' ||
  fail "the chmod shim did not install the exact mode"
printf '%s\n' "$listing" |
  grep -aqE -- '-r-xr--r--[[:space:]]+[0-9]+[[:space:]]+system-tty-direct$' ||
  fail "sysbox chmod did not install the exact mode"
printf '%s\n' "$listing" |
  grep -aqE -- '-rw-r--r--[[:space:]]+[0-9]+[[:space:]]+system-tty-default-file$' ||
  fail "System-created file did not use the creator-relative default"
printf '%s\n' "$listing" |
  grep -aqE -- 'drwxr-xr-x[[:space:]]+system-tty-default-dir$' ||
  fail "System-created directory did not use the creator-relative default"
vm_ssh '[ -e /user/tmp/system-tty-script-v1 ]' ||
  fail "the finalized System-role script did not run"
vm_ssh '[ -e /user/tmp/system-tty-script-v2 ]' ||
  fail "the replacement System-role script did not run"
if vm_ssh '[ -e /user/tmp/system-tty-edit-succeeded ]'; then
  fail "the finalized System-role script remained writable"
fi
printf '%s\n' "$listing" |
  grep -aqE -- '-r-xr--r--[[:space:]]+[0-9]+[[:space:]]+system-tty-script$' ||
  fail "the finalized System-role script regained write permission"

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
