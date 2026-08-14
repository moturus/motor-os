# Bounded VM teardown, sourced by the harnesses that boot one. Not executable.
#
# Teardown runs on the way out of a failed run as often as a passing one, and a
# VM that is failing is exactly the one that will not accept a shutdown -- so
# every step here is bounded. Unbounded, an unreachable VM turns a one-line ssh
# error into the harness's whole-run timeout with the console log dumped after
# it, which is a worse report of the same failure, and leaves a qemu holding the
# tap so that the next run looks like a boot failure in turn.
#
# The caller supplies SSH_OPTIONS.

# Reap $1, giving it up to $2 seconds to exit on its own; false if it is still
# running after that. `kill -0` is the liveness test the boot loops already use:
# bash reaps a background child on SIGCHLD, so the pid stops answering once it
# has exited, and `wait` then returns its stored status immediately.
reap_within() {
  local pid="$1" limit="$2" waited=0
  while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$limit" ]; do
    sleep 1
    waited=$((waited + 1))
  done
  kill -0 "$pid" 2>/dev/null && return 1
  wait "$pid" 2>/dev/null || true
  return 0
}

# Shut down the VM whose VMM process is $1, and make sure it is really gone.
stop_vm() {
  local pid="$1"
  if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
    return 0
  fi
  timeout 30s ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=5 \
    motor@192.168.4.2 shutdown || true
  # An orderly shutdown is seconds. Longer means the VM is no longer listening
  # to us, so stop asking and take it down from the outside.
  reap_within "$pid" 20 && return 0
  echo "the VM did not shut down; killing qemu" >&2
  # Current run-qemu.sh execs qemu, so this pid normally is qemu. Keep the
  # child kill for older copied launchers and wrappers such as taskset, where
  # killing only the outer process could leave the VM holding the tap.
  pkill -P "$pid" 2>/dev/null || true
  kill "$pid" 2>/dev/null || true
  reap_within "$pid" 10 ||
    echo "qemu (pid $pid) outlived SIGTERM; it is still running" >&2
  return 0
}
