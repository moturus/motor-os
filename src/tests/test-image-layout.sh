#!/usr/bin/env bash
# Check shipped and installed paths on an already booted image.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
ssh_options=(-F /dev/null -p 2222 -o IdentitiesOnly=yes -o BatchMode=yes
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$ROOT_DIR/src/tests/test-known-hosts"
  -i "$ROOT_DIR/src/tests/test.key")
remote() { ssh "${ssh_options[@]}" motor@192.168.4.2 "$@"; }
fail() { echo "test-image-layout: $*" >&2; exit 1; }
denied() {
  if remote "$@" > /dev/null 2>&1; then
    fail "unexpected success: $*"
  fi
}
mode() {
  local path="$1" expected="$2" actual
  actual="$(remote "/user/bin/ls -l ${path%/*}" | awk -v name="${path##*/}" '$NF == name { print $1 }')"
  [ "$actual" = "$expected" ] || fail "$path has mode '$actual', expected '$expected'"
}

remote '[ ! -e /system/bin ]'
remote '/user/bin/rush -c "echo migrated-shell"' | grep -qx migrated-shell
mode /user/bin drwxrwxr-x
mode /user/bin/rush -r-xr-xr-x
mode /user/bin/sh -rwxrwxr-x
mode /none/dev drwxrwxrwx
mode /user/cfg drwxrwxr-x
mode /user/cfg/rush.cfg -rwxrw-r--
mode /user/cfg/rush.toml -rwxrw-r--
mode /user/cfg/sshd.toml -rwxrw----
for path in /user/cfg/rush.cfg /user/cfg/rush.toml; do
  remote "MOTOR_OS_CAPS=0x204 /user/bin/cat $path" > /dev/null
  # Opening a readable file alone need not check write access; send bytes.
  denied "MOTOR_OS_CAPS=0x204 /user/bin/rush -c 'echo denied >>$path'"
done
for path in /user/cfg/sshd.toml /user/cfg/russhd/users.toml /user/cfg/ssh/authorized_keys.motor; do
  denied "MOTOR_OS_CAPS=0x204 /user/bin/cat $path"
done
for path in /system /user /user/bin /user/cfg; do
  denied "MOTOR_OS_CAPS=0x204 /user/bin/mkdir $path/.image-layout-denied"
done
remote '[ ! -e /system/cfg/rush.cfg ] && [ ! -e /system/cfg/sshd.toml ]'

# An Interactive installer can replace its own prior output. The shipped ELF
# remains immutable; a copied ELF and script use the runtime installation modes.
probe=/user/bin/.image-layout-probe
data=/user/cfg/.image-layout-data
directory=/user/bin/.image-layout-directory
cleanup() {
  local status=$? path
  for path in "$probe" "$probe.tmp" "$data"; do
    remote "if [ -e $path ]; then /user/bin/rm $path; fi" || status=1
  done
  remote "if [ -d $directory ]; then /user/bin/rmdir $directory; fi" || status=1
  exit "$status"
}
remote "[ ! -e $probe ] && [ ! -e $probe.tmp ] && [ ! -e $data ] && [ ! -e $directory ]"
trap cleanup EXIT
remote "/user/bin/mkdir $directory"
mode "$directory" drwxrwxr-x
remote "MOTOR_OS_CAPS=0x204 /user/bin/ls $directory" > /dev/null
denied "MOTOR_OS_CAPS=0x204 /user/bin/mkdir $directory/denied"
for pass in 1 2; do
  remote "/user/bin/cp /user/bin/sysbox $probe.tmp && /user/bin/chmod rwxrwxr-x $probe.tmp && /user/bin/mv $probe.tmp $probe"
  mode "$probe" -rwxrwxr-x
  remote "MOTOR_OS_CAPS=0x204 $probe echo installed-elf" | grep -qx installed-elf
  denied "MOTOR_OS_CAPS=0x204 /user/bin/rush -c 'echo denied >>$probe'"
done
remote "/user/bin/rm $probe && /user/bin/cp /user/bin/echo $probe.tmp && /user/bin/chmod rwxr-xr-x $probe.tmp && /user/bin/chmod rwxrwxr-x $probe.tmp && /user/bin/mv $probe.tmp $probe"
mode "$probe" -rwxrwxr-x
remote "MOTOR_OS_CAPS=0x204 $probe installed-script" | grep -qx installed-script
remote "/user/bin/cp /user/cfg/rush.toml $data && /user/bin/chmod rwxrw-r-- $data"
mode "$data" -rwxrw-r--
remote "MOTOR_OS_CAPS=0x204 /user/bin/cat $data" > /dev/null
denied "MOTOR_OS_CAPS=0x204 /user/bin/rush -c 'echo denied >>$data'"

if remote '[ -e /user/bin/dev/lorry ]'; then
  mode /user/bin/dev drwxrwxr-x
  mode /user/lib drwxrwxr-x
  mode /user/dev/lorry drwxrwxr-x
  mode /none/dev/lorry drwxrwxrwx
  mode /user/cfg/lorry.toml -rwxrw-r--
  mode /user/cfg/helix drwxrwxr-x
  mode /user/cfg/helix/languages.toml -rwxrw-r--
  for path in /user/cfg/lorry.toml /user/cfg/helix/languages.toml /user/dev/lorry/vendor/repository.toml; do
    remote "MOTOR_OS_CAPS=0x204 /user/bin/cat $path" > /dev/null
    denied "MOTOR_OS_CAPS=0x204 /user/bin/rush -c 'echo denied >>$path'"
  done
  remote '[ ! -e /devtools/src ] && [ ! -e /devtools/lorry ] && [ -f /user/lib/imager/imager ]'
  for tool in lorry gix mdbg sed lua www hx javy wasmi wasmtime wasmtime-rt qjs qjsc; do
    remote "[ -x /user/bin/dev/$tool ] && [ ! -e /devtools/bin/$tool ]"
  done
  # --health loads the shared configuration and creates the log directory in the
  # caller's cache. Each role's TMPDIR is supplied by the runtime.
  remote 'MOTOR_OS_CAPS=0x204 /user/bin/dev/hx --health rust' > /dev/null
  remote 'MOTOR_OS_CAPS=0x204 /user/bin/ls /none/tmp/.cache/helix' > /dev/null
  remote 'MOTOR_OS_CAPS=0x204 /user/bin/dev/qjs -e "print(6 * 7)"' | grep -qx 42
fi
echo "test-image-layout PASS"
