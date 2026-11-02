#!/bin/bash
#
# Acceptance for several SSH keys per login name and for remote key installation
# (docs/ssh-client.md): russhd as shipped, on a disposable copy of the image
# that imager provisions and two boots use. russhd's host tests cover parsing,
# limits and races; this is what only a guest can show: Motor's role checks, the
# installers against a real Motor server, and what survives a reboot.
#
# Nothing here touches a developer's credentials or the host's sshd: every key is
# generated in the fixture, HOME points at it, and OpenSSH's installers run only
# against the guest.

if [ "${TEST_SSHD_KEYS_TIMEOUT_ACTIVE:-0}" != "1" ]; then
  export TEST_SSHD_KEYS_TIMEOUT_ACTIVE=1
  # See full-test.sh for why job control keeps timeout's process group safe.
  set -m
  timeout 600s "$0" "$@" < /dev/null
  status=$?
  set +m
  if [ "$status" -eq 124 ]; then
    echo "test-sshd-keys: timed out after 600 seconds" >&2
  fi
  exit "$status"
fi

set -euo pipefail

WD="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$WD/../.." && pwd)"

BUILD=debug
VMM=qemu
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release) BUILD=release; shift ;;
    --vmm) [ "$#" -ge 2 ] || { echo "test-sshd-keys: --vmm requires a VMM" >&2; exit 2; }
      VMM="$2"; shift 2 ;;
    --vmm=*) VMM="${1#--vmm=}"; shift ;;
    *) echo "usage: $0 [--release] [--vmm qemu|chv|fc]" >&2; exit 2 ;;
  esac
done

. "$WD/vm-console-filter.sh"
. "$WD/vm-test-boot.sh"
. "$WD/vm-test-boot-check.sh"
. "$WD/vm-test-selection.sh"

select_test_vm "$ROOT_DIR" "$BUILD" standard "$VMM"

if [ "${FULL_TEST_IMAGE_PREBUILT:-0}" != 1 ]; then
  make -C "$ROOT_DIR" "$TEST_VM_IMG_TARGET" BUILD="$BUILD" -j"$(nproc)"
fi
IMAGER="$TEST_VM_IMG_DIR/tools/imager"
[ -x "$IMAGER" ] || { echo "test-sshd-keys: imager is missing at $IMAGER" >&2; exit 1; }
case "$(ssh-copy-id -h 2>&1 || true)" in
  *target_path*) ;;
  *) echo "test-sshd-keys: ssh-copy-id -t needs OpenSSH 9.4 or newer" >&2; exit 1 ;;
esac

HOST=192.168.4.2
USERS=/user/cfg/russhd/users.toml
KEYS=/user/cfg/ssh
CONSOLE_LOG=/tmp/test-sshd-keys.log
GUEST_TMP=/user/tmp/sshd-keys

mkdir -p "$ROOT_DIR/build/host-tests"
FIXTURE="$(mktemp -d "$ROOT_DIR/build/host-tests/sshd-keys.XXXXXX")"
# Control sockets outgrow sun_path below a repository path.
SOCKETS="$(mktemp -d "${TMPDIR:-/tmp}/sshd-keys.XXXXXX")"
ADMIN="$SOCKETS/admin"
IMAGE_COPY="test-sshd-keys-$$.${TEST_VM_IMAGE##*.}"
export MOTO_IMAGE="$IMAGE_COPY"
export MOTO_CHV_RUNTIME_DIR="$FIXTURE/chv"
export MOTO_FC_RUNTIME_DIR="$FIXTURE/fc"
export MOTO_FC_VSOCK_UDS=''
# ssh-copy-id keeps a control socket under ~/.ssh, so HOME has to be short too.
export HOME="$SOCKETS/home"
mkdir -m 700 "$HOME" "$HOME/.ssh"

VMM_PID=""
DAEMON_PIDS=()
PASSED=0

fail() {
  echo "test-sshd-keys: $* (logs: $FIXTURE, console: $CONSOLE_LOG)" >&2
  exit 1
}

close_session() {
  ssh "${SSH_OPTIONS[@]}" -S "$1" -O exit "motor@$HOST" >/dev/null 2>&1 || true
}

# The daemons die with the VM; this ends the host's side of their sessions.
stop_daemon_sessions() {
  local pid
  for pid in ${DAEMON_PIDS[@]+"${DAEMON_PIDS[@]}"}; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  DAEMON_PIDS=()
}

stop_vm_owned() {
  stop_daemon_sessions
  close_session "$ADMIN"
  stop_test_vm_owned "$VMM" "$TEST_VM_LABEL"
}

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if [ -n "$VMM_PID" ]; then
    stop_vm_owned || [ "$status" -ne 0 ] || status=1
  fi
  rm -f "$TEST_VM_IMG_DIR/$IMAGE_COPY"
  rm -rf "$SOCKETS"
  if [ "$status" -eq 0 ] && [ "$PASSED" = 1 ]; then
    rm -rf "$FIXTURE"
  else
    echo "test-sshd-keys: failed; logs are in $FIXTURE" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

test_vm_configure_ssh
USER_OPTIONS=(
  -F /dev/null -p 2222 -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile="$WD/test-known-hosts" -o ConnectTimeout=20
)

# ---- guest access ------------------------------------------------------------

# The shipped key opens one connection that outlives every credential broken
# below: russhd checks credentials when a connection authenticates, not after,
# and a multiplexed session needs no new authentication.
open_admin() {
  ssh "${SSH_OPTIONS[@]}" -M -S "$ADMIN" -N -f "motor@$HOST" || fail "cannot open the admin connection"
}

admin() {
  ssh "${SSH_OPTIONS[@]}" -S "$ADMIN" -o ControlMaster=no "motor@$HOST" "$@"
}

put() { admin "/system/bin/cat > $1"; }
get() { admin "/system/bin/cat $1"; }
mode_of() {
  local entry
  entry="$(admin "/system/bin/ls -l ${1%/*}" | grep -E " ${1##*/}\$")" || fail "$1 is missing"
  printf '%s\n' "${entry%% *}"
}

expect_mode() {
  local mode
  mode="$(mode_of "$1")"
  [ "$mode" = "$2" ] || fail "$1 has mode '$mode', want '$2'"
}

chmod_guest() { admin "/system/bin/chmod $1 $2"; }

# ---- what a login sees -------------------------------------------------------

key_attempt() {
  ssh "${USER_OPTIONS[@]}" -o BatchMode=yes -o PreferredAuthentications=publickey \
    -i "$2" "$1@$HOST" "${3:-/system/bin/rush -c true}" 2>"$FIXTURE/last.err"
}

password_attempt() {
  SSHD_KEYS_PASSWORD="$2" SSH_ASKPASS="$FIXTURE/askpass" SSH_ASKPASS_REQUIRE=force \
    ssh "${USER_OPTIONS[@]}" -o BatchMode=no -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 \
    "$1@$HOST" /system/bin/rush -c true 2>"$FIXTURE/last.err"
}

# Only a refusal counts: a dead VM must not read as a passing negative check.
denied() {
  local status=0
  "$@" || status=$?
  [ "$status" -eq 255 ] && grep -q 'Permission denied' "$FIXTURE/last.err"
}

key_works() { key_attempt "$1" "$FIXTURE/$2" || fail "$1 cannot log in with $2: $(cat "$FIXTURE/last.err")"; }
key_denied() { denied key_attempt "$1" "$FIXTURE/$2" || fail "$1 was not refused with $2"; }
password_works() { password_attempt "$1" "$2" || fail "$1 cannot log in with a password: $(cat "$FIXTURE/last.err")"; }
password_denied() { denied password_attempt "$1" "$2" || fail "$1 was not refused its password"; }

# What the server says can continue, from a client that tries nothing.
methods_for() {
  # Trying nothing ends in exit 255; the list is what this is here for.
  ssh "${USER_OPTIONS[@]}" -v -o BatchMode=yes -o PreferredAuthentications=none \
    "$1@$HOST" true > "$FIXTURE/methods.log" 2>&1 || true
  tr -d '\r' < "$FIXTURE/methods.log" |
    sed -n 's/^debug1: Authentications that can continue: //p' | head -n 1
}

expect_methods() {
  local name methods
  for name in "$@"; do
    methods="$(methods_for "$name")"
    [ "$methods" = "password,publickey" ] ||
      fail "'$name' was offered methods '$methods'"
  done
}

# ---- fixtures ----------------------------------------------------------------

new_key() { ssh-keygen -q -t ed25519 -N '' -C "$1" -f "$FIXTURE/$1"; }
public() { cat "$FIXTURE/$1.pub"; }

# One registry record: SHA-256 of the salt's bytes followed by the password.
record() {
  local name="$1" password="$2" salt hash
  salt="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  hash="$( { printf "$(printf '%s' "$salt" | sed 's/../\\x&/g')"; printf '%s' "$password"; } |
    sha256sum | cut -d' ' -f1)"
  printf "[users.%s]\nsalt = '%s'\npassword_hash = '%s'\n" "$name" "$salt" "$hash"
}

# As docs/ssh-client.md says to edit it: a whole new file, renamed into place.
# A file a shell creates starts None-readable, which russhd refuses in a registry.
install_registry() {
  put "$USERS.new" < "$1"
  chmod_guest rwxrw---- "$USERS.new"
  admin "/system/bin/mv $USERS.new $USERS"
}

cat > "$FIXTURE/askpass" <<'SH'
#!/bin/sh
printf '%s\n' "$SSHD_KEYS_PASSWORD"
SH
chmod 700 "$FIXTURE/askpass"

for key in alice-1 alice-2 bob-1 bob-2 shared carol installed-1 installed-2 \
  motor-client forced bootstrap host-installed; do
  new_key "$key"
done

# ---- provisioning ------------------------------------------------------------

echo "-- imager provisions several names --"
cp --reflink=auto "$TEST_VM_IMG_DIR/$TEST_VM_IMAGE" "$TEST_VM_IMG_DIR/$IMAGE_COPY"
copy="$TEST_VM_IMG_DIR/$IMAGE_COPY"
"$IMAGER" set --ssh-new-user alice --ssh-password alice-password -i "$copy"
"$IMAGER" set --ssh-user alice --ssh-key "$FIXTURE/alice-1.pub" -i "$copy"
"$IMAGER" set --ssh-new-user bob --ssh-key "$FIXTURE/bob-1.pub" -i "$copy"
if "$IMAGER" set --ssh-user nobody --ssh-password x -i "$copy" 2>/dev/null; then
  fail "imager accepted a name with no record"
fi

start_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" "$CONSOLE_LOG"
open_admin
admin "/system/bin/mkdir $GUEST_TMP"

echo "-- images ship the credential layout --"
expect_mode "$USERS" -rwxrw----
expect_mode "$KEYS/authorized_keys.motor" -rwxrw----
expect_mode "$KEYS/authorized_keys.alice" -rwxrw----
expect_mode /user/cfg/ssh drwxrwx---
expect_mode /user/cfg/russhd drwxrwx---
expect_mode /system/cfg/sshd.toml -rw-r-----
if get /system/cfg/sshd.toml | grep -Eq '^\[users|^authorized_key[ =]|^password_hash|^salt'; then
  fail "the service configuration still holds user credentials"
fi

# ---- logins ------------------------------------------------------------------

echo "-- two names, two keys each --"
# The form for clients without ssh-copy-id -t: it appends, and needs nothing else.
ssh "${USER_OPTIONS[@]}" -o BatchMode=yes -i "$FIXTURE/alice-1" "alice@$HOST" \
  "/system/bin/cat >> $KEYS/authorized_keys.alice" < "$FIXTURE/alice-2.pub" ||
  fail "cat >> did not install a key"
ssh "${USER_OPTIONS[@]}" -o BatchMode=yes -i "$FIXTURE/bob-1" "bob@$HOST" \
  "/system/bin/cat >> $KEYS/authorized_keys.bob" < "$FIXTURE/bob-2.pub" ||
  fail "cat >> did not install a key for the second name"
expect_mode "$KEYS/authorized_keys.bob" -rwxrw----
for key in alice-1 alice-2; do key_works alice "$key"; done
for key in bob-1 bob-2; do key_works bob "$key"; done
key_denied alice bob-1
key_denied nobody alice-1
password_works alice alice-password
password_denied bob alice-password
password_denied '../ssh/authorized_keys.alice' alice-password
expect_methods alice bob nobody

echo "-- a key listed for two names --"
{ public shared; } | put "$GUEST_TMP/shared"
admin "/system/bin/rush -c '/system/bin/cat $GUEST_TMP/shared >> $KEYS/authorized_keys.alice'"
admin "/system/bin/rush -c '/system/bin/cat $GUEST_TMP/shared >> $KEYS/authorized_keys.bob'"
key_works alice shared
key_works bob shared
{ public alice-1; public alice-2; } | put "$KEYS/authorized_keys.alice"
key_denied alice shared
key_works bob shared
key_works alice alice-1

# ---- live updates ------------------------------------------------------------

echo "-- changes apply to the next authentication --"
public alice-1 | put "$KEYS/authorized_keys.alice"
key_denied alice alice-2
key_works alice alice-1

{
  printf 'version = 1\n\n'
  record motor vroomvroom
  record alice changed-password
  printf '[users.bob]\n'
} > "$FIXTURE/users.1"
install_registry "$FIXTURE/users.1"
password_denied alice alice-password
password_works alice changed-password

public carol | put "$KEYS/authorized_keys.carol"
{ cat "$FIXTURE/users.1"; record carol carol-password; } > "$FIXTURE/users.2"
install_registry "$FIXTURE/users.2"
key_works carol carol
password_works carol carol-password

CAROL_SESSION="$SOCKETS/carol"
ssh "${USER_OPTIONS[@]}" -o BatchMode=yes -i "$FIXTURE/carol" -M -S "$CAROL_SESSION" -N -f "carol@$HOST" ||
  fail "cannot hold a session for carol"
install_registry "$FIXTURE/users.1"
key_denied carol carol
password_denied carol carol-password
[ "$(ssh "${USER_OPTIONS[@]}" -S "$CAROL_SESSION" -o ControlMaster=no "carol@$HOST" /system/bin/echo still-here)" = still-here ] ||
  fail "removing a name ended its established session"
ssh "${USER_OPTIONS[@]}" -S "$CAROL_SESSION" -O exit "carol@$HOST" >/dev/null 2>&1 || true

# ---- failures ----------------------------------------------------------------

echo "-- a bad key file costs one name its key method --"
good_alice="$(public alice-1)"
printf '%s\n\0' "$good_alice" | put "$KEYS/authorized_keys.alice"
key_denied alice alice-1
password_works alice changed-password
key_works bob bob-1
{
  printf '# comment\r\n\r\nrestrict %s\n' "$(public alice-2)"
  printf 'from="10.0.0.1" %s\n' "$(public alice-2)"
  printf 'not a key\n%s' "$good_alice"
} | put "$KEYS/authorized_keys.alice"
key_works alice alice-1
key_denied alice alice-2
public alice-1 | put "$KEYS/authorized_keys.alice"
if ! get "$KEYS/authorized_keys.alice" | grep -Fqx "$good_alice"; then
  fail "the key file was not restored"
fi

echo "-- a bad registry denies new authentication, with no fallback --"
printf 'version = 1\n[users.alice]\npassword_hash = "not hexadecimal"\n' > "$FIXTURE/users.bad"
install_registry "$FIXTURE/users.bad"
key_denied alice alice-1
password_denied alice changed-password
expect_methods alice nobody
admin "/system/bin/rm $USERS"
key_denied bob bob-1
install_registry "$FIXTURE/users.1"
key_works alice alice-1

# ---- installers --------------------------------------------------------------

# Everything an installer must leave alone, as guest-side text.
snapshot() {
  local name
  for name in "$@"; do
    printf '%s: %s\n' "$name" "$(mode_of "$name")"
    get "$name"
  done
  admin "/system/bin/ls -l /user/cfg/ssh" | grep -v "authorized_keys\.$SELECTED\$"
}

motor_copy_id() {
  local name="$1" identity="$2" public_key="$3" target="$4"
  admin "/user/bin/ssh-copy-id -F /dev/null -p 2222 -o IdentityFile=$GUEST_TMP/$identity \
    -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile=$GUEST_TMP/known_hosts -i $GUEST_TMP/$public_key.pub \
    -t $target $name@127.0.0.1"
}

stage_identity() {
  put "$GUEST_TMP/$1" < "$FIXTURE/$1"
  chmod_guest rwxrw---- "$GUEST_TMP/$1"
  put "$GUEST_TMP/$1.pub" < "$FIXTURE/$1.pub"
}

# OpenSSH 9.4's installer. Its duplicate probe would log in with any key that
# works and call the new one installed, so this passes it no alternate identity:
# it finds the key missing and installs it with the password.
openssh_copy_id() {
  local name="$1" password="$2" public_key="$3" target="$4"
  shift 4
  SSHD_KEYS_PASSWORD="$password" SSH_ASKPASS="$FIXTURE/askpass" SSH_ASKPASS_REQUIRE=force \
    ssh-copy-id "$@" -t "$target" -i "$FIXTURE/$public_key.pub" -p 2222 -F /dev/null \
    -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$WD/test-known-hosts" -o PreferredAuthentications=password \
    "$name@$HOST" </dev/null
}

expect_lines() {
  local path="$1" actual expected
  shift
  actual="$(get "$path")"
  expected="$(printf '%s\n' "$@")"
  [ "$actual" = "$expected" ] || fail "$path holds '$actual', want '$expected'"
}

stage_identity motor-client
stage_identity installed-1
stage_identity alice-1
public motor-client | put "$KEYS/authorized_keys.bob"
put "$KEYS/id_ed25519" < "$FIXTURE/carol"
chmod_guest rwxrw---- "$KEYS/id_ed25519"

echo "-- Motor ssh-copy-id -t --"
SELECTED=bob
before="$(snapshot "$USERS" "$KEYS/authorized_keys.motor" "$KEYS/authorized_keys.alice" "$KEYS/id_ed25519")"
motor_copy_id bob motor-client installed-1 "$KEYS/authorized_keys.bob" >/dev/null ||
  fail "Motor ssh-copy-id -t failed"
expect_lines "$KEYS/authorized_keys.bob" "$(public motor-client)" "$(public installed-1)"
expect_mode "$KEYS/authorized_keys.bob" -rwxrw----
key_works bob installed-1
motor_copy_id bob motor-client installed-1 "$KEYS/authorized_keys.bob" >/dev/null ||
  fail "repeating Motor ssh-copy-id -t failed"
expect_lines "$KEYS/authorized_keys.bob" "$(public motor-client)" "$(public installed-1)"

# The name's own file need not exist, or may be empty, and a missing final
# newline or a comment is no reason to lose anything.
admin "/system/bin/rm $KEYS/authorized_keys.alice"
motor_copy_id bob motor-client installed-1 "$KEYS/authorized_keys.alice" >/dev/null ||
  fail "Motor ssh-copy-id -t failed on a missing file"
expect_lines "$KEYS/authorized_keys.alice" "$(public installed-1)"
expect_mode "$KEYS/authorized_keys.alice" -rwxrw----
: | put "$KEYS/authorized_keys.alice"
motor_copy_id bob motor-client installed-1 "$KEYS/authorized_keys.alice" >/dev/null ||
  fail "Motor ssh-copy-id -t failed on an empty file"
expect_lines "$KEYS/authorized_keys.alice" "$(public installed-1)"
printf '# keep this\n%s' "$(public alice-1)" | put "$KEYS/authorized_keys.alice"
motor_copy_id bob motor-client installed-1 "$KEYS/authorized_keys.alice" >/dev/null ||
  fail "Motor ssh-copy-id -t failed on a file with no final newline"
expect_lines "$KEYS/authorized_keys.alice" '# keep this' "$(public alice-1)" "$(public installed-1)"
key_works alice alice-1
key_works alice installed-1

restricted="$(printf 'from="10.0.0.1" %s' "$(public installed-1)")"
printf '%s\n' "$restricted" | put "$KEYS/authorized_keys.alice"
if output="$(motor_copy_id bob motor-client installed-1 "$KEYS/authorized_keys.alice" 2>&1)"; then
  fail "Motor ssh-copy-id widened a restricted key"
fi
case "$output" in
  *"not as a plain record"*) ;;
  *) fail "Motor ssh-copy-id reported '$output' for a restricted key" ;;
esac
expect_lines "$KEYS/authorized_keys.alice" "$restricted"
public alice-1 | put "$KEYS/authorized_keys.alice"
after="$(snapshot "$USERS" "$KEYS/authorized_keys.motor" "$KEYS/authorized_keys.alice" "$KEYS/id_ed25519")"
[ "$before" = "$after" ] || fail "an installer changed something else: '$before' became '$after'"
expect_mode /user/cfg/ssh drwxrwx---
expect_mode "$KEYS/id_ed25519" -rwxrw----

echo "-- OpenSSH ssh-copy-id -s -t --"
SELECTED=alice
before="$(snapshot "$USERS" "$KEYS/authorized_keys.motor" "$KEYS/authorized_keys.bob" "$KEYS/id_ed25519")"
openssh_copy_id alice changed-password installed-2 "$KEYS/authorized_keys.alice" -s \
  > "$FIXTURE/openssh-copy-id.log" 2>&1 || fail "ssh-copy-id -s -t failed"
expect_lines "$KEYS/authorized_keys.alice" "$(public alice-1)" "$(public installed-2)"
expect_mode "$KEYS/authorized_keys.alice" -rwxrw----
key_works alice installed-2

# The duplicate probe sees the key and leaves the file alone.
ssh-copy-id -s -t "$KEYS/authorized_keys.alice" -i "$FIXTURE/installed-2.pub" -p 2222 -F /dev/null \
  -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$WD/test-known-hosts" "alice@$HOST" </dev/null \
  > "$FIXTURE/openssh-copy-id-repeat.log" 2>&1 || fail "a repeated ssh-copy-id -s -t failed"
expect_lines "$KEYS/authorized_keys.alice" "$(public alice-1)" "$(public installed-2)"

for state in missing empty comment; do
  case "$state" in
    missing) admin "/system/bin/rm $KEYS/authorized_keys.alice" ;;
    empty) : | put "$KEYS/authorized_keys.alice" ;;
    comment) printf '# keep this\n%s' "$(public alice-1)" | put "$KEYS/authorized_keys.alice" ;;
  esac
  openssh_copy_id alice changed-password installed-2 "$KEYS/authorized_keys.alice" -s \
    > "$FIXTURE/openssh-copy-id-$state.log" 2>&1 || fail "ssh-copy-id -s -t failed on a $state file"
  case "$state" in
    comment) expect_lines "$KEYS/authorized_keys.alice" '# keep this' "$(public alice-1)" "$(public installed-2)" ;;
    *) expect_lines "$KEYS/authorized_keys.alice" "$(public installed-2)" ;;
  esac
  expect_mode "$KEYS/authorized_keys.alice" -rwxrw----
done
public alice-1 | put "$KEYS/authorized_keys.alice"
after="$(snapshot "$USERS" "$KEYS/authorized_keys.motor" "$KEYS/authorized_keys.bob" "$KEYS/id_ed25519")"
[ "$before" = "$after" ] || fail "ssh-copy-id changed something else: '$before' became '$after'"
expect_mode /user/cfg/ssh drwxrwx---
expect_mode "$KEYS/id_ed25519" -rwxrw----

echo "-- forced OpenSSH installation --"
ssh-copy-id -f -s -t "$KEYS/authorized_keys.bob" -i "$FIXTURE/forced.pub" -p 2222 -F /dev/null \
  -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityFile="$FIXTURE/bob-1" \
  -o IdentityFile="$FIXTURE/motor-client" -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$WD/test-known-hosts" "bob@$HOST" </dev/null \
  > "$FIXTURE/openssh-copy-id-forced.log" 2>&1 || fail "ssh-copy-id -f -s -t failed"
key_works bob forced

echo "-- a password-only name bootstraps its first key --"
{ cat "$FIXTURE/users.1"; record dana dana-password; } > "$FIXTURE/users.3"
install_registry "$FIXTURE/users.3"
key_denied dana bootstrap
openssh_copy_id dana dana-password bootstrap "$KEYS/authorized_keys.dana" -s \
  > "$FIXTURE/openssh-copy-id-bootstrap.log" 2>&1 || fail "password bootstrap failed"
key_works dana bootstrap
if ssh-copy-id -s -n -t "$KEYS/authorized_keys.dana" -i "$FIXTURE/bootstrap.pub" -p 2222 -F /dev/null \
  -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$WD/test-known-hosts" "dana@$HOST" </dev/null 2>&1 |
  grep -q 'would have added'; then
  fail "the duplicate probe did not see the installed key"
fi
install_registry "$FIXTURE/users.1"
admin "/system/bin/rm $KEYS/authorized_keys.dana"

echo "-- other installer forms fail and install nothing --"
SELECTED=none
before="$(snapshot "$USERS" "$KEYS/authorized_keys.motor" "$KEYS/authorized_keys.alice" "$KEYS/authorized_keys.bob")"
# $2 is why it has to fail: not logging in at all would prove nothing here.
installer_refused() {
  local label="$1" reason="$2" output status=0
  shift 2
  output="$("$@" 2>&1 </dev/null)" || status=$?
  printf '%s\n' "$output" > "$FIXTURE/refused-$label.log"
  [ "$status" -ne 0 ] || fail "$label reported success"
  case "$output" in
    *"Number of key(s) added"*|*"Key installed"*) fail "$label reported an installed key" ;;
    *"(password,publickey)"*) fail "$label did not log in: $output" ;;
    *"$reason"*) ;;
    *) fail "$label failed for another reason: $output" ;;
  esac
  admin "[ ! -e /user/.ssh ]" || fail "$label created /user/.ssh"
}
installer_refused openssh-sftp-default 'Permission denied' ssh-copy-id -f -s -i "$FIXTURE/forced.pub" -p 2222 \
  -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityFile="$FIXTURE/motor-client" \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" "bob@$HOST"
installer_refused openssh-shell dirname ssh-copy-id -f -t "$KEYS/authorized_keys.bob" \
  -i "$FIXTURE/forced.pub" -p 2222 -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes \
  -o IdentityFile="$FIXTURE/motor-client" -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$WD/test-known-hosts" "bob@$HOST"
installer_refused openssh-shell-default dirname ssh-copy-id -f -i "$FIXTURE/forced.pub" -p 2222 \
  -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityFile="$FIXTURE/motor-client" \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" "bob@$HOST"
installer_refused motor-default 'Permission denied' admin "/user/bin/ssh-copy-id -F /dev/null -p 2222 \
  -o IdentityFile=$GUEST_TMP/motor-client -o IdentitiesOnly=yes -o BatchMode=yes \
  -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$GUEST_TMP/known_hosts \
  -i $GUEST_TMP/installed-1.pub bob@127.0.0.1"
after="$(snapshot "$USERS" "$KEYS/authorized_keys.motor" "$KEYS/authorized_keys.alice" "$KEYS/authorized_keys.bob")"
[ "$before" = "$after" ] || fail "a refused installer changed something: '$before' became '$after'"

# ---- trust -------------------------------------------------------------------

echo "-- Motor roles decide what is trusted --"
key_list="$KEYS/authorized_keys.alice"
# None can read a key file without harm, but not a registry.
chmod_guest rwxrw-r-- "$key_list"
key_works alice alice-1
chmod_guest rwxrw---- "$key_list"
chmod_guest rwxrw-r-- "$USERS"
key_denied alice alice-1
password_denied alice changed-password
chmod_guest rwxrw---- "$USERS"
key_works alice alice-1

chmod_guest rwxrw-rw- "$key_list"
key_denied alice alice-1
password_works alice changed-password
chmod_guest rwxrw---- "$key_list"

chmod_guest rwxrwxrwx /user/cfg/ssh
key_denied alice alice-1
password_works alice changed-password
chmod_guest rwxrwx--- /user/cfg/ssh

chmod_guest rwxrwxrwx /user/cfg/russhd
password_denied alice changed-password
chmod_guest rwxrwx--- /user/cfg/russhd

chmod_guest rwxrwxrwx /user/cfg
password_denied alice changed-password
chmod_guest rwxrwx--- /user/cfg
key_works alice alice-1

admin "/system/bin/rm $key_list"
admin "/system/bin/mkdir $key_list"
key_denied alice alice-1
password_works alice changed-password
admin "/system/bin/rmdir $key_list" 2>/dev/null || admin "/system/bin/rm -r $key_list"
public alice-1 | put "$key_list"
key_works alice alice-1

echo "-- the size limit, through the guest's own read path --"
padded() {
  local size="$1" line
  line="$(public alice-1)"
  # Comment lines up to the size, the key last: a match needs the whole file.
  awk -v size="$((size - ${#line} - 1))" 'BEGIN {
    while (size > 1000) { printf "#%998s\n", ""; size -= 1000 }
    if (size > 0) { printf "#%*s\n", size - 2, "" }
  }'
  printf '%s\n' "$line"
}
padded 1048576 > "$FIXTURE/keys.exact"
[ "$(stat -c %s "$FIXTURE/keys.exact")" = 1048576 ] || fail "the 1 MiB fixture is the wrong size"
put "$key_list" < "$FIXTURE/keys.exact"
key_works alice alice-1
{ printf '#\n'; cat "$FIXTURE/keys.exact"; } | put "$key_list"
key_denied alice alice-1
password_works alice changed-password
public alice-1 | put "$key_list"

# ---- a second daemon ---------------------------------------------------------

# A daemon on port $1 reading configuration $2. OpenSSH keeps the first -p it
# sees, so another port needs its own options and its own pin of the same host
# key. Nothing here can stop a daemon: each gets a port, and the reboot ends it.
second_daemon() {
  local port="$1" config="$2" attempt
  sed "s/:2222/:$port/" "$WD/test-known-hosts" > "$FIXTURE/known-hosts-$port"
  DAEMON_OPTIONS=(
    -F /dev/null -p "$port" -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="$FIXTURE/known-hosts-$port" -o ConnectTimeout=20
  )
  # On a terminal russhd logs to it: the system log takes one russhd.
  ssh "${SSH_OPTIONS[@]}" -tt "motor@$HOST" "/system/services/russhd $config" \
    > "$FIXTURE/daemon-$port.log" 2>&1 </dev/null &
  DAEMON_PIDS+=("$!")
  for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    ssh "${DAEMON_OPTIONS[@]}" -o BatchMode=yes -o PreferredAuthentications=none \
      "probe@$HOST" true > "$FIXTURE/probe.log" 2>&1 || true
    grep -q 'Permission denied' "$FIXTURE/probe.log" && return 0
    sleep 1
  done
  fail "the daemon on port $port did not start: $(cat "$FIXTURE/daemon-$port.log")"
}

# One step at a time: russhd refuses overlapping channels on a connection.
guest_config() {
  get /system/cfg/sshd.toml > "$FIXTURE/sshd.toml"
  sed -e "s/0\.0\.0\.0:2222/0.0.0.0:$1/" -e "s#^users_file = .*#users_file = '$2'#" \
    -e "s#^authorized_keys_dir = .*#authorized_keys_dir = '$3'#" "$FIXTURE/sshd.toml" |
    put "$4"
}

echo "-- a location outside /user is checked through the root --"
none_dir=/none/tmp/sshd-keys
admin "/system/bin/mkdir $none_dir"
put "$none_dir/users.toml" < "$FIXTURE/users.1"
public alice-1 | put "$none_dir/authorized_keys.alice"
guest_config 2223 "$none_dir/users.toml" "$none_dir" "$GUEST_TMP/outside.toml"
# Private as files, but None could replace them: /none/tmp is None's own.
chmod_guest rwxrw---- "$none_dir/users.toml"
chmod_guest rwxrw---- "$none_dir/authorized_keys.alice"
chmod_guest rwxrwx--- "$none_dir"
second_daemon 2223 "$GUEST_TMP/outside.toml"
if ssh "${DAEMON_OPTIONS[@]}" -o BatchMode=yes -o PreferredAuthentications=publickey \
  -i "$FIXTURE/alice-1" "alice@$HOST" true 2>"$FIXTURE/last.err"; then
  fail "a location under None's own directory was trusted"
fi
grep -q 'Permission denied' "$FIXTURE/last.err" || fail "the outside location was not refused"

echo "-- a daemon started now sees every change --"
key_list_now="$(get "$key_list")"
guest_config 2224 "$USERS" "$KEYS" "$GUEST_TMP/restarted.toml"
second_daemon 2224 "$GUEST_TMP/restarted.toml"
ssh "${DAEMON_OPTIONS[@]}" -o BatchMode=yes -i "$FIXTURE/alice-1" "alice@$HOST" \
  /system/bin/rush -c true 2>"$FIXTURE/last.err" || fail "a new daemon refused alice: $(cat "$FIXTURE/last.err")"
if ssh "${DAEMON_OPTIONS[@]}" -o BatchMode=yes -o PreferredAuthentications=publickey \
  -i "$FIXTURE/alice-2" "alice@$HOST" true 2>"$FIXTURE/last.err"; then
  fail "a new daemon accepted a removed key"
fi

# ---- ordinary use under a second name ----------------------------------------

echo "-- ssh, scp and sftp under another name --"
[ "$(key_attempt alice "$FIXTURE/alice-1" '/system/bin/echo as-alice')" = as-alice ] ||
  fail "ssh as alice returned the wrong output"
printf 'payload\n' > "$FIXTURE/payload"
scp -F /dev/null -P 2222 -q -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$WD/test-known-hosts" -i "$FIXTURE/alice-1" \
  "$FIXTURE/payload" "alice@$HOST:$GUEST_TMP/payload" || fail "scp as alice failed"
printf 'get %s/payload %s/returned\n' "$GUEST_TMP" "$FIXTURE" |
  sftp -q -b - -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" \
    -i "$FIXTURE/alice-1" "alice@$HOST" >/dev/null || fail "sftp as alice failed"
cmp -s "$FIXTURE/payload" "$FIXTURE/returned" || fail "the transfers changed the data"

# ---- a clean reboot ----------------------------------------------------------

echo "-- every change survives a clean reboot --"
mode_now="$(mode_of "$key_list")"
stop_vm_owned || fail "the VM did not shut down cleanly"
start_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" "$CONSOLE_LOG"
open_admin
key_works alice alice-1
key_works bob motor-client
password_works alice changed-password
key_denied alice alice-2
password_denied alice alice-password
[ "$(get "$key_list")" = "$key_list_now" ] || fail "alice's key list did not survive the reboot"
expect_mode "$key_list" "$mode_now"

stop_vm_owned || fail "the VM did not shut down cleanly"
PASSED=1
echo "test-sshd-keys: PASS"
