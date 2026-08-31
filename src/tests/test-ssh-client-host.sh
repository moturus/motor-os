# Private moto-tap SSH compatibility cases for the Motor client.

SSH_CLIENT_HOST_PROCESS=""
SSH_CLIENT_HOST_OUTPUT_FD=""
SSH_CLIENT_HOST_BASE=""
SSH_CLIENT_HOST_ROOT=""
SSH_CLIENT_HOST_PORT=""

stop_ssh_client_host() {
  if [ -n "$SSH_CLIENT_HOST_PROCESS" ]; then
    kill "$SSH_CLIENT_HOST_PROCESS" 2>/dev/null || true
    wait "$SSH_CLIENT_HOST_PROCESS" 2>/dev/null || true
    SSH_CLIENT_HOST_PROCESS=""
  fi
  if [ -n "$SSH_CLIENT_HOST_OUTPUT_FD" ]; then
    local output_fd="$SSH_CLIENT_HOST_OUTPUT_FD"
    exec {output_fd}<&-
    SSH_CLIENT_HOST_OUTPUT_FD=""
  fi
}

cleanup_ssh_client_host() {
  stop_ssh_client_host
  if [ -n "$SSH_CLIENT_HOST_ROOT" ]; then
    case "$SSH_CLIENT_HOST_ROOT" in
      "$SSH_CLIENT_HOST_BASE"/ssh-client-host.*)
        rm -rf "$SSH_CLIENT_HOST_ROOT"
        ;;
      *)
        printf 'refusing to remove unexpected SSH fixture path: %s\n' \
          "$SSH_CLIENT_HOST_ROOT" >&2
        ;;
    esac
    SSH_CLIENT_HOST_ROOT=""
  fi
}

write_ssh_client_host_config() {
  local path="$1"
  local address="$2"
  local host_key="$3"
  {
    printf "version = 1\nlisten_on = '%s'\npath = '/bin:/usr/bin'\n" "$address"
    printf 'host_key = """%s"""\n\n[users.motor]\n' "$(cat "$host_key")"
    printf "salt = 'd6973342749609329b41f52d390fcd0a4732df20e15dc6766d37f09ac8f129a1'\n"
    printf "password_hash = '37a651a4c34e3738af54c29d1cf7b1d46fc893440797a3b72b578ec151df0d41'\n"
    printf "authorized_key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqjlUjeBcqvHyy+RvVL54pfyK7vj5kAkJRt+qLlZWPH'\n"
  } > "$path"
}

start_ssh_client_host() {
  local host_key="$1"
  local requested_port="$2"
  local repo_root
  repo_root="$(cd "$ROOT_DIR" && pwd)"
  local host_bin="$repo_root/src/bin/russhd/target/$BUILD/russhd"
  local config="$SSH_CLIENT_HOST_ROOT/sshd.toml"
  local input_fd
  local startup_log=""
  local deadline

  [ -x "$host_bin" ] || fail "host russhd is missing at $host_bin"
  write_ssh_client_host_config "$config" "192.168.4.1:$requested_port" "$host_key"
  coproc SSH_CLIENT_HOST_SERVER {
    cd "$SSH_CLIENT_HOST_ROOT"
    exec env HOME="$SSH_CLIENT_HOST_ROOT" "$host_bin" "$config" </dev/null 2>&1
  }
  SSH_CLIENT_HOST_PROCESS="$SSH_CLIENT_HOST_SERVER_PID"
  exec {SSH_CLIENT_HOST_OUTPUT_FD}<&"${SSH_CLIENT_HOST_SERVER[0]}"
  input_fd="${SSH_CLIENT_HOST_SERVER[1]}"
  exec {input_fd}>&-

  SSH_CLIENT_HOST_PORT=""
  deadline=$((SECONDS + 5))
  while [ "$SECONDS" -lt "$deadline" ]; do
    local remaining=$((deadline - SECONDS))
    local line
    if ! IFS= read -r -t "$remaining" line <&"$SSH_CLIENT_HOST_OUTPUT_FD"; then
      break
    fi
    startup_log="$startup_log$line
"
    case "$line" in
      *"Listening on "*)
        local address="${line##*Listening on }"
        SSH_CLIENT_HOST_PORT="${address##*:}"
        break
        ;;
    esac
  done
  case "$SSH_CLIENT_HOST_PORT" in
    ""|*[!0-9]*)
      printf '%s' "$startup_log" >&2
      stop_ssh_client_host
      fail "host russhd did not report a valid listening address"
      ;;
  esac
  if [ "$requested_port" != 0 ] && [ "$SSH_CLIENT_HOST_PORT" != "$requested_port" ]; then
    stop_ssh_client_host
    fail "host russhd listened on $SSH_CLIENT_HOST_PORT, expected $requested_port"
  fi
}

test_ssh_client_host() {
  local guest_key=/user/cfg/ssh/id_ed25519
  local guest_wrong=/user/cfg/ssh/wrong_ed25519
  local guest_known=/user/cfg/ssh/known_hosts
  local guest_executable="$TEST_TMP/ssh-client-host-executable"
  local host=192.168.4.1
  local first_key="$WD/test.key"
  local second_key="$WD/test-host-alt.key"
  local public_file
  local public_key
  local known
  local output
  local port
  local repo_root
  local guest_file

  echo "-- Motor SSH client private-network compatibility --"
  repo_root="$(cd "$ROOT_DIR" && pwd)"
  SSH_CLIENT_HOST_BASE="$repo_root/build/host-tests"
  mkdir -p "$SSH_CLIENT_HOST_BASE"
  SSH_CLIENT_HOST_ROOT="$(mktemp -d "$SSH_CLIENT_HOST_BASE/ssh-client-host.XXXXXX")"
  public_file="$SSH_CLIENT_HOST_ROOT/id_ed25519.pub"
  public_key="$(ssh-keygen -y -f "$first_key")"
  printf '%s\n' "$public_key" > "$public_file"

  for guest_file in "$guest_key" "$guest_key.pub" "$guest_wrong" "$guest_known" "$guest_executable"; do
    vm_ssh "/system/bin/rm $guest_file" >/dev/null 2>&1 || true
  done
  printf 'put %s %s\nchmod 600 %s\nput %s %s\nchmod 644 %s\nput %s %s\nchmod 600 %s\n' \
    "$first_key" "$guest_key" "$guest_key" \
    "$public_file" "$guest_key.pub" "$guest_key.pub" \
    "$second_key" "$guest_wrong" "$guest_wrong" |
    sftp -b - -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
      -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" \
      -i "$WD/test.key" motor@192.168.4.2 >/dev/null

  start_ssh_client_host "$first_key" 0
  port="$SSH_CLIENT_HOST_PORT"
  output="$(vm_ssh "/user/bin/ssh -F /dev/null -p $port -o BatchMode=yes -o StrictHostKeyChecking=accept-new motor@$host /bin/echo unknown-ok")" ||
    fail "Motor client rejected an unknown host under accept-new"
  [ "$output" = unknown-ok ] || fail "unknown-host command returned '$output'"

  output="$(vm_ssh "/user/bin/ssh -F /dev/null -p $port -o BatchMode=yes -o StrictHostKeyChecking=yes motor@$host /bin/echo matching-ok")" ||
    fail "Motor client rejected its recorded host key"
  [ "$output" = matching-ok ] || fail "matching-host command returned '$output'"
  known="$(vm_ssh /system/bin/cat "$guest_known")"
  [ "$known" = "[$host]:$port $public_key" ] ||
    fail "known_hosts contains an unexpected record: '$known'"

  local host_executable="$SSH_CLIENT_HOST_ROOT/executable"
  local returned_executable="$SSH_CLIENT_HOST_ROOT/returned-executable"
  printf '#!/bin/sh\necho executable-download\n' > "$host_executable"
  chmod 755 "$host_executable"
  local native_scp="/user/bin/scp -P $port -i $guest_key -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$guest_known"
  vm_ssh "$native_scp motor@$host:$host_executable $guest_executable" ||
    fail "Motor client could not download a 0755 Unix file"
  vm_ssh "$native_scp $guest_executable motor@$host:$returned_executable" ||
    fail "Motor client could not return the downloaded executable"
  [ "$(stat -c %a "$returned_executable")" = 555 ] ||
    fail "Motor client did not normalize a downloaded 0755 file to 0555"

  local password_command="/user/bin/ssh -F /dev/null -p $port -i $guest_wrong -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes motor@$host /bin/echo password-ok"
  output="$(printf 'vroomvroom\n' | ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 "$password_command" 2>&1)" ||
    fail "Motor client password fallback failed"
  printf '%s\n' "$output" | tr -d '\r' | grep -qx password-ok ||
    fail "password-auth command returned '$output'"

  local copy_id="/user/bin/ssh-copy-id -F /dev/null -p $port -o BatchMode=yes -o StrictHostKeyChecking=yes -i $guest_key.pub motor@$host"
  vm_ssh "$copy_id" >/dev/null || fail "ssh-copy-id failed"
  [ "$(stat -c %a "$SSH_CLIENT_HOST_ROOT/.ssh")" = 700 ] ||
    fail "ssh-copy-id did not create .ssh with mode 0700"
  [ "$(stat -c %a "$SSH_CLIENT_HOST_ROOT/.ssh/authorized_keys")" = 600 ] ||
    fail "ssh-copy-id did not create authorized_keys with mode 0600"
  printf '# preserved\n' >> "$SSH_CLIENT_HOST_ROOT/.ssh/authorized_keys"
  vm_ssh "$copy_id" >/dev/null || fail "duplicate ssh-copy-id failed"
  [ "$(grep -Fxc "$public_key" "$SSH_CLIENT_HOST_ROOT/.ssh/authorized_keys")" = 1 ] ||
    fail "ssh-copy-id did not install exactly one key"
  grep -Fqx '# preserved' "$SSH_CLIENT_HOST_ROOT/.ssh/authorized_keys" ||
    fail "ssh-copy-id discarded an unrecognized authorized_keys line"

  stop_ssh_client_host
  start_ssh_client_host "$second_key" "$port"
  if vm_ssh "/user/bin/ssh -F /dev/null -p $port -o BatchMode=yes -o StrictHostKeyChecking=yes motor@$host /bin/true"; then
    fail "Motor client accepted a changed host key"
  else
    local status=$?
    [ "$status" -eq 255 ] || fail "changed host key returned status $status"
  fi
  [ "$(vm_ssh /system/bin/cat "$guest_known")" = "$known" ] ||
    fail "changed host key modified known_hosts"

  stop_ssh_client_host
  for guest_file in "$guest_key" "$guest_key.pub" "$guest_wrong" "$guest_known" "$guest_executable"; do
    vm_ssh "/system/bin/rm $guest_file" >/dev/null ||
      fail "failed to remove guest SSH fixture $guest_file"
  done
  cleanup_ssh_client_host
  echo "-- Motor SSH client private-network compatibility PASS"
}
