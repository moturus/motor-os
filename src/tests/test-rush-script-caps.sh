# Native Rush script and function capability regressions. Sourced by full-test.sh.

test_rush_script_caps() {
  local interpreter="$1"
  local dir="$TEST_TMP/rush-script-caps-$interpreter"
  local test_case prefix suffix out expected body parent_pid script_pid
  vm_ssh "/system/bin/mkdir $dir"
  {
    printf '#!/system/bin/%s\n' "$interpreter"
    cat <<'SCRIPT'
echo script=$$
echo mask=${MOTOR_OS_CAPS-unset}
unset MOTOR_OS_CAPS
if echo changed > "$1"; then echo write=allowed; else echo write=denied; fi
"$2" print-caps descendant
echo spawn=$?
exit 7
SCRIPT
  } | vm_ssh "/system/bin/rush -c 'cat >$dir/script'"
  vm_ssh "/system/bin/chmod rwxr-xr-x $dir/script"

  for test_case in default assigned exported override zero invalid-assigned invalid-exported empty \
    command exec function function-raise; do
    suffix=""
    case "$test_case" in
      default) prefix="" ;;
      assigned) prefix="MOTOR_OS_CAPS=0x44" ;;
      exported) prefix="export MOTOR_OS_CAPS=0x44;" ;;
      override) prefix="export MOTOR_OS_CAPS=zz; MOTOR_OS_CAPS=0x44" ;;
      zero) prefix="MOTOR_OS_CAPS=0" ;;
      invalid-assigned) prefix="MOTOR_OS_CAPS=zz" ;;
      invalid-exported) prefix="export MOTOR_OS_CAPS=zz;" ;;
      empty) prefix="MOTOR_OS_CAPS=" ;;
      command) prefix="MOTOR_OS_CAPS=0x44 command" ;;
      # A subshell keeps exec from ending the shell before it reports status.
      exec) prefix="(MOTOR_OS_CAPS=0x44 exec" suffix=")" ;;
      function) prefix="f() { unset MOTOR_OS_CAPS; \"\$@\"; }; MOTOR_OS_CAPS=0x44 f" ;;
      function-raise) prefix="f() { MOTOR_OS_CAPS=0x344 \"\$@\"; }; MOTOR_OS_CAPS=0x44 f" ;;
    esac
    # The parent has Interactive, spawn, network and FS-write authority.
    # The restricted script must not regain the latter two by unsetting its mask.
    out="$(vm_ssh "MOTOR_OS_CAPS=0x344 /system/bin/rush -c 'echo parent=\$\$; $prefix $dir/script $dir/$test_case $TEST_BIN/systest$suffix; echo status=\$?'")" ||
      fail "Rush script capabilities ($test_case): launch failed"
    parent_pid="${out%%$'\n'*}"
    [[ "$parent_pid" =~ ^parent=([0-9]+)$ ]] ||
      fail "Rush script capabilities ($test_case): bad parent PID: '$out'"
    parent_pid="${BASH_REMATCH[1]}"
    body="${out#*$'\n'}"

    case "$test_case" in
      invalid-*|empty)
        expected="status=126"
        ;;
      *)
        script_pid="${body%%$'\n'*}"
        [[ "$script_pid" =~ ^script=([0-9]+)$ ]] ||
          fail "Rush script capabilities ($test_case): missing script PID: '$out'"
        script_pid="${BASH_REMATCH[1]}"
        if [ "$test_case" = default ]; then
          [ "$parent_pid" = "$script_pid" ] || fail "unrestricted script stopped running in-process"
          expected=$'mask=unset\nwrite=allowed\ndescendant=0x344\nspawn=0\nstatus=7'
        else
          [ "$parent_pid" != "$script_pid" ] || fail "explicit script mask did not create a process: '$out'"
          if [ "$test_case" = zero ]; then
            expected=$'mask=unset\nwrite=denied\nspawn=126\nstatus=7'
          else
            expected=$'mask=unset\nwrite=denied\ndescendant=0x44\nspawn=0\nstatus=7'
          fi
        fi
        expected="script=$script_pid"$'\n'"$expected"
        ;;
    esac
    [ "$body" = "$expected" ] || fail "Rush script capabilities ($test_case): '$out'"
    if [ "$test_case" = default ]; then
      [ "$(vm_ssh /system/bin/cat "$dir/$test_case")" = changed ] || fail "unrestricted script did not write"
    else
      vm_ssh "[ ! -e $dir/$test_case ]" || fail "restricted script created $dir/$test_case"
    fi
  done
  vm_ssh "/system/bin/rm -r $dir"
  echo "Rush script capabilities ($interpreter) PASS"
}

# A function runs in Rush's own process, so Rush bounds every child it starts.
test_rush_function_caps() {
  local dir="$TEST_TMP/rush-function-caps"
  local out expected
  vm_ssh "/system/bin/mkdir $dir"
  vm_ssh "/system/bin/rush -c 'cat >$dir/script'" <<'SCRIPT'
g() { "$@"; }
f() {
  "$1" print-caps plain
  unset MOTOR_OS_CAPS
  "$1" print-caps unset
  MOTOR_OS_CAPS=0x344 "$1" print-caps assigned
  export MOTOR_OS_CAPS=0x344
  "$1" print-caps exported
  MOTOR_OS_CAPS=0x4 "$1" print-caps narrowed
  command "$1" print-caps command
  (exec "$1" print-caps exec)
  "$1" print-caps pipeline | { read line; echo "$line"; }
  echo "$("$1" print-caps substitution)"
  "$1" print-caps background &
  wait
  MOTOR_OS_CAPS=0x344 g "$1" print-caps nested
}
MOTOR_OS_CAPS=0x44 f "$1"
unset MOTOR_OS_CAPS
"$1" print-caps after
MOTOR_OS_CAPS=zz f "$1"
echo invalid=$?
SCRIPT
  out="$(vm_ssh "MOTOR_OS_CAPS=0x344 /system/bin/rush $dir/script $TEST_BIN/systest")" ||
    fail "Rush function capabilities: launch failed"
  expected="plain=0x44
unset=0x44
assigned=0x44
exported=0x44
narrowed=0x4
command=0x44
exec=0x44
pipeline=0x44
substitution=0x44
background=0x44
nested=0x44
after=0x344
invalid=126"
  [ "$out" = "$expected" ] || fail "Rush function capabilities: '$out'"
  vm_ssh "/system/bin/rm -r $dir"
  echo "Rush function capabilities PASS"
}
