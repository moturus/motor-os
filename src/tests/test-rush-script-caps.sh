# Native Rush capability regressions. Sourced by full-test.sh.

test_rush_script_caps() {
  local interpreter="$1"
  local dir="$TEST_TMP/rush-script-caps-$interpreter"
  local test_case prefix suffix out status expected body parent_pid script_pid
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
      # Also exercise exec's emulated exit inside a subshell.
      exec) prefix="(MOTOR_OS_CAPS=0x44 exec" suffix=")" ;;
      function) prefix="f() { unset MOTOR_OS_CAPS; \"\$@\"; }; MOTOR_OS_CAPS=0x44 f" ;;
      function-raise) prefix="f() { MOTOR_OS_CAPS=0x344 \"\$@\"; }; MOTOR_OS_CAPS=0x44 f" ;;
    esac
    # The parent has Interactive, spawn, network and FS-write authority.
    # The restricted script must not regain the latter two by unsetting its mask.
    if out="$(vm_ssh "MOTOR_OS_CAPS=0x344 /system/bin/rush -c 'echo parent=\$\$; $prefix $dir/script $dir/$test_case $TEST_BIN/systest$suffix'")"; then
      status=0
    else
      status=$?
    fi
    out+=$'\n'"status=$status"
    parent_pid="${out%%$'\n'*}"
    [[ "$parent_pid" =~ ^parent=([0-9]+)$ ]] ||
      fail "Rush script capabilities ($test_case): bad parent PID: '$out'"
    parent_pid="${BASH_REMATCH[1]}"
    body="${out#*$'\n'}"

    case "$test_case" in
      invalid-*|empty|function*)
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

# One SSH run observes isolated child shells; exports cannot poison the observer.
test_rush_inproc_caps() {
  local dir="$TEST_TMP/rush-inproc-caps"
  local mode kind prefix setup definitions invocation expected out
  vm_ssh "/system/bin/mkdir $dir"
  {
    cat <<'SCRIPT'
dir=$1
probe=$2
count=0
cat >"$dir/body" <<'BODY'
echo entered > "$target"
unset MOTOR_OS_CAPS
"$probe" print-caps escaped
BODY
check() {
  label=$1
  expected_status=$2
  expected_output=$3
  expected_error=$4
  actual_output=$(MOTOR_OS_CAPS=0x344 /system/bin/rush -c "$5" 2>"$dir/error")
  actual_status=$?
  actual_error=$(cat "$dir/error")
  if [ "$actual_status" != "$expected_status" ] || [ "$actual_output" != "$expected_output" ]; then
    echo "FAIL $label: status=$actual_status output=[$actual_output] error=[$actual_error]"
    exit 1
  fi
  case "$actual_error" in
    *"$expected_error"*) ;;
    *) echo "FAIL $label: missing diagnostic [$expected_error]: $actual_error"; exit 1 ;;
  esac
  if [ -e "$dir/body-effect" ] || [ -e "$dir/redirect" ] || [ -e "$dir/function-redirect" ]; then
    echo "FAIL $label: side effects before refusal"
    exit 1
  fi
  count=$((count + 1))
}
SCRIPT
    for mode in assigned exported; do
      prefix="MOTOR_OS_CAPS=0x44"
      setup=""
      if [ "$mode" = exported ]; then
        prefix=""
        setup="export MOTOR_OS_CAPS=0x44;"
      fi
      for kind in function eval source builtin alias command command-source nested-command \
        inspect exec pipeline background substitution redirection compound subshell shadow-command \
        exit return break continue wait unset trap if for while; do
        definitions=""
        expected=126
        if [ "$mode" = assigned ] && [[ "$kind" = compound || "$kind" = subshell || "$kind" = if || "$kind" = for || "$kind" = while ]]; then
          continue # Assignments cannot syntactically precede compounds.
        fi
        case "$kind" in
          function) invocation="$prefix f > $dir/redirect" ;;
          eval) invocation="$prefix eval f > $dir/redirect" ;;
          source) invocation="$prefix . $dir/body > $dir/redirect" ;;
          builtin) invocation="$prefix echo entered > $dir/redirect" ;;
          alias) invocation="$prefix guarded > $dir/redirect" ;;
          command) invocation="$prefix command -- echo entered > $dir/redirect" ;;
          command-source) invocation="$prefix command -p . $dir/body > $dir/redirect" ;;
          nested-command) invocation="$prefix command command eval f > $dir/redirect" ;;
          inspect) invocation="$prefix command -v f > $dir/redirect" ;;
          exec) invocation="$prefix exec > $dir/redirect" ;;
          pipeline) invocation="$prefix f > $dir/redirect | /system/bin/rush -c :" ;;
          background)
            invocation="$prefix f > $dir/redirect &"
            if [ "$mode" = assigned ]; then invocation+=" wait %1"; else expected=0; fi
            ;;
          substitution) invocation="result=\$($prefix f > $dir/redirect)" ;;
          redirection) invocation="$prefix > $dir/redirect" ;;
          compound) invocation="{ f; } > $dir/redirect" ;;
          subshell) invocation="(f) > $dir/redirect" ;;
          shadow-command)
            definitions="command() { f; };"
            invocation="$prefix command /system/bin/sh > $dir/redirect"
            ;;
          exit|return|break|continue|wait) invocation="$prefix $kind" ;;
          unset) invocation="$prefix unset MOTOR_OS_CAPS" ;;
          trap) invocation="$prefix trap : EXIT" ;;
          if) invocation="if true; then f; fi" ;;
          for) invocation="for x in a; do f; done" ;;
          while) invocation="while false; do f; done" ;;
        esac
        printf "check '%s/%s' %s '' 'requires a child process' '%s'\n" \
          "$mode" "$kind" "$expected" \
          "probe=$TEST_BIN/systest; target=$dir/body-effect; f() { . $dir/body; } > $dir/function-redirect; alias guarded=f; set -o pipefail; $definitions $setup $invocation"
      done
    done
    cat <<'SCRIPT'
for mask in 0 "" zz; do
  check "mask=$mask" 126 "" "requires a child process" \
    "f() { echo entered; }; MOTOR_OS_CAPS=$mask f"
done
check exported-exit 0 "after-exit=0x44" "rush: exit:" \
  "export MOTOR_OS_CAPS=0x44; exit 23; $probe print-caps after-exit"
check exported-exit-trap 0 "" "rush: echo:" \
  "trap \"echo entered >$dir/body-effect\" EXIT; export MOTOR_OS_CAPS=0x44"
for masks in "0x44 0x344" "0x344 0x44"; do
  set -- $masks
  check "exec-background/$masks" 0 "requested=$2
later=$1" "" \
    "export MOTOR_OS_CAPS=$1; MOTOR_OS_CAPS=$2 exec $probe print-caps requested & $probe print-caps later"
  check "exec-substitution/$masks" 0 "later=$1" "" \
    "export MOTOR_OS_CAPS=$1; result=\$(MOTOR_OS_CAPS=$2 exec $probe print-caps requested); $probe print-caps later"
done
for mask in 0x44 0x244; do
  status=2
  piped=""
  substituted=""
  error="rush:"
  if [ "$mask" = 0x244 ]; then status=0; piped=b; substituted=hi; error=""; fi
  check "pipeline/$mask" "$status" "$piped" "$error" \
    "MOTOR_OS_CAPS=$mask /system/bin/sh -c 'printf \"a\\nb\\n\" | /system/bin/rg \"^b$\"'"
  check "substitution/$mask" "$status" "" "$error" \
    "MOTOR_OS_CAPS=$mask /system/bin/sh -c 'x=\$(printf hi)'"
  check "substitution-errexit/$mask" "$status" "$substituted" "$error" \
    "MOTOR_OS_CAPS=$mask /system/bin/sh -c 'set -e; x=\$(printf hi); echo \"\$x\"'"
done
cat >"$dir/inside" <<'BODY'
#!/system/bin/sh
f() { "$1" print-caps inside; }
unset MOTOR_OS_CAPS
eval 'f "$1"'
MOTOR_OS_CAPS=0x344 "$1" print-caps forbidden
echo upward=$?
BODY
chmod rwxr-xr-x "$dir/inside" || exit 1
check reduced-sh 0 "inside=0x44
upward=126" "permission denied" "MOTOR_OS_CAPS=0x44 /system/bin/sh $dir/inside $probe"
check script-diagnostic 126 "" "rush: $dir/inside:" "MOTOR_OS_CAPS=zz $dir/inside $probe"
echo "Rush in-process capabilities PASS ($count cases)"
SCRIPT
  } | vm_ssh "/system/bin/rush -c 'cat >$dir/checks'"
  out="$(vm_ssh "/system/bin/rush $dir/checks $dir $TEST_BIN/systest")" || fail "$out"
  [[ "$out" =~ ^Rush\ in-process\ capabilities\ PASS\ \([0-9]+\ cases\)$ ]] || fail "$out"
  vm_ssh "/system/bin/rm -r $dir"
  echo "$out"
}
