# Guest test directories, shared by the VM harnesses (docs/fs-permissions.md).
#
# The development image ships its test binaries in /devtools/tests. The
# standard image gets them staged below /none/tmp, so None-role children can
# run them. Interactive scratch lives in /user/tmp, which None cannot reach;
# fixtures that a None-role child must open go in NONE_TEST_TMP.

if [ "${FULL_TEST_VERIFY_DEV_SOURCES:-0}" = "1" ]; then
  MOTOR_TEST_ROOT=/devtools
else
  MOTOR_TEST_ROOT=/none/tmp/motor-tests
fi
TEST_BIN="$MOTOR_TEST_ROOT/tests"
TEST_TMP=/user/tmp/motor-tests
NONE_TEST_ROOT=/none/tmp/motor-tests
NONE_TEST_TMP="$NONE_TEST_ROOT/tmp"
MOTOR_TEST_TMP="$TEST_TMP"
MOTOR_NONE_TEST_TMP="$NONE_TEST_TMP"
export MOTOR_TEST_ROOT MOTOR_TEST_TMP MOTOR_NONE_TEST_TMP

# Removes an earlier run's directories. The arguments run one guest command.
remove_test_roots() {
  local dir
  for dir in "$TEST_TMP" "$NONE_TEST_ROOT"; do
    if "$@" "[ -e $dir ]"; then
      echo "removing the leftover $dir"
      "$@" "/system/bin/rm -r $dir" || fail "cannot remove the leftover $dir"
    fi
  done
}

# sftp batch lines that create this run's directories. A batch stops at the
# first failed mkdir, so every directory is new: one that None created first
# would be writable by None.
test_root_mkdirs() {
  printf 'mkdir %s\n' "$TEST_TMP" "$NONE_TEST_ROOT" "$NONE_TEST_TMP"
  [ "$TEST_BIN" = /devtools/tests ] || printf 'mkdir %s\n' "$TEST_BIN"
}
