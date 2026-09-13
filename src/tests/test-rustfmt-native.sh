#!/usr/bin/env bash
# Exercise the packaged formatter in an already booted developer VM.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
FIXTURES="$ROOT_DIR/src/tests/rustfmt-fixtures"
temporary="$(mktemp -d)"
fail() { echo "test-rustfmt-native: $*" >&2; exit 1; }

ssh_options=(-F /dev/null -o IdentitiesOnly=yes -o BatchMode=yes
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$ROOT_DIR/src/tests/test-known-hosts"
  -i "$ROOT_DIR/src/tests/test.key")
remote() {
  ssh "${ssh_options[@]}" -p 2222 motor@192.168.4.2 "$@"
}
sftp_batch() {
  sftp "${ssh_options[@]}" -P 2222 -b - motor@192.168.4.2
}
download() {
  printf 'get "%s" "%s"\n' "$1" "$2" | sftp_batch
}

# User configuration installed on the guest is removed even when a case fails,
# so a later suite in the same VM still sees the image's formatting defaults.
guest_user_paths=()
cleanup() {
  local status=$? path
  rm -rf "$temporary"
  for path in ${guest_user_paths[@]+"${guest_user_paths[@]}"}; do
    remote "/system/bin/rm -r '$path'" || status=1
  done
  exit "$status"
}
trap cleanup EXIT

assembly_images="$("$ROOT_DIR/src/select-toolchain-assembly.sh" --resolve)"
manifest="$assembly_images/rustc/devtools/toolchain/manifest"
revision="$(sed -n 's/^effective_rust_rev=//p' "$manifest")"
version_base64="$(sed -n 's/^native_rustfmt_expected_version_base64=//p' "$manifest")"
[ "$(grep -c '^effective_rust_rev=' "$manifest")" -eq 1 ] ||
  fail 'assembly manifest lacks one effective Rust revision'
[ "$(grep -c '^native_rustfmt_expected_version_base64=' "$manifest")" -eq 1 ] ||
  fail 'assembly manifest lacks one native rustfmt version'
expected_version="$(printf '%s' "$version_base64" | base64 -d)" ||
  fail 'assembly rustfmt version is not valid base64'
[[ "$expected_version" =~ ^rustfmt\ 1\.10\.0-dev\ \(${revision:0:10}\ [0-9]{4}-[0-9]{2}-[0-9]{2}\)$ ]] ||
  fail "assembly rustfmt version does not match its effective revision: $expected_version"
actual_version="$(remote /devtools/bin/rustfmt --version)"
[ "$actual_version" = "$expected_version" ] ||
  fail "native version is '$actual_version', expected '$expected_version'"

guest_root="/devtools/tmp/rustfmt-native-$$"
in_place_dir="$guest_root/in place"
project_dir="$guest_root/project config"
user_case_dir="$guest_root/user config"
env_case_dir="$guest_root/env config"
user_config_dir=/user/cfg/rustfmt
user_home_toml=/user/rustfmt.toml
{
  printf 'mkdir "%s"\n' "$guest_root"
  printf 'mkdir "%s"\n' "$in_place_dir"
  printf 'mkdir "%s"\n' "$project_dir"
  printf 'mkdir "%s"\n' "$user_case_dir"
  printf 'mkdir "%s"\n' "$env_case_dir"
  printf 'mkdir "%s"\n' "$env_case_dir/home"
  printf 'mkdir "%s"\n' "$env_case_dir/xdg"
  printf 'mkdir "%s"\n' "$env_case_dir/xdg/rustfmt"
  printf 'put "%s" "%s"\n' "$FIXTURES/in-place.in.rs" "$in_place_dir/input.rs"
  printf 'put "%s" "%s"\n' "$FIXTURES/width.in.rs" "$project_dir/input.rs"
  printf 'put "%s" "%s"\n' "$FIXTURES/width.toml" "$project_dir/rustfmt.toml"
  printf 'put "%s" "%s"\n' "$FIXTURES/width.in.rs" "$user_case_dir/config-dir.rs"
  printf 'put "%s" "%s"\n' "$FIXTURES/width.in.rs" "$user_case_dir/home.rs"
  printf 'put "%s" "%s"\n' "$FIXTURES/width.in.rs" "$env_case_dir/input.rs"
  printf 'put "%s" "%s"\n' "$FIXTURES/width.toml" "$env_case_dir/home/rustfmt.toml"
  printf 'put "%s" "%s"\n' "$FIXTURES/width.toml" "$env_case_dir/xdg/rustfmt/rustfmt.toml"
  printf 'put "%s" "%s"\n' "$FIXTURES/edition.in.rs" "$guest_root/edition.rs"
  printf 'put "%s" "%s"\n' "$FIXTURES/macro.in.rs" "$guest_root/macro.rs"
  printf 'put "%s" "%s"\n' "$FIXTURES/lexer-error.rs" "$guest_root/lexer-error.rs"
  printf 'put "%s" "%s"\n' "$FIXTURES/parser-error.rs" "$guest_root/parser-error.rs"
} | sftp_batch
for path in "$user_home_toml" "$user_config_dir"; do
  if remote "/system/bin/ls '$path'" > /dev/null 2>&1; then
    fail "$path already exists on the guest"
  fi
done

started_ns="$(date +%s%N)"
remote /devtools/bin/rustfmt --edition 2024 < "$FIXTURES/stdin.in.rs" \
  > "$temporary/stdin.rs" 2> "$temporary/stdin.stderr"
cmp "$FIXTURES/stdin.expected.rs" "$temporary/stdin.rs" ||
  fail 'stdin formatting differs from the checked-in output'
[ ! -s "$temporary/stdin.stderr" ] || fail 'stdin formatting wrote to stderr'

remote "/devtools/bin/rustfmt --edition 2024 '$in_place_dir/input.rs'"
download "$in_place_dir/input.rs" "$temporary/in-place-first.rs"
cmp "$FIXTURES/in-place.expected.rs" "$temporary/in-place-first.rs" ||
  fail 'in-place formatting in a spaced directory differs'
remote "/devtools/bin/rustfmt --edition 2024 '$in_place_dir/input.rs'"
download "$in_place_dir/input.rs" "$temporary/in-place-second.rs"
cmp "$temporary/in-place-first.rs" "$temporary/in-place-second.rs" ||
  fail 'a second in-place run changed the file'

remote "TMPDIR=/devtools/tmp /devtools/rust/bin/rustfmt --edition 2024 '$project_dir/input.rs'"
download "$project_dir/input.rs" "$temporary/project-width.rs"
cmp "$FIXTURES/width.expected.rs" "$temporary/project-width.rs" ||
  fail 'project rustfmt.toml was not honored'

# Motor's user configuration lives at fixed paths under /user (see
# docs/toolchain.md); HOME and XDG_CONFIG_HOME are not consulted.
printf 'mkdir "%s"\nput "%s" "%s"\n' "$user_config_dir" "$FIXTURES/width.toml" \
  "$user_config_dir/rustfmt.toml" | sftp_batch
guest_user_paths=("$user_config_dir")
remote "/devtools/bin/rustfmt --edition 2024 '$user_case_dir/config-dir.rs'"
download "$user_case_dir/config-dir.rs" "$temporary/config-dir-width.rs"
cmp "$FIXTURES/width.expected.rs" "$temporary/config-dir-width.rs" ||
  fail '/user/cfg/rustfmt/rustfmt.toml was not honored'
remote "/system/bin/rm -r '$user_config_dir'"
guest_user_paths=()

printf 'put "%s" "%s"\n' "$FIXTURES/width.toml" "$user_home_toml" | sftp_batch
guest_user_paths=("$user_home_toml")
remote "/devtools/bin/rustfmt --edition 2024 '$user_case_dir/home.rs'"
download "$user_case_dir/home.rs" "$temporary/home-width.rs"
cmp "$FIXTURES/width.expected.rs" "$temporary/home-width.rs" ||
  fail '/user/rustfmt.toml was not honored'
remote "/system/bin/rm '$user_home_toml'"
guest_user_paths=()

remote "TMPDIR=/devtools/tmp HOME='$env_case_dir/home' XDG_CONFIG_HOME='$env_case_dir/xdg' /devtools/rust/bin/rustfmt --edition 2024 '$env_case_dir/input.rs'"
download "$env_case_dir/input.rs" "$temporary/env-width.rs"
cmp "$FIXTURES/width.default.expected.rs" "$temporary/env-width.rs" ||
  fail 'HOME or XDG_CONFIG_HOME changed configuration discovery'

edition_status=0
remote "/devtools/bin/rustfmt --edition 2015 '$guest_root/edition.rs'" \
  > "$temporary/edition-2015.stdout" 2> "$temporary/edition-2015.stderr" || edition_status="$?"
[ "$edition_status" -eq 1 ] || fail "edition 2015 returned $edition_status instead of 1"
grep -qi error "$temporary/edition-2015.stderr" || fail 'edition 2015 emitted no error'
remote "/devtools/bin/rustfmt --edition 2024 '$guest_root/edition.rs'"
download "$guest_root/edition.rs" "$temporary/edition.rs"
cmp "$FIXTURES/edition.expected.rs" "$temporary/edition.rs" ||
  fail 'edition 2024 formatting differs'

remote "/devtools/bin/rustfmt --edition 2024 '$guest_root/macro.rs'"
download "$guest_root/macro.rs" "$temporary/macro.rs"
cmp "$FIXTURES/macro.expected.rs" "$temporary/macro.rs" ||
  fail 'speculatively parsed macro formatting differs'

for kind in lexer parser; do
  expected_status=1
  [ "$kind" = lexer ] && expected_status=101
  status=0
  remote "/devtools/bin/rustfmt --edition 2024 '$guest_root/$kind-error.rs'" \
    > "$temporary/$kind.stdout" 2> "$temporary/$kind.stderr" || status="$?"
  [ "$status" -eq "$expected_status" ] ||
    fail "$kind error returned $status instead of $expected_status"
  grep -qi error "$temporary/$kind.stderr" || fail "$kind error emitted no diagnostic"
  download "$guest_root/$kind-error.rs" "$temporary/$kind-after.rs"
  cmp "$FIXTURES/$kind-error.rs" "$temporary/$kind-after.rs" ||
    fail "$kind error changed its input file"
  remote /devtools/bin/rustfmt --edition 2024 < "$FIXTURES/stdin.in.rs" \
    > "$temporary/$kind-recovery.rs"
  cmp "$FIXTURES/stdin.expected.rs" "$temporary/$kind-recovery.rs" ||
    fail "valid formatting did not recover after $kind error"
done

elapsed_ms="$((($(date +%s%N) - started_ns) / 1000000))"
remote "/system/bin/rm -r '$guest_root'"
echo "test-rustfmt-native PASS; elapsed_ms=$elapsed_ms"
