#!/usr/bin/env bash
# Exercise the pinned Gitoxide fork on the host or an already booted Motor VM.
set -euo pipefail
unset GIT_INDEX_FILE GIT_AUTHOR_DATE GIT_COMMITTER_DATE

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
WD="$ROOT_DIR/src/tests"
APP_DIR="$ROOT_DIR/src/bin/gix"
mode="${1:-}"
[ "$#" -eq 1 ] && { [ "$mode" = --host ] || [ "$mode" = --guest ]; } ||
  { echo "usage: $0 --host|--guest" >&2; exit 2; }

temporary="$(mktemp -d)"
guest_root=
guest_created=0
policy_head_id=
fail() { echo "test-gix: $*" >&2; exit 1; }
cleanup() {
  local status=$?
  rm -rf "$temporary"
  if [ "$guest_created" -eq 1 ]; then
    vm_ssh /system/bin/rm -r "$guest_root" || status=1
  fi
  exit "$status"
}
trap cleanup EXIT

fixture="$temporary/fixture"
mkdir -p "$temporary/home" "$temporary/xdg" "$temporary/template"
clean_git() {
  local git_env=(
    env -i "PATH=$PATH" "HOME=$temporary/home"
    "XDG_CONFIG_HOME=$temporary/xdg" GIT_CONFIG_NOSYSTEM=1
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
    "GIT_TEMPLATE_DIR=$temporary/template"
  )
  if [ -n "${GIT_AUTHOR_DATE:-}" ]; then
    git_env+=("GIT_AUTHOR_DATE=$GIT_AUTHOR_DATE" "GIT_COMMITTER_DATE=$GIT_COMMITTER_DATE")
  fi
  if [ -n "${GIT_INDEX_FILE:-}" ]; then
    git_env+=("GIT_INDEX_FILE=$GIT_INDEX_FILE")
  fi
  "${git_env[@]}" git -c core.hooksPath=/dev/null "$@"
}
git_fixture() {
  clean_git -C "$fixture" "$@"
}
build_fixture() {
  local initial_id link_id utf8_name
  utf8_name=$'caf\xc3\xa9'
  clean_git init -q --initial-branch=main "$fixture"
  git_fixture config user.name "Motor Test"
  git_fixture config user.email motor-test@example.invalid
  printf 'first\n' > "$fixture/editable"
  printf 'utf8\n' > "$fixture/$utf8_name"
  git_fixture add editable "$utf8_name"
  git_fixture update-index --chmod=+x editable
  link_id="$(printf editable | git_fixture hash-object -w --stdin)"
  git_fixture update-index --add --cacheinfo "120000,$link_id,link"
  GIT_AUTHOR_DATE=2001-01-01T00:00:00Z GIT_COMMITTER_DATE=2001-01-01T00:00:00Z git_fixture commit -qm initial
  initial_id="$(git_fixture rev-parse HEAD)"
  printf 'other\n' > "$fixture/editable"
  git_fixture add editable
  git_fixture update-index --chmod=+x editable
  git_fixture update-index --add --cacheinfo "160000,$initial_id,nested"
  GIT_AUTHOR_DATE=2001-01-02T00:00:00Z GIT_COMMITTER_DATE=2001-01-02T00:00:00Z git_fixture commit -qm second
  git_fixture commit-graph write --reachable
  git_fixture pack-refs --all
  git_fixture repack -adq
  git_fixture prune-packed
  git_fixture fsck --strict
  [ "$(git_fixture count-objects -v | sed -n 's/^count: //p')" = 0 ] ||
    fail "fixture contains loose objects"
  # Motor represents indexed symlinks as ordinary files containing the link text.
  printf editable > "$fixture/link"
}
build_fixture
git_fixture log --format='%h %s' --abbrev=12 > "$temporary/expected.log"
prepare_user_config() {
  mkdir -p "$temporary/xdg/git" "$temporary/fake-bin"
  printf '[core]\n\tabbrev = 6\n' > "$temporary/xdg/git/config"
  printf '[core]\n\tabbrev = 9\n' > "$temporary/included.gitconfig"
  printf '[merge "path-only"]\n\tdriver = must-not-run\n' \
    > "$temporary/command-only.gitconfig"
  printf '[core]\n\tabbrev = 8\n[include]\n\tpath = %s\n\tpath = %s\n' \
    "$temporary/included.gitconfig" "$temporary/command-only.gitconfig" \
    > "$temporary/home/.gitconfig"
  cat > "$temporary/fake-bin/git" <<'SH'
#!/bin/sh
: > "$GIX_FAKE_GIT_SENTINEL"
exit 97
SH
  cat > "$temporary/fake-bin/filter" <<'SH'
#!/bin/sh
: > "$GIX_FILTER_SENTINEL"
exit 97
SH
  chmod +x "$temporary/fake-bin/git" "$temporary/fake-bin/filter"
}
prepare_policy_fixture() {
  local parent_id
  git_fixture config core.abbrev 7
  git_fixture config core.useReplaceRefs false
  policy_head_id="$(git_fixture rev-parse HEAD)"
  parent_id="$(git_fixture rev-parse HEAD^)"
  mkdir -p "$fixture/.git/refs/replace"
  printf '%s\n' "$parent_id" > "$fixture/.git/refs/replace/$policy_head_id"
  printf '%s\n' "$policy_head_id" > "$fixture/.git/info/grafts"
}
verify_log() {
  cmp "$temporary/expected.log" "$1" >/dev/null ||
    fail "gix log differs from the clean host Git result"
}
verify_index() {
  local actual expected
  expected="$(git_fixture rev-parse 'HEAD^{tree}')"
  actual="$(GIT_INDEX_FILE="$1" git_fixture write-tree)"
  [ "$actual" = "$expected" ] || fail "written index does not reproduce fixture tree"
}

cargo="$(cd "$ROOT_DIR" && rustup which cargo)"
export RUSTC="$(cd "$ROOT_DIR" && rustup which rustc)"
export RUSTDOC="$(cd "$ROOT_DIR" && rustup which rustdoc)"
common=(--manifest-path "$APP_DIR/Cargo.toml" --release --locked --offline
  --target-dir "$APP_DIR/target/component-test")

if [ "$mode" = --host ]; then
  "$cargo" test "${common[@]}" --lib
  metadata="$temporary/metadata.json"
  "$cargo" metadata --manifest-path "$APP_DIR/Cargo.toml" --locked --offline \
    --format-version 1 --filter-platform x86_64-unknown-linux-gnu > "$metadata"
  fork_manifest="$(python3 - "$metadata" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
root = next(package for package in data["packages"] if package["id"] == data["resolve"]["root"])
direct = [dependency for dependency in root["dependencies"] if dependency["name"] == "gix"]
if len(direct) != 1:
    raise SystemExit("direct gix dependency was not found exactly once")
prefix = "git+https://github.com/moturus/gitoxide.git?rev="
source = direct[0].get("source", "")
revision = source.removeprefix(prefix)
if not source.startswith(prefix) or len(revision) != 40 or not all(c in "0123456789abcdef" for c in revision):
    raise SystemExit("direct gix dependency is not pinned to the Motor fork")
packages = [
    package for package in data["packages"]
    if package["name"] == "gix" and package.get("source") == source + "#" + revision
]
if len(packages) != 1:
    raise SystemExit("resolved gix revision does not match the direct pin")
print(pathlib.Path(packages[0]["manifest_path"]).parent.parent / "Cargo.toml")
PY
)"
  external=(--manifest-path "$fork_manifest" --release --locked --offline
    --target-dir "$APP_DIR/target/component-test/external")
  "$cargo" test "${external[@]}" -p gix-motor-filetime \
    system_times_are_normalized_and_ordered
  "$cargo" test "${external[@]}" -p gix-index --features sha1 --test index \
    an_index_shorter_than_its_checksum_is_rejected
  "$cargo" test "${external[@]}" -p gix-pack --features sha1 --test pack \
    iter::new_from_header::
  "$cargo" test "${common[@]}" --test native-port -- \
    "$fixture" "$temporary/host-output"
  verify_index "$temporary/host-output/written.index"

  "$cargo" build "${common[@]}" --bin gix
  gix_binary="$APP_DIR/target/component-test/release/gix"
  prepare_user_config
  prepare_policy_fixture
  app_env=(
    env -i "PATH=$temporary/fake-bin:$PATH" "HOME=$temporary/home"
    "XDG_CONFIG_HOME=$temporary/xdg"
    "GIX_FAKE_GIT_SENTINEL=$temporary/git-invoked"
    "GIX_FILTER_SENTINEL=$temporary/filter-invoked"
  )
  "${app_env[@]}" "$gix_binary" -r "$fixture" -c core.abbrev=12 \
    --config-paths log > "$temporary/log.out" 2> "$temporary/config-paths.out"
  verify_log "$temporary/log.out"
  for config_path in "$temporary/xdg/git/config" "$temporary/home/.gitconfig" \
    "$temporary/included.gitconfig" "$temporary/command-only.gitconfig" \
    "$fixture/.git/config"; do
    grep -F "$config_path" "$temporary/config-paths.out" >/dev/null ||
      fail "configuration path was not reported: $config_path"
  done
  for variable in GIT_INDEX_FILE GIT_WORK_TREE; do
    if "${app_env[@]}" "$variable=$temporary/unselected" \
      "$gix_binary" -r "$fixture" log \
      > "$temporary/$variable.out" 2> "$temporary/$variable.err"; then
      fail "$variable override was accepted"
    fi
    grep -F "$variable is not supported" "$temporary/$variable.err" >/dev/null ||
      fail "$variable rejection was not reported"
  done
  git_fixture config gitoxide.core.indexFile "$temporary/unselected-index"
  if "${app_env[@]}" "$gix_binary" -r "$fixture" log \
    > "$temporary/config-index.out" 2> "$temporary/config-index.err"; then
    fail "repository index override was accepted"
  fi
  grep -F "repository configuration selected a different index" \
    "$temporary/config-index.err" >/dev/null || fail "repository index rejection was not reported"
  git_fixture config --unset gitoxide.core.indexFile
  "${app_env[@]}" python3 - "$gix_binary" "$fixture" <<'PY'
import os
import subprocess
import sys

read_fd, write_fd = os.pipe()
os.close(read_fd)
try:
    result = subprocess.run(
        [sys.argv[1], "-r", sys.argv[2], "log"],
        stdout=write_fd,
        stderr=subprocess.PIPE,
        check=False,
    )
finally:
    os.close(write_fd)
if result.returncode == 0:
    raise SystemExit("closed stdout was reported as success")
if b"Broken pipe" not in result.stderr or b"panicked" in result.stderr:
    raise SystemExit(f"unexpected broken-pipe diagnostic: {result.stderr!r}")
PY

  printf 'editable filter=blocked\n' > "$fixture/.git/info/attributes"
  git_fixture config filter.blocked.clean "$temporary/fake-bin/filter"
  git_fixture config filter.blocked.required true
  if "${app_env[@]}" "$gix_binary" -r "$fixture" status \
    > "$temporary/filter-status.out" 2> "$temporary/filter-status.err"; then
    fail "status accepted a required external filter"
  fi
  grep -F "tracked path 'editable' uses unsupported filter 'blocked'" \
    "$temporary/filter-status.err" >/dev/null || fail "filter rejection was not reported"
  [ ! -e "$temporary/filter-invoked" ] || fail "status invoked an external filter"
  git_fixture config --unset-all filter.blocked.clean
  git_fixture config --unset-all filter.blocked.required
  printf '\n[filter "required-only"]\n\trequired\n' >> "$fixture/.git/config"
  printf 'editable filter=required-only\n' > "$fixture/.git/info/attributes"
  if "${app_env[@]}" "$gix_binary" -r "$fixture" status \
    > "$temporary/required-status.out" 2> "$temporary/required-status.err"; then
    fail "status accepted an implicit required filter"
  fi
  grep -F "unsupported filter 'required-only'" "$temporary/required-status.err" >/dev/null ||
    fail "implicit required filter rejection was not reported"
  git_fixture config --remove-section filter.required-only
  rm "$fixture/.git/info/attributes"

  printf 'staged\n' > "$fixture/editable"
  git_fixture add editable
  printf 'unstaged\n' > "$fixture/editable"
  git_fixture rm --cached -q link
  printf 'untracked\n' > "$fixture/untracked"
  : > "$fixture/.git/MERGE_HEAD"
  cat > "$temporary/expected.status" <<'EOF'
operation merge
MM editable
D? link
?? untracked
EOF
  index_before="$(sha256sum "$fixture/.git/index")"
  "${app_env[@]}" "$gix_binary" -r "$fixture" status > "$temporary/status.out"
  cmp "$temporary/expected.status" "$temporary/status.out" >/dev/null ||
    fail "gix status output differs from the expected state"
  [ "$(sha256sum "$fixture/.git/index")" = "$index_before" ] ||
    fail "gix status modified the source index"
  [ ! -e "$temporary/git-invoked" ] || fail "repository open invoked installed Git"
  echo "test-gix host PASS"
  exit
fi

. "$WD/vm-test-boot.sh"
test_vm_configure_ssh
assembly_images="$("$ROOT_DIR/src/select-toolchain-assembly.sh" --resolve)"
linker="${assembly_images%/images}/sysroot/bin/motor-clang"
messages="$temporary/cargo-messages.json"
native_env=(
  "CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER=$linker"
  "CARGO_TARGET_X86_64_UNKNOWN_MOTOR_RUSTFLAGS=-C link-self-contained=no -C default-linker-libraries=yes"
)
env "${native_env[@]}" "$cargo" build "${common[@]}" \
  --target x86_64-unknown-motor --bin gix --test native-port \
  --message-format json-render-diagnostics > "$messages"
artifact_paths="$(python3 - "$messages" <<'PY'
import json
import pathlib
import sys

targets = {"native-port": [], "gix": []}
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    message = json.loads(line)
    if message.get("reason") != "compiler-artifact" or not message.get("executable"):
        continue
    name = message["target"]["name"]
    kind = message["target"]["kind"]
    if name == "native-port" and kind == ["test"]:
        targets[name].append(message["executable"])
    elif name == "gix" and kind == ["bin"]:
        targets[name].append(message["executable"])
for name in ["native-port", "gix"]:
    if len(targets[name]) != 1:
        raise SystemExit(f"{name} executable was not found exactly once")
    print(targets[name][0])
PY
)"
mapfile -t executables <<< "$artifact_paths"
[ "${#executables[@]}" -eq 2 ] || fail "native executables were not found"
native_port_binary="${executables[0]}"
gix_binary="${executables[1]}"

guest_root="/devtools/tmp/gix-test-$$"
vm_ssh /system/bin/mkdir "$guest_root"
guest_created=1
vm_ssh /system/bin/mkdir "$guest_root/fixture"
vm_ssh /system/bin/mkdir "$guest_root/home"
vm_ssh /system/bin/mkdir "$guest_root/xdg"
sftp_command=(
  sftp -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts"
  -i "$WD/test.key" -b - motor@192.168.4.2
)
{
  printf 'put "%s" "%s"\n' "$native_port_binary" "$guest_root/native-port"
  printf 'chmod 755 "%s"\n' "$guest_root/native-port"
  printf 'put "%s" "%s"\n' "$gix_binary" "$guest_root/gix"
  printf 'chmod 755 "%s"\n' "$guest_root/gix"
  printf 'put -r "%s" "%s"\n' "$fixture/.git" "$guest_root/fixture"
} | "${sftp_command[@]}"
vm_ssh "$guest_root/native-port" "$guest_root/fixture" "$guest_root/output"
printf 'get "%s" "%s"\n' "$guest_root/output/written.index" "$temporary/guest.index" |
  "${sftp_command[@]}"
verify_index "$temporary/guest.index"

prepare_policy_fixture
vm_ssh /system/bin/mkdir "$guest_root/fixture/.git/refs/replace"
{
  printf 'put "%s" "%s"\n' "$fixture/.git/config" "$guest_root/fixture/.git/config"
  printf 'put "%s" "%s"\n' \
    "$fixture/.git/refs/replace/$policy_head_id" "$guest_root/fixture/.git/refs/replace/$policy_head_id"
  printf 'put "%s" "%s"\n' "$fixture/.git/info/grafts" "$guest_root/fixture/.git/info/grafts"
} | "${sftp_command[@]}"
vm_ssh \
  "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_root/gix -r $guest_root/fixture -c core.abbrev=12 log" \
  > "$temporary/guest.log"
verify_log "$temporary/guest.log"
vm_ssh /system/bin/mv "$guest_root/fixture/.git" "$guest_root/output/worktree/.git"
printf 'UTF8\n' > "$temporary/native-edit"
printf 'put "%s" "%s"\n' \
  "$temporary/native-edit" "$guest_root/output/worktree/café" | "${sftp_command[@]}"
vm_ssh \
  "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_root/gix -r $guest_root/output/worktree status" \
  > "$temporary/guest.status"
cat > "$temporary/expected-guest.status" <<'EOF'
 M café
EOF
cmp "$temporary/expected-guest.status" "$temporary/guest.status" >/dev/null ||
  fail "native gix status output differs from the expected state"
printf 'get "%s" "%s"\n' "$guest_root/output/worktree/.git/index" "$temporary/guest-source.index" |
  "${sftp_command[@]}"
cmp "$fixture/.git/index" "$temporary/guest-source.index" >/dev/null ||
  fail "native gix status modified the source index"
echo "test-gix guest PASS"
