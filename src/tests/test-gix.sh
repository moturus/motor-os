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
https_pid=
https_out_fd=
gix_pty_pid=
gix_pty_out=
gix_pty_in=
fail() { echo "test-gix: $*" >&2; exit 1; }
cleanup() {
  local status=$? server_status=0
  if [ -n "$gix_pty_pid" ]; then
    kill "$gix_pty_pid" 2>/dev/null || :
    wait "$gix_pty_pid" 2>/dev/null || :
  fi
  [ -z "$gix_pty_in" ] || exec {gix_pty_in}>&-
  [ -z "$gix_pty_out" ] || exec {gix_pty_out}<&-
  if [ -n "$https_pid" ]; then
    kill "$https_pid" 2>/dev/null || status=1
    wait "$https_pid" 2>/dev/null || server_status=$?
    [ "$server_status" -eq 143 ] || status=1
  fi
  rm -rf "$temporary"
  if [ "$guest_created" -eq 1 ]; then
    vm_ssh /system/bin/rm -r "$guest_root" || status=1
  fi
  exit "$status"
}
trap cleanup EXIT

wait_https_line() {
  local expected="$1" line remaining deadline=$((SECONDS + 20))
  while [ "$SECONDS" -lt "$deadline" ]; do
    remaining=$((deadline - SECONDS))
    IFS= read -r -t "$remaining" line <&"$https_out_fd" || break
    printf '%s\n' "$line" >> "$temporary/https-server.stdout"
    [[ "$line" == "$expected"* ]] && { HTTPS_LINE="$line"; return; }
  done
  fail "HTTPS server did not print '$expected': $(cat "$temporary/https-server.stderr")"
}
start_https_server() {
  local bind="$1" name="$2"
  coproc HTTPS_SERVER {
    exec "$https_server" "$https_remote" "$temporary/https-server-work" "$bind" \
      </dev/null 2> "$temporary/https-server.stderr"
  }
  https_pid="$HTTPS_SERVER_PID"
  exec {https_out_fd}<&"${HTTPS_SERVER[0]}"
  wait_https_line HTTPS_READY=
  https_port="${HTTPS_LINE#HTTPS_READY=}"
  case "$https_port" in "" | *[!0-9]*) fail "invalid HTTPS server port: $https_port" ;; esac
  [ "$https_port" -ge 1 ] && [ "$https_port" -le 65535 ] ||
    fail "invalid HTTPS server port: $https_port"
  https_origin="https://$name:$https_port"
}
stop_https_server() {
  local spontaneous=0 server_status=0
  kill -0 "$https_pid" 2>/dev/null || spontaneous=1
  [ "$spontaneous" -eq 1 ] || kill "$https_pid"
  set +e
  wait "$https_pid"
  server_status=$?
  set -e
  exec {https_out_fd}<&-
  https_pid=
  [ "$spontaneous" -eq 0 ] || fail "HTTPS server exited spontaneously"
  [ "$server_status" -eq 143 ] || fail "HTTPS server stopped with status $server_status"
  [ ! -s "$temporary/https-server.stderr" ] ||
    fail "HTTPS server wrote stderr: $(cat "$temporary/https-server.stderr")"
}

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
advance_https_remote() {
  local update="$temporary/https-update"
  clean_git clone -q --no-hardlinks "$https_remote" "$update"
  clean_git -C "$update" config user.name "Motor Test"
  clean_git -C "$update" config user.email motor-test@example.invalid
  printf 'remote update\n' > "$update/remote-only"
  clean_git -C "$update" add remote-only
  GIT_AUTHOR_DATE=2001-01-03T00:00:00Z GIT_COMMITTER_DATE=2001-01-03T00:00:00Z \
    clean_git -C "$update" commit -qm remote-update
  clean_git -C "$update" push -q origin main
}
verify_https_clone() {
  local before="$1" after="$2" initial remote initial_index
  initial="$(clean_git -C "$before" rev-parse HEAD)"
  remote="$(clean_git --git-dir="$https_remote" rev-parse refs/heads/main)"
  [ "$initial" = "$https_initial_head" ] || fail "initial HTTPS clone has the wrong HEAD"
  [ "$(clean_git -C "$before" rev-parse refs/remotes/origin/main)" = "$https_initial_head" ] ||
    fail "initial HTTPS clone has the wrong tracking ref"
  initial_index="$(sha256sum "$before/.git/index")"
  clean_git -C "$before" -c core.symlinks=false diff-index --cached --quiet \
    --ignore-submodules=all "$https_initial_head" -- || fail "initial HTTPS index differs from HEAD"
  # Copying changes stat data; inspect Git's content/mode diff without refreshing the index.
  clean_git -C "$before" -c core.symlinks=false -c core.fileMode=true \
    diff-files -p --no-ext-diff --no-textconv --ignore-submodules=all -- \
    > "$temporary/https-worktree.diff"
  [ ! -s "$temporary/https-worktree.diff" ] || fail "initial HTTPS worktree differs from the index"
  [ "$(sha256sum "$before/.git/index")" = "$initial_index" ] ||
    fail "host Git verification modified the initial HTTPS index"
  [ "$remote" != "$initial" ] || fail "HTTPS remote did not advance"
  [ "$(clean_git -C "$after" rev-parse HEAD)" = "$initial" ] ||
    fail "fetch changed the checked-out HTTPS branch"
  [ "$(clean_git -C "$after" rev-parse refs/remotes/origin/main)" = "$remote" ] ||
    fail "fetch did not advance origin/main"
  cmp "$before/.git/index" "$after/.git/index" >/dev/null || fail "fetch changed the index"
  diff -r --exclude=.git "$before" "$after" >/dev/null || fail "fetch changed the worktree"
  clean_git -C "$after" fsck --strict
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
  git_fixture commit-graph write --reachable --split=no-merge
  printf 'other\n' > "$fixture/editable"
  git_fixture add editable
  git_fixture update-index --chmod=+x editable
  git_fixture update-index --add --cacheinfo "160000,$initial_id,nested"
  GIT_AUTHOR_DATE=2001-01-02T00:00:00Z GIT_COMMITTER_DATE=2001-01-02T00:00:00Z git_fixture commit -qm second
  git_fixture commit-graph write --reachable --split=no-merge
  [ "$(wc -l < "$fixture/.git/objects/info/commit-graphs/commit-graph-chain")" -eq 2 ] ||
    fail "fixture does not contain a two-file commit-graph chain"
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
https_remote="$temporary/https-remote.git"
clean_git clone -q --bare --no-hardlinks "$fixture" "$https_remote"
https_initial_head="$(clean_git --git-dir="$https_remote" rev-parse refs/heads/main)"
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

verify_pack() {
  local indices=("$1"/*.idx)
  [ "${#indices[@]}" -eq 1 ] && [ -f "${indices[0]}" ] ||
    fail "rewritten fixture pack index was not found exactly once"
  clean_git verify-pack -- "${indices[0]}"
}

cargo="$(cd "$ROOT_DIR" && rustup which cargo)"
export RUSTC="$(cd "$ROOT_DIR" && rustup which rustc)"
export RUSTDOC="$(cd "$ROOT_DIR" && rustup which rustdoc)"
common=(--manifest-path "$APP_DIR/Cargo.toml" --release --locked --offline
  --target-dir "$APP_DIR/target/component-test")
https_messages="$temporary/https-server-messages.json"
"$cargo" build "${common[@]}" --test https-server \
  --message-format json-render-diagnostics > "$https_messages"
https_server="$(python3 - "$https_messages" <<'PY'
import json
import pathlib
import sys

executables = []
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    message = json.loads(line)
    if (message.get("reason") == "compiler-artifact"
            and message.get("target", {}).get("name") == "https-server"
            and message["target"].get("kind") == ["test"]
            and message.get("executable")):
        executables.append(message["executable"])
if len(executables) != 1:
    raise SystemExit("https-server executable was not found exactly once")
print(executables[0])
PY
)"

if [ "$mode" = --host ]; then
  "$cargo" test "${common[@]}" --lib
  metadata="$temporary/metadata.json"
  "$cargo" metadata --manifest-path "$APP_DIR/Cargo.toml" --locked --offline \
    --format-version 1 --filter-platform x86_64-unknown-linux-gnu > "$metadata"
  fork_info="$(python3 - "$metadata" <<'PY'
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
print(revision)
print(pathlib.Path(packages[0]["manifest_path"]).parent.parent / "Cargo.toml")
PY
)"
  mapfile -t fork_info_lines <<< "$fork_info"
  [ "${#fork_info_lines[@]}" -eq 2 ] || fail "invalid pinned fork metadata"
  fork_revision="${fork_info_lines[0]}"
  fork_manifest="${fork_info_lines[1]}"
  external=(--manifest-path "$fork_manifest" --release --locked --offline
    --target-dir "$APP_DIR/target/component-test/external/$fork_revision")
  "$cargo" test "${external[@]}" -p gix-motor-filetime \
    system_times_are_normalized_and_ordered
  "$cargo" test "${external[@]}" -p gix-index --features sha1 --test index \
    an_index_shorter_than_its_checksum_is_rejected
  "$cargo" test "${external[@]}" -p gix-features --test features fs::
  "$cargo" test "${external[@]}" -p gix-commitgraph --lib --features sha1 native::tests::
  "$cargo" test "${external[@]}" -p gix-pack --lib --features sha1,streaming-input
  "$cargo" test "${external[@]}" -p gix-pack --features sha1 --test pack \
    iter::new_from_header::
  "$cargo" test "${external[@]}" -p gix-pack --features sha1 --test pack \
    bundle::write_to_directory::
  "$cargo" test "${external[@]}" -p gix --test gix \
    --features blocking-network-client,worktree-mutation \
    clone::blocking_io::from_shallow_allowed_by_default
  "$cargo" test "${common[@]}" --test native-port -- \
    "$fixture" "$temporary/host-output"
  verify_index "$temporary/host-output/written.index"
  verify_pack "$temporary/host-output/pack-roundtrip"
  verify_pack "$temporary/host-output/pack-thin"

  "$cargo" build "${common[@]}" --bin gix
  gix_binary="$APP_DIR/target/component-test/release/gix"
  prepare_user_config
  app_env=(
    env -i "PATH=$temporary/fake-bin:$PATH" "HOME=$temporary/home"
    "XDG_CONFIG_HOME=$temporary/xdg"
    "GIX_FAKE_GIT_SENTINEL=$temporary/git-invoked"
    "GIX_FILTER_SENTINEL=$temporary/filter-invoked"
  )
  ca="$APP_DIR/tests/https-test-ca.pem"
  start_https_server 127.0.0.1 localhost
  clone="$temporary/https-clone"
  "${app_env[@]}" "$gix_binary" -c "http.sslCAInfo=$ca" \
    clone "$https_origin/redirect/repo.git" "$clone"
  cp -a "$clone" "$temporary/https-clone-before"
  advance_https_remote
  "${app_env[@]}" "$gix_binary" -r "$clone" -c "http.sslCAInfo=$ca" fetch
  verify_https_clone "$temporary/https-clone-before" "$clone"

  mkdir "$temporary/preexisting"
  printf 'preserve\n' > "$temporary/preexisting/sentinel"
  if "${app_env[@]}" "$gix_binary" -c "http.sslCAInfo=$ca" \
    clone "$https_origin/repo.git" "$temporary/preexisting" 2> "$temporary/preexisting.err"; then
    fail "clone accepted a preexisting destination"
  fi
  grep -Fqx preserve "$temporary/preexisting/sentinel" || fail "clone changed preexisting destination"

  clean_git -C "$clone" config --replace-all remote.origin.fetch \
    '+refs/heads/main:refs/heads/forbidden'
  if "${app_env[@]}" "$gix_binary" -r "$clone" -c "http.sslCAInfo=$ca" fetch \
    > /dev/null 2> "$temporary/refspec.err"; then
    fail "fetch accepted a local-branch destination refspec"
  fi
  grep -F "not a tracking reference or tag" "$temporary/refspec.err" >/dev/null ||
    fail "fetch refspec rejection was not reported"
  ! clean_git -C "$clone" show-ref --verify --quiet refs/heads/forbidden ||
    fail "rejected fetch wrote a local branch"

  printf 'editable filter=blocked\n' > "$temporary/clone-attributes"
  filter_clone="$temporary/filter-clone"
  if "${app_env[@]}" "$gix_binary" -c "http.sslCAInfo=$ca" \
    -c "core.attributesFile=$temporary/clone-attributes" \
    -c "filter.blocked.clean=$temporary/fake-bin/filter" -c filter.blocked.required=true \
    clone "$https_origin/repo.git" "$filter_clone" 2> "$temporary/filter-clone.err"; then
    fail "clone accepted a required external filter"
  fi
  grep -F "unsupported filter 'blocked'" "$temporary/filter-clone.err" >/dev/null ||
    fail "required filter rejection was not reported"
  [ ! -e "$temporary/filter-invoked" ] || fail "clone invoked an external filter"
  [ ! -e "$filter_clone/editable" ] || fail "failed clone published the filtered path"
  [ ! -e "$filter_clone/.git/index" ] || fail "failed clone published its index"
  [ -f "$filter_clone/.git/gix-incomplete-clone" ] || fail "failed clone lost its marker"
  "${app_env[@]}" "$gix_binary" -r "$filter_clone" status > "$temporary/filter-clone.status"
  grep -Fx 'operation incomplete-clone' "$temporary/filter-clone.status" >/dev/null ||
    fail "status did not report the incomplete clone"
  if "${app_env[@]}" "$gix_binary" -r "$filter_clone" -c "http.sslCAInfo=$ca" fetch \
    > /dev/null 2> "$temporary/incomplete-fetch.err"; then
    fail "fetch accepted an incomplete-clone marker"
  fi
  grep -F gix-incomplete-clone "$temporary/incomplete-fetch.err" >/dev/null ||
    fail "incomplete-clone fetch rejection was not reported"

  while read -r route expected; do
    destination="$temporary/$route"
    if "${app_env[@]}" "$gix_binary" -c "http.sslCAInfo=$ca" \
      clone "$https_origin/$route/repo.git" "$destination" \
      > /dev/null 2> "$destination.err"; then
      fail "clone accepted HTTPS fixture route $route"
    fi
    grep -F "$expected" "$destination.err" >/dev/null || fail "$route rejection was not reported: $(cat "$destination.err")"
  done <<'EOF'
reject-status Git HTTP returned status 401
reject-type Git HTTP expected content type `application/x-git-upload-pack-advertisement`, got `text/plain`
reject-origin redirect changed the HTTPS origin
EOF
  if "${app_env[@]}" "$gix_binary" -c "http.sslCAInfo=$ca" \
    clone "$https_origin/bad-protocol/repo.git" "$temporary/bad-protocol" \
    > /dev/null 2> "$temporary/bad-protocol.err"; then
    fail "clone accepted malformed Git protocol data"
  fi
  "${app_env[@]}" "$gix_binary" -c "http.sslCAInfo=$ca" \
    clone "$https_origin/repo.git" "$temporary/good-after-bad"
  stop_https_server

  prepare_policy_fixture
  "${app_env[@]}" "$gix_binary" -r "$fixture" -c core.abbrev=12 \
    -c gitoxide.objects.allocLimit=0 \
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
guest_gix="$guest_root/gix"
if [ "${FULL_TEST_VERIFY_DEV_SOURCES:-0}" = 1 ]; then
  guest_gix=/devtools/bin/gix
fi
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
  if [ "$guest_gix" = "$guest_root/gix" ]; then
    printf 'put "%s" "%s"\n' "$gix_binary" "$guest_gix"
    printf 'chmod 755 "%s"\n' "$guest_gix"
  fi
  printf 'put "%s" "%s"\n' "$APP_DIR/tests/https-test-ca.pem" "$guest_root/test-ca.pem"
  printf 'put -r "%s" "%s"\n' "$fixture/.git" "$guest_root/fixture"
} | "${sftp_command[@]}"
vm_ssh "$guest_root/native-port" "$guest_root/fixture" "$guest_root/output"
printf 'get "%s" "%s"\n' "$guest_root/output/written.index" "$temporary/guest.index" |
  "${sftp_command[@]}"
verify_index "$temporary/guest.index"
printf 'get -r "%s" "%s"\n' "$guest_root/output/pack-roundtrip" "$temporary/guest-pack" |
  "${sftp_command[@]}"
verify_pack "$temporary/guest-pack"
printf 'get -r "%s" "%s"\n' "$guest_root/output/pack-thin" "$temporary/guest-thin-pack" |
  "${sftp_command[@]}"
verify_pack "$temporary/guest-thin-pack"

start_https_server 192.168.4.1 192.168.4.1
guest_clone="$guest_root/https-clone"
vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -c http.sslCAInfo=$guest_root/test-ca.pem clone $https_origin/redirect/repo.git $guest_clone"
printf 'get -r "%s" "%s"\n' "$guest_clone" "$temporary/guest-clone-before" |
  "${sftp_command[@]}"
advance_https_remote
vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_clone -c http.sslCAInfo=$guest_root/test-ca.pem fetch"
printf 'get -r "%s" "%s"\n' "$guest_clone" "$temporary/guest-clone-after" |
  "${sftp_command[@]}"
verify_https_clone "$temporary/guest-clone-before" "$temporary/guest-clone-after"

coproc GIX_PTY {
  ssh "${SSH_OPTIONS[@]}" -e none -tt motor@192.168.4.2 \
    "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -c http.sslCAInfo=$guest_root/test-ca.pem clone $https_origin/stall/repo.git $guest_root/stalled-clone" 2>&1
}
gix_pty_pid="$GIX_PTY_PID"
exec {gix_pty_out}<&"${GIX_PTY[0]}"
exec {gix_pty_in}>&"${GIX_PTY[1]}"
wait_https_line STALL_READY
printf '\003' >&"$gix_pty_in"
exec {gix_pty_in}>&-
gix_pty_in=
set +e
gix_pty_output="$(cat <&"$gix_pty_out")"
gix_pty_read_status=$?
wait "$gix_pty_pid"
gix_pty_status=$?
gix_pty_pid=
set -e
exec {gix_pty_out}<&-
gix_pty_out=
[ "$gix_pty_read_status" -eq 0 ] || fail "cancelled clone PTY output failed"
[ "$gix_pty_status" -eq 130 ] ||
  fail "cancelled clone exited $gix_pty_status, want 130: $gix_pty_output"
wait_https_line STALL_CLOSED
printf 'get "%s" "%s"\n' \
  "$guest_root/stalled-clone/.git/gix-incomplete-clone" "$temporary/native-incomplete-clone" |
  "${sftp_command[@]}"
[ ! -s "$temporary/native-incomplete-clone" ] ||
  fail "cancelled native clone marker was not empty"
stop_https_server

prepare_policy_fixture
vm_ssh /system/bin/mkdir "$guest_root/fixture/.git/refs/replace"
{
  printf 'put "%s" "%s"\n' "$fixture/.git/config" "$guest_root/fixture/.git/config"
  printf 'put "%s" "%s"\n' \
    "$fixture/.git/refs/replace/$policy_head_id" "$guest_root/fixture/.git/refs/replace/$policy_head_id"
  printf 'put "%s" "%s"\n' "$fixture/.git/info/grafts" "$guest_root/fixture/.git/info/grafts"
} | "${sftp_command[@]}"
vm_ssh \
  "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_root/fixture -c core.abbrev=12 -c gitoxide.objects.allocLimit=0 log" \
  > "$temporary/guest.log"
verify_log "$temporary/guest.log"
vm_ssh /system/bin/mv "$guest_root/fixture/.git" "$guest_root/output/worktree/.git"
printf 'UTF8\n' > "$temporary/native-edit"
printf 'put "%s" "%s"\n' \
  "$temporary/native-edit" "$guest_root/output/worktree/café" | "${sftp_command[@]}"
vm_ssh \
  "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_root/output/worktree status" \
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
