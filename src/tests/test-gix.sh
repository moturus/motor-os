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
. "$WD/test-ssh-client-host.sh"
cleanup() {
  local status=$? server_status=0
  if [ -n "$gix_pty_pid" ]; then
    kill "$gix_pty_pid" 2>/dev/null || :
    wait "$gix_pty_pid" 2>/dev/null || :
  fi
  [ -z "$gix_pty_in" ] || exec {gix_pty_in}>&-
  [ -z "$gix_pty_out" ] || exec {gix_pty_out}<&-
  cleanup_ssh_client_host
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
advance_remote() {
  local remote="$1" update="$2" content="$3"
  clean_git clone -q --no-hardlinks "$remote" "$update"
  clean_git -C "$update" config user.name "Motor Test"
  clean_git -C "$update" config user.email motor-test@example.invalid
  printf '%s\n' "$content" > "$update/remote-only"
  clean_git -C "$update" add remote-only
  GIT_AUTHOR_DATE=2001-01-03T00:00:00Z GIT_COMMITTER_DATE=2001-01-03T00:00:00Z \
    clean_git -C "$update" commit -qm remote-update
  clean_git -C "$update" push -q origin main
}
verify_network_clone() {
  local before="$1" after="$2" remote_repo="$3" initial_head="$4" label="$5"
  local initial remote initial_index
  initial="$(clean_git -C "$before" rev-parse HEAD)"
  remote="$(clean_git --git-dir="$remote_repo" rev-parse refs/heads/main)"
  [ "$initial" = "$initial_head" ] || fail "initial $label clone has the wrong HEAD"
  [ "$(clean_git -C "$before" rev-parse refs/remotes/origin/main)" = "$initial_head" ] ||
    fail "initial $label clone has the wrong tracking ref"
  initial_index="$(sha256sum "$before/.git/index")"
  clean_git -C "$before" -c core.symlinks=false diff-index --cached --quiet \
    --ignore-submodules=all "$initial_head" -- || fail "initial $label index differs from HEAD"
  # Copying changes stat data; inspect Git's content/mode diff without refreshing the index.
  clean_git -C "$before" -c core.symlinks=false -c core.fileMode=true \
    diff-files -p --no-ext-diff --no-textconv --ignore-submodules=all -- \
    > "$temporary/network-worktree.diff"
  [ ! -s "$temporary/network-worktree.diff" ] || fail "initial $label worktree differs from the index"
  [ "$(sha256sum "$before/.git/index")" = "$initial_index" ] ||
    fail "host Git verification modified the initial $label index"
  [ "$remote" != "$initial" ] || fail "$label remote did not advance"
  [ "$(clean_git -C "$after" rev-parse HEAD)" = "$initial" ] ||
    fail "fetch changed the checked-out $label branch"
  [ "$(clean_git -C "$after" rev-parse refs/remotes/origin/main)" = "$remote" ] ||
    fail "fetch did not advance $label origin/main"
  cmp "$before/.git/index" "$after/.git/index" >/dev/null || fail "fetch changed the $label index"
  diff -r --exclude=.git "$before" "$after" >/dev/null || fail "fetch changed the $label worktree"
  clean_git -C "$after" fsck --strict
}
wait_ssh_fixture_closed() {
  local name="$1" pid deadline=$((SECONDS + 20))
  wait_ssh_fixture_file "$SSH_CLIENT_HOST_ROOT/$name.closed" "$name-closed"
  pid="$(cat "$SSH_CLIENT_HOST_ROOT/$name.pid")"
  case "$pid" in ""|*[!0-9]*) fail "SSH fixture returned an invalid child pid" ;; esac
  while kill -0 "$pid" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ]; do
    sleep 0.05
  done
  ! kill -0 "$pid" 2>/dev/null || fail "SSH fixture $name process survived completion"
}
wait_ssh_fixture_file() {
  local path="$1" label="$2" deadline=$((SECONDS + 20))
  while [ ! -e "$path" ] && [ "$SECONDS" -lt "$deadline" ]; do
    kill -0 "$SSH_CLIENT_HOST_PROCESS" 2>/dev/null || fail "host russhd exited while waiting for $label"
    sleep 0.05
  done
  [ -e "$path" ] || fail "SSH fixture did not create $label"
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

verify_add_repository() {
  local repository="$1" listing="$temporary/add-index" tree
  clean_git -C "$repository" ls-files --stage > "$listing"
  [ "$(wc -l < "$listing")" -eq 12 ] || fail "add fixture index has the wrong entry count"
  grep -Eq '^100755 [0-9a-f]{40} 0[[:space:]]+executable$' "$listing" ||
    fail "add did not preserve executable mode"
  grep -Eq '^120000 [0-9a-f]{40} 0[[:space:]]+link-preserved$' "$listing" ||
    fail "add did not preserve symlink mode"
  for path in gitlink missing-gitlink blocked-parent/nested; do
    grep -Eq "^160000 [0-9a-f]{40} 0[[:space:]]+$path$" "$listing" ||
      fail "add did not preserve gitlink $path"
  done
  [ -z "$(clean_git -C "$repository" ls-files --unmerged)" ] ||
    fail "add did not resolve the regular-file conflict"
  for path in deleted ignored-new file-parent directory/old gitlink/untracked-child; do
    ! grep -Eq "[[:space:]]$path$" "$listing" || fail "add retained forbidden path $path"
  done
  [ "$(clean_git -C "$repository" show :modified)" = new ] ||
    fail "add staged the wrong modified content"
  [ "$(clean_git -C "$repository" show :ignored-tracked)" = 'new ignored' ] ||
    fail "add did not update a tracked ignored path"
  [ "$(clean_git -C "$repository" show :conflict)" = resolved ] ||
    fail "add staged the wrong conflict resolution"
  [ "$(clean_git -C "$repository" show :file-parent/child)" = child ] ||
    fail "add did not replace an indexed file with a child"
  [ "$(clean_git -C "$repository" show :directory)" = 'now a file' ] ||
    fail "add did not replace an indexed directory with a file"
  tree="$(clean_git -C "$repository" write-tree)"
  clean_git -C "$repository" cat-file -e "$tree^{tree}"
  clean_git -C "$repository" fsck --strict --no-dangling >/dev/null
}

verify_add_cli() {
  local repository="$1" expected actual
  expected="$(printf 'cli stage\n' | clean_git hash-object --stdin)"
  actual="$(clean_git -C "$repository" ls-files --stage -- -leading)"
  [ "$actual" = "$(printf '100644 %s 0\t-leading' "$expected")" ] ||
    fail "gix add -- did not stage the literal leading-dash filename"
  [ "$(clean_git -C "$repository" show :-leading)" = 'cli stage' ] ||
    fail "gix add -- wrote the wrong blob"
}

verify_unstage_cli() {
  local repository="$1" entries
  entries="$(clean_git -C "$repository" ls-files -- -leading)"
  [ -z "$entries" ] ||
    fail "gix unstage retained the selected unborn entry"
  [ "$(cat "$repository/-leading")" = 'cli stage' ] ||
    fail "gix unstage changed the worktree file"
  [ ! -e "$repository/.git/index.lock" ] || fail "gix unstage left index.lock"
}

verify_restore_cli() {
  local repository="$1"
  [ "$(cat "$repository/-leading")" = 'cli stage' ] ||
    fail "gix restore wrote the wrong worktree content"
  [ ! -e "$repository/.git/index.lock" ] || fail "gix restore left index.lock"
}

verify_commit_cli() {
  local repository="$1"
  [ "$(clean_git -C "$repository" symbolic-ref HEAD)" = refs/heads/main ] ||
    fail "gix commit detached HEAD"
  [ "$(clean_git -C "$repository" rev-list --count HEAD)" -eq 1 ] ||
    fail "gix commit created the wrong initial history"
  [ "$(clean_git -C "$repository" log -1 --format=%s)" = cli-initial ] ||
    fail "gix commit wrote the wrong message"
  [ "$(clean_git -C "$repository" show HEAD:-leading)" = 'cli stage' ] ||
    fail "gix commit wrote the wrong tree"
  clean_git -C "$repository" fsck --strict --no-dangling >/dev/null
}

verify_refs_cli() {
  local branches="$1" tags="$2"
  printf '%s\n' cli-earlier earlier main > "$temporary/expected-branches"
  printf '%s\n' at-head cli-head > "$temporary/expected-tags"
  cmp "$temporary/expected-branches" "$branches" >/dev/null ||
    fail "gix branch list output differs from expected names"
  cmp "$temporary/expected-tags" "$tags" >/dev/null ||
    fail "gix tag list output differs from expected names"
}

verify_pack() {
  local indices=("$1"/*.idx)
  [ "${#indices[@]}" -eq 1 ] && [ -f "${indices[0]}" ] ||
    fail "rewritten fixture pack index was not found exactly once"
  clean_git verify-pack -- "${indices[0]}"
}

verify_push_pack() {
  local fixture="$1" receiver="$2" c0 merge
  read -r c0 < "$fixture/C0"
  read -r merge < "$fixture/M"
  [[ "$c0" =~ ^[0-9a-f]{40}$ ]] || fail "push fixture has an invalid C0"
  [[ "$merge" =~ ^[0-9a-f]{40}$ ]] || fail "push fixture has an invalid M"
  [ "$(clean_git -C "$fixture/source" rev-parse refs/heads/main)" = "$merge" ] ||
    fail "push source main does not name M"

  clean_git init --bare -q "$receiver"
  clean_git -C "$receiver" index-pack --strict --stdin < "$fixture/initial.pack" >/dev/null
  clean_git -C "$receiver" cat-file -e "$c0^{commit}"
  if clean_git -C "$receiver" cat-file -e "$merge^{commit}" 2>/dev/null; then
    fail "initial push pack already contains M"
  fi
  clean_git -C "$receiver" update-ref refs/heads/main "$c0"
  clean_git -C "$receiver" index-pack --strict --stdin < "$fixture/incremental.pack" >/dev/null
  clean_git -C "$receiver" update-ref refs/heads/main "$merge" "$c0"
  [ "$(clean_git -C "$receiver" show main:conflict)" = resolved ] ||
    fail "incremental push pack has the wrong merge resolution"
  [ "$(clean_git -C "$receiver" show main:unchanged)" = unchanged ] ||
    fail "incremental push pack lost baseline content"
  [ "$(clean_git -C "$receiver" show main:side-one)" = one ] ||
    fail "incremental push pack lost the first parent content"
  [ "$(clean_git -C "$receiver" show main:side-two)" = two ] ||
    fail "incremental push pack lost the second parent content"
  clean_git -C "$receiver" fsck --strict --no-dangling >/dev/null
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
  lorry_metadata="$temporary/lorry-metadata.json"
  "$cargo" metadata --manifest-path "$ROOT_DIR/src/bin/lorry/Cargo.toml" --locked --offline \
    --format-version 1 --filter-platform x86_64-unknown-linux-gnu > "$lorry_metadata"
  python3 - "$metadata" "$lorry_metadata" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
root = next(package for package in data["packages"] if package["id"] == data["resolve"]["root"])
direct = [dependency for dependency in root["dependencies"] if dependency["name"] == "gix"]
if len(direct) != 1:
    raise SystemExit("direct gix dependency was not found exactly once")
prefix = "git+https://github.com/moturus/gitoxide.git?"
source = direct[0].get("source", "")
if source != prefix + "branch=gix-moturus-cli":
    raise SystemExit("direct gix dependency does not use the shared Motor fork branch")
packages = [
    package for package in data["packages"]
    if package["name"] == "gix" and package.get("source", "").startswith(source + "#")
]
if len(packages) != 1:
    raise SystemExit("resolved gix dependency was not found exactly once")
revision = packages[0]["source"].removeprefix(source + "#")
if len(revision) != 40 or not all(c in "0123456789abcdef" for c in revision):
    raise SystemExit("resolved gix dependency has no full commit ID")

# Both applications must select one branch and resolve all fork crates at one commit.
for metadata_path in sys.argv[1:]:
    graph = json.loads(pathlib.Path(metadata_path).read_text())
    application = next(package for package in graph["packages"] if package["id"] == graph["resolve"]["root"])
    direct_sources = {
        dependency["source"] for dependency in application["dependencies"]
        if (dependency.get("source") or "").startswith(prefix)
    }
    resolved_sources = {
        package["source"] for package in graph["packages"]
        if (package.get("source") or "").startswith(prefix)
    }
    if direct_sources != {source} or resolved_sources != {source + "#" + revision}:
        raise SystemExit(f"{application['name']} does not use the shared gitoxide branch and commit")
PY
  "$cargo" test "${common[@]}" --features native-test-support --test native-port -- \
    "$fixture" "$temporary/host-output"
  verify_index "$temporary/host-output/written.index"
  verify_add_repository "$temporary/host-output/add-repository"
  verify_pack "$temporary/host-output/pack-roundtrip"
  verify_pack "$temporary/host-output/pack-thin"
  verify_push_pack "$temporary/host-output/push-pack" "$temporary/host-push-receiver"

  "$cargo" build "${common[@]}" --bin gix
  gix_binary="$APP_DIR/target/component-test/release/gix"
  prepare_user_config
  app_env=(
    env -i "PATH=$temporary/fake-bin:$PATH" "HOME=$temporary/home"
    "XDG_CONFIG_HOME=$temporary/xdg"
    "GIX_FAKE_GIT_SENTINEL=$temporary/git-invoked"
    "GIX_FILTER_SENTINEL=$temporary/filter-invoked"
  )
  init_repo="$temporary/init"
  mkdir "$init_repo"
  printf 'preserve\n' > "$init_repo/sentinel"
  (
    cd "$init_repo"
    "${app_env[@]}" "$gix_binary" init
  )
  grep -Fqx 'ref: refs/heads/main' "$init_repo/.git/HEAD" ||
    fail "gix init did not select the default main branch"
  grep -Fqx preserve "$init_repo/sentinel" || fail "gix init changed an existing file"
  printf 'cli stage\n' > "$init_repo/-leading"
  "${app_env[@]}" "$gix_binary" -r "$init_repo" add -- -leading
  verify_add_cli "$init_repo"
  "${app_env[@]}" "$gix_binary" -r "$init_repo" unstage -- -leading
  verify_unstage_cli "$init_repo"
  "${app_env[@]}" "$gix_binary" -r "$init_repo" add -- -leading
  "${app_env[@]}" "$gix_binary" -r "$init_repo" -c user.name=CLI -c user.email=cli@example.com commit -m cli-initial
  printf 'dirty\n' > "$init_repo/-leading"
  "${app_env[@]}" "$gix_binary" -r "$init_repo" restore -- -leading
  verify_add_cli "$init_repo"
  verify_restore_cli "$init_repo"
  verify_commit_cli "$init_repo"
  "${app_env[@]}" "$gix_binary" -r "$init_repo" branch create cli-topic
  printf 'foreign\n' > "$init_repo/.git/HEAD.lock"
  if "${app_env[@]}" "$gix_binary" -r "$init_repo" switch cli-topic 2> "$temporary/switch.err"; then
    fail "switch published through a foreign HEAD lock"
  fi
  [ -f "$init_repo/.git/gix-operation" ] || fail "failed switch lost its operation record"
  "${app_env[@]}" "$gix_binary" -r "$init_repo" recover > "$temporary/recover.out"
  grep -Fqx 'restored recorded original state' "$temporary/recover.out" || fail "recover reported the wrong outcome"
  [ ! -e "$init_repo/.git/gix-operation" ] || fail "recover retained a completed record"
  grep -Fqx 'ref: refs/heads/main' "$init_repo/.git/HEAD" || fail "recover changed original HEAD"
  grep -Fqx foreign "$init_repo/.git/HEAD.lock" || fail "recover changed a foreign HEAD lock"
  rm "$init_repo/.git/HEAD.lock"
  "${app_env[@]}" "$gix_binary" -r "$init_repo" switch cli-topic
  grep -Fqx 'ref: refs/heads/cli-topic' "$init_repo/.git/HEAD" || fail "switch selected the wrong branch"
  "${app_env[@]}" "$gix_binary" -r "$init_repo" merge main
  if "${app_env[@]}" "$gix_binary" -r "$init_repo" merge --abort 2> "$temporary/merge-abort.err"; then
    fail "merge --abort accepted an idle repository"
  fi
  grep -F "repository has no ready merge" "$temporary/merge-abort.err" >/dev/null ||
    fail "merge --abort reported the wrong admission error"

  "${app_env[@]}" "$gix_binary" -r "$fixture" branch create cli-earlier HEAD^
  "${app_env[@]}" "$gix_binary" -r "$fixture" tag create cli-head
  "${app_env[@]}" "$gix_binary" -r "$fixture" branch list > "$temporary/host-branches"
  "${app_env[@]}" "$gix_binary" -r "$fixture" tag list > "$temporary/host-tags"
  verify_refs_cli "$temporary/host-branches" "$temporary/host-tags"
  [ "$(git_fixture rev-parse refs/heads/cli-earlier)" = "$(git_fixture rev-parse HEAD^)" ] ||
    fail "gix branch create selected the wrong commit"
  [ "$(git_fixture rev-parse refs/tags/cli-head)" = "$(git_fixture rev-parse HEAD)" ] ||
    fail "gix tag create did not default to HEAD"

  ca="$APP_DIR/tests/https-test-ca.pem"
  start_https_server 127.0.0.1 localhost
  clone="$temporary/https-clone"
  "${app_env[@]}" "$gix_binary" -c "http.sslCAInfo=$ca" \
    clone "$https_origin/redirect/repo.git" "$clone"
  cp -a "$clone" "$temporary/https-clone-before"
  advance_remote "$https_remote" "$temporary/https-update" "remote update"
  "${app_env[@]}" "$gix_binary" -r "$clone" -c "http.sslCAInfo=$ca" fetch
  verify_network_clone "$temporary/https-clone-before" "$clone" "$https_remote" "$https_initial_head" HTTPS

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
  grep -F "path 'editable' uses unsupported filter 'blocked'" \
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
  "${app_env[@]}" "$gix_binary" -r "$fixture" diff editable > "$temporary/worktree.diff"
  "${app_env[@]}" "$gix_binary" -r "$fixture" diff --staged > "$temporary/staged.diff"
  for line in '--- a/editable' '+++ b/editable' '-staged' '+unstaged'; do
    grep -Fqx -- "$line" "$temporary/worktree.diff" || fail "worktree diff lacks $line"
  done
  for line in '--- a/editable' '+++ b/editable' '-other' '+staged' 'deleted file mode 120000' '+++ /dev/null'; do
    grep -Fqx -- "$line" "$temporary/staged.diff" || fail "staged diff lacks $line"
  done
  [ "$(sha256sum "$fixture/.git/index")" = "$index_before" ] ||
    fail "gix status or diff modified the source index"
  [ ! -e "$temporary/git-invoked" ] || fail "repository open invoked installed Git"
  echo "test-gix host PASS"
  exit
fi

. "$WD/vm-test-boot.sh"
test_vm_configure_ssh
assembly_images="$("$ROOT_DIR/src/resolve-toolchain-assembly.sh" --resolve)"
linker="${assembly_images%/images}/sysroot/bin/motor-clang"
messages="$temporary/cargo-messages.json"
native_env=(
  "CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER=$linker"
  "CARGO_TARGET_X86_64_UNKNOWN_MOTOR_RUSTFLAGS=-C link-self-contained=no -C default-linker-libraries=yes"
)
env "${native_env[@]}" "$cargo" build "${common[@]}" \
  --features native-test-support \
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
printf 'get -r "%s" "%s"\n' "$guest_root/output/push-pack" "$temporary/guest-push-pack" |
  "${sftp_command[@]}"
verify_push_pack "$temporary/guest-push-pack" "$temporary/guest-push-receiver"

printf 'get -r "%s" "%s"\n' "$guest_root/output/add-repository" "$temporary/guest-add" |
  "${sftp_command[@]}"
verify_add_repository "$temporary/guest-add"

guest_fixture_app="HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_root/fixture"
vm_ssh "$guest_fixture_app branch create cli-earlier HEAD^"
vm_ssh "$guest_fixture_app tag create cli-head"
vm_ssh "$guest_fixture_app branch list" > "$temporary/guest-branches"
vm_ssh "$guest_fixture_app tag list" > "$temporary/guest-tags"
verify_refs_cli "$temporary/guest-branches" "$temporary/guest-tags"

vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix init $guest_root/init"
printf 'get "%s" "%s"\n' "$guest_root/init/.git/HEAD" "$temporary/guest-init-head" |
  "${sftp_command[@]}"
grep -Fqx 'ref: refs/heads/main' "$temporary/guest-init-head" ||
  fail "native gix init did not select the default main branch"
printf 'cli stage\n' > "$temporary/add-cli-source"
printf 'put "%s" "%s"\n' "$temporary/add-cli-source" "$guest_root/init/-leading" |
  "${sftp_command[@]}"
vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_root/init add -- -leading"
vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_root/init unstage -- -leading"
guest_unstage_status="$(vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_root/init status")"
[ "$guest_unstage_status" = '?? -leading' ] || fail "native gix unstage changed the worktree or retained the index entry"
vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_root/init add -- -leading"
vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_root/init -c user.name=CLI -c user.email=cli@example.com commit -m cli-initial"
printf 'dirty\n' > "$temporary/add-cli-source"
printf 'put "%s" "%s"\n' "$temporary/add-cli-source" "$guest_root/init/-leading" |
  "${sftp_command[@]}"
vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_root/init diff -- -leading" > "$temporary/guest-worktree.diff"
for line in '--- a/-leading' '+++ b/-leading' '-cli stage' '+dirty'; do
  grep -Fqx -- "$line" "$temporary/guest-worktree.diff" || fail "native worktree diff lacks $line"
done
vm_ssh "[ ! -e $guest_root/init/.git/index.lock ]" || fail "native diff left index.lock"
vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_root/init restore -- -leading"
printf 'get -r "%s" "%s"\n' "$guest_root/init" "$temporary/guest-add-cli" |
  "${sftp_command[@]}"
verify_add_cli "$temporary/guest-add-cli"
verify_restore_cli "$temporary/guest-add-cli"
verify_commit_cli "$temporary/guest-add-cli"
guest_init_app="HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_root/init"
vm_ssh "$guest_init_app branch create cli-topic"
vm_ssh "$guest_init_app switch cli-topic"
vm_ssh "cat $guest_root/init/.git/HEAD" > "$temporary/guest-switch-head"
grep -Fqx 'ref: refs/heads/cli-topic' "$temporary/guest-switch-head" || fail "native switch selected the wrong branch"
vm_ssh "$guest_init_app merge main"

start_https_server 192.168.4.1 192.168.4.1
guest_clone="$guest_root/https-clone"
vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -c http.sslCAInfo=$guest_root/test-ca.pem clone $https_origin/redirect/repo.git $guest_clone"
printf 'get -r "%s" "%s"\n' "$guest_clone" "$temporary/guest-clone-before" |
  "${sftp_command[@]}"
advance_remote "$https_remote" "$temporary/https-update" "remote update"
vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_clone -c http.sslCAInfo=$guest_root/test-ca.pem fetch"
printf 'get -r "%s" "%s"\n' "$guest_clone" "$temporary/guest-clone-after" |
  "${sftp_command[@]}"
verify_network_clone "$temporary/guest-clone-before" "$temporary/guest-clone-after" "$https_remote" "$https_initial_head" HTTPS

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

BUILD=release
prepare_ssh_client_host "$WD/test.key"
ssh_bin="$SSH_CLIENT_HOST_ROOT/gix-bin"
ssh_remote="$SSH_CLIENT_HOST_ROOT/repo name's.git"
ssh_push_remote="$SSH_CLIENT_HOST_ROOT/push.git"
mkdir -p "$ssh_bin"
clean_git clone -q --bare --no-hardlinks "$fixture" "$ssh_remote"
clean_git init --bare -q "$ssh_push_remote"
mkdir -p "$ssh_push_remote/hooks"
ssh_initial_head="$(clean_git --git-dir="$ssh_remote" rev-parse refs/heads/main)"
cat > "$ssh_bin/git-upload-pack" <<'SH'
#!/bin/sh
root=${0%/gix-bin/git-upload-pack}
case "${1:-}" in
"$root/repo name's.git")
  printf 'GIX_SSH_SUCCESS_STDERR\n' >&2
  exec /usr/bin/git-upload-pack "$@"
  ;;
"$root/stderr.git")
  trap ': > "$root/stderr.closed"' EXIT
  printf '%s\n' "$$" > "$root/stderr.pid"
  : > "$root/stderr.ready"
  /usr/bin/head -c 65537 /dev/zero | /usr/bin/tr '\000' E >&2
  while IFS= read -r line; do :; done
  ;;
"$root/stall.git")
  trap ': > "$root/stall.closed"' EXIT
  printf '%s\n' "$$" > "$root/stall.pid"
  : > "$root/stall.ready"
  while IFS= read -r line; do :; done
  ;;
*)
  printf 'unexpected upload-pack path: %s\n' "${1:-}" >&2
  exit 97
  ;;
esac
SH
cat > "$ssh_bin/git-receive-pack" <<'SH'
#!/bin/sh
root=${0%/gix-bin/git-receive-pack}
case "${1:-}" in
"$root/push.git") exec /usr/bin/git-receive-pack "$@" ;;
*) printf 'unexpected receive-pack path: %s\n' "${1:-}" >&2; exit 97 ;;
esac
SH
cat > "$ssh_push_remote/hooks/pre-receive" <<'SH'
#!/bin/sh
cat >/dev/null
if [ -e hooks/reject ]; then
  printf 'fixture hook rejection\n' >&2
  exit 1
fi
SH
chmod 755 "$ssh_bin/git-upload-pack" "$ssh_bin/git-receive-pack" \
  "$ssh_push_remote/hooks/pre-receive"
start_ssh_client_host "$WD/test.key" 0 "$ssh_bin:/bin:/usr/bin"
ssh_base="ssh://motor@192.168.4.1:$SSH_CLIENT_HOST_PORT$SSH_CLIENT_HOST_ROOT"
ssh_repo_url="$ssh_base/repo%20name%27s.git"

ssh_rejected="$guest_root/ssh-unknown-host"
set +e
vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix clone $ssh_repo_url $ssh_rejected" \
  > "$temporary/ssh-unknown.stdout" 2> "$temporary/ssh-unknown.stderr"
ssh_status=$?
set -e
[ "$ssh_status" -eq 1 ] || fail "unknown-host SSH clone exited $ssh_status, want 1"
grep -F 'Unknown server key' "$temporary/ssh-unknown.stderr" >/dev/null ||
  fail "unknown-host SSH clone lacked the host-key diagnostic: $(cat "$temporary/ssh-unknown.stderr")"
vm_ssh "[ ! -e $SSH_CLIENT_HOST_GUEST_KNOWN ]" || fail "strict SSH clone recorded an unknown host"
printf 'get "%s" "%s"\n' \
  "$ssh_rejected/.git/gix-incomplete-clone" "$temporary/ssh-unknown-marker" |
  "${sftp_command[@]}"
[ ! -s "$temporary/ssh-unknown-marker" ] || fail "unknown-host clone marker was not empty"

trust_ssh_client_host "$SSH_CLIENT_HOST_PORT"

guest_push_source="$guest_root/output/push-pack/source"
guest_push_app="HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_push_source push"
ssh_push_url="$ssh_base/push.git"
guest_named_push_app="HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $guest_push_source -c remote.fixture.url=$ssh_base/not-push.git -c remote.fixture.pushUrl=$ssh_push_url push"
read -r push_c0 < "$temporary/guest-push-pack/C0"
read -r push_m < "$temporary/guest-push-pack/M"
expect_guest_push() {
  local expected="$1" actual
  shift
  actual="$(vm_ssh "$guest_push_app $*")" || fail "SSH push failed: $*"
  [ "$actual" = "$expected" ] ||
    fail "SSH push output differs: got '$actual', want '$expected'"
}
expect_guest_push_failure() {
  local name="$1" expected="$2" status
  shift 2
  set +e
  vm_ssh "$guest_push_app $*" > "$temporary/$name.stdout" 2> "$temporary/$name.stderr"
  status=$?
  set -e
  [ "$status" -eq 1 ] || fail "$name push exited $status, want 1"
  grep -F "$expected" "$temporary/$name.stderr" >/dev/null ||
    fail "$name push lacked '$expected': $(cat "$temporary/$name.stderr")"
}
push_remote_snapshot() {
  (
    cd "$ssh_push_remote"
    while IFS= read -r -d '' file; do sha256sum "$file"; done \
      < <(find . -type f -print0 | sort -z)
  )
}
verify_read_only_push() {
  local name="$1" before="$2" after
  after="$temporary/$name-remote-after"
  push_remote_snapshot > "$after"
  cmp "$before" "$after" >/dev/null || fail "$name push changed the remote"
  printf 'get -r "%s" "%s"\n' "$guest_push_source" "$temporary/$name-source" |
    "${sftp_command[@]}"
  diff -qr "$temporary/guest-push-pack/source" "$temporary/$name-source" >/dev/null ||
    fail "$name push changed the source repository"
  vm_ssh "[ ! -e $guest_push_source/.git/index.lock ] && [ ! -e $guest_push_source/.git/gix-operation ] && [ ! -e $guest_push_source/.git/packed-refs.lock ]" ||
    fail "$name push left a source lock"
  [ -z "$(find "$ssh_push_remote" -name '*.lock' -print -quit)" ] ||
    fail "$name push left a remote lock"
}

push_output="$(vm_ssh "$guest_named_push_app fixture $push_c0:refs/heads/main")" ||
  fail "configured-remote SSH push failed"
[ "$push_output" = "remote accepted: refs/heads/main -> $push_c0" ] ||
  fail "configured-remote SSH push output differs: $push_output"
[ "$(clean_git -C "$ssh_push_remote" rev-parse refs/heads/main)" = "$push_c0" ] ||
  fail "initial SSH push wrote the wrong main"
if clean_git -C "$ssh_push_remote" cat-file -e "$push_m^{commit}" 2>/dev/null; then
  fail "initial SSH push sent the incremental commit"
fi

push_remote_snapshot > "$temporary/push-dry-remote-before"
expect_guest_push "would update: refs/heads/main -> $push_m" \
  --dry-run "$ssh_push_url" "HEAD:refs/heads/main"
verify_read_only_push push-dry "$temporary/push-dry-remote-before"

expect_guest_push "remote accepted: refs/heads/main -> $push_m" \
  "$ssh_push_url" "HEAD:refs/heads/main"
[ "$(clean_git -C "$ssh_push_remote" show main:conflict)" = resolved ] ||
  fail "incremental SSH push has the wrong merge resolution"
[ "$(clean_git -C "$ssh_push_remote" show main:unchanged)" = unchanged ] ||
  fail "incremental SSH push lost baseline content"
clean_git -C "$ssh_push_remote" fsck --strict --no-dangling >/dev/null

expect_guest_push_failure push-stale-lease \
  'push lease does not match the advertised destination' \
  "--force-with-lease=refs/heads/main:$push_c0" "$ssh_push_url" "HEAD:refs/heads/main"
push_remote_snapshot > "$temporary/push-noop-remote-before"
expect_guest_push "up to date: refs/heads/main -> $push_m" \
  "$ssh_push_url" "HEAD:refs/heads/main"
verify_read_only_push push-noop "$temporary/push-noop-remote-before"

expect_guest_push_failure push-non-ff \
  'push is not a fast-forward; an explicit matching lease is required' \
  "$ssh_push_url" "$push_c0:refs/heads/main"
expect_guest_push "remote accepted: refs/heads/main -> $push_c0" \
  "--force-with-lease=refs/heads/main:$push_m" "$ssh_push_url" "$push_c0:refs/heads/main"
expect_guest_push "remote accepted: refs/heads/main -> $push_m" \
  "--force-with-lease=refs/heads/main:$push_c0" "$ssh_push_url" "$push_m:refs/heads/main"

expect_guest_push "remote accepted: refs/tags/published -> $push_c0" \
  "$ssh_push_url" "$push_c0:refs/tags/published"
expect_guest_push_failure push-tag-replace \
  'replacing an existing tag requires an explicit matching lease' \
  "$ssh_push_url" "$push_m:refs/tags/published"
expect_guest_push "remote accepted: refs/tags/published -> $push_m" \
  "--force-with-lease=refs/tags/published:$push_c0" "$ssh_push_url" "$push_m:refs/tags/published"

# M is already advertised, so this successful new-ref update carries the valid empty pack.
expect_guest_push "remote accepted: refs/heads/copy -> $push_m" \
  "$ssh_push_url" "$push_m:refs/heads/copy"
touch "$ssh_push_remote/hooks/reject"
expect_guest_push_failure push-hook-reject \
  'remote rejected the update: pre-receive hook declined' \
  "$ssh_push_url" "$push_m:refs/heads/rejected"
rm "$ssh_push_remote/hooks/reject"
if clean_git -C "$ssh_push_remote" rev-parse --verify refs/heads/rejected >/dev/null 2>&1; then
  fail "rejected SSH push created its destination"
fi
[ "$(clean_git -C "$ssh_push_remote" rev-parse refs/heads/main)" = "$push_m" ] ||
  fail "SSH push lifecycle left main at the wrong commit"
[ "$(clean_git -C "$ssh_push_remote" rev-parse refs/heads/copy)" = "$push_m" ] ||
  fail "empty-pack SSH push wrote the wrong ref"
[ "$(clean_git -C "$ssh_push_remote" rev-parse refs/tags/published)" = "$push_m" ] ||
  fail "leased SSH tag replacement wrote the wrong ref"
clean_git -C "$ssh_push_remote" fsck --strict --no-dangling >/dev/null

ssh_clone="$guest_root/ssh-clone"
vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix clone $ssh_repo_url $ssh_clone" \
  > "$temporary/ssh-clone.stdout" 2> "$temporary/ssh-clone.stderr" ||
  fail "native SSH clone failed: $(cat "$temporary/ssh-clone.stderr")"
[ "$(grep -Fxc GIX_SSH_SUCCESS_STDERR "$temporary/ssh-clone.stderr")" -eq 1 ] ||
  fail "successful SSH clone did not forward stderr exactly once"
printf 'get -r "%s" "%s"\n' "$ssh_clone" "$temporary/ssh-clone-before" |
  "${sftp_command[@]}"
advance_remote "$ssh_remote" "$temporary/ssh-update" "SSH remote update"
vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix -r $ssh_clone fetch" \
  > "$temporary/ssh-fetch.stdout" 2> "$temporary/ssh-fetch.stderr" ||
  fail "native SSH fetch failed: $(cat "$temporary/ssh-fetch.stderr")"
[ "$(grep -Fxc GIX_SSH_SUCCESS_STDERR "$temporary/ssh-fetch.stderr")" -eq 1 ] ||
  fail "successful SSH fetch did not forward stderr exactly once"
printf 'get -r "%s" "%s"\n' "$ssh_clone" "$temporary/ssh-clone-after" |
  "${sftp_command[@]}"
verify_network_clone "$temporary/ssh-clone-before" "$temporary/ssh-clone-after" \
  "$ssh_remote" "$ssh_initial_head" SSH

set +e
vm_ssh "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix clone $ssh_base/stderr.git $guest_root/ssh-stderr-clone" \
  > "$temporary/ssh-stderr.stdout" 2> "$temporary/ssh-stderr.stderr"
ssh_status=$?
set -e
[ "$ssh_status" -eq 1 ] || fail "oversized-stderr SSH clone exited $ssh_status, want 1"
grep -F 'SSH stderr exceeded the 65536-byte limit' "$temporary/ssh-stderr.stderr" >/dev/null ||
  fail "oversized-stderr SSH clone lacked the limit diagnostic: $(cat "$temporary/ssh-stderr.stderr")"
wait_ssh_fixture_file "$SSH_CLIENT_HOST_ROOT/stderr.ready" stderr-ready
wait_ssh_fixture_closed stderr
printf 'get "%s" "%s"\n' \
  "$guest_root/ssh-stderr-clone/.git/gix-incomplete-clone" "$temporary/ssh-stderr-marker" |
  "${sftp_command[@]}"
[ ! -s "$temporary/ssh-stderr-marker" ] || fail "oversized-stderr clone marker was not empty"

coproc GIX_PTY {
  ssh "${SSH_OPTIONS[@]}" -e none -tt motor@192.168.4.2 \
    "HOME=$guest_root/home XDG_CONFIG_HOME=$guest_root/xdg $guest_gix clone $ssh_base/stall.git $guest_root/ssh-stalled-clone" 2>&1
}
gix_pty_pid="$GIX_PTY_PID"
exec {gix_pty_out}<&"${GIX_PTY[0]}"
exec {gix_pty_in}>&"${GIX_PTY[1]}"
wait_ssh_fixture_file "$SSH_CLIENT_HOST_ROOT/stall.ready" stall-ready
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
[ "$gix_pty_read_status" -eq 0 ] || fail "cancelled SSH clone PTY output failed"
[ "$gix_pty_status" -eq 130 ] ||
  fail "cancelled SSH clone exited $gix_pty_status, want 130: $gix_pty_output"
wait_ssh_fixture_closed stall
printf 'get "%s" "%s"\n' \
  "$guest_root/ssh-stalled-clone/.git/gix-incomplete-clone" "$temporary/ssh-stall-marker" |
  "${sftp_command[@]}"
[ ! -s "$temporary/ssh-stall-marker" ] || fail "cancelled SSH clone marker was not empty"
kill -0 "$SSH_CLIENT_HOST_PROCESS" 2>/dev/null || fail "host russhd exited during SSH lifecycle tests"
stop_ssh_client_host
remove_ssh_client_host_identity || fail "failed to remove the gix SSH identity fixture"
cleanup_ssh_client_host

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
