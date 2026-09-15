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
  local link_id utf8_name
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
  printf 'other\n' > "$fixture/editable"
  git_fixture add editable
  git_fixture update-index --chmod=+x editable
  GIT_AUTHOR_DATE=2001-01-02T00:00:00Z GIT_COMMITTER_DATE=2001-01-02T00:00:00Z git_fixture commit -qm second
  git_fixture commit-graph write --reachable
  git_fixture pack-refs --all
  git_fixture repack -adq
  git_fixture prune-packed
  git_fixture fsck --strict
  [ "$(git_fixture count-objects -v | sed -n 's/^count: //p')" = 0 ] ||
    fail "fixture contains loose objects"
}
build_fixture
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
  "$cargo" test "${common[@]}" --test native-port -- \
    "$fixture" "$temporary/host-output"
  verify_index "$temporary/host-output/written.index"
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
  --target x86_64-unknown-motor --test native-port \
  --message-format json-render-diagnostics > "$messages"
binary="$(python3 - "$messages" <<'PY'
import json
import pathlib
import sys

executables = []
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    message = json.loads(line)
    if (
        message.get("reason") == "compiler-artifact"
        and message["target"]["name"] == "native-port"
        and message.get("executable")
    ):
        executables.append(message["executable"])
if len(executables) != 1:
    raise SystemExit("native-port executable was not found exactly once")
print(executables[0])
PY
)"

guest_root="/devtools/tmp/gix-test-$$"
vm_ssh /system/bin/mkdir "$guest_root"
guest_created=1
vm_ssh /system/bin/mkdir "$guest_root/fixture"
sftp_command=(
  sftp -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts"
  -i "$WD/test.key" -b - motor@192.168.4.2
)
{
  printf 'put "%s" "%s"\n' "$binary" "$guest_root/native-port"
  printf 'chmod 755 "%s"\n' "$guest_root/native-port"
  printf 'put -r "%s" "%s"\n' "$fixture/.git" "$guest_root/fixture"
} | "${sftp_command[@]}"
vm_ssh "$guest_root/native-port" "$guest_root/fixture" "$guest_root/output"
printf 'get "%s" "%s"\n' "$guest_root/output/written.index" "$temporary/guest.index" |
  "${sftp_command[@]}"
verify_index "$temporary/guest.index"
echo "test-gix guest PASS"
