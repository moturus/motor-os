#!/usr/bin/env bash
# Only the user's own configuration grants trust: `vendor --accept-all` and
# interactive approvals are recorded there per workspace, and a committed
# admission record counts only after the user approves its review.
set -euo pipefail
export CARGO_NET_OFFLINE=true

LORRY="$(realpath "${1:?usage: workspace-trust-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${LORRY_TEST_RUSTC:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
WORK="$(mktemp -d /tmp/lorry-workspace-trust-XXXXXX)"
trap 'status=$?; if [ "$status" = 0 ]; then rm -rf "$WORK"; else echo "Retained failed fixture: $WORK" >&2; fi' EXIT
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME:?}/.rustup}"
export CARGO_HOME="${CARGO_HOME:-${HOME:?}/.cargo}"
export RUSTC="$LORRY_TEST_RUSTC"
HOME_DIR="$WORK/home"
PROJECT="$WORK/project"
CLONE="$WORK/clone"
DECISIONS="$HOME_DIR/.config/lorry/workspaces"

fail() {
    echo "workspace-trust-contract: $*" >&2
    exit 1
}

mkdir -p "$HOME_DIR/.config/lorry" "$PROJECT"/{app,tool}/src
printf 'config-version = 1\nuse-cargo-registry = false\n[cache]\ndirectory = "%s"\n' "$WORK/cache" \
    >"$HOME_DIR/.config/lorry/lorry.toml"
printf '[workspace]\nmembers = ["app", "tool"]\nresolver = "2"\n' >"$PROJECT/Cargo.toml"
printf '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2024"\n[dependencies]\ntool = { path = "../tool" }\n' \
    >"$PROJECT/app/Cargo.toml"
printf 'fn main() { println!("{}", tool::VALUE); }\n' >"$PROJECT/app/src/main.rs"
printf '[package]\nname = "tool"\nversion = "0.1.0"\nedition = "2024"\n' >"$PROJECT/tool/Cargo.toml"
printf 'pub const VALUE: &str = env!("FROM_SCRIPT");\n' >"$PROJECT/tool/src/lib.rs"
printf 'fn main() { println!("cargo:rustc-env=FROM_SCRIPT=scripted"); }\n' >"$PROJECT/tool/build.rs"
(cd "$PROJECT" && "$LORRY_TEST_CARGO" generate-lockfile --offline)

lorry() {
    local directory="$1"
    shift
    (cd "$directory" && env HOME="$HOME_DIR" "$LORRY" "$@")
}

# The decisions file that names a workspace, if any.
decisions_for() {
    grep -l -F "workspace = \"$1\"" "$DECISIONS"/*.toml 2>/dev/null || true
}

interactive_vendor() {
    local directory="$1" answer="$2" typescript="$3"
    printf '%s\n' "$answer" | script -qefc \
        "cd '$directory' && HOME='$HOME_DIR' '$LORRY' vendor" "$typescript" >/dev/null
}

echo "== A member's build script needs a grant from the user =="
if lorry "$PROJECT" build 2>"$WORK/ungranted.err"; then
    fail "built a member script without a grant"
fi
grep -F 'build script without an explicit matching policy grant' "$WORK/ungranted.err" >/dev/null ||
    fail "missing-grant error changed: $(cat "$WORK/ungranted.err")"
grep -F "[workspaces.\"$PROJECT\".policy.rules.allow-tool-0_1_0]" "$WORK/ungranted.err" >/dev/null ||
    fail "missing-grant help does not name this workspace's table"
grep -F 'interactive `lorry vendor` review' "$WORK/ungranted.err" >/dev/null ||
    fail "missing-grant help does not mention the review"

echo "== --accept-all is recorded for this workspace only =="
lorry "$PROJECT" vendor --accept-all >/dev/null 2>&1
record="$(decisions_for "$PROJECT")"
[ -n "$record" ] || fail "--accept-all was not recorded"
grep -Fx 'accept-all = true' "$record" >/dev/null || fail "decisions lack accept-all: $(cat "$record")"
[ "$(lorry "$PROJECT" run -q)" = scripted ] || fail "accepted workspace did not run its build script"
[ -f "$PROJECT/.lorry/dependencies-v2.toml" ] || fail "vendor wrote no admission record"

echo "== A copied checkout's record needs its own approval =="
cp -R "$PROJECT" "$CLONE"
rm -rf "$CLONE/target"
if lorry "$CLONE" build 2>"$WORK/clone.err"; then
    fail "built a copied checkout from a record nobody approved there"
fi
grep -F "you have not approved this workspace's dependency review" "$WORK/clone.err" >/dev/null ||
    fail "unapproved record had the wrong error: $(cat "$WORK/clone.err")"

echo "== A declined review records nothing =="
if interactive_vendor "$CLONE" n "$WORK/declined.typescript"; then
    fail "a declined review succeeded"
fi
grep -F 'Build-time code to approve (1):' "$WORK/declined.typescript" >/dev/null ||
    fail "the review did not list the build-time code"
grep -F '+ tool (path): build script (native tools: none configured)' \
    "$WORK/declined.typescript" >/dev/null || fail "the review did not name the script and its tools"
[ -z "$(decisions_for "$CLONE")" ] || fail "a declined review recorded decisions"

echo "== An approved review records exactly what it showed =="
interactive_vendor "$CLONE" y "$WORK/approved.typescript" ||
    fail "the approved review failed: $(cat "$WORK/approved.typescript")"
record="$(decisions_for "$CLONE")"
[ -n "$record" ] || fail "the approval was not recorded"
if grep -F 'accept-all' "$record" >/dev/null; then fail "an approval recorded accept-all"; fi
grep -F 'name = "tool"' "$record" >/dev/null || fail "the approval did not record the grant"
grep -F 'approved-review-sha256 = ' "$record" >/dev/null || fail "the approval did not record the review"
[ "$(lorry "$CLONE" run -q)" = scripted ] || fail "approved workspace did not run its build script"

echo "== New build-time code asks again =="
printf 'fn main() { println!("cargo:rustc-env=APP_SCRIPT=yes"); }\n' >"$CLONE/app/build.rs"
if lorry "$CLONE" build 2>"$WORK/new-script.err"; then
    fail "built a new member script that nobody approved"
fi
grep -F 'package `app 0.1.0` contains a build script' "$WORK/new-script.err" >/dev/null ||
    fail "a new script had the wrong error: $(cat "$WORK/new-script.err")"
interactive_vendor "$CLONE" y "$WORK/again.typescript" || fail "the second approval failed"
grep -F 'Build-time code to approve (1):' "$WORK/again.typescript" >/dev/null ||
    fail "the second review did not list only the new script"
grep -F '+ app (path): build script' "$WORK/again.typescript" >/dev/null ||
    fail "the second review did not name the new script"
lorry "$CLONE" build -q

echo "== Deleting the decisions revokes them =="
rm "$(decisions_for "$PROJECT")"
if lorry "$PROJECT" build 2>"$WORK/revoked.err"; then
    fail "built after the decisions were deleted"
fi
grep -F "you have not approved this workspace's dependency review" "$WORK/revoked.err" >/dev/null ||
    fail "revoked approval had the wrong error: $(cat "$WORK/revoked.err")"

echo "PASS: only the user's configuration grants a workspace's build-time code"
