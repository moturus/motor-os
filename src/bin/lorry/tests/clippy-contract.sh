#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: clippy-contract.sh LORRY" >&2
    exit 1
fi
LORRY="$(realpath "$1")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
HOST_CARGO_HOME="${CARGO_HOME:-${HOME:?}/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME:?}/.rustup}"
export RUSTC="$LORRY_TEST_RUSTC"
export PATH="$(dirname "$RUSTC"):$PATH"
WORK="$(mktemp -d /tmp/lorry-clippy-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
PROJECT="$WORK/project"
mkdir -p "$WORK/home/.config/lorry" "$PROJECT/app/src" \
    "$PROJECT/shared/src" "$WORK/external/src"
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" \
    >"$WORK/home/.config/lorry/lorry.toml"
export HOME="$WORK/home"
printf '[workspace]\nmembers = ["app", "shared"]\nresolver = "2"\n' \
    >"$PROJECT/Cargo.toml"
for package in app shared; do
    printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2024"\n' \
        "$package" >"$PROJECT/$package/Cargo.toml"
    printf '[lints.clippy]\nneedless_return = "warn"\n' \
        >>"$PROJECT/$package/Cargo.toml"
done
printf '[dependencies]\nshared = { path = "../shared" }\nexternal = { path = "../../external" }\n' \
    >>"$PROJECT/app/Cargo.toml"
printf '%s\n' 'config-version = 1' '[policy.rules.shared]' \
    'action = "allow"' 'name = "shared"' 'version = "=0.1.0"' \
    'source = "path"' 'allow-build-script = true' >"$PROJECT/lorry.toml"
cat >"$PROJECT/shared/build.rs" <<'RS'
fn main() {
    let out = std::env::var_os("OUT_DIR").unwrap();
    std::fs::write(std::path::Path::new(&out).join("generated.rs"), "pub const VALUE: u8 = 20;\n").unwrap();
    println!("cargo:rerun-if-changed=build.rs");
    return;
}
RS
printf '[package]\nname = "external"\nversion = "0.1.0"\nedition = "2024"\n[workspace]\n' \
    >"$WORK/external/Cargo.toml"
printf 'pub fn value() -> u8 { return 20; }\n' >"$PROJECT/shared/src/lib.rs"
printf 'pub fn value() -> u8 { return 22; }\n' >"$WORK/external/src/lib.rs"
printf 'pub fn value() -> u8 { return shared::value() + external::value(); }\n' \
    >"$PROJECT/app/src/lib.rs"

compare() {
    CARGO_HOME="$HOST_CARGO_HOME" "$LORRY_TEST_CARGO" run \
        --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" --locked --offline --quiet \
        -- differential-check-messages "$1" "$2"
}

cd "$PROJECT"
CARGO_HOME="$HOST_CARGO_HOME" "$LORRY_TEST_CARGO" generate-lockfile --offline
"$LORRY" vendor -p app --accept-all >"$WORK/vendor.out"
# A completed check must not suppress the first Clippy pass.
"$LORRY" check -p app --lib --message-format=json >"$WORK/check.json"
"$LORRY" clippy -p app --lib --message-format=json >"$WORK/lorry.json"
CARGO_HOME="$HOST_CARGO_HOME" "$LORRY_TEST_CARGO" clippy -p app --lib \
    --target-dir "$WORK/cargo" --message-format=json >"$WORK/cargo.json"
compare "$WORK/lorry.json" "$WORK/cargo.json"
python3 - "$WORK/lorry.json" "$WORK/check.json" <<'PY'
import json, sys
def events(path):
    return [json.loads(line) for line in open(path)]
linted = {event['target']['name']
          for event in events(sys.argv[1]) if event['reason'] == 'compiler-message'
          and event['target']['kind'] != ['custom-build']
          and (event['message'].get('code') or {}).get('code') == 'clippy::needless_return'}
assert linted == {'app', 'shared'}, linted
assert any(event['reason'] == 'compiler-message' and event['target']['kind'] == ['custom-build']
           for event in events(sys.argv[1]))
assert not [event for event in events(sys.argv[2]) if event['reason'] == 'compiler-message']
PY
"$LORRY" -v clippy -p app --lib --message-format=json \
    >"$WORK/fresh.json" 2>"$WORK/fresh.err"
compare "$WORK/fresh.json" "$WORK/cargo.json"
if grep -E 'Running .* --crate-name ' "$WORK/fresh.err"; then
    echo "unchanged Clippy started a compiler" >&2
    exit 1
fi
"$LORRY" clippy -p app --lib >"$WORK/human.out" 2>"$WORK/human.err"
[ ! -s "$WORK/human.out" ]
grep -F 'unneeded `return` statement' "$WORK/human.err" >/dev/null

# An inherited primary-package marker must not enable dependency lints.
CARGO_PRIMARY_PACKAGE=1 "$LORRY" clippy -p app --lib --no-deps \
    --message-format=json >"$WORK/no-deps.json"
CARGO_HOME="$HOST_CARGO_HOME" "$LORRY_TEST_CARGO" clippy -p app --lib --no-deps \
    --target-dir "$WORK/cargo-no-deps" --message-format=json >"$WORK/cargo-no-deps.json"
compare "$WORK/no-deps.json" "$WORK/cargo-no-deps.json"
python3 - "$WORK/no-deps.json" <<'PY'
import json, sys
messages = [json.loads(line) for line in open(sys.argv[1])]
linted = [message['target']['name'] for message in messages
          if message['reason'] == 'compiler-message']
assert linted == ['app'], linted
PY
if "$LORRY" clippy -p app --lib --no-deps --message-format=json \
    -- -D clippy::needless_return >"$WORK/deny.json" 2>"$WORK/deny.err"; then
    echo "denied Clippy lint succeeded" >&2
    exit 1
fi
python3 - "$WORK/deny.json" <<'PY'
import json, sys
messages = [json.loads(line) for line in open(sys.argv[1])]
assert messages[-1] == {'reason': 'build-finished', 'success': False}
assert any(message['reason'] == 'compiler-message'
           and message['message']['level'] == 'error'
           and (message['message'].get('code') or {}).get('code') == 'clippy::needless_return'
           for message in messages)
PY
for package in app shared; do
    printf 'pub fn named(configured: u8) -> u8 { configured + 1 }\n' \
        >>"$PROJECT/$package/src/lib.rs"
done
configuration_case() {
    local name="$1" expected="$2"
    "$LORRY" clippy -p app --lib --message-format=json >"$WORK/$name.lorry.json"
    CARGO_HOME="$HOST_CARGO_HOME" "$LORRY_TEST_CARGO" clippy -p app --lib \
        --target-dir "$WORK/cargo-$name" --message-format=json >"$WORK/$name.cargo.json"
    compare "$WORK/$name.lorry.json" "$WORK/$name.cargo.json"
    python3 - "$WORK/$name.lorry.json" "$expected" <<'PY'
import json, sys
names = {message['target']['name'] for message in map(json.loads, open(sys.argv[1]))
         if message['reason'] == 'compiler-message'
         and (message['message'].get('code') or {}).get('code') == 'clippy::disallowed_names'}
assert names == set(sys.argv[2].split()), names
PY
}
printf 'disallowed-names = ["configured"]\n' >"$WORK/clippy.toml"
configuration_case above 'app shared'
printf 'disallowed-names = []\n' >"$WORK/clippy.toml"
configuration_case edited ''
printf 'disallowed-names = ["configured"]\n' >"$PROJECT/app/.clippy.toml"
configuration_case nearer app
rm "$PROJECT/app/.clippy.toml"
configuration_case removed ''
mkdir "$WORK/override"
printf 'disallowed-names = ["configured"]\n' >"$WORK/override/clippy.toml"
export CLIPPY_CONF_DIR=../override
configuration_case override 'app shared'
unset CLIPPY_CONF_DIR
echo "PASS: Clippy member coverage, no-deps, cached warnings, and lint arguments match Cargo"
