#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LORRY="$(realpath "${1:?usage: workspace-admission-contract.sh LORRY}")"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
WORK="$(mktemp -d /tmp/lorry-workspace-admission-XXXXXX)"
cleanup() {
    local status="$?"
    if [ "$status" -ne 0 ]; then
        for log in "$WORK"/*.err "$WORK"/transitive.json "$WORK"/upgrade.json; do
            [ ! -f "$log" ] || cat "$log" >&2
        done
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export RUSTC="$LORRY_TEST_RUSTC"
export HOME="$WORK/home"
PROJECT="$WORK/project"
mkdir -p "$HOME/.config/lorry" "$PROJECT"/{app,shared,outside,second}/src
cat >"$PROJECT/Cargo.toml" <<'EOF'
[workspace]
members = ["app", "shared"]
default-members = ["app"]
exclude = ["outside", "second"]
resolver = "2"
EOF
for package in app shared outside second; do
    cat >"$PROJECT/$package/Cargo.toml" <<EOF
[package]
name = "$package"
version = "1.0.0"
edition = "2018"
rust-version = "1.60"
EOF
    echo 'compile_error!("vendor must not compile package code");' >"$PROJECT/$package/src/lib.rs"
done
cat >>"$PROJECT/app/Cargo.toml" <<'EOF'
[dependencies]
shared = { path = "../shared" }
EOF
cat >>"$PROJECT/shared/Cargo.toml" <<'EOF'
[dependencies]
outside = { path = "../outside", optional = true }
EOF
cat >"$HOME/.config/lorry/lorry.toml" <<EOF
config-version = 1
[repositories]
user = "$WORK/repository"
[network]
curl = "$WORK/no-network-curl"
[cache]
directory = "$WORK/cache"
[policy.limits]
max-packages = 1
EOF
cd "$PROJECT"
"$LORRY" -q --lorry-messages vendor --accept-all >"$WORK/fresh.out" 2>"$WORK/fresh.json"
test ! -s "$WORK/fresh.out"
grep -F 'version = 3' Cargo.lock >/dev/null
grep -F 'name = "outside"' Cargo.lock >/dev/null
grep -F 'review-format-version = 4' .lorry/dependencies-v2.toml >/dev/null
cp Cargo.lock "$WORK/lorry.lock"
rm Cargo.lock
"$LORRY_TEST_CARGO" generate-lockfile --offline
cmp Cargo.lock "$WORK/lorry.lock"
cp .lorry/dependencies-v2.toml "$WORK/original.admission"
cat >>app/Cargo.toml <<'EOF'
[features]
unused = []
EOF
"$LORRY" -q --lorry-messages vendor >"$WORK/warm.out" 2>"$WORK/warm.err"
test ! -s "$WORK/warm.err"
cmp Cargo.lock "$WORK/lorry.lock"
cmp .lorry/dependencies-v2.toml "$WORK/original.admission"
cat >>shared/Cargo.toml <<'EOF'
second = { path = "../second", optional = true }
EOF
if "$LORRY" -q --lorry-messages vendor --accept-all >"$WORK/limited.out" 2>"$WORK/limited.err"; then
    echo 'vendor skipped an optional dependency to satisfy its package cap' >&2
    exit 1
fi
grep -F 'outside the workspace' "$WORK/limited.err" >/dev/null
cmp Cargo.lock "$WORK/lorry.lock"
cmp .lorry/dependencies-v2.toml "$WORK/original.admission"
"$LORRY" -q --max-packages 2 vendor --accept-all >"$WORK/reconcile.out" 2>"$WORK/reconcile.err"
grep -F 'name = "second"' Cargo.lock >/dev/null
cp Cargo.lock "$WORK/reconciled.lock"
rm Cargo.lock
"$LORRY_TEST_CARGO" generate-lockfile --offline
cmp Cargo.lock "$WORK/reconciled.lock"
for package in app shared outside second; do
    sed -i '/^rust-version = /d' "$PROJECT/$package/Cargo.toml"
done
"$LORRY" -q --max-packages 2 vendor --accept-all >"$WORK/format.out" 2>"$WORK/format.err"
cmp Cargo.lock "$WORK/reconciled.lock"
"$LORRY_TEST_CARGO" metadata --offline --format-version 1 >"$WORK/cargo-metadata.json"
cmp Cargo.lock "$WORK/reconciled.lock"
test ! -e app/.lorry/dependencies-v2.toml
test ! -e shared/.lorry/dependencies-v2.toml
echo 'PASS: ordinary workspace vendor matches Cargo locks and excludes members from package caps'
# Migration replaces only selected members after approval; nonmembers survive.
mkdir -p app/.lorry shared/.lorry outside/.lorry
python3 - "$WORK/original.admission" "$WORK/member.admission" <<'PYCODE'
import re, sys
source = open(sys.argv[1]).read().replace('review-format-version = 4', 'review-format-version = 3')
source = re.sub(r'\[review-scope\].*?(?=\[\[context\]\])', '', source, flags=re.S)
open(sys.argv[2], 'w').write(source)
PYCODE
for package in app shared outside; do
    cp "$WORK/member.admission" "$package/.lorry/dependencies-v2.toml"
done
echo 'unrelated state' >app/.lorry/sentinel
cp .lorry/dependencies-v2.toml "$WORK/before-migration.admission"
if "$LORRY" -q --max-packages 2 --lorry-messages vendor --locked --offline -p app \
    >"$WORK/declined-migration.out" 2>"$WORK/declined-migration.err"; then
    echo 'migration removed member approval without confirmation' >&2
    exit 1
fi
cmp .lorry/dependencies-v2.toml "$WORK/before-migration.admission"
cmp app/.lorry/dependencies-v2.toml "$WORK/member.admission"
"$LORRY" -q --max-packages 2 --lorry-messages vendor --locked --offline -p app --accept-all \
    >"$WORK/migration.out" 2>"$WORK/migration.json"
test ! -e app/.lorry/dependencies-v2.toml
grep -F 'unrelated state' app/.lorry/sentinel >/dev/null
cmp shared/.lorry/dependencies-v2.toml "$WORK/member.admission"
cmp outside/.lorry/dependencies-v2.toml "$WORK/member.admission"
python3 - "$WORK/migration.json" "$PROJECT/app/.lorry/dependencies-v2.toml" <<'PYCODE'
import json, sys
messages = [json.loads(line) for line in open(sys.argv[1])]
assert [m['reason'] for m in messages] == ['lorry-admission-migration', 'lorry-vendor-change', 'lorry-admission-migration']
assert [m['stage'] for m in messages if 'stage' in m] == ['proposed', 'completed']
assert all(m['replaced_records'] == [sys.argv[2]] for m in messages if 'stage' in m)
PYCODE
mv shared/.lorry shared/saved-lorry
ln -s ../outside/.lorry shared/.lorry
cp .lorry/dependencies-v2.toml "$WORK/scoped-migration.admission"
if "$LORRY" -q --max-packages 2 --lorry-messages vendor --locked --offline --workspace --accept-all \
    >"$WORK/link-migration.out" 2>"$WORK/link-migration.err"; then
    echo 'migration followed a symbolic member state directory' >&2
    exit 1
fi
grep -F 'not a real directory' "$WORK/link-migration.err" >/dev/null
cmp .lorry/dependencies-v2.toml "$WORK/scoped-migration.admission"
cmp outside/.lorry/dependencies-v2.toml "$WORK/member.admission"
rm shared/.lorry
mv shared/saved-lorry shared/.lorry
"$LORRY" -q --max-packages 2 --lorry-messages vendor --locked --offline --workspace --accept-all \
    >"$WORK/all-migration.out" 2>"$WORK/all-migration.json"
test ! -e shared/.lorry/dependencies-v2.toml
cmp outside/.lorry/dependencies-v2.toml "$WORK/member.admission"
echo 'PASS: workspace review migrates only selected real member records after approval'
"$LORRY" -q --max-packages 2 review >"$WORK/root-review.toml"
(cd app && "$LORRY" -q --max-packages 2 review) >"$WORK/member-review.toml"
"$LORRY" -q --max-packages 2 review -p shared >"$WORK/selected-review.toml"
cmp "$WORK/root-review.toml" "$WORK/member-review.toml"
cmp "$WORK/root-review.toml" "$WORK/selected-review.toml"
grep -F 'review-format-version = 4' "$WORK/root-review.toml" >/dev/null

cat >>outside/Cargo.toml <<'TOML'
[dependencies]
cfg-if = "=1.0.3"
TOML
sed -i 's/path = "..\/outside", optional = true/path = "..\/outside"/' shared/Cargo.toml
"$LORRY_TEST_CARGO" generate-lockfile --offline
cp Cargo.lock "$WORK/before-upgrade.lock"
sed -i 's/"=1.0.3"/"1.0"/' outside/Cargo.toml
"$LORRY_TEST_CARGO" update --offline -p cfg-if --precise 1.0.4
cp Cargo.lock "$WORK/after-upgrade.lock"
"$RUSTC" --edition=2024 -D warnings -O "$SCRIPT_DIR/helpers/cache-curl.rs" -o "$WORK/cache-curl"
"$WORK/cache-curl" prepare "$CARGO_HOME" "$WORK/crates-io" \
    "$WORK/before-upgrade.lock" "$WORK/after-upgrade.lock"
sed -i "s|$WORK/no-network-curl|$WORK/crates-io/curl|; s/max-packages = 1/max-packages = 8/" \
    "$HOME/.config/lorry/lorry.toml"
cp "$WORK/before-upgrade.lock" Cargo.lock
"$LORRY" -q --lorry-messages vendor --accept-all >"$WORK/transitive.out" 2>"$WORK/transitive.json"
cmp Cargo.lock "$WORK/before-upgrade.lock"
"$LORRY" -q --lorry-messages vendor --accept-all upgrade cfg-if --to 1.0.4 \
    >"$WORK/upgrade.out" 2>"$WORK/upgrade.json"
cmp Cargo.lock "$WORK/after-upgrade.lock"
grep -F 'review-format-version = 4' .lorry/dependencies-v2.toml >/dev/null
python3 - "$WORK/upgrade.json" <<'PY'
import json, sys
message = json.load(open(sys.argv[1]))
assert message['reason'] == 'lorry-vendor-change'
assert [(p['name'], p['version']) for p in message['added']] == [('cfg-if', '1.0.4')]
assert [(p['name'], p['version']) for p in message['removed']] == [('cfg-if', '1.0.3')]
PY
cat >>shared/Cargo.toml <<'TOML'
cfg-if = { version = "1.0", optional = true }
TOML
cp .lorry/dependencies-v2.toml "$WORK/upgraded.admission"
if "$LORRY" -q --lorry-messages vendor --accept-all upgrade cfg-if --to 1.0.4 \
    >"$WORK/direct.out" 2>"$WORK/direct.err"; then
    echo 'upgrade accepted a dependency declared directly by a non-anchor member' >&2
    exit 1
fi
grep -F 'direct dependency' "$WORK/direct.err" >/dev/null
cmp Cargo.lock "$WORK/after-upgrade.lock"
cmp .lorry/dependencies-v2.toml "$WORK/upgraded.admission"
echo 'PASS: transitive workspace upgrade matches Cargo and protects every member declaration'

# A valid Cargo patch can describe targets Lorry does not yet compile.
mkdir -p patched/src
sed -i 's/outside = { path/aardvark = { package = "outside", path/; s/cfg-if = { version = "1.0", optional = true }/zulu = { package = "cfg-if", version = "1.0" }/' shared/Cargo.toml
cat >patched/Cargo.toml <<'TOML'
[package]
name = "cfg-if"
version = "1.0.4"
edition = "2021"
[lib]
crate-type = ["staticlib"]
[dev-dependencies]
second = { path = "../second" }
TOML
echo 'compile_error!("metadata must never compile patched sources");' >patched/src/lib.rs
cat >>Cargo.toml <<'TOML'
[patch.crates-io]
cfg-if = { path = "patched" }
TOML
"$LORRY_TEST_CARGO" generate-lockfile --offline
cp Cargo.lock "$WORK/patched.lock"
"$LORRY" -q metadata --format-version 1 >"$WORK/lorry-patched.json"
"$LORRY_TEST_CARGO" metadata --offline --format-version 1 >"$WORK/cargo-patched.json"
python3 - "$WORK/lorry-patched.json" "$WORK/cargo-patched.json" <<'PYCODE'
import difflib, json, sys
actual, expected = [json.load(open(path)) for path in sys.argv[1:]]
assert actual == expected, ''.join(difflib.unified_diff(
    json.dumps(expected, sort_keys=True, indent=2).splitlines(True),
    json.dumps(actual, sort_keys=True, indent=2).splitlines(True),
    fromfile='Cargo', tofile='Lorry'))
PYCODE
cmp Cargo.lock "$WORK/patched.lock"
echo 'PASS: patched source metadata matches Cargo without compiler target restrictions'
