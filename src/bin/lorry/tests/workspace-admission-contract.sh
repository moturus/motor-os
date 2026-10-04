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
