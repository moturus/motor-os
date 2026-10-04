#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LORRY="$(realpath "${1:?usage: fetch-contract.sh LORRY}")"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
WORK="$(mktemp -d /tmp/lorry-fetch-contract-XXXXXX)"
cleanup() {
    local status="$?"
    if [ "$status" -ne 0 ]; then
        for log in "$WORK"/*.err; do
            [ ! -f "$log" ] || cat "$log" >&2
        done
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT
HOST_CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="$HOST_CARGO_HOME"
export RUSTC="$LORRY_TEST_RUSTC"
mkdir -p "$WORK/home/.config/lorry" "$WORK/project/app/src"
export HOME="$WORK/home"
PROJECT="$WORK/project"
cat >"$PROJECT/Cargo.toml" <<'EOF'
[workspace]
members = ["app"]
resolver = "2"
EOF
cat >"$PROJECT/app/Cargo.toml" <<'EOF'
[package]
name = "app"
version = "1.0.0"
edition = "2021"
[dependencies]
cfg-if = { version = "=1.0.4", optional = true }
[target.'cfg(windows)'.dependencies]
equivalent = "=1.0.2"
[features]
default = ["dep:cfg-if"]
EOF
echo 'compile_error!("fetch must never compile this package");' >"$PROJECT/app/src/lib.rs"
"$LORRY_TEST_CARGO" generate-lockfile --manifest-path "$PROJECT/Cargo.toml" --offline
cp "$PROJECT/Cargo.lock" "$WORK/original.lock"
"$RUSTC" --edition=2024 -D warnings -O "$SCRIPT_DIR/helpers/cache-curl.rs" -o "$WORK/cache-curl"
"$WORK/cache-curl" prepare "$HOST_CARGO_HOME" "$WORK/crates-io" "$PROJECT/Cargo.lock"
cat >"$WORK/curl" <<EOF
#!/bin/sh
printf '%s\n' "\$@" >> "$WORK/requests"
exec "$WORK/crates-io/curl" "\$@"
EOF
chmod 0700 "$WORK/curl"
cat >"$HOME/.config/lorry/lorry.toml" <<EOF
config-version = 1
[repositories]
user = "$WORK/repository"
[network]
curl = "$WORK/curl"
[cache]
directory = "$WORK/cache"
[policy]
default = "deny"
EOF
mkdir "$PROJECT/.lorry"
echo 'existing admission bytes' >"$PROJECT/.lorry/dependencies-v2.toml"
cp "$PROJECT/.lorry/dependencies-v2.toml" "$WORK/original.admission"
cd "$PROJECT"
cp "$HOME/.config/lorry/lorry.toml" "$WORK/allowed.config"
cat >>"$HOME/.config/lorry/lorry.toml" <<'EOF_CONFIG'
[policy.rules.veto]
action = "deny"
name = "cfg-if"
version = "=1.0.4"
source = "crates.io"
checksum = "9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801"
EOF_CONFIG
if "$LORRY" -q --lorry-messages fetch >"$WORK/veto.out" 2>"$WORK/veto.err"; then
    echo 'fetch acquired an explicitly denied locked source' >&2
    exit 1
fi
grep -F 'denied by policy rule' "$WORK/veto.err" >/dev/null
test ! -e "$WORK/requests"
cmp Cargo.lock "$WORK/original.lock"
cmp .lorry/dependencies-v2.toml "$WORK/original.admission"
cp "$WORK/allowed.config" "$HOME/.config/lorry/lorry.toml"
"$LORRY" fetch --locked --target x86_64-unknown-linux-gnu >"$WORK/targeted.out" 2>"$WORK/targeted.err"
grep -F 'Downloading cfg-if v1.0.4' "$WORK/targeted.err"
if grep -F 'https://static.crates.io/crates/equivalent/' "$WORK/requests"; then
    echo 'targeted fetch downloaded an inactive platform archive' >&2
    exit 1
fi
cmp Cargo.lock "$WORK/original.lock"
cmp .lorry/dependencies-v2.toml "$WORK/original.admission"
# Targeted acquisition must retain resolution inputs for inactive lock nodes.
cp "$WORK/requests" "$WORK/targeted.requests"
"$LORRY" -q fetch --offline --target x86_64-unknown-linux-gnu \
    >"$WORK/targeted-offline.out" 2>"$WORK/targeted-offline.err"
cmp "$WORK/requests" "$WORK/targeted.requests"
"$LORRY" -q tree -p app --target x86_64-unknown-linux-gnu >"$WORK/targeted.tree" 2>"$WORK/targeted-tree.err"
if "$LORRY" -q --lorry-messages metadata --format-version 1 \
    >"$WORK/incomplete-metadata.out" 2>"$WORK/incomplete-metadata.err"; then
    echo 'metadata gave a partial answer after a targeted fetch' >&2
    exit 1
fi
grep -F 'lorry fetch' "$WORK/incomplete-metadata.err" >/dev/null
cmp Cargo.lock "$WORK/original.lock"
cmp .lorry/dependencies-v2.toml "$WORK/original.admission"
rm .lorry/dependencies-v2.toml
"$LORRY" -q vendor --locked --offline --accept-all >"$WORK/targeted-admission.out" 2>"$WORK/targeted-admission.err"
echo 'pub fn fixture() { cfg_if::cfg_if! { if #[cfg(unix)] {} else {} } }' >app/src/lib.rs
"$LORRY" -q build -p app --target x86_64-unknown-linux-gnu >"$WORK/targeted-build.out" 2>"$WORK/targeted-build.err"
echo 'compile_error!("fetch must never compile this package");' >app/src/lib.rs
cp "$WORK/original.admission" .lorry/dependencies-v2.toml
cmp "$WORK/requests" "$WORK/targeted.requests"
cmp Cargo.lock "$WORK/original.lock"
"$LORRY" fetch --locked >"$WORK/full.out" 2>"$WORK/full.err"
grep -F 'Downloading equivalent v1.0.2' "$WORK/full.err"
test "$(find "$WORK/repository/objects/crates-io/sha256" -name package.toml | wc -l)" -eq 2
cp "$WORK/requests" "$WORK/requests.before"
"$LORRY" -q fetch --offline --target x86_64-unknown-linux-gnu --target x86_64-pc-windows-gnu >"$WORK/offline.out" 2>"$WORK/offline.err"
test ! -s "$WORK/offline.out"
test ! -s "$WORK/offline.err"
cmp "$WORK/requests" "$WORK/requests.before"
cmp Cargo.lock "$WORK/original.lock"
cmp .lorry/dependencies-v2.toml "$WORK/original.admission"
# Tree verifies descriptive sources without reading or requiring admission.
"$LORRY" -q tree -p app --target x86_64-unknown-linux-gnu >"$WORK/unadmitted.tree"
"$LORRY_TEST_CARGO" tree --locked --offline -p app --target x86_64-unknown-linux-gnu >"$WORK/cargo.tree"
cmp "$WORK/unadmitted.tree" "$WORK/cargo.tree"
"$LORRY" -q tree -p app --no-default-features --target x86_64-unknown-linux-gnu >"$WORK/narrow.tree"
"$LORRY_TEST_CARGO" tree --locked --offline -p app --no-default-features --target x86_64-unknown-linux-gnu >"$WORK/cargo-narrow.tree"
cmp "$WORK/narrow.tree" "$WORK/cargo-narrow.tree"
cmp .lorry/dependencies-v2.toml "$WORK/original.admission"
rm .lorry/dependencies-v2.toml
"$LORRY" -q --lorry-messages vendor --locked --offline --all-features --accept-all >"$WORK/review.out" 2>"$WORK/review.json"
test ! -s "$WORK/review.out"
grep -F 'review-format-version = 4' .lorry/dependencies-v2.toml
grep -F '"reason":"lorry-vendor-change"' "$WORK/review.json" >/dev/null
test ! -e app/.lorry/dependencies-v2.toml
cmp Cargo.lock "$WORK/original.lock"
cmp "$WORK/requests" "$WORK/requests.before"
cp .lorry/dependencies-v2.toml "$WORK/original.admission"
cat >>app/Cargo.toml <<'EOF'
unused = []
EOF
"$LORRY" -q --lorry-messages vendor --locked --offline >"$WORK/repeated.out" 2>"$WORK/repeated.err"
test ! -s "$WORK/repeated.out"
test ! -s "$WORK/repeated.err"
cmp .lorry/dependencies-v2.toml "$WORK/original.admission"
echo 'pub fn fixture() { cfg_if::cfg_if! { if #[cfg(unix)] {} else {} } }' >app/src/lib.rs
"$LORRY" -q build -p app >"$WORK/build.out" 2>"$WORK/build.err"
"$LORRY" -q build -p app >"$WORK/cached.out" 2>"$WORK/cached.err"
cmp Cargo.lock "$WORK/original.lock"
rm .lorry/dependencies-v2.toml
if "$LORRY" -q build -p app >"$WORK/unadmitted.out" 2>"$WORK/unadmitted.err"; then
    echo 'cached build accepted outside sources after admission was removed' >&2
    exit 1
fi
grep -F 'requires' "$WORK/unadmitted.err" >/dev/null
cp "$WORK/original.admission" .lorry/dependencies-v2.toml
"$LORRY" -q --lorry-messages vendor --locked --offline -p app --no-default-features --accept-all >"$WORK/narrow.out" 2>"$WORK/narrow.json"
python3 - "$WORK/narrow.json" <<'PY'
import json, sys
message = json.load(open(sys.argv[1]))
assert message['previous_review_available'] is True
assert message['added'] == []
assert [package['name'] for package in message['removed']] == ['cfg-if']
PY
if "$LORRY" -q build -p app >"$WORK/uncovered.out" 2>"$WORK/uncovered.err"; then
    echo 'cached build escaped its no-default-features review scope' >&2
    exit 1
fi
grep -F 'does not cover' "$WORK/uncovered.err" >/dev/null
"$LORRY" -q --lorry-messages vendor --locked --offline >"$WORK/retained.out" 2>"$WORK/retained.err"
test ! -s "$WORK/retained.err"
"$LORRY" -q vendor --locked --offline --workspace --all-features --accept-all >"$WORK/reset.out" 2>"$WORK/reset.err"
cmp .lorry/dependencies-v2.toml "$WORK/original.admission"
cat >>app/Cargo.toml <<'EOF'
[dependencies.semver]
version = "=1.0.27"
EOF
if "$LORRY" --lorry-messages fetch --offline >"$WORK/stale.out" 2>"$WORK/stale.err"; then
    echo 'fetch accepted a stale workspace lock' >&2
    exit 1
fi
grep -F 'Cargo.lock has no crates.io package' "$WORK/stale.err"
cmp Cargo.lock "$WORK/original.lock"
cmp .lorry/dependencies-v2.toml "$WORK/original.admission"
cmp "$WORK/requests" "$WORK/requests.before"
echo 'PASS: hermetic workspace fetch preserves lock and admission without executing code'

# A fresh registry macro must use host cfg before choosing any child archive.
PROC_PROJECT="$WORK/proc-project"
mkdir -p "$PROC_PROJECT/src" "$PROC_PROJECT/macro/src"
cat >"$PROC_PROJECT/Cargo.toml" <<'TOML'
[package]
name = "proc-root"
version = "1.0.0"
edition = "2021"
[dependencies]
macro-fixture = { path = "macro" }
TOML
cat >"$PROC_PROJECT/macro/Cargo.toml" <<'TOML'
[package]
name = "macro-fixture"
version = "1.0.0"
edition = "2021"
license = "MIT"
[lib]
proc-macro = true
[target.'cfg(target_os = "linux")'.dependencies]
cfg-if = "=1.0.4"
[target.'cfg(target_os = "windows")'.dependencies]
equivalent = "=1.0.2"
TOML
for source in "$PROC_PROJECT/src/lib.rs" "$PROC_PROJECT/macro/src/lib.rs"; do
    echo 'compile_error!("fetch must not compile root or procedural macro code");' >"$source"
done
"$LORRY_TEST_CARGO" generate-lockfile --offline --manifest-path "$PROC_PROJECT/Cargo.toml"
cp -a "$WORK/crates-io" "$WORK/macro-crates-io"
python3 - "$PROC_PROJECT" "$WORK/macro-crates-io" <<'PY'
import hashlib, io, json, pathlib, sys, tarfile
project, fixture = map(pathlib.Path, sys.argv[1:])
archive = fixture / 'archives/macro-fixture/macro-fixture-1.0.0.crate'
archive.parent.mkdir(parents=True)
with tarfile.open(archive, 'w:gz', format=tarfile.USTAR_FORMAT) as tar:
    for name in ['Cargo.toml', 'src/lib.rs']:
        data = (project / 'macro' / name).read_bytes()
        entry = tarfile.TarInfo('macro-fixture-1.0.0/' + name)
        entry.size, entry.mode = len(data), 0o644
        tar.addfile(entry, io.BytesIO(data))
checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
index = fixture / 'index/ma/cr/macro-fixture'
index.parent.mkdir(parents=True)
deps = [dict(name=name, req=version, features=[], optional=False, default_features=True,
             target=f'cfg(target_os = "{platform}")', kind='normal', registry=None)
        for name, version, platform in [('cfg-if', '=1.0.4', 'linux'), ('equivalent', '=1.0.2', 'windows')]]
index.write_text(json.dumps(dict(name='macro-fixture', vers='1.0.0', cksum=checksum,
                                deps=deps, features={}, yanked=False)) + '\n')
lock = project / 'Cargo.lock'
lock.write_text(lock.read_text().replace('name = "macro-fixture"\nversion = "1.0.0"\n',
    'name = "macro-fixture"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + checksum + '"\n'))
manifest = project / 'Cargo.toml'
manifest.write_text(manifest.read_text().replace('{ path = "macro" }', '"=1.0.0"'))
PY
cat >"$WORK/macro-curl" <<EOF_CURL
#!/bin/sh
printf '%s\n' "\$@" >> "$WORK/macro-requests"
exec "$WORK/macro-crates-io/curl" "\$@"
EOF_CURL
chmod 0700 "$WORK/macro-curl"
sed -i "s|$WORK/curl|$WORK/macro-curl|; s|$WORK/repository|$WORK/macro-repository|" \
    "$HOME/.config/lorry/lorry.toml"
cd "$PROC_PROJECT"
cp Cargo.lock "$WORK/macro-original.lock"
"$LORRY" -q fetch --target x86_64-pc-windows-gnu >"$WORK/macro-fetch.out" 2>"$WORK/macro-fetch.err"
grep -F 'https://static.crates.io/crates/macro-fixture/' "$WORK/macro-requests" >/dev/null
grep -F 'https://static.crates.io/crates/cfg-if/' "$WORK/macro-requests" >/dev/null
if grep -F 'https://static.crates.io/crates/equivalent/' "$WORK/macro-requests"; then
    echo 'targeted fetch downloaded target dependencies of a host procedural macro' >&2
    exit 1
fi
cp "$WORK/macro-requests" "$WORK/macro-requests.before"
"$LORRY" -q fetch --offline --target x86_64-pc-windows-gnu >"$WORK/macro-offline.out" 2>"$WORK/macro-offline.err"
cmp "$WORK/macro-requests" "$WORK/macro-requests.before"
cmp Cargo.lock "$WORK/macro-original.lock"
test ! -e .lorry/dependencies-v2.toml
echo 'PASS: targeted registry macro fetch acquires host dependencies without executing code'
