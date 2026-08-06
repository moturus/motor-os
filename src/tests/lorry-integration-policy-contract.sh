#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RENDERER="$SCRIPT_DIR/lorry-integration-policy.py"
WORK="$(mktemp -d /tmp/lorry-integration-policy-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

make_object() {
    local name="$1"
    local version="$2"
    local checksum="$3"
    local build="$4"
    local object="$WORK/repository/objects/crates-io/sha256/${checksum:0:2}/$checksum"
    local build_path=""
    local cargo_hash
    local cargo_length
    local script_hash
    local script_length

    mkdir -p "$object/source"
    cat >"$object/package.toml" <<EOF
format-version = 1
name = "$name"
version = "$version"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "$checksum"
license = "MIT"
source-tree-sha256 = "$checksum"
retained-source = true
EOF
    case "$build" in
        none)
            printf '[package]\nname = "%s"\nversion = "%s"\nbuild = false\n' \
                "$name" "$version" >"$object/source/Cargo.toml"
            ;;
        default)
            printf '[package]\nname = "%s"\nversion = "%s"\n' \
                "$name" "$version" >"$object/source/Cargo.toml"
            : >"$object/source/build.rs"
            build_path="build.rs"
            ;;
        explicit)
            printf '[package]\nname = "%s"\nversion = "%s"\nbuild = "tools/build.rs"\n' \
                "$name" "$version" >"$object/source/Cargo.toml"
            mkdir -p "$object/source/tools"
            : >"$object/source/tools/build.rs"
            build_path="tools/build.rs"
            ;;
    esac
    cargo_hash="$(sha256sum "$object/source/Cargo.toml")"
    cargo_hash="${cargo_hash%% *}"
    cargo_length="$(wc -c <"$object/source/Cargo.toml")"
    if [ -n "$build_path" ]; then
        script_hash="$(sha256sum "$object/source/$build_path")"
        script_hash="${script_hash%% *}"
        script_length="$(wc -c <"$object/source/$build_path")"
        printf '{"entries":[{"executable":false,"kind":"file","length":%s,"path":"Cargo.toml","sha256":"%s"},{"executable":false,"kind":"file","length":%s,"path":"%s","sha256":"%s"}],"format-version":1,"source-tree-sha256":"%s"}\n' \
            "$cargo_length" "$cargo_hash" "$script_length" "$build_path" \
            "$script_hash" "$checksum" >"$object/source-manifest.json"
    else
        printf '{"entries":[{"executable":false,"kind":"file","length":%s,"path":"Cargo.toml","sha256":"%s"}],"format-version":1,"source-tree-sha256":"%s"}\n' \
            "$cargo_length" "$cargo_hash" "$checksum" \
            >"$object/source-manifest.json"
    fi
}

alpha_checksum="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
beta_checksum="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
gamma_checksum="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
delta_checksum="dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
make_object alpha 1.0.0 "$alpha_checksum" none
make_object beta 2.0.0 "$beta_checksum" explicit
make_object gamma 3.0.0 "$gamma_checksum" default

cat >"$WORK/first.lock" <<EOF
version = 4

[[package]]
name = "root"
version = "0.1.0"

[[package]]
name = "patched"
version = "1.0.0"
source = "git+https://example.invalid/patched#0123456789012345678901234567890123456789"

[[package]]
name = "beta"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "$beta_checksum"

[[package]]
name = "alpha"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "$alpha_checksum"
EOF
cat >"$WORK/second.lock" <<EOF
version = 4

[[package]]
name = "gamma"
version = "3.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "$gamma_checksum"

[[package]]
name = "delta"
version = "4.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "$delta_checksum"
EOF

cat >"$WORK/first-state.toml" <<EOF
format-version = 1
source-tree-format-version = 1

[[locked-registry]]
name = "alpha"
version = "1.0.0"
checksum = "$alpha_checksum"

[[locked-registry]]
name = "beta"
version = "2.0.0"
checksum = "$beta_checksum"

[[admitted-registry]]
name = "alpha"
version = "1.0.0"
checksum = "$alpha_checksum"
license = "MIT"
source-tree-sha256 = "$alpha_checksum"
build-script = false

[[admitted-registry]]
name = "beta"
version = "2.0.0"
checksum = "$beta_checksum"
license = "MIT"
source-tree-sha256 = "$beta_checksum"
build-script = true
EOF
cat >"$WORK/second-state.toml" <<EOF
format-version = 1
source-tree-format-version = 1

[[locked-registry]]
name = "delta"
version = "4.0.0"
checksum = "$delta_checksum"

[[locked-registry]]
name = "gamma"
version = "3.0.0"
checksum = "$gamma_checksum"

[[admitted-registry]]
name = "gamma"
version = "3.0.0"
checksum = "$gamma_checksum"
license = "MIT"
source-tree-sha256 = "$gamma_checksum"
build-script = true
EOF

"$RENDERER" build-scripts "$WORK/repository" \
    --project "$WORK/first.lock" "$WORK/first-state.toml" \
    --project "$WORK/second.lock" "$WORK/second-state.toml" \
    >"$WORK/build-scripts.toml"
"$RENDERER" all "$WORK/repository" \
    --project "$WORK/first.lock" "$WORK/first-state.toml" \
    --project "$WORK/second.lock" "$WORK/second-state.toml" \
    >"$WORK/all.toml"

[ "$(grep -c '^\[policy.rules\.' "$WORK/build-scripts.toml")" -eq 2 ]
[ "$(grep -c '^allow-build-script = true$' "$WORK/build-scripts.toml")" -eq 2 ]
grep -F '[policy.rules.allow-beta-2_0_0]' "$WORK/build-scripts.toml" >/dev/null
grep -F '[policy.rules.allow-gamma-3_0_0]' "$WORK/build-scripts.toml" >/dev/null
! grep -F 'name = "alpha"' "$WORK/build-scripts.toml" >/dev/null

[ "$(grep -c '^\[policy.rules\.' "$WORK/all.toml")" -eq 3 ]
[ "$(grep -c '^allow-build-script = true$' "$WORK/all.toml")" -eq 2 ]
grep -F '[policy.rules.allow-alpha-1_0_0]' "$WORK/all.toml" >/dev/null

printf '# changed after verification\n' \
    >>"$WORK/repository/objects/crates-io/sha256/${alpha_checksum:0:2}/$alpha_checksum/source/Cargo.toml"
if "$RENDERER" all "$WORK/repository" \
    --project "$WORK/first.lock" "$WORK/first-state.toml" \
    >"$WORK/changed.out" 2>"$WORK/changed.err"; then
    echo "lorry integration policy accepted changed repository evidence" >&2
    exit 1
fi
grep -F "does not match its manifest" "$WORK/changed.err" >/dev/null

mv "$WORK/repository/objects/crates-io/sha256/${gamma_checksum:0:2}/$gamma_checksum" \
    "$WORK/missing-gamma"
if "$RENDERER" all "$WORK/repository" \
    --project "$WORK/second.lock" "$WORK/second-state.toml" \
    >"$WORK/missing.out" 2>"$WORK/missing.err"; then
    echo "lorry integration policy accepted missing repository evidence" >&2
    exit 1
fi
grep -F 'cannot load repository metadata' "$WORK/missing.err" >/dev/null

echo "PASS: Lorry integration policy is derived from locks and repository evidence"
