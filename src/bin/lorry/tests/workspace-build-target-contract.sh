#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true
LORRY="$(realpath "${1:?usage: workspace-build-target-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
export RUSTC="$LORRY_TEST_RUSTC"
WORK="$(mktemp -d /tmp/lorry-workspace-build-target-XXXXXX)"
trap 'status=$?; if [ "$status" = 0 ]; then rm -rf "$WORK"; else echo "Retained build target fixture: $WORK" >&2; fi' EXIT
mkdir -p "$WORK/home/.config/lorry" "$WORK/project/.cargo"
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" >"$WORK/home/.config/lorry/lorry.toml"
cat >"$WORK/project/Cargo.toml" <<'EOF'
[workspace]
members = ["a", "b"]
resolver = "2"
EOF
for member in a b; do
    mkdir -p "$WORK/project/$member"/{src,tests,examples,benches}
    cat >"$WORK/project/$member/Cargo.toml" <<EOF
[package]
name = "$member"
version = "1.0.0"
edition = "2024"
[lib]
doctest = false
EOF
    printf 'pub fn value() -> u32 { 42 }\n' >"$WORK/project/$member/src/lib.rs"
    printf 'fn main() { assert_eq!(%s::value(), 42); }\n' "$member" >"$WORK/project/$member/src/main.rs"
    if [ "$member" = b ]; then continue; fi
    sed -i '/\[lib\]/a test = false' "$WORK/project/$member/Cargo.toml"
    cat >>"$WORK/project/$member/Cargo.toml" <<'EOF'
[[bin]]
name = "a"
test = false
[[example]]
name = "library"
crate-type = ["rlib", "staticlib"]
EOF
    cp "$WORK/project/$member/src/main.rs" "$WORK/project/$member/examples/demo.rs"
    printf 'pub fn example() -> u32 { %s::value() }\n' "$member" >"$WORK/project/$member/examples/library.rs"
    for name in first second; do
        printf '#[test] fn test() { assert_eq!(%s::value(), 42); }\n' "$member" >"$WORK/project/$member/tests/$name.rs"
        cp "$WORK/project/$member/tests/$name.rs" "$WORK/project/$member/benches/$name.rs"
    done
done
cat >>"$WORK/project/a/Cargo.toml" <<'EOF'
[dev-dependencies]
b = { path = "../b" }
EOF
cat >>"$WORK/project/b/Cargo.toml" <<'EOF'
[dependencies]
a = { path = "../a" }
EOF
cat >"$WORK/project/.cargo/config.toml" <<EOF
[target.x86_64-unknown-motor]
linker = "$LORRY_MOTOR_LINKER"
rustflags = ["--sysroot", "$LORRY_MOTOR_SYSROOT"]
EOF
cd "$WORK/project"
"$LORRY_TEST_CARGO" generate-lockfile --offline
for platform in native motor; do
    target=()
    if [ "$platform" = motor ]; then target=(--target x86_64-unknown-motor); fi
    for selection in lib bins tests examples benches named repeated patterns overlap all groups release-library; do
        args=(--workspace "--$selection")
        if [ "$selection" = named ]; then args=(--workspace --example library); fi
        if [ "$selection" = release-library ]; then args=(--workspace --example library --release); fi
        if [ "$selection" = repeated ]; then args=(--workspace --bin a --bin b --test first --test second --example demo --example library --bench first --bench second); fi
        if [ "$selection" = patterns ]; then args=(--workspace --bin '[ab]' --test 'f*' --test 's?cond' --example 'd*' --example 'libra[!x]y' --bench '*'); fi
        if [ "$selection" = overlap ]; then args=(--workspace --bin 'a*' --bin a --test 'first*' --test first --example 'demo*' --example demo --bench 'second*' --bench second); fi
        if [ "$selection" = all ]; then args=(--workspace --all-targets); fi
        if [ "$selection" = groups ]; then args=(--workspace --lib --bins --tests --examples --benches --bin missing --test missing --example missing --bench missing); fi
        commands=(build test)
        if [ "$selection" = patterns ] || [ "$selection" = overlap ]; then commands+=(check); fi
        for command in "${commands[@]}"; do
        execution=()
        if [ "$command" = test ]; then execution=(--no-run); fi
        env HOME="$WORK/home" "$LORRY" "$command" "${execution[@]}" "${args[@]}" "${target[@]}" --message-format=json >"$WORK/lorry.json"
        "$LORRY_TEST_CARGO" "$command" "${execution[@]}" "${args[@]}" "${target[@]}" --offline --message-format=json >"$WORK/cargo.json"
        "$LORRY_TEST_CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" --locked --offline -- \
            differential-workspace-messages "$WORK/lorry.json" "$WORK/cargo.json"
        python3 - "$WORK/lorry.json" "$WORK/cargo.json" <<'PY'
import json, pathlib, re, sys
def archive(path):
    data = pathlib.Path(path).read_bytes()
    assert data[:8] == b'!<arch>\n'
    offset, names, members = 8, b'', []
    while offset < len(data):
        header = data[offset:offset + 60]
        assert len(header) == 60 and header[58:] == b'`\n'
        size = int(header[48:58])
        payload = data[offset + 60:offset + 60 + size]
        assert len(payload) == size
        name = header[:16].decode().rstrip()
        if name == '//':
            names = payload
        else:
            if name.startswith('/') and name[1:].isdigit():
                name = names[int(name[1:]):].split(b'/\n', 1)[0].decode()
            name = re.sub(r'\.[a-z0-9]{7}(\.rcgu\.o)$', r'.0000000\1', name)
            # rmeta-link is an ELF object whose string table names those objects.
            if name == 'lib.rmeta-link/':
                payload = re.sub(rb'\.[a-z0-9]{7}(\.rcgu\.o)', rb'.0000000\1', payload)
            members.append((name, payload))
        offset += 60 + size + size % 2
    assert offset == len(data)
    return members
def artifacts(path):
    return {(m['package_id'], m['target']['name'], tuple(m['target']['kind']), m['profile']['test']): m
            for m in map(json.loads, open(path)) if m['reason'] == 'compiler-artifact'}
lorry, cargo = map(artifacts, sys.argv[1:])
assert lorry.keys() == cargo.keys()
for key, actual in lorry.items():
    expected = cargo[key]
    if actual['executable']:
        assert open(actual['executable'], 'rb').read() == open(expected['executable'], 'rb').read(), key
    if actual['target']['kind'] == ['example']:
        for extension in ('rlib', 'a'):
            a = [p for p in actual['filenames'] if p.endswith('.' + extension)]
            b = [p for p in expected['filenames'] if p.endswith('.' + extension)]
            assert len(a) == len(b)
            if a:
                if actual['profile']['opt_level'] == '3':
                    assert open(a[0], 'rb').read() == open(b[0], 'rb').read(), (key, extension)
                else:
                    assert archive(a[0]) == archive(b[0]), (key, extension)
PY
        done
    done
done
for command in build check test; do
    for kind in bin test example bench; do
        for builder in "$LORRY" "$LORRY_TEST_CARGO"; do
            if env HOME="$WORK/home" "$builder" "$command" --workspace "--$kind" 'missing-*' --offline >"$WORK/missing.out" 2>"$WORK/missing.err"; then
                echo "unmatched target pattern succeeded: $builder $command $kind" >&2
                exit 1
            fi
            rg -F 'matches pattern `missing-*`' "$WORK/missing.err"
        done
    done
done
for profile in debug x86_64-unknown-motor/debug; do
    [ -f "target/lorry/$profile/examples/demo" ]
    [ -f "target/lorry/$profile/examples/liblibrary.rlib" ]
    [ -f "target/lorry/$profile/examples/liblibrary.a" ]
    target=()
    if [ "$profile" != debug ]; then target=(--target x86_64-unknown-motor); fi
    env HOME="$WORK/home" "$LORRY" clean -p a "${target[@]}"
    [ ! -e "target/lorry/$profile/examples/demo" ]
    [ ! -e "target/lorry/$profile/examples/liblibrary.rlib" ]
    [ ! -e "target/lorry/$profile/examples/liblibrary.a" ]
    [ -e "target/lorry/$profile/b" ]
done
echo "PASS: workspace build/test target groups, repeated names, dev cycle, JSON, and native/Motor Cargo artifact bytes"
