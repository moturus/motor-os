#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true
LORRY="$(realpath "${1:?usage: static-library-contract.sh LORRY}")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
export RUSTC="$LORRY_TEST_RUSTC"
WORK="$(mktemp -d /tmp/lorry-static-library-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/home/.config/lorry" "$WORK/project"/{archive,mixed,helper,app}/src "$WORK/project/.cargo"
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" >"$WORK/home/.config/lorry/lorry.toml"
cat >"$WORK/project/Cargo.toml" <<'EOF'
[workspace]
members = ["archive", "mixed", "helper", "app"]
default-members = ["archive", "mixed", "app"]
resolver = "2"
EOF
for member in archive mixed helper app; do
    printf '[package]\nname = "%s"\nversion = "1.0.0"\nedition = "2024"\n' "$member" >"$WORK/project/$member/Cargo.toml"
done
cat >>"$WORK/project/archive/Cargo.toml" <<'EOF'
[lib]
crate-type = ["staticlib"]
[dependencies]
helper = { path = "../helper" }
EOF
cat >>"$WORK/project/mixed/Cargo.toml" <<'EOF'
[lib]
crate-type = ["rlib", "staticlib"]
[dependencies]
helper = { path = "../helper" }
EOF
cat >>"$WORK/project/app/Cargo.toml" <<'EOF'
[dependencies]
mixed = { path = "../mixed" }
EOF
printf '#[inline(never)]\npub fn value() -> u32 { std::hint::black_box(42) }\n' >"$WORK/project/helper/src/lib.rs"
for member in archive mixed; do
    cat >"$WORK/project/$member/src/lib.rs" <<'EOF'
#[unsafe(no_mangle)]
pub extern "C" fn value() -> u32 { helper::value() }
EOF
done
printf 'fn main() { println!("{}", mixed::value()); }\n' >"$WORK/project/app/src/main.rs"
printf '[target.x86_64-unknown-motor]\nlinker = "%s"\nrustflags = ["--sysroot=%s"]\n' \
    "$LORRY_MOTOR_LINKER" "$LORRY_MOTOR_SYSROOT" >"$WORK/project/.cargo/config.toml"
cd "$WORK/project"
"$LORRY_TEST_CARGO" generate-lockfile --offline
for platform in native motor; do
    target=()
    profile=debug
    if [ "$platform" = motor ]; then target=(--target x86_64-unknown-motor); profile=x86_64-unknown-motor/debug; fi
    for selection in defaults archive mixed; do
        packages=()
        archive_count=2
        if [ "$selection" != defaults ]; then packages=(-p "$selection"); archive_count=1; fi
    for command in build check; do
        comparison=differential-workspace-messages
        if [ "$command" = check ]; then comparison=differential-workspace-check-messages; fi
        env HOME="$WORK/home" "$LORRY" "$command" -j1 "${target[@]}" "${packages[@]}" \
            --message-format=json >"$WORK/lorry.json"
        "$LORRY_TEST_CARGO" "$command" -j1 "${target[@]}" "${packages[@]}" --offline \
            --message-format=json >"$WORK/cargo.json"
        if [ "$command" = build ]; then
            if [ "$selection" = defaults ]; then cmp "target/$profile/app" "target/lorry/$profile/app"; fi
            python3 - "$WORK/lorry.json" "$WORK/cargo.json" "$archive_count" <<'PY'
import json, pathlib, re, sys
def members(path):
    data = pathlib.Path(path).read_bytes()
    assert data[:8] == b'!<arch>\n'
    offset, names, result = 8, b'', []
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
            # rustc gives temporary object filenames a random invocation suffix.
            name = re.sub(r'\.[a-z0-9]{7}(\.rcgu\.o)$', r'\1', name)
            result.append((name, payload))
        offset += 60 + size + size % 2
    assert offset == len(data)
    return result
def archives(filename):
    return {event['package_id']: members(path)
            for line in open(filename) for event in [json.loads(line)]
            if event['reason'] == 'compiler-artifact'
            for path in event['filenames'] if path.endswith('.a')}
lorry, cargo = map(archives, sys.argv[1:3])
assert len(lorry) == len(cargo) == int(sys.argv[3]) and lorry == cargo
PY
            # A missing published archive must be restored from the complete cache entry.
            python3 - "$WORK/lorry.json" <<'PY'
import json, pathlib, sys
for line in open(sys.argv[1]):
    event = json.loads(line)
    if event['reason'] == 'compiler-artifact':
        for path in event['filenames']:
            if path.endswith('.a'): pathlib.Path(path).unlink()
PY
            env HOME="$WORK/home" "$LORRY" build -j1 "${target[@]}" "${packages[@]}" --message-format=json >"$WORK/restored.json"
            python3 - "$WORK/restored.json" "$archive_count" <<'PY'
import json, pathlib, sys
archives = [event for line in open(sys.argv[1]) for event in [json.loads(line)]
            if event['reason'] == 'compiler-artifact' and any(path.endswith('.a') for path in event['filenames'])]
assert len(archives) == int(sys.argv[2]) and all(event['fresh'] for event in archives)
assert all(pathlib.Path(path).is_file() for event in archives for path in event['filenames'])
PY
        fi
        "$LORRY_TEST_CARGO" run --quiet --manifest-path "$SCRIPT_DIR/metadata-schema/Cargo.toml" \
            --locked --offline -- "$comparison" "$WORK/lorry.json" "$WORK/cargo.json"
    done
    done
done
[ "$(target/lorry/debug/app)" = 42 ]
echo "PASS: static and mixed archives match Cargo native/cross object bytes, JSON, and cache restoration"
