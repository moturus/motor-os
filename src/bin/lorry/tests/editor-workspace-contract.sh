#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
LORRY="$(realpath "${1:?usage: editor-workspace-contract.sh LORRY}")"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
WORK="$(mktemp -d /tmp/lorry-editor-workspace-XXXXXX)"
trap 'status=$?; if [ "$status" = 0 ]; then rm -rf "$WORK"; else echo "Retained editor fixture: $WORK" >&2; fi' EXIT
python3 - "$ROOT_DIR" "$WORK/shipped.json" <<'PY'
import json, pathlib, sys, tomllib
root = pathlib.Path(sys.argv[1])
shipped = tomllib.loads((root / 'img_files/motor-os-dev/user/.config/helix/languages.toml').read_text())
config = shipped['language-server']['rust-analyzer']['config']
assert 'workspace' not in config['check']
project = tomllib.loads((root / '.helix/languages.toml').read_text())
assert project['language-server']['rust-analyzer']['config']['check'] == {'workspace': False}
grant = tomllib.loads((root / 'src/sys/lorry.toml').read_text())['policy']['rules']['moto-io']
assert grant == {'action': 'allow', 'source': 'path', 'name': 'moto-io', 'allow-build-script': True}
pathlib.Path(sys.argv[2]).write_text(json.dumps(config))
PY
RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" run --quiet --locked --offline \
    --manifest-path "$SCRIPT_DIR/editor-workspace/Cargo.toml" -- "$LORRY" "$ROOT_DIR" "$WORK" "$WORK/shipped.json"
