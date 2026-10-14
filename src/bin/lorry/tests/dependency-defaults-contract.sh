#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
LORRY="$(realpath "${1:-$SCRIPT_DIR/../target/debug/lorry}")"
WORK="$(mktemp -d /tmp/lorry-dependency-defaults-XXXXXX)"
trap 'status=$?; if [ "$status" = 0 ]; then rm -rf "$WORK"; else echo "Retained failed fixture: $WORK" >&2; fi' EXIT
export LORRY WORK
python3 - <<'PY'
import json, os, subprocess
from pathlib import Path

work = Path(os.environ['WORK'])
home = work / 'home'
(home / '.config/lorry').mkdir(parents=True)
(home / '.config/lorry/lorry.toml').write_text('config-version = 1\nuse-cargo-registry = false\n')
env = dict(os.environ, HOME=str(home), RUSTC=os.environ['LORRY_TEST_RUSTC'])
variants = ('legacy', 'both', 'member-legacy', 'root-legacy',
            'root-legacy-member-new', 'member-both')
for edition in ('2015', '2018', '2021', '2024'):
    for variant in variants:
        root = work / f'{edition}-{variant}'
        member = root / 'member'
        dep = root / 'dep'
        for path in (member, dep):
            (path / 'src').mkdir(parents=True)
            (path / 'src/lib.rs').write_text('pub fn probe() {}\n')
        (dep / 'Cargo.toml').write_text(
            '[package]\nname="dep"\nversion="1.0.0"\n'
            '[features]\ndefault=["sentinel"]\nsentinel=[]\n')
        inherited = variant not in ('legacy', 'both')
        root_keys = ', default_features=false' if variant.startswith('root-legacy') else ', default-features=true'
        (root / 'Cargo.toml').write_text(
            '[workspace]\nmembers=["member", "dep"]\nresolver="2"\n'
            + (f'[workspace.dependencies]\ndep={{path="dep"{root_keys}}}\n' if inherited else ''))
        keys = ', default_features=false' if variant in ('legacy', 'member-legacy') else ''
        if variant in ('both', 'member-both'):
            keys = ', default_features=false, default-features=true'
        if variant.endswith('member-new'):
            keys = ', default-features=true'
        source = 'workspace=true' if inherited else 'path="../dep"'
        (member / 'Cargo.toml').write_text(
            f'[package]\nname="probe"\nversion="1.0.0"\nedition="{edition}"\n'
            f'[dependencies]\ndep={{{source}{keys}}}\n')
        results = []
        for tool, executable in [('cargo', os.environ['LORRY_TEST_CARGO']), ('lorry', os.environ['LORRY'])]:
            result = subprocess.run([executable, 'metadata', '--no-deps', '--format-version=1', '--offline'],
                                    cwd=root, env=env, capture_output=True)
            (root / f'{tool}.out').write_bytes(result.stdout)
            (root / f'{tool}.err').write_bytes(result.stderr)
            results.append(result)
        cargo, lorry = results
        assert (cargo.returncode == 0) == (lorry.returncode == 0), (root, cargo.stderr, lorry.stderr)
        if cargo.returncode:
            assert b'unsupported as of the 2024 edition' in cargo.stderr
            assert b'unsupported as of the 2024 edition' in lorry.stderr
        else:
            def defaults(output):
                package = next(p for p in json.loads(output)['packages'] if p['name'] == 'probe')
                return package['dependencies'][0]['uses_default_features']
            assert defaults(cargo.stdout) == defaults(lorry.stdout), root
print('PASS: legacy dependency defaults and workspace inheritance match Cargo across editions')
PY
