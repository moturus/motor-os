#!/usr/bin/env bash
# Validate the external sources' lockfiles offline, at the checkouts' current heads.

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
if [ "$#" -ne 0 ]; then
	printf 'usage: %s\nValidates the existing external sources offline; does not fetch or build.\n' "$0" >&2
	exit 2
fi
. "$ROOT_DIR/src/build-motor-os.sh"
export RUSTUP_TOOLCHAIN="$TOOLCHAIN"
select_external_sources all
if check_external_lockfiles --offline; then
	exit 0
else
	exit 1
fi
