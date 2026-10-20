#!/usr/bin/env bash
# Validate the add-on workspaces' lockfiles offline, at the fork checkouts' current heads.

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
if [ "$#" -ne 0 ]; then
	printf 'usage: %s\nValidates existing add-on sources offline; does not fetch or build.\n' "$0" >&2
	exit 2
fi
. "$ROOT_DIR/src/build-motor-os.sh"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-$(sed -n 's/^channel = "\(.*\)"/\1/p' "$MOTOR/rust-toolchain.toml")}"
select_addon_workspaces all
if check_addon_lockfiles --offline; then
	exit 0
else
	exit 1
fi
