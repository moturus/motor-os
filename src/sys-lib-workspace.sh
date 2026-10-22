#!/usr/bin/env bash
#
# sys-lib-workspace.sh -- assemble on the host the Motor OS library workspace
# that the developer image stages under /devtools/src/motor-os/sys/lib.
#
# The crates are the source_dirs of src/imager/motor-os-dev.yaml below that
# path. The workspace manifest, and the empty tokio placeholder that fills the
# lock entry of moto-sdk's Unix-only tokio, are the image's static files.
# Cargo.lock is derived from src/sys/Cargo.lock, so native tests use the
# dependency versions of the in-tree build. src/build-motor-os.sh vendors the
# workspace's dependencies, and src/prepare-dev-image.sh installs its
# Cargo.lock.

set -euo pipefail

usage() {
	echo "usage: $0 [--offline] DESTINATION" >&2
	exit 2
}

offline=()
if [ "${1:-}" = --offline ]; then
	offline=(--offline)
	shift
fi
[ "$#" -eq 1 ] || usage
destination="$1"

ROOT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
STAGED=/devtools/src/motor-os/sys/lib
die() { echo "sys-lib-workspace: $*" >&2; exit 1; }

[ ! -e "$destination" ] || die "destination already exists: $destination"
mapfile -t crates < <(awk -v staged="$STAGED/" '
	/^  - source: / { source = $3; gsub(/"/, "", source) }
	/^    destination: / {
		destination = $2
		gsub(/"/, "", destination)
		if (index(destination, staged) == 1) print source " " destination
	}' "$ROOT_DIR/src/imager/motor-os-dev.yaml")
[ "${#crates[@]}" -gt 0 ] || die "src/imager/motor-os-dev.yaml stages nothing under $STAGED"

mkdir -p "$destination"
for entry in "${crates[@]}"; do
	source="${entry% *}"
	[ "${entry#* }" = "$STAGED/${source##*/}" ] && [ "${source%/*}" = src/sys/lib ] ||
		die "unexpected staged source in motor-os-dev.yaml: $entry"
	# The same exclusions as the imager's source trees.
	tar -C "$ROOT_DIR/src/sys/lib" --exclude=.git --exclude=.lorry \
		--exclude=__pycache__ --exclude=target -cf - "${source##*/}" |
		tar -C "$destination" -xf -
done
cp -R "$ROOT_DIR/img_files/motor-os-dev$STAGED/." "$destination/"
cp "$ROOT_DIR/src/sys/Cargo.lock" "$destination/Cargo.lock"

# Cargo keeps the locked versions and drops the packages this workspace does
# not use. The destination may lie outside this checkout's toolchain selection.
if [ -z "${RUSTUP_TOOLCHAIN:-}" ]; then
	RUSTUP_TOOLCHAIN="$(sed -n 's/^channel = "\(.*\)"/\1/p' "$ROOT_DIR/rust-toolchain.toml")"
	export RUSTUP_TOOLCHAIN
fi
(cd "$destination" && cargo metadata --quiet --format-version 1 "${offline[@]}" >/dev/null) ||
	die "cannot derive $destination/Cargo.lock from src/sys/Cargo.lock"
