#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

# Git protects tracked files, including lockfiles and Lorry admission records.
artifacts=(
	build target vm_images
	':(glob)src/**/target/**' ':(glob)src/**/.lorry/**'
	':(glob)src/**/Cargo.lock'
	src/sys/lib/rt.vdso/rt.vdso{,.tmp}
)

# Include release downloads from earlier builds and interrupted downloads.
if [[ -d external-sources && ! -L external-sources ]]; then
	release='^external-sources/(lua-[0-9]+\.[0-9]+\.[0-9]+(\.tar\.gz)?|wasi-sdk-[0-9]+\.[0-9]+-x86_64-linux(\.part|\.tar\.gz\.part)?)$'
	for path in external-sources/{lua,wasi-sdk}-*; do
		if [[ "$path" =~ $release ]]; then
			artifacts+=("$path")
		fi
	done
fi

git clean -fdx -- "${artifacts[@]}"

if [[ -d external-sources && ! -L external-sources ]]; then
	# The optional native test builds Helix inside its own Git checkout.
	if [[ ! -L external-sources/helix && -e external-sources/helix/.git ]]; then
		git -C external-sources/helix clean -fdx -- target .lorry
	fi
	find external-sources -maxdepth 0 -type d -empty -delete
fi
