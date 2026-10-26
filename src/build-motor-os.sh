#!/usr/bin/env bash
#
# build-motor-os.sh — build the external sources and the base, standard,
# development, and wasm VM images with the Motor toolchain that
# rust-toolchain.toml names.
#
# The toolchain is built separately (github.com/moturus/motor-os-toolchain)
# and comes as two archives named by its version, x86_64-unknown-motor-<Rust
# version>:
#   motor-toolchain-<version>-x86_64-linux.tar.zst, the Linux-host toolchain,
#     installed by the install.sh inside it, which links it into rustup;
#   $MOTORH/motor-toolchain-<version>.tar.zst, the native toolchain, whose
#     image overlays this script unpacks.
#
# Everything else stays in the checkout. The external sources (ripgrep,
# Helix, uutils sed, Lua, tar and zstd, Javy with Wasmi, and Wasmtime) are
# fetched into external-sources/. The assembly, build/assembly/, holds what
# the images take from outside the tree: the overlays of the native toolchain,
# of the external sources, and of the dependencies of the staged library
# sources, plus the external sources' build trees.

set -euo pipefail

log()  { printf '\033[1;34m[build-motor-os]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[build-motor-os]\033[0m WARNING: %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[build-motor-os]\033[0m ERROR: %s\n' "$*" >&2; exit 1; }
trap 'die "failed at line $LINENO"' ERR

usage() {
	cat << 'EOF'
Usage: src/build-motor-os.sh
       src/build-motor-os.sh [--javy-only] [--wasmtime-only]
       src/build-motor-os.sh --sys-lib-deps-only

Build the external sources and all four images with the Motor toolchain that
rust-toolchain.toml names, which must be installed in rustup, and whose
native archive must be $MOTORH/motor-toolchain-<version>.tar.zst:
  - ripgrep as /system/bin/rg;
  - tar and zstd in /system/bin;
  - Helix as /devtools/helix/hx in the development image;
  - uutils sed as /devtools/bin/sed in the development image;
  - Lua as /devtools/bin/lua in the development image;
  - Javy and Wasmi in the development and small wasm images;
  - runtime-only Wasmtime as /devtools/bin/wasmtime-rt in both of those images;
  - the crates.io dependencies of the Motor OS library sources the development
    image stages for native tests, as Lorry repository objects;
  - all standard and dev-image Motor OS binaries;
  - base, standard, dev, and wasm images under vm_images/release.

--javy-only and --wasmtime-only build only Javy/Wasmi and the runtime-only
Wasmtime; they skip host provisioning and image construction.
--sys-lib-deps-only likewise fetches only the dependencies of the development
image's library sources.

Environment:
  MOTORH  The directory with the native toolchain archive. Defaults to the
          parent of the Motor OS checkout.
  MOTOR_SKIP_HOST_NETWORK_SETUP=1
          Skip build-base.sh's privileged tap/NAT setup after independently
          verifying that host VM networking is already configured.

Every run builds the external sources and the images again, incrementally
through Cargo and make, so it is safe to rerun. After installing a different or
rebuilt toolchain, run make clean first. The script fetches the external
sources into external-sources/ and builds in build/ and vm_images/. It uses
sudo only at the start, for missing Ubuntu packages and host VM setup, and
starts a VM only to prepare the development image.
EOF
}

parse_options() {
	JAVY_ONLY=false
	WASMTIME_ONLY=false
	SYS_LIB_DEPS_ONLY=false
	while [ "$#" -gt 0 ]; do
		case "$1" in
			-h|--help) usage; return 2 ;;
			--javy-only) JAVY_ONLY=true; shift ;;
			--wasmtime-only) WASMTIME_ONLY=true; shift ;;
			--sys-lib-deps-only) SYS_LIB_DEPS_ONLY=true; shift ;;
			*) usage >&2; die "unknown argument: $1" ;;
		esac
	done
}

# --- paths ------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
MOTOR="$(cd "$SCRIPT_DIR/.." && pwd)"
[ -e "$MOTOR/.git" ] ||
	die "run this script from its Motor OS checkout; .git is missing at $MOTOR"
. "$SCRIPT_DIR/build-scripts/external-sources.sh"
. "$SCRIPT_DIR/build-scripts/build-javy.sh"
. "$SCRIPT_DIR/build-scripts/build-wasmtime.sh"

MOTORH="$(readlink -f "${MOTORH:-$MOTOR/..}")"
export MOTORH
export MOTOR_OS_DIR="$MOTOR"
EXTERNAL_SOURCES="$MOTOR/external-sources"

RIPGREP="$EXTERNAL_SOURCES/ripgrep"
HELIX="$EXTERNAL_SOURCES/helix"
SED="$EXTERNAL_SOURCES/sed"
MOTOR_OS_TAR="$EXTERNAL_SOURCES/motor-os-tar"

# External sources. Lua is a release; ripgrep, Helix, sed, and motor-os-tar
# follow a fork branch.
LUA_VER=5.4.8
RIPGREP_BRANCH=master
HELIX_BRANCH=helix-motor-25.7.1_2026-08-31
SED_BRANCH=main
MOTOR_OS_TAR_BRANCH=master

# Guest WebAssembly test inputs of Javy and Wasmtime are built with this pinned
# upstream Rust; the Motor toolchain itself carries no wasm32 targets.
WASM_GUEST_TOOLCHAIN=1.99.0
# The QuickJS C code of javy-smoke's test plugins needs wasi-sdk: the release
# rquickjs-sys would otherwise download unchecked.
WASI_SDK_VERSION=24.0
WASI_SDK_SHA=c6c38aab56e5de88adf6c1ebc9c3ae8da72f88ec2b656fb024eda8d4167a0bc5
TARGET=x86_64-unknown-motor
# The Motor toolchain that rust-toolchain.toml names, and its native archive.
TOOLCHAIN="$(sed -n 's/^channel = "\(.*\)"/\1/p' "$MOTOR/rust-toolchain.toml")"
[[ "$TOOLCHAIN" =~ ^[A-Za-z0-9._-]+$ ]] ||
	die "$MOTOR/rust-toolchain.toml does not name one toolchain as channel = \"...\""
NATIVE_ARCHIVE="$MOTORH/motor-toolchain-$TOOLCHAIN.tar.zst"

ASSEMBLY_ROOT="$MOTOR/build/assembly"
ASSEMBLY_IMAGE_ROOT="$ASSEMBLY_ROOT/images"
ASSEMBLY_BUILD_ROOT="$ASSEMBLY_ROOT/build"
RG_IMG="$ASSEMBLY_IMAGE_ROOT/rg"
HELIX_IMG="$ASSEMBLY_IMAGE_ROOT/helix"
LUA_IMG="$ASSEMBLY_IMAGE_ROOT/lua"
SED_IMG="$ASSEMBLY_IMAGE_ROOT/sed"
TAR_IMG="$ASSEMBLY_IMAGE_ROOT/tar"
JAVY_IMG="$ASSEMBLY_IMAGE_ROOT/javy"
WASMTIME_IMG="$ASSEMBLY_IMAGE_ROOT/wasmtime"
JAVY_TESTS="$ASSEMBLY_ROOT/tests/javy"
WASMTIME_TESTS="$ASSEMBLY_ROOT/tests/wasmtime"
LUA_BUILD="$ASSEMBLY_BUILD_ROOT/lua-$LUA_VER"
RIPGREP_TARGET_DIR="$ASSEMBLY_BUILD_ROOT/ripgrep"
HELIX_TARGET_DIR="$ASSEMBLY_BUILD_ROOT/helix"
SED_TARGET_DIR="$ASSEMBLY_BUILD_ROOT/sed"
TAR_TARGET_DIR="$ASSEMBLY_BUILD_ROOT/motor-os-tar"

# --- external source checkout: one branch of a fork, at its head or a revision
update_external_source() {
	local name="$1" checkout="$2" url="$3" branch="$4" revision="${5:-}" head remote
	if [ ! -e "$checkout" ]; then
		log "cloning $name ($branch)"
		git clone --branch "$branch" --single-branch "$url" "$checkout"
		[ -n "$revision" ] || return 0
	fi
	# It sits inside the Motor OS checkout, so it needs a .git of its own.
	[ -e "$checkout/.git" ] && git -C "$checkout" rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
		die "$checkout exists but is not a Git checkout"
	[ -n "$revision" ] || [ "$(git -C "$checkout" branch --show-current)" = "$branch" ] ||
		die "$name checkout must be on branch $branch: $checkout"
	[ -z "$(git -C "$checkout" status --porcelain)" ] ||
		die "$name checkout is dirty — preserve its changes and re-run: $checkout"

	git -C "$checkout" fetch "$url" "$branch"
	head="$(git -C "$checkout" rev-parse HEAD)"
	remote="$(git -C "$checkout" rev-parse FETCH_HEAD)"
	if [ -z "$revision" ]; then
		[ "$head" != "$remote" ] || return 0
		git -C "$checkout" merge-base --is-ancestor "$head" "$remote" ||
			die "$name checkout has local or diverged commits — update it manually: $checkout"
		log "updating $name ($branch)"
		git -C "$checkout" merge --ff-only "$remote"
		return
	fi
	[ "$head" != "$revision" ] || return 0
	# The declared revision may be ahead of the branch, or on another branch.
	git -C "$checkout" cat-file -e "$revision^{commit}" 2>/dev/null ||
		git -C "$checkout" fetch "$url" "$revision" ||
		die "$name revision $revision is not in $url"
	# Commits that are on no branch of the fork are local work: never leave
	# them. Pin them (MOTOR_<NAME>_REV) or check out the declared revision.
	local pushed=false tip
	git -C "$checkout" fetch "$url" $(git ls-remote --heads "$url" | cut -f2)
	for tip in $(cut -f1 "$(git -C "$checkout" rev-parse --absolute-git-dir)/FETCH_HEAD"); do
		if git -C "$checkout" merge-base --is-ancestor "$head" "$tip"; then
			pushed=true
			break
		fi
	done
	[ "$pushed" = true ] ||
		die "$name checkout has commits that are not in $url — pin HEAD or check out $revision: $checkout"
	if [ "$(git -C "$checkout" branch --show-current)" = "$branch" ] &&
		git -C "$checkout" merge-base --is-ancestor "$head" "$revision"; then
		log "updating $name ($branch) to $revision"
		git -C "$checkout" merge --ff-only "$revision"
		return
	fi
	log "checking out $name at $revision (git checkout $branch resumes work on the branch)"
	git -C "$checkout" checkout --detach "$revision"
}

# --- external source: Lua, an end-to-end native C application ----------------
# motor-clang compiles for the cross sysroot, and clang's Motor driver links
# crt1.o and mlibc's link group, as the native cc does on Motor OS.
build_lua() {
	log "building Lua $LUA_VER and staging it as /devtools/bin/lua"
	mkdir -p "$EXTERNAL_SOURCES"
	( cd "$EXTERNAL_SOURCES"
		if [ ! -d "lua-$LUA_VER" ]; then
			curl -LO "https://www.lua.org/ftp/lua-$LUA_VER.tar.gz"
			tar xf "lua-$LUA_VER.tar.gz"
			rm "lua-$LUA_VER.tar.gz"
		fi )

	( cd "$EXTERNAL_SOURCES/lua-$LUA_VER/src"
		mkdir -p "$LUA_BUILD"
		local cc="$SYSROOT/bin/motor-clang" f
		for f in ./*.c; do
			case "$f" in ./lua.c|./luac.c) continue ;; esac
			"$cc" -O2 -DLUA_USE_POSIX -c "$f" -o "$LUA_BUILD/$(basename "${f%.c}").o"
		done
		"$LLVM_TOOLS/llvm-ar" rcs "$LUA_BUILD/liblua.a" "$LUA_BUILD"/*.o
		"$cc" -O2 -DLUA_USE_POSIX lua.c "$LUA_BUILD/liblua.a" -o "$LUA_BUILD/lua" )
	mkdir -p "$LUA_IMG/devtools/bin"
	"$LLVM_TOOLS/llvm-strip" -o "$LUA_IMG/devtools/bin/lua" "$LUA_BUILD/lua"
}

# --- external source: ripgrep ---------------------------------------------------
build_ripgrep() {
	log "building ripgrep and staging it as /system/bin/rg"
	( cd "$RIPGREP" && \
		CARGO_TARGET_DIR="$RIPGREP_TARGET_DIR" \
			cargo build --target "$TARGET" --release --locked )

	local binary="$RIPGREP_TARGET_DIR/$TARGET/release/rg"
	[ -x "$binary" ] || die "ripgrep binary was not produced: $binary"
	mkdir -p "$RG_IMG/system/bin"
	"$LLVM_TOOLS/llvm-strip" -o "$RG_IMG/system/bin/rg" "$binary"
	chmod 755 "$RG_IMG/system/bin/rg"
}

# --- external source: sed (uutils) ---------------------------------------------
build_sed() {
	log "building sed and staging it as /devtools/bin/sed"
	# One codegen unit, as sed's Cargo.toml suggests: smaller, and no slower.
	( cd "$SED" && \
		CARGO_TARGET_DIR="$SED_TARGET_DIR" \
		CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
			cargo build --target "$TARGET" --release --locked )

	local binary="$SED_TARGET_DIR/$TARGET/release/sed"
	[ -x "$binary" ] || die "sed binary was not produced: $binary"
	mkdir -p "$SED_IMG/devtools/bin"
	"$LLVM_TOOLS/llvm-strip" -o "$SED_IMG/devtools/bin/sed" "$binary"
	chmod 755 "$SED_IMG/devtools/bin/sed"
}

validate_helix_elf() {
	local binary="$1" stack
	"$LLVM_TOOLS/llvm-readelf" -h "$binary" | grep -Eq 'Type:.*DYN' ||
		die "Helix is not a static PIE (ELF DYN): $binary"
	if "$LLVM_TOOLS/llvm-readelf" -d "$binary" | grep -q '(NEEDED)'; then
		die "Helix has a dynamic library dependency: $binary"
	fi
	if "$LLVM_TOOLS/llvm-readelf" -l "$binary" | awk '$1 == "TLS" { found = 1 } END { exit !found }'; then
		die "Helix has a loader-incompatible TLS segment: $binary"
	fi
	stack="$("$LLVM_TOOLS/llvm-readelf" -l "$binary" | awk '$1 == "GNU_STACK" { print; found++ } END { if (found != 1) exit 1 }')" ||
		die "Helix lacks one GNU_STACK program header: $binary"
	case "$stack" in
		*E*) die "Helix requests an executable stack: $binary" ;;
	esac
	"$LLVM_TOOLS/llvm-readelf" --dyn-syms "$binary" |
		awk '$7 == "UND" && $1 != "0:" { bad = 1 } END { exit bad }' ||
		die "Helix has unresolved dynamic symbols: $binary"
	if "$LLVM_TOOLS/llvm-nm" -u "$binary" 2>/dev/null |
		grep -Eq '(^|[[:space:]])(dlopen|dlsym|tree_sitter_|__cxa_|_Z)'; then
		die "Helix has an unresolved loader, grammar, or C++ runtime symbol: $binary"
	fi
}

stage_helix() {
	local binary="$HELIX_TARGET_DIR/$TARGET/release/hx" component
	[ -x "$binary" ] || die "Helix binary was not produced: $binary"
	validate_helix_elf "$binary"
	mkdir -p "$HELIX_IMG/devtools/helix/runtime"
	"$LLVM_TOOLS/llvm-strip" -o "$HELIX_IMG/devtools/helix/hx" "$binary"
	chmod 755 "$HELIX_IMG/devtools/helix/hx"
	validate_helix_elf "$HELIX_IMG/devtools/helix/hx"
	for component in queries themes tutor; do
		[ -e "$HELIX/runtime/$component" ] ||
			die "Helix runtime component is missing: $component"
		cp -a "$HELIX/runtime/$component" "$HELIX_IMG/devtools/helix/runtime/"
	done
}

# --- external sources ------------------------------------------------------------
# External sources link against the toolchain's sysroot and are staged in its
# assembly. Every run builds each into an empty overlay; their Cargo target
# directories keep that incremental.
build_external_source() {
	local name="$1" overlay="$2" executable="$3" build="$4"
	rm -rf "$overlay"
	"$build"
	[ -x "$overlay/$executable" ] || die "$name was not staged: $overlay/$executable"
}

ensure_wasm_guest_toolchain() {
	log "providing Rust $WASM_GUEST_TOOLCHAIN with wasm32-wasip1 and wasm32-wasip2 for wasm test inputs"
	rustup toolchain install "$WASM_GUEST_TOOLCHAIN" --profile minimal --no-self-update \
		--target wasm32-wasip1 --target wasm32-wasip2
}

ensure_wasi_sdk() {
	local name="wasi-sdk-$WASI_SDK_VERSION-x86_64-linux"
	WASI_SDK="$EXTERNAL_SOURCES/$name"
	[ ! -d "$WASI_SDK" ] || return 0
	log "fetching wasi-sdk $WASI_SDK_VERSION for javy-smoke's test plugins"
	mkdir -p "$EXTERNAL_SOURCES"
	local archive="$EXTERNAL_SOURCES/$name.tar.gz.part"
	curl --fail --location -o "$archive" \
		"https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_SDK_VERSION%.*}/$name.tar.gz"
	printf '%s  %s\n' "$WASI_SDK_SHA" "$archive" | sha256sum -c -
	rm -rf "$WASI_SDK.part"
	mkdir "$WASI_SDK.part"
	tar -xzf "$archive" -C "$WASI_SDK.part" --strip-components=1
	rm "$archive"
	mv "$WASI_SDK.part" "$WASI_SDK"
}

build_external_sources() {
	build_external_source lua "$LUA_IMG" devtools/bin/lua build_lua
	build_external_source ripgrep "$RG_IMG" system/bin/rg build_ripgrep
	build_external_source helix "$HELIX_IMG" devtools/helix/hx build_helix
	build_external_source sed "$SED_IMG" devtools/bin/sed build_sed
	build_external_source tar "$TAR_IMG" system/bin/tar build_tar
	ensure_wasm_guest_toolchain
	ensure_wasi_sdk
	build_external_source javy "$JAVY_IMG" devtools/bin/javy build_javy
	build_external_source wasmtime "$WASMTIME_IMG" devtools/bin/wasmtime-rt build_wasmtime
	fetch_sys_lib_deps
}

# --- external source: tar and zstd ---------------------------------------------
build_tar() {
	log "building tar and zstd and staging them in /system/bin"
	( cd "$MOTOR_OS_TAR" && \
		CARGO_TARGET_DIR="$TAR_TARGET_DIR" \
			cargo build --target "$TARGET" --release --locked )
	local tool
	mkdir -p "$TAR_IMG/system/bin"
	for tool in tar zstd; do
		"$LLVM_TOOLS/llvm-strip" -o "$TAR_IMG/system/bin/$tool" \
			"$TAR_TARGET_DIR/$TARGET/release/$tool"
		chmod 755 "$TAR_IMG/system/bin/$tool"
	done
}

# --- dependencies of the staged Motor OS library sources ------------------------
# The development image stages src/sys/lib crates for native tests, and
# `make dev.img` admits and compiles them there offline
# (src/build-scripts/prepare-dev-image.sh). Their crates.io dependencies
# come from this overlay: objects of the image's
# Interactive Lorry repository, fetched by a Lorry built for this host. Fetch
# takes every package of the workspace's Cargo.lock, whatever features the
# staged manifests select, so that lock alone decides the overlay; and
# src/sys/Cargo.lock decides the lock.
fetch_sys_lib_deps() {
	local work="$ASSEMBLY_BUILD_ROOT/sys-lib-deps" overlay="$ASSEMBLY_IMAGE_ROOT/sys-lib-deps"
	local repository="$overlay/devtools/lorry/user/vendor"
	log "fetching the dependencies of the staged Motor OS library sources"
	rm -rf "$work" "$overlay"
	"$MOTOR/src/build-scripts/sys-lib-workspace.sh" "$work/workspace"
	CARGO_TARGET_DIR="$ASSEMBLY_BUILD_ROOT/host-lorry" \
		cargo build --manifest-path "$MOTOR/src/bin/lorry/Cargo.toml" --release --locked
	mkdir -p "$work/home/.config/lorry" "${repository%/*}"
	cat > "$work/home/.config/lorry/lorry.toml" << EOF
config-version = 1

[repositories]
user = "$repository"
EOF
	# A private HOME keeps the user's own Lorry configuration out.
	( cd "$work/workspace" &&
		RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" \
		HOME="$work/home" "$ASSEMBLY_BUILD_ROOT/host-lorry/release/lorry" fetch --locked )
	# The image ships its own repository header; only objects and index records
	# belong to the overlay.
	rm -rf "$repository/repository.toml" "$repository/.staging"
	[ -n "$(find "$repository/objects" -type f)" ] ||
		die "Lorry fetched no dependency objects into $repository"
}

build_helix() {
	log "fetching, building, and staging Helix as /devtools/helix/hx"
	(
		cd "$HELIX"
		cargo fetch --locked
		env \
			CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER="$SYSROOT/bin/motor-clang" \
			CC_x86_64_unknown_motor="$SYSROOT/bin/motor-clang" \
			CXX_x86_64_unknown_motor="$SYSROOT/bin/motor-clang++" \
			CXXSTDLIB_x86_64_unknown_motor=c++ \
			AR_x86_64_unknown_motor="$LLVM_TOOLS/llvm-ar" \
			ARFLAGS_x86_64_unknown_motor= \
			CARGO_TARGET_DIR="$HELIX_TARGET_DIR" \
			HELIX_DEFAULT_RUNTIME=/devtools/helix/runtime \
			HELIX_DISABLE_AUTO_GRAMMAR_BUILD=1 \
			cargo build --target "$TARGET" --release --locked \
				--offline -p helix-term --bin hx
	)
	stage_helix
}

# --- rebuild the OS and images ----------------------------------------------
build_images() {
	log "rebuilding Motor OS and all images (make images BUILD=release)"
	( cd "$MOTOR" && make images BUILD=release -j"$(nproc)" )
}

# --- the native toolchain ------------------------------------------------------
# Its overlays (llvm, rustc, rust-analyzer, libc) join those of the external
# sources in the assembly, unpacked by motor-os-tar's tar built for Linux.
# Every run unpacks them again, before the external sources are built, so a
# replaced archive takes effect and a bad one fails early.
unpack_native_toolchain() {
	local top="motor-toolchain-$TOOLCHAIN" unpacked="$ASSEMBLY_BUILD_ROOT/native-toolchain"
	local tar="$ASSEMBLY_BUILD_ROOT/motor-os-tar-linux/release/tar" overlay
	log "unpacking the native toolchain from $NATIVE_ARCHIVE"
	( cd "$MOTOR_OS_TAR" && \
		CARGO_TARGET_DIR="$ASSEMBLY_BUILD_ROOT/motor-os-tar-linux" \
			cargo build --release --locked --bin tar )
	rm -rf "$unpacked"
	mkdir -p "$unpacked" "$ASSEMBLY_IMAGE_ROOT"
	"$tar" -x -f "$NATIVE_ARCHIVE" -C "$unpacked"
	for overlay in llvm rustc rust-analyzer libc; do
		rm -rf "${ASSEMBLY_IMAGE_ROOT:?}/$overlay"
		mv "$unpacked/$top/images/$overlay" "$ASSEMBLY_IMAGE_ROOT/$overlay"
	done
	rm -rf "$unpacked"
}

main() {
	local parse_status=0
	parse_options "$@" || parse_status=$?
	[ "$parse_status" -eq 0 ] || {
		[ "$parse_status" -eq 2 ] && return 0
		return "$parse_status"
	}
	local complete=true caller_has_rustup=true
	if [ "$JAVY_ONLY" = true ] || [ "$WASMTIME_ONLY" = true ] || [ "$SYS_LIB_DEPS_ONLY" = true ]; then
		complete=false
	else
		log "complete Motor OS build starting"
		log "Motor OS checkout: $MOTOR"

		local test_ssh_key="$MOTOR/src/tests/test.key"
		[ -f "$test_ssh_key" ] && [ ! -L "$test_ssh_key" ] ||
			die "Motor test SSH key is absent or linked: $test_ssh_key"
		chmod 400 "$test_ssh_key"
		[ -f "$NATIVE_ARCHIVE" ] ||
			die "the native toolchain archive is missing: $NATIVE_ARCHIVE (see docs/toolchain.md)"

		log "provisioning host packages, rustup, and VM prerequisites"
		local base="$SCRIPT_DIR/build-scripts/build-base.sh"
		[ -x "$base" ] || die "required build stage is not executable: $base"
		# The caller's shell keeps its PATH; note whether it can already see rustup.
		command -v rustup >/dev/null 2>&1 || caller_has_rustup=false
		MOTOR_BUILD_ORCHESTRATOR=1 "$base"
		[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
		command -v rustup >/dev/null || die "rustup is unavailable after host provisioning"
	fi
	# Helix and Javy pin toolchains of their own; the exported name overrides them.
	export RUSTUP_TOOLCHAIN="$TOOLCHAIN"
	local toolchain_sysroot
	toolchain_sysroot="$(rustc --print sysroot)"
	SYSROOT="$toolchain_sysroot/lib/rustlib/$TARGET/sysroot"
	LLVM_TOOLS="$toolchain_sysroot/lib/rustlib/x86_64-unknown-linux-gnu/bin"

	if [ "$complete" = false ]; then
		local wasm=false
		if [ "$JAVY_ONLY" = true ] || [ "$WASMTIME_ONLY" = true ]; then
			wasm=true
			local selection=wasm
			if [ "$WASMTIME_ONLY" = false ]; then selection=javy
			elif [ "$JAVY_ONLY" = false ]; then selection=wasmtime; fi
			select_external_sources "$selection"
			prepare_external_sources
			check_external_lockfiles ||
				die "external source preflight failed; see $MOTOR/build/external-lockfiles.log"
		fi
		[ "$wasm" = false ] || ensure_wasm_guest_toolchain
		if [ "$JAVY_ONLY" = true ]; then
			ensure_wasi_sdk
			build_external_source javy "$JAVY_IMG" devtools/bin/javy build_javy
		fi
		[ "$WASMTIME_ONLY" = false ] ||
			build_external_source wasmtime "$WASMTIME_IMG" devtools/bin/wasmtime-rt build_wasmtime
		[ "$SYS_LIB_DEPS_ONLY" = false ] || fetch_sys_lib_deps
		return
	fi
	log "toolchain: $TOOLCHAIN"
	select_external_sources all
	prepare_external_sources
	check_external_lockfiles ||
		die "external source preflight failed; see $MOTOR/build/external-lockfiles.log"
	unpack_native_toolchain
	build_external_sources

	log "building Motor OS and all images with $TOOLCHAIN"
	build_images

	local required_outputs=(
		"$ASSEMBLY_IMAGE_ROOT/llvm/devtools/llvm/bin/llvm"
		"$ASSEMBLY_IMAGE_ROOT/rustc/devtools/rust/bin/rustc"
		"$ASSEMBLY_IMAGE_ROOT/rustc/devtools/rust/bin/rustfmt"
		"$ASSEMBLY_IMAGE_ROOT/rustc/devtools/rust/bin/clippy-driver"
		"$ASSEMBLY_IMAGE_ROOT/rust-analyzer/devtools/rust/bin/rust-analyzer"
		"$RG_IMG/system/bin/rg"
		"$TAR_IMG/system/bin/tar"
		"$TAR_IMG/system/bin/zstd"
		"$HELIX_IMG/devtools/helix/hx"
		"$SED_IMG/devtools/bin/sed"
		"$MOTOR/vm_images/release/motor-os.qcow2"
		"$MOTOR/vm_images/release/motor-os-dev.qcow2"
		"$MOTOR/vm_images/release/motor-os-wasm.qcow2"
		"$JAVY_IMG/devtools/bin/javy"
		"$JAVY_IMG/devtools/bin/wasmi"
		"$WASMTIME_IMG/devtools/bin/wasmtime-rt"
	)
	local output
	for output in "${required_outputs[@]}"; do
		[ -f "$output" ] || die "final build output is missing: $output"
	done
	log "base, standard, dev, and wasm release images built successfully"
	[ "$caller_has_rustup" = true ] ||
		warn "this shell's PATH lacks rustup: open a new shell or run '. \"\$HOME/.cargo/env\"' before make or the tests"
	return 0
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	main "$@"
fi
