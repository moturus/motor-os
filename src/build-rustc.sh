#!/usr/bin/env bash
#
# build-rustc.sh — build a native rustc for Motor OS (rustc + Rust sysroot) and
# bake it into the VM image. The linker driver rustc uses (/bin/cc) and the LLVM
# multicall it fronts (/sys/tools/llvm/bin/llvm) are produced by build-llvm.sh.
#
# This assumes build-base.sh and build-llvm.sh have completed in the same
# directory: the rust checkout with the dev-x86_64-unknown-motor toolchain,
# the host cross clang in llvm-project/build/bin, mlibc, and the populated
# motor-sysroot must all exist. It then performs every step from
# docs/build-rustc.md and finally rebuilds the image.
#
# All Motor OS support lives on `motor-os-rustc` branches of github.com/moturus
# forks, all one LLVM version (23). build-llvm.sh already checked out mlibc and
# llvm-project (LLVM 23) on that branch, so the only checkout this script
# switches is the rust tree: it adds the moturus remote to $MOTORH/rust,
# switches to motor-os-rustc, and seeds the src/llvm-project submodule from
# build-llvm's llvm-project (same LLVM 23 commit, objects shared). The four
# dependency forks are [patch.crates-io] git URLs cargo fetches — not cloned —
# and moto-rt comes from crates.io. No patches of its own.
#
# NOTE: $MOTORH/rust is also what build-base.sh registered the
# dev-x86_64-unknown-motor toolchain against, and `make all` builds every Motor
# OS component with that toolchain. So switching the tree to the fork hands the
# whole Motor OS build over to the fork's compiler and std, and everything built
# with the toolchain beforehand — cargo caches, the clippy binaries in stage2 —
# goes stale. See "This build repurposes the dev toolchain" in docs/build-rustc.md.
#
# On-image layout: the Rust toolchain lives at /sys/tools/rust (bin/rustc,
# lib/rustlib/x86_64-unknown-motor/lib, sample sources at src/). rustc drives the
# link through /bin/cc (from build-llvm.sh) — Motor's system C compiler — which
# it finds on PATH by default, so no `-C linker=` flag is needed (just like
# /usr/bin/cc on Linux).
#
# USAGE
#   Copy this script next to build-base.sh and build-llvm.sh in $MOTORH and,
#   after those two have run:
#
#       ./build-rustc.sh
#
#   These files are kept in the repo at src/ only as the canonical copies to
#   hand out; do not run them from inside a checkout.
#
# RE-RUNNING is safe: fetches and branch switches are no-ops when already in
# place, and the compiles run again (incrementally). A first build is
# ~1.5-2.5 h (two LLVM builds + the compiler crates). See docs/build-rustc.md
# for the prose walkthrough and the pitfall list this script encodes.

set -euo pipefail

# --- logging helpers ---------------------------------------------------------
log()  { printf '\033[1;34m[build-rustc]\033[0m %s\n' "$*"; }
skip() { printf '\033[1;32m[build-rustc]\033[0m (skip) %s\n' "$*"; }
warn() { printf '\033[1;33m[build-rustc]\033[0m WARNING: %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[build-rustc]\033[0m ERROR: %s\n' "$*" >&2; exit 1; }
trap 'die "failed at line $LINENO"' ERR

# --- paths (same scheme as docs/build-rustc.md) ------------------------------
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
MOTORH="$(readlink -f "${MOTORH:-$SCRIPT_DIR}")"
export MOTORH
MOTOR="${MOTOR_OS_DIR:-$MOTORH/motor-os}"
LLVM="$MOTORH/llvm-project"
MLIBC="$MOTORH/mlibc"
RUST="$MOTORH/rust"
B="$LLVM/build/bin"                  # host cross toolchain (build-llvm stage 1)
SYSROOT="$MOTORH/motor-sysroot"
HOST=x86_64-unknown-linux-gnu
TARGET=x86_64-unknown-motor
LLVM_IMG="$MOTOR/img_files/generated/llvm"
RUSTC_IMG="$MOTOR/img_files/generated/rustc"
BRANCH=motor-os-rustc

RUSTC_MAIN="$RUST/build/$HOST/stage2-rustc/$TARGET/release/rustc-main"
STAGE2="$RUST/build/$HOST/stage2"
RUSTLIB_SRC="$STAGE2/lib/rustlib/$TARGET/lib"
MAKE_LOG="$MOTORH/build-rustc-make.log"

# --- prerequisites ------------------------------------------------------------
verify_prereqs() {
	log "verifying build-base/build-llvm prerequisites"
	[ -x "$B/clang" ] || die "host cross clang not found at $B/clang — run build-llvm.sh first"
	[ -d "$RUST/.git" ] || die "rust checkout not found at $RUST — run build-base.sh first"
	local f
	for f in libc.a crt1.o libc++.a libc++abi.a libunwind.a libmoto_rt_cabi.a; do
		[ -f "$SYSROOT/sys/tools/llvm/lib/$f" ] || \
			die "sysroot incomplete ($f missing) — run build-llvm.sh first"
	done
	[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
	rustup toolchain list | grep -q '^dev-x86_64-unknown-motor' || \
		die "dev-x86_64-unknown-motor toolchain not registered — run build-base.sh first"

	# rustc's default linker is the bare name `cc`, resolved on the image's PATH
	# (=/bin), and that script fronts the llvm multicall. Both are build-llvm.sh's
	# staging, and this build only adds the Rust half on top. Without them the
	# image ships a rustc that cannot link anything, and nothing here would notice
	# — the failure would surface only in the VM, at the end of a 2 h build.
	[ -f "$LLVM_IMG/bin/cc" ] || \
		die "$LLVM_IMG/bin/cc is missing — build-llvm.sh stages the linker driver rustc needs; re-run it"
	[ -f "$LLVM_IMG/sys/tools/llvm/bin/llvm" ] || \
		die "$LLVM_IMG/sys/tools/llvm/bin/llvm is missing — build-llvm.sh stages the LLVM multicall that /bin/cc fronts; re-run it"

	# The Motor OS checkout must carry the rustc-era runtime fixes (RT.VDSO
	# ChildStdio EOF mapping + O_APPEND, and a 512 MB data partition).
	grep -q 'E_BAD_HANDLE) => Ok(0)' "$MOTOR/src/sys/lib/rt.vdso/src/stdio.rs" || \
		die "motor-os checkout lacks the ChildStdio EOF fix (rt.vdso/src/stdio.rs) — update the checkout"
	grep -q 'self.metadata(entry_id)?.size' "$MOTOR/src/sys/lib/rt.vdso/src/rt_fs.rs" || \
		die "motor-os checkout lacks the O_APPEND fix (rt.vdso/src/rt_fs.rs) — update the checkout"
	local yaml="$MOTOR/src/imager/motor-os.yaml" size
	size="$(sed -n 's/^data_partition_size_mb: *\([0-9]\{1,\}\).*/\1/p' "$yaml")"
	if [ -z "$size" ] || [ "$size" -lt 512 ]; then
		die "data_partition_size_mb in $yaml must be >= 512 — update the checkout"
	fi
}

# The four dependency forks (libc, rust_libloading, stacker, rust-ctrlc) are NOT
# cloned: the rust fork's [patch.crates-io] references them as moturus git URLs,
# so cargo fetches them. moto-rt comes from crates.io. Nothing to do here.

# --- mlibc: only the sysroot's libc.a matters here ----------------------------
check_mlibc() {
	# rustc links against the *sysroot* libc.a / crt1.o that build-llvm.sh built
	# from mlibc @ motor-os-rustc — the mlibc source tree itself is not needed
	# by this build (it can even be deleted after build-llvm). The one property
	# that matters is that the installed libc.a carries the operator-delete stub
	# guard, i.e. has NO strong _ZdlPvm (the motor-os-rustc branch guarantees
	# this; the older `motor` branch did not).
	if ! "$B/llvm-nm" "$SYSROOT/sys/tools/llvm/lib/libc.a" 2>/dev/null | grep -q 'T _ZdlPvm'; then
		skip "sysroot libc.a already clean of the delete stubs (mlibc source not needed)"
	elif [ -d "$MLIBC/.git" ]; then
		# Stale libc.a (built from the old `motor` branch) but mlibc is present:
		# switch it to motor-os-rustc if needed and rebuild into the sysroot.
		grep -q '__motor__' "$MLIBC/options/internal/gcc-extra/cxxabi.cpp" || \
			die "mlibc lacks the operator-delete stub guard — put it on branch $BRANCH (see build-llvm.sh)"
		log "rebuilding mlibc (sysroot libc.a predates the stub guard)"
		ninja -C "$MLIBC/build"
		( cd "$MLIBC/build" && DESTDIR="$SYSROOT" meson install --no-rebuild >/dev/null )
		"$B/llvm-nm" "$SYSROOT/sys/tools/llvm/lib/libc.a" 2>/dev/null | grep -q 'T _ZdlPvm' && \
			die "strong _ZdlPvm still present in libc.a after rebuild"
	else
		die "sysroot libc.a predates the operator-delete guard and mlibc is not cloned at $MLIBC — re-run build-llvm.sh (or clone moturus/mlibc @ $BRANCH and rebuild)"
	fi
	# Keep the on-image copy in sync (build-llvm stage 8 staged it).
	if [ -f "$LLVM_IMG/sys/tools/llvm/lib/libc.a" ]; then
		"$B/llvm-objcopy" --strip-debug \
			"$SYSROOT/sys/tools/llvm/lib/libc.a" \
			"$LLVM_IMG/sys/tools/llvm/lib/libc.a"
	fi
}

# --- the rust tree: add moturus remote, switch to motor-os-rustc --------------
update_rust() {
	# build.md left the rust tree on upstream rust-lang/rust; add the fork and
	# switch. This is the only checkout that switches branches here.
	if grep -q 'motor-os-rustc' "$RUST/Cargo.toml"; then
		skip "rust tree already carries the motor port"
	else
		if [ -n "$(git -C "$RUST" status --porcelain --untracked-files=no)" ]; then
			die "rust tree is dirty but lacks the motor port — clean it (git stash) and re-run"
		fi
		log "switching rust to moturus/$BRANCH"
		git -C "$RUST" remote add moturus https://github.com/moturus/rust.git 2>/dev/null || true
		git -C "$RUST" fetch -q moturus "$BRANCH"
		git -C "$RUST" switch -q -c "$BRANCH" "moturus/$BRANCH" 2>/dev/null || \
			git -C "$RUST" switch -q "$BRANCH"
	fi

	# Seed rustc's LLVM tree from the checkout build-llvm just compiled, and put
	# it on that checkout's exact commit. Do not use `git submodule update` here:
	# the rust fork currently pins an orphaned pre-amend commit. Besides relying
	# on GitHub to retain that unreachable object, submodule's direct-fetch
	# fallback can reject the local reference with "transport 'file' not
	# allowed" on Ubuntu's Git.
	#
	# A direct local clone is safe here because both paths are controlled build
	# inputs under MOTORH. Keep protocol.file.allow scoped to those commands;
	# never weaken the user's global Git policy. --shared preserves the original
	# --reference optimization, and absorbgitdirs restores the normal submodule
	# gitdir layout.
	local rust_llvm="$RUST/src/llvm-project"
	local llvm_commit llvm_url
	llvm_commit="$(git -C "$LLVM" rev-parse HEAD)"
	llvm_url="$(git -C "$RUST" config -f .gitmodules \
		--get submodule.src/llvm-project.url)"
	[ -n "$llvm_url" ] || die "rust fork has no src/llvm-project URL in .gitmodules"

	git -C "$RUST" submodule init src/llvm-project >/dev/null

	# An uninitialized Rust LLVM submodule can still leave an empty directory
	# here. `git -C "$rust_llvm" rev-parse --git-dir` is not a valid
	# initialization test: Git walks up from that directory, finds $RUST/.git,
	# and reports the *superproject* as though it were the submodule. Require a
	# .git entry of its own and verify that Git considers rust_llvm—not RUST—the
	# worktree root.
	local rust_llvm_top=
	if [ -e "$rust_llvm/.git" ]; then
		rust_llvm_top="$(git -C "$rust_llvm" rev-parse --show-toplevel \
			2>/dev/null || true)"
	fi
	if [ "$(readlink -f "$rust_llvm_top" 2>/dev/null || true)" = "$rust_llvm" ]; then
		skip "rust LLVM submodule already initialized"
	else
		if [ -e "$rust_llvm" ] && [ -n "$(ls -A "$rust_llvm" 2>/dev/null)" ]; then
			die "$rust_llvm exists but is not a Git checkout — move it aside and re-run"
		fi
		log "seeding rust LLVM submodule from $LLVM"
		git -c protocol.file.allow=always clone --no-checkout --shared \
			"$LLVM" "$rust_llvm"
		git -C "$RUST" submodule absorbgitdirs src/llvm-project
	fi

	if ! git -C "$rust_llvm" cat-file -e "$llvm_commit^{commit}" 2>/dev/null; then
		log "importing build-llvm's commit into the existing rust LLVM submodule"
		git -c protocol.file.allow=always -C "$rust_llvm" \
			fetch -q "$LLVM" "$llvm_commit"
	fi
	git -C "$rust_llvm" checkout -q --detach "$llvm_commit"
	git -C "$rust_llvm" remote set-url origin "$llvm_url" 2>/dev/null || \
		git -C "$rust_llvm" remote add origin "$llvm_url"
	git -C "$RUST" config submodule.src/llvm-project.url "$llvm_url"

	[ "$(git -C "$rust_llvm" rev-parse HEAD)" = "$llvm_commit" ] || \
		die "rust LLVM submodule did not reach build-llvm commit $llvm_commit"
	grep -q 'Motor, // Motor OS' "$RUST/src/llvm-project/llvm/include/llvm/TargetParser/Triple.h" || \
		die "src/llvm-project is not on the Motor triple — is $LLVM on moturus/llvm-project @ $BRANCH?"
	grep -q 'set(LLVM_VERSION_MAJOR 23)' "$RUST/src/llvm-project/cmake/Modules/LLVMVersion.cmake" || \
		die "src/llvm-project is not LLVM 23 — check $LLVM"

	# The [patch.crates-io] deps are moturus git URLs and moto-rt is on
	# crates.io, so there are no local paths to rewrite. Refresh the lock so the
	# git patches + moto-rt >= 0.16.1 resolve (no-op if the fork's lock is
	# already current).
	( cd "$RUST" && cargo update -p libloading -p stacker -p libc -p ctrlc >/dev/null 2>&1 || true )
	( cd "$RUST/library" && cargo update -p moto-rt >/dev/null 2>&1 || true )
}

# --- compiler wrappers + bootstrap.toml ---------------------------------------
write_wrappers() {
	log "writing motor-clang / motor-clang++ / motor-rust-cc wrappers"
	mkdir -p "$SYSROOT/bin"
	local cc
	for cc in clang clang++; do
		cat > "$SYSROOT/bin/motor-$cc" << EOF
#!/bin/sh
# Compiler driver for x86_64-unknown-motor cross builds (cmake/cc-rs use this
# for both compiling and linking). --no-default-config bypasses
# build/bin/x86_64-unknown-motor.cfg (its -nostdlib is for the explicit-link
# recipes in build-llvm.sh). The Motor clang driver resolves headers, crt1.o
# and the runtime link group from the sysroot. _GNU_SOURCE/_DEFAULT_SOURCE:
# mlibc hides realpath & friends under strict-ANSI C++ dialects otherwise.
exec $B/$cc --no-default-config \\
  --target=x86_64-unknown-motor --sysroot=$SYSROOT \\
  -D_GNU_SOURCE -D_DEFAULT_SOURCE "\$@"
EOF
		chmod +x "$SYSROOT/bin/motor-$cc"
	done

	cat > "$SYSROOT/bin/motor-rust-cc" << EOF
#!/bin/sh
# Linker driver for Rust binaries targeting x86_64-unknown-motor that link
# mlibc (the libc crate, or rustc itself with its C++ LLVM). rustc passes
# -nostartfiles/-nodefaultlibs, so the Motor clang driver's automatic
# crt1.o + lib group is suppressed; re-add it after rustc's own inputs.
# crt1.o's strong motor_start overrides std's weak one: mlibc initializes
# the C runtime (TCB, stdio, .init_array) and calls the Rust C main.
SR=$SYSROOT
exec $B/clang --no-default-config \\
  --target=x86_64-unknown-motor --sysroot=\$SR "\$@" \\
  -Wl,--start-group \\
  \$SR/sys/tools/llvm/lib/crt1.o \\
  -lmoto_rt_cabi -lc++ -lc++abi -lunwind -lc -lclang_rt.builtins-x86_64 \\
  -Wl,--end-group
EOF
	chmod +x "$SYSROOT/bin/motor-rust-cc"
}

write_bootstrap_toml() {
	if grep -q 'download-ci-llvm' "$RUST/bootstrap.toml" 2>/dev/null; then
		skip "bootstrap.toml already configured for the rustc port"
		return
	fi
	log "writing rust/bootstrap.toml (backing up the build-base one)"
	[ -f "$RUST/bootstrap.toml" ] && cp "$RUST/bootstrap.toml" "$RUST/bootstrap.toml.pre-rustc"
	cat > "$RUST/bootstrap.toml" << EOF
change-id = "ignore"

profile = "library"

[build]
host = ["$HOST"]
target = ["$HOST", "$TARGET"]
# src/llvm-project is moturus/llvm-project @ motor-os-rustc (LLVM 23), the same
# checkout build-llvm builds from; keep bootstrap from resetting it.
submodules = false

[rust]
deny-warnings = false
incremental = true

# --- rustc-on-motor port (see docs/build-rustc.md) ---
# LLVM 23 is built from src/llvm-project for both the build triple and
# x86_64-unknown-motor. X86-only keeps the component lists of the two builds
# identical — rustc_llvm's build.rs queries the *host* llvm-config and rewrites
# host->target paths.
[llvm]
download-ci-llvm = false
targets = "X86"
experimental-targets = ""
static-libstdcpp = false

[target.$TARGET]
cc = "$SYSROOT/bin/motor-clang"
cxx = "$SYSROOT/bin/motor-clang++"
ar = "$B/llvm-ar"
ranlib = "$B/llvm-ranlib"
linker = "$SYSROOT/bin/motor-rust-cc"
EOF
}

# --- build rustc + std --------------------------------------------------------
build_rustc() {
	log "building rustc for $TARGET (first run: ~1.5-2.5 h — two LLVMs + the compiler)"
	# --host is what requests a compiler that *runs on* Motor; --target alone
	# builds nothing new. To force a relink later, delete rustc-main AND the
	# .rustc-stamp next to it (bootstrap trusts the stamp).
	( cd "$RUST" && ./x.py build --stage 2 compiler --host "$TARGET" --target "$TARGET" )
	[ -f "$RUSTC_MAIN" ] || die "rustc-main not produced at $RUSTC_MAIN"
}

build_stds() {
	# ONE x.py INVOCATION, BOTH TARGETS, CLIPPY INCLUDED. This single line is
	# load-bearing in a way that is easy to "tidy" into a broken build, so:
	#
	# Bootstrap's Sysroot step opens with an unconditional
	# `remove_dir_all(build/$HOST/stage2)` ("Removing sysroot ... to avoid
	# caching bugs", src/bootstrap/src/core/build_steps/compile.rs). That is the
	# *dev-x86_64-unknown-motor toolchain directory* — the one `make all` runs
	# on. So every x.py invocation empties the whole stage2 sysroot, bin/ and
	# lib/rustlib/ alike, and re-links only what that invocation builds. The
	# wipe happens once per invocation, so everything named in a single command
	# survives together, while a *later* invocation silently throws away what an
	# earlier one produced:
	#
	#   x.py build library --target A,B   then   x.py build clippy
	#       -> the clippy run wipes the sysroot and puts NO std back. Both
	#          targets lose core+std, and the next `cargo
	#          +dev-x86_64-unknown-motor` — i.e. all of `make all` — dies with
	#          `error[E0463]: can't find crate for core`/`std` ... "target may
	#          not be installed", on whatever dependency it compiles first
	#          (futures-io, futures-sink, ...). It reads as a Motor OS or a
	#          toolchain-registration failure; it is neither, and re-registering
	#          the toolchain cannot help.
	#   x.py build library --target A     then   x.py build library --target B
	#       -> B evicts A's std, same E0463 for A.
	#
	# Naming clippy and library together (exactly what build-base.sh does) makes
	# the whole set survive one wipe, so no ordering can be wrong and nothing has
	# to be copied back afterwards. Do not split this into two commands.
	#
	# clippy must be *rebuilt* here rather than reused: build-base.sh already
	# built it from the tree as it cloned it (upstream rust-lang/rust), so
	# stage2-tools-bin holds binaries from a *different source tree* by the time
	# update_rust switches the checkout to the fork. clippy-driver dynamically
	# loads the hash-suffixed librustc_driver-*.so out of stage2/lib, so a stale
	# pair cannot load (or resolve against) this compiler and the Motor OS build
	# dies in its vdso step (rt.vdso/build.sh runs clippy). Naming clippy here
	# rebuilds it from the fork; it is incremental, and a no-op when current.
	log "building std for both targets + clippy (ONE x.py — each invocation wipes the stage2 sysroot)"
	( cd "$RUST" && ./x.py build --stage 2 clippy library --target "$TARGET,$HOST" )

	# Belt and braces: bootstrap installs the clippy pair into stage2/bin itself,
	# but stage2-tools-bin is the copy that survives a sysroot wipe, so top up
	# from it if a future bootstrap ever stops populating bin/.
	local tb="$RUST/build/$HOST/stage2-tools-bin"
	local b
	for b in cargo-clippy clippy-driver; do
		[ -f "$STAGE2/bin/$b" ] || cp "$tb/$b" "$STAGE2/bin/$b"
	done

	verify_stage2_sysroot
}

# The dev-x86_64-unknown-motor toolchain is exactly build/$HOST/stage2, and
# `make all` compiles every Motor OS component with it. Check here — while the
# rust tree that produced it is still in hand — that it carries everything that
# build needs, rather than letting a gap surface an hour later as an E0463 deep
# inside a dependency crate.
verify_stage2_sysroot() {
	log "verifying the stage2 sysroot the dev toolchain points at"
	local t
	for t in "$TARGET" "$HOST"; do
		[ -n "$(ls "$STAGE2/lib/rustlib/$t/lib"/libcore-*.rlib 2>/dev/null)" ] || \
			die "no core rlib for $t in $STAGE2 — an x.py build ran after the library build and wiped the sysroot (see the ordering note in build_stds)"
		[ -n "$(ls "$STAGE2/lib/rustlib/$t/lib"/libstd-*.rlib 2>/dev/null)" ] || \
			die "no std rlib for $t in $STAGE2 — an x.py build ran after the library build and wiped the sysroot (see the ordering note in build_stds)"
	done

	# clippy-driver links librustc_driver-<hash>.so out of stage2/lib, so this
	# also proves the pair matches the rustc `make all` is about to use.
	"$STAGE2/bin/clippy-driver" --version >/dev/null || \
		die "clippy-driver does not run against the freshly built rustc — Motor OS's vdso step would fail; see the clippy pitfall in docs/build-rustc.md"

	# The end-to-end check: actually compile something for each target with the
	# very toolchain make will use. This is what catches an E0463 here, in one
	# second, instead of an hour into `make all` inside some dependency crate.
	local probe
	probe="$(mktemp -d)"
	printf 'pub fn f() -> u32 { 1 }\n' > "$probe/probe.rs"
	for t in "$TARGET" "$HOST"; do
		"$STAGE2/bin/rustc" --edition 2021 --crate-type rlib --target "$t" \
			-o "$probe/probe-$t.rlib" "$probe/probe.rs" || {
				rm -rf "$probe"
				die "the dev toolchain's rustc cannot compile for $t — the stage2 sysroot is incomplete; make all would fail with E0463 (see the ordering note in build_stds)"
			}
	done
	rm -rf "$probe"
	log "stage2 sysroot OK: std for $TARGET and $HOST, clippy matches rustc"
}

# build-llvm initially creates the C ABI shim with the bootstrap Motor
# toolchain. Rebuild it after the forked stage2 toolchain is complete so the
# DNS resolver and every later mixed Rust+C link use the final std/moto-rt
# implementation. A fresh target directory avoids cargo accepting artifacts
# fingerprinted by the compiler that the rustc stage just replaced.
rebuild_shim() {
	log "rebuilding moto-rt-cabi with the final Motor Rust toolchain"
	local rustlibs=("$RUSTLIB_SRC"/*.rlib)
	local symbol
	for symbol in motor_start memcpy memmove memset memcmp; do
		if "$B/llvm-nm" --defined-only "${rustlibs[@]}" 2>/dev/null |
				awk -v symbol="$symbol" '$2 ~ /^[Tt]$/ && $3 == symbol { found = 1 } END { exit !found }'; then
			die "final Motor target libraries still define strong $symbol; update the motor-os-rustc toolchain before the strict DNS resolver link"
		fi
	done

	local target_dir="$MOTOR/build/native-toolchain/moto-rt-cabi"
	rm -rf "$target_dir"
	( cd "$MOTOR/src/sys/lib/moto-rt-cabi" \
		&& CARGO_TARGET_DIR="$target_dir" \
			cargo +dev-x86_64-unknown-motor build \
				--target "$TARGET" --release )
	local shim="$target_dir/$TARGET/release/libmoto_rt_cabi.a"
	[ -f "$shim" ] || die "final moto-rt-cabi archive was not produced: $shim"
	for symbol in motor_start memcpy memmove memset memcmp; do
		if "$B/llvm-nm" --defined-only "$shim" 2>/dev/null |
				awk -v symbol="$symbol" '$2 ~ /^[Tt]$/ && $3 == symbol { found = 1 } END { exit !found }'; then
			die "final moto-rt-cabi still defines strong $symbol; the strict DNS resolver link would be unsafe"
		fi
	done
	cp "$shim" "$SYSROOT/sys/tools/llvm/lib/libmoto_rt_cabi.a"

	# build-llvm has already staged the C sysroot. Keep that generated image
	# tree synchronized with the final shim before the imager consumes it.
	[ -d "$LLVM_IMG/sys/tools/llvm/lib" ] ||
		die "generated LLVM image tree is missing: $LLVM_IMG"
	"$B/llvm-objcopy" --strip-debug \
		"$shim" "$LLVM_IMG/sys/tools/llvm/lib/libmoto_rt_cabi.a"
}

# cc — the system C compiler / linker driver rustc uses on the image — is not
# built here: it is a `#!/bin/rush` script produced by build-llvm.sh (it belongs
# with the C toolchain: it fronts /sys/tools/llvm/bin/llvm and the sysroot libs).
# rustc's default linker is the bare name `cc`, resolved on PATH (=/bin on the
# image), so a native `rustc hello.rs -o hello` links with no `-C linker=` flag,
# exactly as rustc uses /usr/bin/cc on Linux. Nothing to do in this build.

# --- stage everything into the image ------------------------------------------
stage_image() {
	log "staging rustc and the Rust sysroot into img_files/generated/rustc"
	# Remove generated files left in the tracked static root by the old
	# workflow; duplicate destinations across static roots are invalid.
	rm -rf "$MOTOR/img_files/motor-os/sys/tools/rust"
	rm -f "$MOTOR/img_files/motor-os/bin/motor-cc"
	rm -rf "$RUSTC_IMG"
	local rust_img="$RUSTC_IMG/sys/tools/rust"
	mkdir -p "$rust_img/bin" "$rust_img/src" \
		"$rust_img/lib/rustlib/$TARGET"

	# The compiler, stripped (~154 MB -> ~98 MB).
	"$B/llvm-strip" -o "$rust_img/bin/rustc" "$RUSTC_MAIN"
	# A binary that still carries mlibc's operator-delete panic stub would
	# abort at runtime; the stub guard must have taken effect.
	if grep -aq 'operator delete called! delete expressions' "$rust_img/bin/rustc"; then
		die "staged rustc contains mlibc's operator-delete stub — sysroot libc.a is stale (see docs/build-rustc.md pitfalls)"
	fi

	# The Rust sysroot. Copy the whole lib dir: the rlibs carry only metadata
	# *stubs* (bootstrap uses -Zembed-metadata=no) — the .rmeta siblings and
	# self-contained/ must come along or rustc fails with "only metadata stub
	# found for rlib dependency `std`".
	rm -rf "$rust_img/lib/rustlib/$TARGET/lib"
	mkdir -p "$rust_img/lib/rustlib/$TARGET/lib"
	cp -r "$RUSTLIB_SRC"/* "$rust_img/lib/rustlib/$TARGET/lib/"
	[ -n "$(ls "$rust_img/lib/rustlib/$TARGET/lib"/*.rmeta 2>/dev/null)" ] || \
		die "no .rmeta files staged — rustc on the image would reject every rlib"

	# (/bin/cc, the linker driver rustc uses, is a rush script staged by
	# build-llvm.sh — nothing to stage here.)

	# A sample source exercising HashMap, sorting, and thread spawn/join.
	cat > "$rust_img/src/hello.rs" << 'EOF'
use std::collections::HashMap;

fn main() {
    let mut m = HashMap::new();
    for (i, w) in "hello from rustc running natively on motor os".split(' ').enumerate() {
        m.insert(w, i);
    }
    let mut kv: Vec<_> = m.into_iter().collect();
    kv.sort_by_key(|&(_, i)| i);
    let words: Vec<&str> = kv.into_iter().map(|(w, _)| w).collect();
    println!("{}", words.join(" "));
    let t = std::thread::spawn(|| (1..=10u64).product::<u64>());
    println!("10! = {}", t.join().unwrap());
}
EOF
}

# --- rebuild the OS and the image ---------------------------------------------
build_image() {
	# Two builds of the same rust tree produce byte-different compilers with
	# identical `rustc -vV`, which is all cargo fingerprints — every cache
	# built with the previous dev toolchain is silently poisoned (E0463
	# "can't find crate" for random deps). Clear before rebuilding. src/sys/target
	# is the workspace target dir build-llvm.sh's shim stage builds into with the
	# same dev toolchain, so it is poisoned too.
	log "clearing the Motor OS cargo caches (stale after the rustc rebuild)"
	rm -rf "$MOTOR/build/obj/release" "$MOTOR/src/sys/target"

	log "rebuilding Motor OS + image (make all BUILD=release)"
	# Keep make's output visible: when a component fails, the compiler diagnostic
	# is the whole diagnosis, and the log alone is easy to overlook.
	( cd "$MOTOR" && \
		make all BUILD=release MOTOR_DNS_STRICT_LINK=1 -j"$(nproc)" ) \
		2>&1 | tee "$MAKE_LOG"
	grep -q 'built Motor OS image' "$MAKE_LOG" || \
		die "make finished without the imager running — see $MAKE_LOG"
}

main() {
	log "Motor OS native rustc build starting; MOTORH = $MOTORH"
	verify_prereqs
	check_mlibc
	update_rust
	write_wrappers
	write_bootstrap_toml
	build_rustc
	build_stds
	rebuild_shim
	stage_image
	build_image
	log "done — the image at $MOTOR/vm_images/release now carries a native rustc."
	log "to run the VM:  cd \"$MOTOR/vm_images/release\" && ./run-qemu.sh"
	log "then, at the Motor OS prompt:"
	log "  /sys/tools/rust/bin/rustc --version"
	log "  /sys/tools/rust/bin/rustc /sys/tools/rust/src/hello.rs -o /sys/tmp/hello"
	log "  /sys/tmp/hello"
}

main "$@"
