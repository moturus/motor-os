#!/usr/bin/env bash
#
# build-rustc.sh — build a native rustc for Motor OS (rustc + Rust sysroot +
# the motor-cc linker driver) and bake it into the VM image.
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
# switches to motor-os-rustc, and points the src/llvm-project submodule at
# build-llvm's llvm-project (same LLVM 23 commit, objects shared). The four
# dependency forks are [patch.crates-io] git URLs cargo fetches — not cloned —
# and moto-rt comes from crates.io. No patches of its own.
#
# On-image layout: the Rust toolchain lives at /sys/tools/rust (bin/rustc,
# lib/rustlib/x86_64-unknown-motor/lib, sample sources at src/), the linker
# driver at /bin/motor-cc.
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
MOTORH="$SCRIPT_DIR"
export MOTORH
MOTOR="$MOTORH/motor-os"
LLVM="$MOTORH/llvm-project"
MLIBC="$MOTORH/mlibc"
RUST="$MOTORH/rust"
B="$LLVM/build/bin"                  # host cross toolchain (build-llvm stage 1)
SYSROOT="$MOTORH/motor-sysroot"
HOST=x86_64-unknown-linux-gnu
TARGET=x86_64-unknown-motor
IMG="$MOTOR/img_files/motor-os"
BRANCH=motor-os-rustc

RUSTC_MAIN="$RUST/build/$HOST/stage2-rustc/$TARGET/release/rustc-main"
STAGE2="$RUST/build/$HOST/stage2"
RUSTLIB_SRC="$STAGE2/lib/rustlib/$TARGET/lib"

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
	if [ -f "$IMG/sys/tools/llvm/lib/libc.a" ]; then
		cp "$SYSROOT/sys/tools/llvm/lib/libc.a" "$IMG/sys/tools/llvm/lib/libc.a"
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

	# The fork's .gitmodules points src/llvm-project at moturus/llvm-project @
	# motor-os-rustc (LLVM 23) with the gitlink at the right commit, so a plain
	# submodule update checks out the LLVM 23 tree. --reference reuses the
	# objects of build-llvm's $MOTORH/llvm-project (the same commit), so nothing
	# is re-downloaded. bootstrap.toml sets submodules = false so bootstrap
	# leaves this checkout alone afterwards.
	git -C "$RUST" submodule update --init --progress --reference "$LLVM" src/llvm-project
	grep -q 'Motor, // Motor OS' "$RUST/src/llvm-project/llvm/include/llvm/TargetParser/Triple.h" || \
		die "src/llvm-project is not on the Motor triple — does moturus/rust $BRANCH pin moturus/llvm-project @ $BRANCH?"
	grep -q 'set(LLVM_VERSION_MAJOR 23)' "$RUST/src/llvm-project/cmake/Modules/LLVMVersion.cmake" || \
		die "src/llvm-project is not LLVM 23 — check the moturus/rust $BRANCH submodule pin"

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
	log "building std for both targets (single invocation — one target evicts the other)"
	( cd "$RUST" && ./x.py build --stage 2 library --target "$TARGET,$HOST" )
	[ -n "$(ls "$RUSTLIB_SRC"/libstd-*.rlib 2>/dev/null)" ] || \
		die "motor std rlibs missing from $RUSTLIB_SRC"

	# Every x.py build recreates stage2/bin, dropping the clippy binaries the
	# Motor OS vdso build step needs; restore them.
	if [ -f "$RUST/build/$HOST/stage2-tools-bin/cargo-clippy" ]; then
		cp "$RUST/build/$HOST/stage2-tools-bin/"{cargo-clippy,clippy-driver} \
			"$RUST/build/$HOST/stage2/bin/"
	else
		log "building clippy (stage2-tools-bin is empty)"
		( cd "$RUST" && ./x.py build --stage 2 clippy )
		cp "$RUST/build/$HOST/stage2-tools-bin/"{cargo-clippy,clippy-driver} \
			"$RUST/build/$HOST/stage2/bin/"
	fi
}

# --- motor-cc: the on-image linker driver -------------------------------------
build_motor_cc() {
	log "building motor-cc (the on-image linker driver)"
	mkdir -p "$MOTORH/motor-cc/src"
	cat > "$MOTORH/motor-cc/Cargo.toml" << 'EOF'
[package]
name = "motor-cc"
version = "0.1.0"
edition = "2021"

[profile.release]
opt-level = "s"
EOF
	cat > "$MOTORH/motor-cc/src/main.rs" << 'EOF'
//! cc-style linker driver for rustc running natively on Motor OS.
//!
//! rustc invokes the linker with `-nostartfiles ... -nodefaultlibs`, which
//! suppresses the Motor clang driver's automatic crt1.o + runtime link
//! group. This wrapper re-invokes the on-image `llvm` multicall as `clang`
//! and appends that group after rustc's own inputs, so mlibc owns the entry
//! point (its crt1 initializes the C runtime and calls the Rust C main).

use std::process::{exit, Command};

const LIB: &str = "/sys/tools/llvm/lib";

fn main() {
    let mut cmd = Command::new("/bin/llvm");
    cmd.arg("clang");
    cmd.args(std::env::args().skip(1));
    cmd.arg("-Wl,--start-group");
    cmd.arg(format!("{LIB}/crt1.o"));
    for lib in ["-lmoto_rt_cabi", "-lc++", "-lc++abi", "-lunwind", "-lc", "-lclang_rt.builtins-x86_64"] {
        cmd.arg(lib);
    }
    cmd.arg("-Wl,--end-group");
    match cmd.status() {
        Ok(st) => exit(st.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("motor-cc: failed to spawn /bin/llvm: {e}");
            exit(1);
        }
    }
}
EOF
	( cd "$MOTORH/motor-cc" && \
		cargo +dev-x86_64-unknown-motor build --target "$TARGET" --release )
}

# --- stage everything into the image ------------------------------------------
stage_image() {
	log "staging rustc, the Rust sysroot, and motor-cc into img_files"
	local rust_img="$IMG/sys/tools/rust"
	mkdir -p "$IMG/bin" "$rust_img/bin" "$rust_img/src" \
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

	# The linker driver.
	cp "$MOTORH/motor-cc/target/$TARGET/release/motor-cc" "$IMG/bin/"

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
	# "can't find crate" for random deps). Clear before rebuilding.
	log "clearing the Motor OS cargo caches (stale after the rustc rebuild)"
	rm -rf "$MOTOR/build/obj/release"

	log "rebuilding Motor OS + image (make all BUILD=release)"
	( cd "$MOTOR" && make all BUILD=release -j"$(nproc)" ) | tee /tmp/build-rustc-make.log | tail -2
	grep -q 'built Motor OS image' /tmp/build-rustc-make.log || \
		die "make finished without the imager running — see /tmp/build-rustc-make.log"
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
	build_motor_cc
	stage_image
	build_image
	log "done — the image at $MOTOR/vm_images/release now carries a native rustc."
	log "to run the VM:  cd \"$MOTOR/vm_images/release\" && ./run-qemu.sh"
	log "then, at the Motor OS prompt:"
	log "  /sys/tools/rust/bin/rustc --version"
	log "  /sys/tools/rust/bin/rustc /sys/tools/rust/src/hello.rs -o /sys/tmp/hello -C linker=/bin/motor-cc"
	log "  /sys/tmp/hello"
}

main "$@"
