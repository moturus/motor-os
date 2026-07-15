#!/usr/bin/env bash
#
# build-base.sh — set up a Motor OS development environment from scratch and
# build the base OS image, following docs/build.md.
#
# USAGE
#   Copy this script into an empty directory and run it there:
#
#       ./build-base.sh
#
#   The directory the script lives in becomes $MOTORH (the Motor OS dev root).
#   Everything is cloned/built underneath it. This file is kept in the repo at
#   src/build-base.sh only as the canonical copy to hand out; do not run it from
#   inside a checkout (that would make $MOTORH be .../motor-os/src).
#
# WHAT IT DOES (all under $MOTORH), mirroring docs/build.md:
#   1. install host build packages via apt          [skipped if already present]
#   2. install rustup + the pinned nightly toolchain [skipped if already present]
#   3. clone + build the Rust Motor OS toolchain      [clone skipped if present]
#   4. clone the motor-os repo                         [skipped if already present]
#   5. build Motor OS: make all BUILD=release          [always; incremental]
#   6. create the moto-tap interface + /dev/kvm access [skipped if already done]
#
#   It does NOT launch the VM (run-qemu.sh) — that is left to you.
#
# RE-RUNNING is safe: completed setup steps are detected and skipped; only the
# (incremental) compiles run again.
#
# See docs/build.md for the prose walkthrough behind each step.

set -euo pipefail

# --- logging helpers --------------------------------------------------------
log()  { printf '\033[1;34m[build-base]\033[0m %s\n' "$*"; }
skip() { printf '\033[1;32m[build-base]\033[0m (skip) %s\n' "$*"; }
warn() { printf '\033[1;33m[build-base]\033[0m WARNING: %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[build-base]\033[0m ERROR: %s\n' "$*" >&2; exit 1; }
trap 'die "failed at line $LINENO"' ERR

# --- $MOTORH is the directory this script lives in --------------------------
MOTORH="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
export MOTORH

# --- pins (keep in sync with docs/build.md) ---------------------------------
NIGHTLY="nightly-2026-06-19"
HOST_TRIPLE="x86_64-unknown-linux-gnu"
# Build deps from docs/build.md, plus qemu-system so the host is ready to run
# the VM (this script still stops short of actually running it).
#
# zlib1g-dev, not the libz-dev that docs/build.md names: libz-dev is a pure
# virtual package (zlib1g-dev "Provides: libz-dev"), and dpkg-query never
# reports a virtual package as installed. Listing it here made the "missing"
# probe below always fire, so every single run — including a fully provisioned
# re-run — did `apt-get update` plus a full `apt-get -y upgrade`, needing sudo
# and defeating this script's own "skipped if already present" promise (and any
# unattended re-run). Naming the real package makes the probe work.
PACKAGES=(git build-essential nasm clang cmake ninja-build \
          zlib1g-dev libssl-dev pkg-config curl qemu-system)

# --- 1. host packages -------------------------------------------------------
install_packages() {
	if ! command -v apt-get >/dev/null 2>&1; then
		warn "apt-get not found; skipping automatic package installation."
		warn "Install these manually: ${PACKAGES[*]}"
		return
	fi

	local missing=()
	local p
	for p in "${PACKAGES[@]}"; do
		if ! dpkg-query -W -f='${Status}' "$p" 2>/dev/null \
			| grep -q 'install ok installed'; then
			missing+=("$p")
		fi
	done

	if [ ${#missing[@]} -eq 0 ]; then
		skip "all host packages already installed"
		return
	fi

	log "installing host packages (missing: ${missing[*]})"
	sudo apt-get update
	sudo DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
	sudo DEBIAN_FRONTEND=noninteractive apt-get -y install "${PACKAGES[@]}"
}

# --- 2. rustup + pinned nightly ---------------------------------------------
install_rust() {
	# Bring cargo/rustup onto PATH if a previous run (or the user) installed it.
	[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

	if command -v rustup >/dev/null 2>&1; then
		skip "rustup already installed"
	else
		log "installing rustup (non-interactive)"
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
		. "$HOME/.cargo/env"
	fi

	# Idempotent: installs the toolchain on the first run, no-ops afterwards.
	log "selecting ${NIGHTLY} + rust-src (pinned per docs/build.md)"
	rustup default "${NIGHTLY}"
	rustup component add rust-src --toolchain "${NIGHTLY}-${HOST_TRIPLE}"
}

# --- 3. Rust Motor OS toolchain ---------------------------------------------
build_rust_toolchain() {
	if [ -d "$MOTORH/rust/.git" ]; then
		skip "rust sources already cloned"
	else
		log "cloning rust-lang/rust (large; this can take a while)"
		git clone https://github.com/rust-lang/rust.git "$MOTORH/rust"
	fi

	if [ -f "$MOTORH/rust/bootstrap.toml" ]; then
		skip "rust/bootstrap.toml already present"
	else
		log "writing rust/bootstrap.toml"
		cat > "$MOTORH/rust/bootstrap.toml" << 'EOF'
change-id = "ignore"

profile = "library"

[build]
host = ["x86_64-unknown-linux-gnu"]
target = ["x86_64-unknown-linux-gnu", "x86_64-unknown-motor"]

[rust]
# std-features = ["debug_refcell"]
deny-warnings = false
incremental = true
# debug = true
# debuginfo-level = 2
EOF
	fi

	log "building the Rust Motor OS toolchain (x.py build --stage 2 ...)"
	( cd "$MOTORH/rust" \
		&& ./x.py build --stage 2 clippy library src/tools/remote-test-server )

	if rustup toolchain list | grep -q '^dev-x86_64-unknown-motor'; then
		skip "dev-x86_64-unknown-motor toolchain already linked"
	else
		log "registering the dev-x86_64-unknown-motor toolchain"
		rustup toolchain link dev-x86_64-unknown-motor \
			"$MOTORH/rust/build/${HOST_TRIPLE}/stage2"
	fi
}

# --- 4. motor-os repo -------------------------------------------------------
clone_motor_os() {
	if [ -d "$MOTORH/motor-os/.git" ]; then
		skip "motor-os already cloned"
	else
		log "cloning moturus/motor-os"
		git clone https://github.com/moturus/motor-os.git "$MOTORH/motor-os"
	fi
}

# --- 5. build Motor OS ------------------------------------------------------
build_motor_os() {
	log "building Motor OS (make all BUILD=release)"
	( cd "$MOTORH/motor-os" && make all BUILD=release -j"$(nproc)" )
}

# --- 6. host VM prerequisites (tap + kvm), but NOT running the VM -----------
setup_host_vm_prereqs() {
	# moto-tap network interface (create-tap.sh is not idempotent on its own).
	if ip link show moto-tap >/dev/null 2>&1; then
		skip "moto-tap interface already exists"
	else
		log "creating the moto-tap interface"
		local tap="$MOTORH/motor-os/vm_images/release/create-tap.sh"
		if [ -f "$tap" ]; then
			sh "$tap"
		else
			sudo ip tuntap add mode tap moto-tap
			sudo ip addr add 192.168.4.1/24 dev moto-tap
			sudo ip link set moto-tap up
		fi
	fi

	# /dev/kvm access — needed to run the VM; harmless to grant now.
	if [ -e /dev/kvm ]; then
		if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
			skip "/dev/kvm already accessible"
		else
			log "granting read/write access to /dev/kvm"
			sudo chmod a+rw /dev/kvm
		fi
	else
		warn "/dev/kvm not present — KVM may be unavailable on this host"
	fi
}

main() {
	log "Motor OS base build starting; MOTORH = $MOTORH"
	install_packages
	install_rust
	build_rust_toolchain
	clone_motor_os
	build_motor_os
	setup_host_vm_prereqs
	log "done — the environment is ready."
	log "to run the VM:  cd \"$MOTORH/motor-os/vm_images/release\" && ./run-qemu.sh"
}

main "$@"
