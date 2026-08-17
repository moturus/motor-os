#!/usr/bin/env bash
#
# build-base.sh — set up a Motor OS development environment from scratch and
# build the base OS image, following docs/build.md.
#
# USAGE
#   Run it from a Motor OS checkout (src/build-base.sh), or copy it into an
#   empty directory and run it there:
#
#       ./build-base.sh
#
#   From a checkout, the checkout's parent becomes $MOTORH (the Motor OS dev
#   root); copied out, the directory the script lives in becomes $MOTORH.
#   MOTORH and MOTOR_OS_DIR override either default (the unified
#   build-motor-os.sh sets both).
#   MOTOR_SKIP_HOST_NETWORK_SETUP=1 skips the privileged tap/NAT setup when
#   the caller has independently verified the host network configuration.
#
# WHAT IT DOES (all under $MOTORH), mirroring docs/build.md:
#   1. install host build packages via apt          [skipped if already present]
#   2. install rustup + the pinned nightly toolchain [skipped if already present]
#   3. clone + build the Rust Motor OS toolchain      [clone skipped if present]
#   4. clone the motor-os repo                         [skipped if already present]
#   5. build the base image                         [incremental]
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

# --- development root and Motor OS checkout ---------------------------------
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
# In a checkout, this script lives in <repo>/src: the repo is the Motor OS
# tree and $MOTORH defaults to its parent. Copied out into an empty dev root,
# the script's own directory is $MOTORH and the repo gets cloned beneath it.
if [ -e "$SCRIPT_DIR/../.git" ]; then
	MOTOR_DEFAULT="$(readlink -f "$SCRIPT_DIR/..")"
	MOTORH="$(readlink -f "${MOTORH:-$MOTOR_DEFAULT/..}")"
	MOTOR="${MOTOR_OS_DIR:-$MOTOR_DEFAULT}"
else
	MOTORH="$(readlink -f "${MOTORH:-$SCRIPT_DIR}")"
	MOTOR="${MOTOR_OS_DIR:-$MOTORH/motor-os}"
fi
export MOTORH

# --- pins (keep in sync with docs/build.md) ---------------------------------
NIGHTLY="nightly-2026-06-19"
HOST_TRIPLE="x86_64-unknown-linux-gnu"
RUST_REPO="https://github.com/moturus/rust.git"
RUST_BASE_BRANCH="motor-os-rt-v17"
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
	# Once build-motor-os.sh's rustc stage has taken over the checkout (the
	# motor-os-rustc compiler branch and its bootstrap.toml), the dev toolchain
	# is built there. Switching back to motor-os-rt-v17 here would rebuild it
	# from the wrong branch against the wrong LLVM (and x.py's stage2 sysroot
	# wipe would break the working toolchain first) — leave the tree alone.
	if [ -d "$MOTORH/rust/.git" ]; then
		local rust_branch
		rust_branch="$(git -C "$MOTORH/rust" branch --show-current 2>/dev/null)"
		if [ "$rust_branch" = "motor-os-rustc" ] || \
				grep -q 'download-ci-llvm' "$MOTORH/rust/bootstrap.toml" 2>/dev/null; then
			skip "rust toolchain (owned by build-motor-os.sh's rustc stage; tree on ${rust_branch:-a detached HEAD})"
			return
		fi
	fi

	if [ -d "$MOTORH/rust/.git" ]; then
		skip "rust sources already cloned"
	else
		log "cloning moturus/rust @ $RUST_BASE_BRANCH (large; this can take a while)"
		git clone --branch "$RUST_BASE_BRANCH" "$RUST_REPO" "$MOTORH/rust"
	fi

	local current_branch
	current_branch="$(git -C "$MOTORH/rust" branch --show-current)"
	if [ "$current_branch" = "$RUST_BASE_BRANCH" ]; then
		skip "rust sources already on $RUST_BASE_BRANCH"
	else
		if [ -n "$(git -C "$MOTORH/rust" status --porcelain --untracked-files=no)" ]; then
			die "rust tree is dirty on $current_branch — clean it (git stash) and re-run"
		fi
		if git -C "$MOTORH/rust" show-ref --verify --quiet \
				"refs/heads/$RUST_BASE_BRANCH"; then
			log "switching rust to local $RUST_BASE_BRANCH"
			git -C "$MOTORH/rust" switch -q "$RUST_BASE_BRANCH"
		else
			log "fetching moturus/rust @ $RUST_BASE_BRANCH"
			git -C "$MOTORH/rust" remote add moturus "$RUST_REPO" 2>/dev/null || true
			git -C "$MOTORH/rust" fetch -q moturus "$RUST_BASE_BRANCH"
			git -C "$MOTORH/rust" switch -q -c "$RUST_BASE_BRANCH" \
				"moturus/$RUST_BASE_BRANCH"
		fi
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
	if [ -e "$MOTOR/.git" ]; then
		skip "motor-os already cloned"
	else
		log "cloning moturus/motor-os"
		git clone https://github.com/moturus/motor-os.git "$MOTOR"
	fi
}

# --- 5. build the Motor OS base image ---------------------------------------
build_motor_os() {
	log "building the Motor OS base image (make base.img BUILD=release)"
	( cd "$MOTOR" && make base.img BUILD=release -j"$(nproc)" )
}

# --- 6. host VM prerequisites (tap + kvm), but NOT running the VM -----------
host_networking_ready() {
	[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ] || return 1
	ip -o link show dev moto-tap 2>/dev/null | grep -q '<[^>]*UP[,>]' || return 1
	ip -o -4 addr show dev moto-tap 2>/dev/null |
		awk '$4 == "192.168.4.1/24" { found = 1 } END { exit !found }'
}

setup_host_networking() {
	if [ "${MOTOR_SKIP_HOST_NETWORK_SETUP:-0}" = "1" ]; then
		skip "host networking setup (explicitly bypassed)"
		return
	fi
	if host_networking_ready; then
		skip "host networking already configured"
		return
	fi

	# moto-tap network interface (create-tap.sh is not idempotent on its own).
	if ip link show moto-tap >/dev/null 2>&1; then
		skip "moto-tap interface already exists"
	else
		log "creating the moto-tap interface"
		local tap="$MOTOR/vm_images/release/create-tap.sh"
		if [ -f "$tap" ]; then
			sh "$tap"
		else
			sudo ip tuntap add mode tap moto-tap
			sudo ip addr add 192.168.4.1/24 dev moto-tap
			sudo ip link set moto-tap up
		fi
	fi

	log "configuring nft routing"
	sudo sysctl -w net.ipv4.ip_forward=1
	if ! sudo nft list table ip nat >/dev/null 2>&1; then
		sudo nft add table ip nat
	fi
	if ! sudo nft list chain ip nat postrouting >/dev/null 2>&1; then
		sudo nft add chain ip nat postrouting \
			'{ type nat hook postrouting priority 100; policy accept; }'
	fi
	if ! sudo nft list chain ip nat postrouting |
			grep -q 'ip saddr 192\.168\.4\.0/24 masquerade'; then
		sudo nft add rule ip nat postrouting \
			ip saddr 192.168.4.0/24 masquerade
	fi
}

setup_host_vm_prereqs() {
	setup_host_networking

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
	if [ "${MOTOR_SKIP_OS_BUILD:-0}" = "1" ]; then
		skip "base Motor OS image build (deferred to the unified toolchain build)"
	elif ! "$MOTORH/rust/build/${HOST_TRIPLE}/stage2/bin/rustc" --version \
			>/dev/null 2>&1; then
		die "the dev-x86_64-unknown-motor toolchain is not functional — run src/build-motor-os.sh (its rustc stage rebuilds it), then re-run this script"
	else
		build_motor_os
	fi
	setup_host_vm_prereqs
	log "done — the environment is ready."
	if [ -f "$MOTOR/vm_images/release/motor-os-base.img" ]; then
		log "to run the VM:  cd \"$MOTOR/vm_images/release\" && MOTO_IMAGE=motor-os-base.img ./run-qemu.sh"
	else
		log "next: run $MOTOR/src/build-motor-os.sh to build the complete main image"
	fi
}

main "$@"
