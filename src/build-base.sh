#!/usr/bin/env bash
#
# build-base.sh — private host provisioning for build-motor-os.sh.
#
# This file remains sourceable by its offline host-networking test. It may be
# executed only by build-motor-os.sh; contributors use src/build-motor-os.sh.
#
# MOTORH and MOTOR_OS_DIR are supplied by the unified orchestrator.
#   MOTOR_SKIP_HOST_NETWORK_SETUP=1 skips the privileged tap/NAT setup when
#   the caller has independently verified the host network configuration.
#
# WHAT IT DOES, mirroring docs/build.md:
#   1. install host build packages via apt          [skipped if already present]
#   2. install rustup without selecting a default    [skipped if already present]
#   3. create the moto-tap interface + /dev/kvm access [skipped if already done]
#
#   It does NOT launch the VM (run-qemu.sh) — that is left to you.
#
# RE-RUNNING is safe: completed setup steps are detected and skipped.
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

# Build deps from docs/build.md, plus qemu-system so the host is ready to run
# the VM and qemu-utils so the complete build can create qcow2 images (this
# script still stops short of actually running a VM).
#
# zlib1g-dev, not the libz-dev that docs/build.md names: libz-dev is a pure
# virtual package (zlib1g-dev "Provides: libz-dev"), and dpkg-query never
# reports a virtual package as installed. Listing it here made the "missing"
# probe below always fire, so every single run — including a fully provisioned
# re-run — did `apt-get update` plus a full `apt-get -y upgrade`, needing sudo
# and defeating this script's own "skipped if already present" promise (and any
# unattended re-run). Naming the real package makes the probe work.
PACKAGES=(git build-essential nasm clang cmake ninja-build \
          zlib1g-dev libssl-dev pkg-config curl qemu-system qemu-utils)

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

# --- 2. rustup, deliberately without a default toolchain --------------------
install_rust() {
	# Bring cargo/rustup onto PATH if a previous run (or the user) installed it.
	[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

	if command -v rustup >/dev/null 2>&1; then
		skip "rustup already installed"
	else
		log "installing rustup without a default toolchain"
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
			sh -s -- -y --default-toolchain none
		. "$HOME/.cargo/env"
	fi
}

# --- 3. host VM prerequisites (tap + kvm), but NOT running the VM -----------
host_networking_ready() {
	[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ] || return 1
	ip -o link show dev moto-tap 2>/dev/null | grep -q '<[^>]*UP[,>]' || return 1
	ip -o -4 addr show dev moto-tap 2>/dev/null |
		awk '$4 == "192.168.4.1/24" { found = 1 } END { exit !found }' || return 1
	ip -o -6 addr show dev moto-tap 2>/dev/null |
		awk '$4 == "2001:db8::1/64" { found = 1 } END { exit !found }'
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
		fi
	fi
	if ! ip -o -4 addr show dev moto-tap 2>/dev/null |
			awk '$4 == "192.168.4.1/24" { found = 1 } END { exit !found }'; then
		log "adding the IPv4 address to moto-tap"
		sudo ip addr add 192.168.4.1/24 dev moto-tap
	fi
	if ! ip -o -6 addr show dev moto-tap 2>/dev/null |
			awk '$4 == "2001:db8::1/64" { found = 1 } END { exit !found }'; then
		log "adding the IPv6 address to moto-tap"
		sudo ip -6 addr add 2001:db8::1/64 dev moto-tap
	fi
	if ! ip -o link show dev moto-tap 2>/dev/null |
			grep -q '<[^>]*UP[,>]'; then
		sudo ip link set moto-tap up
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
	log "Motor OS host provisioning starting; MOTORH = $MOTORH"
	install_packages
	install_rust
	setup_host_vm_prereqs
	log "host provisioning complete"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	[ "${MOTOR_BUILD_ORCHESTRATOR:-0}" = "1" ] ||
		die "build-base.sh is private; run src/build-motor-os.sh"
	main "$@"
fi
