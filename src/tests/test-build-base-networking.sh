#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/build-base.sh"

fail_test() {
  echo "test-build-base-networking: $*" >&2
  exit 1
}

ipv4=1
ipv6=0
sudo_calls=()

cat() {
  if [ "$#" -eq 1 ] && [ "$1" = /proc/sys/net/ipv4/ip_forward ]; then
    printf '1\n'
  else
    command cat "$@"
  fi
}

ip() {
  case "$*" in
    '-o link show dev moto-tap')
      printf '4: moto-tap: <BROADCAST,MULTICAST,UP> mtu 1500\n'
      ;;
    'link show moto-tap')
      return 0
      ;;
    '-o -4 addr show dev moto-tap')
      if [ "$ipv4" -eq 1 ]; then
        printf '4: moto-tap inet 192.168.4.1/24 scope global moto-tap\n'
      fi
      ;;
    '-o -6 addr show dev moto-tap')
      if [ "$ipv6" -eq 1 ]; then
        printf '4: moto-tap inet6 2001:db8::1/64 scope global\n'
      fi
      ;;
    *)
      fail_test "unexpected ip command: $*"
      ;;
  esac
}

sudo() {
  sudo_calls+=("$*")
  case "$*" in
    'ip -6 addr add 2001:db8::1/64 dev moto-tap')
      ipv6=1
      ;;
    'sysctl -w net.ipv4.ip_forward=1')
      ;;
    'nft list table ip nat')
      ;;
    'nft list chain ip nat postrouting')
      printf 'ip saddr 192.168.4.0/24 masquerade\n'
      ;;
    *)
      fail_test "unexpected sudo command: $*"
      ;;
  esac
}

log() { :; }
skip() { :; }

if host_networking_ready; then
  fail_test "networking without the required IPv6 address was accepted"
fi

setup_host_networking
[ "$ipv6" -eq 1 ] || fail_test "setup did not add the IPv6 address"
host_networking_ready || fail_test "repaired networking was not accepted"

ipv6_adds=0
for call in "${sudo_calls[@]}"; do
  if [ "$call" = 'ip -6 addr add 2001:db8::1/64 dev moto-tap' ]; then
    ipv6_adds=$((ipv6_adds + 1))
  fi
done
[ "$ipv6_adds" -eq 1 ] || fail_test "IPv6 address was added $ipv6_adds times"

sudo_calls=()
setup_host_networking
[ "${#sudo_calls[@]}" -eq 0 ] || fail_test "ready networking was reconfigured"

echo "test-build-base-networking PASS"
