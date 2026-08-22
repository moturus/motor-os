#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
usage: run-dev.sh [--vmm qemu|chv] [-- VMM-ARGUMENTS...]

Runs motor-os-dev.qcow2 with QEMU by default. The development defaults are
8 vCPUs and 8192 MiB of RAM. MOTO_SMP and MOTO_MEMORY_MIB override them.
EOF
}

VMM=qemu
while [ "$#" -gt 0 ]; do
  case "$1" in
    --vmm)
      [ "$#" -ge 2 ] || {
        echo "run-dev: --vmm requires qemu or chv" >&2
        exit 2
      }
      VMM="$2"
      shift 2
      ;;
    --vmm=*)
      VMM="${1#--vmm=}"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "run-dev: unknown argument '$1'" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$VMM" in
  qemu | chv) ;;
  *)
    echo "run-dev: unsupported VMM '$VMM'; expected qemu or chv" >&2
    exit 2
    ;;
esac

WD="$(dirname "$0")"
export MOTO_IMAGE=motor-os-dev.qcow2
export MOTO_SMP="${MOTO_SMP:-8}"
export MOTO_MEMORY_MIB="${MOTO_MEMORY_MIB:-8192}"

case "$VMM" in
  qemu) exec "$WD/run-qemu.sh" "$@" ;;
  chv) exec "$WD/run-chv.sh" "$@" ;;
esac
