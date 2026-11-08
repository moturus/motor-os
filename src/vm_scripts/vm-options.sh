#!/bin/sh

# Shared by the launchers. On success, VM_OPTION_SHIFT tells the caller how
# many arguments to consume; unrecognized options belong to the VMM.
vm_option() {
  case "$1" in
    --root-read-only)
      VM_ROOT_READ_ONLY=on
      VM_OPTION_SHIFT=1
      return 0
      ;;
    --extra-disk | --extra-disk-ro)
      [ "$#" -ge 2 ] || { echo "$0: $1 requires an image filename" >&2; exit 2; }
      vm_extra_disk_format "$2"
      VM_READ_ONLY=off
      [ "$1" != --extra-disk-ro ] || VM_READ_ONLY=on
      VM_DISKS="${VM_DISKS:+$VM_DISKS }$2:$VM_READ_ONLY"
      VM_OPTION_SHIFT=2
      return 0
      ;;
    --cpus | --memory)
      [ "$#" -ge 2 ] || {
        echo "$0: $1 requires a value" >&2
        exit 2
      }
      VM_OPTION="$1"
      VM_VALUE="$2"
      VM_OPTION_SHIFT=2
      ;;
    --cpus=* | --memory=*)
      VM_OPTION="${1%%=*}"
      VM_VALUE="${1#*=}"
      VM_OPTION_SHIFT=1
      ;;
    *) return 1 ;;
  esac

  VM_MULTIPLIER=1
  if [ "$VM_OPTION" = --memory ]; then
    case "$VM_VALUE" in
      *M) VM_VALUE="${VM_VALUE%M}" ;;
      *G) VM_VALUE="${VM_VALUE%G}"; VM_MULTIPLIER=1024 ;;
      *)
        echo "$0: --memory requires a positive integer with M or G suffix (e.g. 512M or 2G)" >&2
        exit 2
        ;;
    esac
  fi
  case "$VM_VALUE" in
    "" | *[!0-9]* | 0*)
      echo "$0: $VM_OPTION requires a positive integer without leading zeros" >&2
      exit 2
      ;;
  esac

  if [ "$VM_OPTION" = --cpus ]; then
    SMP="$VM_VALUE"
  else
    # Keep the size in bytes representable by a signed 64-bit integer.
    if [ "${#VM_VALUE}" -gt 13 ] || [ "$VM_VALUE" -gt $((8796093022207 / VM_MULTIPLIER)) ]; then
      echo "$0: --memory is too large" >&2
      exit 2
    fi
    MEMORY_MIB=$((VM_VALUE * VM_MULTIPLIER))
  fi
}

vm_usage() {
  echo "usage: $0 [--cpus N] [--memory SIZE] [--root-read-only] [--extra-disk FILE | --extra-disk-ro FILE]... [-- VMM-ARGUMENTS...]"
  echo "SIZE is a positive integer with M (MiB) or G (GiB) suffix."
  echo "Options override MOTO_SMP and MOTO_MEMORY_MIB; put them before VMM arguments."
  echo "Disk filenames are relative to this launcher; .img/.raw are raw, .qcow2 is qcow2."
  echo "Device indices follow PCI scan order, logged at startup. Firecracker requires raw disks."
}

vm_extra_disk_format() {
  case "$1" in
    "" | *[!A-Za-z0-9._-]*) echo "$0: invalid extra-disk filename '$1'" >&2; exit 2 ;;
  esac
  case "$1" in
    *.img | *.raw) VM_DISK_FORMAT=raw ;;
    *.qcow2) VM_DISK_FORMAT=qcow2 ;;
    *) echo "$0: unsupported extra-disk filename '$1'" >&2; exit 2 ;;
  esac
}

# Parse the common prefix without losing quoting in the remaining arguments.
vm_parse_options() {
  VM_ARGS_SHIFT=0
  VM_DISKS=""
  VM_ROOT_READ_ONLY=off
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -h | --help) vm_usage; exit 0 ;;
      --) VM_ARGS_SHIFT=$((VM_ARGS_SHIFT + 1)); break ;;
    esac
    vm_option "$@" || break
    shift "$VM_OPTION_SHIFT"
    VM_ARGS_SHIFT=$((VM_ARGS_SHIFT + VM_OPTION_SHIFT))
  done
}
