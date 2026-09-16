#!/bin/bash
#
# full-test-dev.sh — the full test suite against the dev image.
#
# The dev-image full test includes the repository suite, native source builds,
# and Lorry's bounded product suite. Lorry validation is profile-independent
# and does not multiply coverage by the OS image profile.
#
# Work that is not explicitly scoped to Lorry runs this suite only with
# --release. If such work necessarily changes src/bin/lorry, ask before adding
# a debug run; the path overlap alone does not make it Lorry work.

set -euo pipefail

WD="$(dirname "$0")"
ROOT_DIR="$WD/../.."

ORIGINAL_ARGS=("$@")
VMM=qemu
SEEN_RELEASE=0
SEEN_VMM=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release)
      [ "$SEEN_RELEASE" = 0 ] || { echo "full-test-dev: duplicate --release" >&2; exit 2; }
      SEEN_RELEASE=1
      shift
      ;;
    --vmm)
      [ "$SEEN_VMM" = 0 ] || { echo "full-test-dev: duplicate --vmm" >&2; exit 2; }
      [ "$#" -ge 2 ] || { echo "full-test-dev: --vmm requires qemu or chv" >&2; exit 2; }
      VMM="$2"
      SEEN_VMM=1
      shift 2
      ;;
    --vmm=*)
      [ "$SEEN_VMM" = 0 ] || { echo "full-test-dev: duplicate --vmm" >&2; exit 2; }
      VMM="${1#--vmm=}"
      SEEN_VMM=1
      shift
      ;;
    *) echo "usage: $0 [--release] [--vmm qemu|chv]" >&2; exit 2 ;;
  esac
done
case "$VMM" in
  qemu|chv) ;;
  fc)
    echo "full-test-dev: Firecracker does not support developer images" >&2
    exit 2
    ;;
  *) echo "full-test-dev: unsupported VMM '$VMM'" >&2; exit 2 ;;
esac

# Native analyzer acceptance uses 8 GiB; the separate developer-source phase
# retains its 4 GiB default. An explicit caller override applies to both.
REPOSITORY_MEMORY_MIB="${MOTO_MEMORY_MIB:-8192}"
DEV_MEMORY_MIB="${MOTO_MEMORY_MIB:-4096}"

# Keep a local runtime version bump from breaking only the dev-image suite.
python3 "$WD/test-dev-path-locks.py"

MOTO_MEMORY_MIB="$REPOSITORY_MEMORY_MIB" \
  FULL_TEST_IMG_TARGET=dev.img FULL_TEST_IMAGE=motor-os-dev.qcow2 \
  FULL_TEST_VERIFY_DEV_SOURCES=1 \
  "$WD/full-test.sh" "${ORIGINAL_ARGS[@]}"

MOTO_MEMORY_MIB="$DEV_MEMORY_MIB" FULL_TEST_IMAGE_PREBUILT=1 \
  "$WD/test-dev-sources.sh" "${ORIGINAL_ARGS[@]}"

"$ROOT_DIR/src/bin/lorry/tests/test-all.sh"

echo "full-test-dev.sh ALL PASS"
