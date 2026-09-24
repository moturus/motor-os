#!/bin/bash
#
# full-test-dev.sh — the full test suite against the dev image.
#
# The dev-image full test includes the repository suite, httpd-axum regressions,
# native source builds, and Lorry's bounded product suite. Lorry validation is
# profile-independent and does not multiply coverage by the OS image profile.
#
# Work that is not explicitly scoped to Lorry runs this suite only with
# --release. If such work necessarily changes src/bin/lorry, ask before adding
# a debug run; the path overlap alone does not make it Lorry work.

set -euo pipefail

WD="$(dirname "$0")"
ROOT_DIR="$WD/../.."

# Size options become environment settings shared by every phase. Forward only
# the profile and VMM options supported by the component/source-build runners.
FORWARDED_ARGS=()
VMM=qemu
SEEN_RELEASE=0
SEEN_VMM=0
SEEN_CPUS=0
SEEN_MEMORY=0
positive_integer() { case "$1" in "" | *[!0-9]* | 0*) return 1 ;; esac; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release)
      [ "$SEEN_RELEASE" = 0 ] || { echo "full-test-dev: duplicate --release" >&2; exit 2; }
      SEEN_RELEASE=1
      FORWARDED_ARGS+=(--release)
      shift
      ;;
    --vmm)
      [ "$SEEN_VMM" = 0 ] || { echo "full-test-dev: duplicate --vmm" >&2; exit 2; }
      [ "$#" -ge 2 ] || { echo "full-test-dev: --vmm requires qemu or chv" >&2; exit 2; }
      VMM="$2"
      FORWARDED_ARGS+=(--vmm "$VMM")
      SEEN_VMM=1
      shift 2
      ;;
    --vmm=*)
      [ "$SEEN_VMM" = 0 ] || { echo "full-test-dev: duplicate --vmm" >&2; exit 2; }
      VMM="${1#--vmm=}"
      FORWARDED_ARGS+=(--vmm "$VMM")
      SEEN_VMM=1
      shift
      ;;
    --cpus | --cpus=*)
      [ "$SEEN_CPUS" = 0 ] || { echo "full-test-dev: duplicate --cpus" >&2; exit 2; }
      case "$1" in
        --cpus=*) MOTO_SMP="${1#--cpus=}"; shift ;;
        *) [ "$#" -ge 2 ] || { echo "full-test-dev: --cpus requires a vCPU count" >&2; exit 2; }
           MOTO_SMP="$2"; shift 2 ;;
      esac
      SEEN_CPUS=1
      ;;
    --memory | --memory=*)
      [ "$SEEN_MEMORY" = 0 ] || { echo "full-test-dev: duplicate --memory" >&2; exit 2; }
      case "$1" in
        --memory=*) MOTO_MEMORY_MIB="${1#--memory=}"; shift ;;
        *) [ "$#" -ge 2 ] || { echo "full-test-dev: --memory requires a size in MiB" >&2; exit 2; }
           MOTO_MEMORY_MIB="$2"; shift 2 ;;
      esac
      SEEN_MEMORY=1
      ;;
    *) echo "usage: $0 [--release] [--vmm qemu|chv] [--cpus N] [--memory MIB]" >&2; exit 2 ;;
  esac
done
positive_integer "${MOTO_SMP-4}" || { echo "full-test-dev: CPU count must be a positive integer" >&2; exit 2; }
positive_integer "${MOTO_MEMORY_MIB-8192}" || { echo "full-test-dev: memory must be a positive integer (MiB)" >&2; exit 2; }
export MOTO_SMP="${MOTO_SMP-4}"
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
  "$WD/full-test.sh" "${FORWARDED_ARGS[@]}"

MOTO_MEMORY_MIB="$DEV_MEMORY_MIB" MOTO_IMAGE=motor-os-dev.qcow2 \
  "$ROOT_DIR/src/bin/httpd-axum/tests/run.sh" --motor "${FORWARDED_ARGS[@]}"

MOTO_MEMORY_MIB="$DEV_MEMORY_MIB" FULL_TEST_IMAGE_PREBUILT=1 \
  "$WD/test-dev-sources.sh" "${FORWARDED_ARGS[@]}"

"$ROOT_DIR/src/bin/lorry/tests/test-all.sh"

echo "full-test-dev.sh ALL PASS"
