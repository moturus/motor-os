#!/bin/bash
#
# full-test-dev.sh — the full test suite against the dev image.
#
# The dev-image full test includes the repository suite, native source builds,
# and Lorry's bounded product suite. Lorry validation is profile-independent
# and does not multiply coverage by the OS image profile.

set -euo pipefail

WD="$(dirname "$0")"
ROOT_DIR="$WD/../.."

# Match the native Lorry harness only where compilers run: four concurrent
# compiler processes need the 4 GiB profile. The repository suite keeps its
# established default VM memory unless the caller explicitly overrides it.
DEV_MEMORY_MIB="${MOTO_MEMORY_MIB:-4096}"

FULL_TEST_IMG_TARGET=dev.img FULL_TEST_IMAGE=motor-os-dev.qcow2 \
  FULL_TEST_VERIFY_DEV_SOURCES=1 \
  "$WD/full-test.sh" "$@"

MOTO_MEMORY_MIB="$DEV_MEMORY_MIB" FULL_TEST_IMAGE_PREBUILT=1 \
  "$WD/test-dev-sources.sh" "$@"

"$ROOT_DIR/src/bin/lorry/tests/test-all.sh"
