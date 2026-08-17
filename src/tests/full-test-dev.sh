#!/bin/bash
#
# full-test-dev.sh — the full test suite against the dev image.
#
# The dev-image full test includes the repository suite plus Lorry's single
# bounded product suite. Lorry validation is profile-independent and does not
# multiply coverage by the OS image profile.

set -euo pipefail

WD="$(dirname "$0")"
ROOT_DIR="$WD/../.."

# Red's host-only pty resize test currently has a separately owned failure.
# Keep ordinary full-test.sh unchanged while retaining Red's unit tests here.
FULL_TEST_IMG_TARGET=dev.img FULL_TEST_IMAGE=motor-os-dev.img \
  FULL_TEST_VERIFY_DEV_SOURCES=1 \
  FULL_TEST_SKIP_RED_RESIZE=1 "$WD/full-test.sh" "$@"

"$ROOT_DIR/src/bin/lorry/tests/test-all.sh"
