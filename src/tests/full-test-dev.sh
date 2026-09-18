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

# Native analyzer acceptance uses 8 GiB; the separate developer-source phase
# retains its 4 GiB default. An explicit caller override applies to both.
REPOSITORY_MEMORY_MIB="${MOTO_MEMORY_MIB:-8192}"
DEV_MEMORY_MIB="${MOTO_MEMORY_MIB:-4096}"

# Keep a local runtime version bump from breaking only the dev-image suite.
python3 "$WD/test-dev-path-locks.py"

MOTO_MEMORY_MIB="$REPOSITORY_MEMORY_MIB" \
  FULL_TEST_IMG_TARGET=dev.img FULL_TEST_IMAGE=motor-os-dev.qcow2 \
  FULL_TEST_VERIFY_DEV_SOURCES=1 \
  "$WD/full-test.sh" "$@"

MOTO_MEMORY_MIB="$DEV_MEMORY_MIB" MOTO_IMAGE=motor-os-dev.qcow2 \
  "$ROOT_DIR/src/bin/httpd-axum/tests/run.sh" --motor "$@"

MOTO_MEMORY_MIB="$DEV_MEMORY_MIB" FULL_TEST_IMAGE_PREBUILT=1 \
  "$WD/test-dev-sources.sh" "$@"

"$ROOT_DIR/src/bin/lorry/tests/test-all.sh"

echo "full-test-dev.sh ALL PASS"
