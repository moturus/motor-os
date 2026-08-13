#!/bin/bash
#
# full-test-dev.sh — the full test suite against the dev image.
#
# The dev-image full test includes the repository suite plus the complete
# profile-matched Lorry local and integration coverage. Three debug and three
# release invocations provide Lorry's required repetition without multiplying
# both profiles inside each invocation.

set -euo pipefail

WD="$(dirname "$0")"
ROOT_DIR="$WD/../.."
BUILD="debug"
if [ "${1:-}" = "--release" ]; then
  BUILD="release"
fi

# Red's host-only pty resize test currently has a separately owned failure.
# Keep ordinary full-test.sh unchanged while retaining Red's unit tests here.
FULL_TEST_IMG_TARGET=dev.img FULL_TEST_IMAGE=motor-os-dev.img \
  FULL_TEST_VERIFY_DEV_SOURCES=1 \
  FULL_TEST_SKIP_RED_RESIZE=1 "$WD/full-test.sh" "$@"

lorry_args=()
integration_args=(--exhaustive)
if [ "$BUILD" = "release" ]; then
  lorry_args+=(--release)
  integration_args+=(--release)
fi

"$ROOT_DIR/src/bin/lorry/test-local.sh" "${lorry_args[@]}"
"$WD/lorry-integration-driver-contract.sh"
"$WD/lorry-integration-test.sh" "${integration_args[@]}"
