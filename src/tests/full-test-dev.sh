#!/bin/bash
#
# full-test-dev.sh — the full test suite against the dev image.
#
# The dev image (motor-os-dev.img) is the main image plus the lorry-built
# curl, gears, and lorry binaries, so the whole full-test.sh suite applies to
# it verbatim; only the make target and the disk image differ. The env
# overrides survive full-test.sh's timeout re-exec.

WD="$(dirname "$0")"
FULL_TEST_IMG_TARGET=dev.img FULL_TEST_IMAGE=motor-os-dev.img \
  exec "$WD/full-test.sh" "$@"
