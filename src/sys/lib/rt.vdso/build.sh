#!/bin/bash
set -e

TARGET_DIR="${CARGO_TARGET_DIR:-../../target}"
SCRIPT_DIR="$(dirname $(readlink -f $0))"
cd "$SCRIPT_DIR"

# Don't update the output file if nothings has changed,
# otherwise sys-io is always relinked, which takes time.
TARGET_FNAME="${SCRIPT_DIR}/rt.vdso"
PREV_HASH="--"

if [ -f "${TARGET_FNAME}" ]; then
    PREV_HASH=$(sha256sum "${TARGET_FNAME}" | awk '{print $1}')
fi

cargo +dev-x86_64-unknown-moturus build --target x86_64-unknown-moturus --features "netdev" $@

cargo +dev-x86_64-unknown-moturus clippy --target x86_64-unknown-moturus --features "netdev" $@

# Don't update the output file if nothings has changed,
# otherwise sys-io is always relinked, which takes time.
TEMP_FNAME="${TARGET_FNAME}".tmp

if [[ "$1" == "--release" ]] ; then
  strip -o "${TEMP_FNAME}" "${TARGET_DIR}/x86_64-unknown-moturus/release/rt"
else
  strip -o "${TEMP_FNAME}" "${TARGET_DIR}/x86_64-unknown-moturus/debug/rt"
fi

NEW_HASH=$(sha256sum "${TEMP_FNAME}" | awk '{print $1}')

if [ "${NEW_HASH}" != "${PREV_HASH}" ]; then
    if [ -f "${TARGET_FNAME}" ]; then
        rm "${TARGET_FNAME}"
    fi
    mv "${TEMP_FNAME}" "${TARGET_FNAME}"
    echo "did build"
else
    rm "${TEMP_FNAME}"
    echo "nothing done"
fi

