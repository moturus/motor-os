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

RUSTFLAGS="-C force-frame-pointers=yes " \
cargo build --target rt.json -Zbuild-std=core,alloc \
  -Zbuild-std-features=compiler-builtins-mem --no-default-features $@

cargo clippy --target rt.json -Zbuild-std=core,alloc \
  -Zbuild-std-features=compiler-builtins-mem --no-default-features $@

# Don't update the output file if nothings has changed,
# otherwise sys-io is always relinked, which takes time.
TEMP_FNAME="${TARGET_FNAME}".tmp

if [[ "$1" == "--release" ]] ; then
  strip -o "${TEMP_FNAME}" "${TARGET_DIR}/rt/release/rt"
else
  strip -o "${TEMP_FNAME}" "${TARGET_DIR}/rt/debug/rt"
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

