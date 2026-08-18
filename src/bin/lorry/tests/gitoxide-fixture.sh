#!/usr/bin/env bash

LORRY_GITOXIDE_PACKAGES_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/gitoxide-packages.txt"

stage_gitoxide_checkout() {
    local source="$1"
    local destination="$2"
    local package

    if [ ! -f "$source/Cargo.toml" ]; then
        echo "gitoxide fixture: checkout '$source' is absent" >&2
        return 1
    fi
    rm -rf "$destination"
    mkdir -p "$destination"
    cp "$source/Cargo.toml" "$destination/"
    while IFS= read -r package; do
        if [ ! -d "$source/$package" ]; then
            echo "gitoxide fixture: package '$package' is absent" >&2
            return 1
        fi
        # Lorry rejects symlinks in path dependencies, so stage license links
        # as their regular-file contents.
        cp -RL "$source/$package" "$destination/$package"
    done <"$LORRY_GITOXIDE_PACKAGES_FILE"
}
