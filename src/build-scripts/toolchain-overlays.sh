#!/usr/bin/env bash
# Payloads owned by this checkout; compiler overlays come from the release.
MOTOR_TOOLCHAIN_OVERLAYS=(motor helix sed lua quickjs javy wasmtime)

toolchain_collect_overlays() (
    set -euo pipefail
    local root="$1" binaries="$2" assembly="$3" imager="$4" output="$5" overlay command
    mkdir -p "$output"
    for overlay in "${MOTOR_TOOLCHAIN_OVERLAYS[@]}"; do
        rm -rf "${output:?}/$overlay"
        if [ "$overlay" != motor ]; then
            [ -d "$assembly/$overlay" ] || {
                echo "toolchain: missing staged overlay: $assembly/$overlay" >&2; exit 1;
            }
            cp -a "$assembly/$overlay" "$output/"
        fi
    done
    local motor="$output/motor" defaults="$root/img_files/motor-os-dev"
    mkdir -p "$motor/user/bin" "$motor/user/lib/imager" "$motor/none"
    cp -a "$defaults/user/bin/dev" "$motor/user/bin/"
    cp -a "$defaults/user/lib/www" "$motor/user/lib/"
    cp -a "$defaults/user/cfg" "$motor/user/"
    # Installation extends these existing files; it never replaces them.
    rm -f "$motor/user/cfg/rush.cfg" "$motor/user/cfg/sshd.toml"
    cp -a "$defaults/none/cfg" "$motor/none/"
    for command in lorry gix mdbg; do
        install -m 755 "$binaries/$command" "$motor/user/bin/dev/$command"
    done
    install -m 755 "$imager" "$motor/user/lib/imager/imager"
)
