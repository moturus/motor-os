#!/bin/sh
#
# run-qemu.sh, but with qemu's console-escape character moved off Ctrl-A.
#
# `-nographic` (see run-qemu.sh) makes Ctrl-A qemu's own monitor-escape prefix,
# so a single Ctrl-A never reaches the guest -- and Ctrl-A is exactly rmux's (and
# tmux's) default prefix. `-echr 0x14` moves the escape to Ctrl-T instead, so
# Ctrl-A passes straight through to the guest with one press. Use this variant
# when driving rmux/tmux on the Motor console. See src/bin/rmux/plan.md §9.4.
#
# Everything else is run-qemu.sh's; extra args still pass through to qemu.

WD="$(dirname "$0")"

exec "$WD/run-qemu.sh" -echr 0x14 "$@"
