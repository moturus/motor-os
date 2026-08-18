#!/bin/bash

# The VM serial stream is test output, not an interactive terminal. Remove the
# queries a host terminal would answer on its own input; otherwise tmux leaves
# those answers queued for the shell that invoked the test.
filter_vm_console() {
  LC_ALL=C sed -u \
    -e $'s/\033\\[6n//g' \
    -e $'s/\033\\[18t//g' \
    -e $'s/\033\\[?2048$p//g'
}
