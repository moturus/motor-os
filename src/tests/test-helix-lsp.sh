#!/bin/bash
# Sourced by test-tui.sh in its developer VM. Use the shipped configuration
# and launcher; only the project, cache, and log are isolated test data.

HELIX_LSP_EVIDENCE="$(mktemp -d /tmp/motor-helix-lsp.XXXXXX)"
helix_lsp_log="$GUEST_HELIX_ROOT/lsp.log"
helix_project="$GUEST_HELIX_ROOT/rust project"
helix_log_start=1
echo "-- Helix native rust-analyzer; evidence=$HELIX_LSP_EVIDENCE --"

helix_log_wait() {
  local pattern="$1" label="$2" count="${3:-1}"
  local deadline=$((SECONDS + 60))
  local chunk
  while [ "$SECONDS" -lt "$deadline" ]; do
    vm_ssh "cat $helix_lsp_log" > "$HELIX_LSP_EVIDENCE/helix.log" ||
      fail "cannot read Helix LSP log"
    tail -n +"$helix_log_start" "$HELIX_LSP_EVIDENCE/helix.log" > "$HELIX_LSP_EVIDENCE/latest.log"
    if [ "$(grep -Ec "$pattern" "$HELIX_LSP_EVIDENCE/latest.log")" -ge "$count" ]; then
      return
    fi
    if grep -Eq 'request [0-9]+ timed out|failed to initialize language server' \
      "$HELIX_LSP_EVIDENCE/helix.log"; then
      fail "Helix LSP failed during $label; evidence=$HELIX_LSP_EVIDENCE"
    fi
    # Keep consuming terminal redraws while observing server progress. Leaving
    # stdout unread would eventually block the editor in the test's own pipe.
    chunk=""
    if IFS= read -r -t 0.1 -N 4096 chunk <&"$PTY_OUT_FD"; then
      :
    elif [ "$?" -le 128 ]; then
      fail "Helix terminal closed during $label"
    fi
    PTY_OUTPUT+="$chunk"
  done
  fail "Helix LSP $label did not complete; evidence=$HELIX_LSP_EVIDENCE"
}

helix_log_mark() {
  vm_ssh "cat $helix_lsp_log" > "$HELIX_LSP_EVIDENCE/helix.log"
  helix_log_start=$(( $(wc -l < "$HELIX_LSP_EVIDENCE/helix.log") + 1 ))
  PTY_OUTPUT=""
}

helix_save_screen() {
  printf '%s' "$PTY_OUTPUT" > "$HELIX_LSP_EVIDENCE/$1.terminal"
  PTY_OUTPUT=""
}

vm_ssh "/system/bin/sysbox cp -r /devtools/src/helix-rust-demo '$helix_project'"
start_pty "cd '$helix_project' && XDG_CACHE_HOME=$helix_cache hx -v --log $helix_lsp_log '$helix_project/src/main.rs:6:33'"
wait_pty_output "main.rs" "Helix Rust project startup"
helix_save_screen startup
helix_check_end='"token":"rust-analyzer/flycheck/0","value":\{"kind":"end"'
helix_log_wait "$helix_check_end" "initial Lorry check"

# Hover must render server-supplied documentation in the editor. The selected
# identifier itself is in the source, so it would not prove a hover response.
printf ' k' >&"$PTY_IN_FD"
wait_pty_output "small constant" "Helix Rust hover"
helix_save_screen hover
printf '\033' >&"$PTY_IN_FD"
wait_pty_output ' ~' "Helix hover dismissal"
PTY_OUTPUT=""
printf 'gd' >&"$PTY_IN_FD"
wait_pty_output "greeting.rs" "Helix Rust definition"
helix_save_screen definition

printf '\017' >&"$PTY_IN_FD"
wait_pty_output "main.rs" "Helix jump back"
helix_log_mark
printf '6G32lv5lc' >&"$PTY_IN_FD"
wait_pty_output "INS" "Helix completion edit"
PTY_OUTPUT=""
printf '\030' >&"$PTY_IN_FD"
wait_pty_output "ANSWER" "Helix Rust completion"
helix_log_wait '"method":"textDocument/completion"' "completion request"
helix_save_screen completion
# Select the completion, accept it, then leave insert mode in a separate event.
printf '\016\r' >&"$PTY_IN_FD"
helix_log_wait '"method":"completionItem/resolve"' "completion resolution"
PTY_OUTPUT=""
printf '\033' >&"$PTY_IN_FD"
wait_pty_output "NOR" "Helix completion normal mode"

helix_log_mark
printf '6G16lv2lcbool' >&"$PTY_IN_FD"
wait_pty_output "INS" "Helix diagnostic edit"
PTY_OUTPUT=""
printf '\033' >&"$PTY_IN_FD"
wait_pty_output "NOR" "Helix diagnostic normal mode"
printf ':w\r' >&"$PTY_IN_FD"
helix_log_wait '"code":"E0308".*"source":"rustc"' "rustc diagnostic on save"
helix_log_wait "$helix_check_end" "error check completion"
printf ' d' >&"$PTY_IN_FD"
wait_pty_output "mismatched types" "Helix diagnostic display"
helix_save_screen diagnostic
printf '\033' >&"$PTY_IN_FD"
wait_pty_output 'rt_version' "Helix diagnostic picker dismissal"

helix_log_mark
printf '6G16lv3lcu32' >&"$PTY_IN_FD"
wait_pty_output "INS" "Helix diagnostic fix"
PTY_OUTPUT=""
printf '\033' >&"$PTY_IN_FD"
wait_pty_output "NOR" "Helix fix normal mode"
printf ':w\r' >&"$PTY_IN_FD"
helix_log_wait "$helix_check_end" "fixed check completion"
helix_log_wait 'publishDiagnostics".*"uri":"[^"]*/src/main.rs".*"diagnostics":\[\]' "diagnostic clearing"
helix_save_screen fixed
vm_ssh "/system/bin/sysbox cat '$helix_project/src/main.rs'" > "$HELIX_LSP_EVIDENCE/main.rs"
cmp "$ROOT_DIR/img_files/motor-os-dev/devtools/src/helix-rust-demo/src/main.rs" \
  "$HELIX_LSP_EVIDENCE/main.rs" || fail "Helix completion/fix changed unexpected source bytes"

printf '8G/rt_version\r' >&"$PTY_IN_FD"
helix_log_mark
printf 'gd' >&"$PTY_IN_FD"
wait_pty_output "RT_VERSION" "Helix Motor std definition"
helix_log_wait '"uri":"file:///devtools/rust/lib/rustlib/src/rust/library/std/src/os/motor/mod.rs"' "Motor std navigation"
helix_save_screen std_definition

helix_log_mark
printf ':q!\r' >&"$PTY_IN_FD"
finish_pty 0 "Helix Rust project"
helix_save_screen exit
helix_log_wait '"method":"shutdown"' "server shutdown"
helix_log_wait '"method":"exit"' "server exit"
vm_ssh ps > "$HELIX_LSP_EVIDENCE/processes-after-exit"
if grep -Fq '/devtools/rust/bin/rust-analyzer' "$HELIX_LSP_EVIDENCE/processes-after-exit"; then
  fail "Helix left a native language server running"
fi
echo "Helix native hover/definition/completion/save-diagnostics/shutdown PASS; evidence=$HELIX_LSP_EVIDENCE"
# Preserve the log before test-tui removes the guest fixture directory.
HELIX_LSP_EVIDENCE=""
