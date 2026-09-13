#!/bin/bash
# Sourced by test-tui.sh in its developer VM. Use the shipped configuration
# and launcher; only the project, cache, and log are isolated test data.

HELIX_LSP_EVIDENCE="$(mktemp -d /tmp/motor-helix-lsp.XXXXXX)"
helix_lsp_log="$GUEST_HELIX_ROOT/lsp.log"
helix_project="$GUEST_HELIX_ROOT/rust project"
rustfmt_fixtures="$ROOT_DIR/src/tests/rustfmt-fixtures"
helix_log_start=1
echo "-- Helix native rust-analyzer; evidence=$HELIX_LSP_EVIDENCE --"

helix_log_wait() {
  local pattern="$1" label="$2" count="${3:-1}"
  local require_ready="${4:-false}"
  local deadline=$((SECONDS + 60))
  local chunk
  while [ "$SECONDS" -lt "$deadline" ]; do
    vm_ssh "cat $helix_lsp_log" > "$HELIX_LSP_EVIDENCE/helix.log" ||
      fail "cannot read Helix LSP log"
    tail -n +"$helix_log_start" "$HELIX_LSP_EVIDENCE/helix.log" > "$HELIX_LSP_EVIDENCE/latest.log"
    if [ "$(grep -Ec "$pattern" "$HELIX_LSP_EVIDENCE/latest.log")" -ge "$count" ]; then
      if [ "$require_ready" = false ]; then
        return
      elif python3 "$WD/test-helix-lsp-ready.py" "$HELIX_LSP_EVIDENCE/helix.log"; then
        return
      elif [ "$?" -ne 1 ]; then
        fail "cannot observe analyzer readiness"
      fi
    fi
    if grep -Eq 'request [0-9]+ timed out|failed to initialize language server|StreamClosed' \
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

helix_wait_screen_text() {
  local pattern="$1" label="$2" chunk
  local deadline=$((SECONDS + 20))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if printf '%s' "$PTY_OUTPUT" | strip_escapes | grep -Fq -- "$pattern"; then
      return
    fi
    chunk=""
    if IFS= read -r -t 0.1 -N 4096 chunk <&"$PTY_OUT_FD"; then
      :
    elif [ "$?" -le 128 ]; then
      fail "Helix terminal closed during $label"
    fi
    PTY_OUTPUT+="$chunk"
  done
  fail "$label did not show '$pattern' in the terminal"
}

helix_sftp_batch() {
  sftp -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" \
    -i "$WD/test.key" -b - motor@192.168.4.2
}

helix_assert_file() {
  local guest="$1" expected="$2" evidence_name="$3"
  vm_ssh "/system/bin/sysbox cat '$guest'" > "$HELIX_LSP_EVIDENCE/$evidence_name.rs"
  cmp "$expected" "$HELIX_LSP_EVIDENCE/$evidence_name.rs" ||
    fail "Helix file differs after $evidence_name; evidence=$HELIX_LSP_EVIDENCE"
}

helix_wait_format_edits() {
  local label="$1"
  helix_log_wait '"method":"textDocument/formatting"' "$label request"
  helix_log_wait 'rust-analyzer <- .*"result":\[' "$label non-null response"
}

helix_check_end='"token":"rust-analyzer/flycheck/0","value":\{"kind":"end"'
# Reproduce the reported workflow on the shipped project. Opening and editing
# during workspace loading previously cancelled Salsa work and killed the server.
helix_lsp_log="$GUEST_HELIX_ROOT/open.log"
shipped_format=/devtools/src/helix-rust-demo/src/rustfmt-test.rs
printf 'put "%s" "%s"\n' "$rustfmt_fixtures/in-place.in.rs" "$shipped_format" |
  helix_sftp_batch
start_pty "cd /devtools/src/helix-rust-demo && hx -v --log $helix_lsp_log"
wait_pty_output "[scratch]" "empty Helix startup"
PTY_OUTPUT=""
printf ':o src/main.rs\r' >&"$PTY_IN_FD"
wait_pty_output "main.rs" "opening Rust after Helix startup"
# The buffer can render before LSP initialization. Wait for didOpen so the
# insertion and undo are both changes, rather than insertion entering didOpen.
helix_log_wait '"method":"textDocument/didOpen"' "initial document notification"
PTY_OUTPUT=""
printf 'i// analysis edit' >&"$PTY_IN_FD"
wait_pty_output "INS" "edit during initial analysis"
PTY_OUTPUT=""
printf '\033' >&"$PTY_IN_FD"
wait_pty_output "NOR" "initial edit normal mode"
printf 'u' >&"$PTY_IN_FD"
helix_log_wait "$helix_check_end" "initial analysis after edit" 1 true
helix_log_wait '"method":"textDocument/didChange"' "initial analysis changes" 2
helix_save_screen open_and_edit
printf ':o src/rustfmt-test.rs\r' >&"$PTY_IN_FD"
wait_pty_output "rustfmt-test.rs" "opening shipped rustfmt fixture"
helix_log_mark
printf ':format\r' >&"$PTY_IN_FD"
helix_wait_format_edits "shipped rustfmt"
helix_wait_screen_text "if value > 0" "shipped formatted buffer"
helix_save_screen shipped_format
helix_assert_file "$shipped_format" "$rustfmt_fixtures/in-place.in.rs" shipped-format-before-save
helix_log_mark
printf ':w\r' >&"$PTY_IN_FD"
helix_log_wait '"method":"textDocument/formatting"' "shipped format-on-save request"
helix_log_wait '"method":"textDocument/didSave"' "shipped formatted save"
helix_assert_file "$shipped_format" "$rustfmt_fixtures/in-place.expected.rs" shipped-format-saved
printf ':o src/main.rs\r' >&"$PTY_IN_FD"
wait_pty_output "main.rs" "returning to shipped Rust source"
printf '6G32lgd' >&"$PTY_IN_FD"
wait_pty_output "greeting.rs" "shipped ANSWER definition"
helix_save_screen shipped_definition
printf ':q!\r' >&"$PTY_IN_FD"
finish_pty 0 "shipped project navigation"
helix_log_wait '"method":"shutdown"' "shipped server shutdown"
cp "$HELIX_LSP_EVIDENCE/helix.log" "$HELIX_LSP_EVIDENCE/shipped-project.log"
vm_ssh "/system/bin/rm '$shipped_format'"

helix_lsp_log="$GUEST_HELIX_ROOT/lsp.log"
helix_log_start=1
vm_ssh "/system/bin/sysbox cp -r /devtools/src/helix-rust-demo '$helix_project'"
helix_format_file="$helix_project/src/format.rs"
helix_width_dir="$helix_project/src/width-case"
helix_width_file="$helix_width_dir/input.rs"
helix_error_file="$helix_project/src/error.rs"
{
  printf 'mkdir "%s"\n' "$helix_width_dir"
  printf 'put "%s" "%s"\n' "$rustfmt_fixtures/in-place.in.rs" "$helix_format_file"
  printf 'put "%s" "%s"\n' "$rustfmt_fixtures/width.in.rs" "$helix_width_file"
  printf 'put "%s" "%s"\n' "$rustfmt_fixtures/width.toml" "$helix_width_dir/rustfmt.toml"
  printf 'put "%s" "%s"\n' "$rustfmt_fixtures/stdin.in.rs" "$helix_error_file"
} | helix_sftp_batch
start_pty "cd '$helix_project' && XDG_CACHE_HOME=$helix_cache hx -v --log $helix_lsp_log '$helix_project/src/main.rs:6:33'"
wait_pty_output "main.rs" "Helix Rust project startup"
helix_save_screen startup
helix_log_wait "$helix_check_end" "initial analysis and Lorry check" 1 true

# A manual format changes only the buffer; saving formats again and writes the
# expected bytes. Replacing the buffer then proves format-on-save independently.
printf ':o src/format.rs\r' >&"$PTY_IN_FD"
wait_pty_output "format.rs" "opening Rust formatting fixture"
helix_log_mark
printf ':format\r' >&"$PTY_IN_FD"
helix_wait_format_edits "manual formatting"
helix_wait_screen_text "if value > 0" "manual formatted buffer"
helix_save_screen manual_format
helix_assert_file "$helix_format_file" "$rustfmt_fixtures/in-place.in.rs" manual-format-before-save
helix_log_mark
printf ':w\r' >&"$PTY_IN_FD"
helix_log_wait '"method":"textDocument/formatting"' "manual formatted save request"
helix_log_wait '"method":"textDocument/didSave"' "manual formatted save"
helix_assert_file "$helix_format_file" "$rustfmt_fixtures/in-place.expected.rs" manual-format-saved

printf '%%cpub fn calculate(value:i32)->i32{if value>0{value*2}else{0}}' >&"$PTY_IN_FD"
wait_pty_output "INS" "format-on-save edit"
PTY_OUTPUT=""
printf '\033' >&"$PTY_IN_FD"
wait_pty_output "NOR" "format-on-save normal mode"
helix_log_mark
printf ':w\r' >&"$PTY_IN_FD"
helix_wait_format_edits "format-on-save"
helix_log_wait '"method":"textDocument/didSave"' "format-on-save write"
helix_save_screen format_on_save
helix_assert_file "$helix_format_file" "$rustfmt_fixtures/in-place.expected.rs" format-on-save

# A colocated project configuration must affect both LSP formatting and save.
printf ':o src/width-case/input.rs\r' >&"$PTY_IN_FD"
wait_pty_output "input.rs" "opening width formatting fixture"
helix_log_mark
printf ':format\r' >&"$PTY_IN_FD"
helix_wait_format_edits "project rustfmt configuration"
helix_save_screen project_config_format
helix_assert_file "$helix_width_file" "$rustfmt_fixtures/width.in.rs" project-config-before-save
helix_log_mark
printf ':w\r' >&"$PTY_IN_FD"
helix_log_wait '"method":"textDocument/formatting"' "project configuration save request"
helix_log_wait '"method":"textDocument/didSave"' "project configuration save"
helix_assert_file "$helix_width_file" "$rustfmt_fixtures/width.expected.rs" project-config-saved

# Parser failure is a non-editing response: Helix saves the user's bytes, and
# the same buffer formats normally again after the syntax is repaired.
printf ':o src/error.rs\r' >&"$PTY_IN_FD"
wait_pty_output "error.rs" "opening formatting error fixture"
printf '%%cfn main() { let value = ; }' >&"$PTY_IN_FD"
wait_pty_output "INS" "formatting error edit"
PTY_OUTPUT=""
printf '\033' >&"$PTY_IN_FD"
wait_pty_output "NOR" "formatting error normal mode"
helix_log_mark
printf ':w\r' >&"$PTY_IN_FD"
helix_log_wait '"method":"textDocument/formatting"' "formatting error request"
helix_log_wait 'rustfmt exited with status 1' "formatting error status"
helix_log_wait '"method":"textDocument/didSave"' "unformatted error save"
helix_save_screen format_error
helix_assert_file "$helix_error_file" "$rustfmt_fixtures/parser-error.rs" format-error-saved

printf '%%cfn main(){let values=vec![3,1,2];println!("{:?}",values);}' >&"$PTY_IN_FD"
wait_pty_output "INS" "formatting recovery edit"
PTY_OUTPUT=""
printf '\033' >&"$PTY_IN_FD"
wait_pty_output "NOR" "formatting recovery normal mode"
helix_log_mark
printf ':w\r' >&"$PTY_IN_FD"
helix_wait_format_edits "formatting recovery"
helix_log_wait '"method":"textDocument/didSave"' "formatting recovery save"
helix_save_screen format_recovery
helix_assert_file "$helix_error_file" "$rustfmt_fixtures/stdin.expected.rs" format-recovery-saved

printf ':o src/main.rs\r' >&"$PTY_IN_FD"
wait_pty_output "main.rs" "returning to semantic fixture"
printf '6G32l' >&"$PTY_IN_FD"

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
