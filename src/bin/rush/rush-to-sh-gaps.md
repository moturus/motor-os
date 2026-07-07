# rush → sh: POSIX conformance gap analysis

This document inventories what `rush` currently supports and, more importantly,
where it diverges from a POSIX-conformant `sh`. It is a **gap list**, not a plan:
it describes the current state so future work can be prioritized.

- Reference spec: POSIX.1-2017 Shell Command Language —
  <https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html>
- Scope: analysis is based on reading the source as of this writing
  (`src/lib.rs`, `src/line_parser.rs`, `src/exec.rs`, `src/redirect.rs`,
  `src/term.rs`, `src/term_impl_unix.rs`). File:line references point at the
  relevant code.

---

## 1. What rush supports today

**Invocation / modes** (`src/lib.rs`)
- `-c <string>` — run a command string.
- `-i` — interactive terminal mode (optionally preceded by an init script arg).
- `-h` — usage.
- `-piped` — internal/hidden mode.
- Bare `script` argument — run a file, then exit.
- Leading `VAR=val` positional arg flips into command mode.
- `--` is skipped after `-c` (for `system()`/`popen()` compatibility).

**Parsing** (`src/line_parser.rs`)
- Whitespace tokenization into `argv`.
- Single `'…'` and double `"…"` quoting (currently **identical** semantics).
- Backslash escaping, both bare and inside quotes.
- `|` splits a pipeline into commands (see gap: execution panics).
- `&&` splits and sequences pipelines with short-circuit.
- Trailing `\` line continuation (multi-line input, interactive and script).

**Execution** (`src/exec.rs`)
- Spawning a single external command (via `std::process::Command`, which does
  its own `PATH` search).
- Built-ins: `cd` (single arg only), `exit`, `quit`.
- Inline env assignment `A=B command` (passed to the child only).
- Bare `A=B` assignment applied to the process environment (global/script mode,
  single command only).
- Literal `$@` token expands to positional args `[1..]` (`process_vars`).
- `>` and `>>` stdout redirection (`src/redirect.rs`).
- Script execution line-by-line, skipping blank lines and whole-line `#` comments.

**Interactive line editing** (`src/term.rs`)
- Left/Right cursor, Home/End, Backspace, Delete, mid-line insert.
- Up/Down in-memory history navigation.
- Ctrl+C cancels the current line (does not exit).
- Local meta-commands: `clear`, `history`, `--debug`.
- Raw-mode termios handling on Unix (`src/term_impl_unix.rs`).

---

## 2. Gaps vs. POSIX sh

### 2.1 Parameters, variables & expansion (largest gap)
POSIX §2.5, §2.6. Almost none of the word-expansion machinery exists.

- **Variable expansion** `$VAR`, `${VAR}` — not implemented. Only the exact
  literal token `$@` is recognized (`exec.rs:33`); `$` is otherwise a plain char.
- **Shell variables** — no concept distinct from the process environment.
  Assignment `A=B` mutates the OS env directly (`exec.rs:20`), so there is no
  `export` boundary and no unexported shell-local vars.
- **Special parameters** — missing `$*`, `$#`, `$0`, `$1`…`$9`, `$?`, `$$`,
  `$!`, `$-`, `$IFS`. Only `$@` is handled, and only as a whole token.
- **Parameter expansion forms** — none of `${VAR:-word}`, `${VAR:=word}`,
  `${VAR:?word}`, `${VAR:+word}`, `${#VAR}`, `${VAR#pat}`, `${VAR##pat}`,
  `${VAR%pat}`, `${VAR%%pat}`, `${VAR/…}`.
- **Command substitution** — `$(…)` and backticks `` `…` `` unsupported.
- **Arithmetic expansion** — `$(( … ))` unsupported.
- **Tilde expansion** — `~`, `~user` unsupported.
- **Field splitting (`IFS`)** — not implemented; substitution results would not
  be re-split even if they existed.
- **Quote-removal nuance** — single vs. double quotes are treated identically
  (`line_parser.rs:61`), so double-quote interpolation vs. single-quote literal
  semantics do not exist. No `$'…'` (ANSI-C) or `$"…"` quoting.

### 2.2 Pathname & brace expansion
POSIX §2.6.6, §2.13.

- **Globbing disabled.** `*`, `?`, `[…]` pathname expansion is commented out
  (`line_parser.rs:117`, `process_arg`). A leftover special-case keeps `*` as a
  literal inside quotes (`line_parser.rs:67`). (README's "Globbing works" claim
  is currently inaccurate.)
- **Brace expansion** `{a,b,c}` — unsupported (also non-POSIX, but expected).

### 2.3 Control flow & language constructs (entirely absent)
POSIX §2.9.4, §2.9.5. rush is a command runner, not a language interpreter.

- No `if / then / elif / else / fi`.
- No `for … do … done`.
- No `while` / `until` loops.
- No `case … in … esac`.
- No function definitions `name() { … }`.
- No `break`, `continue`, `return`.
- No compound grouping `{ …; }` or subshells `( … )`.
- No `!` pipeline negation.

### 2.4 Command lists / separators & operators
POSIX §2.9.3.

- **`;` sequential separator — not recognized.** The parser has no `;` case
  (`line_parser.rs:30`), so `;` becomes a literal character inside a token.
- **`||` OR-list — not supported.** Only `&&` is handled (`line_parser.rs:33`).
  A `||` is parsed as two pipes around an empty command, not logical-or.
- **`&` background — not supported.** A lone `&` is emitted as a literal
  character (`line_parser.rs:53`), not an async-list operator.
- No `;;` (needs `case`).

### 2.5 Pipelines & job control
POSIX §2.9.2, §2.9.1.

- **Multi-stage pipelines panic.** `run()` hits
  `todo!("piping needs better stdio treatment")` whenever `commands.len() > 1`
  (`exec.rs:62`). So `ls | wc -l` aborts the shell (README's "piping works"
  claim is currently inaccurate).
- No pipeline exit-status semantics; `$?` does not exist; no `set -o pipefail`.
- No job control: `jobs`, `fg`, `bg`, `wait`, `kill %n`, `%1` job specs,
  Ctrl+Z / SIGTSTP suspension.
- No stderr-including pipe (`|&`).

### 2.6 Redirection
POSIX §2.7. Only stdout `>`/`>>` exist.

- No input redirection `< file`.
- No stderr redirection `2>`, `2>>`.
- No fd duplication/merge: `2>&1`, `1>&2`, `n>&m`, `n<&m`, fd close `n>&-`.
- No combined redirect `&>`, `>&`.
- No here-documents `<<`, `<<-`, or here-strings `<<<`.
- No read-write `<>`, no noclobber override `>|`.
- **Operator must be a standalone, space-separated token.** `>file` (no space)
  or `2>file` are not tokenized as redirects; redirects are matched only by
  `arg == ">"` / `">>"` (`redirect.rs:30`). So `echo hi>out` writes the literal
  `hi>out` as an argument.
- **Non-streaming implementation.** The child's stdout is read fully into memory
  and then written to the file (`redirect.rs:12`), so it does not stream and can
  block/OOM on large or unbounded output.

### 2.7 Built-in utilities (mostly missing)
POSIX §2.14 (special) and XCU (regular).

- **Special built-ins absent:** `:` (no-op), `.` (source), `break`, `continue`,
  `eval`, `exec`, `export`, `readonly`, `return`, `set`, `shift`, `times`,
  `trap`, `unset`.
- **Regular built-ins absent:** `alias`/`unalias`, `command`, `type`, `hash`,
  `getopts`, `read`, `pwd`, `test` / `[`, `true`, `false`, `umask`, `ulimit`,
  `wait`, `kill`, `fg`/`bg`/`jobs`, `printf`, `echo` (relies on an external
  binary — absent on a minimal OS).
- **`cd` is partial** (`exec.rs:99`): requires exactly one argument, so bare
  `cd` does not go to `$HOME`; no `cd -` (OLDPWD), no `CDPATH`, no `-L`/`-P`,
  and it does not update `PWD`/`OLDPWD`.
- **`exit` is partial** (`exec.rs:235`): no bare-`exit` = "exit with `$?`";
  non-numeric arg yields `-1` (→ 255) rather than a POSIX status; no masking to
  0–255.

### 2.8 Exit status & error handling
POSIX §2.8.

- **No `$?`** — last command status is neither tracked nor exposable.
- **No shell options** `set -e`, `-x` (xtrace), `-u` (nounset), `-n`,
  `-o pipefail`, `-C` (noclobber), `-f` (noglob), `-v`, etc.
- **Wrong "command not found" behavior:** prints to **stdout** and returns `-1`
  (`exec.rs:158`); POSIX requires status **127** (and **126** for
  found-but-not-executable), with the message on stderr.
- **Diagnostics on stdout, not stderr.** `cd` errors, "command not found",
  the "`[cmd] exited with status N`" line, and env-in-subcommand errors all use
  `println!` (`exec.rs:83,101,108,158,162,176,186`). This corrupts pipeline data
  and violates the expectation that a failing command is silent except for its
  own stderr. The extra "exited with status" line has no POSIX analogue.

### 2.9 Comments
POSIX §2.3.

- Only **whole-line** `#` comments are stripped, and only in script mode
  (`exec.rs:212`). Inline comments (`cmd # note`) are not recognized in any mode,
  and `#` is not handled at all on the interactive/`parse_line` path.

### 2.10 Startup, options & environment
POSIX §2.5.3, `sh` invocation (XCU).

- **Prompts are hardcoded** (`term.rs:713`); no `PS1`/`PS2`/`PS4`, no `$PWD`,
  `$HOME`, `$OLDPWD`, `$IFS` maintenance.
- **No rc/profile processing** (`$ENV`, `.profile`) per POSIX interactive rules.
- **Option parsing is positional and single-shot** (`lib.rs:82`): only the first
  arg is inspected; no bundled flags, no `-s`, no `-o option`, no `+x` form, no
  setting of positional parameters (`$1`…`$9`) via `set` or invocation.
- **`-c` drops trailing operands.** `run_command` joins **all** remaining args
  with spaces and re-parses (`exec.rs:224`), so `sh -c 'cmd' name a b` neither
  sets `$0=name` nor `$1=a` — it appends them to the command string. Joining also
  loses original word boundaries/quoting.
- No `PATH` management by the shell itself: no `hash` table, relies entirely on
  the OS `execvp`-style lookup inside `std::process::Command`.

### 2.11 Signals & traps
POSIX §2.11.

- No `trap` builtin; no signal disposition management.
- Raw mode clears `ISIG` (`term_impl_unix.rs:26`), so within the line editor
  Ctrl+C/Ctrl+\ do not raise signals (handled manually as line-cancel); there is
  no shell-level SIGINT/SIGQUIT/EXIT trap handling for scripts.

---

## 3. Interactive/UX gaps (not POSIX-required, but expected of a shell)

- **No Tab completion** — TAB is read and ignored (`term.rs:188`).
- **EOF (Ctrl+D) is not clean** — a zero-length read is treated as an error and
  exits with status 1 (`term.rs:122`); POSIX interactive shells exit `0` on EOF
  at an empty prompt.
- **No emacs/readline key bindings** — Ctrl+A/E/K/U/W/L, Alt+b/f word motion,
  reverse-i-search (Ctrl+R) are all absent.
- **History is in-memory only** — not persisted across sessions; no `$HISTFILE`,
  no `fc`, no `!!`/`!n` history expansion.
- **No UTF-8 input editing** — bytes ≥ 128 are dropped (`term.rs:150`), so
  multi-byte characters cannot be entered or edited.
- No word-wise cursor movement; redraw assumes a single terminal row for the
  input line.

---

## 4. Correctness issues & documentation drift (worth flagging now)

- `README.md` "What works" lists **piping** and **globbing** as working; both are
  currently non-functional (piping `todo!()` at `exec.rs:62`; globbing commented
  out at `line_parser.rs:117`).
- Multi-command pipelines don't just fail gracefully — they **panic/abort the
  whole shell**.
- Shell diagnostics printed to **stdout** rather than stderr (see §2.8).
- **No test suite** — there are no unit/integration tests exercising parsing,
  expansion, redirection, or conformance, so regressions in the above areas are
  unguarded.

---

## 5. Rough priority buckets (informational)

To turn `rush` into a usable-if-minimal POSIX-ish `sh`, the gaps cluster as:

1. **Foundational correctness:** make pipelines actually work (remove the
   `todo!`), route diagnostics to stderr, correct exit statuses (127/126, `$?`).
2. **Core language:** `;` and `||` operators, `$VAR`/`${…}` expansion, `$?`,
   command substitution, `if`/`for`/`while`/`case`, functions.
3. **Redirection & I/O:** `<`, `2>`, `2>&1`, here-docs; streaming instead of
   buffering.
4. **Built-ins:** `:`, `.`, `export`, `unset`, `set`, `shift`, `read`, `test`/`[`,
   `pwd`, `echo`/`printf`, `true`/`false`, `eval`, `exec`, `trap`.
5. **Expansion polish:** globbing, tilde, field splitting (`IFS`), quote-removal
   semantics distinguishing `'…'` from `"…"`.
6. **UX:** Tab completion, clean Ctrl+D, persistent history, UTF-8 input.
