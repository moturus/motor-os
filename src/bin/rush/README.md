# rush
RUst SHell: a posixy shell implemented in Rust with minimal external dependencies.

Q: Why another shell in Rust?

A: Existing shell projects (a) aim to be 'a better shell', and (b) have a lot of dependencies, so they cannot be easily ported to non-standard OSes; and even non-standard OSes often need interactive shells.

## Goals

- A simple interactive shell with a familiar subset of standard shell functionality;
- Minimal external dependencies and thus easily portable;
- To eventually comply, as much as posible, with the [spec](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/contents.html).

## Non-goals

- To be better than X (sh, bash, etc). The main purpose of this project is simplicity and portability.

## How to use

- Just do a 'cargo run';
- Try various commands;
- File bug reports;
- Type 'exit' or 'quit'.

## Status

**Work in progress.** Today `rush` is a minimal command runner, not yet a POSIX
shell. A full plan to get there lives in the crate root:

- [`rush-to-sh-gaps.md`](./rush-to-sh-gaps.md) — analysis of what works vs. every
  POSIX gap, grouped by spec area.
- [`rush-to-sh-plan.md`](./rush-to-sh-plan.md) — phased implementation plan
  (P0–P9, milestones M1–M4) and target architecture.

Done so far: Phases 0–6. Phase 0 (a `sys/` platform-abstraction layer with
termios confined to the Linux host backend; correctness fixes; a golden test
suite), Phase 1 (a POSIX lexer, `src/lexer.rs`), Phase 2 (a recursive-descent
parser + AST, `src/parser.rs`/`src/ast.rs`), **Phase 3 — milestone M1**: a
persistent `Shell` (`src/shell.rs`) plus the real execution core — the seven-step
word-expansion engine (`src/expand.rs`), arithmetic (`src/arith.rs`), in-crate
globbing (`src/glob.rs`), and an executor (`src/exec.rs`) with working
multi-stage pipelines, the full fd 0/1/2 redirection set, here-documents, and
command substitution — **Phase 4**: compound commands and functions — and
**Phase 5 — milestone M2**: the POSIX builtins (`src/builtins.rs`) — and
**Phase 6**: shell options (`src/options.rs`), POSIX invocation parsing,
startup files, and prompts. Both verified end-to-end on a Motor OS VM.

**Next step — Phase 7 — M3:** signal traps, `^C`, background `&`/`wait`, and
`$!`. Then **M4** (Phases 8–9: interactive UX, a conformance corpus, docs). See
the plan for details.

## What works today

- Basic line editing (arrows, home/end, del/backspace, in-memory history);
- External commands and **multi-stage pipelines** (`ls | sort | wc -l`),
  including **builtins, compound commands, and functions as pipeline stages**
  (`cmd | while read …; do … done`, `printf … | { read a b; … }`);
- `;` / `&&` / `||` sequencing, pipeline `!` negation, and `\` line continuation;
- **Control flow**: `if`/`elif`/`else`, `for [in …]`, `while`/`until`, `case`
  (with `|` alternation and glob patterns), brace groups `{ …; }`, subshells
  `( … )`, and **functions** `name() { … }` with `return`/`break`/`continue`
  (including `break n`/`continue n`);
- **Variables**, `$?`, `$#`, `$@`/`$*`, positional parameters, and `export`able
  environment; inline `VAR=value command`;
- **Word expansion**: `$var` / `${var}` with `:-` `:=` `:?` `:+` `${#x}`
  `#`/`##`/`%`/`%%`, command substitution (`$(…)` / `` `…` ``), arithmetic
  `$(( … ))` (with `$`-params inside), tilde `~`, field splitting on `IFS`, and
  pathname globbing (`*` `?` `[...]`);
- **Redirections**: `<`, `>`, `>>`, `2>`, `2>&1`-style fd duplication, `<>`, and
  here-documents (`<<`, `<<-`, quoted delimiter); redirections also apply to
  compound commands (`… done > file`) and to builtins (`echo hi >f`);
- **Builtins**: special — `:` `.` `eval` `exec` `exit` `export` `readonly` `set`
  `shift` `unset` `times` `trap` `break` `continue` `return`; regular — `cd`
  (full) `pwd` `echo` `printf` `test`/`[` `read` `true` `false` `getopts`
  `command` `type` `hash` `alias`/`unalias` `umask`;
- **Shell options**, enforced: `set -e` (errexit, with the POSIX condition-context
  rules), `-u` (nounset), `-x` (xtrace via `PS4`), `-n` (noexec), `-f` (noglob),
  `-C` (noclobber, with `>|`), `-a` (allexport), `-v` (verbose), `-o pipefail`,
  `set -o`/`+o` listings, and `$-`;
- **POSIX invocation**: `rush [options] script [args…]`, `-c string [name
  [args…]]`, `-s`/stdin, clustered (`-ex`) and `+`-form options, `-o name`,
  `--`; positional parameters from operands in every form;
- **Startup & prompts**: an interactive shell sources `$ENV` (a login shell also
  reads `/etc/profile` and `~/.profile`); `PS1`/`PS2`/`PS4` are expanded
  variables, and `PWD`/`OLDPWD` are maintained.

## Not yet working (see the gap analysis)

- Signal traps (only `EXIT` fires), `^C`, background `&`/`wait`, `kill`, job
  control — Phase 7;
- Tab completion, UTF-8 input editing, persistent history, `^D` at an empty
  prompt, and multi-row line wrapping — Phase 8;
- `umask` affecting file creation, `times` accounting (both display-only); the
  `monitor`/`notify`/`vi`/`nolog`/`hashall`/`ignoreeof` options are accepted but
  inert; a `case` with plain `pat)` patterns *inside* `$( … )` (lexer
  paren-balancing — use `(pat)`).

### Deliberate divergences from `dash`

`dash` is rush's reference for POSIX behavior, but a few things differ on
purpose: `set -o pipefail` exists (POSIX.1-2024 added it; dash has no such
option); `-h` is accepted as an inert option rather than rejected (POSIX
reserves the letter for command hashing, so rush's old "`-h` prints usage" is
gone); `$-` lists option letters in a canonical order (POSIX leaves the order
unspecified); `set -v` echoes a script in one piece rather than interleaving it
line-by-line (rush reads a whole script before parsing it — the interactive
loop, which reads a line at a time, does interleave); and the default `PS1` is
rush's colored `rush:$PWD$ ` rather than a bare `$ ` (it is an ordinary
variable, so `PS1='$ '` restores dash's).

## Contributions:

- Are welcome;
- If you plan to add a large feature or make a non-trivial refactoring, please discuss your approach first.
