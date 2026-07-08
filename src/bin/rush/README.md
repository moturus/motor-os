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

Done so far: Phase 0 (a `sys/` platform-abstraction layer with termios confined
to the Linux host backend; correctness fixes — diagnostics to stderr, 127/126
exit codes, POSIX `exit` semantics; a golden integration test suite), Phase 1
(a POSIX lexer in `src/lexer.rs` — operators, `IO_NUMBER`, quoting with
preserved metadata, `$`/backtick expansions captured opaquely, comments,
here-documents, and continuation reporting), and Phase 2 (a recursive-descent
parser in `src/parser.rs` building an AST — `src/ast.rs` — of lists, and-or
lists, pipelines, and simple commands with assignments and redirections, now
wired into a minimal AST-walking executor that replaces the old flat parser).

**Next step — Phase 3 (milestone M1):** shell state plus the real execution
core — variables and `$?`, the POSIX word-expansion engine (parameter/command/
arithmetic expansion, field splitting, globbing), working multi-stage pipelines,
the full redirection set, here-document delivery, and command substitution. This
is the biggest jump in value. See the plan for details.

## What works today

- Basic line editing (arrows, home/end, del/backspace, in-memory history);
- Running a single external command, plus `cd` / `exit` / `quit` builtins;
- `;` / `&&` / `||` sequencing (left-associative), and `\` line continuation;
- Inline `VAR=value command` and fd 0/1/2 file redirection (`<`, `>`, `>>`, `2>`, …);
- `-c <string>` and running a script file.

## Not yet working (see the gap analysis)

- `$`-expansion — variables, `$?`, command substitution, arithmetic (words
  currently flatten to their literal parts; expansion is Phase 3);
- Multi-stage pipelines (`ls | wc -l`), here-document delivery, and fd
  duplication (`2>&1`) — parsed, but execution is deferred to Phase 3;
- Globbing (`*`, `?`, `[...]`) — currently disabled;
- Control flow (`if` / `for` / `while` / `case`), functions, and most builtins.

## Contributions:

- Are welcome;
- If you plan to add a large feature or make a non-trivial refactoring, please discuss your approach first.
