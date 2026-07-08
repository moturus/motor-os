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
exit codes, POSIX `exit` semantics; a golden integration test suite) and Phase 1
(a POSIX lexer in `src/lexer.rs` — operators, `IO_NUMBER`, quoting with
preserved metadata, `$`/backtick expansions captured opaquely, comments,
here-documents, and continuation reporting, with unit tests). The lexer is not
yet wired into execution.

**Next step — Phase 2:** a recursive-descent parser building an AST (lists,
and-or, pipelines, simple commands with redirections) on top of the lexer,
replacing the flat `line_parser`. See the plan for details.

## What works today

- Basic line editing (arrows, home/end, del/backspace, in-memory history);
- Running a single external command, plus `cd` / `exit` / `quit` builtins;
- `&&` sequencing and `\` line continuation;
- Inline `VAR=value command` and stdout redirection (`>`, `>>`);
- `-c <string>` and running a script file.

## Not yet working (see the gap analysis)

- Multi-stage pipelines (`ls | wc -l`) — currently unimplemented;
- Globbing (`*`, `?`, `[...]`) — currently disabled;
- Variables / `$?`, `;` and `||`, control flow (`if` / `for` / `while` / `case`),
  functions, command substitution, `<` / `2>` redirects, and most builtins.

## Contributions:

- Are welcome;
- If you plan to add a large feature or make a non-trivial refactoring, please discuss your approach first.
