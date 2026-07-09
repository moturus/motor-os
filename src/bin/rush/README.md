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

Done so far: Phases 0–4. Phase 0 (a `sys/` platform-abstraction layer with
termios confined to the Linux host backend; correctness fixes; a golden test
suite), Phase 1 (a POSIX lexer, `src/lexer.rs`), Phase 2 (a recursive-descent
parser + AST, `src/parser.rs`/`src/ast.rs`), **Phase 3 — milestone M1**: a
persistent `Shell` (`src/shell.rs`) plus the real execution core — the seven-step
word-expansion engine (`src/expand.rs`), arithmetic (`src/arith.rs`), in-crate
globbing (`src/glob.rs`), and an executor (`src/exec.rs`) with working
multi-stage pipelines, the full fd 0/1/2 redirection set, here-documents, and
command substitution — and **Phase 4**: compound commands and functions.

**Next step — Phase 5 (milestone M2):** the POSIX builtins — `echo`/`printf`/
`test`/`[`/`read`/`export`/`readonly`/`set`/`shift`/`unset`/`.`/`eval`/…, split
into special vs. regular. See the plan for details.

## What works today

- Basic line editing (arrows, home/end, del/backspace, in-memory history);
- External commands and **multi-stage pipelines** (`ls | sort | wc -l`);
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
  compound commands (`… done > file`);
- `cd` / `exit` / `quit` / `:` / `true` / `false` builtins; `-c <string>` and
  running a script file.

## Not yet working (see the gap analysis)

- Most builtins (`echo`/`printf`/`test`/`read`/`export`/`set`/…) — Phase 5;
- Shell options (`set -e`/`-u`/`-x`/`-f`), full invocation parsing (incl.
  positional params for `-c string name args`) — Phase 6;
- Traps, background `&`/`wait`, job control — Phase 7;
- A compound command or function as a stage of a multi-stage pipeline
  (`{ …; } | cmd`, `cmd | while …`) is not yet wired.

## Contributions:

- Are welcome;
- If you plan to add a large feature or make a non-trivial refactoring, please discuss your approach first.
