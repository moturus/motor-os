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

Tab completes commands, filenames and `$variables`; Up/Down and `^R` search the
history, which persists across sessions when `$HISTFILE` is set; the usual emacs
keys work (`^A` `^E` `^K` `^U` `^W` `^Y` `^L`, `M-b`/`M-f`, `^R`).

## Status

**A working POSIX-ish shell.**

Conformance is measured, not asserted: `tests/conformance.rs` runs a corpus of
POSIX snippets through **both rush and `dash`** and requires them to agree on
stdout and exit status. What rush answers differently is listed, with reasons, in
that file's `DIVERGENCES` — and each entry is itself tested, so a divergence
cannot be quietly fixed or quietly introduced.

## What works today

- **Interactive editing**: arrows, Home/End, Del/Backspace, and emacs bindings
  (`^A` `^E` `^B` `^F` `^K` `^U` `^W` `^Y` `^T` `^L` `^D`, `M-b`/`M-f`/`M-d`,
  word-wise Ctrl/Alt-arrows); **UTF-8** input edited by character (including
  double-width CJK and emoji); lines that **wrap across rows**; `^C` to abandon a
  line and `^D` to end the session (with `$?`, as POSIX asks). The editor paints
  only what changed — a character typed at the end of a line costs the one byte
  that character is — so a slow console does not flicker;
- **Tab completion** of commands (builtins, functions, aliases, `$PATH`),
  filenames, and `$variables`, quoting-aware in both directions — it matches
  `ls 'my fi<TAB>` against the real name and escapes what it inserts;
- **History**: Up/Down, reverse-i-search (`^R`), the `history` builtin, and
  persistence via `$HISTFILE`/`$HISTSIZE` — a multi-line command is stored as
  *one* entry and recalled whole;
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
  `command` `type` `hash` `alias`/`unalias` `umask` `wait` `jobs` `fg` `bg`
  `kill`;
- **Signals & traps**: `trap` on `EXIT` and any signal (by name, `SIG`-prefixed
  name, or number), `trap ''` to ignore and `trap -` to restore; `^C` at the
  prompt raises `INT` (rush detects the byte itself — no platform generates the
  signal); `kill` with `-s`/`-NAME`/`-N`/`%job`/`-l`/`-0`;
- **Background jobs**: `cmd &` runs concurrently, with `$!`, `wait`
  (pid/`%job`/all), `jobs`, and `fg`. On Motor OS, which has neither signals nor
  a child pid, job identity is rush's own and `kill` can only terminate — see
  the plan's Phase 7 for the exact degradations;
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

## Not yet working

- Interactive **job control** — `^Z`/suspend, `bg`/resume, and foreground-group
  handoff — which Motor OS cannot support (no termios, no tty signals); `&` on a
  builtin/compound command gives isolation but not concurrency (no `fork`);
- **Redirections to fds above 2** (`exec 3>file`, `>&3`): Motor OS hands a child
  only inherit/null/pipe as its stdio, so an arbitrary fd cannot reach one at all;
- `umask` affecting file creation, `times` accounting (both display-only); the
  `monitor`/`notify`/`vi`/`nolog`/`hashall`/`ignoreeof` options are accepted but
  inert; a `case` with plain `pat)` patterns *inside* `$( … )` (lexer
  paren-balancing — use `(pat)`);
- `~user` tilde expansion (Motor OS has no user database), `fc`, and history
  expansion (`!!`, `!n`) — a bash-ism, deliberately skipped.

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
variable, so `PS1='$ '` restores dash's). rush also answers `history`, `clear`
and `quit` as builtins — extensions, and `clear` is one the Motor OS image needs
because it ships no external `clear`. Aliases expand at execution rather than
parse time, so `alias e=echo; e hi` works in a single `-c` string where dash
needs a second parse unit.
