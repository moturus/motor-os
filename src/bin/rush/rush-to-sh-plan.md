# rush → POSIX sh: implementation plan

Companion to [`rush-to-sh-gaps.md`](./rush-to-sh-gaps.md) (the gap analysis). That document
says *what is missing*; this one says *how to build it*, in a logical, incremental
order where the shell compiles and works at the end of every phase.

- Reference spec: POSIX.1-2017 Shell Command Language,
  <https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html>.
- Reference behavior target: **`dash`** (a small, near-pure POSIX shell). When
  the spec is ambiguous, match `dash`. Bash-only extensions are out of scope
  unless explicitly listed.
- Guiding constraints (from the project's charter):
  - **Minimal/zero external dependencies.** Implement globbing, pattern
    matching, arithmetic, etc. in-crate rather than pulling crates.
  - **Portability to Motor OS**, which is *not* a standard POSIX host.

---

## 0. Guiding constraints that shape the whole design

### 0.1 The terminal model: no termios on Motor OS
Motor OS does **not** implement termios. There is no `tcgetattr`/`tcsetattr`,
no raw/cooked mode toggle, no `ISIG`/`ICANON`, no `tcsetpgrp`. The console is
**always raw**: the shell receives input bytes directly and must drive the
display entirely with **ANSI escape sequences** (the existing `ESC[6n`
cursor-position query in `term.rs:647` is exactly the right idiom; keep that
style and extend it).

Consequences that ripple through the plan:

- **`term_impl_unix.rs` (termios) is a Linux-host-only backend**, used so the
  shell is pleasant to develop and test on Linux. It must never be on the core
  path. The core assumes "console is always raw; I own echo and editing."
- **No mode-flip around child processes.** The current code cooks the terminal
  before running a child (`term.rs:317`) and re-raws afterward. On Motor OS this
  is a no-op, so the portable contract is: the terminal stays in one mode; any
  child that wants line editing does its own. The Linux backend *may* emulate
  cook/uncook for dev convenience, but the core must not depend on it.
- **Signal delivery cannot come from the tty.** Because no terminal driver turns
  `^C`/`^Z` into SIGINT/SIGTSTP, the shell must detect the control **bytes**
  itself (0x03, etc.) and, if it wants to interrupt a running child, deliver a
  signal via an OS primitive (`kill`) — assuming Motor OS exposes one. Terminal
  job control (`^Z` suspend, `tcsetpgrp` foreground handoff) is **not
  achievable** here and is deferred/marked platform-dependent (see §8, §9).
- **Terminal size / cursor** are obtained via escape sequences (`ESC[6n`;
  size via `ESC[999;999H` + `ESC[6n`), never via `TIOCGWINSZ` ioctls.

### 0.2 A `sys` abstraction layer
Introduce `src/sys/` with a platform-agnostic trait surface and two backends
(`sys/unix.rs` for the Linux host, `sys/motor.rs` / the existing
`#[cfg(not(unix))]` path for Motor OS). Everything platform-specific lives
behind it so the shell core is pure logic:

- **Process primitives:** spawn a program with explicit fd wiring; `wait`;
  send a signal (`kill`) if available.
- **Pipe/fd primitives:** create a pipe, `dup2`, close — needed for real
  multi-stage pipelines and fd redirections (`std::process`/`Stdio` alone cannot
  wire a *builtin* into a pipeline; see §3.3).
- **Terminal I/O:** read input bytes; write output; the raw-console assumption
  above. termios calls exist **only** in `sys/unix.rs`.
- **Subshell strategy:** whether real `fork` is available (Unix) or must be
  **emulated by cloning shell state and running in-process** (Motor OS, if it
  lacks fork). The shell core calls `sys::run_subshell(closure)`; the backend
  decides fork vs. emulate. (See §3.4 and §4 for the emulation semantics and its
  limits.)

This layer is created incrementally: Phase 0 stubs it and moves the existing
termios/spawn code behind it; later phases add pipe/dup/kill as needed.

### 0.3 Testing strategy (built alongside, from Phase 0)
The crate currently has **zero tests**. Every phase adds tests; no phase is
"done" without them.

- **Unit tests** for the lexer, parser (AST snapshots), and expansion engine.
- **Golden integration tests**: a harness that runs `rush -c '<script>'` and
  compares stdout / stderr / exit status against a recorded expectation, with
  the expectation cross-checked against `dash` on the Linux host. This is the
  primary conformance net.
- A small **corpus of `.sh` scripts** exercised end-to-end (grows each phase).

---

## 1. Target architecture

Replace the line-at-a-time, flat `Vec<Vec<Vec<String>>>` model with a real
pipeline: **lex → parse → AST → expand → execute**, over a persistent `Shell`
state object.

```
input bytes ─► Lexer ─► tokens ─► Parser ─► AST ─┐
                                                  ▼
   Shell state (vars, funcs, opts, $?, params) ─► Executor ─► exit status
                                                  ▲
                              Expansion engine (per word, on demand)
```

Proposed module layout (each introduced in the phase noted):

| Module | Responsibility | Phase |
| --- | --- | --- |
| `sys/` | platform primitives (process, pipe, tty, signals, subshell) | 0 |
| `token.rs` | token & operator definitions | 1 |
| `lexer.rs` | POSIX token recognition, quoting, here-doc collection, continuation | 1 |
| `ast.rs` | AST node types | 2 |
| `parser.rs` | recursive-descent parser → AST; "needs more input" signaling | 2 |
| `shell.rs` | `Shell` state: variables, functions, options, `$?`, positional params, traps | 3 |
| `expand.rs` | the 4-stage word-expansion engine | 3 |
| `glob.rs` | in-crate pathname + pattern matching (fnmatch) | 3 |
| `arith.rs` | `$(( ))` integer arithmetic evaluator | 3 |
| `exec.rs` | AST walker: lists, pipelines, redirections, subshells | 3–4 |
| `builtins/` | special + regular builtins | 5 |
| `options.rs` | `set` options, invocation parsing | 6 |
| `signal.rs` | traps, `^C` handling, background/`wait` | 7 |
| `term.rs` | interactive line editor (escape-sequence based) | 8 |

**AST shape (sketch):**
```
CompleteCommand = List
List            = [ (AndOr, sep ∈ {';','&'}) ... ]
AndOr           = Pipeline ( ('&&'|'||') Pipeline )*
Pipeline        = ['!'] Command ( '|' Command )*
Command         = Simple | Compound | FunctionDef
Simple          = { assigns: [Assign], words: [Word], redirs: [Redirect] }
Compound        = Brace(List) | Subshell(List) | If | For | While | Until | Case
                  ( each carrying optional redirs )
Redirect        = { fd: Option<u32>, op: RedirOp, target: Word | HereDoc }
Word            = [ WordPart ]   // parts tagged quoted/unquoted, incl. expansions
WordPart        = Literal(text, quoted) | Param(...) | CmdSub(List) | Arith(expr) | Tilde(user?)
```
Crucially, **quoting is preserved into the AST** (a `Word` is a list of tagged
parts), because expansion behaves differently in quoted vs. unquoted context and
quote removal is the *last* expansion step.

---

## 2. Milestones (value delivery checkpoints)

- **M1 — "Usable interactive shell"** (end of Phase 3): variables & `$VAR`/`${…}`,
  `$?`, `;` / `&&` / `||`, **working** multi-stage pipelines, real redirections,
  command substitution, arithmetic, globbing. This is the biggest jump in value.
- **M2 — "Scripting-capable"** (end of Phase 5): `if`/`for`/`while`/`case`,
  functions, and the core builtins. Can run real configure-style scripts.
- **M3 — "Feature-complete POSIX"** (end of Phase 7): shell options (`set -e`,
  `-u`, `-x`, …), traps, background jobs & `wait`.
- **M4 — "Conformant & polished"** (end of Phase 9): passes the conformance
  corpus; interactive UX (completion, persistent history, UTF-8); docs updated.

---

## Phase 0 — Foundations, `sys` layer, and quick correctness wins  ✅ DONE (2026-07-07)
**Goal:** a safety net and the platform seam, before the big refactor. No new
language features yet.

**Landed:** `src/sys/` abstraction layer (`mod.rs` trait + always-raw-console
contract, `unix.rs` termios host backend renamed `HostTerm`, `motor.rs` no-op
`MotorTerm`); `term_impl_unix.rs` deleted and termios now confined to
`sys/unix.rs`. Correctness fixes in `exec.rs`: all diagnostics to stderr;
command-not-found → 127, permission-denied/other spawn error → 126; spurious
"exited with status" line removed; `LAST_STATUS` tracking so bare `exit` uses
`$?`; `exit N` taken mod 256, non-numeric arg → stderr + exit 2 with the common
"numeric argument required" wording (not dash's shell-specific "Illegal number").
`tests/phase0.rs` — 12 golden integration tests (run the real binary via
`CARGO_BIN_EXE_rush`, cross-checked against dash). Crate is warning- and
clippy-clean; dev + release (`panic=abort`/LTO) builds pass.

Work items:
1. **Test harness** (§0.3): integration runner comparing stdout/stderr/status,
   plus a `dash`-diff helper for the Linux host. Add the first ~20 golden cases
   covering *current* behavior so the refactor can't silently regress it.
2. **Create `sys/`** and move existing platform code behind it: termios
   (`term_impl_unix.rs`) → `sys/unix.rs`; the `#[cfg(not(unix))]` no-op terminal
   → `sys/motor.rs`. Define the trait surface from §0.2 (process/pipe/tty/signal
   stubbed where not yet needed). Document the "always-raw console" contract.
3. **Cheap correctness fixes** that don't need the new architecture (from
   `rush-to-sh-gaps.md` §2.8, §4):
   - Route all shell diagnostics to **stderr** (`exec.rs` `println!` → `eprintln!`).
   - `command not found` → exit **127**; found-but-not-executable → **126**.
   - Remove the spurious `"[cmd] exited with status N"` line.
   - Track a single `last_status` and make bare `exit` use it; clamp exit codes
     to 0–255. (Full `$?` exposure comes in Phase 3.)

**Exit criteria:** existing behavior captured by golden tests; termios no longer
referenced outside `sys/unix.rs`; diagnostics on stderr; correct not-found codes.

---

## Phase 1 — Lexer  ✅ DONE (2026-07-08)
**Goal:** replace char-scanning `LineParser` tokenization with a POSIX token
recognizer (§2.2, §2.3, §2.10.1). Parser comes next; this phase just produces a
correct token stream + unit tests.

**Landed:** `src/token.rs` (Token/Operator/Word/WordPart/ExpansionKind/HereDoc)
and `src/lexer.rs` (`tokenize()` → `Result<Vec<Token>, LexError>`). Covers all
control + redirection operators and IO_NUMBER; single/double/backslash/`$'…'`
quoting with per-part quoted flags preserved (never stripped); `$name`/`${…}`/
`$(…)`/`` `…` ``/`$((…))` captured as opaque quote-aware balanced spans; `#`
comments at word boundaries; `\`-newline continuation; and here-docs (`<<`/`<<-`,
quoted-delimiter, tab-strip, multiple-per-line, in-place token with deferred
body collection). `LexError::Incomplete{Quote|Expansion|Backslash|HereDoc}`
drives PS2 continuation. 14 unit tests in `lexer.rs`; not yet wired to execution
(module is `#[allow(dead_code)]` until Phase 2). Known limits (documented in
code): `$((`-vs-`$( (` prefers arithmetic (bash-compatible); `#` comments inside
`$(…)` aren't special-cased. Old `line_parser.rs` still drives execution until
Phase 2 replaces it.

Work items:
- **Operators:** control operators `; & && || | ( ) ;;` and newline; redirection
  operators `< > >> << <<- <& >& <> >|`; `IO_NUMBER` (a digit run immediately
  before `<`/`>`). This directly closes the "`;`, `||`, `&`, redirection-glued-to-
  word" gaps.
- **Quoting** with metadata preserved (not stripped): single `'…'`, double
  `"…"`, backslash, and `$'…'` (ANSI-C) — mark `$"…"` as optional/skip.
- **`$`-introduced tokens** recognized as opaque spans for the parser to sub-parse
  later: `$name`, `${…}` (with brace nesting), `$(…)` (nested, paren-balanced),
  `` `…` ``, `$(( … ))`.
- **Comments:** `#` starts a comment when at the start of a word (fixes
  whole-line-only, script-only comment handling).
- **Line continuation & incompleteness:** the lexer reports "incomplete" when it
  ends inside a quote, an unterminated `${}`/`$()`, or with a trailing `\`. This
  generalizes today's `is_continuation()` and drives the interactive **PS2**
  prompt.
- **Here-document handling:** on seeing `<<`/`<<-` `word`, the lexer must collect
  subsequent input **lines** as the here-doc body (respecting quoted-delimiter =
  no expansion, and `<<-` leading-tab stripping). This requires the lexer/reader
  to cooperate on multi-line input; design the reader interface accordingly now.

**Exit criteria:** lexer unit tests over a table of tricky inputs (operators,
nested quotes, `$()` nesting, here-doc delimiters) pass. Not yet wired to
execution.

---

## Phase 2 — Parser & AST  ✅ DONE (2026-07-08)
**Goal:** turn tokens into the AST of §1, for the *non-compound* core: lists,
and-or lists, pipelines, simple commands with assignments and redirections.
Compound commands (reserved words) land in Phase 4.

**Landed:** `src/ast.rs` (List/ListItem/Separator/AndOr/AndOrOp/Pipeline/Command/
SimpleCommand/Assignment/Redirect/RedirOp — quoting preserved into the AST) and
`src/parser.rs` (recursive-descent `parse_source(&str) -> Parsed`). Parses list
(`;`/`&`/newline) → and-or (`&&`/`||`, left-assoc, newline-after-operator
continuation) → pipeline (`|`) → simple command, with leading `NAME=value`
assignments split from words and redirections (incl. `IO_NUMBER` and here-docs)
attached in any position. Lexer "incomplete" and parser "needs another operand"
fold into one `Parsed::Incomplete` that drives PS2; syntax errors → `Parsed::Error`
(exit 2). Reserved words / `(`-subshells / `!` are *recognized but deferred*
(subshell → clean syntax error) per the Phase 4 seam. `line_parser.rs` and
`redirect.rs` deleted; `exec.rs` rewritten as a minimal AST walker (lists, and-or
short-circuit, single-command pipelines, `cd`/`exit`/`quit` builtins, inline env,
fd 0/1/2 file redirects); `lib.rs` interactive loop now accumulates + re-lexes for
here-doc/continuation support. **Deferred to Phase 3 (refused cleanly, never a
panic):** `$`-expansion (words flatten to literals; bare `$@`/`$*` still splices),
multi-stage pipelines, here-doc delivery, fd-dup (`<&`/`>&`), and honoring a
redirected fd for the shell's own not-found diagnostic. 14 parser unit tests +
8 `tests/phase2.rs` golden tests (`;`/`&`/`||` sequencing); crate warning/clippy-
clean, dev + release build.

Work items:
- **`ast.rs`** node types per §1.
- **Recursive-descent `parser.rs`** for: `list` (`;`, `&`, newline separators) →
  `and_or` (`&&`/`||`, left-assoc) → `pipeline` (`|`, optional leading `!`) →
  `simple_command` (leading `var=val` assignments, words, and redirections in any
  position). Attach redirections to their command.
- **"Needs more input"** result so the interactive loop keeps reading (PS2) until
  a complete command parses — replacing today's ad-hoc `is_continuation()`.
- **Reserved-word recognition** wired in but only *used* in Phase 4; here they
  parse as plain words (with a clear seam to special-case them next).
- Rewire `lib.rs`/`exec.rs` to consume the AST. Execution in this phase can stay
  deliberately minimal (single external command + the temporary env path) so the
  shell keeps working; the real executor arrives in Phase 3.

**Exit criteria:** AST snapshot tests for representative inputs; `;`, `&&`, `||`
sequencing works end-to-end even before full expansion; golden tests green.

---

## Phase 3 — Shell state, expansion engine, real execution  ⟵ **M1**  ✅ DONE (2026-07-08)
**Goal:** the core that makes rush an actual shell. Largest phase; split into
sub-steps, each independently testable.

**Landed:** five new modules wired into a persistent `Shell` threaded through
the executor.
- `src/shell.rs` — `Shell` state: variables (exported live in `std::env`,
  unexported in a side map that shadows it, readonly set), positional params
  `$0`/`$1…`/`$#`, `$?`, `$$`, `IFS`, `noglob`, plus snapshot/restore for
  command-substitution isolation.
- `src/arith.rs` — `$(( ))` evaluator: signed `i64`, full C operator set incl.
  `**`, ternary/`&&`/`||` short-circuit, assignment ops, recursive variable
  refs, decoupled via an `ArithEnv` trait. 10 unit tests.
- `src/glob.rs` — in-crate `fnmatch` (`* ? […]`, `\`-escape) and pathname
  expansion (leading-dot rule, sorted, no-match→literal), reused by trimming.
  4 unit tests.
- `src/expand.rs` — the 7-step engine (tilde → parameter → command → arithmetic
  → field splitting → globbing → quote removal), carrying per-char quoting so
  only unquoted expansion results split and only unquoted `*?[` are magic;
  parameter modifiers `:- := :? :+`, `${#x}`, `#/##/%/%%`; quoted-vs-unquoted
  `$@`/`$*`; here-doc body expansion. `to_fields` (argv) / `to_string`
  (assignments, redirect targets). 8 unit tests.
- `src/exec.rs` — rewritten AST walker: real N-stage pipelines (std stdio
  chaining), full fd 0/1/2 redirection set incl. `2>&1`-style duplication and
  here-documents (fed via a pipe), and command substitution captured through a
  temp file with subshell state rollback. All on `std::process`/`std::fs` — **no
  `fork`/`dup2` syscalls**, preserving Motor OS portability. `lib.rs` now owns
  one `Shell` for the whole session.

16 `tests/phase3.rs` golden tests cross-checked against dash. Crate is
warning/clippy-clean; dev + release build; 91 tests total.

**Documented Phase 3 limits (revisited later):** pipeline stages are external
commands (the only builtins, `cd`/`exit`/`quit`, are nonsensical mid-pipeline);
per-stage `<&`/`>&`/here-docs inside a pipeline and redirections to fds > 2 are
not wired; background `&` runs synchronously (Phase 7); `set -f`/full `$-` await
Phase 6; `${x:?}` diagnoses but does not abort; command-substitution rollback
covers shell vars + cwd but not exported-env mutations. `~user` tilde is left
literal.

### 3.1 `Shell` state (`shell.rs`)
- Variables as a map with flags (**exported**, **readonly**); the shell/env
  boundary that `export` needs. `A=B cmd` sets a *temporary* var for that command
  only; bare `A=B` sets a shell var; only exported vars reach children.
- Positional parameters (`$1`…`$n`, `$0`), `$#`, `$@`, `$*`, `$?`, `$$`, `$-`.
  `$!` arrives with background jobs (Phase 7).
- `last_status` surfaced as `$?`.

### 3.2 Expansion engine (`expand.rs`) — correct POSIX order (§2.6)
Applied per word:
1. **Tilde** expansion (`~`, `~user` → `HOME`/passwd; on Motor OS, `~user`
   may be unsupported — note it).
2. **Parameter** expansion: `$x`, `${x}`, and the modifiers `:-`, `:=`, `:?`,
   `:+`, `${#x}`, prefix/suffix trim `#`, `##`, `%`, `%%`. (Bash `${x/…}`,
   `${!x}`, arrays → **skip**, non-POSIX.)
3. **Command substitution**: `$(…)` and `` `…` `` — parse the inner text as a
   `List`, run it in a subshell (§3.4), capture stdout, strip trailing newlines.
4. **Arithmetic** expansion `$(( … ))` via `arith.rs` (§3.5).
5. **Field splitting** on `IFS` (unquoted results only).
6. **Pathname** expansion (globbing) via `glob.rs` (§3.6), unless `set -f`.
7. **Quote removal.**

Special parameters and the quoted-vs-unquoted `$@`/`$*` splitting rules are part
of this step and need careful tests (they're a classic source of bugs).

### 3.3 Pipelines & redirections (`exec.rs`, uses `sys` pipe/dup)
- **Fix the `todo!` (`exec.rs:62`)**: execute N-stage pipelines by creating
  pipes (`sys::pipe`) and wiring each stage's stdin/stdout with `dup2` in the
  spawn path. External stages spawn with wired fds; a **builtin as a pipeline
  stage** runs in a subshell writing to the pipe (this is *why* raw pipe/dup are
  needed and `Stdio` alone is insufficient). Pipeline status = last stage
  (`pipefail` option later).
- **Redirections** (§2.7), applied per command in order: `<`, `>`, `>>`, `>|`,
  `<>`, `n>`, `n<`, fd-dup `n>&m` / `n<&m`, fd-close `n>&-`, and combined
  `2>&1`. Implemented as a list of fd operations resolved against `sys::dup2`.
  Replace the buffer-everything-in-memory redirect (`redirect.rs:12`) with true
  fd redirection so it **streams** and works for input and stderr.
- **Here-documents** `<<` / `<<-` feed the collected body (Phase 1) to fd 0,
  expanding the body unless the delimiter was quoted.

### 3.4 Subshells & command substitution (`sys::run_subshell`)
- `( … )` and command substitution run in a subshell: **real `fork`** on Unix;
  on Motor OS (if fork is unavailable) **emulate** by deep-cloning `Shell` state,
  running the `List` in-process with output captured/redirected, then discarding
  the clone's mutations. Document emulation limits: `$$` stays the parent PID,
  background `&` inside an emulated subshell degrades, traps differ — acceptable
  for a first cut; note them.

### 3.5 Arithmetic (`arith.rs`)
- Integer arithmetic per §2.6.4: `+ - * / % ** ( )`, comparison, logical,
  bitwise, `?:`, assignment operators, and variable references. Signed `intmax_t`
  semantics. Small Pratt/recursive parser; no external dep.

### 3.6 Globbing (`glob.rs`)
- Re-enable pathname expansion (currently disabled, `line_parser.rs:117`) with an
  **in-crate** matcher: `*`, `?`, `[…]` bracket classes, matched against directory
  entries, honoring the "no match → word stays literal" rule and `set -f`. Fixes
  the trailing-slash concern that motivated disabling glob (match path components,
  don't round-trip through a lossy library). Reused by `case` patterns and `${x#pat}`.

**Exit criteria (M1):** golden tests for variables, `$?`, quoting, `;`/`&&`/`||`,
multi-stage pipes, all redirection forms, here-docs, command substitution,
arithmetic, and globbing — cross-checked against `dash`.

---

## Phase 4 — Compound commands & functions  ✅ DONE (2026-07-08)  ⟵ completes core language
**Goal:** control flow and functions on top of the Phase 3 executor.

**Landed:** compound commands and functions across `ast.rs`, `parser.rs`,
`shell.rs`, and `exec.rs`.
- `ast.rs` — `Command` gains `Compound { kind, redirects }` and
  `Function { name, body }`; new `CompoundCommand` (Brace/Subshell/If/For/
  While/Case), `IfClause`/`ForClause`/`WhileClause`/`CaseClause`/`CaseItem`,
  and `FunctionBody { body, redirects }`.
- `parser.rs` — a `Reserved` word table recognized **only in command position**;
  `parse_compound_list` stops at terminator keywords/operators (`then` `else`
  `elif` `fi` `do` `done` `esac` `}` `)` `;;`); recursive-descent for
  `if`/`elif`/`else`, `for [in …]`, `while`/`until`, `case` (with `|`
  alternation and optional leading `(`), brace groups `{ …; }`, subshells
  `( … )`, and `name() compound-command` function defs; pipeline `!` negation;
  trailing redirect lists on compound commands and function defs. Multi-line
  constructs fold into `Parsed::Incomplete` for PS2.
- `shell.rs` — a `Flow` signal (`Normal`/`Break(n)`/`Continue(n)`/`Return(n)`)
  plus a functions map (`Rc<FunctionBody>`); both threaded into subshell
  snapshot/restore.
- `exec.rs` — `exec_compound` dispatch; `if`/`for`/`while`/`until`/`case`
  (patterns via `expand::to_pattern` + `glob::fnmatch`); brace group (current
  env) vs. subshell (snapshot/restore + flow reset); function invocation
  (positional-param rebind with `$0` unchanged, def redirects applied, `return`
  absorbed at the boundary); `break`/`continue`/`return` builtins with `n`-level
  propagation through lists/loops; pipeline `!` inversion.
- Bonus correctness fix (POSIX §2.6.4): `$(( … ))` now expands `$`-parameters/
  command-substitutions/nested arithmetic **before** evaluation (shared
  double-quote expander in `expand.rs`), so `$1`/`$x`/`$(cmd)` work inside
  arithmetic — needed for recursion and positional-param loops.

24 parser unit tests total + `tests/phase4.rs` (25 golden tests cross-checked
against dash); whole crate warning/clippy-clean (`--all-targets`), dev + release
(`panic=abort`/LTO) builds, and the Motor target (`cargo
+dev-x86_64-unknown-motor check --target x86_64-unknown-motor`) all pass.

**Documented Phase 4 limits:** a multi-stage pipeline's stages must be external
commands — a compound command or function as a non-trivial pipeline stage
(`{ …; } | cmd`, `cmd | while …`) is refused cleanly (needs a subshell wired to
a pipe fd, deferred with the builtins/job work); `exit` inside an emulated
`( … )` subshell exits the whole shell; prefix assignments on a function call
(`VAR=x func`) persist rather than scoping to the call; `${x:?}` still diagnoses
without aborting; `return` outside a function/sourced script stops the current
list rather than erroring.

Work items (parser support + executor support + tests each):
- `if / then / elif / else / fi`.
- `for name [in words]; do … done`.
- `while` / `until` loops.
- `case … in pat) … ;; esac` (patterns reuse `glob.rs` matching).
- Brace group `{ …; }` (current environment) and subshell `( … )` (§3.4).
- **Function definitions** `name() { … }` and invocation; positional params
  rebind within the call; `return`. (`local` is **not** POSIX — offer as an
  optional extension later, note it.)
- Loop/function control: `break [n]`, `continue [n]`, `return [n]` via a
  control-flow signal the executor propagates.
- Pipeline negation `!` semantics finalized.

**Exit criteria (M2 groundwork):** control-flow scripts run; nested constructs,
loop redirections, and `case` globbing covered by tests.

---

## Phase 5 — Builtins  ⟵ **M2**
**Goal:** the builtins POSIX requires, split into special vs. regular (§2.14).
Special builtins have distinct semantics (assignments persist; a syntax/usage
error aborts a non-interactive shell), so encode that property in the dispatch
table.

- **Special builtins:** `:`, `.` (source a file into the current shell), `eval`,
  `exec` (replace shell / apply redirs), `exit`, `export`, `readonly`, `set`,
  `shift`, `unset`, `times`, `trap` (stub until Phase 7), `break`/`continue`/
  `return` (wired to Phase 4 control flow).
- **Regular builtins:** `cd` (full: no-arg→`HOME`, `cd -`→`OLDPWD`, `CDPATH`,
  `-L`/`-P`, maintain `PWD`/`OLDPWD`), `pwd`, `echo`, `printf`, `test` / `[`
  (string/numeric/file predicates), `read`, `true`, `false`, `getopts`,
  `command`, `type`, `hash`, `alias`/`unalias`, `umask`, `kill`, and the job
  builtins `jobs`/`fg`/`bg`/`wait` (real behavior in Phase 7).
- Provide `echo`/`printf`/`test` as **builtins** specifically because a minimal
  Motor OS image may ship no external `coreutils`.

**Exit criteria (M2):** builtin unit + golden tests; a real-world-ish
configure/init script runs to completion using only builtins.

---

## Phase 6 — Shell options, invocation, startup, prompts
**Goal:** make behavior configurable and fix invocation/startup gaps
(`rush-to-sh-gaps.md` §2.10).

- **`set` options** honored by the executor: `-e` (errexit), `-u` (nounset),
  `-x` (xtrace → `PS4`), `-n` (noexec/parse-only), `-f` (noglob), `-C`
  (noclobber, gates `>` vs `>|`), `-v` (verbose), `-o pipefail`, and `$-`
  reporting. Hooks were reserved during Phases 3–5; this phase wires them on.
- **Invocation parsing rewrite** (`lib.rs:82`): bundled flags, `+x` form, `-s`
  (read stdin), `-o option`, `--`, and correct **`sh -c string [name [args…]]`**
  (set `$0`, `$1`…; stop appending operands to the command string). Set
  positional parameters from remaining operands for script mode too.

  **Invocation compatibility — what stays vs. what breaks.** The current arg
  parsing (untouched by Phase 0) is a *mostly*-compatible subset of POSIX
  `sh [options] [command_file [args…]]` / `sh -c string [name [args…]]`
  (POSIX XCU `sh`, §2.5.1 special parameters). Verified against `dash`:

  *Stable — compatible today, this phase only extends them:*
  - `sh -c 'single command string'` (one operand) — the form libc
    `system()`/`popen()` emit, with or without a leading `--`. The hot path.
  - `sh scriptfile` — running a file is the correct shape.
  - interactive `sh` with no operands.
  - unknown option → diagnostic + non-zero exit (wording/`exit 2` polish only).

  *Breaking — current behavior actively diverges and MUST change here:*
  1. **`-c` with extra operands** — rush joins them into the command string
     (`run_command`'s `args.join(" ")`); POSIX makes operand 1 = `$0`, operand
     2 = `$1`, …  e.g. `rush -c 'echo $1' NAME hello` prints `$1 NAME hello`
     today, must become `hello`. The join is replaced once positional params +
     `$`-expansion exist (why this waits for Phases 2–3).
  2. **Script operands** — `sh script.sh WORLD` does not set `$1` today; it must.
  3. **`-h` = print usage** — non-POSIX (dash rejects `-h` as an illegal option;
     POSIX reserves the letter for the `set -h` hashing option). Drop it or keep
     as an explicitly documented deviation.
  4. **`-i <script>`** = "run this file, then go interactive" — invented; POSIX
     locates an init file via `$ENV`. Replaced by the startup-file handling below.
  5. **`VAR=val` as the first operand → command mode** — a non-standard heuristic
     (`sh FOO=bar` should seek a *file* named that). Removed/changed.
  6. **`-piped`** — a rush-internal, hidden mode; as a token it is not a valid
     POSIX option cluster. Kept only as an internal extension (candidate for a
     `--long` rename), never advertised as POSIX.
- **Startup files:** interactive shells expand and source `$ENV`; login shells
  read profile. Keep this minimal and documented (note what's honored).
- **Environment maintenance:** `PWD`/`OLDPWD`/`HOME`/`IFS`, and prompt variables
  `PS1`/`PS2`/`PS4` with expansion, replacing the hardcoded prompt
  (`term.rs:713`). PS2 drives the continuation reader from Phase 2.

**Exit criteria:** option matrix tests; `-c`/`-s`/script positional-parameter
tests (the six breaking cases above pass, matching dash where applicable, and
any retained deviations like `-h`/`-piped` are documented); prompt/`$ENV`
behavior tested.

---

## Phase 7 — Signals, traps, background & wait  ⟵ **M3**
**Goal:** signal handling and asynchronous execution, within Motor OS's limits
(§0.1). This phase is explicitly **platform-gated**.

- **`trap`**: register handlers for signals, `EXIT`, and (best-effort) the shell's
  own interrupt; run `EXIT` trap on shell exit. Requires a `sys::on_signal` /
  self-`kill` capability; where Motor OS lacks a signal a trap targets, `trap`
  degrades gracefully and is documented.
- **Interactive `^C`:** since no tty generates SIGINT (§0.1), the reader detects
  the 0x03 **byte** and, if a child is running, asks `sys` to signal it (needs
  Motor OS `kill`); otherwise cancels the current input line.
- **Background jobs `&`** and **`wait`**, with `$!` set to the last background
  PID. A simple job table tracks async children.
- **Deferred (write down explicitly):** full interactive **job control** —
  `^Z`/SIGTSTP suspend, `fg`/`bg` resume, `tcsetpgrp` foreground-group handoff —
  depends on terminal/process-group facilities Motor OS does not provide without
  termios/tty ioctls. `jobs`/`fg`/`bg` are implemented as far as the platform
  allows (likely: list/wait for background jobs; no suspend/resume).

**Exit criteria:** trap/background/`wait` tests on the Linux host; Motor OS
capabilities documented with graceful degradation.

---

## Phase 8 — Interactive UX & polish
**Goal:** bring the escape-sequence line editor up to expectations
(`rush-to-sh-gaps.md` §3). All display via ANSI sequences, no termios (§0.1).

- **Clean EOF:** `^D` (or `read` returning 0) at an empty prompt exits with
  status 0, instead of the current error-exit (`term.rs:122`).
- **UTF-8 input editing:** stop dropping bytes ≥ 128 (`term.rs:150`); decode and
  edit by grapheme/codepoint, tracking display width for correct cursor math.
- **Tab completion:** filename completion (and command completion from `PATH`),
  driven by the same escape-sequence rendering.
- **Emacs-style bindings:** `^A ^E ^K ^U ^W ^L`, word motion, and reverse history
  search `^R`.
- **Persistent history:** `$HISTFILE` load/save across sessions (in-memory today).
  History expansion (`!!`, `!n`) is a bash-ism — **optional**, note if skipped.
- **Robust redraw:** handle input lines that wrap across terminal rows (current
  redraw assumes a single row) using cursor queries already in place.

**Exit criteria:** interactive behaviors verified on both backends;
completion/history/UTF-8 tested.

---

## Phase 9 — Conformance, hardening, docs  ⟵ **M4**
**Goal:** prove conformance and remove documentation drift.

- Run an external **POSIX shell conformance corpus** (e.g. the public
  modernish/oil-style POSIX test cases, or a curated corpus) and triage failures;
  every fixed case becomes a golden test.
- Fuzz the lexer/parser for panic-freedom (no `todo!`/`unwrap` on user input).
- **Update `README.md`**: correct the now-accurate "what works" list (piping and
  globbing become true), and update `rush-to-sh-gaps.md` to reflect closed gaps.

---

## Explicitly skipped / deferred features (with rationale)

**Out of scope — non-POSIX bashisms** (POSIX equivalents suffice):
- `[[ … ]]` (use `test`/`[`), arrays, `${!var}` indirection, `${var/…}`
  substitution, process substitution `<(…)`, here-strings `<<<`, `&>`/`|&`
  combined redirs, brace expansion `{a,b}`, coprocesses, `/dev/tcp` redirects,
  `local`/`declare`/`typeset` (may add `local` later as a documented extension).

**Deferred — platform-limited on Motor OS** (§0.1, §7):
- Full interactive job control: `^Z`/SIGTSTP suspend, `fg`/`bg` resume,
  `tcsetpgrp` foreground-group handoff. Background `&`/`wait` are supported;
  suspend/resume are not until Motor OS grows the needed primitives.
- `ulimit`, `times` resource accounting, and `umask` fidelity depend on Motor OS
  syscalls; implement to the extent the platform supports, else stub + document.
- `~user` (passwd-database) tilde expansion where Motor OS has no user database.

**Deferred — low value for now** (revisit post-M4):
- History expansion (`!!`, `!n`, `fc`).
- Restricted shell (`-r`), `set -o` display formatting niceties, `PROMPT_COMMAND`.
- Locale/collation-aware bracket classes (`[[:alpha:]]` beyond ASCII) and
  multibyte-aware globbing.

---

## Sequencing rationale (why this order)

1. **Phase 0 first** so the giant refactor is guarded by tests, and so the
   platform seam (no-termios reality) is settled before code depends on it.
2. **Lexer → Parser → AST** before anything else: every downstream feature needs
   structured input; the current flat model cannot represent `;`, `||`,
   redirections-on-fds, compound commands, or preserved quoting.
3. **State + expansion + execution together (Phase 3)** because they are mutually
   dependent (expansion reads state; execution drives expansion) and together
   they unlock the single biggest usability jump (**M1**).
4. **Compound commands (4)** need the Phase 3 executor to host loop/branch bodies.
5. **Builtins (5)** need execution, state, and (for `.`/`eval`) the parser — so
   they come after the core, delivering scripting capability (**M2**).
6. **Options/startup (6)** layer configurable behavior onto a working executor.
7. **Signals/jobs (7)** are the most platform-sensitive and depend on everything
   above; isolating them late keeps portability risk contained (**M3**).
8. **UX (8)** and **conformance (9)** polish a functionally complete shell (**M4**).
