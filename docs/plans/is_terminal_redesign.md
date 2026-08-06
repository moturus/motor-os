# Per-descriptor `is_terminal` redesign

2026-08-05. Status: **steps 1-2 implemented (uncommitted); step 3 pending**.

## Summary and decision

Motor OS currently answers `is_terminal(fd)` from the mutable process
environment variable `MOTURUS_STDIO_IS_TERMINAL`. The descriptor is used only
to reject values outside 0, 1, and 2; stdin, stdout, and stderr otherwise all
receive the same answer. This is not a correct implementation of Rust's
`std::io::IsTerminal` or the C `isatty` model:

- one process can have a different answer for each standard stream;
- a duplicated descriptor must have the same answer as its source;
- changing an environment variable must not change the nature of an open
  descriptor; and
- terminal status must follow inherited descriptors independently.

The proposed design makes terminal status immutable metadata on the child-side
stdio descriptor object. Spawn derives a bit independently for stdin, stdout,
and stderr. `is_terminal(fd)` looks up the descriptor and asks the object, so
aliases work naturally and regular files, sockets, null streams, and ordinary
pipes remain non-terminal.

Motor OS still does not need a kernel pty, termios, or a line discipline.
`sys-tty`, `russhd`, and `rmux` may continue to provide terminal behavior over
ordinary pipes. During migration, the existing environment variable becomes a
launch-only instruction for marking explicitly created child stdio pipes; the
VDSO consumes it before the child starts and never uses it as live process
state.

## Terminology

A **terminal endpoint** in this document is a descriptor whose peer provides
the terminal behavior Motor programs expect: ANSI interpretation, interactive
input, and any terminal-size protocol implemented above the byte stream. The
transport may still be a `StdioPipe`.

Terminal status belongs to one endpoint, not to the shared pipe storage. For
example, rmux's end of a pane connection is an ordinary parent-side
`ChildStdio`, while the pane child's corresponding `SelfStdio` is a terminal
endpoint. Marking the shared pipe itself would incorrectly make both ends
terminal.

Terminal status is advisory I/O metadata. It does not prove that a human is
present, identify the peer, or grant authority.

## Current implementation

### Query path

`src/sys/lib/rt.vdso/src/rt_fs.rs::is_terminal` currently:

1. returns false unless `fd` is 0, 1, or 2;
2. reads `MOTURUS_STDIO_IS_TERMINAL` through the process environment; and
3. returns true only for the exact values `true` and `TRUE`.

The implementation never consults the descriptor table. Consequently all
three stdio descriptors have one process-wide answer, and every descriptor
greater than 2 is reported as non-terminal even if it aliases stdout or
stderr.

Rust std passes the queried handle's raw descriptor to this function
(`library/std/src/sys/io/is_terminal/motor.rs`) and implements `IsTerminal` for
`File`, owned descriptors, stdin, stdout, and stderr. The process-wide answer
therefore violates the public API above it, rather than merely exposing a
Motor-specific definition.

### Spawn path

`std::process::Command::new` in Motor's Rust toolchain removes the inherited
terminal environment key. `moto_rt::process::spawn` then tries to reconstruct
one child-wide answer from the child's stdio configuration. The historical
heuristic marks the child terminal when stdin and stdout are both
`STDIO_INHERIT`; adding a check that the parent's stdin reports terminal avoids
one false positive but does not make the model per-descriptor. Stderr is not
part of the inference.

There is also an important build boundary: Motor's custom `libstd` embeds its
own crates.io copy of `moto-rt`. Changing only the core repository's
`src/sys/lib/moto-rt` does not change the implementation used inside
`std::process::Command` until the Rust toolchain is rebuilt. Correctness must
therefore live in the VDSO spawn path reached by old and new callers; it must
not depend on a particular caller-side heuristic.

### How inherited stdio works

`STDIO_INHERIT` does not install the parent's descriptor object in the child.
`src/sys/lib/rt.vdso/src/stdio.rs::create_stdio_pipes` creates a new
`StdioPipe` pair and installs a relay between the parent stream and the child.
`STDIO_MAKE_PIPE` also creates a pair but returns the parent endpoint as
`ChildStdio`. `STDIO_NULL` creates an empty child stream.

The pipe representation cannot reveal terminal status. A pipe relayed to
sys-tty and a pipe pumped into a regular file have the same transport type but
different semantics.

## Concrete incorrect cases

Motor can construct mixed terminal and non-terminal streams today. Rush
configures stdin, stdout, and stderr independently and implements file and
pipeline redirection by pumping `Stdio::piped()` streams.

For a command launched by an interactive shell, the correct terminal mask is:

| Child setup | stdin | stdout | stderr |
| --- | :---: | :---: | :---: |
| no redirection | terminal | terminal | terminal |
| `program > file` | terminal | not terminal | terminal |
| `program < file` | not terminal | terminal | terminal |
| `program 2> file` | terminal | terminal | not terminal |
| first pipeline stage | terminal | not terminal | terminal |
| last pipeline stage | not terminal | terminal | terminal |
| background command with null stdin | not terminal | terminal | terminal |

A single environment bit cannot represent any mixed row. Depending on the
spawn API and heuristic, the current implementation reports either all false
or all true.

Descriptor duplication is a separate counterexample. `posix_duplicate(fd)`
adds another descriptor referring to the same `Arc<dyn PosixFile>`. Duplicating
terminal stdout normally produces an fd greater than 2, but the current range
check reports that alias as non-terminal even though both descriptors refer to
the same endpoint.

## Spoofing and security properties

The current answer is directly mutable. A process can call
`moto_rt::process::setenv`, the C environment API, or Rust's
`std::env::set_var` and change all three answers without changing any I/O
object. A parent can explicitly put the key in a child's environment as well.

This is not by itself a capability escalation:

- the environment is process-local, so a child cannot change its parent's
  answer;
- claiming to be a terminal does not change the pipe or grant an OS handle;
  and
- a process creator can construct a fake pty on conventional systems too.

It is nevertheless unsafe to treat this value as authentication or proof of
human presence. False answers can select interactive parsers, emit ANSI or
terminal-query bytes into files and protocols, change panic-log routing, or
enable prompt-based workflows on piped input. In-tree consumers include shell
interactive mode, terminal sizing, automatic color, raw line editing, panic
diagnostics, and Lorry's interactive approval paths.

The redesign guarantees descriptor consistency, not a trusted user. Code that
authorizes an operation must continue to use an explicit authorization policy;
`is_terminal()` may decide only whether prompting is practical.

## Required invariants

After the redesign:

1. `is_terminal(fd)` describes the object referenced by that descriptor.
2. Stdin, stdout, and stderr may return different values.
3. `duplicate(fd)` returns a descriptor with the same terminal answer.
4. Invalid descriptors, regular files, sockets, null streams, and ordinary
   parent-side `ChildStdio` objects return false.
5. Mutating the process environment after startup cannot change an existing
   descriptor's answer.
6. Each inherited child stream copies the corresponding parent stream's
   answer; stdout must not be inferred from stdin, or vice versa.
7. A newly captured or null child stream is non-terminal unless the spawner is
   explicitly acting as its terminal provider.
8. Old toolchains using the caller-side environment heuristic cannot turn an
   inherited non-terminal pipe into a terminal.
9. Existing terminal owners can launch terminal-backed children throughout a
   staged core/runtime/toolchain update.
10. The change adds no kernel surface, boot-time work, retry, timeout, or
    polling behavior.

## Proposed design

### 1. Descriptor-object query

Add this method to `rt.vdso`'s `PosixFile` trait:

```rust
fn is_terminal(&self) -> bool {
    false
}
```

All existing descriptor kinds remain false by default. Add an immutable
terminal field to `SelfStdio` and override the method there. `ChildStdio`
deliberately retains the false default: it is the terminal provider's end of
the connection, not the endpoint presented to the emulated-terminal child.

Replace `rt_fs::is_terminal` with a descriptor-table lookup:

```rust
posix::get_file(fd).is_some_and(|file| file.is_terminal())
```

This removes the 0..=2 special case. Because duplicates share the same
`PosixFile` object, alias behavior requires no separate bookkeeping.

### 2. Carry status in child bootstrap data

Add a flags word to each `StdioData`, with bit 0 meaning terminal. The parent
VDSO writes the flag while constructing each child stream; the child VDSO
reads it when constructing its three `SelfStdio` objects. An equivalent
three-bit mask in `ProcessData` would work, but keeping the flag beside each
stream's pipe data is clearer and avoids positional coupling.

`ProcessData` is an internal VDSO bootstrap page, and the spawning VDSO loads
the VDSO used by the child. No kernel ABI or public `moto-rt` structure needs
to change for this first patch. The existing process-data version field should
be set or validated if required by the final layout audit.

### 3. Derive each child stream independently

`create_child_stdio` computes each bit from that stream's spawn mode:

| Spawn mode | Child terminal status |
| --- | --- |
| `STDIO_NULL` | false |
| `STDIO_INHERIT` | query the matching parent fd (0, 1, or 2) |
| `STDIO_MAKE_PIPE` | explicit terminal-launch hint, otherwise false |
| arbitrary fd | copy that descriptor's status once fd passing is supported |

Raw-fd stdio is not currently implemented by the runtime even though Rust
std has a representation for it. Supporting raw-fd child stdio is outside
this redesign; the terminal rule above documents how it must behave when that
feature is implemented.

For `STDIO_INHERIT`, the VDSO always derives from the matching parent
descriptor and ignores a legacy process-wide `true` hint. This detail makes
the transition safe with an old `libstd`: its embedded `moto-rt` may still
synthesize the old marker for all-inherited stdio, but it cannot override the
descriptor-derived result.

### 4. Convert the environment key into a launch-only hint

During spawn, the VDSO recognizes the legacy
`MOTURUS_STDIO_IS_TERMINAL=true` value, removes the entry from the child's
environment, and uses it only to mark `STDIO_MAKE_PIPE` endpoints. Existing
terminal owners all create the child's three stdio pipes explicitly, so their
behavior is preserved:

- `sys-tty` provides the serial-console terminal;
- `russhd` marks only sessions for which the SSH client requested a pty; and
- `rmux` provides a terminal emulator for each pane.

The key is consumed regardless of value so it cannot become inherited live
state. After startup, setting or unsetting it has no effect on
`is_terminal()`.

The creator of a pipe can still deliberately mark the child endpoint as a
terminal. That is necessary for userspace terminal emulators and is not a
security capability. The creator is responsible for actually providing the
advertised behavior.

The existing boolean marks all explicitly created stdio pipes. That covers
all current terminal owners. If a future owner needs to emulate a terminal on
only a subset of newly created streams, add a three-bit native spawn option
rather than adding three live environment variables.

### 5. Remove caller-side inference

Once the VDSO owns propagation, delete `moto_rt::process::spawn`'s
stdin/stdout heuristic. Caller-side code cannot reliably infer all three
streams, and there are multiple compiled copies of `moto-rt` during a staged
toolchain update.

Publish the updated `moto-rt`, update the Rust checkout and lockfile, and
rebuild the Motor toolchain. The VDSO compatibility rule above makes this
cleanup independently deployable: correctness does not wait for the rebuilt
`libstd`.

Longer term, a Motor-specific `CommandExt` or native spawn option may replace
the consumed environment hint. That API is not required for correctness and
should not be introduced until a current user needs a partial terminal mask.

## Rejected alternatives

### Keep the parent-stdin inheritance guard

Checking that the parent's stdin is terminal fixes only the case where a
non-terminal process spawns a child with inherited stdin and stdout. It still
makes all child streams equal, ignores stderr, fails mixed redirection, and
gets aliases wrong.

### Use three environment variables

Per-stream keys could represent a mask but would remain mutable after startup,
would still fail descriptor duplication and replacement, and would keep an
I/O-object property in unrelated process-global state.

### Infer terminal status from `StdioPipe`

Terminal and non-terminal stdio use the same pipe implementation. Moreover,
the two endpoints of a terminal-emulator connection intentionally have
different answers. The transport cannot supply this property.

### Define `is_terminal` as "interactive process"

A process-wide interactive-session hint can be useful, but it is a different
API. Existing Rust and C callers query particular descriptors and rely on
redirection-sensitive behavior. Changing the meaning would preserve the bugs
under a misleading standard name.

### Add kernel ptys or terminal devices

Motor already supports terminal emulation in userspace over pipes. A kernel
device abstraction and line discipline would be substantially more complex
and would not be needed to answer this descriptor metadata question.

## Implementation plan

Each core-repository step is intended to remain within roughly 100-300 lines,
including tests. After each implemented step, add a brief implementation note
to this document.

### Step 1 — Per-descriptor VDSO model and compatibility path

- Add the default `PosixFile::is_terminal` method and the immutable
  `SelfStdio` implementation.
- Add per-stream terminal flags to the VDSO bootstrap data.
- Parse and consume the legacy launch hint in the VDSO spawn path.
- Derive the three child flags according to the spawn-mode table.
- Replace the environment-based `rt_fs::is_terminal` implementation with the
  descriptor lookup.
- Add focused systest coverage for terminal-owner pipes, a non-terminal child,
  inherited descendants, mixed stdio, environment mutation, and duplication.

This step must work with the currently installed Motor `libstd`, including its
embedded old `moto-rt` heuristic.

**Implementation note (2026-08-06).** Implemented as designed: a `flags`
word on `StdioData` (bit 0 terminal), consumed-hint parsing beside the
caps/detached keys in `run_elf`, per-mode derivation in
`create_stdio_pipes`, and the descriptor lookup in `rt_fs::is_terminal`.
No version-field change was needed: the spawner maps its own VDSO image
into the child, so both sides of the bootstrap page are always the same
build. One detail beyond the text above: the consumed hint is ignored
entirely when the child's stdin and stdout are both `STDIO_INHERIT`,
because that is precisely the one shape the old embedded heuristic
synthesizes the key for — otherwise an old-toolchain spawn with inherited
stdin/stdout and a captured stderr would mark that stderr pipe terminal
(the `110` test-matrix row). A deliberate partial mask remains future
native-API work (step 4). Coverage lives in
`src/sys/tests/systest/src/stdio_terminal.rs`, which supersedes the old
env-based `test_stdio_is_terminal`, and the non-pty crossterm check in
`src/tests/full-test.sh` was flipped back to rejecting terminal queries.
Writing the duplication test surfaced a preexisting, unrelated gap:
`SelfStdio::close` in the VDSO is an unimplemented `todo!()`, so closing a
duplicated stdio descriptor aborts the process; the test leaves its
duplicate open and the gap awaits its own decision.

### Step 2 — Core `moto-rt` cleanup and documentation

- Delete caller-side terminal inference from `moto_rt::process::spawn`.
- Update the environment-key documentation to describe a consumed spawn hint,
  not child-visible state.
- Update C-runtime documentation to state that the queried descriptor is what
  determines the answer.
- Update in-tree terminal-owner comments and any design documentation that
  describes `is_terminal` as process-wide.
- Audit all in-tree `IsTerminal` consumers for assumptions that all three
  streams have the same status. Fix only concrete assumptions found by that
  audit; terminal status remains advisory rather than authorization.

**Implementation note (2026-08-06).** The caller-side heuristic was deleted
from `moto_rt::process::spawn`; the environment-key and
`moto_rt::fs::is_terminal` documentation now describe the consumed spawn
hint and the descriptor-determined answer, as do the mlibc `Isatty` notes
in `docs/porting-libc/porting-libc-appendix-c.md` and the platform facts in
`docs/plans/crossterm.md`. The consumer audit (rush, lorry, gears, russhd,
sysbox `ls`, rmux) found no code assuming all three streams share one
status — every caller queries the specific stream it acts on — so only
rmux's comments describing the old model were updated.

### Step 3 — Rust toolchain refresh

- Publish or otherwise pin the cleaned-up `moto-rt` version used by Rust std.
- Update the Motor Rust checkout and lockfile.
- Remove the obsolete `Command::new` environment workaround if no old-runtime
  compatibility still requires it.
- Rebuild the custom Motor toolchain and repeat the core tests with that
  toolchain.

This step is in the Motor Rust checkout rather than the core repository and
requires its own review and commit.

### Step 4 — Optional native launch API

Only if a concrete terminal owner needs a partial mask, add a three-bit native
spawn option and a Motor `CommandExt` surface, migrate the owners, and retire
the legacy environment hint. Do not add this API merely to replace a working
launch-only compatibility instruction.

## Test matrix

The VM tests should query all three descriptors in the child and report a
three-bit mask. At minimum they must cover:

| Parent/child arrangement | Expected mask (stdin/stdout/stderr) |
| --- | --- |
| ordinary captured child | `000` |
| captured child inheriting into a grandchild | `000` |
| explicitly terminal-backed child | `111` |
| terminal child, all streams inherited by descendant | `111` |
| terminal child, descendant stdout captured | `101` |
| terminal child, descendant stdin captured | `011` |
| terminal child, descendant stderr captured | `110` |
| terminal child, descendant stdin null | `011` |
| set legacy key after non-terminal child startup | unchanged `000` |
| unset legacy key after terminal child startup | unchanged `111` |
| duplicate terminal stdout to fd > 2 | true on both descriptors |
| duplicate non-terminal stdout | false on both descriptors |
| regular file, socket, invalid fd, parent `ChildStdio` | false |

The mixed tests must exercise `std::process::Command`, not only direct
`moto_rt::process::spawn`, so they cover the embedded runtime copy. Direct
runtime and C-ABI spawn paths should receive focused coverage where their
environment handling differs.

Every test must be included in `src/tests/full-test.sh` directly or
transitively. Before each core patch is presented for commit, format with
`cargo +nightly fmt`, ensure no new compiler or clippy warnings, and run the
full debug and release suites three consecutive times each, as required by
the repository guidelines.

## Acceptance criteria

The redesign is complete when:

- all invariants above hold in both Rust and C-facing queries;
- all mixed-stream and duplicate tests pass;
- descendants of non-pty SSH sessions remain non-terminal;
- children of sys-tty, SSH pty sessions, and rmux panes remain terminal;
- no running process can change an existing descriptor's answer through its
  environment;
- the current and refreshed Motor Rust toolchains both have a safe deployment
  point during the transition;
- no boot work, kernel API, polling, retry, or timeout is added; and
- `src/tests/full-test.sh` passes three times each in debug and release.
