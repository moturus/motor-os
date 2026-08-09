# Motor OS ripgrep port plan

Status: ripgrep-only port implemented; the v9 OS stdio follow-up is complete as
an implementation plan but has not yet been implemented.

## Goal

Port the ripgrep 15.2.0 checkout in `../ripgrep` to
`x86_64-unknown-motor`, preserve its normal recursive and streaming behavior,
and verify a transferred binary in a Motor OS VM. Packaging, image integration,
and the eventual installed path are deferred. Keep the port small and suitable
for carrying in a ripgrep fork: Motor-specific code is limited to places where
the target's non-Unix classification selects an intentionally unsupported
fallback.

The initial scope is ripgrep's default pure-Rust feature set. PCRE2 remains
disabled, as it is in the checkout's default build. External decompressor
commands used by `-z` are not added to the image. Motor OS has no file-backed
memory mapping, so ripgrep retains its existing buffered-I/O fallback instead
of adding an emulated mapping or reading whole files into memory.

## Pre-port baseline

The source baseline is ripgrep commit
`3fce3b5bb0236da2df6d99672afb8a719642eca7`, version 15.2.0, with the
`ignore-0.4.33` tag. Both of the following already build and link with the
Motor toolchain:

```sh
cargo +dev-x86_64-unknown-motor build --locked \
  --target x86_64-unknown-motor
cargo +dev-x86_64-unknown-motor build --locked --release \
  --target x86_64-unknown-motor
```

The build is not yet a functional port:

- It emits eight Motor-only warnings from unsupported-platform branches in
  `ignore` and `grep-printer`.
- On a four-CPU Motor VM, an ordinary recursive search exits with status 2 and
  reports `unsupported platform`. The parallel walker intentionally rejects
  every root on targets that are neither Unix nor Windows.
- `-j1` works, including recursive traversal and `.ignore` matching. This
  confirms that Motor's standard filesystem APIs are sufficient and that the
  defect is confined to ripgrep's parallel directory-entry representation.
- Implicit piped input is not detected. `echo alpha | rg -j1 alpha` scans the
  current directory instead of stdin because the generic platform branch
  always reports stdin as unreadable. Explicit `rg alpha -` works.
- The generic `same-file` implementation cannot identify redirected stdout.
  Without a Motor implementation, ripgrep may search a file that it is also
  writing.
- `memmap2` uses its supported stub, and ripgrep safely falls back to ordinary
  reads. Motor and mlibc explicitly do not provide file-backed `mmap`.
- The unstripped release binary is about 23 MiB; the normal Motor `strip`
  recipe reduces it to about 4.1 MiB.

## Platform boundaries

Motor must not be declared Unix merely to select convenient implementations.
The target has Unix-style UTF-8 paths but deliberately sets no target family.
Each port site therefore uses `target_os = "motor"` only where Motor's actual
API or semantics justify it.

The port will preserve these explicit limitations:

- `--one-file-system` continues to return its existing unsupported-platform
  error. Motor currently exposes no portable filesystem/device number through
  `std`, and silently accepting the option would be incorrect.
- Symlink traversal is not added because Motor's filesystem does not support
  symlinks. Ordinary non-symlink traversal remains fully functional.
- File-backed mmap remains unavailable. `--mmap` may attempt a mapping and
  then use ripgrep's existing streaming fallback.
- PCRE2 and external decompressor programs remain separate optional features,
  not dependencies of this port.

There is also a system-level limitation outside ripgrep. The patched Motor
implementation can compare stdout's `FileAttr::entry_id` with a walked path
when fd 1 is a real regular file. Current `rush` file redirection instead gives
the child a pipe, captures its output, and writes the destination after the
child exits. Ripgrep therefore cannot discover the destination file through fd
1. This is addressed by the proposed hybrid direct-file/inherited-relay design
in [`stdio-file-fix-for-ripgrep.md`](stdio-file-fix-for-ripgrep.md), not by
adding shell-specific behavior to ripgrep.

## Incremental patches

### 1. Functional parallel traversal in ripgrep

Change `crates/ignore/src/walk.rs` so the non-Windows/non-Unix
`DirEntryRaw::from_entry_os` and `DirEntryRaw::from_path` branches construct a
raw entry from the standard `PathBuf` and `FileType` instead of returning an
unconditional error. These fields are already sufficient on a platform with
no symlinks and no Unix inode extension.

Keep the current Unix inode optimization and Windows cached metadata paths
unchanged. Keep `device_num` unsupported, so `--one-file-system` fails clearly
rather than pretending to enforce a boundary.

Validate this patch first with a warning-free Motor cross-build, then in a VM
with default four-thread recursive searches over nested files, hidden files,
and `.ignore` rules. Also test `--files`, explicit files, no-match status 1,
and malformed-pattern status 2.

### 2. Stdin and output-file correctness

Add a `target_os = "motor"` implementation of `grep_cli::is_readable_stdin`.
Motor's standard `IsTerminal` implementation is descriptor-backed and works
for the console and SSH streams. A non-terminal Motor stdin is therefore
treated as readable, preserving the standard `rg PATTERN` pipeline behavior;
an explicit `-` remains available.

For output-file identity, add `moto-rt = 0.17.1` only to the Motor target
dependencies of `crates/ignore`. Use `moto_rt::fs::get_file_attr(FD_STDOUT)`
and `FileAttr::entry_id` to recognize a regular redirected stdout, and compare
it with `moto_rt::fs::stat(path).entry_id` before searching an entry. Reject
zero/unknown entry IDs. This avoids a stat on normal terminal or pipe output
and preserves ripgrep's protection against searching its own output without
adding a dependency to non-Motor builds.

Add focused tests for explicit stdin and implicit piped stdin. In the Motor VM,
verify stdin through a real pipe. The redirected-output regression requires the
OS follow-up: after `rt.vdso` reconstructs a regular `File` at child fd 1 and
`rush` passes redirection files through `Stdio`, append search output to a
matching file inside the searched tree and verify that ripgrep excludes it.

The proposed OS transfer snapshots the parent's generation-bearing `EntryId`,
current offset, access flags, and per-spawn alias key into private child
bootstrap data. The direct child constructs the existing `rt_fs::File` and
performs direct filesystem I/O, so ripgrep sees exact output identity. Parent
and direct-child offsets and lock owners are independent after spawn.

That snapshot alone is unsafe through a process chain: a direct child can
spawn sequential grandchildren, and repeated `STDIO_INHERIT` snapshots from
its unchanged offset can overwrite earlier output. The plan therefore makes
file-backed `STDIO_INHERIT` a bounded-buffer pipe relay through the process's
live `File`. The owner remains the offset authority for descendant writes.
Those descendants see pipes and retain the normal Motor inherited-stdio
parent-lifetime dependency; the directly transferred ripgrep process still
sees a real file. VDSO process wait/status also includes completion of that
child's file relays, so a shell cannot start the next sequential command while
the previous command's output is still waiting to reach the file. Finalization
has no artificial timeout: descendant lifetime cannot retain the immediate
pipe, but a stalled filesystem operation can still delay wait.

An inherited-file relay exclusively reserves its parent's open description
against ordinary position-dependent operations, which return
`E_ALREADY_IN_USE` instead of waiting for the child. Output relays may overlap
each other by reserving disjoint ranges, but an input relay excludes every
other relay. An input relay also treats the first source EOF as final, so nested
file-backed stdin is pipe-like and cannot follow later file growth. Fresh simple
`rush` file redirects take the direct route and retain regular-file behavior.
`rush` pipelines are unchanged,
including their existing non-streaming staging: in `producer | tail -f`, the
`tail` stage does not start until the producer exits. File relays use one
reusable 2 KiB buffer, equal to the stdio pipe ring, so no output batching
policy is needed.

`rush` also keeps its existing pipe-and-pump path for descriptors an immediate
compound, loop, function, builtin, or pipeline context can hand to multiple
commands. It uses direct `Stdio::from(File)` only for a fresh redirect on one
external or background command, which covers `rg PATTERN > file`. This is a
documented hybrid rather than a claim that all other forms have identical
metadata, timing, or inter-stream ordering. No `moto-io` or `sys-io` protocol
change is proposed; fully shared Linux-style open-file descriptions remain
deferred. `moto-rt` gains three parent-stream `STDIO_*` constants and no new
function, and Motor code in Rust `std` stays a thin wrapper over `moto-rt`
calls. The final compatibility stage also fixes `SelfStdio::close()` and the
standard library's stdout/stderr `Stdio` conversions.

### 3. Motor-native presentation paths

Treat Motor as a slash-path platform for ripgrep's default path color and
hyperlink path construction, without changing the target family. Construct a
hyperlink path by canonicalizing with `std`, requiring an absolute UTF-8 path,
and percent-encoding it with the existing encoder. Do not invent a hostname;
formats that require one retain the existing optional-host behavior or can use
`--hostname-bin`.

This removes the current unused-argument/dead-code warnings and makes forced
ANSI color and file hyperlinks behave consistently on Motor terminals. Add
pure tests around canonicalized slash paths and percent encoding where they
can be shared with other platforms, plus a Motor compile check for the target
branches.

### 4. Runtime acceptance for the standalone binary

Strip the release binary, transfer it to a four-CPU Motor VM over SFTP, and use
a deterministic fixture under `/sys/tmp` to cover:

- `rg --version` and feature reporting;
- default multi-threaded recursive matching;
- `.ignore` and hidden-file behavior;
- `--files` and an explicit single-file search;
- implicit piped stdin and explicit stdin;
- output modes such as count and JSON;
- forced color and OSC-8 hyperlinks; and
- success, no-match, and syntax-error exit statuses.

Create and remove only the fixture owned by this test. Do not add retries,
timeouts, or ignored failures. The assertions should compare deterministic
normalized output; use a single thread only where ordering itself is under
test, not as a workaround for parallel traversal.

Redirected-output identity is the acceptance test for the separate OS plan.
Once file-backed child stdio is implemented, add the `rush` regression described
in `stdio-file-fix-for-ripgrep.md` to `src/tests/full-test.sh`. Packaging,
Makefile targets, image contents, and automatic ripgrep installation remain
deferred until their source ownership and installed location are decided.

## Validation per patch

For changes in `../ripgrep`:

```sh
cargo +nightly fmt --all
cargo +nightly fmt --all -- --check
cargo test --workspace --locked
cargo test --workspace --locked --release
cargo +dev-x86_64-unknown-motor check -p ripgrep --locked \
  --target x86_64-unknown-motor
cargo +dev-x86_64-unknown-motor clippy -p ripgrep --locked \
  --target x86_64-unknown-motor -- -D warnings
cargo +dev-x86_64-unknown-motor build -p ripgrep --locked \
  --target x86_64-unknown-motor
cargo +dev-x86_64-unknown-motor build -p ripgrep --locked --release \
  --target x86_64-unknown-motor
```

Run focused VM acceptance tests after the ripgrep patches by transferring the
standalone binary; image integration is not part of this plan. Confirm that the
final code adds no compiler warnings and compare the stripped binary size with
the baseline. Strict Clippy diagnostics in untouched upstream crates should be
reported separately from diagnostics in changed files.

Before any commit containing the later Motor OS stdio implementation, run the
required suite three consecutive times in each configuration, diagnosing any
failure instead of masking it:

```sh
src/tests/full-test.sh
src/tests/full-test.sh
src/tests/full-test.sh
src/tests/full-test.sh --release
src/tests/full-test.sh --release
src/tests/full-test.sh --release
```

No commits are assumed; changes will remain local unless explicitly requested.
