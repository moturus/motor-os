# Fix `ls *.md`

Status: proposed for review. This document records the recommendation; no
implementation or commits are authorized by the documentation request.

## Diagnosis

Rush already implements pathname expansion in
[`expand::to_fields`](../../src/bin/rush/src/expand.rs) and
[`glob`](../../src/bin/rush/src/glob.rs). It expands unquoted patterns, preserves
quoted wildcard characters, and leaves unmatched patterns literal.

The current [`sysbox ls`](../../src/sys/tools/sysbox/src/commands/ls.rs) accepts
only one operand. A second operand causes a usage error, so a successful glob
expansion can produce the reported failure:

```text
ls *.md -> ls a.md b.md -> usage error
```

Two related argument-preservation defects also need attention:

- The packaged [`ls` wrapper](../../img_files/motor-os-base/system/bin/ls)
  forwards arguments with unquoted `$@`. This splits filenames containing
  spaces and performs another glob expansion on literal wildcard characters.
- Sysbox trims each argument and skips empty or whitespace-only arguments.
  This changes filenames and can turn an explicit empty operand into an
  unintended listing of the current directory.

The existing rush test passed on the host during investigation:

```sh
cd src/bin/rush
cargo test --offline --locked --release --test phase3 pathname_expansion -- --exact
```

A host invocation also confirmed that unquoted `$@` splits a space-containing
argument and expands a literal `*.md`, while `"$@"` preserves both. The user's
exact VM failure has not been reproduced; the multiple-operand rejection is
established from the current source.

## Recommendation

Keep pathname expansion in rush. Extend sysbox's `ls` to accept multiple
operands and preserve arguments throughout the wrapper and utility.

The wrapper should forward arguments as:

```sh
/system/bin/sysbox ls "$@"
```

The proposed behavior is:

- Accept `ls [-lh] [--] [FILE ...]`, with `.` as the default only when no
  operands were supplied. Preserve the existing options and `--` delimiter.
- Preserve every operand exactly, including spaces and wildcard characters.
  An empty operand is an operand error; parse it without indexing an empty
  string or silently discarding it.
- List file operands themselves. List directory operands' contents.
- Group file operands first, sorted by the existing string ordering. Process
  directory operands in that ordering, retaining the existing directories-first
  ordering within each directory listing.
- When more than one operand was supplied, prefix each directory listing with
  its operand and a colon. Separate output groups with a blank line. Preserve
  the current presentation for a single operand and for the default `.`.
- Apply `-l` and `-h` consistently to every operand. Align detailed output
  within each group: the file-operand group or an individual directory listing.
- Report inaccessible operands on stderr, continue with other accessible
  operands, and return status 2 if any operand could not be listed. Keep status
  1 for invalid command-line options and status 0 for successful listings.

An unmatched `*.md` remains a literal operand and normally produces status 2.
Quoted patterns and `set -f` retain their existing shell meaning. Sysbox must
not perform an additional wildcard expansion.

## Alternatives considered

| Approach | Benefit | Cost or limitation |
| --- | --- | --- |
| Multiple operands in sysbox; globbing in rush | Fixes both wildcard commands and explicit `ls a.md b.md`; preserves shell quoting semantics. | Requires grouped output and accumulated error status. Recommended. |
| Loop over operands in the wrapper | Small temporary workaround for the single-operand utility. | Starts sysbox for each operand and complicates option forwarding, formatting, and exit status. |
| Expand wildcards inside sysbox | Could support callers that bypass a shell. | Quote information is already lost, so automatic expansion reinterprets literal filenames. Multiple-operand support is still necessary. A new explicit `--glob` option could avoid ambiguity, but is unnecessary here. |

## Scope and incremental work

Use standard Rust and existing Motor OS APIs. The implementation belongs in
sysbox's own source under `src/sys/tools/sysbox`; this is the utility rejecting
the expanded arguments. No kernel, runtime, Rust stdlib, external repository,
new dependency, or rush expansion change is needed. No boot-time work is added.

Keep implementation patches around 100–300 lines including tests:

1. Preserve operands: quote the wrapper's `"$@"`, remove argument trimming and
   skipping in `ls`, and add focused regressions for spaces, empty operands,
   and literal wildcard characters.
2. Support multiple operands: collect operands, group file and directory output,
   and accumulate errors instead of exiting on the first inaccessible operand.
   Extend direct sysbox tests for files, directories, and mixed success/failure.
3. Add the complete rush → packaged wrapper → sysbox regression coverage to
   `src/tests/full-test.sh` or a script it sources. Split the preceding work
   further if necessary to keep patches reviewable.

Commit policy is not decided by this plan; the current request creates only
this document. Implementation should begin only after review.

## Validation

Extend [`sysbox_ls.rs`](../../src/sys/tests/systest/src/sysbox_ls.rs), which is
already called by systest and included transitively in
[`full-test.sh`](../../src/tests/full-test.sh). Run direct utility checks inside
Motor OS and exercise the packaged wrapper through rush as well.

Use temporary local fixtures covering:

- Zero, one, and several glob matches, with deterministic output assertions.
- Several explicit file operands, several directories, and mixed file/directory
  operands; check headings, ordering, and plain, `-l`, and `-lh` output.
- Filenames containing embedded, leading, and trailing spaces, a whitespace-only
  filename, and an explicit empty operand. Compare exact names rather than
  splitting output on whitespace.
- Quoted and escaped wildcard characters, including a literal wildcard filename
  alongside other names that would match it as a pattern.
- `set -f`, unmatched patterns, and leading-dot exclusion during globbing.
- `--` followed by option-looking filenames, and missing operands before and
  after valid operands. Verify continued output, stderr, and final status.

Do not add network-dependent fixtures. Format Rust changes with `cargo fmt`
using the repository-selected toolchain and introduce no compiler or clippy
warnings. Because the implementation touches `src/sys`, the repository gate
requires `src/tests/full-test.sh` to pass consistently at least three times in
debug and three times with `--release` before committing each applicable patch.
Diagnose failures rather than masking them with retries or weaker assertions.
