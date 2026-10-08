# Review of non-Gears changes, 2026-10-07

This records the non-Gears findings from a read-only review of the `gears`
branch. Gears and gears-batteries findings are not included.

## Scope and method

The review compared `gears` against a stale local `main` (`a6a62912`,
2026-09-26) instead of `origin/main` (`6ef7737b`, 2026-10-01). It therefore
also covered the 97 commits in `a6a62912..6ef7737b` that are already on
`origin/main`. This document has two parts:

- **Part A**: code already on `origin/main` (`a6a62912..6ef7737b`): kernel,
  moto-ipc, rt.vdso, sys-io, moto-sys, frusa, rush, rmux, sysbox `diff`,
  `head` and `tail`, and test scripts.
- **Part B**: non-Gears code that exists only on the `gears` branch
  (`6ef7737b..gears`): sysbox `sort`, `uniq`, `cut`, `tr`, `xargs`, `mkdir -p`,
  `echo` and `nproc`, the utility-test harness, and the moto-rt `strlen`.

Nothing was built or run. Each finding is marked:

- **Verified**: re-read in the code and confirmed during the review.
- **Reported**: found by a reviewing agent reading the code; not
  independently re-checked.

## Part A: code already on `origin/main`

### Overall

The core security design holds up:

- **`CAP_FS_WRITE` is enforced server-side.** sys-io denies any command
  outside the `is_read_command` whitelist, so rename, unlink, mkdir,
  setperm, copy-range and locks are all covered. The rt.vdso open check
  only reports the error earlier.
- **Children cannot gain `CAP_NET` or `CAP_FS_WRITE`.** The kernel requires
  every parent, System included, to hold a bit before granting it.
- **The kernel listener rework looks race-free**
  (`Service { owner, endpoints, pending }`):
  - the owner check is `Weak` pointer equality, not pid;
  - requeue drops the reference after unlocking;
  - `dup_object` does lookup and insert under one lock.
- **The DNS resolver checks `CAP_NET`** (`dns-resolver/src/main.rs:112`), and
  rmux checks peer masks. No other service was found that acts on a
  caller's behalf without these capabilities.

The problems are one real regression, a few robustness gaps, and several
places where the mechanism is heavier than its purpose needs.

### A1. Busy sys-io fails connects instead of retrying (high, verified)

**Change.** Commit `c4de82bb` ("Distinguish busy IPC services from absent rmux
servers") changed `src/sys/kernel/src/uspace/shared.rs` `get()`:

- **Before:** an empty listener list removed the URL and returned
  `E_NOT_FOUND`.
- **Now:** a live service whose listener pool is exhausted returns
  `E_NOT_READY` (around line 230: `pending.first_key_value()` → `E_NOT_READY`).

**Clients not updated.** Several clients only treat `NotFound` as transient:

- `src/sys/lib/moto-io/src/net/channel.rs:127-135`: `connect()` retries
  `NotFound` through `ConnectBackoff` (10 s budget). Any other error,
  `NotReady` included, is returned at once (`Err(err) => return Err(err)`).
- `src/sys/lib/moto-dns/src/lib.rs:272` maps only `E_BAD_HANDLE` and
  `E_NOT_FOUND` to `ClientError::ServiceUnavailable`.
- `src/sys/lib/rt.vdso/src/rt_fs.rs:234-235`: `AsyncFsClient::create` calls
  `FsClient::connect()` with no retry at all. This was true before as well,
  but the error is now more reachable.

**Failure.** sys-io keeps 8 listeners each for FS (`sys-io/src/runtime/fs.rs:406`)
and net (`sys-io/src/runtime/net.rs:202`). Suppose more than 8 processes or
channels connect at once, faster than sys-io refills its pool. The extra
connects fail socket creation (or the DNS lookup) instead of backing off.

**Evidence the change was already observed.** The same commit had to widen
`src/sys/tests/systest/src/tcp.rs` `read_sys_io_metric` to accept
`E_NOT_FOUND | E_NOT_READY`, after a debug full-test failed with error 3. That
diagnosis is in `docs/plans/ipc-rmux-issues.md`, "Finding 2". The test helper
was updated; the production clients above were not.

**Fix.**
- Treat `NotReady` like `NotFound` in `ConnectBackoff` (about 2 lines).
- Map `E_NOT_READY` to `ServiceUnavailable` in moto-dns.
- Decide whether `AsyncFsClient::create` should back off the same way.
- Audit the other `shared:` and `io_channel` connect sites for the same
  assumption.

### A2. An exported `MOTOR_OS_CAPS` makes rush refuse every in-process command (medium, verified)

**Code.**
- `src/bin/rush/src/jobs.rs:91`: `has_explicit_env` returns true if the key
  is in the prefix assignments **or** in the process environment
  (`std::env::var_os`).
- `src/bin/rush/src/exec.rs:427` `refuse_inproc_caps` and `:398`
  `launches_child`: refuse any command that would run in-process while that
  holds.

**Failure.** After `export MOTOR_OS_CAPS=0x44`, rush refuses with status 126:
- `echo`, `exit`, `return`, `break`, `continue`, `wait`, `trap`;
- `unset MOTOR_OS_CAPS` itself;
- `if`/`for`/`while`, `{ … }`, subshells, functions, `.` and `eval`.

An interactive user cannot recover except by exiting the shell, and even
`exit` is refused. `src/tests/test-rush-script-caps.sh:126-170` (the
`exported` mode) asserts exactly this behaviour.

**Why a narrower rule is enough.** The property that matters is that an
*assigned* mask never runs in-process: `MOTOR_OS_CAPS=x builtin`, `… function`,
`… . script`. rt.vdso already strips the key from a spawned child's
environment (`src/sys/lib/rt.vdso/src/rt_process.rs:684`). So a rush started as
`MOTOR_OS_CAPS=x rush` does not see it, and an exported value reaches
children through normal environment inheritance.

**Proposal.**
- Keep the refusal for prefix assignments only.
- Let an export apply to spawned children only.
- To restrict the shell itself, start it with the mask.

This removes the `std::env` check in `has_explicit_env` and the `exported`
half of the test matrix. If the current behaviour is intentional, document
the recovery path, because today there is none.

### A3. The IPC client still asserts on values the server writes (low-medium, verified)

**Code.** `src/sys/lib/moto-ipc/src/sync.rs` `do_rpc`:
- line 290: `assert_eq!(seq, self.seq)`, after `fetch_add` on the request
  page, which is shared with the server;
- line 291: `assert_eq!(seq & 1, 0)`;
- line 307: `assert_eq!(self.seq, seq)` on the response page.

**Failure.** A buggy or hostile server that writes those pages can panic its
client. An earlier commit (`fa957693`) made the server side tolerant; the
client side was not changed.

**Exposure.** It is small now that rmux checks the server's capability mask
before connecting.

**Fix.** Return an error and disconnect instead of asserting, as
`finish_rpc_deferred` does.

### A4. The TLS destructor loop is unbounded (low, verified)

**Code.** `src/sys/lib/rt.vdso/src/rt_tls.rs:180`: `while run_dtor_round() {}`.

**Failure.** A destructor that always sets its own key again hangs thread
exit. The previous loop had the same flaw.

**Caution.** std's cleanup guard defers itself to a later round, and runs
only in a round where no other destructor of its runtime ran (see the
comment at `rt_tls.rs:172-176`). POSIX's `PTHREAD_DESTRUCTOR_ITERATIONS` (4)
may therefore be too tight. Pick a cap that leaves that guard room (or
exempt it), then `clear()` and log.

**Side note.** `next_with_dtor` takes the KEYS lock and rescans for every key,
which is O(n²). That is fine at current sizes.

### A5. sys-io FS write gate and `CMD_FLUSH` (low, verified)

**Code.**
- `src/sys/sys-io/src/runtime/fs.rs:569`:
  `if !can_write && api_fs::known_cmd(msg.command) && !api_fs::is_read_command(msg.command)`.
  An unknown command passes the gate and relies on dispatch to reject it.
  Gating on `!can_write && !is_read_command(cmd)` denies it up front.
- `CMD_FLUSH` (`moto-sys-io/src/api_fs.rs:20`) is not a read command. A
  global flush writes no data on the caller's behalf, and a read-only client
  can already load sys-io with reads.

**Proposal.** Classify `CMD_FLUSH` as read-only and remove:
- the rt.vdso special case for read-only flushes (`rt_fs.rs`, around the
  flush path);
- its paragraph in `docs/caps.md`.

### A6. Inherited file-backed stdio writes with the parent's authority (known, documented)

A child that inherits a file-backed stdio stream writes through the parent's
relay, so the write uses the parent's `CAP_FS_WRITE`. `docs/caps.md`
("Network and filesystem-write access") already says this. It is acceptable
today, but the later confinement design should list it explicitly.

### A7. Stdio peek could be avoided (simplification, reported)

**Code.** About 100 lines of core code:
- `moto-ipc/src/stdio_pipe.rs` `nonblocking_peek`;
- `rt.vdso/src/stdio.rs` `peek` and `try_with_impl`;
- the `posix.rs` trait method;
- the non-socket dispatch at `rt_net.rs:399`.

Plus about 530 lines of tests: systest `stdio_peek.rs` (381 lines) and
probably part of `stdio_terminal.rs`.

**Purpose.** Peek exists so that rush can read stdin one line at a time on
Motor OS without taking the next command's bytes. On the Unix host, rush
already reads one byte at a time (`src/bin/rush/src/sys/unix.rs`), as bash
and dash do on pipes.

**Proposal.** Use the same path on Motor OS. This removes a new rt.vdso ABI
behaviour (`peek` on a non-socket fd). The cost is per-byte ring reads, only
when rush itself reads its stdin. Measure before deciding.

### A8. moto-ipc's `retired` name reservation looks redundant (simplification, partly verified)

**Code.** `src/sys/lib/moto-ipc/src/sync.rs`:
- `retire` (line 389);
- the `retired` field (line 582);
- `release_retired` (line 626);
- `Drop for LocalServer`, and the deferred `disconnect`.

That is about 45 lines plus host-test cases.

**Purpose.** It keeps one dead endpoint open so the service name survives
when every listener is gone and a refill fails for lack of memory.

**Why it may be unnecessary.**
- The only consumer that cares is rmux.
- rmux's client already rejects a name squatter by checking that the
  server's capabilities equal the expected profile (`rmux/src/sys/ipc.rs`
  `open()`).
- A squatter with the same mask gains nothing.
- The mechanism also changes behaviour for every `LocalServer` user:
  handles now outlive `disconnect()` until the next `wait()`.

**Proposal.** Restore the immediate `SysObj::put` in `disconnect()` and keep
only the 100 ms refill retry.

### A9. The rmux IPC transport is heavy (simplification, reported, moderate confidence)

**Code.** `src/bin/rmux/src/sys/ipc.rs` (687 lines) and
`src/bin/rmux/src/bin/rmux-probe.rs` (422 lines).

**What is justified.** The peer-capability check: loopback TCP cannot
authenticate the peer, and a cookie would authenticate a role, not a mask.

**What makes it heavy.** `moto_ipc::sync` is request/response only, which
forces:
- two connections per client, with a token to pair them;
- long-polled output and forwarder threads;
- a doorbell IPC pair;
- frame reassembly.

**Proposals.**
- **Transport.** A bidirectional `moto_ipc::io_channel` gives one connection
  with the same `remote_handle()` capability query. That would plausibly
  remove the pairing, outboxes and forwarders: roughly 200–300 lines. The
  caveat is that rmux is thread-based and `io_channel` is async.
- **Probe.** `rmux-probe` is test-only. Its `closing`, `parallel` and
  `saturate` modes duplicate behaviour the real client already exercises.
  Trimming them saves about 150–200 lines.

### A10. sysbox `diff` ports GNU's tie-breaking (simplification, partly verified)

**Code.** `src/sys/tools/sysbox/src/commands/diff.rs` (945 lines) plus
`diff/analyze.rs` (572 lines).

The output is correct. It has GNU's `too_expensive` cost cap
(`analyze.rs:229-258`, `387`), and its hunk grouping and range formats match
GNU. But it ports GNU's `analyze.c`/`diffseq.h` step by step, so that ties
between equally short edit scripts resolve exactly as GNU's do. Any minimal
diff is valid output.

**Keep:**
- the Myers search;
- `too_expensive`;
- `shift_boundaries` (`analyze.rs:460`), which makes hunks read better;
- `-u`, `-q`, `-r`, `-b/-w/-i`;
- exit statuses 0/1/2.

**Candidates to drop:**

| Item | Lines |
|---|---|
| `discard_confusing_lines` (`analyze.rs:73`) and its provisional-run logic | ~130 |
| The context format `-c`/`-C` (`Format::Context`, `diff.rs:55`, `:143`, `:168`, `:600`) | ~70 |
| `--label` and `-N`/`--new-file` (`diff.rs:32`, `:243`) | ~50 |
| The tie-breaking test fixtures `discard1` and `horizon1` | ~40 |

About 300 lines in total, with no loss for normal use.

### A11. sysbox has no shared helper module (simplification, partly verified)

- `strerror` lives in `commands/wc.rs`; the other commands import it from
  there.
- The Motor OS workaround that maps a directory open to an "is a directory"
  error is repeated across `cp`, `cut`, `diff`, `head`, `rm`, `sort`, `uniq`
  and `wc`. Part of this predates the reviewed commits.
- Each command has its own option parser: `diff`, `head` (shared with
  `tail`), and in Part B `sort`, `uniq`, `cut`, `tr`, `xargs`, `mkdir` and
  `echo`. Error wording differs:
  - `head` and `diff`: `invalid option -- 'x'`;
  - the newer commands: `unsupported option '-x'`.

**Proposal.** Add `commands/common.rs` with:
- `strerror`;
- the directory mapping;
- a shared write-failure handler that stays quiet on a broken pipe (fixes
  B1);
- a parser of about 60 lines that handles `--`, a lone `-`, `--name[=v]`,
  short-option clusters, and values attached or in the following argument.

Expected saving: about 200–250 lines, plus consistent errors.

### A12. `head`/`tail` structure (simplification, verified)

**Code.** `src/sys/tools/sysbox/src/commands/head.rs` (587 lines) is not
really bloated. About 250 of its lines are plumbing shared with `tail.rs`.

**Proposals.**
- Move the shared plumbing to `head_tail.rs`.
- Replace the `Command` struct's function-pointer fields
  (`parse_obsolete`, `misplaced_digit`, `head.rs:72-74`, used at `:112-113`
  and `:157`) with `enum { Head, Tail }`. That saves about 20 lines and
  reads more clearly.

### A13. `full-test.sh` leaks rmux coprocesses on failure (medium, verified)

**Code.** `src/tests/full-test.sh` starts coprocesses at:

| Line | Coprocess |
|---|---|
| 986 | `RMUX_TITLE_CLIENT` |
| 1079 | `RMUX_HANGUP_CLIENT` |
| 1189 | `RMUX_SILENT` |
| 1201 | `RMUX_FULL` |
| 1224 | `RMUX_HALF` |

`cleanup_full_test` (line 523) closes only the `RMUX_TITLE` descriptors, and
kills only `RMUX_TITLE_SSH_PID` and `DNS_RESOLVER_SSH_PID`.

**Failure.** Any `fail` between starting one of the other four coprocesses and
its `wait` leaves a host `ssh` running in the suite's process group. One
such `fail` is "rmux pool did not fill".

**Fix.**
- **Minimal:** record every coprocess PID in a list that cleanup kills.
- **Better:** move the ~220-line rmux block into a sourced
  `test-rmux-caps.sh` with its own cleanup, like the other `test-*.sh`
  scripts.

### A14. Test-runner meta-test and duplicated option parsers (simplification, reported)

**`src/tests/test-full-test-size.sh`** (85 lines upstream, +3 on the branch):
- It tests the runners' own `--cpus`/`--memory` parsing on every full-test
  run.
- It hard-codes `full-test-dev.sh`'s phase sequence and stubs, so it breaks
  whenever a phase is added.

**`full-test.sh` and `full-test-dev.sh`** each carry a near-identical option
parser of about 40 lines.

**Proposal.** Source one shared parser, and delete the meta-test or cut it to
3–4 cases. That saves about 100 lines.

### A15. New inline Python in `test-crossterm-host.sh` (low, verified)

`src/tests/test-crossterm-host.sh:42` uses `python3 -c` to parse JSON. This
goes against the repository's preference for no new Python. A Rust helper,
or plain string comparison or `grep -F` on the expected output, avoids it.

### A16. `capabilities.html` (note, reported)

`img_files/motor-os-dev/devtools/www/capabilities.html` is 767 lines:
- about 365 lines of reasonable content that follows the existing
  `devtools/www` convention;
- about 400 lines of the inlined CSS and navigation that every page repeats.

The `www` pages total about 16.8k lines, and adding one navigation link
touched about 25 pages. The duplication is a pre-existing, site-wide
problem; a shared stylesheet and navigation include would fix it
separately.

## Part B: non-Gears code only on the `gears` branch

### B1. New sysbox commands fail noisily on a broken pipe (medium, verified)

**Correct pattern.** Only `head`, `tail` and `diff` stay quiet on `BrokenPipe`
(`head.rs:438`). The new commands print an error and exit non-zero:

| Command | Location | Message | Exit |
|---|---|---|---|
| `sort` | `sort.rs:227`, `:255` | `write failed: …` | 2 |
| `uniq` | `uniq.rs:94` | `write error: …` | 1 |
| `cut` | `cut.rs:235`, `:249`, `:288` | `write error: …` | non-zero |
| `tr` | `tr.rs:144`, `:148` | `write error: …` | non-zero |
| `echo` | (reported) | write error | non-zero |

**Failure.** `sort big.txt | head -1` or `cat log | tr a b | head` puts
`Broken pipe` errors on stderr and gives a failure status. Motor OS has no
SIGPIPE, so the error always surfaces.

**Fix.** One shared write-failure handler (see A11), used by every command.

### B2. xargs edge cases (low, reported)

In `src/sys/tools/sysbox/src/commands/xargs_tokens.rs`, near the end of
`arguments`:

- **Unterminated empty quote.** `printf "'" | xargs` succeeds; GNU fails with
  "unmatched single quote".
- **Empty quoted argument.** It is kept before a newline but dropped at end of
  input: `''\n` passes an empty argument, while `''` passes nothing.
- **`-I` in the command name.** `-I` never substitutes into the command name
  (`literal = index == 0`). GNU does, so `xargs -I{} {}` behaves differently.
  Moderate confidence.

### B3. Small sysbox items (low)

- **`nproc` wrapper (verified).** `img_files/motor-os-base/system/bin/nproc`
  (added in `84e87a78`) passes `$@` unquoted. The other new wrappers quote
  it.
- **`sort -hf` (reported).** It upper-cases size suffixes, so `1m` sorts as
  mega. GNU does not fold suffixes.
- **`tr` (reported).** `tr.rs` detects "ends with a class" with
  `offset + 26 == second.bytes.len()`. That works only because just
  `[:upper:]`/`[:lower:]` are supported; checking the class name directly
  is clearer.
- **`cut -d '\n'` (reported).** The special case reads the whole input to
  match GNU in a case agents rarely hit (about 20 lines). It can be dropped.

### B4. Weak `strlen` in moto-rt needs vetting (process, verified)

`src/sys/lib/moto-rt/src/libc.rs` gains a weak `strlen` (16 lines), with a
systest in `src/sys/tests/systest/src/strlen.rs`. It is the only branch
change under `src/sys` outside sysbox and systest.

AGENTS.md note (4) requires moto-rt changes to be discussed and vetted.
Editing moto-rt also stales the pinned toolchain assembly. The progress
notes say it fixes a native release link failure ("missing runtime
`strlen`"); that rationale should be reviewed on its own.

### B5. Two parallel sysbox test harnesses (simplification, reported)

There are two harnesses:
- **systest:** `sysbox_{head,tail,diff}.rs` (upstream) and
  `sysbox_{sort,mkdir}.rs` (branch), about 1,470 lines;
- **`sysbox/examples/utility-tests*`** (branch), about 860 lines.

`sort` is tested in both.

The filter for runtime log records exists in four copies with two meanings:
- the loose `messages()` in the head, tail and diff tests;
- the strict `runtime_debug()` in utility-tests.

The split follows the 2026-10-06 scope rule of no further systest changes.

**Proposals.**
- A shared test-helper module would save about 150 lines; merging into one
  harness later would save more.
- `full-test.sh` uploads `sysbox-utility-tests` with its own `sftp` call. It
  could join the existing batch upload.

## Rough savings

| Area | Lines |
|---|---|
| sysbox `diff` (A10) | ~300 |
| sysbox shared helpers and parser (A11, B1) | ~200–250 |
| `head`/`tail` enum (A12) | ~20 |
| sysbox test helpers (B5) | ~150 |
| Stdio peek (A7) | ~100 core + ~530 tests |
| moto-ipc `retired` (A8) | ~45 + tests |
| rmux transport and probe (A9) | ~350–500 |
| Rush exported-mask policy (A2) | test matrix halves |
| Test-runner parser and meta-test (A14) | ~100 |

## Suggested order

1. Fix A1 (connect `NotReady`) and A13 (coprocess cleanup); both are small.
2. Decide A2 (rush exported mask), then fix B1 (broken pipe) with the shared
   helper from A11.
3. Fix A3 and A4.
4. Vet B4 (moto-rt `strlen`) explicitly.
5. Take the simplifications (A7–A12, A14, B5) as separate patches, each gated
   by the usual full-test runs.
