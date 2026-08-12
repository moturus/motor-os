# Making Lorry smaller and faster to change

Status: implementation tracker. Updated through the parallel-executor work,
the 2026-08-09 native-link repair, the final diagnosis and fix of the native
rustc hang, and the frame-slab reservation fix exposed by the two-generation
native gate, and the TCP teardown fixes exposed by curl. The work remains
uncommitted at the user's request.

This note analyzes why the dependency-upgrade change was large and why the
Lorry-local verification gate historically took hours. It proposes
alternatives that keep Lorry reproducible, offline at build time, and
fail-closed while making normal dependency upgrades and development practical.

Some analysis below describes the harness before the completed work. Those
sections are retained as the baseline and are labeled historical. The status
here and the numbered work list at the end are authoritative.

## Implementation status

Completed:

- Every local and native phase records machine-readable and console timing.
- Tests under `src/bin/lorry` build only Lorry and its dependencies. Red,
  Rush, curl, the synthetic Stage-1 package, and downstream second-generation
  tests are owned by `src/tests/lorry-integration-test.sh`.
- crates.io and GitHub acquisition tests are fail-closed and use local Cargo
  caches. The curl protocol tests use a repository-local TLS fixture; none of
  these tests has an Internet fallback.
- Stage-1 artifact identity is a same-environment byte comparison between
  Lorry and Cargo, including native, cross-Motor, test-harness, self-build,
  and second-generation outputs. It no longer pins compiler-specific artifact
  digests or hash-derived executable names.
- Ordinary Lorry-local debug and release artifacts run in a release Motor OS
  VM. Debug image coverage remains in the repository integration gate.
- Fast, acceptance, and exhaustive verification have separate entry points.
  The fast gate orders both profiles' host checks before native work and has a
  warm mode that preserves separate host and guest targets. It executes both
  cross-built profiles but reserves the native self-build and byte comparison
  for release. Acceptance adds one release downstream/native smoke campaign;
  exhaustive retains the clean repeated and second-generation campaigns.
  Changed paths select these gates mechanically.
- The Lorry-local native self-gate builds, runs, and tests one compact Motor
  fixture covering a library, binary, integration test, admitted build script,
  Motor-only path dependency, and reviewed registry dependency.
- Native rustc and Lorry self-builds work with captured non-PTY output again.
  The fix is descriptor-wide `fstat` metadata in the VDSO and mlibc, not a
  Lorry or LLVM exception: stdio pipes report FIFO, terminals report character
  device, and sockets report socket. Because native LLVM is static, its mlibc
  and C-ABI shim had to be relinked into the multicall binary. The native
  self-build and repository-integration harnesses also name
  `motor-os-dev.img` explicitly; their previous run-script default was the
  intentionally Lorry-free main image.
- The intermittent native rustc hang is fixed. It was not an
  `rt::io_runtime` lost-wakeup livelock: `ReadDir` retained a prefetched
  directory ID after the entry was concurrently removed, returned the same
  error forever, and rustc intentionally discarded each per-entry error.
  The cursor is now consumed before the lookup, so that error is reported once
  and the stream is then exhausted. A deterministic systest deletes the
  prefetched next entry and verifies exactly that behavior.
- The two-generation native gate exposed a second frame-slab race at the full
  boundary (`slab alloc looping (1)`). Allocation now reserves `used`
  capacity before claiming a bitmap slot, while free publishes the cleared
  bitmap before releasing capacity. The strengthened frame-churn systest and
  the exact two-generation gate pass with the fix.
- The exact Motor curl gate no longer pays one 60-second linger interval.
  Process exit now joins the compatibility network runtimes that deliver
  queued close records, and sys-io resets a fully closed, lingering TCP socket
  if peer data arrives after its receive half was closed. The latter preserves
  `shutdown(Read)` half-close semantics. Focused process-exit and post-FIN
  write regressions cover the two boundaries; the 10-case curl gate fell from
  61.57 s to 4.09 s.
- The isolated registry-cache campaign once again boots its intended minimal
  seed image. Its manifest now names `motor-os.img` explicitly instead of
  inheriting the repository-wide `motor-os-dev.img` default; a bootstrap unit
  test pins that contract.
- Compact format-2 admission is active. Build, run, and test require an exact
  reviewed `(host, target)` context and verify the reconstructed review
  commitment for every recorded context before any generated allow rule
  exists; vendoring builds the candidate review and writes
  `.lorry/dependencies-v2.toml` last after publication; the upgrade journal
  commits it last. The committed Lorry and native-fixture states record the
  four exercised contexts with identities, evidence, and capabilities proven
  equal to the format-1 baseline, and every format-1 parser, fixture, and
  path reference is deleted. The repository integration policy renderer
  derives rules from lockfiles, compact capabilities, and verified repository
  evidence.

Remaining:

- bring both repository integration campaigns to thirty minutes combined (see
  "Thirty-minute integration campaigns" below);
- add the offline `lorry review` command and the paired changed-item approval
  display, then implement vendoring reconciliation, upgrade-core deletion, and
  derived bootstrap-state work described below.

Next step: **thirty-minute integration campaigns**. The parallel executor,
native rustc,
ordinary native self-gates, two-generation native self-gate, and repository
native integration gate now pass. The remaining campaign work is to implement
the concurrency and scope milestones below and measure them against the
thirty-minute target. An independent `sys-tty` EOF busy-wait still burns a
full core in every campaign and is described below.

## Thirty-minute integration campaigns

Target: the two repository integration campaigns
(`lorry-integration-test.sh --exhaustive` and `--release --exhaustive`)
complete in at most thirty minutes of combined wall clock.

Measured baseline (passing exhaustive run, 2026-08-07): the debug campaign's
native phases alone take 4,832 s (image build 68.7 s, host preparation
237.7 s, input staging 90.9 s, smoke gate 1,397.4 s, full gate 3,035.5 s),
the release campaign's take 1,057 s, and each campaign additionally re-runs
its host suite and a Motor registry-cache campaign that builds a dedicated
image, boots a second VM, and rebuilds release curl natively. Combined wall
clock is roughly two and a quarter hours — about 4.5× the target.

Where the time goes and the planned levers, in order:

1. **Per-command native timing.** The harness times phases, not commands, so
   the split of the 3,035 s debug full gate between the two Lorry
   generations and the downstream rebuilds is invisible. Record a duration
   for every `native_command` in `timings.tsv`. Evidence first; this also
   permanently improves failure triage.
2. **Parallel crate compilation in Lorry.** `compile.rs` runs every rustc
   invocation sequentially; the campaign VM has four idle-most-of-the-time
   vCPUs and the host has sixteen. Compile independent plan units
   concurrently in dependency order with per-unit captured diagnostics
   printed atomically on completion. Artifacts are byte-identical by
   construction (each rustc writes disjoint outputs); only wall clock
   changes. This speeds every gate, native and host, and is the largest
   single lever for the 1,400–3,000 s compile-dominated native phases.
3. **Concurrent campaigns.** The two campaigns are independent but run
   sequentially and would collide on the fixed tap interface, guest address,
   and forwarded SSH port. Parametrize the VM network lane (user-mode
   networking with a per-campaign host port, as the registry-cache script
   already uses), then run both campaigns concurrently from
   `test-exhaustive.sh`: combined wall clock becomes the slower campaign,
   not the sum. Sixteen host cores hold two four-to-six vCPU VMs plus host
   preparation comfortably.
4. **Debug-campaign scope.** The debug-image campaign repeats the entire
   release workload — two Lorry generations, three Red builds, a native
   release-curl rebuild — at the debug image's roughly 5× execution cost.
   Debug-image coverage exists to exercise OS debug assertions under real
   native workloads, and one pass of each flow does that: vendoring, builds,
   tests, and a single native Lorry self-build. Keep two-generation
   reproducibility, byte identity, and the native curl rebuild on the
   release campaign, which is the shipped configuration. This is a
   deliberate scope decision, not a timeout: nothing is retried, ignored,
   or run with a longer budget.
5. **VM sizing.** Once compilation parallelizes, raise the campaign VMs'
   vCPU count (`MOTO_SMP`) from the default four and re-measure. **Unblocked
   on 2026-08-08:** an earlier measurement put the guest's limit at six
   vCPUs, but that was a harness artifact (see "Guest sizing"); re-measured,
   eight vCPUs passes at the four-vCPU baseline. The width-independent
   intermittent hang found during that measurement is now fixed; sizing can
   therefore be evaluated solely on measured runtime and memory headroom.

Milestones: land instrumentation (1) and re-measure; land (2) and re-measure
both campaigns; land (3) and (4) together with the scope rationale recorded
here; adjust (5) last. Stop and re-plan if any milestone's measurement
contradicts the analysis above.

Measured after milestones 1 and 2 (2026-08-08): parallel unit execution cut
the cold host self-build from 34.0 s to 20.0 s with byte-identical
artifacts, and the debug campaign's native gates from 1,397.4 s to
1,242.9 s (smoke) and 3,035.5 s to 2,221.5 s (full). Per-command timing
attributes the remaining full gate to the two native Lorry generations
(726.4 s and 747.9 s) and the second-generation Red, Rush, and simple
rebuilds (roughly 640 s combined); the smoke gate is dominated by the Red
and Rush build/test matrix. Parallel compilation changed VM sizing: four
concurrent release-profile rustc invocations exhausted the dedicated
registry-cache VM's previous 1024M — its curl link then failed to spawn
`ld.lld` with a misleading `posix_spawn ... Invalid argument`. Eight-vCPU
8192M VMs were then directed for all Lorry-test VMs — the extra width both
speeds the compile-dominated phases and deliberately widens the OS
concurrency surface, with new failure modes treated as findings, not
regressions to size away. That sizing appeared to expose a guest concurrency
ceiling; it did not, and the finding was withdrawn once the harness defect
behind it was found. See "Guest sizing" below for the re-measurement and for
why the harness still defaults to four vCPUs pending a confirming run.
Concurrency note
for milestone 3: the registry-cache campaign already uses user-mode
networking on a distinct port, so it can run concurrently with the
tap-networked native campaign within each build profile without any lane
changes; cross-profile concurrency still needs the parametrized lane.

### Guest sizing, and the hang underneath it (re-measured 2026-08-08)

The original frame-allocator panic is fixed. An uncommitted kernel change replaces
`Slab4096`'s head-walked slab chain with a partial-slab list (O(1) head peek,
membership under a leaf `list_lock`), and the
`kernel/src/mm/slab.rs:288 slab alloc looping (2)` panic did not recur in any
run below.

**An earlier revision of this section reported a guest concurrency ceiling
that rose with vCPU count. That finding was a harness artifact and is
withdrawn.** `src/vm_scripts/run-qemu.sh` ended with
`$TASKSET qemu-system-x86_64 ...` rather than `exec`, so `/bin/sh` (dash)
forked qemu as a child. Every harness here backgrounds that script and kills
`"$!"` on the way out, which killed only the wrapper: qemu was orphaned to
init and kept holding `moto-tap`, so it went on answering ssh on
192.168.4.2. A run whose guest-side `shutdown` misses its 3 s timeout
therefore leaks a live VM — and a *slow* guest is exactly the guest that
misses that timeout. The next run's ssh then reaches the stale VM, which is
also still compiling, so one slow run cascades into every run after it. That
is the shape the old table actually recorded: 8-vCPU gates degrading
monotonically in run order (175.6 → 374.6 → 854.1 → 855.1 s) while 4-vCPU
runs interleaved between them stayed at ~175 s. Two of those numbers landing
within one second of each other was the tell; contention does not repeat to
the second.

Both are fixed, with the sizing re-measured on the repaired harness. Six runs,
each bracketed by an explicit check that nothing answered on the tap before
the run and nothing survived it:

| Guest | Gate outcome |
|---|---|
| 4 vCPU, 4096M | PASS 171.6 s; PASS 175.9 s; **one hang, cut at the 3,600 s phase cap** |
| 8 vCPU, 4096M | PASS 180.5 s; PASS 178.9 s; PASS 181.1 s |

So width is not the variable. Eight vCPUs passed three times out of three
within 5% of the four-vCPU baseline, and the one failure landed on four —
the width this plan had adopted as "least-bad" precisely because the leak
cascade made it look safe. The real defect is an intermittent hang, seen
once in six runs here, that is independent of guest width. Memory is not the
variable either: 4 vCPU passed at 2048M and 8192M in the older data.

What the hang looks like, from the run that hit it: the native build printed
its seventh `build-script sandbox is not implemented` warning and then
produced nothing for 59 minutes. **The guest stayed healthy throughout** —
at t=3,601 s the harness's `shutdown` was accepted and the kernel logged its
normal `Shutting down via /bin/russhd` and `vm_exit: bye`. No panic, no
filesystem error, no OOM. So a guest *process* stops making progress while
the kernel, sys-io and sshd all keep serving. That is a much narrower target
than "the gate crawls", and it is reachable: the OS answers ssh while stuck,
so the guest can be interrogated mid-hang.

#### The native rustc hang, corrected and fixed (2026-08-09)

The live sampling above was useful evidence, but its original interpretation
as an `rt::io_runtime` lost-wakeup livelock was wrong. An unstripped native
rustc provided the exact stack:

```text
moto_rt::fs::readdir
std::fs::ReadDir::next
rustc ... FileSearch::new
```

Motor's `ReadDir` cursor prefetches the next directory ID. Parallel compiler
work can remove that entry before the following `next` call. The lookup then
returned an error but left the cursor pointing at the removed ID. Rustc's file
search intentionally discards individual directory-entry errors with
`filter_map`, so it immediately called `next` again, received the same error,
and repeated forever. Each iteration made a successful request/reply exchange
with `sys-io`; the near-equal wait/wake counts and CPU split therefore measured
the retry loop, not a lost wakeup.

`rt.vdso::readdir` now replaces the current cursor with `Done` before issuing
the lookup. A successful lookup installs the prefetched next cursor; an error
is returned once and the next call observes end-of-stream. This makes the
iterator fused after an error and prevents any caller that ignores a
per-entry error from spinning. The systest regression creates two entries,
consumes the first while prefetching the second, removes the prefetched entry,
then asserts one error followed by EOF.

The earlier concurrency measurements remain useful as exposure data, not as
evidence of the rejected mechanism. Parallel Lorry creates and deletes more
compiler artifact entries, increasing the chance that a prefetched ID becomes
stale. With the cursor fix, the native self-gate passed three consecutive cold
release runs (153.737, 156.133, and 155.049 s) and three consecutive cold debug
runs (173.063, 174.866, and 175.557 s), all at the normal concurrent setting.
No retry, timeout extension, or serial fallback was added.

#### `sys-tty` busy-waits on EOF (found in the same capture)

Independent of the hang, and visible in the table above: `/sys/sys-tty`
consumed 419 s of CPU during a ~450 s run — a full core, continuously, on a
headless build with nothing reading the console. On a 4-vCPU guest that is a
quarter of the machine, in every campaign.

The cause is in `src/sys/sys-tty/src/main.rs`. Both console pumps are shaped
like this (`:157` for stdout, `:172` for stderr):

```rust
if let Ok(sz) = child_stdout.read(&mut buf) {
    if sz > 0 { write_serial_raw(&buf[0..sz]); }
} else { break; }
```

`read` returning `Ok(0)` is EOF, but only `Err` breaks the loop; `Ok(0)`
falls through and calls `read` again immediately, forever. The stderr pump
is worse — it calls `write_serial_raw(&buf[0..0])` on every iteration.
Compounding it, `serial.rs:8`'s `wait_for!` spins on the UART status bit for
every byte, and each port access is a VM exit, so anything on this path is
expensive.

An idle VM burns 1% of a core, so the pipe blocks correctly while it is open
and empty — the spin needs the EOF (or a spurious `Ok(0)`) to start. Whatever
the trigger, the loop has no break on EOF and no backoff on any non-data
outcome, which makes it a defect on its own terms. It wastes a core but did
not cause the native rustc hang: that independently reproduced mechanism was
the directory-cursor retry described above.

Two further Motor-side defects are identified below.

**ELF-load failure is misreported as `InvalidArgument`, and the read path is
innocent.** At 8 vCPU/2048M the guest failed 30 s in with `clang: error:
unable to execute command: posix_spawn failed: Invalid argument (EINVAL)` and
`rush: /sys/tools/llvm/bin/llvm: InvalidArgument (os error 7)`. An earlier
revision of this note read that as a corrupt read of an unchanging file. That
was wrong, and the guest's own log disproves it: `run_elf` logs the buffer it
read, and both failures recorded `buf len: 107512056 hash:
0x564a75ae8705a1fe`. The length is `/sys/tools/llvm/bin/llvm`'s exact size and
the hash is the FNV-1a of the real file, recomputed on the host. **All 107 MB
were read back byte-perfect, twice.** No filesystem defect is in evidence here.

The failure is downstream, in `src/sys/lib/rt.vdso/src/rt_process.rs`. With
correct bytes, `ElfBinary::new` and the arch and interpreter checks all pass,
so the error comes from `elf_binary.load()`. Its content-dependent failure
modes (write+execute segment, TLS, unsupported relocation) are deterministic
for a given binary and this binary loads on every other spawn, which leaves
the one environment-dependent path: `Loader::allocate` maps *any*
`SysMem::map2` failure to `ElfLoaderErr::OutOfMemory`, and `load_binary` then
flattens *any* `ElfLoaderErr` to `E_INVALID_ARGUMENT`. So a guest that cannot
map the segments reports a corrupt-executable errno. Spawning this binary
needs the whole 107 MB in a buffer (`run_elf` loads it wholesale, as its own
TODO notes) plus the segments mapped again, so >200 MB per concurrent spawn
while eight rustc processes are resident — which is why raising the guest to
4096M made it stop. The previous session's memory reading was closer to right
than the correction that replaced it.

Two diagnostic defects made this hard to see and are worth fixing first: the
`ElfLoaderErr` variant is discarded rather than logged (the `7` in the log is
the outer moto `ErrorCode`, not the loader error), and out-of-memory is
indistinguishable from a malformed binary at the syscall boundary. Neither is
reproducible in isolation — spawning this binary concurrently at 1024M, 512M
and 384M all succeeded; at 320M the guest died without logging anything.

**motor-fs entry generations diverge.** `ERROR lib/motor-fs/src/layout.rs:623:
Corrupt dir entry: 20280 != 20280` reads as nonsense only because the message
is wrong: `validate_entry` compares whole `EntryIdInternal` values, which are
`block_no` plus a never-reused `generation` ABA guard, but logs only
`block_no`. The generations are what differ, so the guard is *working* — it
caught a handle referring to a block that has since been freed and
reallocated. That is stale-handle detection, not on-disk corruption, and the
name "Corrupt dir entry" oversells it.

The run recorded it 459 times with identical values every time — one stale
handle reused, not spreading damage — and it was the run's only error class.
What still needs answering is who held the stale id: if a client legitimately
holds an open handle across an unlink (POSIX semantics that build tools rely
on constantly), then failing every subsequent operation is a real bug in the
handle model rather than a caller error. The log line should print the
generation, and the level should reflect which of those it is.

#### Frame-slab full-boundary race (fixed 2026-08-09)

After the `ReadDir` fix, the exact release two-generation gate progressed far
enough to expose `kernel/src/mm/slab.rs: slab alloc looping (1)` while the
second native Lorry generation was compiling. The symbolized kernel stack was:

```text
MMSlab<Frame>::alloc_arc
VmemSegment::allocate_pages
VmemRegion::allocate_pages
UserAddressSpace::alloc_user_heap
sys_map
```

The slab bitmap and its `used` counter were published in the wrong order.
Allocation first claimed a bitmap bit and only then incremented `used`. If
preempted between those operations at the full boundary, another CPU could
observe every bitmap slot occupied while `used < 4096`, so the allocator kept
searching for the capacity the counter falsely promised and eventually
panicked.

Allocation now reserves capacity by incrementing `used` before claiming a
bitmap bit. A successful reservation guarantees that some bit is available;
the allocator may briefly wait for the matching bitmap publication, but it can
no longer promise nonexistent capacity. Free clears its bit before releasing
the count with release ordering, and the allocator acquires that publication
when reserving the returned capacity. Counting in-flight reservations as used
also makes the outer partial-slab list's full transition correct.

The frame-churn systest was extended from 128 to 512 iterations so concurrent
allocation/free repeatedly crosses this boundary. Both repository full suites
passed, and the exact `./test-native.sh --release --full` two-generation gate
then passed in 294.852 s.

#### TCP teardown and curl's exact 60-second pause (fixed 2026-08-09)

After native compilation was reliable, the selected Motor curl suite still
took 61.57 s although every request completed. The extra time was one exact
default TCP linger interval, not TLS, DNS, curl, or Lorry compilation.

Two teardown boundaries needed correction. First, dropping `TcpStream`
objects queues pending transmit and close records to moto-io's per-process
compatibility channel runtime. A process can call `exit` before those worker
threads deliver the records to sys-io. The process-exit path now stops and
joins live and recently retired network channel runtimes after asking them to
drain, so shared rings do not disappear with teardown still queued. A child
process regression opens 16 streams, transfers ownership to the drivers, and
exits immediately; every peer must observe the close within five seconds.

That repair exposed the more specific curl delay. A full socket close may
start gracefully with an empty receive queue: sys-io sends FIN and marks its
receive half closed. TLS or another user-space protocol can already have the
response buffered while the peer sends more transport bytes after that FIN.
The receive task used to discard those bytes because `rx_closed` was set. The
peer could therefore fill the abandoned receive window and the socket stayed
in linger until the 60-second deadline. When this state belongs to a full
lingering close, sys-io now aborts the netstack socket and notifies the device,
producing a prompt reset. `shutdown(Read)` does not set the lingering flag, so
its intentional read-closed/write-open half-connection remains unchanged.

A focused TCP regression receives the peer FIN and then writes until the
closed reader rejects it, with a five-second correctness deadline and a
200 ms per-write timeout. Both regressions pass in debug `systest`. In the
same final release dev image, the exact 10-case Motor curl gate takes 4.09 s
(4.32 s including harness overhead), compared with 61.57 s before the fix.
No retry, ignored error, or linger-timeout adjustment was introduced.

### Read-path audit (2026-08-08) — fixed, committed as c1fc56ef

The wrong-bytes theory above was disproven, but auditing it surfaced two real
latent defects in the read path, a large gap in what tests it, and — once that
gap was closed — a third defect that was not latent at all. All four are fixed
in c1fc56ef; the numbered items below describe what was wrong. Debug and
release `systest` both pass with the fixes in place.

1. **The B+tree lookup cursor drops the ABA guard.**
   `MotorFs::lookup_cursors` (`motor-fs/src/fs.rs`) caches four
   `(file entry block, tree leaf block)` pairs keyed by `BlockNo` **only** —
   no `generation` — even though `EntryIdInternal` carries a generation
   precisely because block numbers "can be re-used". Every other lookup calls
   `validate_entry`; this fast path does not, and `leaf_probe` validates only
   that the node looks like a leaf. Its soundness rests entirely on every
   mutating transaction clearing the cache, and `remember_lookup_cursor`
   writes a cursor back *after* awaits, so a cursor computed before an
   invalidation can be stored after it. Worse, the miss path is silent: a
   lookup returning `Hole` makes `MotorFs::read` **zero-fill the buffer and
   report success**, so a wrong answer here is undetectable by the caller.
2. **virtio-blk completions never check the device status byte.** The status
   descriptor is initialised to `VIRTIO_BLK_S_UNSUPP` at four sites in
   `virtio-async/src/virtio_blk.rs` and the `S_OK`/`S_IOERR` constants are
   declared, but nothing ever reads the byte back — `read_header` is used only
   by virtio-net. `VqCompletion::do_poll` returns `Ok` unconditionally, so a
   failed device read publishes a recycled 4 KiB buffer into the block cache
   as valid file data, with no error anywhere.
3. **systest does not cover this.** It never reads a file from two threads or
   two processes at once; its one concurrent FS test writes to disjoint files
   and never reads; its repeated-read test asserts length, not content; the
   largest file it reads is 19 MB, so neither 100 MB+ toolchain binary is ever
   read by a test; there is no readdir test; it always runs alone at 4 vCPU
   and 1024M; and motor-fs's own 3,600-line unit suite, which covers the
   B+tree, transaction log, resize and readdir paths, was not invoked by any
   gate. `full-test.sh` now runs it in both profiles.
   `concurrent_large_file_read_test` closes the main gap: two child processes
   plus one thread per vCPU stream the same 48 MB file — three times the block
   cache — while verifying a self-describing pattern, so a block served from
   the wrong offset names its true origin. `hot_cache_read_test` now also
   re-checks content after its timed loop instead of trusting the length.
4. **Sub-page reads crossing a block boundary failed.** The new test found
   this on its first run, and it was not latent: `MotorFs::read` rejects any
   read spanning two blocks, and `FsClient::read` sized its requests so that a
   short read starting near the end of a block (128 bytes at offset 4088) was
   sent as a single sub-page request covering two blocks. The server picks the
   single-page format for anything up to a page, so the request came back
   `InvalidArgument`. Any unaligned reader hit this; nothing tested unaligned
   reads. The client now stops such a request at the boundary and picks the
   remainder up on the next pass.

### Harness defects found while measuring (2026-08-08)

**Orphaned qemu (fixed).** Described under "Guest sizing" above:
`run-qemu.sh` forked qemu instead of `exec`ing it, so `kill "$!"` killed the
wrapper and left a live VM answering on the tap. This is the same failure the
pid-refactoring plan records under its gate totals ("a killed `run-qemu.sh`
wrapper leaves its qemu behind — shut the guest down instead"), where it was
treated as operator discipline; `stress-soak.sh` worked around it with
`setsid` plus a process-group kill. It is now fixed at the source — one
`exec` — which repairs every caller at once, `full-test.sh` and
`full-test-networking.sh` included. Cost of not having fixed it: hours spent
this session concluding that FS fixes "did not work" when the ssh carrying
the test was reaching a stale VM booted from an older image.

**Silent stale-VM adoption (fixed).** The leak above was invisible because a
leaked VM answers ssh exactly like a fresh one. `test-native.sh`,
`lorry-native-integration.sh` and `lorry-motor-registry-cache.sh` now probe
their endpoint before starting and abort if anything answers, so a stale VM
is a loud failure instead of a silently substituted system under test. The
guard is deliberately not an auto-kill: cleaning up after the defect would
hide it again.

**Minimal-seed image-name drift (fixed).** The main image manifest now names
`motor-os-dev.img`, which is correct for the Lorry/curl/gears development
image but changed the default inherited by the registry-cache campaign's
minimal seed manifest. The campaign still looked for `motor-os.img`, so it
could not boot the artifact it had just built. The minimal manifest now names
`motor-os.img` explicitly, and its bootstrap test asserts the filename. This
keeps the special image independent of future repository-wide defaults.

**Leaked guest trees (left as a decision).** The guest disk persists across boots, and
a cold `test-native.sh` run deletes its `/user/tmp/lorry-self/<run-id>` tree
only from its exit trap. A run killed before that trap leaks the tree, and
enough leaks fill the 2 GiB guest disk so that a *later* run fails with
`cp failed: StorageFull (os error 20)` — which reads as a product defect and
is not one. Five aborted sizing experiments did exactly that here and were
cleaned up by hand. Making the gate prune leaked roots at startup would fix
the confusion, but it would also hide a real disk-space regression, so it is
left as a decision rather than applied.

Consequences for this plan: the harness still defaults to four vCPUs and
4096M in `test-native.sh`, `lorry-native-integration.sh`, and
`lorry-motor-registry-cache.sh`, each overridable through `LORRY_VM_SMP` and
`LORRY_VM_MEMORY`. That default was chosen to dodge a ceiling that turned out
not to exist. Restore the directed 8-vCPU sizing only as a measured performance
change; it is no longer a correctness workaround. No test was retried,
lengthened, ignored, or forced into serial execution.

The correctness blocker described in the 2026-08-08 measurements is resolved.
The ordinary debug and release native gates are repeatably green, the release
two-generation gate is green, and the release repository native-integration
campaign is green. The remaining exhaustive campaign work measures and lands
milestones 3–5; it is no longer waiting for an unexplained hang.

### Cost of landing this patch

Worth stating plainly, because it is the most important fact in this
document. The last Lorry commit is `ac21d31b` ("lorry: step 8 patch 12",
2026-08-07 10:52). As of 2026-08-08 13:24 the parallel-executor patch has sat
uncommitted for **26.5 hours**. The patch itself is small and was validated
early: 248 unit tests, `cargo +nightly fmt` clean, cold host self-build
34.0 s → 20.0 s, byte-identical artifacts across `jobs=1`/`jobs=16`. None of
the elapsed time went into the patch. All of it went into the gate the patch
must pass.

The pattern is consistent and worth naming. Each time the gate failed, the
cause was somewhere other than Lorry, and each one cost roughly a day:

| Blocker | Where it actually lived | Outcome |
|---|---|---|
| `slab alloc looping (2)` panic | kernel frame allocator | fixed (uncommitted) |
| Suspected read corruption | disproven; four real read-path defects | fixed in `c1fc56ef` |
| "Guest concurrency ceiling" | the test harness leaking VMs | withdrawn; harness fixed |
| The gate hang | `rt.vdso` directory cursor retained a removed prefetched ID | fixed and regression-tested (uncommitted) |
| `slab alloc looping (1)` panic | kernel frame-slab full-boundary accounting | fixed and stress-tested (uncommitted) |
| Registry-cache image missing | minimal manifest inherited the dev-image filename | fixed and unit-tested (uncommitted) |
| curl completed after exactly 60 s | process-exit channel drain and sys-io full-close semantics | fixed and regression-tested (uncommitted) |

None of those failures was a Lorry compiler defect, and three were not product
defects — a disproven theory and two harness/configuration defects. The OS
runtime defects were workloads that Lorry exposed. So the recurring cost here is not
the difficulty of the Lorry change; it is that a Lorry change can only be
verified by a full-system gate, and that gate has been the first workload to
run concurrent, I/O-heavy, long-lived processes on this OS. It finds a new
defect nearly every time it is pointed at something new.

That is genuinely valuable — these are real bugs that would otherwise have
shipped, and the wider sizing was chosen deliberately to expose them. But it
means "land the Lorry patch" and "harden the OS under concurrent load" have
become the same task, and the plan should stop pretending the first can be
scheduled independently of the second. Two consequences are worth weighing
before the next attempt:

- The measurement loop is expensive relative to what it verifies. A single
  native self-gate costs about three minutes when healthy. The new deterministic
  `ReadDir` regression now covers the former infinite-retry mechanism without
  requiring a full Lorry self-build; the native gate remains the integration
  proof.
- Several blockers were artifacts of the measuring apparatus rather
  than the system. The harness now fails loudly on the one class it used to
  absorb silently (stale VMs), which should reduce, but will not eliminate,
  that category.

### Resume state (updated 2026-08-09; patch still uncommitted)

The workspace holds the parallel-executor patch and the harness changes that
support measuring it, plus the native-toolchain and OS fixes required to make
its gates reliable. They are kept uncommitted at the user's request:

- `src/process.rs` — `RustcCommand::run` split into `execute` (spawn and
  capture) and `finish` (render diagnostics, check status), so concurrent
  units print their diagnostics as uninterrupted blocks.
- `src/executor.rs` — dependency units now execute concurrently: a
  `Scheduler` (ready set ordered by plan index, per-unit remaining-dependency
  counts, reverse-dependency map) dispatches units to `Options.jobs` worker
  threads under `Mutex`+`Condvar`; each unit executes against a cloned
  snapshot of its direct-dependency outputs; reuse and cache-restore
  short-circuits are preserved; failures collect as (plan index, error) and
  the lowest-index error is reported for determinism; a stall guard fails
  instead of hanging if no unit is ready, none is in flight, and work
  remains.
- `src/engine.rs` — `executor::Options.jobs` set from `compile_jobs()`:
  `LORRY_JOBS` if a positive integer, else available hardware parallelism.
- `src/tests/lorry-native-integration.sh` — every `native_command`,
  `native_capture`, and SFTP batch records its duration to a new
  `commands.tsv` evidence file and a console `timing: native command` line.
- `src/tests/lorry-motor-registry-cache.sh`, `test-native.sh`,
  `lorry-native-integration.sh` — guest sizing is now `LORRY_VM_SMP` and
  `LORRY_VM_MEMORY`, defaulting to four vCPUs and 4096M; see "Guest sizing"
  above for why that default should now be raised. The registry-cache VM
  needs more than its historical 1024M once builds parallelize.
  `test-native.sh` also records the sizing in its evidence summary, so a
  run's width is never inferred.
- `src/vm_scripts/run-qemu.sh` — `exec`s qemu, so a harness that kills `"$!"`
  stops the VM instead of orphaning it. Repo-wide fix; see the harness
  section above.
- `test-native.sh`, `lorry-native-integration.sh`,
  `lorry-motor-registry-cache.sh` — abort when a VM already answers on the
  endpoint they are about to use, so a stale guest cannot be silently adopted
  as the system under test.
- `test-native.sh` — `LORRY_JOBS`, when set, is forwarded into the guest as a
  command prefix on the three native build invocations. ssh carries no
  environment, so this is the only way to pin Lorry's unit concurrency on the
  guest side; without it, the guest always picks its own available
  parallelism and the concurrency variable cannot be controlled.
- `bootstrap/minimal-seed-image.yaml` and its Python test — pin the dedicated
  registry-cache artifact to `motor-os.img`, independently of the main/dev
  image naming policy.
- `moto-io`, `rt.vdso`, and `sys-io` TCP teardown — process exit drains and
  joins channel drivers, while peer data after a full lingering close resets
  the abandoned connection without changing `shutdown(Read)`. Two systests
  pin prompt peer close and prompt rejection of post-FIN writes.
- `make-it-faster.md` — this plan, measurements, and findings.

Validation performed for the patch: 248 unit tests pass; `cargo +nightly fmt`
is clean; cold host self-build improved from 34.0 s to 20.0 s (jobs=16) and
21.5 s (jobs=4), with byte-identical artifacts across jobs=1/16. After the
runtime fixes, the ordinary native self-gate passed three consecutive cold
release runs and three consecutive cold debug runs at normal concurrency; the
release two-generation native gate passed in 294.852 s. The release repository
native-integration gate passed all Stage-2 fixtures, native Red/Rush/simple
builds and tests, the HTTPS fixture, and all 10 native curl boundary cases.
After the TCP fixes, the exact release native-integration gate passed again;
its 10 curl cases took 4.09 s instead of 61.57 s. The debug repository full
suite also passes with the directory, slab, process-exit, and TCP-close
regressions. The exhaustive debug campaign subsequently passed both native
Lorry generations, Red, Rush, the simple fixture, HTTPS, curl, and the
dedicated minimal-seed registry-cache rebuild. The complete
`test-exhaustive.sh` then passed: three clean local both-profile matrices,
both full Motor image campaigns, both native Lorry generations, the required
release generation byte identity, and both isolated registry-cache campaigns.
The debug and release native full phases took 2,225.771 s and 378.036 s
respectively. A final `src/tests/full-test.sh --release` pass exercised all new
regressions, and direct release dev-image `lorry --help`, `curl --help`,
`cc --help`, and `rustc --version` smokes passed.

The work remains uncommitted because the user explicitly requested local
changes only, not because a known correctness gate is blocked. The remaining
unmeasured item in this plan is the final combined exhaustive-campaign runtime
after milestones 3–5, not native Lorry correctness.

`cargo clippy --all-targets` reports one error, `unit_hash` at
`src/hash.rs:306` (`().hash(&mut empty)` in a test). It is present at HEAD in
an unmodified file, so it predates this work and is not a regression; no gate
script runs clippy, so it does not block any campaign. Fixing it changes what
that test asserts, so it is left for a decision rather than patched here.

Milestone 3–4 design (ready to implement once gates are reliable):

- In-campaign concurrency, no lane changes: `lorry-integration-test.sh
  run_native` launches `lorry-native-integration.sh` (tap, 192.168.4.2)
  and `lorry-motor-registry-cache.sh` (user-net, port 10023) as background
  jobs, waits on both, propagates both exit codes, and prefixes each
  child's console lines for readability. Also overlap `run_host` with
  `run_native`; they are independent.
- Cross-campaign concurrency: only one tap exists, so the second lane must
  use user-mode networking — parametrize the hostfwd port in
  `src/vm_scripts/run-qemu.sh` (`MOTO_HOSTFWD_PORT`, default 10023), give
  `lorry-native-integration.sh` an optional user-net mode (SSH/SFTP to
  127.0.0.1:$PORT), parametrize the registry-cache port and its
  port-ownership guard, then `test-exhaustive.sh` runs the debug campaign
  (tap + registry port 10023) concurrently with the release campaign
  (user-net + distinct ports).
- Debug-campaign scope (milestone 4, from the 4-vCPU measurements): the
  debug full gate is 726.4 s + 747.9 s for the two Lorry generations plus
  roughly 640 s of second-generation Red/Rush/simple rebuilds. Keep one
  pass of every flow on the debug image (vendors, builds, one native Lorry
  self-build, https/curl fixtures, registry-cache overlapped) and leave
  two-generation reproducibility, byte identity, and profile-duplicate
  builds to the release campaign, which is the shipped configuration.

Resume checklist:

1. Implement milestones 3–4 per the design above and re-measure against the
   thirty-minute target.
2. Reconsider milestone 5 with measured 8-vCPU data. The former width ceiling
   was a harness artifact, so sizing is now a performance decision.
3. Run the combined exhaustive campaign after those changes, then land the
   patches only when the user asks for commits.
4. Also open for the `sys-io`/motor-fs owner: the `sys-tty` EOF busy-loop
   above (a full core wasted in every campaign); the
   ELF-load failure misreported as `InvalidArgument` (the `ElfLoaderErr`
   variant is discarded, so out-of-memory is indistinguishable from a
   malformed binary), and who holds the stale `EntryIdInternal` — if a client
   legitimately holds a handle across an unlink, the handle model is wrong
   rather than the caller.

## Summary

At the time of the original analysis, the design was over-specified in four
places. The implementation status above records which observations have since
been addressed.

1. Dependency admission copies graph and source facts already represented by
   Cargo.lock and immutable repository objects.
2. Every supported Cargo release adds a permanent 1,100-line frozen oracle
   family, and all retained families are exercised in every gate.
3. The test harness hardcodes other packages' dependency versions, checksums,
   and build-script sets, so upgrades elsewhere in the repository break
   Lorry's gate without any Lorry change.
4. The test harness multiplies artifact profile, build topology, Motor OS image
   profile, and reliability repetition into one clean-room matrix.

The recommended direction is:

- keep Cargo.toml as the only human-edited dependency file;
- keep Cargo.lock as the only resolved-graph representation;
- keep immutable repository objects as the source-evidence authority;
- replace the full generated admission file with a compact cryptographic
  commitment plus exceptional capability grants;
- make ordinary `lorry vendor` reconcile intentional dependency changes;
- bound the retained Cargo oracle families and derive harness dependency
  facts from the consumed packages' lockfiles; and
- split testing into fast, acceptance, and exhaustive gates.

## Size of the dependency-upgrade change

Commit `0c148180` inserted 5,077 lines. The largest additions were:

| Area | Added lines |
|---|---:|
| Cargo 1.99 compatibility oracle | 1,106 |
| `src/admission_state.rs` | 1,024 |
| `src/upgrade.rs` | 866 |
| Generated `.lorry/dependencies-v1.toml` | 534 |
| Documentation and plans | about 800 |
| CLI, resolver, vendor integration, tests, and harness | remainder |

The admission and upgrade modules alone added 1,890 lines. With their vendor,
resolver, and CLI integration, explicit dependency upgrading added roughly
2,300 lines of Rust. The feature became a manifest editor, resolver mode,
approval database, acquisition workflow, and transaction coordinator.

The largest single file addition was not admission machinery: the frozen
Cargo 1.99 oracle exists because the same commit moved `cargo-compat-version`
from 1.98 to 1.99. Toolchain upgrades are a distinct breakage vector and are
analyzed separately below.

Lorry currently contains about 38,500 lines of Rust including inline tests.
This makes continued expansion of the supported package-manager surface a
material maintainability concern.

## Problems with the dependency design

### Repeated representations of the same graph

The dependency graph is represented in four places:

1. Cargo.toml contains human dependency intent.
2. Cargo.lock contains resolved identities, dependency edges, and checksums.
3. `.lorry/dependencies-v1.toml` repeats direct intent and locked identities,
   then adds admitted evidence.
4. `bootstrap/stage2-seed.toml` repeats much of the Lorry and curl graph for
   bootstrapping.

For Lorry itself, the admission file has 534 lines and the bootstrap seed has
553 lines. The admission file repeats 8 direct dependencies, 38 locked
packages, and 33 admitted packages.

Much of this information already has an authoritative source:

- Cargo.lock records exact registry identities and checksums.
- Repository `RegistryObject` metadata records license and source-tree
  evidence and is verified during lookup.
- Cargo.toml records direct requirements.

The generated state is described as evidence rather than another version
requirement, but operationally it is a denormalized copy that must remain
synchronized with the authoritative inputs.

### Approval, integrity, and policy are conflated

Four concerns can be kept separate:

- Cargo.lock defines the graph.
- Repository objects establish source integrity and evidence.
- System and project policy impose constraints and explicit denials.
- Project admission state proves that a graph and its evidence were reviewed.

The current admission file serializes the underlying graph and evidence and
then translates every admitted identity back into a generated policy allow
rule. A compact commitment to a canonical review document can establish the
same approval without copying the entire document into the project.

### Ordinary vendoring cannot reconcile an intentional edit

`lorry vendor` validates existing admission state before it resolves or
acquires anything. An intentional Cargo.toml or Cargo.lock change therefore
forces the separate `vendor upgrade` path.

Vendoring is already the networked, policy-enforcing, human-approval boundary.
Build, run, and test should reject stale state, but `lorry vendor` should be
the command that repairs it.

### Upgrade owns too many responsibilities

The current upgrade path:

- edits Cargo.toml while preserving its formatting;
- selectively unlocks one package;
- resolves and acquires the candidate graph;
- constructs temporary review policy;
- presents and records approval;
- replaces Cargo.toml, Cargo.lock, and admission state; and
- implements an exact-command recovery journal.

If Lorry does not edit Cargo.toml, only Cargo.lock and an admission commit
marker need replacement. Repository objects can be published first,
Cargo.lock can be atomically replaced second, and admission can be written
last. A crash leaves a detectable mismatch, and rerunning `lorry vendor` can
safely reconstruct and review the candidate.

### Bootstrap state is still a synchronization exception

The original upgrade plan stated that upgrades update
`bootstrap/stage2-seed.toml` in the same transaction. The implementation has a
fixed three-file transaction containing Cargo.toml, Cargo.lock, and
`.lorry/dependencies-v1.toml`; it does not update the bootstrap seed. The
recent seed change was committed separately.

Consequently, upgrading a dependency of Lorry itself can leave its bootstrap
seed stale. The bootstrap representation should be derived or explicitly
regenerated rather than being another implicit upgrade responsibility.

## Upgrade breakage beyond the admission file

The admission file is only one of the frozen copies that fail closed when
something is upgraded. The recent upgrade cycle exercised two more, and the
first observation below narrows what the admission file is actually
responsible for.

### Admission invalidation is narrower than it appears

Both admission fingerprints cover only crates.io packages: the manifest hash
skips non-registry dependencies and the lock hash skips packages without a
crates.io source. Bumping an in-tree path dependency such as moto-rt
therefore does not invalidate admission state. What broke Lorry during the
moto-rt 0.17 move was an exact `=0.16.4` version pin on the path dependency
in Cargo.toml, which had to be removed in a separate commit. Two rules
follow: in-tree path dependencies must never carry version pins, and a
diagnosis of "upgrades break Lorry" must name which frozen copy failed,
because the admission file is only one of several.

### Toolchain upgrades add a permanent frozen oracle

`src/tests/lorry-fixtures/stage1-oracles/cargo-1.99.json` added 1,106 lines
because commit `0c148180`
moved `cargo-compat-version` from 1.98 to 1.99. Oracle families accumulate:
1.97, 1.98, and 1.99 are all checked in, the spec requires identity checks
for all of them, and the Stage-2 resolution check re-runs every retained
Cargo binary in each gate pass. The per-family runtime is small; the
unbounded growth is the problem. Without a lifecycle rule, every future
Cargo release produces another 1,100-line commit and another permanent lane,
independent of any admission redesign.

The oracle set needs a retention policy: keep the oldest-supported and the
newest family, or keep full captures only for the newest family and digests
for the rest. A `cargo-compat-version` bump should be a documented, small
workflow — regenerate, verify family equivalence once, retire whatever the
policy allows — not an open-ended compatibility project.

### The harness freezes other packages' dependency facts

The repository integration harness hardcodes exact versions and checksums for
libc, parking_lot_core, rustix, and signal-hook in the host policy it generates,
and hardcodes the build-script package set by name in the generated Motor
configuration. When Red or Rush upgrades a dependency, Lorry's gate breaks
with no Lorry change — exactly the reported failure mode. The Motor
configuration already derives package identities from the Red and Rush
lockfiles; the host policy and the build-script set must be derived the same
way, from those lockfiles plus verified repository evidence.

## Dependency-state alternatives

| Alternative | Ergonomics | Security and reproducibility | Complexity |
|---|---|---|---|
| Current full admission file | Large diffs and synchronization burden | Strong fail-closed checks | Highest |
| Compact review commitment | Small generated state and simple reconciliation | Equivalent integrity and stale-state detection | Moderate |
| Cargo.lock plus policy only | Simplest workflow | Reproducibility retained, explicit review persistence weakened | Lowest |
| Signed compact commitment | Small state with authorization | Strongest against unauthorized state changes | Requires key and reviewer infrastructure |
| Cargo-backed Linux provisioner | Best Cargo compatibility | Lorry can independently verify Cargo's result | Violates the current no-operational-Cargo requirement |
| Linux provisioning with an offline Motor executor | Smaller Motor surface | Strong offline boundary | Motor cannot acquire or upgrade dependencies itself |

### Recommended compact commitment

Keep a small generated file such as:

```toml
format-version = 2
review-sha256 = "..."
targets = ["x86_64-unknown-linux-gnu", "x86_64-unknown-motor"]

[[capability]]
package = "libc"
version = "0.2.187"
checksum = "..."
build-script = true
```

The hash would commit to a canonical review document containing:

- direct dependency semantics;
- Cargo.lock identities and dependency edges;
- reviewed target closures;
- checksums, licenses, source-tree digests, and build-script presence;
- exact native-tool and build-script grants; and
- relevant format versions.

Lorry would reconstruct this document from Cargo.toml, Cargo.lock, and
verified repository objects. It would compare the hash before treating the
graph as approved. `lorry review` could print the full document or compare it
with a previous admission, while CI could retain the report as review
evidence.

This does not weaken source integrity or reproducibility. Corrupt sources are
still rejected by checksum and source-tree verification, graph changes still
invalidate admission, and explicit policy denials still win. The existing
full state is not signed, so someone able to maliciously change project files
can already replace it. A signature is the appropriate additional mechanism
if admission must resist an unauthorized committer.

The cost is that a one-line hash is opaque in a raw Git diff. Cargo.lock and
exceptional capability changes remain visible, but today's full admission
file lets a reviewer see what was admitted directly in the diff. The
reviewable report is therefore a requirement of this design, not a
mitigation: `lorry review` must reconstruct the complete document offline
and diff any two admissions, and CI must retain the rendered report as
review evidence.

Two boundary conditions need stating. A checkout without the vendored
repository objects cannot recompute the review document; it stays fail-closed
until `lorry vendor` reconstructs and verifies them, which matches today's
behavior for missing sources. There are no external format-version 1 users, so
the repository uses a direct cutover with no reader, translation, or
compatibility window for the old state.

### Recommended reconciliation workflow

The normal direct-upgrade workflow should be:

```sh
# Edit the exact version in Cargo.toml.
lorry vendor
```

`lorry vendor` should:

1. load previous admission only as a comparison baseline;
2. resolve the current manifest using Cargo.lock entries as preferences;
3. acquire and verify missing sources;
4. display the graph, evidence, and capability difference;
5. require approval;
6. publish immutable objects;
7. atomically replace Cargo.lock; and
8. atomically write compact admission last.

An exact direct requirement naturally selects the intended version. A narrow
option can remain for a transitive-only update:

```sh
lorry vendor --update package@old-version --to new-version
```

A one-command direct update could be a convenience wrapper that visibly edits
Cargo.toml and then invokes the same reconciliation path. It need not restore
the old manifest if acquisition fails: the requested edit can remain, and all
build operations remain fail-closed until vendoring succeeds.

This direction should permit deletion of most of the upgrade transaction and
much of the admission parser. A reasonable design target is a net reduction
of roughly 1,000 to 1,500 lines — counted after adding the new canonical
review renderer and comparison code — and generated project state measured
in tens of lines rather than hundreds.

## Why the test gate took hours (historical baseline)

Before the completed test-scope work, the three successful debug native phases
took between 70.73 and 71.27 minutes
each, or 213.1 minutes total. The release phases took between 11.12 and 11.15
minutes each, or 33.4 minutes total. Native execution alone therefore took
246.5 minutes, excluding host preparation and image builds.

The two matrices perform closely comparable native work — the release matrix
compiles Lorry with fat LTO and a single codegen unit, which is heavier, yet
finishes six times faster — so the difference is almost entirely the debug
Motor OS image executing the work. Moving Lorry-only validation to a release
image should bring the debug-artifact passes near the eleven-minute release
figure, cutting the mandated six-pass gate from roughly 247 native minutes
to roughly 67 before any coverage is removed. This is the largest single win
and the least controversial change.

The same evidence directory records seven failed full runs beside the three
passes, so reaching three consecutive passes cost roughly ten runs that day.
A serial 71-minute gate that can fail near its end amortizes poorly; phases
must be ordered so likely failures surface in the first minutes. Host
preparation and image builds are untimed today, so every figure above
understates the true cost of a pass.

Every `test-local.sh` repetition reruns:

- all Cargo compatibility oracles;
- Rust tests and hosted builds;
- Motor image preparation;
- fresh repositories and staged source trees;
- Linux-to-Motor builds of Lorry, Red, Rush, curl, and test fixtures;
- Motor-native debug and release builds of Red and Rush;
- Red tests, simple run tests, and curl/TLS tests;
- first-generation native Lorry self-build;
- second-generation native Lorry self-build; and
- second-generation Red, Rush, and simple-package builds.

Before guest staging, the harness deliberately deletes the staged target
directories. This is valuable for one clean-room acceptance run but ensures
that every matrix repetition pays for another cold native build.

The matrix conflates independent assurance dimensions:

- Lorry debug versus release artifact profile;
- Linux, cross-Motor, and native-Motor build topology;
- debug versus release Motor OS image;
- deterministic reproducibility versus transport/VM reliability; and
- ordinary development versus milestone acceptance.

These dimensions should receive representative coverage without taking their
full Cartesian product on every change.

## Recommended test structure

### Fast local gate: minutes warm, ten to fifteen minutes cold

Run once for an ordinary Lorry code change:

- all Rust tests and Cargo compatibility oracles;
- Linux debug and release Lorry builds;
- Linux-to-Motor debug and release Lorry cross-builds;
- one release Motor OS VM;
- execution of both cross-built Lorry profiles in that VM;
- one Motor-native release Lorry self-build and byte comparison; and
- one small purpose-built package covering library, binary, integration test,
  build script, target dependency, registry dependency, run, and test.

Use a release Motor OS image for Lorry-only debug and release artifact tests.
The OS image profile is relevant when system code changes; it is not a useful
multiplier when only Lorry changed.

Targets are stated warm and cold separately because the currently quoted
native timings exclude host preparation, image building, and boot. The
complete release matrix already finishes its native phase in about eleven
minutes, so this trimmed set fits the cold budget. During iteration the
staged target directories should stay warm; the deliberate clean-room
deletion belongs to the acceptance and exhaustive gates, paid once before
merge rather than on every run.

### Acceptance gate: ten to twenty minutes

Run for high-risk Lorry changes or before merge:

- one cold repository cycle;
- Red or Rush as a real package;
- curl acquisition and TLS only for repository, archive, redirect, curl, or
  policy changes;
- one native self-host generation; and
- release byte-identity comparison.

Executing the native Lorry and using it to build one representative package
establishes basic self-host usability. Rebuilding the complete downstream set
with a second-generation Lorry should not be part of every local gate.

### Exhaustive gate

Reserve the full clean-room campaign for:

- nightly CI and milestone closure;
- bootstrap, compiler-identity, cache-identity, native-tool, or harness
  changes; and
- system changes covered by the repository-wide full test.

Second-generation Lorry plus Red, Rush, curl, both OS image profiles, and full
repetition belong here.

### Repeat nondeterministic boundaries, not the full build

The three release runs produced identical hashes. Debug artifacts are
intentionally not compared because paths and debug information can differ.
Repeating every deterministic compilation therefore adds little information.

If three repetitions are required for reliability, repeat only:

- VM boot and SSH readiness;
- upload/download integrity;
- a tiny native build and run; and
- explicitly concurrent vendoring cases.

Do not repeat image construction, resolver oracles, native self-hosting, and
the complete downstream package set.

### Resize and parallelize the VM before cutting coverage

The guest runs with 4 vCPUs and 2 GiB of memory on a 16-core host, and
native compilation dominates every long phase. Before any coverage is
removed, measure whether more vCPUs and memory shorten the native phase; a
host-resource change may buy back much of the remaining cost without losing
any assurance. The debug and release Lorry matrices are also independent and
can run concurrently in separate VMs once they stop sharing the single tap
network endpoint — the user-mode networking knob in `run-qemu.sh` already
provides per-instance port forwarding.

## Test-policy ownership

`src/bin/lorry/AGENTS.md` should route verification by affected scope:

- Lorry-only changes use the fast local gate plus risk-selected acceptance
  tests.
- Lorry bootstrap or harness changes use the exhaustive Lorry gate.
- Kernel, sys-io, shared-library, image-construction, or repository-harness
  changes use the repository-wide debug and release full tests.

The product specification should define behavioral coverage and acceptance
invariants. A requirement for three consecutive local runs is contributor
workflow and belongs in AGENTS.md rather than spec.md.

Routing should be mechanical: a small script maps changed paths to the
required gate so the decision is never re-derived from prose. The exhaustive
gate also needs a named trigger — a nightly CI job, a cron entry, or a
release-checklist item with an owner. A gate that no schedule invokes
silently stops existing.

## Proposed order of work

1. **Completed 2026-08-04.** Added machine-readable and console per-phase
   timing to the local and native harnesses, including explicit Stage 2 seed,
   Motor image build, host preparation, VM startup, input staging, smoke, and
   full-gate phases. Native evidence summaries retain every phase duration.
2. **Completed 2026-08-05.** Decoupled the Lorry artifact profile from the VM
   image profile and ran both artifact profiles in a release image. The debug
   native self-gate fell from 1,215.6--1,217.0 seconds to 193.9 seconds; total
   measured native phases fell from 1,272.6--1,275.0 seconds to 252.1 seconds.
   The release native self-gate remained stable at 203.5 seconds versus the
   203.7--204.7 second baseline, including byte-identity verification. The
   repository integration gate retains debug image coverage.
3. **Completed 2026-08-05.** Added separate fast, acceptance, and exhaustive
   entry points. The fast gate runs both profiles cheapest-first and supports
   persistent host and guest target directories with `--warm`; acceptance adds
   one release downstream/native smoke campaign; exhaustive retains three
   clean local passes, both second-generation integration campaigns, and the
   dedicated-image Motor registry campaign.
   `test-changed.sh` maps changed paths to the strongest required gate, with a
   contract test for the routing policy. The combined fast gate measured 488.6
   seconds cold and 442.2 seconds with populated warm targets. Warm reuse cut
   the release guest self-build from 203.0 seconds to 100.7 seconds; the first
   warm population run took 583.4 seconds. The first exhaustive campaign passed
   all three local debug/release repetitions and both integration profiles; its
   full native phases took 3,156.5 seconds for debug and 501.9 for release.
4. **Completed 2026-08-06.** The repository integration harness now vendors
   Red and Rush before building either, then derives exact host and Motor policy
   rules from each Cargo.lock, Lorry's generated admission state, and verified
   retained repository sources. The acquisition-only build-script grant is
   replaced before any build runs. The focused contract rejects mismatched
   locks, missing or changed evidence, and incorrect build-script facts while
   allowing locked packages not selected for the tested targets. A release
   native smoke campaign passed in 147.4 seconds.
5. **Completed 2026-08-06.** Added a purpose-built Motor-native fixture to the
   Lorry self-gate. It uses a reviewed `cfg-if` registry object, a Motor-only
   path dependency, and an admitted path dependency whose build script emits
   compiled source. Lorry builds and runs its binary, then runs its library,
   binary, and integration tests. A focused warm release native gate passed in
   218.5 seconds with all three fixture tests green. The exhaustive campaign
   then passed three local debug matrices in 301.7--302.6 seconds, three local
   release matrices in 318.5--321.8 seconds, the full debug native gate in
   3,149.3 seconds, and the full release native gate in 502.8 seconds.
6. **Completed 2026-08-05.** Moved Red, Rush, curl, the synthetic Stage-1
   package/oracles, and downstream second-generation coverage to the repository
   integration gate. The Lorry-local matrix now builds only Lorry and its
   dependencies. crates.io and GitHub acquisition use fail-closed fixtures
   derived from local Cargo caches, with no Internet fallback. Stage-1
   artifact identity is now relational against Cargo rather than pinned to
   compiler-specific digests.
7. **Completed 2026-08-06.** Large Stage-1 captures are retained only for the
   oldest and newest supported Cargo families. Regeneration still captures
   every supported family and rejects adjacent identity or artifact drift;
   every supported family also remains in the live Stage-2 resolution gate.
   The oracle README documents the `cargo-compat-version` bump and separate
   family-retirement workflows.
8. **Cutover completed 2026-08-06; the offline `lorry review` command (slice
   5) remains.** Eleven inactive patches added the canonical writer, the
   review and compact-state models with validation, rendering, and golden
   vectors, strict compact parsing, cfg-selector canonicalization, and the
   complete review builder. The twelfth patch performed the direct cutover:
   commitment verification before generated policy in every build, candidate
   review and state-last writing in vendor, the format-2 upgrade journal,
   regenerated committed states proven equal to the format-1 baseline, and
   deletion of every format-1 code path. There was no format-version 1
   migration or compatibility path. The first cutover build blew the debug
   integration campaign's shared 5,400-second native budget (smoke 2,252.7 s
   plus staging 90.7 s plus a full gate killed at 3,056.6 s) because every
   `lookup_registry` re-verified its object — archive hash plus retained-tree
   hash — so with verification added, each package was re-hashed up to six
   times per build (two catalog loads, two evidence lookups, two
   `from_registry` rescans). The same patch removed the duplication instead
   of raising the budget: `RepositorySet` caches verified objects per process
   (content-addressed objects are never replaced in place), `RegistryObject`
   carries its verified source tree so evidence no longer rescans it, the
   engine shares one registry source between admission verification and
   prepare, and vendor shares one set across inventory, resolution,
   missing-package, evidence, and upgrade-baseline passes. A warm no-op
   debug host self-build measures 25.6 s with full four-context commitment
   verification, equal to the 25.7 s pre-cutover baseline (the unfixed
   cutover measured 29.4 s).
9. **Remaining.** Make ordinary `lorry vendor` reconcile intentional
   dependency changes.
10. **Remaining.** Remove manifest editing and the three-file transaction from
    the trusted upgrade core.
11. **Remaining.** Derive bootstrap registry entries from lockfiles and
    verified cached objects, retaining only exceptional seeded-Git provenance
    explicitly.

The test items precede the dependency items deliberately: once verification
takes minutes, every later change is cheaper to land and to revert.

This preserves Lorry's independent, offline, fail-closed build model while
making routine dependency upgrades small and making normal verification take
minutes rather than hours.
