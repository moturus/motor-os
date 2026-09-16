# Virtio-vsock implementation plan

Status: v2.9. The v1 open questions Q1–Q13 were approved on 2026-09-14 as
recorded in the Decisions section, adopting the second review's
recommendations. The launch-infrastructure questions raised afterwards
(Q14, Q15) were approved the same day with the `--vmm` caveat recorded in
D15 and D16. Follow-up review corrections and simplifications are retained.
Q16 is settled in D16: an explicitly requested `raw.img` target for standard
Firecracker tests, with no developer-image Firecracker support. Q18 is settled
in D17: preserve RX used-ring order inside virtio-async using the existing
queue, without negotiating `IN_ORDER`. Q19 and Q20 are approved in D18 and
D19: one-read shared reset verification and connection-local rejection of
impossible peer credit. Q22 is approved in D13: integrated pumps and IPC
accounting belong in M2, with all gate counts and test coverage retained.
Q21 is deferred in D20: defending against buggy or malicious VMMs is out of
scope, with the BAR-boundary concern recorded in `future-work.md`.
Repository and references inspected on 2026-09-14, with the CID and VMM
ordering review updated on 2026-09-15;
M1 foundations have passed their repeated full gate. M2 integration is
underway, with progress recorded below. Q23 is settled in D21: discovery
checks CAP_VSOCK first (`NotAllowed` if missing), then device presence
(`NotFound` if absent), without activating the device.
Q24–Q25 are settled in D22: wrong-state packets and payloads exceeding
advertised credit reset only their identified connection.
Q26 is settled in D23: fix the preexisting shared NET subchannel validation
gap with guest regressions, then continue vsock integration.
The first outgoing vertical is implemented and incrementally gated. Q27 is
resolved by diagnosis in D24: the failing test assumed transparent
Unix-socket half-close, and the
same test fails against Linux. Correct the Motor test protocol, keep all
VMMs unchanged, and retain the directional stream API/protocol requirements.
Q28 is settled in D25: eight pending accept calls per listener, separately
from its eight-stream backlog. Q29 is settled in D26: a transport reset
permanently disables vsock; no snapshot/reset recovery or snapshot tests.
Q31 is approved in D27 as a separate kernel fix with its own three debug,
three release, and one release developer-suite gate before commit. Q30's
requested simplification is recorded in D28: discard abandoned operations
and fix channel ownership without a cancellation protocol or new IPC API.

Implement a modern virtio-vsock driver in `src/sys/lib/virtio-async`, serve
vsock streams through sys-io, and expose moto-io's native Rust API. Follow
the existing block and network drivers' structure and reuse their virtqueue
implementation and networking IPC machinery. Implementation is approved and
proceeds in small reviewed commits; the full repeated gate belongs at the
two approved milestones, not every commit (D13).
The explicitly requested D27 kernel gate is an exception to that grouping.

## Implementation progress

Stage 1 baseline, before source changes at `6918384e`:

- Selected toolchain:
  `motor-1.99.0-beta-f47d5bb-dev.2-669057dcd9e729bc97418edb8b926b9e7526202a217dfc8dd9dd8dda561ca4e4`
  (`rustc 1.99.0-dev`, Motor dev.2, LLVM 23.1.0).
- `make -j"$(nproc)"` and `make -j"$(nproc)" BUILD=release` image builds
  passed with the existing kloader `clippy::ptr_eq` warning at
  `src/boot/x64.kloader/src/loader.rs:177`.
- `src/tests/full-test.sh --release` passed with exit status 0 on QEMU.
  No debug baseline full-test was run. These are pre-change baseline checks,
  not the repeated M1/M2 gates or validation of implementation patches.
- The standard main-image VM logged "most services up" at 108 ms; separate
  System-console/TUI/terminal-size boots logged 106–108 ms. These are baseline
  observations, not a controlled boot-time benchmark or acceptance threshold.
- Local evidence: `/tmp/vsock-baseline.qoT1LL/build-debug.log`,
  `build-release.log`, and `full-test-release.log` in the same directory.

Stage 2 capability foundation is implemented, parent-reviewed, and validated.
Wire decoding is also validated below; device I/O, IPC, and native vsock API
implementation remain pending.

- The initial debug build failed; the original log is preserved at
  `/tmp/vsock-cap.XxgFum/build-debug.log`. Rush's published moto-sys dependency
  lacked the new constant; its dependency now uses the in-tree crate.
- The same build correctly rejected the now-stale runtime assembly because
  moto-sys content contributes to its identity. Standard/developer images
  require a matching assembly from `src/build-motor-os.sh`; do not bypass
  the selector or reuse a mismatched overlay. The documented producer can
  provision host packages and managed sibling sources, and writes generated
  artifacts under `/home/posk/motor-dev/assemblies` and related build trees
  outside this repository. The user authorized this refresh and subsequent
  builds on 2026-09-15. The refresh passed with host networking setup skipped
  after checking the existing configuration; all three release images built.
  Assembly `0a7f8808364649c86f1f81a21651970b9705ba5e15c552fa67f258ce6190bd0b`
  is pinned and compatible with the current runtime contents; the host Rust
  toolchain was reused. Log: `/tmp/vsock-assembly.wd1K5M/build-motor-os.log`.
  No external source-code or toolchain declaration changes are part of the
  vsock patch.
- `make base.img systest` passed in debug and release, with the same
  preexisting kloader warning. On both profiles, the base-image
  `MOTOR_OS_CAPS=0xcc .../systest capability-policy-tests` passed, as did
  `src/tests/test-system-tty.sh` (with `--release` for release). These cover
  default inheritance, explicit grant/denial, and System-parent
  non-escalation. Both test bodies remain reachable through full-test.
- Formatting, shell syntax, the existing moto-sys host tests, and separate
  kernel/userspace, rush, and russhd Clippy checks passed. Clippy still reports
  preexisting diagnostics in untouched virtio-async and allocation-benchmark
  code; no diagnostic points to changed code.
- Evidence is in `/tmp/vsock-cap.XxgFum`: `build-base-systest-*.log`,
  `guest-capabilities-*-sftp.log`, `system-tty-*.log`, and `clippy-*.log`.
  Initial invalid feature-combination checks and manual guest-launch errors
  are retained separately, not counted as passing validation.
- After the assembly refresh, `src/tests/full-test.sh` and
  `src/tests/full-test.sh --release` both passed with exit status 0 on QEMU.
  Logs: `/tmp/vsock-assembly.wd1K5M/full-test-debug.log` and
  `full-test-release.log` in the same directory. These are one debug and one
  release full run validating this patch, not the repeated milestone gates;
  neither M1 nor M2 is complete.

Stage 2 wire decoding is implemented and parent-reviewed:

- The private driver module checks the 44-byte header, little-endian fields,
  lengths/capacity, CID width, type/op/flags, control payloads, and four-byte
  events. Incomplete received headers expose no refusal metadata; complete
  invalid headers retain untrusted metadata. SHUTDOWN accepts flags 0–3.
- Literal wire examples and malformed-input assertions execute in existing
  guest `test-virtio-descriptors`, also reached by ordinary systest/full-test.
  Both profiles passed, including the unchanged descriptor-ownership cases.
- `make base.img systest` and targeted virtio-async/systest Clippy passed in
  debug and release, with only the previously recorded warnings; formatting
  and diff checks passed. Logs: `/tmp/vsock-wire.PxfFMs/{build,clippy,guest}-*.log`.
- Actual DMA and queue-capacity coverage arrives with stage 4. No activation
  or boot tasks are added here, and neither milestone is complete.

Stage 3 modern-device discovery and feature selection are implemented and
parent-reviewed; CID validation and device initialization remain:

- Recognize PCI device ID `0x1053` without initializing the device. The private
  driver requires `VERSION_1`, accepts only optional `RING_EVENT_IDX`, and
  uses the existing feature-confirmation sequence. No queues/tasks are added.
- Guest `test-virtio-descriptors` covers the real device classifier and feature
  selector, including legacy/unknown IDs, missing required features, and
  ignored unsupported features. Debug and release guest runs passed alongside
  the existing wire/descriptor tests. Both base-image builds and targeted
  virtio-async/systest Clippy checks passed; no new warnings remain.
- Logs: `/tmp/vsock-discovery.e6ysJI/` (initial builds) and its
  `final-clean.Ij0yeZ/` directory (final builds, Clippy, and guest runs).
  The initial new test's Clippy identity-operation warning was corrected.
  An intermediate run in `final.raplX8/` failed before systest because the
  temporary harness reused an uploaded executable's non-writable guest path;
  this is the intentional behavior covered by `test-sftp.sh`. The harness
  now uses a fresh per-run path. Original logs are retained; no OS change,
  permission bypass, test retry, or weakened assertion was needed.
- CID reads will reuse the existing PCI helper with the Virtio 1.1 width and
  reserved-value checks described in constraint 5; no snapshot retry loop.

Stage 3 shared IRQ/MMIO capacity checks are implemented and parent-reviewed:

- The mapper reserves IRQs 64–79 without wrapping, and checks page-rounded
  allocations before advancing the existing 2 MiB pool cursor. Exact-end
  allocations fit; invalid/exhausted requests return errors without consuming
  capacity. DMA zeroing, ring layout, device-count policy, and the multi-block
  guard are unchanged.
- The production reservation helpers are source-included by the existing
  guest I/O-task tests. Both profiles passed rounding, overflow, exact-end,
  exhaustion, and count-independent reservation cases, plus existing
  descriptor/task ownership and actual scattered-write filesystem regressions.
- Final base-image/systest builds and virtio-async/sys-io/systest Clippy passed
  in debug and release. The initial build's deprecated atomic method warning
  was corrected to the selected toolchain's `try_update`; remaining diagnostics
  are in untouched virtio-async, sys-io/netstack, and allocation-benchmark code.
  Formatting/diff checks passed. Logs: `/tmp/vsock-capacity.1ukWmk/` (initial)
  and `final.xtVxhg/` beneath it (final). Neither milestone is complete.

Stage 4 header-scratch sizing (D3) is implemented and parent-reviewed:

- Production and memory-backed fixtures share the allocator: 64-byte vsock
  scratch, unchanged 16-byte block/net scratch, and fallible allocation.
  Both typed accessors check capacity/alignment in release. No eager zeroing,
  device activation, extra boot tasks, or completion-ownership changes were
  added; packet publication will initialize the actual wire bytes.
- Guest descriptor tests cover exact capacities, valid aligned typed access,
  the real 44-byte header, and child-process rejection of oversized/misaligned
  access. Both profiles also passed existing premature-drop, I/O-task, and
  scattered-write filesystem regressions. Base-image/systest builds, targeted
  Clippy, formatting, and diff checks passed with no new warnings.
- The initial build failed on a missing generic type annotation in the new
  fixture, before guest execution; the annotation was corrected. Logs:
  `/tmp/vsock-scratch.AbeL6N/` (original failure) and `final.UT8Gf1/` beneath it
  (final validation). RX/event completions and both milestones remain pending.

Stage 4 private TX encoding/submission is implemented and parent-reviewed:

- Reuses `RawHeader`, `HeaderBuffer`, and `WriteCompletion`; publishes one
  readable descriptor for header-only packets or two for page-backed data.
  Validates outgoing fields and DMA bounds before admission, preserves raw
  unknown socket types only for RST, and returns the unchanged payload on
  invalid input or descriptor exhaustion. No activation or native API is added.
- Guest fixtures cover literal wire bytes, descriptor layout, shutdown flags,
  payload ownership, full-queue rejection/recovery, and invalid inputs.
  Both profiles passed base-image/systest builds, targeted Clippy, and the
  descriptor, I/O-task, and scattered-write regressions; no new warnings.
  Logs: `/tmp/vsock-tx.qe5IRA/`. Two initial sub-agent compile-check failures
  required explicit byte-slice `AsRef`/`AsMut` types (tool transcript evidence);
  those checks and the subsequent parent gates passed after correction.
- The RX completion-order approach is approved in D17; accessor progress is
  recorded below. The packet/completion pool remains pending.

Shared-queue prerequisite: full-width used-ID validation is implemented and
parent-reviewed:

- The existing reclaimer narrowed the device's 32-bit used ID before checking
  it, so `0x1_0000` could complete descriptor zero. It now rejects an ID outside
  the queue before narrowing, indexing, or changing DMA ownership. This
  predates vsock; the user authorized virtio-related bug fixes on 2026-09-15.
- Guest descriptor tests cover the last valid ID and child-process rejection
  of the queue size, `0x1_0000`, and `u32::MAX`, checking the guard diagnostic.
  Both profiles passed these cases, existing ownership/I/O-task tests, and
  scattered-write filesystem regressions. Base-image/systest builds, targeted
  Clippy, formatting, and diff checks passed with no new warnings.
- Logs: `/tmp/vsock-used-id.5eQDzj/`. The initial targeted compile check failed
  because a fixture passed `()` instead of its existing `u32` value; that
  mechanical correction and the final checks are recorded separately. This
  patch adds no ordered accessor or activation; neither milestone is complete.

Stage 4 ordered-completion accessor (D17) is implemented and parent-reviewed:

- A crate-private, one-shot idle-queue cursor observes retained used heads
  after the normal reclaimer processes them. Raw-device and reclaimed lag
  checks cover counter wrap; one completion waiter supplies wakeups. Fetching
  a head neither reclaims nor frees descriptors. Existing block/net APIs,
  feature negotiation, and boot tasks are unchanged.
- Guest fixtures cover a full-ring precompleted batch in reversed used order,
  independently polled futures, wrap/reuse, descriptor retention, an unreclaimed
  head remaining pending, waiter replacement/drop, and rejection of duplicate
  or busy claims and raw/reclaimed overruns. Debug and release passed, together
  with existing descriptor, I/O-task, and scattered-write regressions.
- Base-image/systest builds, targeted Clippy, formatting, and diff checks passed
  with no new warnings. Logs: `/tmp/vsock-order.EVlyIY/`. RX packet validation
  through this accessor and the bounded RX pool are next; neither milestone
  is complete.

Stage 4 private RX submission/completion is implemented and parent-reviewed:

- Publishes a zeroed 44-byte header and one page-aligned 4 KiB payload, both
  writable, using the existing completion ownership. Rejected admission
  preserves the buffer; successful admission clears its visible length.
  Ordered completion first establishes DMA completion, then copies/validates
  the header. Valid packets expose only validated payload bytes; invalid
  packets return the same zero-length buffer and applicable refusal metadata.
- Guest fixtures cover poisoned scratch, descriptor addresses/directions,
  short/full-page/control packets, invalid used/payload lengths, buffer
  identity/release, and invalid/full-queue admission without publication.
  Debug and release passed these and existing descriptor/I/O-task/filesystem
  regressions. Base-image/systest builds, targeted Clippy, formatting, and
  diff checks passed with no new warnings.
- Logs: `/tmp/vsock-rx.VOkuco/`. The initial targeted check's direct `IoBuf`
  indexing error was corrected to an explicit byte slice; original and final
  check logs are retained. Events, the RX pool, and activation remain pending;
  neither milestone is complete.

Stage 4 fixed RX pool (D7, D17) is implemented and parent-reviewed:

- Prepares all pages and completion capacity fallibly before publication,
  then retains `min(64, rx_descriptors / 2)` pages. Each ordered head resolves
  its owner, supplies validated bytes or refusal metadata to a synchronous
  callback, and reposts the same page afterwards without allocation. The
  active pool must remain with its device, including on cached failure.
- Guest fixtures cover the 64-page cap, tiny-queue rejection, reversed used
  order across counter wrap, malformed packets between valid ones, full-page
  payloads, callback-before-repost, page identity/reuse, and completion-driven
  wakeup. A child case checks premature pool destruction remains fatal.
  Both profiles passed these and existing descriptor/I/O-task/filesystem
  regressions, base-image/systest builds, and targeted Clippy. No new warnings;
  formatting and diff checks passed.
- Logs: `/tmp/vsock-rx-pool.s3fbfy/`. The initial targeted check needed an
  explicit array length in the fixture. Parent review also corrected the
  fixture to use captured virtual pointers, never dereference physical DMA
  addresses, and initialize the entire reported full-page payload before
  completion. All corrections preceded guest validation. Events and device
  activation are next; neither milestone is complete.

Stage 4 event completion/pool is implemented and parent-reviewed:

- Publishes one writable four-byte descriptor per event, copies bytes only
  after completion, and validates the exact used length and event ID. The
  fixed `min(4, event_descriptors)` pool uses the same ordered accessor and
  synchronous consume/repost boundary as RX, with capacity reserved before
  publication. Invalid events replenish normally; no extra queue library,
  payload allocation, block status, or submission-order waiting is added.
- Guest fixtures cover scratch initialization/layout, literal reset and
  unknown IDs, invalid lengths, exhausted admission, pool bounds, reversed
  completion order, callback-before-repost, scratch reuse, and concrete
  completion wakeups. Event fixture writes bypass only the synthetic block
  status write; existing block/net test behavior is preserved.
- Debug and release base-image/systest builds, targeted Clippy, and guest
  descriptor/I/O-task/filesystem regressions passed with no new warnings.
  Formatting/diff checks passed; no initial check failures. Logs:
  `/tmp/vsock-events.Jh4yKQ/`. Activation and both milestones remain pending.

Shared initialization prerequisite is implemented and parent-reviewed:

- Source review found that queue allocation started tasks before setup could
  fail, and the no-MSI-X path succeeded without a usable interrupt handle.
  The kernel ignores a zero wait handle, leaving an unwakeable task; this
  analysis did not establish a sys-io panic. Missing/insufficient MSI-X and
  missing notification capability now fail explicitly before allocation.
- Queue tasks start as a validated batch from the final `driver_ok` step,
  not allocation. Queue-owned RAII handles close on failed setup; existing
  IRQ-number and ring-pool reservations remain monotonic. Net's missing
  device-configuration check now precedes its feature-time configuration read.
  No new boot tasks, queue enumeration pass, or teardown framework is added.
- Guest tests use memory-backed queues and native IPC handles to exercise
  failed-batch atomicity, delayed/immediate and signaled reclamation,
  duplicate-start rejection, and handle release with/without task startup.
  These are not injected PCI/MSI-X failures. Debug/release builds, Clippy,
  descriptor/I/O-task/filesystem regressions, and SSH/SFTP traffic passed.
  Formatting/diff checks passed; no new warnings remain.
- Logs: `/tmp/vsock-init.1EvIqp/`. Two new test Clippy warnings were corrected;
  their original log is retained. Parent review corrected a fixture owner
  that outlived its ring storage before any guest run. A separately identified
  block small-queue limit bug is next; neither milestone is complete.

Shared block-queue limit prerequisite is implemented and parent-reviewed:

- Source review found that the half-queue segment limit was calculated after
  `DRIVER_OK`: sizes 1/2 underflowed in debug (wrapped in release), while size
  4 supplied invalid clamp bounds in both profiles. The driver now rejects
  these sizes before subtraction, clamping, or task/device activation.
  Supported queues retain the same limits, including two payload segments at
  size 8 and 126 at size 256; the single-filesystem policy is unchanged.
- The production helper runs through guest descriptor tests with rejected
  sizes and zero, one, exact-limit, and maximum offered segment counts.
  Both profiles passed builds, targeted Clippy, descriptor/I/O-task tests,
  and real scattered-write regressions. Formatting/diff checks passed with
  no new warnings or initial check failures. Logs:
  `/tmp/vsock-blk-seg.O17eAB/`. Vsock activation and both milestones remain
  pending.

Stage 3 CID/configuration validation is implemented and parent-reviewed:

- Requires at least eight configuration bytes and a guest CID in
  `3..=0xffff_fffe` with a zero upper word. The private reader rejects absent
  or short configuration and missing BAR mappings, then uses the existing
  low/high-32-bit `PciBar::read_u64` once. No generation accessor or retry loop.
- Guest pure-helper tests cover valid/reserved CIDs, nonzero high words with
  otherwise valid low words, and short/extended configuration lengths.
  Debug/release builds, targeted Clippy, and descriptor/I/O-task/filesystem
  regressions passed with no new warnings. Formatting/diff checks passed;
  no initial check failures. Logs: `/tmp/vsock-cid.0J53Yp/`.
- These tests validate the pure contract, not real VMM configuration reads.
  The MMIO wrapper was source-reviewed and remains unactivated. Separate
  generic PCI capability index/range validation is needed before constructor
  integration; real BAR/device coverage remains for activation tests. Neither
  milestone is complete.

Shared PCI capability metadata validation is implemented and parent-reviewed:

- Parse only supported common/device/notify metadata after checking the
  consumed 16/20-byte prefix against configuration-space bounds. Reserved
  types and BAR indices are skipped before indexing; extended capability
  lengths remain accepted. The first supported metadata instance is selected
  for each type, and shared device/notify BARs are mapped only once.
- Guest pure-helper tests cover short/extended lengths, exact-end and
  out-of-range prefixes, reserved types, and BAR indices. Debug/release
  builds, targeted Clippy, descriptor/I/O-task/filesystem regressions, and
  formatting/diff checks passed without new warnings. Parent review corrected
  a missing notification-loop `break` before these gates. Logs:
  `/tmp/virtio-cap-meta.gsqhq1/` and `/tmp/virtio-cap-meta-gate.mNm6aE/`.
- Additional release base-image boots on CHV 52.0 and Firecracker 1.15.1
  passed the same three guest test groups and SSH/SFTP traffic. The temporary
  harness used fresh runtime paths and the shared VM lock. Logs:
  `/tmp/vsock-other-vmm.mz7vi7/`. No vsock device was attached; these are
  launcher/shared-driver checks, not vsock interoperability or milestone gates.
- Malformed hardware metadata was not injected. Mapped MMIO access ranges,
  MSI-X regions, and unsupported I/O BAR selection remain separate work;
  neither milestone is complete.

Shared mapped-configuration access checks are implemented and parent-reviewed:

- Common configuration is checked before its first MMIO access. Block, net,
  and vsock use one device-configuration accessor to validate their consumed
  prefixes; vsock's separate length validator was removed. Notification
  addresses are checked against both the capability and mapped BAR before
  queue use. Checks require the actual field alignment, not aligned lengths,
  and ignore unused extended tails. Hot-path PCI accesses are unchanged.
- Guest tests cover exact-end/short/extended regions, six-byte net config,
  two-byte notifications, misalignment, all checked-add failure boundaries,
  and maximum notification arithmetic. Debug/release builds, targeted Clippy,
  descriptor/I/O-task/filesystem regressions, and formatting/diff checks passed
  without new warnings or initial check failures. Logs:
  `/tmp/virtio-mmio-range.GjqBSs/` and `/tmp/virtio-mmio-gate.AB4j7s/`.
- CHV and Firecracker release base-image boots also passed these guest groups
  and SSH/SFTP with the new range checks. Logs:
  `/tmp/virtio-mmio-other-vmm.qDcdb0/`. No malformed hardware injection or
  vsock activation was performed. MSI-X/BAR initialization checks and the
  separately identified hardcoded-zero queue notification value remain;
  neither milestone is complete.

Shared queue notification values are corrected and parent-reviewed:

- Both notification paths now write the queue index instead of zero, as
  required without `NOTIFICATION_DATA`
  ([Virtio 1.1 section 4.1.5.2](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html)).
  A shared notification address cannot identify the queue from its address
  alone. Suppression, fences, event-index arithmetic, and task counts are
  unchanged. This issue was found by source review, not an initial VM failure.
- The existing guest queue fixture uses test-only mapped register storage
  to inspect real volatile writes for queues 0/1/2, both notification modes,
  suppression, exact write width/offset, and adjacent bytes. All queue and
  completion owners drop before the simulated BAR and its backing storage.
- Debug/release builds, targeted Clippy, and descriptor/I/O-task/filesystem
  regressions passed, as did the same release groups on CHV and Firecracker.
  No new warnings; formatting/diff checks passed. Logs:
  `/tmp/virtio-notify-value.GOkoEO/`, `/tmp/virtio-notify-gate.Aw995F/`, and
  `/tmp/virtio-notify-other-vmm.ZafiEf/`. The initial fixture compile error
  needed a mutable binding; parent review then reduced the register allocation
  to its fully initialized 16 bytes before guest validation. No vsock hardware
  activation or milestone gate is implied. MSI-X/BAR checks remain next.

Shared MSI-X metadata and mapped-region checks are implemented and
parent-reviewed:

- Reject truncated capability prefixes and invalid table/PBA BAR indices
  before field reads or indexing. Validate both complete regions against
  their mapped BARs before table writes. Existing enablement readbacks now
  return initialization errors instead of panicking; block/net propagate
  those errors. No extra hardware reads, tasks, or reset policy are added.
- Guest pure-helper tests cover exact-end/truncated metadata, vector-count
  boundaries, PBA rounding, and exact-end/one-byte-short table/PBA mappings.
  Debug/release builds, targeted Clippy, descriptor/I/O-task/filesystem
  regressions, and the same release groups on CHV and Firecracker passed.
  Formatting/diff checks passed with no new warnings or compile failures;
  the initial formatting check required only line wrapping. Logs:
  `/tmp/virtio-msix.hJGoIK/`, `/tmp/virtio-msix-gate.uTFBso/`, and
  `/tmp/virtio-msix-other-vmm.FAlPEL/`.
- Malformed hardware and enablement failures were not injected; actual
  supported-VMM boots exercise normal MSI-X setup. BAR probing/mapping
  robustness and Q19 remain separate work. No vsock device was activated,
  and neither milestone is complete.

Stage 4 fixed TX pool (D7) is implemented and parent-reviewed:

- One fallible constructor reserves `min(64, (tx_descriptors - 8) / 2)`
  pages and completion capacity for the whole queue before publication.
  Validated synchronous submission retains every completion, restores a
  page on rejected admission, and wakes the drainer for newly posted work.
  Bounded completion polling recycles one returned owner in any order;
  it does not sort TX or account for peer credit.
- Guest queue fixtures cover pool limits, actual descriptor layout/copied
  bytes, empty/nonempty submission wakeups, unreclaimed pending completion,
  completion-driven wakeup, opposite completion order, distinct in-flight
  pages, invalid/oversized input, data saturation with control capacity,
  and a control-filled ring returning a rejected data page. These are
  memory-backed queue tests, not attached-vsock hardware transfers. Existing
  generic premature-completion-drop tests remain; no new pool-drop child
  fixture or client-cancellation coverage is claimed by this increment.
- Parent review removed an unnecessary prepared-TX wrapper and strengthened
  wakeup/rejection coverage before validation. Debug/release builds, targeted
  Clippy, and descriptor/I/O-task/filesystem regressions passed; formatting
  and diff checks passed, with no new warnings or initial check failures.
  Logs: `/tmp/vsock-tx-pool.7bn4lj/` and
  `/tmp/vsock-tx-pool-gate.sf43rI/`. Device construction, runtime pumps, and
  both milestones remain pending.

Stage 6 pure credit arithmetic is implemented and parent-reviewed:

- The dependency-free sys-io helper checks local occupancy, wraps protocol
  counters explicitly, rejects impossible peer advances without changing
  either advertised field, and reports zero allowance after an allocation
  shrink below outstanding bytes. The single-pump API charges only after
  successful synchronous publication; it adds no callback, reservation
  token, rollback ledger, or connection-error policy.
- The actual production source is included in existing guest I/O-task tests.
  Both profiles passed initial/partial/exhausted credit, duplicate/changed
  advertisements, overcharge rejection, atomic invalid updates, intermediate
  counter-wrap values, checked local overflow, forwarding counts, and
  independent state. These numerical tests do not exercise real publication,
  cancellation, IPC page transfer, or a live vsock peer; those remain pending.
- Debug/release builds, targeted Clippy, and guest descriptor/I/O-task/
  filesystem regressions passed with no new warnings. The fixture also
  passes Clippy with `-D warnings` in both profiles; formatting/diff checks
  passed. Final logs: `/tmp/vsock-credit-gate.DFsWDg/`.
- Original sub-agent transcript evidence records a check accidentally using
  the host target, rejected by moto-async's existing Motor-only guard, and a
  strict sys-io Clippy run rejected by existing warnings in untouched code.
  Correct-target checks and ordinary baseline-aware Clippy passed; those
  initial outputs were not saved as log files. No boot work, device activation,
  or Q20 policy was added. Runtime integration and both milestones remain.

Stage 3 initial-buffer notification ordering is implemented and parent-reviewed:

- RX/event preparation now publishes its initial batch without notifications;
  a narrow explicit kick reuses existing suppression and wrapping EVENT_IDX
  arithmetic after DRIVER_OK. Shared device setup separates task start from
  DRIVER_OK without changing block/net callers. Immediate submissions and
  RX/event reposts retain their previous notification path and fences. No
  persistent queue mode, extra boot reads, or additional tasks are introduced.
- Memory-backed guest queue tests inspect notification bytes, batch indices
  and heads, queues 0/1/2, suppression/unsuppression, combined suppression and
  counter wrap, and repeated kicks with no new work. Initial pool calls and
  immediate repost wiring were source-reviewed; the fixture does not emulate
  PCI initialization or a device observing DRIVER_OK.
- Debug/release builds, targeted Clippy, and descriptor/I/O-task/filesystem
  regressions passed, as did these release groups on CHV and Firecracker.
  No new warnings; formatting/diff checks passed. Logs:
  `/tmp/vsock-deferred.D7Hx5d/`, `/tmp/vsock-deferred-gate.zWYckv/`, and
  `/tmp/vsock-deferred-other-vmm.6CjTs4/`. The first fixture compile error was
  an ambiguous byte-slice conversion, corrected with explicit slice bindings;
  the first strict Clippy check rejected existing warnings in unchanged code.
  Parent review added the combined suppression/wrap case before final gates.
- All VM runs used existing block/net devices, without attached vsock hardware.
  The vsock constructor, runtime integration, Q19–Q21, and both milestones
  remain pending.

Stage 3 device constructor and driver facade are implemented and parent-reviewed:

- The crate-private, unactivated constructor follows block/net's `from`
  pattern. It stabilizes and retains the original BAR-owning device before
  creating queues, prepares all three bounded pools, and allocates the outer
  owner before starting queue tasks. Event then RX owners are published and
  installed before DRIVER_OK and the two deferred kicks; no returned-error
  path can abandon published buffers. Shared reset policy is unchanged.
- Separate pool borrows expose synchronous TX submission, TX reclamation,
  ordered RX consumption, and event consumption. TX rejects a foreign local
  CID before touching its pool; CID refresh commits only a validated value.
  The future sys-io runtime must retain the complete driver on cached failure.
- Guest fixtures exercise the production three-pool preparation helper with
  empty/short/extra queue sets, undersized RX/TX, and minimum supported sizes.
  Rejections and preparation publish nothing. Root added mapped notification
  storage to verify actual initial event/RX pool publication makes no MMIO
  writes, then explicit kicks identify queues 2/0 without changing adjacent
  bytes. Returned completions are reclaimed before fixture owners are freed.
- Debug/release builds, targeted Clippy, and descriptor/I/O-task/filesystem
  regressions passed with no new warnings or initial check failures;
  formatting/diff checks passed. Logs: `/tmp/vsock-device.COL6rU/` and
  `/tmp/vsock-device-gate.8HSDNS/`. Constructor status/CID MMIO sequencing,
  failed live initialization, and external facade use remain source-reviewed,
  not fixture-emulated or tested on attached vsock hardware. Runtime pumps,
  lazy service activation, Q19–Q21, and both milestones remain pending.

Shared modern PCI discovery no longer rejects revision zero:

- Removed the revision-register read and stale legacy-device heuristic.
  Modern device IDs, capabilities, and required features still select the
  supported transport. This follows
  [Virtio 1.1 section 4.1.2.2](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html),
  which requires accepting every PCI Revision ID. The issue was identified
  by source/specification review, not a failing supported-VMM boot.
- Existing guest modern/legacy/unknown-ID and feature tests remain the
  relevant contract coverage; no artificial ignored-revision parameter or
  PCI injection seam was added. Debug/release builds, targeted Clippy, and
  descriptor/I/O-task/filesystem regressions passed, as did these release
  groups on CHV and Firecracker. No new warnings or initial check failures;
  formatting/diff checks passed. Logs: `/tmp/virtio-revision.1xA619/`,
  `/tmp/virtio-revision-gate.A29VEj/`, and
  `/tmp/virtio-revision-other-vmm.2mFG6R/`.
- Revision-zero hardware was not injected, and no vsock device was activated.
  M1/M2 remain pending; the Q22 adjustment now recorded in D13 addresses the
  dependency of integrated Stage 5 pumps on the connection/IPC implementation.

Stage 5/6 bounded receive storage is implemented and parent-reviewed:

- One concrete stream buffer owns a pre-reserved byte deque and its credit
  state. The credit state's fixed logical capacity remains authoritative
  even if the allocation is larger. Packet admission is all-or-nothing;
  copying an ordered prefix into already-reserved storage advances forwarding
  by exactly the copied byte count and removes those bytes. There is no
  mutable credit accessor, duplicate occupancy field, or per-stream TX ring.
  Future stream admission supplies D7's 128 KiB capacity; nothing is activated
  or allocated at boot by this private helper.
- Source-included guest tests cover tiny packets, interleaved appends/drains,
  exact fill, rejected packets preserving earlier data/accounting, zero
  operations/capacity, independent streams, and over-wide capacity rejection
  before allocation. Partial destination fills preserve the unused suffix;
  copying again from the empty buffer changes neither bytes nor credit.
- Debug/release builds, targeted Clippy, and descriptor/I/O-task/filesystem
  regressions passed without new warnings or initial failures. Direct fixture
  Clippy with `-D warnings` passed in both profiles; formatting/diff checks
  passed. Logs: `/tmp/vsock-stream-buffer-*.log` and
  `/tmp/vsock-rx-buffer-gate.ZeNVXk/`. These tests copy actual bytes but do not
  reserve real IPC pages, perform DMA, or prove allocator-specific deque
  layout. Runtime pumps and both milestone gates remain pending.

Follow-up decisions approved on 2026-09-15, without additional source changes:

- Q19's reset check (D18), including its one MMIO read per initialization,
  and Q20's connection-local invalid-credit reaction (D19) are approved but
  not yet implemented. Earlier progress entries record implementation status
  at each patch, not outstanding approval requests.
- Q22's foundation/integration boundary is reflected in D13 and the stages
  and validation schedule below. Neither milestone is complete. Q21 is
  deferred under D20; no BAR-layout walk is approved or implemented.

Shared reset completion check (D18) is implemented and parent-reviewed:

- Reset writes zero and reads status exactly once. Nonzero returns an
  initialization error, propagated by block/net/vsock before ACKNOWLEDGE or
  queue startup. There is no polling, retry, task, or transport-reset change.
- Debug/release builds, targeted Clippy, and existing guest descriptor,
  I/O-task, and scattered-write regressions passed on QEMU; the same release
  guest groups passed on CHV and Firecracker. Normal block/net initialization
  exercises the new read. No new warnings or initial check failures;
  selected-toolchain formatting and diff checks passed.
- Logs: `/tmp/virtio-reset.nJa8bu/`, `/tmp/vsock-reset-gate.mlFnfA/`, and
  `/tmp/vsock-reset-other-vmm.FudnJ5/`. The nonzero-status branch remains
  source-reviewed, not injection-tested; no new production test hook was
  added. No vsock device was attached. M1 foundations are ready for D13's
  repeated full gates; neither milestone is complete yet.

M1 foundation milestone is complete at `d77b038e`:

- Three debug and three release main-image build/full-test cycles passed on
  QEMU, with source unchanged throughout the six cycles. Each cycle ran
  `make -j"$(nproc)"` in its selected profile followed by
  `src/tests/full-test.sh` (with `--release` for release). No gate failure,
  retry, timeout increase, or test exclusion was needed.
- Logs: `/tmp/vsock-m1-gate.oGRjOm/build-{debug,release}-{1,2,3}.log` and
  `full-test-{debug,release}-{1,2,3}.log` in the same directory. All six full
  suites finished with the full-test PASS marker and exit status zero.
- This gates the capability, shared-driver/queue, fixed-pool, credit, and
  bounded-storage foundations. It does not claim attached-vsock PCI/DMA,
  peer interoperability, runtime pumps, connection/IPC/native API, or D19's
  integrated reaction. Those remain M2 work under D13. Earlier pending
  milestone statements describe the state at their respective increments.

M2 established-stream state is implemented and parent-reviewed:

- A private helper owns the existing fixed 128 KiB receive buffer and credit
  state. Impossible peer credit marks only that stream reset without changing
  its credit fields or admitting the bad payload. Validated RX drains before
  the retained reset error; permanent peer SEND/RECEIVE flags preserve the
  approved half-close behavior. Wire dispatch, orderly-close phases, local
  shutdown sequencing, IPC ownership, and pumps remain integration work.
- Source-included guest tests cover credit advancement/rejection, reset after
  buffered data, independent streams, both peer half-closes, zero-length
  reads, and exact receive capacity with atomic overflow rejection. These
  run through ordinary systest/full-test, not new boot self-tests or hooks.
- `make base.img systest`, targeted Clippy, and guest descriptor/I/O-task/
  scattered-write tests passed in debug and release with no new warnings.
  Logs: `/tmp/vsock-stream-state-gate.y0JM1x/`. Selected-toolchain formatting
  and strict fixture Clippy also passed. An initial fixture-only literal/
  destination length mismatch was corrected; its failed compilation remains
  in `/tmp/vsock-stream-state.a7xXxC/cargo-check-final.log`.
- No attached-vsock, real IPC, wire RST exchange, or D19 end-to-end coverage
  is claimed by these helper tests. M2 remains pending.

M2's shared socket backend preparation is implemented and parent-reviewed:

- `IpSocketBackend` now groups the NIC index, device notification, local IP
  address, and netstack-handle conversion. Common socket IDs, client
  ownership, rollback, and cleanup ordering are unchanged. Construction is
  explicitly IP-only; no unused vsock socket variant, fake IP address, new
  allocation, or task was added. TCP tuple scans reject non-TCP state before
  accessing the IP backend.
- A `test-native-net` systest selector runs the existing native-driver,
  TCP, and UDP suites in their ordinary-suite order. Their default full-test
  calls remain unchanged. These suites and the complete existing `mio-test`
  suite passed in debug and release, as did base-image/test builds, selected
  formatting, and targeted Clippy. No new warning or gate failure occurred.
  Logs: `/tmp/vsock-ip-backend-gate.jGrqSg/`.
- Discovery follows in the increment below. Socket integration, activation,
  and end-to-end vsock coverage remain pending.

M2's discovery IPC/API increment is implemented, parent-reviewed, and has
passed its debug/release incremental gate:

- `moto_io::net::vsock::availability(&NetClient)` uses the existing driven
  channel/RPC, without a reservation or device activation. The appended
  command preserves existing wire values. Sys-io caches trusted peer
  capabilities on the first query, checks authorization before request
  shape/device presence, and returns native errors directly.
- Sys-io retains the first dormant vsock device and ignores extras. Its
  shared endpoint starts with vsock but no usable IP devices, without DNS
  writes or IP-runtime poll/stats/recovery tasks. With neither IP nor vsock,
  the endpoint stays disabled. Block-device rejection and the NIC vector
  remain unchanged.
- The no-IP test exposed a preexisting NET ownership defect: queue tasks
  outlived an unconfigured device whose PCI metadata they still referenced.
  No invalid access was observed; no RX buffers had been posted. The runtime
  now retains the existing unused-device vector for its permanent lifetime,
  with no new allocation/task. The stale `RxPacket` Drop explanation and
  unused global/unsafe `Send` implementation were removed or corrected.
- Ordinary systest covers absent-device errors, repeated discovery with zero
  reservations, native/raw capability denial, malformed raw requests, and
  continued UDP use after denial. `full-test.sh` now also invokes a required
  `test-vsock.sh` phase: CHV boots an isolated, preinstalled-systest image
  with IP/loopback disabled, first with vsock and then without it. The
  explicit `vsock-test.img` target does not join default image builds. CHV
  uses the existing QEMU lock domain; PTY/CR console input and exact guest
  verdicts avoid relying on IP. This first phase uses the approved development
  VMM; D16's selected-VMM generalization remains pending.
- This increment includes its permanent VM test wiring so present/no-IP
  coverage is not deferred. No real vsock DMA, peer data transfer, activation,
  or complete M2 gate is claimed.
- Base/test builds, selected formatting, targeted Clippy, all 21 existing
  imager tests, native TCP/UDP/driver tests, and the complete `mio-test` suite
  passed in both profiles with no new warnings. The permanent CHV phase
  passed both present/disabled cases in both profiles, including strict child
  teardown. Additional IP-enabled CHV discovery and scattered filesystem
  writes passed in both profiles. Final evidence is under
  `/tmp/vsock-discovery-final.EijLfP/`: `cwd-corrected/` for debug build/native
  gates, `teardown-corrected/` for release build/native gates,
  `vsock-{debug,release}-final.log`, and `chv-present-{debug,release}.log`.
  The final permanent phase took about 4 seconds debug and 27 seconds release,
  including its explicit image build; full-test's timeout is unchanged.
- Diagnostic history is preserved: the initial private-RPC compile error in
  `/tmp/vsock-discovery.zMlDFp/check-1.log`; the temporary overlay's missing
  `[devices]` table and CHV's refusal of FIFO input in
  `/tmp/vsock-discovery-gate.xZP35C/`; and an imager test invocation that
  missed its directory-local Cargo configuration plus wrapper-first PTY
  teardown's child-reaping race in `/tmp/vsock-discovery-final.EijLfP/`.
  Release also exposed a Rush size-control prefix on the guest PASS line;
  the harness now reuses the existing console filter while retaining raw logs
  and exact verdict text. Teardown now stops the owned CHV child and lets its
  wrapper reap it. No retry, delay workaround, relaxed assertion, or timeout
  extension was added; corrected phases were rerun for those specific fixes.

M2's bounded tuple/port admission helper is implemented and parent-reviewed:

- The secondary index maps full local/peer CID-and-port tuples to opaque
  socket IDs; it owns no connection state or client authority. Separate
  listener entries and the 64-stream/32-listener limits use fallible,
  on-demand storage. Entries remain charged until explicit removal, including
  accepted children retaining their local port after their listener drops.
- Source-included guest fixtures cover 32-bit ports, invalid/reserved ports,
  full-tuple lookup, automatic-allocation collisions and wrap, unchanged
  counts/cursor on logical admission failure, both limits, and removal/reuse.
  Allocator-failure injection is not claimed. No activation or task is added.
- Debug/release base/test builds, targeted Clippy, and guest descriptor,
  I/O-task, and scattered-write regressions passed with no new warnings:
  `/tmp/vsock-admission-gate.1VLkuM/`. Selected formatting and strict fixture
  Clippy passed. Initial strict Clippy attempts also rejected unchanged
  dependency/sys-io baseline lints; their logs remain under
  `/tmp/vsock-admission.DPF8YH/`. Production connection admission, wire/IPC
  dispatch, real-peer traffic, and the complete M2 gate remain pending.

The explicit standard raw-image prerequisite from D16 is implemented and
parent-reviewed:

- `make raw.img [BUILD=release]` produces `motor-os.img` from the same
  `motor-os.yaml` and assembly inputs as `main.img`, using a small imager
  `--raw-output` override. It is not a dependency of default `make`, `all`,
  or `images`. Main/raw recipes no longer delete one another's outputs.
- Existing full-test-wired imager and image-format tests cover content
  configuration parity, invalid output names without partial mutation,
  explicit-only make selection, and Firecracker's raw-standard filename.
  All 22 imager tests, formatting, shell checks, and targeted imager Clippy
  passed in debug/release with no new warnings.
- Explicit raw/main builds passed in both profiles; checksum checks proved
  each build preserved the other's artifact, and `qemu-img info` confirmed
  the formats. Firecracker booted each raw standard image and passed native
  driver/TCP/UDP, complete `mio-test`, and scattered filesystem writes, with
  strict owned-process teardown. Logs: `/tmp/vsock-raw-image-gate.s6O9tf/`.
- `full-test.sh --vmm fc` selection, cross-VMM boot checks, and peer-vsock
  coverage remain later D16/M2 integration; no developer-image FC support is
  added or claimed.

The native stream TX-page reuse seam is implemented and parent-reviewed:

- `PendingStreamTx` now holds the existing pending IPC pages, byte copying,
  partial-page append, marker publication/rollback under the same lock, and
  bounded multi-page claims. TCP uses it immediately; TCP wire messages,
  readiness, cancellation, Drop ordering, and its allocation/copy behavior
  are unchanged. No new framework, public API, or test hook is introduced.
- Selected formatting, Motor-target checks, and Clippy passed in both
  profiles with no new warnings. Debug/release base/test builds and the
  existing native-driver/TCP/UDP and complete `mio-test` suites passed on
  QEMU: `/tmp/vsock-pending-tx-gate.mPAeWb/`. The same frozen sources also
  passed those guest suites on Firecracker during the raw-image gate above.
  These cover existing backpressure, partial writes, cancellation, concurrent
  writers, and teardown through ordinary full-test-wired tests.
- The helper is ready for the native vsock consumer. Connection transitions,
  vsock IPC/pumps and real-peer traffic remain unimplemented. Q24–Q25 were
  subsequently approved in D22; their rejection branches remain to be added.

M2's per-connection receive transitions are implemented and parent-reviewed:

- A concrete connection owns one established-stream buffer and tracks
  connecting, established, or a retained terminal cause. It handles outgoing
  RESPONSE/refusal, incoming early data, credit messages, permanent peer
  shutdown, and RST without adding another socket registry or owner.
- D19/D22 rejection returns a connection-local RST action, preserves old
  credit/data atomically, and drains previously validated RX before error.
  Late packets cannot replace the first terminal cause; RST never elicits
  RST. Payload after peer SEND shutdown cannot appear after EOF.
- The existing guest I/O-task fixture source-includes the actual helper and
  uses the driver's wire types. Transition, invalid-credit, over-credit,
  buffered-drain, and independent-connection cases passed in both profiles,
  alongside descriptor and scattered-write filesystem regressions. Both
  base-image/systest builds, targeted Clippy, and formatting passed with no
  new warnings. Evidence: `/tmp/vsock-connection-gate.JpUrp1/`.
- These are state-helper tests, not actual packet publication, IPC, native
  API, or peer interoperability tests. The common runtime must execute the
  returned actions; local shutdown/cleanup and M2 integration remain.

Firecracker's opt-in vsock runner configuration is implemented and reviewed:

- `MOTO_FC_VSOCK_UDS` adds guest CID 3 and an absolute UDS path; an unset or
  empty value preserves the existing no-vsock configuration. Invalid paths
  fail before launching the VMM. The runner now holds the same host-wide VM
  lock as QEMU and Cloud Hypervisor across `exec`.
- The existing full-test-wired image-format regression checks absent/present
  JSON, invalid paths, conflicting locks, and lock lifetime in the executed
  VMM. Shell syntax and that regression passed. Actual Firecracker 1.15.1
  guests passed capability-gated discovery with vsock present and absent,
  plus scattered filesystem writes, in debug and release with strict
  owned-process cleanup. Evidence: `/tmp/vsock-fc-runner-gate.VbSdmM/`.
- This is runner/discovery coverage, not device activation or peer traffic.
  Selected-VMM full-test wiring and full M2 coverage remain pending.

M2's local shutdown/terminal-state helper is implemented and reviewed:

- Requested, queued, and published shutdown flags are distinct and permanent.
  SEND stops new writes immediately; all shutdown publication waits for the
  owner's accepted-TX drain boundary. An incoming RST is orderly only after
  published local BOTH or observed peer BOTH, not merely queued shutdown.
- Peer BOTH retains buffered RX until it drains, then produces one orderly
  RST action. Clean close yields EOF after data; protocol rejection remains
  an error even after shutdown flags. Connect timeout, transport reset, and
  cleanup expiry preserve the first terminal cause. Cleanup starts once and
  expiry requests one forced reset; actual timers and tuple release stay with
  the future runtime owner.
- Source-included guest transition fixtures, descriptor ownership, and
  scattered filesystem writes passed in debug/release, along with both
  base-image/systest builds, formatting, and targeted Clippy without new
  warnings. Evidence: `/tmp/vsock-shutdown-gate.WPTEcN/`. These are helper
  transitions, not proof of actual TX drain, timers, IPC, or peer close.

QEMU's shared-memory opt-in (D15) is implemented and parent-reviewed:

- `MOTO_SHARED_MEM=1` selects shared memfd RAM, using hugetlb pages only when
  the existing pool check succeeds, and never combines it with `-mem-path`.
  Default RAM arguments, CPU/memory budgets, and ordinary boots are unchanged.
- The existing image-format regression covers default/opt-in arguments and
  the incompatible-argument exclusion. Shell checks passed. Actual QEMU
  10.2.1 guests with the installed `vhost-device-vsock` 0.3.0 backend passed
  device-present discovery and scattered filesystem writes in both profiles;
  both owned processes were stopped and reaped after each run. Evidence:
  `/tmp/vsock-qemu-shared-gate.8fvewn/`.
- Actual shared-memory validation used ordinary memfd pages, not a hugetlb
  pool. No device activation, application peer traffic, or throughput result
  is claimed by this runner/discovery gate.

The authorized shared NET subchannel fix (D23) is implemented and reviewed:

- TCP connect rejects an invalid index before route/port work; the single
  socket-creating UDP path rejects it before port/accounting mutation for
  both bind forms. Valid indices and existing TCP/UDP wire formats are
  unchanged; no shared helper or broad validation framework was added.
- The existing guest native-net route sends raw requests with indices 4 and
  255 through all three operations, checks `InvalidArgument` and unchanged
  live/total socket/client counts, then proves valid TCP and UDP use and
  cleanup on that same channel.
- Debug/release base-image/systest/mio builds, native-net and complete mio
  guest suites, formatting, and targeted Clippy passed without new warnings.
  Evidence: `/tmp/vsock-subchannel-gate.tJ4eM0/`. The agent's initial strict
  systest Clippy rejection of the two preexisting allocation-benchmark
  precedence warnings is retained in `/tmp/net-subchannel.u84imZ/`; ordinary
  Clippy and the final gates passed with those baseline warnings unchanged.

M2's outgoing connect IPC codec is implemented and parent-reviewed:

- Appends vsock stream command values without changing TCP/UDP values. The
  address is two `u32` fields, not an IP address; connect carries the peer and
  existing reservation index, while success returns the common socket ID
  and local address. Reserved bytes, flags, addresses, and subchannel indices
  are checked in release. Syntactically valid non-host CIDs remain a runtime
  support decision; native error replies are decoded before success fields.
- Literal wire/negative fixtures run through ordinary guest native-net tests.
  Debug/release base-image/systest/mio builds, the complete native-net and mio
  guest suites, formatting, and targeted Clippy passed without new warnings.
  Evidence: `/tmp/vsock-connect-codec-gate.lhTAqw/`.
- These are codecs and executable fixtures, not live connect handlers or
  native streams. Control/page codecs and the functional runtime remain next.

D16's common runner/image selection and SSH-startup preparation is implemented
and parent-reviewed:

- A small sourced helper resolves the approved image/profile/VMM matrix;
  `start_test_vm` takes the resolved runner and diagnostic label. Existing
  full-test/candidate consumers still explicitly select QEMU. Defaults,
  image overrides, QEMU arguments, CPU/RAM budgets, and owned-process cleanup
  are unchanged; the suite-wide `--vmm` option is not exposed prematurely.
- Existing image-format and developer-memory mocks cover the matrix and
  preserved caller behavior. Shell checks passed. Actual QEMU native-net/mio
  and CHV/Firecracker no-device discovery/filesystem guests passed through
  the generalized helper in both profiles, with each VMM stopped and reaped.
  Evidence: `/tmp/vsock-connect-codec-gate.lhTAqw/` and
  `/tmp/d16-selection-corrected.Hkg7iZ/`.
- Serial-console phases, selected-VMM CLI propagation, and permanent boot
  checks remain required before claiming D16 or M2 completion.

M2's shutdown/close/state-notification IPC codecs are implemented and reviewed:

- Shutdown carries nonzero RECEIVE/SEND flags and a zero payload; close is
  handle-only. Socket ownership and stale-handle errors stay server-side.
  State events carry cumulative local-direction/terminal flags with `E_OK`
  status and a separate native reset/configuration-error cause. Orderly
  termination has no error cause. Invalid flags, causes, and reserved payload
  bytes are rejected in release without copying TCP's state enum or mapper.
- Ordinary guest native-net wire fixtures, the complete native-net/mio
  suites, base-image/systest/mio builds, formatting, and targeted Clippy passed
  in debug and release without new warnings. Evidence:
  `/tmp/vsock-control-codec-gate.9IyTY2/`. Functional shutdown/drain/close
  behavior still requires the runtime/native stream integration.

M2's shared stream page codecs are implemented and parent-reviewed:

- TCP and vsock use the same single-page TX/RX encoder and multi-page TX
  encoder/decoder. TCP's public functions, wire layout, limits, and validation
  behavior remain unchanged. The vsock decoder additionally checks its own
  command before recovering pages; no second page-ownership implementation
  or transport-specific allocator was added.
- Ordinary native-net fixtures allocate real IPC pages and verify single-
  and multi-page fields, contents, ownership recovery, and invalid commands
  and lengths. Debug/release base-image/systest/mio builds, complete
  native-net/mio guest suites, formatting, and targeted Clippy passed with
  the preexisting warnings unchanged. Evidence:
  `/tmp/vsock-page-codec-gate.x8XejM/`. Live page delivery still requires the
  outgoing runtime/native stream integration.

M2's first outgoing vertical is implemented, parent-reviewed, and passes its
incremental gates; the complete M2 milestone remains pending:

- Connect, native stream I/O, directional shutdown, lazy device activation,
  independent device pumps, common socket ownership, and client teardown are
  wired together. Bind/listen/accept and the remaining M2 coverage are pending.
- This is a larger coherent integration patch: the live queue pumps, server
  socket/page ownership, native routing, and real-peer fixture must work
  together to exercise the first functional stream. The preceding wire,
  queue, and pure-state foundations were separate small patches; subsequent
  cancellation, listener, and launch work remains incremental.
- Debug base/systest/mio and standard-image builds passed. Release standard
  image/systest builds passed during diagnosis. Debug/release sys-io Clippy
  retains its baseline 31/29 warnings; native moto-io's strict checks pass.
  Systest retains its existing two allocation-benchmark warnings.
- The first CHV debug run passed echo sizes 0, 1, 4095, 4096, 4097, and 65536,
  plus 1 MiB simultaneous traffic in each direction. Guest-initiated SEND-only
  shutdown then failed: the host timed out waiting for Unix-socket EOF before
  sending its reply. The peer-initiated half-close case was not reached.
- Targeted diagnostics preserved that failure in debug and release. CHV's
  own packet log proves it received 4096-byte and 4-byte RW packets followed
  by SHUTDOWN with flags 2 on the same tuple. At the host's 30-second read
  timeout, its close caused CHV to send SHUTDOWN flags 3 with `fwd_cnt=4100`.
  This isolates the test's incorrect EOF dependency, not missing publication
  of Motor's shutdown or a passing acceptance run (D24).
- Evidence: `/tmp/vsock-outgoing-gate.P6UYYi/`, initial run
  `/tmp/test-vsock.9u3REW/`, and decisive VMM packet trace
  `/tmp/test-vsock.bBrj6i/runtime.*/chv/cloud-hypervisor.log`. Earlier diagnostic
  guest traces were incomplete because the console dropped burst records;
  the final diagnostic used CHV's existing debug logging without Motor
  instrumentation. All temporary Motor tracing and case filtering were
  removed. Preserve this original failure alongside the corrected fixture's
  subsequent results; a later pass alone is not the diagnosis.
- A temporary Linux 7.0.0-31 guest reproduced both original shutdown tests
  on unchanged CHV, QEMU, and Firecracker: guest `SHUT_WR` succeeds but the
  host times out waiting for EOF, and host Unix `SHUT_WR` gives Linux EOF
  followed by `BrokenPipe` on write. Baseline echoes succeed on CHV and
  Firecracker. Evidence is under
  `/tmp/vsock-linux-reference.ojIL7v/`; the reference probe is diagnostic-only,
  not a new test prerequisite or regular host test suite. The corrective
  two-stream fixtures in D24 now pass the live incremental gate below.
- Review also identified that a cleanup timer must cancel when its connection
  terminalizes, rather than leaving a weak-reference task asleep for the rest
  of its eight-second budget. The correction now waits on the existing
  notifier and one fixed deadline without retaining the socket. Debug Clippy
  and release Clippy pass with the baseline warnings; the live gates below
  include normal connection teardown. No M2 milestone run is claimed.
- The corrected QEMU debug run passed all guest cases, then exposed a second
  test-harness error: it rejected status 33 after requesting guest shutdown.
  Motor writes `0x10` to the configured `isa-debug-exit` device; QEMU encodes
  this as `(0x10 << 1) | 1`. Accept that result only for QEMU after an owned
  shutdown request, continue rejecting other unexpected exits, and print the
  overall PASS only after owned teardown. Evidence: the original
  `corrected-qemu-debug.log` and the successful verification
  `corrected-qemu-debug-exit-status.log` in the outgoing gate directory.
  See [QEMU's debug-exit implementation](https://github.com/qemu/qemu/blob/master/hw/misc/debugexit.c).
- Final incremental validation passed in debug and release: base, standard,
  explicit raw, systest, and mio builds; ten real-peer cases on each of QEMU,
  CHV, and Firecracker; queue/task/descriptor fixtures; the complete native-net
  and mio guest suites; and the complete currently wired `test-vsock.sh`
  phase. The latter runs QEMU outgoing tests followed by CHV's IP-disabled
  attached/disabled serial cases; D16's all-selected-VMM propagation is still
  pending. All owned VMMs and peers were reaped.
- The raw guest regressions now check CAP-first denial for valid and
  malformed connects and stream controls, malformed authorized requests,
  absent-device connect, and stale handles. Attached discovery remains idle:
  it never issues a valid connect. Tests use the existing discovery/native-net
  routes, transitively reached by full-test. Formatter, shell syntax, strict
  native moto-io Clippy (default and `netdev`), and targeted sys-io/systest
  Clippy pass without new warnings. Final evidence is the `corrected-*` and
  `admission-*` logs in `/tmp/vsock-outgoing-gate.P6UYYi/`.

M2's native read/write waiter-cancellation fixtures are implemented and gated:

- Cancel `readable`/`read_future` before host data and full close; cancel
  `writable`/`write_future` after filling all sixteen IPC pages without
  yielding. An explicit role-consumed acknowledgment makes that page-capacity
  check deterministic. Live I/O then resumes, with exact 80 KiB TX validation.
- Check canceled-waker counters only after the driver drains and reservations
  return to zero. The test uses public native APIs and the existing host peer;
  no production hooks, retries, or shutdown/timeout changes were added.
- The complete outgoing phase (now twelve cases), builds, and targeted
  systest Clippy passed on CHV in debug and release; the two preexisting
  systest warnings remain unchanged. Evidence:
  `/tmp/vsock-waiter-cancel-gate.E7I0no/`. These cases are wired transitively
  into full-test; connect cancellation and the remaining M2 cases are pending.

M2's connect-cancellation and queued-TX Drop fixtures are implemented and gated:

- Dropping an unpolled connect releases its reservation immediately. Dropping
  an established stream after accepting 64 KiB without yielding delivers the
  exact bytes before whole-stream close. A separately canceled, locally queued
  connect is allowed to succeed late; the host verifies rollback closes it.
- Driver exit, zero remaining reservations, and no canceled-waker invocation
  are checked through public APIs. No production hooks or retries were added;
  this does not claim cancellation at every response-dispatch boundary.
  In particular, this case retains two live reservations. A later diagnostic
  reproduced a final-reservation cleanup gap with a retained `NetClient`;
  Q30 records the evidence and proposed lifecycle fix.
- All fourteen outgoing cases, builds, and targeted systest Clippy passed on
  CHV in debug and release, without new warnings. Evidence:
  `/tmp/vsock-connect-cancel-gate.UvPKLu/`. The existing full-test phase reaches
  these cases transitively; listener implementation and the remaining M2
  integration/coverage are still pending.

M2's listener bind/drop IPC contract is implemented and parent-reviewed:

- Append listener command numbers without changing existing values. Bind
  carries only a 32-bit port; sys-io supplies the local CID and fixed backlog.
  Handle-only drop uses the existing nonzero-ID RPC/zero-ID fire-and-forget
  convention; a successful RPC acknowledges local removal, not peer cleanup.
- Literal wire, reserved-field, high-port, identity, and native-error fixtures
  run through ordinary native-net/full-test. Debug/release base, systest, and
  mio builds, queue/task fixtures, full native-net/mio guest regressions, and
  targeted Clippy passed with no new warnings. Logs:
  `/tmp/vsock-listener-bind-codec-gate.RdOIia/`. The sandbox-rejected launch
  (no KVM/socket access, before guest boot) is retained under `sandbox-launch/`;
  the actual guest gates used host access. Runtime listeners are not yet added.

M2's listener accept IPC contract is implemented and parent-reviewed:

- Accept supplies the existing bounded subchannel index and listener handle;
  success returns a new stream handle and full-width local/peer addresses.
  Native errors precede success-field decoding, with zero reserved bytes.
- Literal layout, identity, invalid subchannel/flags/address/reserved-field,
  and error fixtures execute through native-net/full-test. Debug/release
  base/systest/mio builds, queue/task/descriptor fixtures, complete native-net
  and mio guest regressions, formatting, and targeted Clippy passed without
  new warnings. Logs: `/tmp/vsock-listener-accept-codec-gate.uXMpfv/`.
  This defines the wire contract only; incoming admission and accept delivery
  remain integration work.

M2's unread-stream progress fixture is implemented and parent-reviewed:

- Leave readable data untouched while an unrelated stream completes a framed
  round trip; then validate an exact ordered 1 MiB transfer and ordinary
  driver/reservation cleanup. The host retains the data connection until the
  guest acknowledges completion. No timing-based saturation assertion is used.
- This proves independent progress and lossless resumption, not an observed
  128 KiB/64 KiB saturation threshold: public APIs expose no occupancy counts,
  and host UDS buffering cannot identify which layer holds queued bytes.
- All fifteen outgoing cases, builds, targeted Clippy, formatting, and shell
  checks passed on CHV in debug and release with no new warnings. Evidence:
  `/tmp/vsock-stalled-reader-gate.mLHjs8/`. Full-test reaches the added case
  through its existing vsock phase; remaining M2 coverage is still required.

M2's sys-io listener bind/drop ownership slice is implemented and parent-reviewed:

- Listener state lives in the existing socket/client maps, with only a
  secondary port index. CAP validation precedes decode and lazy activation;
  bind is transactional, and acknowledged drop removes local ownership before
  replying. The bind address is a snapshot at synchronous admission; a later
  transport reset may refresh the listener CID, even before reply delivery.
- Raw guest checks cover explicit/high and automatic ports, collision,
  foreign/stale drop, drop/rebind, CID consistency, denial, and absence. The
  existing tuple fixture verifies CID refresh preserves listener IDs/ports
  and old stream tuples while new children use the refreshed CID. This is not
  live transport-reset injection. First outgoing use still activates by connect.
- Debug/release builds, complete native-net/mio and task/descriptor guest
  regressions, the full currently wired CHV vsock phase, formatting, and
  targeted Clippy passed without new warnings. Evidence:
  `/tmp/vsock-listener-bind-runtime-gate.EpFQAN/`. Tests remain transitively
  wired into full-test. Peer REQUEST/backlog/accept handling and native
  `VsockListener` are not yet implemented; Q28 awaits a pending-accept bound.

D16's selected-VMM System-console path is implemented and parent-reviewed:

- `test-system-tty.sh` accepts the shared selector, retains its raw image,
  and uses one narrow serial-launch helper. CHV gets a PTY with child-first
  teardown; QEMU/FC retain FIFO input. Each owned process is waited once,
  ownership clears before post-wait validation, and unexpected exits fail.
- Existing System-console guest tests and their builds passed on QEMU, CHV,
  and Firecracker in both debug and release. CLI rejection/shell checks also
  passed; developer-image FC is rejected before building. No developer-image
  run is claimed. Logs and saved serial transcripts:
  `/tmp/vsock-d16-system-tty-gate.zE9Za4/`.
- Full-test already reaches the default System-console path. TUI, terminal
  size, discovery selection, other-VMM boot checks, and final full-suite
  selector propagation remain D16 work; no VMM binary/source was changed.

D16's selected-VMM TUI path is implemented and parent-reviewed:

- `test-tui.sh` uses the same serial helper and selected standard image,
  including the explicit raw-image target for FC. Console input uses carriage
  return consistently; existing TUI, stdio, Ctrl+C, rmux, and SSH assertions
  are unchanged. Developer-image FC fails before any build or launch.
- All existing standard-image cases and their builds passed on QEMU, CHV,
  and FC in debug and release, including owned-process teardown. CLI
  rejection, syntax, and diff checks passed. Evidence and saved consoles:
  `/tmp/vsock-d16-tui-gate.htNovh/`. Developer-image validation and final
  full-suite selector propagation remain pending; full-test already reaches
  this script using its default QEMU selection.

The outgoing host harness now clears each owned PID immediately after its
sole `wait`, before checking the exit status. Review found that an unexpected
exit previously left ownership set while `set -e` entered EXIT cleanup,
causing a second wait on an already reaped process. Pre-wait failures retain
ownership for cleanup; unexpected exits still fail. All fifteen outgoing
cases and owned teardown passed on QEMU in debug and release, with syntax
and diff checks: `/tmp/vsock-outgoing-ownership-gate.qeS5wh/`. This is a
test-only correction, not a VMM or guest-runtime change.

D16's selected-VMM terminal-size path is implemented and parent-reviewed:

- `test-terminal-size.sh` uses the shared selector and serial lifecycle,
  including FC's explicitly built standard raw image. Existing resize,
  editor, rmux, and SSH assertions remain unchanged; developer-image FC is
  rejected before building.
- The first CHV run exposed a harness bug: rmux refresh used doubled Ctrl+A
  to pass QEMU's monitor, but CHV/FC deliver both bytes directly to the guest.
  Only QEMU now doubles the prefix. The original failure is preserved in
  `/tmp/vsock-d16-terminal-size-gate.uHhSg4/`; no timeout, assertion, or VMM
  change was needed.
- All cases and builds then passed on QEMU, CHV, and FC in debug and release,
  including owned teardown. CLI rejection, syntax, and diff checks passed.
  Logs and saved console/editor evidence:
  `/tmp/vsock-d16-terminal-size-fixed-gate.bhpiVj/`. Full-test already reaches
  the default path; developer-image validation and suite selector propagation
  remain pending.

M2 cleanup review and listener-capacity coverage are complete for this slice:

- After a fatal device failure, retained RX/event DMA buffers still get
  reclaimed/reposted, but their contents no longer create protocol work.
  Previously a late packet could set `pending_reset` on a terminal stream
  although the failed submit pump could never publish that reset, pinning
  the stream; malformed refusals could also refill the control queue.
  This failure branch was source-reviewed, not exercised by a new injection
  hook. Normal DMA handling and pump fairness are unchanged.
- The existing raw listener test now fills all 32 slots, checks that the
  next bind returns `OutOfMemory`, and proves acknowledged drop permits a
  same-port replacement with a new handle, followed by complete cleanup.
- Debug/release builds, task/descriptor and complete native-net/mio guest
  regressions, and the full CHV vsock phase passed. Formatting, diff, and
  targeted Clippy checks passed with unchanged baseline warnings. Evidence:
  `/tmp/vsock-failure-quota-gate.A3pv6o/`. M2 remains incomplete.

M2's incoming REQUEST/backlog slice is implemented and parent-reviewed:

- A listener has eight pre-reserved FIFO child IDs; connections remain in
  the common socket/client maps. Admission reserves receive storage and
  control capacity before publishing RESPONSE. Listener drop abandons
  unconsumable bytes and retains each locally required reset until it is
  published; an already received peer RST does not provoke a reset loop.
  Reset/failure also removes unaccepted children. Admission and teardown
  land together in this larger slice because RESPONSE makes the connection
  live to its peer.
- The initial QEMU debug gate failed on its first host CONNECT. Targeted
  existing-test diagnostics confirmed a valid REQUEST with source port zero;
  our tuple admission wrongly applied the native connect-target restriction.
  Admission and accept-response codecs now preserve all `u32` source ports,
  with zero/MAX fixtures and unchanged native destination restrictions (D8).
  Original evidence: `/tmp/vsock-incoming-backlog-gate.0nqaJU/` and
  `/tmp/vsock-incoming-qemu-diag.1Jhh4U/`. No VMM/backend change was made.
- All sixteen peer cases passed on QEMU, CHV, and FC in both profiles after
  removing temporary diagnostics. The new case proves eight handshakes,
  ninth-connection refusal, listener-drop closure, and same-port rebind.
  Host early writes do not prove guest delivery before an independent sync
  frame; buffered-RX/reset semantics have source-included fixture coverage,
  while integrated early-data delivery awaits accept.
- Debug/release builds, complete native-net/mio and task/descriptor guest
  regressions, CHV's full vsock phase, formatting, and targeted Clippy passed
  with unchanged baseline warnings. Evidence:
  `/tmp/vsock-incoming-backlog-fixed-gate.PyOX7R/`. Native accept, owner-channel
  loss coverage, and the remaining M2 gates are still pending.

M2's current-CID query is implemented and parent-reviewed:

- `VsockLocalCid` appends a command without changing existing values.
  `moto_io::net::vsock::local_cid(&NetClient)` needs no reservation and
  lazily activates only after CAP validation. The reply is a CID snapshot
  when sys-io handles the query, not a promise against later transport reset.
- Guest tests cover canonical wire fields, repeated present/absent queries,
  CAP-first denial, malformed requests, IP-disabled activation, and pending
  query failure on an existing native channel-failure fixture. Status is
  checked before success decoding so synthetic channel errors remain
  `NotConnected` rather than becoming `InvalidData`.
- Debug/release builds, complete native-net/mio and task/descriptor guest
  regressions, CHV's full vsock phase, formatting, and targeted Clippy passed.
  Strict moto-io Clippy passed with and without `netdev`; other baseline
  warnings were unchanged. Evidence: `/tmp/vsock-local-cid-gate.HCOY3a/`.

M2's native listener bind/drop API and owner-channel cleanup are implemented
and parent-reviewed:

- `VsockListener::bind_reserved` reuses `PendingBind` and its rollback-owned
  reservation. Validate status before decoding, and keep rollback armed until
  the success payload is valid. Drop uses the existing guaranteed teardown
  queue; no new listener map, cached CID, or background driver is added.
- `socket_addr_async` combines the immutable bound port with a fresh CID
  query. Guest coverage includes ordinary bind/drop, invalid/unpolled bind,
  cancellation after staging, and the existing failed-channel mechanism.
  The failed-channel fixture uses its own runtime thread, preserving the
  existing one-driver-per-runtime topology.
- The new `incoming-owner-drop` peer case fills the eight-child backlog,
  closes its owning IPC channel without a listener-drop RPC, requires host
  EOF on all children, then rebinds the same port after that acknowledgment.
- Both profiles built and passed all seventeen peer cases on QEMU, CHV, and
  Firecracker. Existing task/descriptor/native-net/mio guest regressions and
  CHV's present/disabled IP-free discovery passed in both profiles. Strict
  moto-io Clippy (default and `netdev`) is clean; other targeted warning
  baselines are unchanged. Evidence: `/tmp/vsock-listener-native-gate.9ewOn3/`.
  All cases remain transitively included in full-test. Accept and Q30's
  final-slot cancellation repair remain pending.

D16's IP-disabled discovery phase now uses the selected VMM:

- `test-vsock.sh` runs its existing present/disabled guest assertions on
  QEMU, CHV, or Firecracker, including capability/error precedence and current
  CID queries without IP networking. It reuses the strict serial helper and
  preserves the same guest commands, status markers, liveness checks, and
  deadlines. QEMU alone starts the pinned UDS backend/shared RAM; each run
  owns and reaps its processes exactly once.
- All three VMMs passed the full vsock phase in debug and release, including
  all seventeen peer cases. Evidence: `/tmp/vsock-d16-discovery-gate.AtDQcd/`.
  Observed phase times, including incremental image builds, were 26/32/18
  seconds for QEMU/CHV/FC debug and 37/14/13 seconds for release. These are
  harness timings, not the outstanding stage 15 performance measurements.
- Shell syntax, invalid/duplicate option checks, and early developer-FC
  rejection pass. The isolated raw discovery image remains test-only; normal
  suite images and formats are unchanged. Full-test selector exposure,
  non-selected boot checks, and developer selector propagation remain pending.

The first D16 full-suite run exposed an unrelated pressure-test race, now
corrected without changing production memory admission:

- The queued file-lock waiter's TLS destructors could run concurrently with
  the fresh FS client's large, conservative mapping reservation. A captured
  stack showed a 192-byte TLS-map allocation correctly refused at the user
  memory floor. `is_finished()` alone does not wait for TLS destruction.
- Join the waiter before starting the independent fresh-client probe, using
  the existing ten-second grant budget. Both the under-pressure grant and
  fresh-client refusal checks remain; release the squeeze before reporting
  any failure. No retries, larger timeout, stdlib, or moto-rt changes.
- Original failure: `/tmp/vsock-d16-full-test-gate.vDIsxi/`. The allocation
  stack and admission arithmetic are retained in
  `/tmp/vsock-bounded-stack-diagnostic.kShuWf/diagnosis.md`. The corrected
  diagnostic passed 33 pressure episodes in the ordinary systest sequence
  (`/tmp/vsock-shared-progress-regression.BCjdkB/green.log`). Temporary
  diagnostics are removed. The reviewed shared-fix stack passed clean
  debug/release builds and full suites (738/606 seconds), including both
  ordinary pressure episodes, in `/tmp/vsock-shared-fixes-clean-gate.5GQhNV/`.
  This is the incremental D13 gate, not the outstanding M2 repeated gate.

The observed shared virtio wake stall was in Motor's local executor, not the
VMM or completion ordering:

- Live diagnostics found a current interrupt threshold and an already
  delivered, latched IRQ, but 96 consecutive waits containing that device
  future had returned `BadHandle`. Kernel wait-set validation rejects the
  whole set before delivering valid wakes. The runtime removed only one
  disconnected registration per I/O turn, delaying device progress behind
  a batch of disconnected IPC clients.
- `LocalRuntimeInner::wait` now drains recognized invalid registrations in
  the same turn, reusing its handle vector. Each pass removes an entry;
  subsequent passes are nonblocking because error waiters may already be
  runnable. Preserve unknown-handle behavior and do not repeat the processed
  wake target. No kernel, VMM, backend, or syscall change is needed.
- The existing guest async test now checks a latched healthy wake behind
  eight dropped registrations plus a retained bad future, and the blocking
  scheduler path with an unsignaled healthy handle. The first assertion
  fails on the old runtime and passes with the fix. Evidence:
  `/tmp/vsock-stack-wait-diagnostic.lJi4BS/` and
  `/tmp/vsock-shared-progress-regression.BCjdkB/`. Clean debug/release full
  suites passed without queue-stall recovery in
  `/tmp/vsock-shared-fixes-clean-gate.5GQhNV/`; Clippy adds no warnings.

A separate shared-queue defect was found during that investigation and fixed
for blk, net, and vsock alike:

- Descriptor-allocation pressure and dropping an already-used, unpolled
  completion could advance the used cursor without updating `used_event`.
  Those paths now share the main reclaimer's disable/drain/arm/recheck batch
  helper. Arm once per stable batch, not per descriptor; preserve completion
  ownership and the fatal early-DMA-drop rule.
- The existing memory-backed queue fixture exercises the real allocation
  and completion-drop paths, both notification modes, and `u16` wrap. The
  EVENT_IDX assertion fails on old code and passes with the fix. This was
  not the cause of the captured stall above, where the threshold was current.
- Both regressions remain transitively in full-test. The same clean
  debug/release gates passed with no queue-stall warning and no new Clippy
  warning; all temporary queue/kernel/runtime probes are removed. No feature
  negotiation or VMM-specific behavior was added.

D16's standard full-suite selector and non-selected boot checks are implemented:

- `full-test.sh --vmm qemu|chv|fc` propagates selection through the vsock,
  System-console, TUI, terminal-size, and main-suite VMs. Standard FC selects
  the opt-in `raw.img`; other standard runs retain qcow2 and use the raw base
  image only for FC's boot check. Preserve CPU/memory overrides and isolate
  QEMU-only arguments. Developer FC is rejected before builds or launches.
- Every standard run checks SSH and owned-process liveness for the two
  non-selected VMMs. The shared teardown helper reaps each owned VMM once,
  validates its exit status, and makes teardown failure fail the suite.
  Main-suite cleanup preserves the original failure; PASS follows teardown.
- Clean QEMU full suites and all three VMM boot checks passed in both
  profiles, with the existing 1500/900-second suite budgets unchanged.
  Evidence: `/tmp/vsock-shared-fixes-clean-gate.5GQhNV/`. The full selected
  CHV/FC M2 gates and QEMU/CHV developer-wrapper propagation remain pending;
  these boot checks are not substitutes for those full runs.

M2's live global stream bound and connect-error coverage are implemented:

- A fresh VM admits one control stream plus 63 incoming streams across eight
  listeners. The next connection is refused while its listener still has a
  backlog slot; the existing control stream continues working. Listener
  cleanup must produce EOF on all children before rebind/new admission.
- Native connect tests require `NotImplemented` for a valid non-host CID and
  the exact refusal/timeout result declared by the host fixture, with all
  failed reservations reclaimed. D24 records the failed initial assumption,
  backend trace, and matching Linux timeout; no VMM or production change.
- Debug/release builds, targeted Clippy, and all eighteen peer cases plus
  IP-disabled discovery passed on QEMU, CHV, and FC. Formatting and shell
  checks passed, with no new warnings. Evidence:
  `/tmp/vsock-capacity-errors-clean.wuGNc9/`. These are incremental gates;
  accept, reset integration, final-slot cancellation, and M2 remain pending.

M2's block/network/vsock coexistence acceptance case is implemented:

- A framed barrier interleaves two 256 KiB transfers per direction with a
  64 KiB file write/flush/readback, 16 KiB TCP echo, and 256-byte UDP echo.
  TCP/UDP traverse the actual virtual NIC to the local tap host, not loopback.
  Both workloads must make progress before continuing; exact payloads and
  owned worker completion are required. This is functional coexistence, not
  a timing or throughput benchmark.
- The existing peer phase supplies a fresh guest temporary directory and
  retains its deadlines, cleanup, and offline-only traffic. Debug/release
  builds, targeted Clippy, and all nineteen peer cases plus discovery passed
  on QEMU, CHV, and FC, with no new warnings. Formatting/shell checks passed.
  Evidence: `/tmp/vsock-coexistence-gate.f5bPHf/`. Stage 15 measurements and
  the remaining M2 work are not complete.

D16's developer-suite selector and strict teardown are implemented:

- QEMU/CHV selection reaches both developer VM phases and the candidate
  wrapper. Keep the developer qcow2 image, existing CPU/memory overrides,
  8 GiB/4 GiB defaults, and QEMU-only arguments isolated. Reject FC before
  builds or launches; the separate Lorry product gate remains unchanged.
- Reuse the existing strict owned-VMM teardown helper. Preserve original
  failures, fail on bad teardown, and print PASS only after reaping. The
  existing memory-contract regression covers selection, defaults/overrides,
  early rejection, failure propagation, and teardown ordering.
- `full-test-dev.sh --release --vmm qemu` and `--vmm chv` both passed,
  including native source builds and Lorry's complete product gate. Shell,
  argument-rejection, and memory-contract checks passed. No debug developer
  run, longer timeout, or VMM change was used. Evidence:
  `/tmp/vsock-d16-developer-gate.NEOmKO/`. Its temporary QEMU results collector
  rejected a CR-prefixed PASS line; correcting the exact-line parser verified
  the original successful run without rerunning tests (`collector-diagnosis.md`).
- These functional passes do not resolve the preexisting kernel thread
  rollback leak diagnosed during the runs (Q31). The user subsequently
  approved a separate kernel fix and full gate (D27). Pending accepts and
  permanent reset failure are now specified by D25/D26, but not implemented;
  D28's cleanup simplification and the complete M2 gate remain outstanding.

D27's separate kernel thread-creation fix is implemented and fully gated:

- Allocate stacks before taking the process status lock, then hold that lock
  from the Running check through thread construction and map insertion. If
  exit already won, release the lock and return the unused stacks without
  publishing a thread or its self/join objects. Normal exit cleanup owns any
  thread admitted before exit. No counter semantics or external code changed.
- The existing guest systest now exercises 32 process-exit/spawn races and
  checks each child's active-thread count after wait, while retaining its
  process handle. The direct-syscall fixture failed on the unchanged kernel
  in its first episode (one leaked thread), then passed with the fix. An
  earlier std-thread fixture passed the old kernel and was not counted as
  evidence; its userspace setup left the exit signal too far from the syscall.
- Fresh `full-test.sh` gates passed three times in debug (734/739/741 seconds)
  and three times in release (556/511/512 seconds). The requested
  `full-test-dev.sh --release` also passed (1,445 seconds), including native
  source builds and Lorry's complete product suite. All seven ran the new
  regression; no nonzero active-thread-drop diagnostic recurred. Formatting
  and targeted Clippy passed with no new warnings.
- Evidence: `/tmp/thread-spawn-rollback-gate.sxnICK/`, including original
  diagnostic attempts, red/green fixture results, immutable tested-source
  hashes, and per-run logs. These gates cover this kernel patch only; they do
  not count as M2 validation of the still-unapplied vsock drafts.

D28's simplified abandoned-operation teardown is implemented:

- `NetClient` is weak; only drivers, reservations, and actual in-flight
  operations retain the channel. After normal RX/TX drain, the driver's
  existing failure path resolves residual RPCs and closes admission.
  Immediate Drop before staging work is nonallocating. Ordinary queued-TX
  socket Drop keeps its existing drain behavior; no cancellation protocol
  or explicit IPC disconnect API was added.
- Guest regressions prove both queued reservation-free queries are woken
  with `NotConnected`, and a retained idle client cannot keep late canceled
  connects alive. The host confirms both connects were admitted before the
  last real owner leaves, then requires EOF. Existing native TCP/UDP and
  queued-TX teardown tests remain intact.
- Debug/release builds, native-network suites, and all nineteen peer cases
  plus discovery passed on QEMU, CHV, and FC. Targeted Clippy and formatting
  passed with no new warnings. Evidence: `/tmp/vsock-a30-gate.7ebi5S/`.
  Its first temporary runner uploaded an older systest because default
  `make` does not build that target; mandatory new-marker checks rejected
  the run. Original logs are preserved in `stale-fixture-run/`. Explicitly
  building `all systest` corrected the runner, without changing assertions
  or timeouts. Only the subsequent fresh-binary runs count as validation.

D25's bounded accept server is implemented and incrementally gated:

- Keep eight pending accept RPCs independently of the eight-child backlog;
  the ninth returns `OutOfMemory`. Match both queues FIFO. Existing NET
  control tasks own waiters; matched children remain charged to the global
  stream cap and tied to the listener until response publication.
- Permit another channel in the same process to accept, while preserving
  capability checks and hiding foreign listeners. Publish the response
  before installing client routing and delivering buffered RX. Listener
  removal fails queued accepts and resets all unaccepted children; channel
  disconnect removes its pending requests without disturbing FIFO order.
- Component fixtures cover both limits, FIFO matching and removal. Raw guest
  IPC covers eight parked calls, overflow, listener-drop errors, stale
  handles, cross-channel ownership, response ordering, and early bytes.
  This coherent server/cleanup change is larger than the usual patch target;
  the native accept API and its live cancellation cases remain separate.
- Debug/release image builds, component/native-network suites, and all
  nineteen peer cases plus discovery passed on QEMU, CHV, and FC. Formatting,
  source hashes, and targeted Clippy passed with no new warnings. Evidence:
  `/tmp/vsock-a28-server-gate.mWXAgT/`. The full M2 gate remains outstanding.

The native accept API is implemented and incrementally gated:

- `VsockListener::accept_reserved` borrows its listener and accepts a reserved
  slot from any channel in the same process. Connect and accept share the
  existing weak open waiter. Inline reply processing validates endpoints and
  installs routing before publishing the usable stream or dispatching RX.
- The twentieth real-peer case accepts through a separately driven channel,
  checks endpoint metadata and bytes sent before accept, exchanges a reply,
  and requires EOF after Drop. It also covers unpolled cancellation, a
  canceled parked accept's successful late reply, reservation reclamation,
  driver exit, and removal of the canceled future's waker.
- Both profiles passed component/native-network tests and all twenty peer
  cases plus discovery on QEMU, CHV, and FC. Builds, formatting, source-hash
  checks, and targeted Clippy passed without new warnings; moto-io passed
  strict Clippy. Evidence: `/tmp/vsock-a28-native-gate.BGGqe2/`. Cross-process
  denial, early full peer close, and process-exit fixtures follow separately.

Accept isolation and process-exit fixtures are implemented and gated:

- Valid and malformed accepts without CAP_VSOCK return `NotAllowed`;
  wrong-kind handles and another process's listener return `NotFound`.
  A full host close before accept preserves exact buffered bytes, then EOF
  and write closure. No Unix SEND-only half-close is implied (D24).
- A child leaves eight admitted accepts (one matched, seven waiting), a
  listener, a claimed RX page, submitted TX, and an unread outgoing-connect
  reply behind at process exit. The host holds both streams before exit,
  then requires an exact zero-or-one-byte TX prefix and EOF on both. Only
  that cleanup token permits parent-process listener-port reuse. Submitted
  TX is not claimed to remain credit-blocked, nor the outgoing connection
  to remain in its internal pre-response state at exit.
- The first build failed on a missing test-only `alloc_page().await`.
  After correction, QEMU exposed an invalid synchronous reservation-count
  assumption after Drop. Drop intentionally pins the slot in its queued
  teardown record. A later same-channel availability RPC now proves that
  record drained before the unchanged exact count assertion; no polling,
  retries, or production change was needed. Original evidence and diagnoses:
  `/tmp/vsock-a28-cleanup-gate.zYIk1o/` and `/tmp/test-vsock.mDHKUl/`.
- Fresh debug/release builds, component/native-network suites, all twenty
  peer cases, and discovery passed on all three VMMs. Formatting, tested
  hashes, and Clippy passed with no new warnings. Final evidence:
  `/tmp/vsock-a28-cleanup-fixed-gate.LkmztB/`.

D26's returned-DMA retirement primitive is implemented:

- RX/event pools check whether to repost after the completion's consumer
  runs. The device can permanently disable reposting from within an event
  callback, before that event buffer would be recycled. Returned memory may
  then be released; outstanding completions and their DMA remain owned.
- Existing guest descriptor fixtures cover unchanged used-ring ordering,
  normal reposts, retirement without advancing the available index, and a
  stop decision made inside the event callback. Premature-drop assertions
  remain intact. This is queue-level coverage, not a live reset test.
- Both profiles passed image builds, descriptor/component/native-network
  suites, formatting, tested-source hashes, and targeted Clippy without new
  warnings. Evidence: `/tmp/vsock-a29-dma-gate.wDcm2q/`. Runtime permanent
  failure and removal of CID-refresh logic follow in the next patch.

D26's permanent runtime/native failure transition is implemented:

- A transport-reset event disables reposting before returning its event
  buffer, caches `InternalError`, stops TX submission/protocol dispatch,
  and discards controls, stream RX, and queued TX. Retained device owners
  still reap returned DMA. CID refresh and listener recovery are removed.
- Fail pending listener accepts before removal; mark matched children failed
  before removing their routing state. Later service operations check cached
  availability before stale-handle lookup. Native streams discard buffered
  RX/TX, wake waiters, and prioritize device failure over local EOF, empty
  I/O, or a pending shutdown. Already-established normal peer closure still
  preserves early data and successful open semantics.
- Component fixtures cover connecting, empty-read and zero-credit states,
  buffered-data discard, prior-cause override, idempotence, and late input.
  All eight queued accept receivers are parked first; each registered waker
  must fire before repoll returns `InternalError`. Queue fixtures separately
  cover retirement without repost. These do not inject failure through the
  complete runtime/IPC/native path or a live VMM.
- The initial fixture build lacked a declared in-tree `moto-rt` dependency;
  adding that test dependency fixed compilation, with no runtime-library or
  toolchain source change. The original failure is preserved under
  `/tmp/vsock-a29-failure-gate.FU0m8U/missing-test-dependency/`.
- Fresh debug/release builds, descriptor/component/native-network suites,
  all twenty peer cases, and discovery passed on QEMU, CHV, and FC. Clippy,
  formatting, and frozen-source checks passed with no new warnings. Evidence:
  `/tmp/vsock-a29-failure-gate.FU0m8U/`. This larger coordinated state change
  includes its component fixtures; failure-aware publication under reply-ring
  backpressure remains a separate follow-up.

D26's failure-aware reply publication is implemented and reviewed:

- Success replies for availability, CID, bind, and listener drop register a
  lazily allocated failure notifier before rechecking state. Shutdown and
  stream-state replies similarly recheck before publication after reply-ring
  backpressure. A failed activation wakes existing query waiters without
  assuming device pumps started. The permanent transition is idempotent.
- Keep failure notification separate from the TX pump's exclusive wake
  permit. Update published state flags only after enqueue, and ensure device
  `InternalError` can supersede an earlier per-stream terminal notification.
- One RX message whose page ownership was already encoded into a raw IPC
  message remains serialized before the failure notification. Canceling that
  send would lose page ownership. Native processing claims/discards it when
  failure arrives; unstaged RX is discarded immediately. This preserves
  bounded ownership without a new IPC cancellation API or a claim of instant
  cross-process retraction.
- Fresh debug/release descriptor/component/native-network tests, all twenty
  peer cases, and discovery passed on all three VMMs. Builds, formatting,
  source hashes, and Clippy passed with no new warnings. Evidence:
  `/tmp/vsock-a29-publication-gate.zzlr5S/`. Those live runs exercise normal
  traffic and teardown, not injected reset/backpressure combinations. A29's
  implementation is complete; Stage 15 and the full M2 gate remain.

Stage 15's measurement fixtures are implemented and gated:

- Existing discovery reports attached-unused, dormant, activated, absent,
  and disabled-endpoint process memory and 100 ms CPU/wait/wake samples,
  including actual intervals and observer cost. First/warm CID queries are
  timed separately. All measurement work is in systest, not the boot path.
- Repeat the existing framed one-byte exchange 128 times on one stream;
  report aggregate/mean RTT. Existing global-capacity, duplex, and concurrent
  block/TCP/UDP cases report whole-process footprint and payload rates while
  retaining exact bytes, EOF, credit, and cleanup checks. No threshold,
  timeout, or resource limit changed.
- Both profiles passed native/component tests and all twenty peer actions
  plus discovery on all VMMs; builds, formatting, hashes, and Clippy passed
  without new warnings. Evidence: `/tmp/vsock-stage15-gate.b3pd2N/`. QEMU's
  System/IP-disabled boot pair used matching shared memory; its standard
  no-device boot kept default backing. Detailed observations and caveats
  accompany the API documentation. Final repeated-capacity/close fixtures
  and M2's full gate remain outstanding.

The progress entries above describe behavior at each incremental commit.
D26 supersedes earlier CID-refresh/listener-recovery work and reset-test
proposals: remove recovery rather than extending it.

## Scope and simplicity

- One Virtio 1.1 modern PCI implementation requiring `VIRTIO_F_VERSION_1`, with
  the existing split virtqueues and MSI-X support. No legacy transport,
  packed-ring implementation, alternate queue library, or VMM-specific guest
  protocol.
- Defending against buggy or malicious VMMs is out of scope (D20). Continue
  normal protocol validation and guest-driver correctness work; do not add
  defensive PCI metadata checks for Q21.
- Native Motor OS I/O using existing in-tree libraries and Rust facilities.
  Preserve moto-io's `no_std` boundary by using `core`, `alloc`, and native
  APIs there; do not add a dependency on `std` or virtio-async to moto-io.
- Reliable byte streams with connect, listen/accept, bidirectional I/O,
  shutdown, and permanent failure on transport reset (D26). Snapshot/migration
  support and reset recovery are out of scope. Virtio 1.1 defines only stream
  sockets: no seqpacket/datagram API or associated feature negotiation,
  message reassembly, or record-boundary handling in this work (D1).
- Support one vsock device. Do not assume that there is only one NIC or that
  the shared driver infrastructure will only serve one block device.
  Preserve sys-io's current rejection of multiple block devices until
  multiple filesystems are supported. Preserve the multiple-NIC path;
  testing or fixing multi-NIC support is out of scope (D1).
- Reuse the existing networking endpoint, client/driver, reservations, and
  shared pages. Add a vsock stream socket kind without using the IP
  netstack. Keep packet/event I/O in virtio-async and connection/credit state
  in sys-io (D2, D4).
- Add `CAP_VSOCK` (D8). This requires in-tree moto-sys/kernel capability
  changes and edits to every explicit process-launch mask between sys-init
  and an application (constraint 11). No new syscall, kernel vsock driver,
  Rust-stdlib, moto-rt, libc, or toolchain source changes are planned. Changing
  moto-sys does require normal runtime-assembly regeneration as noted above.
  rt.vdso already calls the shared default-capability helper; avoid changing
  it unless the capability audit demonstrates a need.
- Initialize lazily on authorized native use (D9). An absent device or an
  attached but unused device must add no queue initialization, polling, host
  rendezvous, or background tasks to boot. No hot-plug/unplug or migration
  support.
- Support QEMU, Cloud Hypervisor, and Firecracker using unprivileged host
  UDS backends (D11). Cloud Hypervisor is the development VMM for the first
  real-device work. `full-test.sh` gains a `--vmm` selector for the VMM that
  runs the whole suite, defaulting to QEMU, and boot-checks the other two in
  every standard main-image run (D16). Firecracker coverage is standard-image
  only; developer-image tests do not require it. No changes to external
  VMM/backend repositories are planned.
- Add tests only through guest `systest`, reached from `full-test.sh` in
  debug and release. No new host-only tests or sys-io self-tests; a host UDS
  peer is test infrastructure, not a second test suite (D12).

## Existing code and integration points

Paths below are relative to the repository root.

| Location | Existing facility and planned use |
| --- | --- |
| `src/sys/lib/virtio-async/src/virtio_device.rs` | Modern PCI discovery, feature negotiation, device status, queue setup, and MSI-X. Add the vsock device kind and reuse these operations. |
| `src/sys/lib/virtio-async/src/virtio_blk.rs` | `BlockDevice::from`, initialization failure reporting, and nonblocking descriptor submission provide a compact driver pattern. |
| `src/sys/lib/virtio-async/src/virtio_net.rs` | Separate RX/TX queues, owned `IoBuf` submissions, and validated receive completions provide the packet-I/O pattern. |
| `src/sys/lib/virtio-async/src/virtio_queue.rs` | Reuse `Virtqueue`, `VqAlloc`, `UserData`, `VqCompletion<T>`, and `WriteCompletion<T>` for all three vsock queues. |
| `src/sys/sys-io/src/runtime/mod.rs` | `async_runtime` discovers devices and runs services on one `LocalRuntime`, affined to CPU 0. Attach the vsock runtime here. |
| `src/sys/sys-io/src/runtime/net.rs` and `src/sys/sys-io/src/runtime/net/socket/tcp.rs` | Examples of channel admission, client ownership, socket dispatch, shared-page I/O, and disconnect cleanup. Reuse applicable mechanisms without adopting TCP/IP-specific state. |
| `src/sys/sys-io/src/util.rs` | `map_err_into_native` folds refused, reset, and aborted connections into `NotConnected`. Vsock handlers return `moto_rt::Error` values directly per D14; the TCP mapping is unchanged. |
| `src/sys/lib/moto-sys-io/src/api_net.rs` | Extend shared-channel command dispatch without changing existing TCP/UDP command values; keep vsock-specific fields in `api_vsock.rs`. |
| `src/sys/lib/moto-io/src/net/{channel,tcp,wait,readiness}.rs` | Reuse `NetClient`, `NetDriver`, reservations, page ownership, waits, and cancellation; narrowly generalize TCP-specific dispatch. |
| `src/sys/lib/moto-sys/src/caps.rs`, `src/sys/kernel/src/uspace/process.rs` | Add the capability, default inheritance, and non-escalation checks, including for System parents. |
| `img_files/*/system/cfg/sys-init.cfg`, `src/sys/sys-init/src/main.rs`, `src/sys/sys-tty/src/main.rs`, `src/bin/russhd/src/local_session.rs`, `src/bin/rush/src/sys/motor.rs`, and the explicit `MOTOR_OS_CAPS` values in `src/tests/*.sh` | Every explicit capability mask between sys-init and a test process. Each must pass `CAP_VSOCK`, or the default grant never reaches applications (constraint 11, D8). |
| `src/sys/lib/moto-sys/src/sys_obj.rs` | `SysObj::get_capabilities` can query an admitted channel's peer; use existing trusted identity rather than client-supplied claims. `runtime/fs.rs` already uses it at admission. |
| `src/sys/tests/systest/src/{virtio,net_driver}.rs` and `src/tests/full-test.sh` | Existing guest queue-fixture, native API, and VM acceptance paths. Do not add a self-test runner. |
| `src/vm_scripts/run-{qemu,chv,fc}.sh`, `src/tests/vm-test-boot.sh`, and the `main.img` recipe in `Makefile` | Only the QEMU runner holds the VM exclusion lock, the boot helper starts only that runner, and the standard image is built only as qcow2. D15 and D16 cover launch changes and the opt-in `raw.img` target. |

The following constraints affect the design:

1. Queue scratch buffers are **16 bytes**. Both `get_buffer<T>` and
   `read_header<H>` only `debug_assert!` that limit; a release build would
   silently overrun. A vsock header is **44 bytes**. D3 reuses `HeaderBuffer`
   with 64-byte scratch storage for vsock queues, keeps 16 bytes for
   block/net, replaces the debug assertions with release capacity/alignment
   checks, and updates the memory-backed fixture.
2. A completion owns its descriptors until it is dropped after completion.
   Dropping it while DMA is outstanding asserts. Application cancellation
   therefore cannot directly cancel a submitted device request.
3. Queue allocation no longer starts tasks: the final `driver_ok` step
   validates all queue wait handles before starting IRQ reclamation and
   the existing debug monitors. Failed setup releases queue-owned handles,
   but does not reclaim the shared mapper's ring/IRQ-number reservations.
   `Virtqueue::drop` still has no device teardown implementation. Keep device
   lifetime separate from socket lifetime; do not promise hot-unplug or
   reset/recreation of queues as part of socket cleanup. Setup is still
   synchronous, before packet publication; a device must not consume buffers
   before `DRIVER_OK`
   ([Virtio 1.1 section 2.1.2](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html)).
4. The sys-io mapper currently permits IRQs 64–69, but the kernel registers
   16 custom IRQs, 64–79 (`src/sys/kernel/src/config.rs` and
   `src/sys/kernel/src/arch/x64/irq.rs`). Reuse
   that existing range with bounded allocation and an exhaustion error.
   One block device, two NICs, and one vsock device need eight queue IRQs;
   a future second block device would need nine. No IRQ-sharing framework or
   kernel vector expansion is needed for those examples. Queue sizes remain
   capped at 256; account for aggregate ring use of the existing 2 MiB pool.
5. Reuse `PciBar::read_u64` for the guest CID and reject a nonzero upper word
   or a reserved guest CID. Only the low 32 bits can change in our Virtio 1.1
   profile: the upper 32 bits are reserved and zero, and PCI permits separate
   32-bit accesses to the two halves. Thus a valid CID comes from one atomic
   low-word read, not an assumed atomic 64-bit snapshot. No configuration-generation
   accessor, retry loop, or retry-limit policy is needed here
   (approved 2026-09-15). This reasoning does not generalize to arbitrary
   changing 64-bit configuration fields or multi-field snapshots.
   See [Virtio 1.1 sections 4.1.3 and 5.10.4](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html).
6. `runtime/channel_budget.rs` accounts for net/fs channels. Sharing net's
   endpoint also shares its admission budget; no third channel kind is needed.
7. `api_net::NetCmd::try_from` and client dispatch assume the current command
   set. A shared service requires updates on both sides. Existing command
   numbers must remain stable. TCP's RX acknowledgement is a wakeup signal,
   not a byte-credit acknowledgement. Its receive window opens when sys-io
   drains socket data into an already allocated IPC page. Reuse that boundary
   for vsock credits; keep client-held pages independently bounded (D6).
8. Ordinary `#[cfg(test)]` tests inside these Motor-target crates are not
   automatically run by the suite. sys-io's registered self-tests run in
   debug only. All new coverage must instead execute in guest systest in
   both profiles. Existing registered tests remain unchanged.
9. `async_runtime` already collects NICs in a vector but explicitly rejects
   a second block device before `fs::init`, which takes one device. This is
   an intentional filesystem limitation to preserve, not a vsock fix. Do not
   add singleton assumptions to virtio-async or consume IRQs reserved for
   other device kinds. Multi-NIC testing/fixing and multi-filesystem work are
   outside this plan.
10. `SocketState` has TCP/UDP variants, but `SocketBase` also embeds an IP
    address, a net-device index, and netstack-specific handle/cleanup logic;
    `MotoSocket::drop` removes the socket's handle from a NIC's netstack
    table. Adding enum variants alone is insufficient. Separate those
    IP-backend fields and cleanup paths narrowly, retaining common
    ownership/IPC code.
11. The default capability grant does not reach applications on its own.
    Explicit masks intersect or replace capabilities at every hop between
    sys-init and a test process: `sys-init.cfg` service lines carry decimal
    masks (russhd runs with 124); sys-tty and russhd pass
    `own & (CAP_SPAWN | CAP_LOG | CAP_SPAWN_DETACHED | role)` to shells; rush
    passes `own & (CAP_SYS | CAP_SPAWN | CAP_LOG)` from System shells; and
    full-test, full-test-networking, stress-soak, and test-system-tty launch
    systest with explicit `MOTOR_OS_CAPS` values such as `0x4c`. Every VM
    test runs through this chain over SSH. D8 lists the required edits.
12. `util::map_err_into_native` maps `ConnectionRefused`, `ConnectionReset`,
    and `ConnectionAborted` all to `moto_rt::Error::NotConnected`, although
    `moto_rt::Error::ConnectionReset` exists. Vsock must not route its errors
    through that mapper (D14).
13. `run-qemu.sh` adds `-mem-path` whenever a hugetlbfs pool is available,
    and QEMU 10.2 rejects `-mem-path` together with `-machine memory-backend`,
    which vhost-user devices need for shared guest RAM. `run-chv.sh` and
    `run-fc.sh` take no VM exclusion lock, `vm-test-boot.sh` starts only
    `run-qemu.sh`, and no gate boots Cloud Hypervisor or Firecracker today
    (`test-vm-image-format.sh` uses a fake VMM). Base and System-console test
    images are raw, but the standard main image is qcow2 and cannot boot on
    Firecracker. D16 adds its opt-in raw counterpart.

## Protocol reference and ownership

Use [Virtio 1.1, sections 4.1 and 5.10](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html)
as the reference for the modern PCI/socket interface. Device type 19 maps
to modern PCI device ID `0x1053`. Queue indices are RX=0, TX=1, event=2.
The configuration contains a little-endian 64-bit guest CID with zero upper
32 bits. Guest CIDs exclude 0, 1, 2, and `0xffffffff`; CID 2 addresses the
host. Version 1.1 defines no vsock-specific feature bits and only stream
sockets. Negotiate no device-specific bits, including on newer backends;
retain the modern transport requirement and existing supported ring features.
`VIRTIO_F_VERSION_1` distinguishes modern transport, not 1.1 from 1.2.

The wire header contains source/destination CIDs and ports, payload length,
type, operation, flags, receive allocation, and forwarded-byte count. Use
the 44-byte wire layout, little-endian fields, and checked decoding. Stream
type is 1. Operations are REQUEST=1, RESPONSE=2, RST=3, SHUTDOWN=4, RW=5,
CREDIT_UPDATE=6, and CREDIT_REQUEST=7. Shutdown flag masks are receive=1 and
send=2. The transport-reset event is a four-byte event with ID 0. Newer
socket types are unsupported; retain required unknown-type refusal handling.
[Linux's published virtio-vsock wire definitions](https://github.com/torvalds/linux/blob/master/include/uapi/linux/virtio_vsock.h)
provide an interoperability cross-check.

The agreed boundaries, with API details in D5, are:

```text
Application: native moto-io vsock API
    <-> existing NetClient/NetDriver and shared networking IPC channel
    <-> sys-io vsock connections, credits, listeners, and client ownership
    <-> virtio-async vsock packet/event submissions and completions
    <-> existing Virtqueue / PCI / MSI-X infrastructure
```

The driver returns validated packet data and device events. sys-io owns
connection state and stream buffering. moto-io owns application waits and
IPC resources. Neither Ethernet, IP addressing, DNS, DHCP, nor the TCP
netstack participates in the vsock data path.

## Implementation sequence

Each numbered step is an implementation stage, not necessarily one commit.
Split implementation and tests into roughly 100–300 changed lines per patch.
Keep every intermediate patch buildable, and keep partial functionality
unpublished until its resource ownership and error paths work. D1–D23 are
the authoritative requirements; stages reference them and describe changes,
tests, and completion checks. Tests arrive with behavior; the validation
section groups related commits into the two approved gating milestones.

### 1. Review the contract and record the baseline

Follow D1–D23 without reopening the agreed scope, including Q16's resolution
in D16 and Q18's resolution in D17: opt-in raw standard image, no
developer-image Firecracker support, and ordered RX delivery in virtio-async.

Record the selected Motor toolchain, baseline image build/test results,
current boot measurements, and existing warnings. Keep logs for any initial
failure. Diagnose a newly encountered preexisting bug before discussing an
out-of-scope fix, following AGENTS.md. Make no external-repository changes.
On 2026-09-15, the user explicitly included all virtio-related preexisting
bugs in this work. Diagnose and fix them in small, separately reviewed and
validated patches; continue to raise non-obvious design or policy choices.
The later D20 scope decision excludes hardening against buggy or malicious
VMMs; it does not defer guest-driver bugs affecting valid devices.

### 2. Define capability and wire contracts, with guest tests

Implement D8 in `moto-sys/src/caps.rs` and
`kernel/src/uspace/process.rs`. `default_child_capabilities` needs an
explicit parent-bit check for the System default; its existing intersection
only covers non-System roles. The kernel's general subset check also exempts
System parents, so enforce the CAP_VSOCK subset rule separately. Preserve
unrelated role/cap rules.

Apply the D8 mask table at every launch hop listed in constraint 11.
rt.vdso's `default_child_capabilities` call picks up the new default without
a new API. Document explicit denial via `MOTOR_OS_CAPS`.

When adding the IPC handlers in stages 9–10, use `SysObj::get_capabilities`
on the admitted peer at its first vsock request and cache the trusted,
immutable capability word. Do not add a query to every net-channel admission
at boot. Authoritatively check discovery (D21), connect, and bind/listen
(including accept ownership) before device activation or vsock resource
reservation. Do not reject the entire shared channel:
a process denied vsock must still be able to use its existing TCP/UDP APIs.
Client-side checks are only convenience, never the security boundary.

Add systest child-process cases for default inheritance, explicit grant and
denial, denied descendants, attempted escalation, and System-parent denial.
With the IPC handlers, exercise the real server check using a client that
bypasses moto-io's check, and run one denied case with the pre-change mask
value `0x4c` so a stale test-script mask fails visibly with `NotAllowed`.
No new host-only capability tests or boot-time self-tests are needed.

Add `virtio_vsock.rs` under virtio-async, splitting out a small wire helper
only if that improves readability. Define the header/event layouts and
constants, with size/offset assertions and explicit endian conversions.
Decode untrusted integer tags with matches rather than unchecked enum
transmutes. Keep wire structures separate from native API addresses.

Validate used length, header presence, payload length, and the posted
buffer capacity before creating any payload slice. Validate CID width,
socket type, operation, and operation-specific flags before changing state.
Keep enough decoded metadata to produce a required protocol refusal
when a complete header is present. Never use a malformed length to allocate
a buffer or resize an `IoBuf`.

Keep new assertions in systest; expose only the fixtures/helpers necessary
to exercise real driver code through the existing `test-support` feature.
Run them from `systest/src/virtio.rs` in both profiles. Cover exact header
size, ignored unsupported feature bits, short headers, truncated payloads,
oversized used lengths, integer overflow, high CID bits, unknown tags, and
control packets carrying invalid payloads. Use fixed examples with expected
field values, not just encode/decode round trips. For sys-io's small pure
credit/state helpers, compile the same source into systest with a narrow
source include, as `src/sys/tests/virtio-task-tests` already does for
`runtime/fs/block_io.rs`; do not duplicate the algorithm, extract a broad
protocol crate, or introduce `SELF_TESTS` registrations.

### 3. Add modern discovery and device initialization

Update `VirtioDeviceKind`, the modern PCI ID match, and crate exports. Add
`VsockDevice` following the existing `from`/initialization/error pattern.
Require modern features and leave unsupported optional features disabled.
Do not negotiate vsock-specific features. Check feature confirmation and
configuration length, and read and validate the CID as in constraint 5.
Keep discovery separate from initialization so boot can retain the device
without creating its queues.

Apply D18 in the shared reset path: after writing zero, read status once and
fail initialization if nonzero, before ACKNOWLEDGE or queue-task startup.
Propagate the error through block/net/vsock initialization; add no reset
polling or retry path. This is not a change to vsock transport-reset events.

Use `init_virtqueues(3, 3)`, existing MSI-X assignment, and existing status
operations. Queue setup refuses a device whose MSI-X table has fewer vectors
than queues; confirm on each VMM that the vsock device exposes at least
three vectors, and report a clear initialization error otherwise. Validate
queue capacity against the chosen packet layout and control reserve. Use
the existing PCI read helper and CID validation at lazy activation; do not
refresh the CID after transport reset or add configuration-read retries (D26).

Extend the mapper's bounded IRQ allocation to the already installed 64–79
range, returning an error on exhaustion rather than asserting or wrapping
the `u8`. Keep one IRQ per queue and existing per-device MSI-X setup. Check
aggregate ring allocation, including block and all configured NIC queues,
before consuming the fixed pool. This is shared-infrastructure capacity
work, not a multi-NIC repair or permission to remove the multi-block guard.

Prepare RX/event storage and arrange buffer publication, `DRIVER_OK`, and
notifications in the standard initialization order. Do not announce service
readiness before these paths can make progress. Check initial allocations
before publishing DMA buffers where possible; partial initialization must
not free memory already visible to the device.

Test device-ID mapping, feature combinations, invalid configuration/CID,
insufficient queues, and IRQ/ring capacity arithmetic with systest fixtures.
The capacity checks must not assume one NIC or one block queue; this does
not require new multi-NIC VM tests. Leave activation to step 12; recognition
alone does not make the new device an application service.

### 4. Implement RX, TX, and event completions using the existing queues

Implement small post/try-post operations with explicit buffer ownership.
Reuse queue-owned `HeaderBuffer` for headers and retain payload `IoBuf`s in
the generic completion's owned value. A successful submission retains both
until completion is reaped; failed admission returns payload ownership
without changing connection accounting. Receive and event descriptors are
device-writable; transmit descriptors are
device-readable. A header-only control packet needs no empty data descriptor.

Implement D3 in `allocate_virtqueue`, the typed scratch accessors, and the
memory-backed fixture together. Copy received headers only after completion.
Zero header storage before publication and expose only the 44-byte wire
header, not padding. No separately managed header pool is needed.

Use a page-aligned 4 KiB payload: two descriptors for data and one for a
header-only control or four-byte event. Respect physical page boundaries;
virtual contiguity does not imply physical contiguity. Verify backend packet
splitting against posted RX capacity and reject invalid used lengths without
resizing to a peer-provided length.

The 2026-09-15 source check supports this layout: the pinned
[CHV receive path](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/v52.0/virtio-devices/src/vsock/csm/connection.rs#L208-L231),
[Firecracker receive path](https://github.com/firecracker-microvm/firecracker/blob/v1.15.1/src/vmm/src/devices/virtio/vsock/csm/connection.rs#L217-L241),
and [QEMU backend receive path](https://github.com/rust-vmm/vhost-device/blob/vhost-device-vsock-v0.3.0/vhost-device-vsock/src/vsock_conn.rs#L158-L176)
limit each stream read to posted payload capacity and peer credit. Each
reports header plus actual payload as the used length:
[CHV](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/v52.0/virtio-devices/src/vsock/device.rs#L134-L164),
[Firecracker](https://github.com/firecracker-microvm/firecracker/blob/v1.15.1/src/vmm/src/devices/virtio/vsock/device.rs#L167-L205),
and [QEMU backend](https://github.com/rust-vmm/vhost-device/blob/vhost-device-vsock-v0.3.0/vhost-device-vsock/src/vhu_vsock_thread.rs#L600-L615).
This does not replace the planned real-peer multi-packet tests.

Return buffers on valid and invalid completions so the runtime can reuse
them. Use a dedicated receive completion wrapper, like `NetReadCompletion`,
where header/length validation is needed. Do not request block status for
vsock chains. TX completion means the device released the buffers, not that
the remote application consumed the data.

Implement D17's crate-private ordered-completion accessor in
`virtio_queue.rs`, preserving the existing used-ring order and descriptor
ownership. In `virtio_vsock.rs`, own the bounded RX buffer/completion pool
and use each next used head to resolve the corresponding completion before
delivering a packet to sys-io. Do not poll arbitrary ready futures and then
sort them, sort by submission order, or add a separate completion FIFO or
per-descriptor sequence metadata. Keep the existing block/net APIs unchanged.

Extend the real memory-backed queue fixture minimally to cover vsock
descriptor direction, header-only TX, valid/invalid RX and events,
out-of-order chain completion, descriptor exhaustion/reuse, and owned-buffer
lifetime. Verify ordered packet delivery with multiple completions ready
before the first poll, opposite submission/completion/polling orders, cursor
wrap, and buffer reuse. A malformed packet must advance ordered consumption
without leaking its buffers or stalling later packets. Preserve the existing
premature-drop regression and run these cases through guest systest in both
profiles.

### 5. Build the device pumps and bounded scheduling

The bounded storage and driver poll/send facilities are M1 foundations.
Implement this stage's integrated pumps and scheduling alongside the M2
connection/IPC work, not as idle placeholder tasks before it (D13).

Add the proposed `src/sys/sys-io/src/runtime/vsock.rs`. Use the existing
single-threaded executor and `Rc` ownership; never hold `RefCell` borrows
across awaits. Use one TX submission pump (D6); keep RX processing, event
handling, and TX completion draining independently able to progress.

Consume the driver's already ordered RX packets and process them in that
order in sys-io's connection/credit state machine. Copy or transfer accepted
payloads into bounded per-stream storage, then promptly return buffers to
the driver's fixed RX pool for reposting. Do not reorder packets by spawning
independent per-packet handlers. A blocked application must not retain the
entire device RX ring. Use a bounded pending-control
queue or equivalent reserved state, sized per D7. RX must continue while TX
is full whenever this extra storage can hold the resulting replies, as
required by the
[virtqueue flow-control rules](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html).

Drain completed TX requests before waiting for more descriptors. If using
`VqAlloc`, ensure another live task releases the completions on which it
depends; do not make one task wait for descriptors while retaining the only
completions that can free them. Preserve per-stream ordering, including
data before write-shutdown, while keeping credit and refusal traffic able
to run. Bound work per dispatch so a busy vsock cannot monopolize sys-io.

Test a full TX ring while RX produces replies, all control slots occupied,
completion-driven resumption, and one slow stream alongside an active one.
Every exhausted state needs a concrete wakeup source, without a polling
timer or an automatic retry loop. Run these wakeup tests in release as well
as debug: in debug builds the per-queue monitoring task in
`virtio_queue.rs` polls every second and force-wakes stalled completion
waiters, so a lost wakeup would surface only in release.

Keep queue ordering entirely in virtio-async (D17). sys-io appends payloads
to the appropriate stream in received order; it neither sorts completions
nor reconstructs packet sequence. moto-io has no hardware-completion ordering
logic. Test delivery through the state machine without changing this boundary.

### 6. Implement and test byte-credit accounting

Pure credit arithmetic and bounded receive storage belong to M1. Integration
with real TX publication, connection state, IPC ownership, and control-message
scheduling belongs to M2, with the corresponding behavioral tests (D13).

Add a small credit-state helper, independent of PCI and IPC. Track local
receive capacity/occupancy, local forwarded count, transmitted payload count,
and the peer's advertised allocation/forwarded count. Keep header and control
bytes out of byte accounting. Use explicit wrapping arithmetic for protocol
counters and checked arithmetic for allocation sizes and local totals.

Calculate outstanding bytes as `tx_cnt.wrapping_sub(peer_fwd_cnt)`. Available
credit is the peer allocation minus outstanding bytes when that subtraction
is valid; never let an invalid advertisement become a huge writable window.
Accept ordinary zero-credit conditions, distinguish them from impossible
counter advances, and account for advertised buffer-size changes without
panicking. Validate any claimed consumption against what was actually sent.
Reject impossible advances atomically, preserving both peer credit fields;
the connection state machine rejects the packet and resets only that stream
under D19. A reduced allocation alone is backpressure, not a reset cause.

Implement D6's TX publication and RX-to-IPC accounting boundaries. Update
peer credit from appropriate incoming packets and include current local
accounting on every stream-associated outgoing packet. Reposting a DMA
buffer does not advance `fwd_cnt`; only draining the receive byte buffer
into reserved IPC storage does.

Handle CREDIT_REQUEST and CREDIT_UPDATE without consuming payload credit.
Coalesce redundant pending requests/updates per stream within D7's control
bound and send an update when a blocked peer can progress. Schedule from
state changes, not periodic probes. Control capacity must still work when
payload credit is zero.

Test counters near `u32::MAX`, exact exhaustion, partial credit, duplicate
updates, invalid advances, and peer allocation changes. Verify failed
try-post and canceled unsent writes leave credit unchanged, successful
submission charges once even with competing writes, and caller cancellation
after submission does not refund credit. Test receive capacity restored at
the sys-io-to-IPC boundary and a stalled application without blocking other
streams or exhausting device RX buffers. Run all cases in guest systest in
release as well as debug.

### 7. Implement connect, connection lookup, and protocol transitions

Use a small explicit state machine and a connection table keyed by the full
local/remote CID-and-port tuple. Keep a separate opaque client handle; a wire
tuple is not authority to access another client's socket. Allocate outgoing
ports with collision checks and bounded exhaustion behavior under D8.

Implement REQUEST/RESPONSE establishment, refused connects, stream data,
credit messages, peer shutdown, and reset. Bound pending connects and ensure
response handling verifies the expected peer and state. Reserve receive and
control resources before accepting a connection. Check unknown tuples and
unsupported socket types before delivering data, including protocol-required
RST replies. Do not generate a reset-response loop for an incoming RST.
Apply D19/D22's connection-local reset on impossible peer credit, wrong-state
operations, or payload exceeding advertised credit, without admitting the
offending payload or changing stored peer credit fields on rejection.

Record state transitions in tests as inputs and expected outputs: emitted
control packets, byte/accounting changes, state, and waiter notifications.
Cover refusal, unexpected responses, duplicate requests, wrong destinations,
data before establishment, and stale packets after closure. Test D19/D22's
invalid-credit, wrong-state, and receive-overrun reactions, validated-RX drain
before `ConnectionReset`, no RST-response loop, and continued operation of
unrelated streams. Implement
only the approved scope; unsupported operations need explicit errors (D14).

### 8. Implement bind, listen, and accept

Keep a listener table separate from active streams. Follow D8 for binding
the current local CID, explicit ports, and automatic ports. Reject conflicts
deterministically. Use the fixed backlog from D7,
with each pending accepted stream charged to its owner and global limits.
Separately cap pending accept RPCs at eight per listener (D25); return
`OutOfMemory` at that bound. Pre-reserve the small queue and do not add
per-channel request bookkeeping just to enforce it.

Create a stream only after reserving its resources. Queue it for accept
without changing the listener's identity. Define how data arriving between
RESPONSE and application accept is buffered within that reservation. Refuse
requests that cannot be admitted without losing an existing stream's data.

Test multiple accepts, backlog exhaustion, bind collisions, listener drop,
accept cancellation, early peer data/close, and release of unaccepted streams
when their owning channel disappears. Keep blocked accepts from holding a
runtime borrow or preventing dispatch to established sockets.

### 9. Define the native IPC contract

Add `src/sys/lib/moto-sys-io/src/api_vsock.rs` and export it from the crate.
Extend the existing networking endpoint/dispatch; do not add another service
name, channel-budget kind, or client driver. Specify each message's direction,
handle, request ID, payload fields, ownership transfers, and terminal reply.

The minimal semantic operations are query local CID/availability, connect,
bind/listen, accept, TX, RX delivery, receive-storage release, shutdown,
close/drop, and terminal-state/error notification. A field needed only for
the wire protocol, such as a guest-chosen source CID or peer credit counter,
should remain sys-io-owned rather than client-controlled.

Use fixed-width address fields and existing `io_channel::Msg`/shared pages.
Do not encode CID/port as an IP `SocketAddr`; vsock ports are 32-bit. Avoid
a second serialization framework or a variable-size control protocol.
Reuse page release and wakeup machinery: releasing a client page allows more
RX delivery, but does not directly alter peer byte credit. Check IDs, page
indices, lengths, flags, and ownership in release.

Preserve existing command values and update `NetCmd::try_from`, range checks,
and both dispatchers intentionally. Reuse existing operation bodies where
their layouts/semantics truly match, with explicit socket-kind validation;
add vsock commands for different address/control layouts. Existing TCP/UDP
and rt.vdso callers must keep their current wire contracts.

Add `SocketState::Vsock` and a vsock listener state. Refactor only the
netstack-dependent fields of `SocketBase`/listener dispatch into an explicit
backend/address distinction. Retain common socket IDs, client ownership,
notifications, and cleanup bookkeeping. In particular, dropping a vsock
socket must not remove a handle from a NIC's netstack socket table. Avoid
fake IP addresses, copied TCP state machines, and a new transport framework.

Test fixed wire examples, 32-bit ports above 65535, invalid fields, foreign
handles/pages, duplicate releases, cancellation/late replies, and stale IDs.
Use D14's native errors without changing the TCP mapper.

### 10. Bridge sys-io streams and client pages

Implement IPC handlers around the state machine. Validate owner identity
before touching a socket, and snapshot client-controlled message fields
before using them. Keep raw packet headers and device DMA memory private
to sys-io. Follow D6 for copies and ownership of payload bytes.

On TX, retain a bounded number of client pages until their data is copied
into private packet-sized DMA buffers; then release pages through the
existing ownership mechanism. Do not DMA directly from client-controlled
memory. Preserve stream order across partial progress. A writable notification
must correspond to capacity the application can actually use. Record when a native
write becomes successful and what a later reset does to unsent bytes.

On RX, copy validated payload into the bounded sys-io buffer, then use the
existing allocation-before-drain sequence to deliver IPC pages. Reuse page
ownership validation, not an invented client-reported consumed-byte count.
On refusal or error, return every recovered page exactly once. Coalesce
small wire payloads in byte storage so a peer cannot exhaust metadata by
sending many one-byte packets within its advertised receive credit.

On reset, send cumulative `TERMINAL | WRITE_CLOSED` promptly so writers
wake even if client-held RX pages prevent further delivery. This is not a
read barrier: previously validated bytes may still follow. Send `READ_CLOSED`
only after the last RX page enters the client's FIFO. Native readers drain
those bytes before returning the retained cause or orderly EOF. Do not hold
the output-serialization lock while waiting to allocate an RX page.

Exercise a stalled reader/writer, IPC page exhaustion, slow response queues,
and client death during transfer. Check D14's distinction between admission
failure and ordinary backpressure: partial progress, try-I/O `NotReady`,
async suspension/resumption, and no lost accepted bytes. Verify another
client and the device's event/control paths still progress. Keep pending
close/error delivery bounded when the channel itself is full.

### 11. Add the moto-io native API and cancellation behavior

Placement: `src/sys/lib/moto-io/src/net/vsock.rs`, exported through
`moto_io::net::vsock`. Reuse `NetClient`, its reservation API, and the same
explicitly driven `NetDriver` (D5). Generalize the typed socket maps
(`tcp_streams`, `tcp_listeners`, `udp_sockets`), waiter dispatch, and
cancellation records in `channel.rs` only where needed for vsock. Reuse the
existing Arc/locking model; do not introduce a second local-only client,
background thread, global singleton, or a copy of the TCP client driver.

Implement the D5 API surface with D10/D14 shutdown and error semantics.
Define zero-length operations, short reads/writes, and peer/local addresses.
Preserve existing async read/write and readiness patterns, including
concurrent read/write on a shared handle; add no stream-cloning semantics
beyond shared ownership.

Document which future/task drives IPC, whether handles cross threads, and
what drop does. Cancellation must remove waiter registrations and release
reservations. If a canceled connect/accept later produces a live socket,
close it and reclaim its pages. Define cancellation of a partially admitted
write so it cannot silently duplicate bytes if the caller retries.

Add native tests patterned after `systest/src/net_driver.rs`: construct and
drive the client, reserve/use/release resources, shut down the driver, and
observe its exit. Cover cancellation while waiting for a reply, data, TX
pages, and a close notification. Include registration/recheck/wakeup races
and the approved concurrent-use semantics.

### 12. Wire device discovery, the runtime, and service admission

Extend `runtime::async_runtime` to retain the supported vsock device and
pass its dormant state to the networking runtime. Keep filesystem and IP
initialization working when vsock is absent or rejected. Preserve the vector
of NICs and the explicit multi-block rejection. The one-vsock limit belongs
to service admission, not to generic PCI/queue or other device-kind code.

Implement D9's synchronous first-use transition and cached result. Keep
device lifetime independent of the caller; do not add an initialization
future, waiter list, or cancellation protocol without an actual await point.

Add vsock dispatch and client cleanup to the existing endpoint, independent
of IP configuration. Split the `devices.is_empty()` early return in
`runtime/net.rs::init` from common endpoint startup as required by D4.
Reuse net-channel admission and reserved fs/net capacity.
Do not start another listener, count a shared channel twice, or treat a
CAP_VSOCK denial as denial of the channel's TCP/UDP operations.
Initialization-failure and extra-device handling follow D9.

Bound connections, listeners, pending accepts/connects, queued bytes/pages,
and control work as specified in D7. The copy-based design charges committed
storage before accepting work that needs it. Do not add unbounded tasks as
an alternative to bounded queues. Use the existing trusted channel/process
identity for D8 authorization checks.

Test ordinary no-vsock boot and fail-fast native discovery, attached-but-idle
boot, first-use initialization, simultaneous first callers, cancellation
before/after dispatch, cached failures, capacity boundaries, and denial.
Exercise vsock with zero usable IP devices, including loopback disabled;
the serial-console test route is described in stage 14. Also verify the
existing disabled-service path with no IP or vsock devices, and coexistence
with the ordinary block/network configuration and channel budget. This does
not add multi-NIC testing/fixing or multi-filesystem support. Verify no host
rendezvous or per-application driver initialization.

### 13. Finish shutdown, reset, and teardown under load

Implement D10's directional shutdown, drain/reset policy, and bounded close
cleanup with D14's errors. Deadlines belong to actual connect/close work,
not idle polling. Test simultaneous close and reuse, plus a peer that sends
a request, shuts down its SEND side, and still receives the guest response.
Verify peer RECEIVE and local SEND shutdown stop subsequent local writes,
and an orderly close is not reported as `ConnectionReset`.

Service the event queue while the device is ready. A transport-reset event
permanently changes vsock to the cached failed state (D26). Fail pending
connects, accepts, reads, writes, shutdowns, and queries; terminate listeners
and streams; discard queued TX and buffered RX. Future vsock operations,
including availability queries, return the cached `InternalError` after
the capability check. Do not refresh the CID, preserve listeners, reactivate
the device, or retry. Other services sharing the NET channel remain usable.
Validate event buffers and replenish them only while ready; an unknown event
does not itself cause recovery or device reinitialization.

Remove unsent packets and prevent late completions from reviving socket
state. A transport-reset event does not itself return
DMA ownership of every outstanding descriptor. Keep submitted completions
alive and reclaim only descriptors actually returned through the existing
queue. Stop posting or reposting buffers; discard returned packets instead
of dispatching them. Keep unreclaimed DMA memory pinned for the device's
remaining lifetime. Logical operation errors are not fabricated virtqueue
completions. Do not reset/recreate the device or drop device-owned futures.

On channel failure or client exit, remove that client's listeners, abort or
finish its streams under D10, and drain/release pages, pending replies,
waiters, timers, and reservations. Keep cleanup idempotent across peer reset,
client drop, and late reply races. Device failure must be distinguishable
from a single stream failure (D9, D14).

In existing guest systest component fixtures, exercise failure of connecting,
empty/buffered-read, and zero-credit write states and wake every queued accept
oneshot. Check the terminal cause, data discard, later-state behavior,
idempotence, and late protocol input. Queue fixtures separately check returned
DMA retirement and no reposting; retain the existing outstanding-ownership
and event-length assertions. These fixtures do not drive a reset through the
joined sys-io/IPC/native task graph. Retain ordinary live API, teardown, and
resource-count tests without claiming they inject device failure. Do not add
snapshots, restore, live CID-change tests, a sys-io self-test, or a production
injection command. D26 deliberately excludes reset recovery and live reset
coverage; this is a terminal safety path, not snapshot support.

### 14. Add a hermetic host/guest acceptance phase

Add `src/sys/tests/systest/src/vsock.rs` and an explicit vsock test command
in `systest/src/main.rs`. Run hardware-independent tests in the ordinary
systest path. Run real peer tests through a dedicated
`src/tests/test-vsock.sh`, called directly from `src/tests/full-test.sh` with
the selected debug/release mode and VMM. Device-present testing must be an actual
required phase, not a successful skip when no device was attached.
Bring the necessary pieces of this phase forward with the implementation
commits that need them; do not postpone executable tests until this stage.

The phase runs on the VMM selected by `full-test.sh --vmm` (D16), with one
modern PCI vsock device attached to a separate, sequential VM; the run's
main VM keeps the unchanged no-device topology. Apply D11's backend setup
and D15/D16's runner/image selection. Develop and first validate against
Cloud Hypervisor. All three VMMs are required by M2 through the D13 runs.

Use one small standard-Rust host peer based on `std::os::unix::net`. It only
provides deterministic peer actions/data and orchestration; guest systest
owns test assertions and verdicts. The UDS mapping uses `<path>_<port>` for
guest-to-host service connections; host-to-guest connects send a `CONNECT`
line and consume the backend's `OK` reply before application data. See the
[Firecracker UDS protocol](https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md)
and [vhost-device-vsock setup](https://github.com/rust-vmm/vhost-device/blob/main/vhost-device-vsock/README.md).
Confirm installed versions and prerequisites as described in D11. Existing
tap setup is unchanged; the vsock backend itself must need no new privileges.

Use per-run temporary sockets, a deterministic framed test protocol,
bounded deadlines, explicit readiness, and cleanup of owned processes/files.
Follow D16's launch order and shared lock; do not start this phase while the
main VM still owns the tap/address. Save logs and verify that results came
from this invocation's VM. Upload the selected debug/release systest over
sftp as `full-test.sh` does. Check committed memory against D7 and the
selected phase's memory budget.

For the IP-disabled case, prepare an isolated test-image variant with
loopback/NIC IP configuration disabled and the selected systest already
installed. Launch it and collect the guest verdict through the existing
serial-console path, not SSH. Preserve the normal images and keep assertions
in guest systest; this case must exercise the real shared endpoint, not just
a packet fixture. It remains part of `test-vsock.sh` on the selected VMM.

The acceptance cases are:

- Guest connects to host and host connects to a guest listener, using
  explicit non-default ports and exact byte-content checks.
- Zero-length API operations, one-byte transfers, packet/page boundaries,
  and transfers much larger than the receive window in both directions.
- Full-duplex transfer; a stopped reader that resumes through credits; a
  blocked connection alongside another active connection. Verify partial
  writes, try-I/O `NotReady`, and async resumption under IPC-page exhaustion
  without spurious `OutOfMemory` or lost bytes.
- No listener, duplicate bind, unsupported address/type, connection timeout,
  backlog exhaustion, peer reset, half-close, clean close, and port reuse,
  each reporting the D14 error.
  For directional shutdown, use D24's explicit cross-stream synchronization;
  Unix EOF is not an indication of SEND-only virtio shutdown.
- Cancellation and client process exit during connect, accept, RX, and TX;
  repeated cycles must return observable resource counts to baseline.
- Capability inheritance and denial, including raw IPC attempts; no-device
  errors and attached-but-idle/first-use behavior. Vsock still works with IP
  disabled, including no loopback, without starting the IP backend.
- Permanent device failure on transport reset through existing guest
  fixtures (D26), clearly labeled as such; no listener recovery or snapshots.
- Block and TCP/UDP I/O while vsock transfers run, plus a no-device VM run
  verifying existing services and prompt native unavailability errors. Keep
  the existing NIC/block topology; multi-NIC tests/fixes and enabling multiple
  filesystems are explicitly not acceptance requirements of this work.

Keep payload peers local. The new tests do not contact the Internet, fetch
dependencies, or add retries. Missing mandatory test prerequisites must
produce a clear failure before launching the phase.

### 15. Measure, document, and complete the integration

Measure unchanged-topology boot latency with no vsock device, startup cost
with the device attached but unused, first-use cost, idle CPU/wakeups,
fixed device memory, per-stream memory, small-message latency, and sustained
transfer rate. Include a
concurrent block/network workload to detect executor starvation. Report
the buffer sizes and topology with results; agree material acceptance
thresholds during review instead of inventing a performance target. Attached
but unused must not allocate the lazy device's queues or run device pumps.
Revise the D7 bounds only with review, based on these measurements.

Document the native API with one small client/listener example, driver
lifetime requirements, error/drop semantics, supported endpoints, resource
limits, and the tested launch configuration. State that native vsock support
does not imply a libc, Rust-stdlib, mio, or Tokio socket API.

Keep diagnostics small: initialization/error logs and the resource counters
needed to prove admission and teardown are sufficient initially. Do not add
per-packet production logs or a new monitoring service. Remove temporary
instrumentation before final validation. Update this document with completed
steps and evidence only after the corresponding behavior is implemented.

## Validation and completion criteria

The test wiring must make the following coverage real:

| Coverage | Execution path |
| --- | --- |
| Wire validation, RX used-ring delivery order, and actual queue ownership/exhaustion | Existing virtio-async `test-support` fixture route -> `systest/src/virtio.rs` -> ordinary full-test VM, both profiles. |
| Pure credits, connection transitions, and reset handling | Same implementation helpers compiled into guest systest by source include; no separate host suite or sys-io self-test registration. |
| Capability defaults, delegation, and denial | Systest child-process and native/raw-IPC cases, both profiles. |
| Native API, real DMA, peer interoperability, and cleanup | `test-vsock.sh` -> guest systest plus local UDS peer on the VMM selected by `--vmm`, both profiles; every VMM at least once per profile at M2 (D13). |
| Shared endpoint with IP disabled | `test-vsock.sh` -> isolated IP-disabled image with preinstalled systest, serial-console launch/verdict, and the same local UDS peer. |
| Every VMM boots Motor OS | The boot-check phase of every standard main-image full-test run for the two VMMs not selected, plus the selected VMM's own suite (D16). |
| Existing OS behavior and absent-device behavior | Existing full-test phases, preserving their device configuration and assertions. |

For implementation, format changed Rust with `cargo fmt` from the
repository-selected Motor toolchain and run targeted clippy checks for the
changed crates with `--target x86_64-unknown-motor`. Introduce no new compiler
or clippy warnings and do not broaden existing warning suppressions.

D13 changes the default per-commit repeated gate to a milestone-based gate
with two repeated milestones:

- M1, foundations: capability delegation, modern device support, shared-queue
  changes and fixed pools, pure credit arithmetic, and bounded receive
  storage, with their executable guest fixtures. Gate these foundations
  before client/server integration; M1 does not require the integrated
  Stage 5 pumps or Stage 6 connection/IPC accounting and scheduling.
- M2, complete integration: those integrated Stage 5/6 behaviors alongside
  stages 7–15's state machines, shared networking IPC, native API, lazy
  activation, cleanup, and all three VMMs. Full gates include the complete
  new vsock phase by this milestone. Q22 changes only the dependency boundary,
  not the tests required or the gate counts. M1 is complete as recorded above;
  M2 remains pending.

Each small implementation commit must build and run its affected guest
systest cases in debug and release, plus directly affected existing queue,
capability, TCP/UDP, or native-driver regressions. Keep those tests in
full-test transitively; no commit gets to defer its tests to the milestone.
Bring real-peer test plumbing forward whenever a commit needs it.

At M1 and M2, obtain three passing debug and three passing release
main-image builds/runs on the default VMM, retaining logs for the whole
group:

```sh
make -j"$(nproc)"
src/tests/full-test.sh
make -j"$(nproc)" BUILD=release
src/tests/full-test.sh --release
```

Run each profile's build/full-test cycle three times at that milestone. At
M2 add one passing debug and one passing release run for each of the other
VMMs, so every VMM runs the complete suite including the vsock phase at
least once per profile without tripling the repeated gate (D13, D16):

```sh
src/tests/full-test.sh --vmm chv
src/tests/full-test.sh --release --vmm chv
src/tests/full-test.sh --vmm fc
src/tests/full-test.sh --release --vmm fc
```
These are validation runs, not a retry-until-green policy. Diagnose any
failure, preserve its original evidence, and rerun to test a specific
hypothesis. Do not extend timeouts, weaken assertions, or ignore errors.
Only the already accepted DNS/ping external-network flakes get the single
retry allowed by AGENTS.md; stop and discuss if that retry fails. The added
VM boots lengthen full-test; raising its `TIMEOUT` by the measured cost of
the boot checks and the vsock phase, recorded here, is a budget for added
work, not a workaround (D16).

Verify `raw.img` is absent from default/aggregate image dependencies and is
requested by standard `full-test.sh` only for `--vmm fc`, in the selected
profile. QEMU/Cloud Hypervisor runs retain qcow2 for their standard suite and
use the existing raw base image for a non-selected Firecracker boot check.

If a developer-image gate is needed, use only
`src/tests/full-test-dev.sh --release`, including its release-only
`test-dev-sources.sh` phase. This is not Lorry work. No debug developer-image
run or Lorry changes are planned. Firecracker is not supported or required
for this gate, including its boot checks; reject `--vmm fc` before builds or
VM launches. Do not add a raw developer image or silently substitute a main
image or a different VMM. Supported QEMU/Cloud Hypervisor selection still
propagates to both developer VM phases (D16).

Completion means an application using moto-io can use the approved stream
operations through sys-io and the real virtio queues; flow control and
teardown remain bounded under the listed tests; both present/absent-device
configurations work on all three VMMs with UDS peers; CAP_VSOCK cannot be
escalated or bypassed; errors follow D14; required tests are reachable from
full-test; and the agreed boot/performance checks pass. A discovered PCI
device or a packet echo alone is not completion of the integration.

## Decisions

D1–D13 answer the v1 open questions Q1–Q13 under the same numbers. D14 is
the error-mapping decision from the second review; D15 and D16 answer the
launch-infrastructure questions Q14 and Q15 raised after it. All were
approved on 2026-09-14; they are requirements, not proposals. This revision
clarifies backpressure, half-close, lazy initialization, and TX accounting
without changing the agreed architecture. Q16 is resolved in D16: the raw
standard image is opt-in, and developer-image Firecracker support is excluded.
D17 resolves implementation question Q18, approved on 2026-09-15: retain
RX used-ring order inside virtio-async, with no `IN_ORDER` requirement or
sorting in sys-io/moto-io.
D18 and D19 resolve Q19 and Q20, approved on 2026-09-15. The same review
approved Q22's dependency adjustment in D13. D20 records the subsequent
decision to defer Q21 and exclude hardening against buggy or malicious VMMs.
D21 resolves Q23: discovery uses the same capability and missing-device errors.
D22 resolves Q24–Q25: wrong-state packets and receive-credit overruns reset
only their identified connection.
D23 resolves Q26: include the shared NET subchannel validation fix and its
guest regression before continuing vsock integration.
D24 resolves Q27 by comparing the failed fixture against Linux and correcting
its test protocol, without changing VMMs or the Motor shutdown contract.

### D1. Profile and topology (approved)

- Virtio 1.1, stream-only, modern PCI; no legacy or newer socket features.
  A1's earlier multi-vsock and seqpacket requirements are superseded.
- One vsock device; no multi-vsock implementation or tests.
- Keep generic virtio/IRQ infrastructure compatible with multiple NICs and
  block devices. Do not impose a one-NIC topology to make vsock fit.
- Preserve sys-io's second-block-device rejection until multiple filesystems
  arrive. Do not change root-disk selection or implement secondary-disk use.
- Multiple NICs should continue working; new multi-NIC testing/fixing is out
  of scope except as needed for diagnosed virtio-related bugs under the
  subsequent scope authorization in stage 1. Existing tests and ordinary
  networking regressions still run.
- Host CID 2 is the only required peer. Guest-to-guest routing and
  guest-local loopback are not implemented or tested.

### D2. Ownership (approved)

virtio-async owns packet/event I/O; sys-io owns connection state, credits,
listeners, and client routing. RX completion ordering and the bounded device
RX pool belong to virtio-async; sys-io receives packets already ordered (D17).
No socket framework in the driver crate and no new reusable protocol crate.

### D3. HeaderBuffer reuse (approved)

Reuse `HeaderBuffer` and `get_buffer<T>()`; their lifetime rules already fit
vsock. Allocate 64-byte scratch for vsock queues, keeping block/net at 16
bytes, selected by device kind at queue allocation. Replace the debug-only
size assertions in `get_buffer<T>` and `read_header<H>` with release
capacity/alignment checks and update the memory-backed fixture. Retain the
existing completion ownership and use one page-aligned payload buffer per
data packet.

Three 256-entry vsock queues use 48 KiB of scratch; block/net remain
unchanged. Uniform 64-byte scratch was rejected because it adds 12 KiB per
existing 256-entry queue.

### D4. Networking reuse (approved)

Add a vsock stream variant alongside TCP and UDP, plus a vsock listener, on
the same endpoint. Reuse client identity, socket IDs, reservations, pages,
notification queues, and cancellation plumbing. The concrete changes are in
`SocketState`, IP-specific `SocketBase` fields/drop, listener dispatch, and
`NetClient`'s TCP-specific maps/waiters. A vsock socket must not require a
NIC index or netstack socket handle. Existing TCP/UDP wire values and
behavior remain unchanged.

Keep shared endpoint admission/dispatch available when vsock is present
even if IP configuration yields no devices, including no loopback. The
early return on `devices.is_empty()` in `runtime/net.rs::init` currently
suppresses the entire service; separate this decision from IP-backend
startup. Do not start IP-only tasks or write DNS configuration just to
serve vsock. Preserve the existing disabled-service path when neither IP
devices nor a vsock device exist, and keep device activation lazy (D9).

### D5. Native API (approved)

`VsockAddr`, `VsockStream`, and `VsockListener` in `moto_io::net::vsock`,
created through the existing client/reservation model. The caller drives the
same `NetDriver` as TCP/UDP, and handles reuse existing Arc/waiter
synchronization. The surface is connect, bind/accept, read/write, shutdown,
addresses, local-CID/availability discovery, and existing-style
readiness/try-I/O where reusable; no blocking wrapper, new socket options,
or FD integration. Partial-write and cancellation semantics follow the
existing networking behavior and are defined before signatures are published.

### D6. Byte-credit accounting (approved)

`tcp_read_task` first reserves an IPC page, then removes bytes with
`recv_slice`, reopening the server TCP receive window. The client later
frees whole pages; `TcpStreamRxAck` wakes the server but carries no
consumed-byte count. Vsock uses exactly that separation: it advertises its
sys-io receive-buffer capacity and advances `fwd_cnt` when bytes are moved
into a reserved IPC page. IPC storage stays independently bounded; a stalled
client eventually fills both stages. No end-to-end byte acknowledgement.

For TX, use one submission pump. Check peer credit and descriptor/buffer
capacity, then publish the packet and advance `tx_cnt` in one non-yielding
operation. Count only published payload bytes; header/control bytes do not
consume credit. A failed try-post leaves the counter unchanged. Pending
IPC data has not spent peer credit, so dropping unsent data needs no credit
rollback or second ledger. Multiple pending writes cannot independently
reserve the same credit. Submitted bytes remain charged despite caller
cancellation; a TX completion returns DMA ownership, not peer byte credit.

### D7. Resource bounds (approved as starting bounds)

TCP uses 128 KiB RX/TX defaults; native net reservations divide each
direction's IPC pages into four 16-page subchannels, or 64 KiB per reserved
socket. Reuse the reservations/page pools and the 128 KiB RX size. Vsock
needs neither TCP retransmission storage nor UDP's dropping queues. These
bounds may be revised only with review, based on the stage 15 measurements.

| Resource | Starting bound |
| --- | --- |
| Queue sizes | Use existing negotiated power-of-two sizes, capped at 256; require RX capacity of at least two, TX at least 16 for the reserve below, and event at least one. |
| RX payloads | `min(64, rx_descriptors / 2)` page-sized buffers, reposted promptly while ready. |
| TX payloads | `min(64, (tx_descriptors - 8) / 2)` page-sized buffers; reserve eight descriptors for control. |
| Events / pending control | Up to four posted event buffers; 64 pending control records, coalescing credit updates. |
| Stream receive buffer | Fixed 128 KiB in sys-io, allocated/charged before establishing a connection. |
| Stream IPC / pending TX | Existing 16 pages per direction per reservation; no additional per-stream TX ring. |
| Stream/listener admission | 64 streams globally, counting connecting, unaccepted, and closing states; 32 listeners, backlog eight each, still within the global stream cap. |
| Pending accepts | Eight waiting accept RPCs per listener, independent of its stream backlog (D25). |
| Per-channel admission | Existing four data reservations and channel budget; no separate quota framework. |

At 256 descriptors per queue, the RX/TX pools hold at most 512 KiB of
payload, plus 48 KiB of header scratch, ring allocations, and bookkeeping.
Sixty-four receive buffers reserve 8 MiB before IPC pages and other overhead.
Check total committed memory against the selected VM's memory budget (D16);
the 64 MiB Firecracker interactive default is not the full-suite budget.
Admission/allocation failures follow D14 without killing existing streams;
temporary I/O capacity exhaustion is backpressure, not `OutOfMemory`.
Allocate on demand, not at boot or for every potential connection.
After permanent device failure, retire returned RX/event buffers without
reposting; retain any still-device-owned memory (D26).

Pack small payloads into byte buffers, bounding metadata independently of
wire packet count. Round-robin ready streams with bounded work per turn;
stop accepting new work at capacity, preserve active-stream data, and keep
reserved control/completion work runnable. No timers for idle credit probing,
new adaptive-buffer policy, or unbounded per-request tasks.

### D8. CAP_VSOCK and addressing (approved)

CAP_VSOCK is bit 7, required for discovery (D21), connect, and listen. It is
included in the default child grant for every role when the parent holds it,
so normal system and user processes start with it. Only parents holding the bit may
grant it, including System parents; `CAP_SYS` is not an override. Delegation
is transitive; explicit denial is by `MOTOR_OS_CAPS`. Stage 2 covers the
kernel rule and the default helper.

Because explicit masks replace or intersect capabilities at every hop
(constraint 11), the following sites change so the default actually reaches
applications and the test suite:

| Site | Today | Change |
| --- | --- | --- |
| `img_files/{motor-os,motor-os-base,test-system-tty}/system/cfg/sys-init.cfg`, russhd line | `svc:124` | `svc:252` (adds 128) with the comment updated. |
| Same files, dns-resolver line and strobe launch | `svc:8`; `CAP_SYS \| CAP_LOG` | Unchanged; neither uses vsock. |
| `src/sys/sys-init/src/main.rs` tty mask and `src/sys/sys-tty/src/main.rs` shell mask | IO manager (sys-init only), spawn, log, detached, role | Forward `own & CAP_VSOCK`; preserve unrelated mask semantics. |
| `src/bin/russhd/src/local_session.rs` shell allowlist | `own & (spawn \| log \| detached \| role)` | Add CAP_VSOCK to the allowlist. |
| `src/bin/rush/src/sys/motor.rs` `ordinary_child_cap_grant` (System shells) and `detach_cap_grant` | `own & (sys \| spawn \| log)`; `own & (spawn \| log \| detached \| role)` | Add CAP_VSOCK to both allowlists. Non-System rush children use the default helper and need no change. |
| `full-test.sh`, `full-test-networking.sh`, `stress-soak.sh` systest launches | `MOTOR_OS_CAPS=0x4c` | `0xcc`. |
| `full-test.sh` stdio suite and `test-terminal-size.sh` rmux launch | `0x6c` | `0xec`. |
| `test-system-tty.sh` admission and mmio cases (`0xd`, `0x4e`), `test-sftp.sh` (`0x4`) | explicit | Unchanged; they do not use vsock, and `0x4` doubles as a denial case. |
| sys-io launching sys-init | all bits | Unchanged. |

Addressing: `VsockAddr { cid: u32, port: u32 }` for peer addresses, with
`bind(port)` using the current local CID supplied by sys-io. Port zero
requests automatic allocation from a collision-checked range starting at
49152, consistent with the native networking API. An explicit bind to
`0xffffffff`, or a connect to port 0 or `0xffffffff`, fails with
`InvalidArgument`. Any CAP_VSOCK holder may bind any other explicit port. No
privileged-port classes, cross-device wildcard binds, or reuse options.
Tuples stay reserved through close so automatic reuse cannot attach to an
old connection. Linux uses `0xffffffff` as its wildcard and reserves ports
below 1024; these native conventions differ but do not affect wire
interoperability.

Those restrictions apply to native bind/connect requests, not an incoming
peer's source port. Preserve the complete `u32` source port in accepted
tuples and accept replies, including 0 and `0xffffffff`.
[Virtio 1.1 section 5.10.6.2](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html)
does not reserve wire port values; Linux's
[receive/listen path](https://github.com/torvalds/linux/blob/v6.12/net/vmw_vsock/virtio_transport_common.c#L1410-L1524)
also copies the source port without applying userspace bind sentinels.
In particular, vhost-device-vsock 0.3.0 starts allocating host source ports
at zero. Reusing connect-target validation here incorrectly refused its
first incoming connection; no backend adjustment is needed.

### D9. Lazy initialization (approved)

Lazy init, an unchanged no-device boot path, and no hot-plug or unplug.
Host-to-guest service becomes available only after an authorized guest
operation activates the device and binds its listener; that is a consequence
of lazy initialization, not a boot-time host handshake.

Use absent/dormant/ready/failed state owned by the existing `LocalRuntime`.
Keep first-use initialization synchronous, as in blk/net, using nonblocking
queue setup/publication without awaiting the host. Authorization precedes
activation. An authorized availability query reports discovery without
activation and follows D21's error ordering; querying the actual CID may
initialize. With no initialization-time `await`, the executor serializes
first callers and later callers see the cached
result; no shared initialization future or waiter list is needed.
Cancellation cannot interrupt setup or own the device's lifetime. Prepare
allocations before DMA publication where possible and retain any memory
already visible to the device on failure. If setup genuinely requires an
`await`, revisit that requirement before adding an asynchronous initialization
protocol. Do not create vsock queues, buffers, or pumps for an unused device.

Retain the first discovered vsock device and log/ignore any additional
devices without initializing their queues. Failed initialization leaves
vsock unavailable while fs/IP continue; cache the failure and do not
automatically retry, rescan, or rebuild queues. A fatal later configuration
failure similarly fails vsock clients without dropping outstanding DMA
ownership. A transport-reset event uses the same permanent failed state
(D26); listeners do not survive and the CID is not refreshed. Availability
reports the cached failure instead of merely reporting previous discovery.

### D10. Deadlines and close (approved)

Linux v6.18 provides the reference:

| Behavior | Linux reference | Motor |
| --- | --- | --- |
| Connect timeout | 2 seconds in `af_vsock.c`. | 2 seconds, reusing native deadline/cancellation machinery. |
| Virtio transport close cleanup | 8 seconds in `virtio_transport_common.c`. | An 8-second bounded server cleanup deadline. |
| Read/write waits | Generic socket defaults have no timeout. | No implicit I/O timeout; callers use existing cancellation/deadlines. |
| Blocking linger | Opt-in through `SO_LINGER`. | Nonblocking Drop; no linger option initially. |

Sources: [Linux vsock defaults/linger](https://github.com/torvalds/linux/blob/v6.18/net/vmw_vsock/af_vsock.c),
[virtio close timer](https://github.com/torvalds/linux/blob/v6.18/net/vmw_vsock/virtio_transport_common.c),
and [generic socket initialization](https://github.com/torvalds/linux/blob/master/net/core/sock.c).
Motor's existing TCP constants are 123 seconds for connect and 60 seconds
for default linger; reuse their machinery, not those durations.

Native policy: explicit async shutdown drains accepted TX before sending
shutdown; Drop or client exit starts nonblocking bounded cleanup with a
single 8-second budget including pending-data drain, then a forced reset if
necessary. Keep already validated buffered RX readable before reporting a
connection-local peer/protocol reset, distinguish orderly EOF, and never
reuse an old tuple before terminal cleanup. A completed write is local
acceptance, not proof of peer receipt.
Device-wide failure, including transport reset, instead discards buffered
RX and fails pending operations immediately (D26).

Shutdown is directional and permanent. Peer SEND shutdown produces local
EOF after queued RX data, but leaves local writes usable. Local SEND or peer
RECEIVE shutdown stops local writes (D14). Accumulate shutdown flags and
complete graceful close with the protocol's reset exchange. Distinguish
that orderly RST from an unsolicited reset.

### D11. VMM coverage (approved)

QEMU, Cloud Hypervisor, and Firecracker, each with unprivileged UDS host
backends and no migration. Cloud Hypervisor is the development VMM for the
first real-device work. `vhost-device-vsock` is approved as the QEMU host
prerequisite; it avoids host `AF_VSOCK`, `/dev/vhost-vsock`, FFI in the
Rust peer, and backend source changes. The QEMU launch follows D15 and the
gate arrangement D16. Keep all guest protocol/API code identical across
VMMs and make missing prerequisites a clear gate failure, never a successful
skip.

Pin the released `vhost-device-vsock` crate version `0.3.0` in `test-vsock.sh`,
document installation in `docs/tools.md`, and check the binary/version
before launching. Installation is developer setup, not test work. QEMU
needs a separate vhost-user control socket as well as the peer UDS path.
Firecracker already uses `--enable-pci`; no virtio-MMIO driver is needed.

| VMM | Transport/backend | Evidence and remaining validation |
| --- | --- | --- |
| QEMU | Modern `vhost-user-vsock-pci` plus UDS `vhost-device-vsock`; shared guest RAM. | Installed QEMU 10.2.1 exposes that device. Released backend `0.3.0` was installed in an isolated setup directory as recorded below; add its `bin` directory to PATH for tests. |
| Cloud Hypervisor | Built-in `--vsock cid=3,socket=<path>`. | Installed v52.0; native vsock config is a singleton and its protocol is streams over UDS. |
| Firecracker | Built-in `vsock` JSON configuration over PCI and UDS. | Installed v1.15.1 with `--enable-pci`; native config stores one device. |

Sources: [Cloud Hypervisor's vsock documentation](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/vsock.md),
[its config representation](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/v52.0/vmm/src/vm_config.rs#L733-L739),
[Firecracker's vsock builder](https://github.com/firecracker-microvm/firecracker/blob/main/src/vmm/src/vmm_config/vsock.rs),
and the [vhost-device-vsock README](https://github.com/rust-vmm/vhost-device/blob/main/vhost-device-vsock/README.md).
These are source/help checks, not completed Motor guest interoperability
tests. D17 records the release-specific ordering-feature audit: CHV and
Firecracker offer `IN_ORDER`, but the approved QEMU/backend combination does
not. Therefore it cannot be a required feature for this common driver.

Development setup on 2026-09-15 installed the locked released crate into
`/tmp/vsock-vhost-backend.6RFS2s/`; its binary reports
`vhost-device-vsock 0.3.0`. The install log is `install.log` there. This was
an explicit setup download/build, not test execution; no external source
files were edited. The dependency `nix 0.29.0` emitted a future-compatibility
warning. No backend or VMM interoperability test is implied by installation.

### D12. Test route (approved)

Guest systest only, in both profiles via full-test. No host-helper unit
suite and no sys-io `SELF_TESTS` registrations. Extend the existing guest
queue-fixture route and compile the real pure credit/state helpers into
systest by source include, as `virtio-task-tests` already does. The host UDS
peer supplies actions/data only. Reset fixtures do not imply VMM migration
coverage. If testing requires a new production injection hook or self-test
entry point, stop and discuss it before adding one; do not silently replace
missing coverage with a debug-only test.

### D13. Gate schedule (approved)

Incremental commits are grouped into two repeated milestones. Q22's approved
adjustment replaces the original literal stages 1–6 / 7–15 boundary:

- M1: capability, modern-driver/shared-queue, fixed-pool, pure credit, and
  bounded receive-storage foundations, with executable guest fixtures.
- M2: integrated Stage 5 pumps and Stage 6 accounting/scheduling alongside
  stages 7–15's connection, IPC, native API, activation, cleanup, and VMM work.

RX dispatch and event reactions need connection state; TX scheduling needs
real per-stream work; the reserved-page copy boundary needs IPC ownership.
Implement and test them together in M2. Idle pumps or a substitute transport
framework are not M1 requirements or substitutes for integration coverage.

Each milestone still requires three passing debug and three passing release
main-image full-test runs on the default VMM. M2 adds one debug and one
release run with `--vmm chv` and with `--vmm fc` (D16). Every commit runs its
affected guest tests in both profiles; bring required test plumbing forward.
No case is dropped or counted as covered by a weaker fixture. Do not skip a
VMM, weaken assertions, or add retries to save gate time. A failed milestone
stops progression for diagnosis; preserve the original failure even if a
later diagnostic run passes. M1 is complete as recorded in the progress
section; M2 remains pending.

### D14. Error mapping (approved)

Vsock handlers and the native API use existing `moto_rt::Error` values as
follows. Handlers construct them directly; `util::map_err_into_native` and
the TCP mappings are unchanged, and moto-rt is not expanded.

| Condition | Error |
| --- | --- |
| No vsock device discovered | `NotFound` |
| Device initialization, later configuration, or transport reset permanently failed the device (cached) | `InternalError` |
| Caller lacks CAP_VSOCK | `NotAllowed` |
| Unsupported operation, socket type, or option | `NotImplemented` |
| Invalid CID or port, including port 0 or `0xffffffff` on connect | `InvalidArgument` |
| Bind conflict | `AlreadyInUse` |
| Connect refused by the peer, including no listener or exhausted peer admission/backlog capacity | `NotConnected` |
| Established stream reset by the peer or for a protocol violation covered by D19/D22 | `ConnectionReset` |
| Write after local SEND or peer RECEIVE shutdown, or on an orderly closed stream | `NotConnected` |
| Connect deadline expired | `TimedOut` |
| Local stream/listener admission limit, or allocation failure for a new socket's required buffer/reservation | `OutOfMemory` |
| Try-I/O has no immediately available data/capacity and has made no progress | `NotReady` |
| Unknown, stale, or foreign socket handle on the wire | `NotFound`, as the existing net handlers report |
| Orderly EOF on read | `Ok(0)`, not an error |

Peer SEND shutdown alone is not a write error (D10). Retain the terminal
reset cause rather than turning `ConnectionReset` into `NotConnected`
merely because the stream is now closed; drain validated RX first per D10.
This is connection-local behavior. Device-wide failure uses `InternalError`
and discards buffered RX rather than delaying the error (D26).

Peer-credit stalls, full queues/buffers, and busy IPC pages on established
streams are ordinary backpressure. Preserve accepted bytes and return a
successful partial write when possible. If no progress is possible,
try-I/O returns `NotReady` and async I/O remains pending with a concrete
capacity/data wakeup, following the existing TCP API. Do not report
`OutOfMemory`, drop buffered RX, or fail the stream for these conditions.
A remote REQUEST exceeding local backlog/admission capacity receives the
protocol refusal (RST); it is not a local native `OutOfMemory` reply to the
peer. An accept on an empty live listener waits for a connection.

### D15. QEMU shared guest RAM (approved)

`vhost-user-vsock-pci` needs shared guest RAM, which QEMU provides through
`-object memory-backend-memfd,share=on` plus `-machine memory-backend=`.
`run-qemu.sh` emits `-mem-path` with the hugetlbfs pool whenever one is
available, and the installed QEMU rejects the combination:

```
qemu-system-x86_64: '-mem-path' can't be used together with'-machine memory-backend'
```

Add an opt-in `MOTO_SHARED_MEM=1` to `run-qemu.sh` that replaces the memory
backend with
`-object memory-backend-memfd,id=mem0,size=${MEMORY_MIB}M,share=on` (adding
`hugetlb=on` when the pool is available) and `-machine memory-backend=mem0`.
The default launch is unchanged, so boot-time measurements and every other
phase keep their configuration; `test-vsock.sh` sets the variable for its
QEMU VM only. The edit is in `src/vm_scripts/`, copied to `vm_images/` by
make. Making shared memfd the runner default was rejected because it would
change the boot-time-measured configuration for every run.

### D16. VMM selection, boot checks, and the Firecracker image (approved)

Running the whole suite on every VMM in every run is too long. Instead:

- `full-test.sh` takes an optional `--vmm qemu|chv|fc` parameter selecting
  the VMM that runs the complete suite, including the vsock phase. The
  default is `qemu`. `full-test-dev.sh` passes supported `qemu|chv`
  selections to both its VM phases, but rejects `--vmm fc` before any image
  build or VM launch. No raw developer image or Firecracker dependency is
  added to the developer-image gate; Firecracker coverage is standard-only
  (Q16, approved).
- Every standard main-image run also boot-checks the two VMMs not selected:
  boot the image, wait for SSH exactly as `start_test_vm` does, run one
  trivial remote command through russhd, confirm the VMM process is still
  alive, and stop it. The selected VMM is proven by the suite itself. QEMU and Cloud
  Hypervisor boot `motor-os.qcow2`; Firecracker boots the raw
  `motor-os-base.img`, so `base.img` joins the make targets the suite
  builds. A boot check that fails is a suite failure, never a skip.
- Add a special `raw.img` make target producing `motor-os.img` with the
  normal/standard image's contents in raw format, preferably through an
  imager format override rather than a second copy of `motor-os.yaml`.
  Keep it out of default `make`, `all`, `images`, and ordinary image-target
  dependencies: build it only when explicitly requested, such as
  `make raw.img` or `make raw.img BUILD=release`. Standard
  `full-test.sh --vmm fc` requests this target in its selected profile and
  sets `IMG_TARGET=raw.img` / `MOTO_IMAGE=motor-os.img`. Other suite VMM
  selections must not request it, even for Firecracker's base-image boot
  check. The raw base image lacks the programs needed for the full suite.
  Resolve runner, build profile, image target, and filename together using
  the matrix below; preserve phase-specific overlays and caller overrides,
  rejecting incompatible combinations before launch. Build all required
  suite/boot-check images in the selected profile, without stale-image reuse
  or image targets deleting one another's outputs.
- Each selected VMM uses the same CPU count and memory as the corresponding
  QEMU phase today, through `MOTO_SMP` and `MOTO_MEMORY_MIB`. Preserve caller
  overrides and developer-phase budgets; `run-fc.sh`'s 2-CPU, 64 MiB defaults
  are for interactive use, not the full suite.
- Preparatory work before stage 14's scripts adds the same `flock` to
  `run-chv.sh` and `run-fc.sh`, generalizes `start_test_vm`, and covers every
  launch site listed below. Use a small common runner/image-selection helper,
  not a general VM framework. Keep standalone callers' QEMU default. Prove
  the boot checks on all three VMMs in debug and release and adjust the
  full-test timeout only by the measured added work, recording it here.
- Run boot checks and the dedicated vsock VMs sequentially before the
  long-lived main test VM starts. Stop and wait for each VMM to exit before
  starting another, releasing the shared lock/tap/address. The main VM today
  survives until the suite's exit cleanup; simply appending another VM phase
  before that cleanup would collide with it.
- `test-vsock.sh` boots its device-attached VM on the selected VMM, uploads
  systest over sftp as `full-test.sh` does, runs the vsock command, and
  stops the VM; stage 14's IP-disabled subcase uses the serial console.
  Runner-specific device arguments are D15's opt-in for QEMU, an extra
  `--vsock cid=3,socket=<path>` argument for Cloud Hypervisor, and a new
  `MOTO_FC_VSOCK_UDS` knob that emits `guest_cid`/`uds_path` in Firecracker's
  internally generated JSON. Extra runner arguments cannot supply that JSON.
  Change sources in `src/vm_scripts/`, not generated `vm_images/` copies;
  keep ordinary runners usable without attaching a vsock device.
- The repeated gate stays on the default VMM; M2 adds one debug and one
  release run with each other VMM (D13).

| Suite/phase image | QEMU / Cloud Hypervisor | Firecracker |
| --- | --- | --- |
| Main suite, including ordinary TUI/terminal and vsock phases | `main.img` -> `motor-os.qcow2` | Explicitly requested `raw.img` -> `motor-os.img`, same standard-image contents. |
| System-console phase | Existing `system-tty.img` -> raw `motor-os-system-tty.img` | Same raw test image; retain its System-console overlay. |
| Developer-image phases | `dev.img` -> `motor-os-dev.qcow2` | Not supported; no raw developer image or Firecracker gate requirement. |
| Non-selected VMM boot check in the standard suite only | Main qcow2 image | `base.img` -> raw `motor-os-base.img`; does not request `raw.img`. |

The IP-disabled vsock discovery phase uses the existing isolated raw
`motor-os-vsock-test.img` on all three VMMs, which all support raw disks.
Its test-only overlay and installed systest do not overwrite any ordinary
image. The peer phase still uses the selected standard/developer suite image
and format from the table above; this adds no Firecracker developer support.

| Guest launch site | Required propagation/change |
| --- | --- |
| `full-test.sh` / `vm-test-boot.sh::start_test_vm` | Parse/forward profile and VMM consistently, including the timeout wrapper; pass the resolved runner/image to the main VM and boot checks. Do not pass QEMU-only arguments to other runners. |
| `test-system-tty.sh` | Replace its direct QEMU launch with the selected runner, keeping its raw test image and serial-console input. |
| `test-tui.sh`, `test-terminal-size.sh` | Replace direct QEMU launches and inherit the selected suite image/profile. Preserve FIFO input and adapt console escape handling so each VMM delivers the same guest input. |
| `full-test-dev.sh` / `test-dev-sources.sh` | Propagate `qemu|chv` selection to both VM phases, retaining the developer qcow2 image. Reject `fc` before builds/launches and do not run Firecracker boot checks through the wrapped suite. Keep the Lorry gate unchanged and developer-image validation release-only. |
| New `test-vsock.sh` | Use the same selection, add the approved device/backend configuration, and handle its IP-disabled serial-console subcase. |

Generalizing `start_test_vm` alone is insufficient: the listed subtests
currently launch QEMU directly. Verify phase logs identify the selected
runner, image, and profile; no silent fallback to QEMU or skipped console
assertions. Standalone networking/stress-soak VMM selection is not added by
this work.

### D17. RX completion ordering inside virtio-async (approved)

Resolves Q18, approved on 2026-09-15. Preserve the order already recorded in
the RX used ring instead of reconstructing it from independently ready
futures. Do not negotiate `VIRTIO_F_IN_ORDER`. Continue supporting the three
VMM/backend paths in D11 with one common implementation.

| Component | Responsibility |
| --- | --- |
| `virtio-async/src/virtio_queue.rs` | Expose the next completion in device used-ring order through a narrow crate-private accessor. Keep existing ring reclamation, DMA ownership, and block/net completion APIs. |
| `virtio-async/src/virtio_vsock.rs` | Own the bounded RX buffer/completion pool; resolve and validate packets using that ordered accessor before delivering them to sys-io. |
| sys-io | Process already ordered packets, maintain connection/credit state, and append payloads to each stream's bounded receive buffer. No completion sorting. |
| moto-io | Expose native streams and manage client IPC/waits. No virtqueue ordering knowledge or sorting. |

#### Can all three VMMs negotiate `VIRTIO_F_IN_ORDER`?

No, for the actual vsock paths approved in D11. The 2026-09-15 audit checked
the installed VMM versions, their upstream release sources, and the released
`vhost-device-vsock` 0.3.0 backend. This is source/help evidence, not a live
Motor guest feature-negotiation test. The backend has since been installed
as recorded in D11, but has not yet been exercised by a Motor guest. Recheck
its mask if the test prerequisite is pinned to a different release.

| VMM / vsock path | Offers bit 35 (`IN_ORDER`)? | Release-source evidence |
| --- | --- | --- |
| QEMU 10.2.1, `vhost-user-vsock-pci` + `vhost-device-vsock` 0.3.0 | No with this backend. The QEMU frontend supports forwarding the bit. | QEMU includes it in [`user_feature_bits`](https://github.com/qemu/qemu/blob/v10.2.1/hw/virtio/vhost-user-vsock.c#L19-L27), but [`vhost_get_features_ex`](https://github.com/qemu/qemu/blob/v10.2.1/hw/virtio/vhost.c#L1904-L1916) clears bits absent from the backend. The backend's [`features()`](https://github.com/rust-vmm/vhost-device/blob/vhost-device-vsock-v0.3.0/vhost-device-vsock/src/vhu_vsock.rs#L299-L304) contains `VERSION_1`, `NOTIFY_ON_EMPTY`, `EVENT_IDX`, and the vhost-user protocol-feature bit, not `IN_ORDER`. |
| Cloud Hypervisor v52.0, built-in PCI vsock | Yes, by default for a fresh device. | [`Vsock::new`](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/v52.0/virtio-devices/src/vsock/device.rs#L368-L405) advertises `VERSION_1 \| IN_ORDER` (`0x0000_0009_0000_0000`), optionally also `ACCESS_PLATFORM`. Its [`PCI common configuration`](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/v52.0/virtio-devices/src/transport/pci_common_config.rs#L351-L382) exposes the device's mask directly. |
| Firecracker v1.15.1, built-in PCI vsock | Yes, by default. | [`AVAIL_FEATURES`](https://github.com/firecracker-microvm/firecracker/blob/v1.15.1/src/vmm/src/devices/virtio/vsock/device.rs#L52-L57) is `VERSION_1 \| IN_ORDER` (`0x0000_0009_0000_0000`); [`PCI common configuration`](https://github.com/firecracker-microvm/firecracker/blob/v1.15.1/src/vmm/src/devices/virtio/transport/pci/common_config.rs#L301-L314) exposes that mask directly. |

QEMU's `in_order` property defaults to off, as confirmed by the installed
binary's `-device vhost-user-vsock-pci,help` and its
[property definition](https://github.com/qemu/qemu/blob/v10.2.1/include/hw/virtio/virtio.h#L388-L404).
Setting it on cannot supply missing backend support: the backend framework
[returns the backend mask and rejects unsupported acknowledgements](https://github.com/rust-vmm/vhost/blob/vhost-user-backend-v0.20.0/vhost-user-backend/src/handler.rs#L270-L277).
This is not a claim that every QEMU backend lacks the feature. Do not change
backends, spoof the feature, or patch external sources to satisfy it.

Consequently, leave negotiation unchanged: require `VERSION_1`, optionally
accept `EVENT_IDX`, and do not negotiate or require `IN_ORDER`, even where
offered. This preserves one driver path across the three supported VMMs.
Observed FIFO behavior without the negotiated bit is not a portable contract.

Also, `IN_ORDER` would not be a feature-mask-only change to this split queue.
[Virtio 1.1 sections 2.6.5.2 and 2.6.9](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html)
impose sequential descriptor-chain indices and permit batched completions
that omit individual used entries. Motor's free-list allocator and
one-used-entry-at-a-time reclaimer do not implement that negotiated mode.
Do not enable it without implementing and testing those semantics.

#### Why are the existing block/net futures not sufficient for vsock RX?

Distinguish three orders: posting empty receive buffers, device completion
in the used ring, and polling ready futures. The device need not use buffers
in posting order without `IN_ORDER`; the used ring tells the driver which
buffer was used next. [Virtio 1.1 section 2.5](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html)

The existing [shared queue](../../src/sys/lib/virtio-async/src/virtio_queue.rs)
already walks that ring correctly in `reclaim_used`, using `next_used_idx`.
But `reclaim_task` discards the returned chain heads after marking them ready,
and `VqCompletion::do_poll` returns only that individual buffer and its result.
It exposes no ordering relationship between two ready completions. Waking
futures in ring order does not fix this: wakes may coalesce, and a completion
may already be ready before its first poll. Neither `FuturesUnordered` nor
a FIFO of submitted futures establishes used-ring delivery order.

For example, post empty buffers A then B. The device puts stream bytes
`hello` into B, then `world` into A, and publishes used heads B then A.
The reclaimer marks both ready. Awaiting A then B delivers `worldhello`,
although the device supplied `helloworld`. Nothing in either successful
future result indicates the reversal. This is an illustrative permitted
ordering, not an observed failure of one of these backends.

- Block requests identify their sectors and destination buffers before
  submission. Reading B's completion before A's does not exchange their data
  or change which sectors they refer to. Dependencies between writes and
  flushes still require the existing higher-level sequencing; sorting ready
  futures would not impose device execution or persistence order. See
  [`BlockDevice::try_request`](../../src/sys/lib/virtio-async/src/virtio_blk.rs).
- Net RX delivers independent Ethernet frames into the IP stack. Its current
  [`rx_task`](../../src/sys/sys-io/src/runtime/net/device.rs) awaits a deque in
  submission order, but TCP reconstructs byte order from TCP sequence numbers
  using its [receive assembler](../../src/sys/sys-io/netstack/src/socket/tcp.rs).
  UDP does not promise ordered delivery. Packet reordering can still hurt
  latency/throughput; this is not a claim that arbitrary reordering is free
  or that the current net path needs no further testing. It does not silently
  redefine the TCP byte stream as polling order.
- Vsock bypasses that IP/TCP layer. Its wire header has no payload sequence
  number with which sys-io could repair reordered packets. `buf_alloc` and
  `fwd_cnt` describe receive-side credit, not the position of this packet's
  payload. Data and connection-control packets must reach the vsock state
  machine in their stream order. See the
  [wire and stream definitions in sections 5.10.6–5.10.6.3](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html).
  Linux preserves used-ring order by consuming and immediately dispatching
  each packet in
  [`virtio_transport_rx_work`](https://github.com/torvalds/linux/blob/v6.18/net/vmw_vsock/virtio_transport.c#L611-L671).

Thus the transport machinery is reusable, but its current independent-future
interface omits information this new consumer needs. Preserving the whole
RX used-ring order is the simple way to preserve every stream without a
per-stream sorting protocol. This does not identify a preexisting block/net
bug or authorize changing their completion contracts. TX completions remain
DMA-ownership reclamation; TX packet submission must preserve stream order,
but sorting TX completion futures is not what provides that guarantee.

#### Ordered accessor and lifetime contract

Use an ordered-head accessor over the existing used ring, with an RX-owner
cursor and a head-to-owned-completion lookup inside virtio-async. Observe
only completions already processed by the existing reclaimer; the accessor
must not reclaim or release a descriptor chain a second time. Initialize
the consumer cursor before publishing the first RX buffers. Keep the lookup
bounded by D7's RX pool, not by the number of streams or application reads.

The concrete accessor claims one idle queue once and holds a wrapping cursor
plus one queue-level completion waiter. Check both device-published and
reclaimed lag against queue capacity before reading the retained slot;
exactly one ring's worth is valid. An empty poll waits for the existing
reclaimer, which wakes it after advancing its boundary. Dropping the cursor
removes its waiter without releasing DMA ownership or reopening the claim.

Do not read a ring slot after device reuse. Retain all undelivered buffers
within the bounded RX pool, consume each ordered result before reposting
its buffer, and enforce the ring-lag bound across wrapping counters. The
pool bounds undelivered completions as well as outstanding DMA. Preserve
the existing wakeup and completion-drop rules; an empty ordered view must
have a concrete completion wakeup, never a polling timer or a lost wakeup.

For each next used head, resolve and validate its owned completion. Deliver
the packet or applicable refusal metadata to sys-io in that order, or
discard an invalid packet before fetching another head. The raw-ring cursor
advances when a head is fetched; the RX owner must resolve and handle that
already-ready completion synchronously, before another fetch, repost, or
await. No per-head token or separate acknowledgement phase is needed.
Malformed packets must not stall ordered consumption or leak buffers.
Prepare all RX pages and bookkeeping fallibly before publishing anything;
claim the idle cursor and publish only after device setup permits it. The
fixed pool then uses a synchronous consume callback: resolve the next head,
provide validated bytes and metadata (or empty bytes and refusal metadata),
and repost the same page after the callback returns while ready. sys-io
copies accepted bytes into bounded stream storage in that callback; applications never own
device RX pages. Publication and consumption need no further driver-side
allocation. Retain the active pool with its device on cached failure;
cancellation of a client operation must not drop outstanding DMA owners.
After failure, consume only returned completions, without dispatch callbacks
or reposting; retain buffers whose ownership has not returned (D26).

No separate sorting pass, completed-head FIFO, per-descriptor sequence tag,
or per-stream reorder protocol is part of this approach. Test opposite
submission/completion/polling orders, multiple completions before the first
poll, malformed packets between valid packets, cursor wrap, buffer reuse,
and unchanged block/net behavior through guest systest in both profiles.
Review the concrete implementation and its ring-lifetime/wakeup invariants
as an ordinary incremental patch. If those invariants require a different
mechanism, stop and discuss the deviation instead of silently adding one.

### D18. Shared reset completion check (Q19, approved)

Before this change, `VirtioDevice::reset` wrote device status zero and
immediately allowed initialization to continue without observing completion.
[Virtio 1.1 section 4.1.4.3.2](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html)
requires observing zero before reinitialization. This is a preexisting shared
virtio issue, not a vsock-specific reset or completion-order requirement.

Perform one status read after the reset write; return an initialization
error if it is nonzero, before acknowledging the device or
starting queues. Keep initialization synchronous with no polling, retries,
timeout constant, or added task. This deliberately rejects a device whose
reset has not completed at that read; it does not provide asynchronous-reset
support. The change adds one MMIO read per initialized block/net device at
boot and per lazily initialized vsock device. The user approved this policy
and boot-time cost on 2026-09-15. Implementation and normal-device validation
are recorded in the progress section; the failure branch is source-reviewed.

Pinned-source review on 2026-09-15 supports the one-read policy for initial
pre-activation setup, without proving general backend reset completion:

- [QEMU 10.2.1](https://github.com/qemu/qemu/blob/v10.2.1/hw/virtio/virtio.c#L2253-L2283)
  stores the requested status synchronously; its
  [PCI write handler](https://github.com/qemu/qemu/blob/v10.2.1/hw/virtio/virtio-pci.c#L1679-L1692)
  invokes reset before returning from a zero-status write.
- [CHV 52.0](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/v52.0/virtio-devices/src/transport/pci_device.rs#L1258-L1269)
  resets queue/common configuration in the write handler; the
  [common status register](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/v52.0/virtio-devices/src/transport/pci_common_config.rs#L178-L190)
  is restored to zero.
- [Firecracker 1.15.1](https://github.com/firecracker-microvm/firecracker/blob/v1.15.1/src/vmm/src/devices/virtio/transport/pci/common_config.rs#L164-L185)
  stores zero in its serialized reset transition. However, its
  [PCI reset path](https://github.com/firecracker-microvm/firecracker/blob/v1.15.1/src/vmm/src/devices/virtio/transport/pci/device.rs#L904-L940)
  deliberately leaves status zero even when an activated backend cannot reset,
  blocking reinitialization instead. Zero alone is therefore not evidence
  that arbitrary outstanding DMA can be discarded.

These are source-based expectations, not live one-read measurements. The
planned vsock transport-reset event path keeps existing queues and DMA
owners solely for safe reclamation/retention; it does not reset/reinitialize
the PCI device or attempt transport recovery (D26).

### D19. Connection-local invalid-credit rejection (Q20, approved)

The credit helper already rejects an advertised `fwd_cnt` advance greater
than the payload bytes still outstanding. Rejection is atomic, changing
neither peer credit field. [Virtio 1.1 sections 5.10.6.3.1–5.10.6.3.2](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html)
require valid credit information but do not prescribe the receiver's reaction
to this violation. This is distinct from a peer shrinking `buf_alloc` below
outstanding bytes, which simply leaves zero send allowance until credit
recovers.

Reject the offending packet and reset only its identified connection, using
the existing reset semantics for its current state. An
established stream reports `ConnectionReset` after previously validated RX
has drained; unrelated streams and the device remain operational. Do not
answer an incoming RST with another RST. The user approved this policy on
2026-09-15. The Stage 7 connection helper now returns the reset action and
retains the terminal cause, with source-included guest coverage. Executing
that action through the real runtime/driver and notifying native clients
remain M2 integration work; helper tests do not cover those boundaries.

### D20. VMM defensive hardening (Q21, deferred)

Per the user's 2026-09-15 direction, defending against buggy or malicious
VMMs is outside this work. Do not implement Q21's BAR-layout walk or add its
boot-time PCI reads. The concern is recorded briefly in
[future-work.md](future-work.md#deferred-pci-bar-boundary-hardening-2026-09-15).
This does not remove approved protocol validation or D18's standard reset
completion check. No existing validation is removed as part of this decision.

### D21. Availability discovery (Q23, approved)

The user confirmed that discovery follows D14: return `NotAllowed` when
CAP_VSOCK is missing and `NotFound` when the device is absent. Check the
capability first, so a denied caller receives `NotAllowed` even without a
device. Return success when an authorized caller's device is dormant or
ready; a discovered device that has permanently failed returns its cached
`InternalError` (D26).
Discovery does not initialize queues, read the CID, or start device pumps.

Use `availability(&NetClient) -> Result<(), moto_rt::Error>` with the existing
RPC/driver and no socket reservation. Query/cache the trusted capability
word at the first vsock request, not at channel admission or boot. Preserve
native capability-query errors directly, without the TCP error mapper.
There is no unprivileged boolean-discovery exception.
Authorized requests must have zero handle, flags, and payload; reject a
malformed request with `InvalidArgument` before consulting device presence.

### D22. Connection-local protocol rejection (Q24–Q25, approved)

The user approved both rejection rules on 2026-09-15. A decoded packet with
the correct tuple but an operation invalid in the connection state (for
example, a second RESPONSE after establishment) resets that connection.

Virtio 1.1 [section 5.10.6.5](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html)
defines establishment and shutdown, but does not prescribe every wrong-state
transition. [Linux v6.18's `virtio_transport_recv_connected`](https://github.com/torvalds/linux/blob/v6.18/net/vmw_vsock/virtio_transport_common.c)
discards unexpected operations without resetting the established connection;
its connecting-state handler instead aborts invalid transitions. Motor uses
the approved explicit reset rule for wrong-state operations.

Send RST and terminalize only the offending connection,
retaining validated RX before its reset error. Never answer RST with RST or
overwrite an already retained terminal cause. This adds no recovery framework
and leaves compliant traffic unchanged. This is a peer-protocol policy, not
the deferred PCI/VMM-metadata hardening.

The receive helper atomically rejects an RW payload larger than its remaining
receive allowance. Reset only that connection for this separate violation;
D19's impossible-peer-forwarding rule remains unchanged.
Ordinary full buffers remain backpressure under D14; a peer sending beyond
advertised credit instead violates Virtio 1.1's
[buffer-space rule in section 5.10.6.3](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html).

Reject the excess packet and reset only that connection,
preserving previous credit fields and validated RX, as for D19. This requires
no extra receive storage or retry policy. Do not classify the rejected packet
as ordinary backpressure or broaden D20 into a blanket exemption from approved
protocol validation. Unrelated connections and the device remain operational.

### D23. Shared NET subchannel validation (Q26, approved)

Source review found that `runtime/net/socket/tcp.rs::tcp_connect` passed
client-controlled payload byte 23 directly to
`moto_sys_io::api_net::io_subchannel_mask`. NET ingress did not validate
that field. The helper only has `debug_assert!(idx < IO_SUBCHANNELS)` before
shifting its 16-page mask; there are four valid indices, 0–3. Normal moto-io
constructs valid indices, but raw IPC clients are not constrained by it.

An out-of-range index reaches a panic in debug (`panic = "abort"` for sys-io),
while release removes the guard and performs an oversized shift instead of
rejecting the request. The unchecked call predates vsock (present at baseline
`6918384e`). UDP bind also calls the helper with the same client field and
must be examined if a shared fix is authorized. This is source-level
diagnosis; no malformed-request VM test has been run yet.

The user approved this fix before continuing vsock integration. Reject
out-of-range indices in release as well as debug before reserving a port or
creating a socket, using the existing `InvalidArgument` response. Cover TCP
connect and both UDP bind entry points; valid indices and wire layouts stay
unchanged. Extend the existing raw guest IPC tests, reached through ordinary
native-net/full-test, and verify resource accounting and subsequent valid
operations. No new test framework or production injection hook is needed.

This is a specifically authorized shared NET IPC fix, not a general expansion
into unrelated preexisting bugs or the deferred malicious-VMM hardening.

### D24. Correct the UDS test protocol, not the VMMs (Q27 resolved)

The user directed that all VMMs stay as installed and that failures be
investigated and fixed on Motor's side. Comparing the original failing test
with Linux establishes that its half-close assumptions were incorrect:

- Linux's guest `shutdown(SHUT_WR)` succeeds and publishes SEND-only shutdown,
  just as Motor does. The original host fixture nevertheless times out while
  waiting for Unix EOF before sending its response.
- Host Unix `shutdown(Write)` produces guest EOF and rejects subsequent Linux
  writes with `BrokenPipe`. It is not a way to generate SEND-only virtio
  shutdown; Motor must also reject writes after the BOTH-flags packet.

Live Linux comparisons reproduced both failures on CHV v52.0, Firecracker
v1.15.1, and QEMU with `vhost-device-vsock 0.3.0`. Baseline echo exchanges pass
on CHV and Firecracker. The original Motor failure and the Linux reference
logs are retained in the progress section.
These results explain the failure; no passing rerun, longer timeout, retry,
or VMM modification is needed to infer it.

The corresponding proxy behavior is explicit in
[CHV v52.0's connection state machine](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/v52.0/virtio-devices/src/vsock/csm/connection.rs#L217)
(guest shutdown handling starts at line 335) and
[Firecracker v1.15.1's corresponding implementation](https://github.com/firecracker-microvm/firecracker/blob/v1.15.1/src/vmm/src/devices/virtio/vsock/csm/connection.rs#L222)
(guest shutdown handling starts at line 348). The pinned QEMU UDS backend,
[vhost-device-vsock 0.3.0](https://github.com/rust-vmm/vhost-device/blob/4fe41e353a005b1b7163f3f38efde3523f3b160c/vhost-device-vsock/src/vsock_conn.rs#L166),
also emits both flags for host EOF and does not propagate SEND-only shutdown
to the Unix socket (its guest-shutdown branch starts at line 286). This
concerns these specific UDS backends, not every possible QEMU backend.

Keep D10/D14 unchanged. Correct our guest/host fixtures as follows:

1. Connect a data stream and a separate synchronization stream, identify
   their roles, and exchange exact framed control tokens. Do not synchronize
   by sleeping or by assuming how the UDS proxy maps half-close.
2. Local SEND: send and validate all pre-shutdown bytes; await write-shutdown
   completion; verify a nonempty write returns `NotConnected`; then signal
   completion on the synchronization stream. Only then may the host send its
   response on the data stream. Receiving the exact response proves receive
   still works after write-shutdown completed.
3. Local RECEIVE: receive the exact initial payload; await read-shutdown;
   verify nonempty reads return EOF; synchronize with the host; verify EOF
   again and send the exact post-shutdown payload on the data stream. The
   host acknowledges receipt on the synchronization stream. This proves
   receive-shutdown leaves writes usable, not that a backend must send new
   data after a RECEIVE flag forbids it.
4. Name the host Unix-close case for what it tests: drain the exact buffered
   payload, observe EOF, and reject nonempty writes. Do not call it a
   SEND-only peer half-close or expect the opposite direction to stay open.
5. Retain guest fixtures exercising the actual connection implementation for
   peer SEND-only and RECEIVE-only wire packets. Those are protocol fixtures,
   not claims that the UDS peer can generate those packets. Keep live native
   API, data/credit, shutdown, and teardown assertions on every selected VMM.

No VMM/backend source, installed binary, production shutdown flags, deadlines,
or gate counts change. Linux is a one-off diagnostic reference, not a regular
test dependency. This diagnosis corrects a false test premise; the separate
live gates are recorded above. It does not waive the remaining M2 acceptance
requirements.

The same rule applies to an absent host UDS port: absence is not proof that
the backend sent a refusal. The initial connect-error test expected
`NotConnected` on every VMM, but QEMU's pinned `vhost-device-vsock 0.3.0`
logged the failed Unix connect without queuing RST (`enq_rst()` is a no-op).
Motor correctly returned `TimedOut`; unchanged Linux on the same backend
also returned timeout (`ETIMEDOUT`, 2,036 ms). CHV and FC passed the original
exact refusal assertion. The original failure is preserved in
`/tmp/vsock-capacity-errors-gate.T9Ljpm/`; backend traces, the two other VMM
runs, and the Linux comparison are in `/tmp/vsock-refusal-diagnostic.B2qBMI/`.

The host harness therefore declares the fixture's expected behavior:
`silent` for this pinned QEMU backend, `refused` for CHV/FC. Guest tests
require exactly `TimedOut` or `NotConnected`, respectively, verify a silent
peer cannot complete before the existing two-second connect deadline, and
check reservation reclamation. Do not accept either error interchangeably
or add VMM-specific production logic. D14's error mapping is unchanged.

### D25. Eight pending accepts (Q28, approved)

Allow eight waiting accept RPCs per listener, separately from D7's eight
unaccepted streams. The former stores request metadata and its requesting
channel; the latter owns streams and RX buffers charged to the global cap.
Use a small fixed/pre-reserved queue and return `OutOfMemory` for a ninth
pending call. Four native reservations per channel do not replace this
server-side limit: raw IPC and requests from multiple channels still obey it.
Do not copy TCP's larger 1,024-call queue or introduce a new quota framework.

### D26. Permanent failure on device reset (Q29, approved)

If the device resets, leave it off for the rest of sys-io's lifetime. Use
the existing cached device-failure state and `InternalError`, wake pending
vsock operations with that error, and keep future operations erroneous.
Discard buffered RX and queued TX rather than preserving successful reads
or graceful delivery. Fail listeners and pending accepts as well as streams;
do not fail TCP/UDP that share the native NET channel.

Remove CID refresh, listener rebinding/continuity, and reset-recovery logic.
No snapshots, restore/migration support, or FC snapshot orchestration is
part of this work. Keep small existing guest fixtures for terminal failure,
error propagation, and resource safety; do not claim live reset coverage.

This does not waive memory safety: outstanding DMA is still device-owned
until completion. Stop new submissions/reposting, reap returned descriptors
without dispatching their contents, and retain unreclaimed buffers/queues.
Do not fabricate virtqueue completions, drop their futures, or reinitialize
the device. The permanent failure transition is idempotent. D18's initial
pre-activation status-reset check is unrelated and unchanged.

### D27. Separate kernel thread-creation rollback fix (Q31, approved)

The release developer gates on both QEMU and CHV exposed
`stats: process dropped with 1 active threads` during the existing unwind
abort test. `spawn_thread` constructs a thread and publishes its self/join
objects before checking the process's Running state. If process exit wins
before insertion into the thread map, the error path does not undo
construction. Exit cannot find that thread in the map, so its object cycles
and active-thread accounting survive. Its kernel stack remains in the
global kernel address space because `Thread::cleanup` never runs; user-stack
pages are reclaimed with the process address space. The live process listing
retained a DEAD unwind child with one active thread.

This predates vsock and is not VMM-specific. The diagnostic is also in the
QEMU baseline (`/tmp/vsock-baseline.qoT1LL/full-test-release.log`) and M1
logs. Current evidence is in
`/tmp/vsock-d16-developer-gate.NEOmKO/{qemu,chv}-full-test.log`; relevant code
is `kernel/src/uspace/process.rs::{spawn_thread, Thread::new}` and
`kernel/src/xray/stats.rs::process_dropped`.

The user explicitly approved a separate reviewed kernel patch. Prevent or
undo unpublished construction safely, cover the exit race through existing guest
tests, and retain the unwind test. Before committing this patch, run three
passing debug and three passing release `src/tests/full-test.sh` runs, plus
one `src/tests/full-test-dev.sh --release`. These are fresh patch-specific
gates, not earlier passes or a deferral to M2. Preserve failures and diagnose
them; do not suppress the diagnostic or count functional success as proof
of correct thread reclamation. No external/toolchain source change is needed.

### D28. Drop abandoned operations on driver exit (Q30, simplified)

The existing weak connect waiter closes a successful canceled request only
while the channel's RX task still runs. Releasing the last reservation starts
driver exit; RX drains currently available replies, not replies to requests
that TX has yet to publish. `NetDriver::run` can therefore return before a
late successful connect is closed. A retained `NetClient` keeps the IPC
connection alive, so sys-io does not see the disconnect assumed by the current
`rpc_connect` comment. Cross-channel accepts would have the same gap.

This was reproduced by temporarily adapting the existing
`cancel-queued-connect` guest case: cancel a separate channel's sole connect
before starting its driver, drive it to completion, retain its `NetClient`,
and require the existing host peer to observe EOF. The driver exited with
zero reservations, but the host accepted the connection and its EOF read
timed out. Evidence is in
`/tmp/vsock-final-slot-diagnostic.Ibz2gJ/separate-runtime.log` and
`/tmp/test-vsock.yQWGyr/`. The earlier `run.log` used two drivers on one runtime
and hit its documented single wake-target assertion; the corrected diagnostic
uses a separate runtime thread. Both failures are preserved, and all temporary
diagnostic edits were removed. Neither run is a validation pass.

The user permits discarding abandoned work in this edge case. Require only
bounded resource ownership, memory safety, and prompt error completion;
do not preserve success or data delivery for the canceled operation. Remove
the proposed cancel-open protocol and explicit IPC disconnect API.

Use existing ownership and teardown instead:

1. Make `NetClient` a weak handle to the channel. The driver, reservations,
   and actual in-flight operations retain strong ownership. Keeping an idle
   client after its driver finishes must not keep sys-io's peer alive.
2. Reject reservation-free queries on a closing/dead channel. After the
   existing RX/TX tasks finish, use the existing failure path to resolve
   residual waiters as `NotConnected` and leave admission closed. Do not wait
   for a late successful connect/accept or add per-request cancellation state.
3. Let normal `ClientConnection::Drop` release the mapping and peer handle
   once real owners leave. Handle a freshly connected driver's Drop before
   any work is staged, without a new allocation or stranded channel. Once
   work is staged, retain the existing requirement to drive the channel to
   completion. Preserve ordinary socket Drop's queued-TX drain; this
   edge-case policy does not weaken TCP/UDP or D10.

"Drop everything" means logical work, not freeing borrowed memory. A retained
in-flight future may hold an inert channel until polled after its error wake
or dropped; no new work is admitted. Do not forcibly unmap its pages. Sys-io
copies TX into device-owned buffers before DMA, whose existing global owners
remain until completion independently of client teardown. No per-socket
virtqueue cancellation is needed.

Test retained-client final-slot cancellation, later queries returning errors,
immediate unstaged-driver Drop, and ordinary queued-TX Drop through existing guest
routes. A canceled accept on a still-live channel may retain one of D25's
eight pending-call slots until a peer arrives or the listener drops; existing
late-success cleanup then reclaims the child. Bound and document that case
instead of adding a prompt server-side cancellation protocol.

## Open questions

None currently. Stop for review if implementation requires a non-obvious
deviation from these decisions.
