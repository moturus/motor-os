# Virtio-vsock implementation plan

Status: v2.3. The v1 open questions Q1–Q13 were approved on 2026-09-14 as
recorded in the Decisions section, adopting the second review's
recommendations. The launch-infrastructure questions raised afterwards
(Q14, Q15) were approved the same day with the `--vmm` caveat recorded in
D15 and D16. Follow-up review corrections and simplifications are retained.
Q16 is settled in D16: an explicitly requested `raw.img` target for standard
Firecracker tests, with no developer-image Firecracker support. The original
review questions are settled; implementation follow-ups are listed at the end.
Repository and references inspected on 2026-09-14;
implementation has started, with progress recorded below.

Implement a modern virtio-vsock driver in `src/sys/lib/virtio-async`, serve
vsock streams through sys-io, and expose moto-io's native Rust API. Follow
the existing block and network drivers' structure and reuse their virtqueue
implementation and networking IPC machinery. Implementation is approved and
proceeds in small reviewed commits; the full repeated gate belongs at the
two approved milestones, not every commit (D13).

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
parent-reviewed; CID snapshots and device initialization remain:

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
- Generation-consistent CID reads are held for Q17; independent work continues.

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
  (final validation). Packet submissions/completions and both milestones
  remain pending.

## Scope and simplicity

- One Virtio 1.1 modern PCI implementation requiring `VIRTIO_F_VERSION_1`, with
  the existing split virtqueues and MSI-X support. No legacy transport,
  packed-ring implementation, alternate queue library, or VMM-specific guest
  protocol.
- Native Motor OS I/O using existing in-tree libraries and Rust facilities.
  Preserve moto-io's `no_std` boundary by using `core`, `alloc`, and native
  APIs there; do not add a dependency on `std` or virtio-async to moto-io.
- Reliable byte streams with connect, listen/accept, bidirectional I/O,
  shutdown, and transport-reset handling. Virtio 1.1 defines only stream
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
3. `Virtqueue::allocate_virtqueue` already spawns the IRQ reclamation task.
   `Virtqueue::drop` has no device teardown implementation. Keep device
   lifetime separate from socket lifetime; do not promise hot-unplug or
   reset/recreation of queues as part of socket cleanup.
4. The sys-io mapper currently permits IRQs 64–69, but the kernel registers
   16 custom IRQs, 64–79 (`src/sys/kernel/src/config.rs` and
   `src/sys/kernel/src/arch/x64/irq.rs`). Reuse
   that existing range with bounded allocation and an exhaustion error.
   One block device, two NICs, and one vsock device need eight queue IRQs;
   a future second block device would need nine. No IRQ-sharing framework or
   kernel vector expansion is needed for those examples. Queue sizes remain
   capped at 256; account for aggregate ring use of the existing 2 MiB pool.
5. `PciBar::read_u64` performs two 32-bit reads. Reading a changing guest CID
   needs configuration-generation consistency, not an assumption that this
   helper gives an atomic snapshot. The common-config layout declares
   `config_generation`, but nothing reads it today.
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
unpublished until its resource ownership and error paths work. D1–D16 are
the authoritative requirements; stages reference them and describe changes,
tests, and completion checks. Tests arrive with behavior; the validation
section groups related commits into the two approved gating milestones.

### 1. Review the contract and record the baseline

Follow D1–D16 without reopening the agreed scope, including Q16's resolution
in D16: opt-in raw standard image, no developer-image Firecracker support.

Record the selected Motor toolchain, baseline image build/test results,
current boot measurements, and existing warnings. Keep logs for any initial
failure. Diagnose a newly encountered preexisting bug before discussing an
out-of-scope fix, following AGENTS.md. Make no external-repository changes.

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
at boot. Authoritatively check connect and bind/listen (including accept
ownership) before device activation or vsock resource reservation. Do not
reject the entire shared channel:
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
configuration length, and read a generation-consistent CID. Keep discovery
separate from initialization so
boot can retain the device without creating its queues.

Use `init_virtqueues(3, 3)`, existing MSI-X assignment, and existing status
operations. Queue setup refuses a device whose MSI-X table has fewer vectors
than queues; confirm on each VMM that the vsock device exposes at least
three vectors, and report a clear initialization error otherwise. Validate
queue capacity against the chosen packet layout and control reserve. Add
only the small configuration-read helper necessary for a
generation-consistent CID read. Use it at lazy activation and transport
reset.

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

Return buffers on valid and invalid completions so the runtime can reuse
them. Use a dedicated receive completion wrapper, like `NetReadCompletion`,
where header/length validation is needed. Do not request block status for
vsock chains. TX completion means the device released the buffers, not that
the remote application consumed the data.

Extend the real memory-backed queue fixture minimally to cover vsock
descriptor direction, header-only TX, valid/invalid RX and events,
out-of-order chain completion, descriptor exhaustion/reuse, and owned-buffer
lifetime. Preserve the existing premature-drop regression.

### 5. Build the device pumps and bounded scheduling

Add the proposed `src/sys/sys-io/src/runtime/vsock.rs`. Use the existing
single-threaded executor and `Rc` ownership; never hold `RefCell` borrows
across awaits. Use one TX submission pump (D6); keep RX processing, event
handling, and TX completion draining independently able to progress.

Maintain a fixed RX pool, promptly repost completed buffers, and copy or
transfer accepted data into bounded per-stream storage. A blocked application
must not retain the entire device RX ring. Use a bounded pending-control
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

### 6. Implement and test byte-credit accounting

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

Record state transitions in tests as inputs and expected outputs: emitted
control packets, byte/accounting changes, state, and waiter notifications.
Cover refusal, unexpected responses, duplicate requests, wrong destinations,
data before establishment, and stale packets after closure. Implement only
the approved scope; unsupported operations need explicit errors (D14).

### 8. Implement bind, listen, and accept

Keep a listener table separate from active streams. Follow D8 for binding
the current local CID, explicit ports, and automatic ports. Reject conflicts
deterministically. Use the fixed backlog from D7,
with each pending accepted stream charged to its owner and global limits.

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

Continuously service the event queue. On transport reset, refresh the CID,
terminate active and connecting streams, discard unaccepted streams from
the old transport, and wake affected clients; keep listeners usable with
the current CID. Validate and replenish event buffers, including after an
unknown event. The event path in
[Linux's virtio transport](https://github.com/torvalds/linux/blob/master/net/vmw_vsock/virtio_transport.c)
is a useful cross-check for CID refresh and event-buffer recycling.

Remove unsent old-connection packets and prevent late completions from
changing new socket state. A transport-reset event does not itself return
DMA ownership of every outstanding descriptor. Keep submitted completions
alive and reap them through the existing queue; never implement reset by
dropping all queue futures. Do not reset/recreate the whole device to close
one socket.

On channel failure or client exit, remove that client's listeners, abort or
finish its streams under D10, and drain/release pages, pending replies,
waiters, timers, and reservations. Keep cleanup idempotent across peer reset,
client drop, and late reply races. Device failure must be distinguishable
from a single stream failure (D9, D14).

In guest systest fixtures, test reset during connect, queued accept, read,
credit-blocked write, and in-flight DMA. Test the same CID and a changed CID,
repeated events, invalid
event lengths, listener continuity, stale completions, and bounded resource
counts after repeated create/use/drop cycles. No migration test, new sys-io
self-test, or production event-injection command is planned. Distinguish
fixture coverage from actual VMM-triggered reset coverage; if another test
hook is necessary, discuss it first (D12). Transport reset remains required
Virtio 1.1 behavior even though migration support is out of scope.

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
- Cancellation and client process exit during connect, accept, RX, and TX;
  repeated cycles must return observable resource counts to baseline.
- Capability inheritance and denial, including raw IPC attempts; no-device
  errors and attached-but-idle/first-use behavior. Vsock still works with IP
  disabled, including no loopback, without starting the IP backend.
- Transport-reset handler/listener recovery through the guest fixture route,
  clearly labeled as such, not migration or a new sys-io self-test.
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
| Wire validation and actual queue ownership/exhaustion | Existing virtio-async `test-support` fixture route -> `systest/src/virtio.rs` -> ordinary full-test VM, both profiles. |
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

- M1, foundations: stages 1–6, covering capability delegation, modern device
  support, shared-queue changes, and credit arithmetic. Fully gate this
  related group before moving into the client/server integration.
- M2, complete integration: stages 7–15, covering state machines, shared
  networking IPC, native API, lazy activation, cleanup, and all three VMMs.
  Full gates include the complete new vsock phase by this milestone.

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

### D1. Profile and topology (approved)

- Virtio 1.1, stream-only, modern PCI; no legacy or newer socket features.
  A1's earlier multi-vsock and seqpacket requirements are superseded.
- One vsock device; no multi-vsock implementation or tests.
- Keep generic virtio/IRQ infrastructure compatible with multiple NICs and
  block devices. Do not impose a one-NIC topology to make vsock fit.
- Preserve sys-io's second-block-device rejection until multiple filesystems
  arrive. Do not change root-disk selection or implement secondary-disk use.
- Multiple NICs should continue working; new multi-NIC testing/fixing is out
  of scope. Existing tests and ordinary networking regressions still run.
- Host CID 2 is the only required peer. Guest-to-guest routing and
  guest-local loopback are not implemented or tested.

### D2. Ownership (approved)

virtio-async owns packet/event I/O; sys-io owns connection state, credits,
listeners, and client routing. No socket framework in the driver crate and
no new reusable protocol crate.

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
| RX payloads | `min(64, rx_descriptors / 2)` page-sized buffers, reposted promptly. |
| TX payloads | `min(64, (tx_descriptors - 8) / 2)` page-sized buffers; reserve eight descriptors for control. |
| Events / pending control | Up to four posted event buffers; 64 pending control records, coalescing credit updates. |
| Stream receive buffer | Fixed 128 KiB in sys-io, allocated/charged before establishing a connection. |
| Stream IPC / pending TX | Existing 16 pages per direction per reservation; no additional per-stream TX ring. |
| Stream/listener admission | 64 streams globally, counting connecting, unaccepted, and closing states; 32 listeners, backlog eight each, still within the global stream cap. |
| Per-channel admission | Existing four data reservations and channel budget; no separate quota framework. |

At 256 descriptors per queue, the RX/TX pools hold at most 512 KiB of
payload, plus 48 KiB of header scratch, ring allocations, and bookkeeping.
Sixty-four receive buffers reserve 8 MiB before IPC pages and other overhead.
Check total committed memory against the selected VM's memory budget (D16);
the 64 MiB Firecracker interactive default is not the full-suite budget.
Admission/allocation failures follow D14 without killing existing streams;
temporary I/O capacity exhaustion is backpressure, not `OutOfMemory`.
Allocate on demand, not at boot or for every potential connection.

Pack small payloads into byte buffers, bounding metadata independently of
wire packet count. Round-robin ready streams with bounded work per turn;
stop accepting new work at capacity, preserve active-stream data, and keep
reserved control/completion work runnable. No timers for idle credit probing,
new adaptive-buffer policy, or unbounded per-request tasks.

### D8. CAP_VSOCK and addressing (approved)

CAP_VSOCK is bit 7, required for connect and listen. It is included in the
default child grant for every role when the parent holds it, so normal
system and user processes start with it. Only parents holding the bit may
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

### D9. Lazy initialization (approved)

Lazy init, an unchanged no-device boot path, and no hot-plug or unplug.
Host-to-guest service becomes available only after an authorized guest
operation activates the device and binds its listener; that is a consequence
of lazy initialization, not a boot-time host handshake.

Use absent/dormant/ready/failed state owned by the existing `LocalRuntime`.
Keep first-use initialization synchronous, as in blk/net, using nonblocking
queue setup/publication without awaiting the host. Authorization precedes
activation. An availability query reports discovery without activation;
querying the actual CID may initialize. With no initialization-time `await`,
the executor serializes first callers and later callers see the cached
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
ownership. Normal transport reset follows the protocol and keeps listeners
operational when the refreshed configuration is valid.

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
reset, distinguish orderly EOF, and never reuse an old tuple before terminal
cleanup. A completed write is local acceptance, not proof of peer receipt.

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

Pin the released `vhost-device-vsock` crate version in `test-vsock.sh`,
document installation in `docs/tools.md`, and check the binary/version
before launching. Installation is developer setup, not test work. QEMU
needs a separate vhost-user control socket as well as the peer UDS path.
Firecracker already uses `--enable-pci`; no virtio-MMIO driver is needed.

| VMM | Transport/backend | Evidence and remaining validation |
| --- | --- | --- |
| QEMU | Modern `vhost-user-vsock-pci` plus UDS `vhost-device-vsock`; shared guest RAM. | Installed QEMU 10.2.1 exposes that device. `vhost-device-vsock` is not on PATH; install from its released crate at the pinned version during setup, never during a test. |
| Cloud Hypervisor | Built-in `--vsock cid=3,socket=<path>`. | Installed v52.0; native vsock config is a singleton and its protocol is streams over UDS. |
| Firecracker | Built-in `vsock` JSON configuration over PCI and UDS. | Installed v1.15.1 with `--enable-pci`; native config stores one device. |

Sources: [Cloud Hypervisor's vsock documentation](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/vsock.md),
[its config representation](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/vmm/src/config.rs),
[Firecracker's vsock builder](https://github.com/firecracker-microvm/firecracker/blob/main/src/vmm/src/vmm_config/vsock.rs),
and the [vhost-device-vsock README](https://github.com/rust-vmm/vhost-device/blob/main/vhost-device-vsock/README.md).
These are source/help checks, not completed Motor guest interoperability
tests.

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

Incremental commits grouped into two repeated milestones, M1 (stages 1–6)
and M2 (stages 7–15), each gated by three passing debug and three passing
release main-image full-test runs on the default VMM. M2 adds one debug and
one release run with `--vmm chv` and with `--vmm fc` (D16). Every commit
runs its affected guest tests in both profiles. Do not reduce case coverage,
skip a VMM, weaken assertions, or add retries to save gate time. A failed
milestone stops progression for diagnosis; preserve the original failure
even if a later diagnostic run passes.

### D14. Error mapping (approved)

Vsock handlers and the native API use existing `moto_rt::Error` values as
follows. Handlers construct them directly; `util::map_err_into_native` and
the TCP mappings are unchanged, and moto-rt is not expanded.

| Condition | Error |
| --- | --- |
| No vsock device discovered | `NotFound` |
| Device initialization or later configuration failed (cached) | `InternalError` |
| Caller lacks CAP_VSOCK | `NotAllowed` |
| Unsupported operation, socket type, or option | `NotImplemented` |
| Invalid CID or port, including port 0 or `0xffffffff` on connect | `InvalidArgument` |
| Bind conflict | `AlreadyInUse` |
| Connect refused by the peer, including no listener or exhausted peer admission/backlog capacity | `NotConnected` |
| Established stream reset by the peer or by transport reset | `ConnectionReset` |
| Write after local SEND or peer RECEIVE shutdown, or on an orderly closed stream | `NotConnected` |
| Connect deadline expired | `TimedOut` |
| Local stream/listener admission limit, or allocation failure for a new socket's required buffer/reservation | `OutOfMemory` |
| Try-I/O has no immediately available data/capacity and has made no progress | `NotReady` |
| Unknown, stale, or foreign socket handle on the wire | `NotFound`, as the existing net handlers report |
| Orderly EOF on read | `Ok(0)`, not an error |

Peer SEND shutdown alone is not a write error (D10). Retain the terminal
reset cause rather than turning `ConnectionReset` into `NotConnected`
merely because the stream is now closed; drain validated RX first per D10.

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

The IP-disabled vsock image is an isolated variant of the selected suite
image, using that VMM's format; it must not overwrite the ordinary image.

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

## Open questions

### Q17. Bound generation-consistent CID reads?

Virtio 1.1 section 2.4.1 recommends reading configuration generation before
and after a multiword value and repeating when it changes, without specifying
a retry bound. An indefinitely changing device could therefore occupy sys-io's
single runtime thread during synchronous first use or transport reset.

Proposed: allow eight complete snapshot attempts, then fail the operation with
an unstable-configuration error. D9/D14 would cache initialization failure or
fail the active vsock service with `InternalError`, retaining DMA ownership.
Eight is a proposed liveness bound, not a protocol constant; it adds no idle
polling or boot task. A time-based limit is an alternative. User guidance was
requested on 2026-09-15; hold this helper while independent work continues.
