# virtio-net receive coalescing

2026-07-26. Plan only. No code changes accompany this document.

Revised the same day after review: added the real-world scope analysis (the
receive window), VMM portability, and indirect descriptors. The
recommendation now treats Option A as a QEMU-gated experiment and Option B
as the durable target where Cloud Hypervisor or Firecracker matter. This
plan is sequenced between Stage 2 and Stage 3 of
`docs/plans/vdso-rewrite.md` (see that plan's Section 0).

## Motivation

A Stage-0 re-baseline of the `moto-io`/`rt.vdso` series established that
Motor's TCP receive path is packet-rate bound, not bandwidth bound. Measured
on `moto-tap` at `ab81c861`:

| Run | host->guest (Motor RX) | guest->host (Motor TX) |
|---|---|---|
| default (~512B writes) | 127.6k pkt/s @ 509 B/pkt | 26.1k pkt/s @ 4372 B/pkt |
| bulk (`-b 65536`) | 187.9k pkt/s @ 1355 B/pkt | 32.8k pkt/s @ 15054 B/pkt |

Receive throughput therefore tracks bytes-per-packet: 164 MiB/s at ~512B
writes, ~680 MiB/s at MSS. Two streams nearly double aggregate, and one
stream reaches full speed as soon as writes are 4KB or larger. The transmit
direction already emits 4.4-15KB super-segments because `HOST_TSO4/6` is
negotiated; receive has no equivalent, so every wire segment is delivered
individually.

This is a long-standing gap, not a regression: the pre-rewrite tree measures
the same ~164 MiB/s on this host.

The benchmark understates the real-world stakes. For traffic arriving from a
physical network -- an Internet download -- segments reach the host NIC at
path MTU, and the host kernel's GRO merges each stream's back-to-back
segments into up to 64K super-frames at ingress. GRO is on by default and
engages dependably for exactly this workload. Whether those super-frames
survive to the guest is decided by negotiation: with `GUEST_TSO4/6` acked,
the VMM enables the corresponding tap offloads and large frames flow
through; without it -- the current state -- the host re-segments everything
to MTU before the tap. At the measured 128-188k pkt/s, MTU framing caps
guest RX at roughly 180-260 MiB/s (1.5-2.2 Gbps), with a vCPU burning on
per-packet work -- which matters on the 1-2 vCPU microVM shapes Cloud
Hypervisor and Firecracker target. So the "does the host coalesce?"
uncertainty is specific to the synthetic rig (see Risks); for forwarded
traffic the mechanism is the textbook case.

## Scope: the receive window binds first on long-RTT paths

Coalescing raises the packet-rate ceiling and cuts CPU per byte. It does not
change the other single-stream limit: `TCP_SOCKET_BUFFER_SIZE` is 128KB
(constraint 5 below), and one TCP stream cannot exceed window/RTT. At 20 ms
RTT that is ~6.4 MiB/s; at 50 ms, ~2.6 MiB/s -- far below even the current
un-coalesced 164 MiB/s. For the literal case of downloading a large file
from a distant server, the receive window is the binding constraint, and
raising the receive buffer (and confirming the smoltcp fork's window
scaling engages; stock v0.13 supports it) is a smaller, independent change
with more leverage there. Coalescing is the binding fix for
low-RTT/high-bandwidth paths -- same-datacenter transfers, fast local
networks -- and for aggregate throughput across many connections. The two
are complementary, not alternatives; window sizing is out of scope here and
is planned separately in `docs/plans/tcp-receive-window.md`.

## Current state

Facts, all verified against the tree at `ab81c861`.

**Negotiated features** (`virtio-async/src/virtio_net.rs:20-27`, confirmed
against the boot log): `CSUM`, `GUEST_CSUM`, `MTU`, `MAC`, `STATUS`,
`HOST_TSO4`, `HOST_TSO6`.

Receive is not un-offloaded in general -- `GUEST_CSUM` is negotiated and
sys-io keys smoltcp's `ChecksumCapabilities` off it so RX skips software L4
verification. What is absent is receive-side *segment coalescing*:
`VIRTIO_NET_F_GUEST_TSO4/6` (bits 7/8) and `VIRTIO_NET_F_MRG_RXBUF` (bit 15)
have no constants anywhere in the repo, so the driver never tests or acks
them. `NetHeader::num_buffers` exists in the header layout but is never read;
it is only meaningful once `MRG_RXBUF` is negotiated. QEMU offers these bits
by default, so this is a driver-side gap.

**RX path shape.** `post_read` (`virtio_net.rs:420`) posts a fixed 2-descriptor
chain: a 12-byte `NetHeader` plus one data buffer. `rx_task`
(`sys-io/src/runtime/net/device.rs:116`) pre-posts `rxq_sz()` of them, each
`SMALL_BUF_SIZE` = 2048 bytes, and re-posts one after every completion. The
device-written RX header is never inspected; `RX_SIZE_ADJUSTOR` just subtracts
the header length from the used-ring length. `rxq_sz()` is
`queue_size() / 2`, the 2 reflecting the fixed chain length.

Updated 2026-07-30 by `core-safety-hardening.md` patch 2.1, which this step
depends on. Two facts above are now stale: the `GUEST_TSO4/6`, `GUEST_ECN`,
`GUEST_UFO`, and `MRG_RXBUF` bits do have constants, and the RX header *is*
inspected. `RX_SIZE_ADJUSTOR` is gone; `NetReadCompletion` reads the header
before the chain is released, bounds the used length both ways, rejects a
nonzero `gso_type` or `num_buffers > 1` while the matching feature is
unnegotiated, and returns `RxMeta`. The bits are still not acked, so this
step's work is unchanged -- it acks `GUEST_TSO4/6`, sizes the buffers in the
same patch, and relaxes 2.1's `gso_type` check; Option B likewise acks
`MRG_RXBUF` and relaxes the `num_buffers` check.

**smoltcp is a fork**: `github.com/moturus/smoltcp`, branch `motor-os`
(`src/sys/Cargo.toml:59`). Corrected 2026-07-26: it is stock v0.13.0 plus
**four** commits, not one -- two upstream cherry-picks (`25d4f7c` SACK
sequence overflow, `faa1603` IPv4 IHL check) and two Motor commits
(`44ecae4` configurable neighbor-discovery silent time, `d2ff65b` TSO).
The TSO commit is the one relevant here: it added
`DeviceCapabilities::max_tso_size`, `PacketMeta::tso_seg_size`, and
`TxToken::set_meta`. See `docs/plans/core-networking-rewrite.md` for the
full fork inventory.

## Constraints discovered

These shape the design and are the reason this is not a small change.

1. **`max_transmission_unit` must not change.** TCP MSS is derived from
   `cx.ip_mtu()` (fork `src/socket/tcp.rs:2237, 2546, 2622, 2642`), which
   comes from `caps.max_transmission_unit`. Raising it to describe large
   ingress frames would advertise a bogus MSS and corrupt the transmit side.
   Receive coalescing must be invisible to that value.

2. **smoltcp has no ingress MTU check.** The only two size checks in the
   interface are egress (`iface/interface/mod.rs:1293, 1398`, both bypassed
   when `tso_seg_size != 0`). The ingress path parses whatever byte slice the
   `RxToken` yields, so an oversized frame parses as an ordinary large IPv4/TCP
   packet with no fork change. This is what makes the whole idea viable.

3. **`RxToken::consume` requires a *contiguous* `&[u8]`.** This is the pivotal
   constraint. Any scheme that spreads one packet across several buffers must
   reassemble it before smoltcp sees it, or change the fork's `RxToken`
   contract.

4. **`IoBuf` is physically contiguous only within 4K pages.** `post_write`
   already splits a 64K buffer into up to `MAX_TX_RUNS` = 17 runs
   (`virtio_net.rs:63`, `475-495`). A large RX buffer needs the same
   run-splitting, so its descriptor chain is 1 header + up to 17 data
   descriptors rather than today's 2.

5. **The receive window permits coalescing.** `TCP_SOCKET_BUFFER_SIZE` is
   128KB (`sys-io/src/runtime/net/socket/tcp.rs:231`), so the advertised
   window is large enough that host GRO can build substantial super-segments.

## Options

### Option A: `GUEST_TSO4/6` only, large RX buffers

Negotiate guest TSO without `MRG_RXBUF`. The virtio spec then requires the
driver to supply RX buffers of at least 65550 bytes, since any single buffer
must hold a whole super-segment.

- No reassembly: one packet, one contiguous buffer, zero copies. Constraint 3
  is satisfied for free.
- `post_read` needs constraint 4's run-splitting, which `post_write` already
  demonstrates.
- **Ring depth collapses.** Chains grow from 2 descriptors to up to 18, so
  `rxq_sz()` falls from `queue_size/2` to `queue_size/18` -- a factor of 9.

The depth arithmetic is the problem, and it cuts both ways. In *bytes* the
ring gets deeper. But every packet occupies one whole slot regardless of size,
so a small-packet flood -- exactly the default rnetbench workload -- would
have far fewer slots, each mostly empty. If the host does coalesce, packets
are large and few slots suffice; if it does not, this option makes the very
case we are trying to fix worse. The benefit is conditional on host behavior
in a way Option B's is not.

A third mitigation for the depth collapse is `VIRTIO_F_INDIRECT_DESC`
(transport feature bit 28): with indirect descriptors, each packet's chain
occupies a single ring slot pointing to an out-of-ring descriptor table, so
depth returns to `queue_size` with no gather copy and no `MRG_RXBUF`. QEMU
offers it by default; Firecracker does not offer it at all, and the virtq
code would need to learn to allocate and link the indirect tables. It is
therefore a QEMU-side mitigation, not the portable answer.

### Option B: `GUEST_TSO4/6` + `MRG_RXBUF`

Negotiate mergeable RX buffers. Buffers stay small; the device chains as many
as a packet needs and reports the count in `NetHeader::num_buffers`.

- Ring depth and memory footprint are preserved.
- Degrades gracefully: a small packet still consumes one small buffer.
- **Requires a gather.** Constraint 3 means the chained buffers must be
  copied into one contiguous buffer before `RxToken::consume`. For a 64K
  packet that is a 64K memcpy, on the order of single-digit microseconds.
  The alternative -- teaching the fork's `RxToken` to expose a scatter list --
  touches every ingress parse site and is much larger work.
- The driver must read the RX `NetHeader`, which it currently ignores
  entirely.

## VMM portability

Motor guests should not assume QEMU. The features involved are core
virtio-net, not QEMU-isms, but the relevant VMMs offer different subsets:

- **QEMU** offers the full set and is the most forgiving of unusual
  combinations.
- **Cloud Hypervisor** advertises `GUEST_CSUM`, `GUEST_TSO4/6`,
  `HOST_TSO4/6`, and `MRG_RXBUF`, and enables tap offloads from what the
  guest acks.
- **Firecracker** has been IPv4-centric (`GUEST_TSO4`/`GUEST_UFO`; IPv6
  offloads absent for a long time), gained `MRG_RXBUF` only around v1.6
  (late 2023), and does not offer indirect descriptors. Feature sets vary
  meaningfully by version.

The per-VMM details above are from review memory, not verified against
sources; Step 0's feature-word logging is how they get verified per VMM, at
boot, for whatever versions are actually targeted.

Two design consequences:

1. **Option A is the least-exercised path outside QEMU.** `GUEST_TSO`
   without `MRG_RXBUF` -- one >= 65550-byte buffer per packet -- is
   spec-legal everywhere, but `MRG_RXBUF` is the combination Cloud
   Hypervisor and modern Firecracker are built and tested around. If those
   VMMs matter, Option B is the durable target on its own merits, not a
   fallback.
2. **Negotiation must be defensive by construction.** Ack only offered
   bits; treat `GUEST_TSO4` and `GUEST_TSO6` independently (a VMM may offer
   only one); size RX buffers and read `num_buffers` conditionally on what
   was actually negotiated; keep today's behavior bit-for-bit when the
   device offers nothing. One driver is then correct on all three VMMs.

## Recommendation

**Option A is the quick experiment; Option B is the destination.** A is far
the smaller change, needs no fork work and no copy, and is the direct test
of the hypothesis, so it still goes first. But the portability analysis
demotes it from "commit unless forced to B": if Cloud Hypervisor or
Firecracker are deployment targets, B is the endpoint regardless of what
the depth measurement says, and A's role is to prove the throughput win
cheaply before the gather work is paid for.

The deciding number for how far A alone can be pushed is
`virtq_rx.queue_size()`, which I did not determine; it is read from the
device and is not in the boot log. QEMU's virtio-net default is 256, which
would give depth 128 today and only ~14 under Option A. If that proves too
thin, three mitigations exist before B: `run-qemu.sh` can pass
`rx_queue_size=1024` (it is ours to edit, though see the note below), the
pre-post count is independently tunable, and `VIRTIO_F_INDIRECT_DESC`
restores full depth (see Option A). The first and third do not exist on
Firecracker, which reinforces B as the portable answer.

Treat Steps 0 and 1 as one experiment. Step 0 alone cannot answer the real
question -- whether coalesced frames actually reach the guest -- and Step 1
is ~200 reversible loc; if large frames do not materialize, the plan is
shelved having spent almost nothing.

## Proposed work

Each step is separately reviewable and leaves a runnable tree.

**Step 0 -- measurement only, no production change.** Log the device's full
offered feature word, `virtq_rx.queue_size()`, and `rxq_sz()` at device
init, and add RX packet-size distribution counters to `NetStats`. Boot, and
record what the device offers, what the ring depth actually is, and what
the current RX size histogram looks like. The feature word makes every VMM
answer "what can be negotiated here?" at boot, which is how the portability
section's per-VMM claims get verified. This gives the before evidence and
determines whether Option A can be attempted; Steps 0 and 1 together decide
whether it works well enough to keep. ~50 loc.

**Step 1 -- Option A, if step 0 supports it.** This depends on correct
per-packet handling of the RX header's checksum flags; globally trusting every
frame merely because `GUEST_CSUM` was negotiated is not sufficient. That
dependency is now scheduled: it is item 2 of
`docs/plans/core-safety-hardening.md`, whose patch 2.1 surfaces the RX header's
`flags`, `gso_type`, and `num_buffers` -- which `post_read` currently discards
when the descriptor is released -- and rejects frames impossible for the
negotiated feature set. This step must not begin before that item lands, and it
then *relaxes* 2.1's `gso_type` check as part of acking guest TSO. Define the
`GUEST_TSO4/6` constants and ack them where offered (the spec requires
`GUEST_CSUM`, already negotiated); expose a `guest_tso()` accessor; add
run-splitting to `post_read`; correct `rxq_sz()` for the new chain length;
size RX buffers at >= 65550 in `device.rs`. Negotiation is conditional per
the portability section: TSO4 and TSO6 are acked independently, and a device
offering neither gets today's behavior bit-for-bit. Negotiation and buffer
sizing **must land in the same patch** -- acking guest TSO while still posting
2048-byte buffers is a spec violation that would drop or corrupt traffic.
~150-200 loc.

**Step 2 -- tune and record.** Sweep the pre-post count against throughput,
pick a default, and record the paired A/B in this document.

**Step 3 -- Option B, when step 1's depth proves insufficient or when Cloud
Hypervisor / Firecracker support is prioritized.** Ack `MRG_RXBUF`, read
`num_buffers` from the RX header, gather chained buffers into one contiguous
buffer, and revert to small RX buffers. Larger, and worth splitting further
when it is reached.

## Risks and open questions

- **Does the host coalesce the benchmark traffic?** For forwarded traffic
  from a physical network, GRO merges MTU-sized stream segments at NIC
  ingress by default, so the real-world benefit is close to certain. The
  uncertainty is specific to the synthetic rig: rnetbench's default sender
  is local, and GRO does not run on locally originated traffic -- the host
  TCP stack only builds large GSO frames toward the tap when its send
  buffer has more than one MSS queued. The measured 509 B/pkt shows the
  default run is sender-paced per write, so the expected signature after
  Step 1 is a large bulk-RX jump while default RX may move much less. Step
  0 does not answer this; the cheapest real answer is Step 1 behind a
  temporary feature check, measured immediately -- and if the rnetbench A/B
  is flat, verify with an MTU-framed sender or a real download before
  concluding the negotiation is wrong.
- **`virtq_rx.queue_size()` is unknown.** The entire depth analysis rests on
  it. Step 0 exists to resolve it first.
- **Whether ring depth 14 is workable** for small-packet bursts is genuinely
  uncertain and is the main reason this plan does not simply commit to A.
- **The generated image's `run-qemu.sh` is ignored, but its source is
  tracked** at `src/vm_scripts/run-qemu.sh` and copied by the build. Any
  `rx_queue_size` change belongs in that source. Reproducibility also requires
  the host/VM benchmark manifest described in
  `docs/plans/networking-step-by-step.md`; the script alone does not capture
  the host state behind the historical drift.
- **Scope.** This is virtio-net and sys-io work. It is independent of the
  `moto-io`/`rt.vdso` refactor series and touches no file that series
  touches. It is now sequenced between that series' Stages 2 and 3 (see
  that plan's Section 0): landing it first makes the rewrite's default-RX
  gate axis sensitive to the layers its risky stages churn, instead of
  measuring a driver bottleneck below them.

## Gates

Per AGENTS.md: `full-test.sh` passing three times as debug and three times as
release; no new compiler or clippy warnings; `cargo +nightly fmt`. Plus,
because this is a data-path change, a paired same-host release rnetbench A/B
against `ab81c861` covering default and bulk in both directions -- a receive
coalescing change must be shown not to cost transmit throughput or RR
latency.

After Step 2 lands, record a fresh same-host reference sample for the
`moto-io`/`rt.vdso` series to gate against (that plan's Section 10), since
`ab81c861` ceases to be comparable on the RX axis.
