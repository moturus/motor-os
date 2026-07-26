# virtio-net receive coalescing

2026-07-26. Plan only. No code changes accompany this document.

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

**smoltcp is a fork**: `github.com/moturus/smoltcp`, branch `motor-os`
(`src/sys/Cargo.toml:59`). It is stock v0.13.0 plus exactly one commit,
`d2ff65b "Implement TSO"`, which added `DeviceCapabilities::max_tso_size`,
`PacketMeta::tso_seg_size`, and `TxToken::set_meta`.

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

## Recommendation

**Start with Option A, but gate it on a measurement rather than committing to
it.** A is far the smaller change, needs no fork work and no copy, and is the
direct test of the hypothesis. Its one serious risk -- ring depth -- is
measurable before any of it is written.

The deciding number is `virtq_rx.queue_size()`, which I did not determine;
it is read from the device and is not in the boot log. QEMU's virtio-net
default is 256, which would give depth 128 today and only ~14 under Option A.
If that proves too thin, two mitigations exist before falling back to B:
`run-qemu.sh` can pass `rx_queue_size=1024` (it is ours to edit, though see
the note below), and the pre-post count is independently tunable.

If depth turns out to be the binding constraint, Option B is the durable
answer and the gather-copy is worth paying. That decision should be made on
the measurement, not up front.

## Proposed work

Each step is separately reviewable and leaves a runnable tree.

**Step 0 -- measurement only, no production change.** Log
`virtq_rx.queue_size()` and `rxq_sz()` at device init, and add RX
packet-size distribution counters to `NetStats`. Boot, and record what the
ring depth actually is and what the current RX size histogram looks like.
This decides A vs B and gives the before/after evidence. ~50 loc.

**Step 1 -- Option A, if step 0 supports it.** Define the `GUEST_TSO4/6`
constants and ack them (the spec requires `GUEST_CSUM`, already negotiated);
expose a `guest_tso()` accessor; add run-splitting to `post_read`; correct
`rxq_sz()` for the new chain length; size RX buffers at >= 65550 in
`device.rs`. Negotiation and buffer sizing **must land in the same patch** --
acking guest TSO while still posting 2048-byte buffers is a spec violation
that would drop or corrupt traffic. ~150-200 loc.

**Step 2 -- tune and record.** Sweep the pre-post count against throughput,
pick a default, and record the paired A/B in this document.

**Step 3 -- Option B, only if step 1's depth proves insufficient.** Ack
`MRG_RXBUF`, read `num_buffers` from the RX header, gather chained buffers
into one contiguous buffer, and revert to small RX buffers. Larger, and
worth splitting further when it is reached.

## Risks and open questions

- **Does the host actually coalesce?** GRO is on for `moto-tap` and QEMU
  offers the bits, but this is unverified end to end. If the host declines to
  coalesce, Option A yields nothing and costs ring depth. Step 0 does not
  answer this; the cheapest real answer is Step 1 behind a temporary feature
  check, measured immediately.
- **`virtq_rx.queue_size()` is unknown.** The entire depth analysis rests on
  it. Step 0 exists to resolve it first.
- **Whether ring depth 14 is workable** for small-packet bursts is genuinely
  uncertain and is the main reason this plan does not simply commit to A.
- **`run-qemu.sh` is untracked**, so any `rx_queue_size` change there is
  invisible to git and unreproducible. It should be committed before being
  used as a tuning knob, otherwise the measurements it produces cannot be
  audited -- the same defect that made the historical baselines
  irreproducible.
- **Scope.** This is virtio-net and sys-io work. It is independent of the
  `moto-io`/`rt.vdso` refactor series and touches no file that series
  touches, so it can be sequenced before, after, or alongside it without
  conflict.

## Gates

Per AGENTS.md: `full-test.sh` passing three times as debug and three times as
release; no new compiler or clippy warnings; `cargo +nightly fmt`. Plus,
because this is a data-path change, a paired same-host release rnetbench A/B
against `ab81c861` covering default and bulk in both directions -- a receive
coalescing change must be shown not to cost transmit throughput or RR
latency.
