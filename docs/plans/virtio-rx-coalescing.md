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

The packet-rate column is superseded by the Step 0 measurement below, which
found it understated about 2.6x. It never agreed with the throughput beside it:
127.6k x 509 B is 62 MiB/s, not the 164 MiB/s the next paragraph reads off the
same run. The throughput figures are what Step 0 reproduces, so the conclusion
below stands and the per-packet cost it rests on is larger than recorded here,
not smaller.

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

Corrected 2026-08-01 by the Step 0 measurement below, which reads the words out
of a live device instead of the source: the set is `VERSION_1`, `MAC`,
`RING_EVENT_IDX`, `GUEST_CSUM`, `CSUM`, `HOST_TSO4`, `HOST_TSO6`. `MTU` is not
negotiated because this QEMU does not offer it -- `run-qemu.sh` passes no
`host_mtu=` -- and `STATUS` is not negotiated because the block that would ack
it is commented out (`virtio_net.rs:349`). `RING_EVENT_IDX` was missing from
the list. What follows from the `MTU` absence is a defect of its own, recorded
in the Step 0 result.

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

Updated 2026-07-30 by `core-safety-hardening.md` patch 5, which this step
depends on. Two facts above are now stale: the `GUEST_TSO4/6`, `GUEST_ECN`,
`GUEST_UFO`, and `MRG_RXBUF` bits do have constants, and the RX header *is*
inspected. `RX_SIZE_ADJUSTOR` is gone; `NetReadCompletion` reads the header
before the chain is released, bounds the used length both ways, rejects a
nonzero `gso_type` or `num_buffers > 1` while the matching feature is
unnegotiated, and returns `RxMeta`. The bits are still not acked, so this
step's work is unchanged -- it acks `GUEST_TSO4/6`, sizes the buffers in the
same patch, and relaxes patch 5's `gso_type` check; Option B likewise acks
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

   Step 7 changed it anyway, from 1536 to 1514, and the constraint is intact:
   it forbids *raising* the value to describe ingress frames, and what Step 7
   did was correct the units so it describes the link. The two agree on the
   principle -- `max_transmission_unit` states what the link carries, and
   nothing else may borrow it.

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

Motor guests should not assume QEMU, and the repository does not:
`src/vm_scripts` ships `run-qemu.sh`, `run-chv.sh`, and `run-fc.sh`, and all
three boot the same image. The features involved are core virtio-net, not
QEMU-isms, but the relevant VMMs offer different subsets.

**Measured 2026-08-02**, by booting one debug image under each VMM and reading
the feature word Step 0 added. This replaces what stood here from review
memory, which was wrong in the two places that decide the plan.

| feature (bit) | QEMU 10.2.1 | CHV 52.0 | FC 1.15.1 |
|---|---|---|---|
| `GUEST_TSO4` (7) | yes | yes | yes |
| `GUEST_TSO6` (8) | yes | yes | yes |
| `MRG_RXBUF` (15) | yes | **no** | yes |
| `RING_INDIRECT_DESC` (28) | yes | **no** | **no** |
| `MTU` (3) | **no** | yes | **no** |
| `CTRL_GUEST_OFFLOADS` (2) | yes | yes | **no** |
| `STATUS` (16) | yes | **no** | **no** |
| `CTRL_VQ` (17) | yes | yes | **no** |
| `RING_EVENT_IDX` (29) | yes | yes | yes |

Whole words: QEMU `0x1c0010130bfffa7`, CHV `0x120427faf`, FC `0x12000dda3`.
All three report `rx queue 256 = 128 buffers, tx queue 256 = 128 buffers`, so
the ring depth Step 0 measured is not a QEMU default that the others improve
on. The three rows that decide anything:

- **`GUEST_TSO4/6` is universal.** Option A's one hard requirement is met on
  every VMM the repository ships a script for, IPv6 included.
- **`MRG_RXBUF` is not.** Cloud Hypervisor v52.0 does not offer it. Its
  `--net` takes `offload_tso`, `offload_ufo`, and `offload_csum` but has no
  mergeable-buffer control, so this is not a missing flag in `run-chv.sh`.
  Scope of the claim: CHV's built-in tap backend, which is what Motor uses.
  The `vhost_user=on` path negotiates against a separate backend process and
  was not measured.
- **`RING_INDIRECT_DESC` is QEMU-only**, as this plan supposed. Neither CHV
  nor Firecracker offers it.

Firecracker v1.15.1 has also outgrown the description that stood here: it
offers `GUEST_TSO6`, so the IPv4-only caveat is retired, and it offers
`MRG_RXBUF`. What it does not offer is `CTRL_VQ`, `STATUS`, or
`CTRL_GUEST_OFFLOADS` -- it is the sparsest of the three, and the only one
whose set is a strict subset of another's.

Three design consequences, and the first is the reverse of what this section
used to conclude:

1. **Option A is the portable option; Option B is not.** `GUEST_TSO4/6`
   without `MRG_RXBUF` -- one >= 65550-byte buffer per packet -- is the only
   scheme available on all three, because the VMM that would have to drive
   Option B is the one that cannot. Option B is still valid on QEMU and
   Firecracker, which demotes it from destination to per-VMM optimization.
2. **Nothing restores ring depth on CHV or Firecracker.** Option A's chains
   cost `256 / 18 = 14` slots on all three, and the indirect-descriptor escape
   exists only on QEMU. CHV's `--net` accepts `queue_size=`, so there depth can
   be bought with memory; Firecracker's network interface has no queue-size
   control at all, which makes it the binding case for any depth argument.
3. **Negotiation must be defensive by construction.** Ack only offered bits;
   treat `GUEST_TSO4` and `GUEST_TSO6` independently (a VMM may offer only
   one); size RX buffers and read `num_buffers` conditionally on what was
   actually negotiated; keep today's behavior bit-for-bit when the device
   offers nothing. That no two of the three offer the same set is now measured
   rather than supposed, which is the whole argument for this.

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

**Revised 2026-08-02, once all three VMMs were measured.** The portability half
of the recommendation above inverts. Option B cannot be the destination,
because Cloud Hypervisor does not offer `MRG_RXBUF` at all, so Option A is not
merely the cheap experiment -- it is the only scheme with universal reach, and
the case for B is per-VMM throughput rather than portability. The deciding
number this section said it lacked is also settled: `queue_size()` is 256
everywhere, so Option A's depth is 14 slots, and of the three mitigations
listed above only the pre-post count exists on Firecracker. What remains open
is therefore not which option is portable but whether 14 slots and 918 KB of
posted buffers per device are acceptable, which is the decision the Step 0
result already flagged as one to take before the work, not after.

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
`docs/plans/core-safety-hardening.md`, whose patch 5 surfaces the RX header's
`flags`, `gso_type`, and `num_buffers` -- which `post_read` currently discards
when the descriptor is released -- and rejects frames impossible for the
negotiated feature set. As of 2026-07-30 patch 6 has also landed, so the
per-packet handling this step needs now exists: the verdict reaches the
netstack as `PacketMeta::l4_csum_vouched` and only the frames the device
vouched for skip verification. Coalesced super-segments arrive `NEEDS_CSUM`, so
they are vouched frame by frame with no special case here. Patch 7's
per-verdict coverage landed the same day, so item 2 is complete and this step's
prerequisite is met. It then *relaxes* patch 5's `gso_type` check as part of
acking guest TSO. Define the `GUEST_TSO4/6` constants and ack them where
offered (the spec requires `GUEST_CSUM`, already negotiated); expose a
`guest_tso()` accessor; add run-splitting to `post_read`; correct `rxq_sz()`
for the new chain length; size RX buffers at >= 65550 in `device.rs`.
Negotiation is conditional per the portability section: TSO4 and TSO6 are acked
independently, and a device offering neither gets today's behavior bit-for-bit.
Negotiation and buffer sizing **must land in the same patch** -- acking guest
TSO while still posting 2048-byte buffers is a spec violation that would drop
or corrupt traffic. ~150-200 loc.

**Step 2 -- tune and record.** Sweep the pre-post count against throughput,
pick a default, and record the paired A/B in this document.

**Step 3 -- Option B, when step 1's depth proves insufficient or when Cloud
Hypervisor / Firecracker support is prioritized.** Ack `MRG_RXBUF`, read
`num_buffers` from the RX header, gather chained buffers into one contiguous
buffer, and revert to small RX buffers. Larger, and worth splitting further
when it is reached.

## Step 0 result, 2026-08-01

Instrumentation, plus the MTU fix the measurement turned up (below).
`negotiate_features` logs the acked word beside the offered one, device init
logs the ring depths and MTU, and `NetStats` gained a five-bucket histogram of
received frame lengths (`net.device.rx_size.*`).

All of the logging is `log::debug!` under `#[cfg(debug_assertions)]`, matching
what was already there. An earlier draft promoted the feature word to
`log::info!` so a release boot would answer it; that was reverted on review, and
the rule it broke is worth stating: **release builds do not get new boot-time
logging.** Characterizing a new VMM means booting a debug build on it, which
costs nothing, whereas info-level device chatter is paid by every release boot
forever.

### What the device offers

```
NET features available: 0x1c0010130bfffa7
NET features acked: 0x120001823
virtio-net: rx queue 256 = 128 buffers, tx queue 256 = 128 buffers, mtu None.
```

A debug boot, since that is where these live. `mtu None` is the device's own
answer and still reads `None` after the fix below; what changed is what sys-io
assumes in its place -- an IP MTU of 1500, rather than 1536 taken for a frame.

Offered and unused: `GUEST_TSO4`, `GUEST_TSO6`, `GUEST_ECN`, `GUEST_UFO`,
`MRG_RXBUF`, `RING_INDIRECT_DESC`, `CTRL_VQ`, `CTRL_GUEST_OFFLOADS`, `STATUS`.
Not offered: `MTU`. **Both options are available on this VMM**, and so is
Option A's indirect-descriptor mitigation. Nothing here has to be fought for;
the whole gap is driver-side, as the plan supposed.

**`virtq_rx.queue_size()` is 256**, which the plan called the deciding number
and did not have. So the receive ring holds 128 packets today, and under Option
A -- 1 header plus up to 17 data descriptors -- it holds `256 / 18 = 14`. That
is the "only ~14" the recommendation feared, now measured rather than guessed.

### What arrives on it

Frame-length distribution of one 5-second rnetbench phase in each workload,
Motor receiving. Two rounds agreed to within 0.06 points, so only the first is
shown.

| bucket | default (~512B writes) | bulk (`-b 65536`) |
|---|---|---|
| <= 64 B | 0.98% | 0.00% |
| <= 512 B | 43.78% | 0.05% |
| <= 1024 B | 49.99% | 0.05% |
| <= 1514 B | 5.25% | **99.89%** |
| > 1514 B | 0 | 0 |
| frames/sec | 331k @ 567 B | 505k @ 1510 B |

Three things follow.

**The top bucket is empty, as it must be.** Nothing above a standard Ethernet
frame reaches the guest while `GUEST_TSO4/6` is unacked. That bucket is the
instrument Step 1 will be read with: it goes from zero to most of the traffic,
or Step 1 is shelved.

**The bulk workload is already MTU-framed**, 99.89% of it, at 505k frames/sec
for ~700 MiB/s. This is the clean case for coalescing: the host is handing over
half a million maximally-sized frames a second, and each one costs a descriptor,
a completion, and a poll. Nothing about the framing needs improving; only the
count does.

**The default workload is not one size.** The 567 B/pkt mean hides a genuine
spread -- 44% at or below 512 bytes, 50% between 513 and 1024, 5% above that --
which is exactly what the histogram was added to expose, since a mean of 567
would equally describe uniform 567-byte frames. The host is coalescing writes
somewhat, but not to MTU, so this workload would gain least from Option A and
suffer most from its depth collapse. Motor's own transmit direction is
unambiguous: in the phases where Motor sends, 100% of what it receives is in the
`<= 64 B` bucket -- bare ACKs, nothing else, 149311 frames and 149311 in that
bucket.

The asymmetry the whole plan exists to close, in one pair of numbers from that
same phase: Motor **transmits** 30.6k packets/sec averaging 11099 B/pkt, because
`HOST_TSO4/6` is negotiated and the device does the segmenting. Motor
**receives** 505k packets/sec averaging 1510 B/pkt. Transmit is coalesced
sevenfold; receive is not coalesced at all.

### What that says about Option A

At the measured default rate, 14 slots turn over 23,700 times a second: the RX
task has 42 microseconds to refill the whole ring or it starves. At the
uncoalesced bulk rate it has 28. If coalescing engages, 64 KiB frames at 700
MiB/s arrive 11.2k times a second and the same 14 slots have 1.25 milliseconds
-- comfortable. So Option A's benefit and its risk are the same conditional the
plan identified, and the numbers are now the plan's rather than an estimate.

Memory is the part the depth arithmetic hides: 14 buffers of 65550 bytes is 918
KB per device against today's 128 x 2048 = 262 KB. Restoring depth to 256 with
indirect descriptors would mean 16.8 MB of posted receive buffers per device,
which is not obviously acceptable and should be decided before, not after.

### A defect found while measuring, and fixed

`mtu None` was not cosmetic. `VirtioDevice::new` fell back to `unwrap_or(1536)`
and handed it to `caps.max_transmission_unit` on a `Medium::Ethernet` device,
where it means the *frame* size. So `ip_mtu()` was 1522 and the advertised MSS
`1522 - 20 - 20 = 1482` (`netstack/src/socket/tcp.rs:2388`), on a tap whose MTU
is 1500 and which therefore carries at most 1460 bytes of TCP payload. Motor
advertised 22 bytes more than the path can hold.

It was latent, and the measurement shows why: `ss` reports
`mss:1460 advmss:1460 pmtu:1500`, because the host takes the smaller of its own
path MSS and ours. A peer that honored 1482 without a path of its own to clamp
against would have made Motor emit a 1536-byte frame into a 1500-byte link, with
no PMTU discovery in the fork to recover. The fallback dated to `d5a45ad3`, the
original virtio-net hookup, and answered to no plan.

Fixed on guidance. A named `frame_mtu()` converts the virtio MTU -- which is the
*IP* MTU -- into the frame size moto-netstack wants, and the fallback is now
`DEFAULT_IP_MTU = 1500`, so a device that reports nothing is treated as the
ordinary Ethernet link it is: frame 1514, `ip_mtu()` 1500, MSS 1460. This also
closes the off-by-14 in the other direction that `core-networking-rewrite.md`
recorded under "Smaller, cheap", since the same conversion is now applied when
the device *does* report an MTU. `run-qemu.sh` was deliberately left alone: the
guest should be right about a link that tells it nothing, which is the case a
`host_mtu=` would have papered over.

The fix is not observable under QEMU, and that is why it stayed latent -- the
peer's clamp already produced 1460 in both directions. The proof recorded on
2026-08-01 was therefore the self-test, which pushes each candidate MTU through
the netstack's own `ip_mtu()` rather than re-deriving the subtraction, so a test
that agreed with a wrong answer is not possible, and which pins the no-MTU
default at frame 1514 / MSS 1460.

**It is observable on Cloud Hypervisor, measured 2026-08-02.** CHV is the one
VMM of the three that offers `VIRTIO_NET_F_MTU`, and it reports 1500 -- which
is the *other* sign of this defect, the one `core-networking-rewrite.md`
recorded: 1500 taken for a frame size gives `ip_mtu()` 1486 and MSS 1446, too
small by 14 rather than too large by 22. Rebuilding with only the old line
restored and booting under CHV, the host reports `mss:1446 pmtu:1500`; at HEAD
the same connection reports `mss:1460`. Nothing clamps this one, because it is
below the path MSS rather than above it, so it was costing 1% of every segment's
payload on that VMM for as long as it existed. The QEMU rig was simply the wrong
place to look for it.

### Commands

```
make -j$(nproc) BUILD=release
vm_images/release/run-qemu.sh                       # boot facts on the console
ssh motor@192.168.4.2 /sys/tests/rnetbench -s -p 5542
src/bin/rnetbench/target/release/rnetbench -c 192.168.4.2:5542 -t 5
src/bin/rnetbench/target/release/rnetbench -c 192.168.4.2:5542 -t 5 -b 65536
ssh motor@192.168.4.2 /sys/sysbox stats get 2       # cumulative histogram
```

The per-phase deltas come free: the in-VM rnetbench server already prints every
sys-io net metric that moved, resolved by name, so the histogram appears in its
output with no rnetbench change. The manifest for these runs is in
`docs/plans/networking-step-by-step.md`, Step 7.

### Gate

`full-test-networking.sh` three times debug and three times release, all
passing on the first attempt, with the sys-io self-test suite at 43 (up from
40) and no failures; `cargo +nightly fmt` clean; sys-io clippy byte-identical
to clean `HEAD` in both profiles from wiped target directories.

A paired A/B/A/B rnetbench run as well, because the histogram bump sits on every
received frame -- fewer instructions than patch 19's ingress check, but on more
frames, so it gets the same treatment. It was run **twice**: once on the
instrumentation alone, then again after the MTU fix, which changes
`max_transmission_unit` and so has to answer for itself. Medians of five rounds,
MiB/s; the second run is the gate for the final tree.

| block | tree | default RR usec | default RX | default TX | 64k RX | 64k TX |
|---|---|---|---|---|---|---|
| A1 | clean | 54.38 | 162.31 | 322.87 | 649.28 | 1239.07 |
| B1 | patched | 56.62 | 141.55 | 305.75 | 642.29 | 1214.86 |
| A2 | clean | 56.84 | 139.12 | 303.26 | 651.32 | 1225.36 |
| B2 | patched | 52.93 | 141.93 | 302.74 | 648.73 | 1239.70 |

Read the same-tree pairs first, as the host-regime note requires. **Clean
against clean (A2 vs A1) is default RX -14.29% and TX -6.07% with no code
difference whatsoever** -- past the 5% criterion twice over, and larger than any
cross-tree number in either run. A1 was the only block in the fast regime, in
both runs, which is the whole reason the design is A/B/A/B.

Within a regime the answer is flat, and slightly favors the patched tree: B2 vs
A2 is default RX **+2.02%** and TX -0.17%. The 64 KiB workload is barely
bimodal -- 649.28, 642.29, 651.32, 648.73, a 1.4% spread across all four blocks
-- and its cross-tree pairs are RX -1.08% then -0.40%, TX -1.95% then +1.17%.
No throughput regression. The first run agreed: within-regime RX -0.83%, TX
-0.53%, 64 KiB straddling zero.

The RR story is worth keeping because the first run got it wrong. There, default
RR was clean {57.06, 56.33} against patched {58.70, 58.79} -- a clean +2.05 usec
with within-arm spreads of 0.73 and 0.09, which looked like signal rather than
the throughput bimodality, and was recorded as the one direction favoring clean.
**It reversed in the second run**: clean {54.38, 56.84} against patched {56.62,
52.93}, i.e. -0.84 usec. Pooling all eight samples per arm across both runs --
legitimate, since rnetbench runs the same RR phase before each throughput
workload -- gives clean 55.99 usec (54.00-58.16) against patched 57.30
(52.93-61.40): +1.31 usec, +2.3%, with ranges that almost entirely overlap.

So the finding is host drift, which is what the mechanism said all along: the
added work is two comparisons and one counter increment per received frame,
twice per RR iteration, on the order of 10 nanoseconds against a difference
measured in thousands. Inside the ~5 usec criterion, and the lesson for Step 1
is that a two-block RR comparison on this unpinned, `powersave`-governed host is
not enough to call a 2 usec effect.

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
  Step 0 sharpened the expected signature without settling it: the bulk
  workload is already 99.89% MTU-framed, so it is the one with everything to
  gain, and the default workload's spread (44% at or below 512 B) confirms it
  is sender-paced per write and will gain least.
- **`virtq_rx.queue_size()` is unknown.** Resolved 2026-08-01: it is **256**,
  so depth is 128 today and 14 under Option A. See the Step 0 result.
- **Whether ring depth 14 is workable** for small-packet bursts is genuinely
  uncertain and is the main reason this plan does not simply commit to A.
  Step 0 gives the budget: 42 microseconds to refill the ring at the measured
  default rate, 28 at the uncoalesced bulk rate, 1.25 milliseconds if
  coalescing engages.
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
