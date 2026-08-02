# sys-io TCP receive-window sizing

2026-07-26. Plan only. No code changes accompany this document.

Companion to `docs/plans/virtio-rx-coalescing.md`. That plan raises the
receive path's packet-rate ceiling; this one addresses the other
single-stream limit, the advertised receive window. They are complementary:
for real-world downloads over long-RTT paths, the window binds first, and
neither fixes the case the other covers.

## Motivation

One TCP stream cannot exceed window/RTT regardless of link speed. Every
Motor TCP socket advertises at most 128KB, so:

| RTT | max single-stream RX at 128KB window |
|---|---|
| ~59 usec (the local rig) | ~2 GiB/s -- not binding |
| 10 ms | 12.5 MiB/s |
| 30 ms | 4.2 MiB/s |
| 100 ms | 1.25 MiB/s |

For the literal case of downloading a large file from a distant server, the
window binds one to two orders of magnitude before the ~164 MiB/s
packet-rate ceiling the coalescing plan addresses. Reaching 100 MiB/s at
30 ms RTT needs a ~3MB window; at 50 ms, ~5MB.

## Current state

Facts verified at `d6bcf1de`.

**Buffers are fixed at 128KB each way, per socket.** `create_tcp_socket`
(`sys-io/src/runtime/net/socket/tcp.rs:231-233`) heap-allocates a 128KB RX
and a 128KB TX buffer for every socket. Both creation paths funnel through
it: the connect path, and `create_tcp_listening_socket`, whose listening
sockets are what accepted connections materialize from. The in-code comment
records the constant's history -- 32KB sat exactly at the local rig's
321 MiB/s x ~100 usec BDP -- so the current value was chosen for LAN
throughput, with WAN RTTs never in view. (The comment cites
`net-opportunities.md` N1, which no longer exists in `docs/`; stale
reference, fix in passing.)

**Window scaling already works.** The smoltcp fork sets
`remote_win_shift = rx_cap_log2 - 16` at socket construction and reset
(fork `src/socket/tcp.rs:594, 909`) and advertises it in the SYN
(`:2501-2505`). A 128KB buffer yields shift 2. The advertised window is
capped by the RX buffer, and a larger buffer automatically yields a larger
shift and window: **no fork change is needed for larger fixed windows.**

**The scale factor is fixed at SYN time.** The shift is derived from the
buffer capacity when the socket is created, so sizing must be decided by
then: at connect time for outbound streams, and at listening-socket
creation time for accepted ones. This matches POSIX practice, where
`SO_RCVBUF` is set between `socket()` and `connect()`/`listen()`.

**No `SO_RCVBUF`/`SO_SNDBUF` anywhere.** The identifiers do not appear in
`src/`. Rust std has no buffer-size API, so the consumers would be
socket2/mio/libc users via the raw `setsockopt` dispatch, plus native
`moto-io` callers.

**The protocol has room.** The TCP bind/connect request payloads
(`moto-sys-io/src/api_net.rs`) use only a few of their arg slots; a
buffer-size hint fits in the existing messages without a protocol version
change.

## Measured on the rig, 2026-08-01

Execution Step 7. Two of the claims above were verified by source review only;
this is what a live connection says. No packet capture was involved -- this host
grants no `CAP_NET_RAW`, so `tcpdump` and raw sockets are both unavailable --
but none was needed: the host end of a connection already knows what its peer
advertised, and `ss -i` prints it.

From `ss -tinm dst 192.168.4.2` sampled during a 20-second bulk transfer, on
the connection carrying it (abridged to the fields read below):

```
cubic wscale:2,10 rto:201 rtt:0.046/0.002 mss:1460 pmtu:1500 advmss:1460
      minrtt:0.039 snd_wnd:131072 rcv_wnd:64512
```

**Window scaling engages, at the derived factor.** `wscale:2,10` reports the
peer's scale first, so Motor advertised shift 2 -- matching
`rx_cap_log2.saturating_sub(16)` for a 128KB buffer, where `rx_cap_log2` is the
bit length (18), not the floor log (17). The plan's "shift 2" was right.

**The advertised window is the whole buffer.** `snd_wnd:131072` is the host's
send window, which is Motor's advertised receive window: 131072 bytes exactly,
not a fraction of it and not clipped by the scale.

**The rig's RTT is 46 microseconds** (39 minimum), so window/RTT is 2.65 GiB/s.
The transfer this sample was taken during ran at 697.31 MiB/s. **The
receive window is 3.9x from binding here**, and the packet-rate ceiling binds
first by that factor -- which is the companion plan's territory, not this one's.

The consequence for Proposed work Step 1: **this rig cannot produce evidence for
a raise.** It cannot make the window bind, the plan's own Step 0 removed the
synthetic delay that would have forced it, and no representative long-RTT
workload exists here. So the 512KB proposal has to be decided on the arithmetic
in the Motivation table plus an approved memory budget, or wait for a real WAN
workload. It should not be landed on the strength of a local benchmark, because
a local benchmark cannot move.

One finding from the same measurement belongs to the companion plan and is
recorded there: `VIRTIO_NET_F_MTU` was not negotiated, sys-io fell back to a
1536-byte frame MTU, and Motor therefore advertised MSS 1482 on a path that
carries 1460. `ss` showed the host clamping it to 1460, which is why nothing had
broken. Fixed on guidance in `33df3c02`; see `virtio-rx-coalescing.md`, Step 0
result.

**Both findings confirmed on a second VMM, 2026-08-02.** The same `ss` reading
against a Cloud Hypervisor v52.0 boot gives `wscale:2,10` and
`snd_wnd:131072`, so neither is a QEMU artifact: Motor advertises shift 2 and
its whole 131072-byte buffer whichever VMM presents the device. The RTT is not
comparable across the two samples -- the CHV one was taken on an idle
connection rather than during a bulk transfer -- so the 3.9x headroom figure
above remains a QEMU-rig number, and Step 1 still has no rig on which the
window can be made to bind.

## Constraints

1. **Buffers cannot grow.** smoltcp sockets own fixed rings; per-socket
   sizing must reach sys-io in the bind/connect request itself.
2. **Memory is eager and per-socket.** 256KB (RX+TX) is committed at
   creation today, including for every listening socket. A default raise
   multiplies across all sockets whether or not they face a WAN.
3. **No fixed default covers long fat paths.** ~3-5MB windows cannot be
   the default without wasting megabytes on every LAN socket. Fixed
   defaults trade memory for reach; only autotuning escapes the trade.
4. **TX is symmetric.** The TX buffer caps unacked in-flight upload data
   the same way. Same mechanics, same plumbing; this plan treats RX as
   primary and carries TX along.
5. **The window is necessary, not sufficient.** Long-path throughput also
   depends on the remote sender's congestion behavior and on the fork's
   loss recovery, which we have never exercised at WAN RTTs. Step 0's
   measurement is designed to expose this early.

## Options

**Option A: raise the fixed default.** ~10 loc. Immediate benefit for every
application, bounded by constraint 3: a modest bump (e.g. 512KB) buys
~17 MiB/s at 30 ms for +768KB per socket, and no plausible default reaches
100 MiB/s at WAN RTTs.

**Option B: per-socket sizing, plumbed end to end.** This option needs a
boundary redesign before implementation. Motor's current outbound
`tcp_connect(addr, timeout, nonblocking)` returns an FD only after connection
setup starts, so no vDSO wrapper exists on which socket2/mio/libc can stage
`SO_RCVBUF`/`SO_SNDBUF` before the SYN. A native builder, a new vDSO ABI, or
growable rings could solve that, but choosing among them is a separate design
decision. Listener inheritance, post-connect behavior, and requested versus
effective `getsockopt` values must be defined in that design; silently
reporting a size that was not applied is not acceptable.

**Option C: receive autotuning in the fork.** Linux-style dynamic buffer
growth from measured delivery rate. The durable answer for arbitrary RTTs
without the memory trade, and the only option that helps unmodified
applications on WAN paths -- but it is real fork work on the exact code the
fork otherwise tracks upstream for, and it needs RTT estimation plumbing.
Out of scope for this pass; recorded so the A/B decision is made knowingly.

## Recommendation

Use representative full-OS workload evidence, then A plus B; defer C. Land a
modest default raise (A) for unmodified applications only with an approved
memory budget, and add the per-socket plumbing (B) for applications that
care. Revisit C only if real workloads outgrow B.

## Proposed work

**Step 0 -- removed.** Synthetic tap delay/loss testing is useful for a
standalone netstack, but is not a required gate for the stack integrated into
Motor OS. Do not manipulate the host qdisc as part of this plan.

**Step 1 -- raise the default, after listen-path hardening.** Proposal: 512KB
RX / 512KB TX, i.e. 1MB per socket instead of 256KB, executed only after
`core-networking-rewrite.md` Step 4 has bounded half-open sockets and removed
their eager full-buffer commitment. If the per-socket memory budget is not
obviously acceptable, stop and ask for guidance per AGENTS.md rather than
guessing. Use paired full-OS benchmarks and representative application
workloads. ~10 loc plus tests.

`docs/plans/core-safety-hardening.md` splits that prerequisite in two: the
half-open bound is its item 6 and lands in Step 6 of the execution order, while
the eager full-buffer commitment moves into Step 2 below. So Step 1 after Step 6
alone still multiplies the raise across every listening socket; either take Step
2 first or approve that cost explicitly.

Note also that a raise makes the window-scale accounting defect that plan
records as D1 strictly worse if it is not yet fixed: the shift grows with the
buffer, and the recorded right edge is the unscaled SYN window shifted by it. D1
is that plan's first patch, so this ordering holds by construction, but do not
reorder around it.

**Step 2 -- redesign and implement per-socket sizing (Option B).** First
resolve the outbound pre-connect API, listener timing, post-connect behavior,
requested/effective reporting, and exact RX/TX clamp semantics in a reviewed
plan. Then implement the chosen design in small end-to-end patches. This step
touches the option paths the `moto-io`/`rt.vdso` series is churning, so it
lands after that series' Stage 3 wrappers exist and after core networking Step
4 (see Sequencing).

This step now also owns lazy or growable listening-socket buffers, moved here
from `core-networking-rewrite.md` Step 4 by
`docs/plans/core-safety-hardening.md`. Both need the same netstack surface: a
socket that starts small and grows must still advertise the window scale it will
eventually want in its SYN, and the scale is derived from the receive capacity at
construction (fork `src/socket/tcp.rs:573`, `:594`), so both need an explicit
construct-with-shift API plus a grow-an-empty-ring API. Constraint 1 above
("buffers cannot grow") is therefore a property of the current fork, not a fixed
constraint on this design -- but changing it is fork work to be scoped here, once.

**Step 3 -- autotuning (Option C).** Explicitly deferred. Reopen only with
evidence that fixed defaults plus per-socket sizing are insufficient for a
real workload.

**Note on buffer allocation.** Steps 1-2 change the same allocation that
`docs/plans/core-networking-rewrite.md` Step 4 changes for a different
reason: today every *listening* socket also commits 256KB up front, which is
that plan's SYN-flood exposure. Raising the default makes that worse, so the
two should be sequenced deliberately -- ideally lazy/growable buffers land
first, after which a larger cap costs nothing per half-open socket.

Sequenced as of `docs/plans/core-safety-hardening.md`: the half-open *count* is
bounded first (its item 6, in Step 6 of the execution order), the lazy/growable
buffers are designed and implemented here in Step 2, and the default raise in
Step 1 follows both. The cap alone already bounds the SYN-flood memory to
`cap x 256KB`, which is what makes it safe to land the two halves separately.

## Risks and open questions

- **Loss recovery at WAN RTTs is unexercised, and is known to be weak.**
  `core-networking-rewrite.md` establishes that Motor's build has no
  congestion control at all, a 1-second minimum RTO, go-back-N
  retransmission, and a 4-segment out-of-order assembler. A larger window
  over a lossy path will therefore underdeliver its arithmetic gain until
  that plan's Step 3 lands. This is a known limitation, not an automated gate
  for the receive-window work.
- **Memory growth is diffuse.** The raise applies to every socket,
  including idle and listening ones. If sys-io memory becomes a concern,
  Option B's clamp can be tightened and the default revisited.
- **Interaction with coalescing is positive but sequenced.** A larger
  advertised window lets host GRO build larger super-segments, amplifying
  `virtio-rx-coalescing.md`. But without coalescing landed, high-bandwidth
  paths stay packet-rate bound (~164 MiB/s on the rig).

## Sequencing

Step 1 waits for core networking Step 4; Step 2 waits for both that step and
the vDSO series' Stage 3. Use the benchmark manifest required by
`docs/plans/networking-step-by-step.md`.

## Gates

By explicit user guidance, use `full-test-networking.sh` three times as debug
and three times as release; no new compiler or clippy warnings;
`cargo +nightly fmt`. Plus, for Steps 1 and 2: the paired same-host rnetbench
A/B of the vdso plan's Section 10 methodology (a buffer change must not
regress the full-OS clean-path numbers).
