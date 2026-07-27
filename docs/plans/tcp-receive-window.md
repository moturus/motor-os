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

Measure first, then A plus B; defer C. Step 0 costs nothing and both
confirms that the window is the binder at emulated WAN RTTs and gives the
before-curve. Then land a modest default raise (A) for unmodified
applications, and the per-socket plumbing (B) for applications that care.
Revisit C only if real workloads outgrow B.

## Proposed work

**Step 0 -- measurement only, no production change.** On the host, add
netem delay to `moto-tap` (e.g. 0/10/30/100 ms) and record single-stream RX
throughput at each point; capture a SYN on `moto-tap` to confirm the
advertised window scale on the wire. This validates the window-binding
claim, records the before-curve, and probes constraint 5 (loss recovery at
RTT) before any code is written. ~0 loc; the netem command lines land in
this document.

**Step 1 -- raise the default, after listen-path hardening.** Proposal: 512KB
RX / 512KB TX, i.e. 1MB per socket instead of 256KB, confirmed against Step
0's curve and executed only after `core-networking-rewrite.md` Step 4 has
bounded half-open sockets and removed their eager full-buffer commitment. If
the per-socket memory budget is not obviously acceptable, stop and ask for
guidance per AGENTS.md rather than guessing. Re-run the netem curve and record
both in this document. ~10 loc plus tests.

**Step 2 -- redesign and implement per-socket sizing (Option B).** First
resolve the outbound pre-connect API, listener timing, post-connect behavior,
requested/effective reporting, and exact RX/TX clamp semantics in a reviewed
plan. Then implement the chosen design in small end-to-end patches. This step
touches the option paths the `moto-io`/`rt.vdso` series is churning, so it
lands after that series' Stage 3 wrappers exist and after core networking Step
4 (see Sequencing).

**Step 3 -- autotuning (Option C).** Explicitly deferred. Reopen only with
evidence that fixed defaults plus per-socket sizing are insufficient for a
real workload.

**Note on buffer allocation.** Steps 1-2 change the same allocation that
`docs/plans/core-networking-rewrite.md` Step 4 changes for a different
reason: today every *listening* socket also commits 256KB up front, which is
that plan's SYN-flood exposure. Raising the default makes that worse, so the
two should be sequenced deliberately -- ideally lazy/growable buffers land
first, after which a larger cap costs nothing per half-open socket.

## Risks and open questions

- **Loss recovery at WAN RTTs is unexercised, and is known to be weak.**
  `core-networking-rewrite.md` establishes that Motor's build has no
  congestion control at all, a 1-second minimum RTO, go-back-N
  retransmission, and a 4-segment out-of-order assembler. A larger window
  over a lossy path will therefore underdeliver its arithmetic gain until
  that plan's Step 3 lands. Step 0 with netem loss quantifies the gap
  cheaply; expect the window curve to look good at 0% loss and poor at 1%.
- **Memory growth is diffuse.** The raise applies to every socket,
  including idle and listening ones. If sys-io memory becomes a concern,
  Option B's clamp can be tightened and the default revisited.
- **Interaction with coalescing is positive but sequenced.** A larger
  advertised window lets host GRO build larger super-segments, amplifying
  `virtio-rx-coalescing.md`. But without coalescing landed, high-bandwidth
  paths stay packet-rate bound (~164 MiB/s on the rig), so this plan's
  netem curve will plateau there -- expected, not a defect of this work.
- **netem fidelity.** Delay on the tap emulates RTT one-way and shapes the
  rig only coarsely. Good enough to demonstrate window binding; not a
  substitute for a real WAN test, which is worth one manual confirmation
  (an actual large download) once Step 1 lands.

## Sequencing

Step 0 can run in the same sitting as the coalescing measurements. Step 1
waits for core networking Step 4; Step 2 waits for both that step and the vDSO
series' Stage 3. `src/vm_scripts/run-qemu.sh` is already tracked; the netem
curves use the benchmark manifest required by
`docs/plans/networking-step-by-step.md`.

## Gates

Per AGENTS.md: `full-test.sh` passing three times as debug and three times
as release; no new compiler or clippy warnings; `cargo +nightly fmt`. Plus,
for Steps 1 and 2: the paired same-host rnetbench A/B of the vdso plan's
Section 10 methodology (a buffer change must not regress LAN-RTT numbers),
and the before/after netem RTT curve recorded in this document.
