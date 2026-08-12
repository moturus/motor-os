# TCP close path: orphaned-socket divergences from Linux

2026-08-11. Design for the step 6 work item scheduled the same day (see
`networking-remaining-steps.md`): release the dead rings when an orphaned
socket enters FIN-WAIT-2, and answer data arriving after our FIN with RST.
Ordered before the step 2 default raise, because FIN-WAIT-2 pins full rings
for the linger and a bigger default multiplies that.

## What the close path already gets right (verified in code 2026-08-11)

`close_tcp_socket_inner` already aborts (RST) on SO_LINGER(0), on unread
data at close time (Linux parity: the peer must learn its data was not
read), and on a connection that never carried a byte of ours. A graceful
close drains pending TX, sends the FIN, and a linger task sees the
handshake through bounded by 60 s (`DEFAULT_LINGER_SECS`), waking on state
changes rather than polling. TIME-WAIT lasts 10 s (`CLOSE_DELAY`).

## The two remaining divergences

1. **Data after our FIN is absorbed, not reset.** After close, sys-io sets
   `rx_closed` and stops draining, but the netstack socket still accepts
   in-window payload in FIN-WAIT-1/2 into the rx ring. Nobody ever reads
   it, the advertised window shrinks to zero, and a writing peer hangs in
   zero-window probes until our linger deadline resets -- up to 60 s.
   Linux (RCV_SHUTDOWN set, new data beyond rcv_nxt) resets immediately;
   the peer gets ECONNRESET on its next write.
2. **Dead rings stay pinned for the linger.** At FIN-WAIT-2 entry the TX
   ring is empty by definition (our FIN is acked, so all data is acked),
   and on an orphaned socket the RX ring is empty too (unread data at
   close aborted; new arrivals will now reset per item 1). Yet 2x128 KiB
   stays allocated for up to 60 s + 10 s TIME-WAIT -- and step 2's
   per-socket sizing raises the worst case to 2x8 MiB per orphan.

The two interact: the RST path ends the linger early when the peer keeps
sending (state goes Closed, the linger task wakes on the state change and
drops the socket), so item 1 also caps how long item 2's savings matter.

## Design

**Marker.** A sticky `set_rx_shutdown()` on the netstack socket, cleared
by `reset()`. sys-io calls it exactly where it sets its own `rx_closed`:
the close path and (per the 2026-08-11 ruling below) the shutdown(RD)
handler. The netstack cannot infer this itself -- `close()` on the
netstack socket is TX-side only (shutdown(WR) shares it), and RX
liveness is a sys-io fact.

**RST on data after FIN.** In `process()`, states FIN-WAIT-1 and
FIN-WAIT-2 only -- the peer's stream is still open there; in CLOSE-WAIT,
CLOSING, LAST-ACK and TIME-WAIT the peer's FIN already ended its stream,
so new data is out of window and existing handling applies. On an
accepted segment carrying payload that advances beyond `remote_seq_no`
(rcv_nxt) while `rx_shutdown` is set: emit `rst_reply`, enter Closed.
Retransmits entirely below rcv_nxt still get a plain ACK, as on Linux --
they are the network being slow, not the peer writing into the void.

**Ring release.** At `set_state(FinWait2)` and `set_state(TimeWait)`
entry, if `rx_shutdown` is set and both rings are empty, release both to
the 16 KiB floor (`SocketBuffer::release_to`, the shrink mirror of
step 2's `grow_to`: empty-ring-only, owned-storage-only, replaces the
Vec so the large allocation actually frees, `read_at = 0`). The floor
rather than zero: a zero-capacity rx ring advertises a zero window, and
the segment acceptance test rejects the peer's FIN (one octet of
sequence space) against a zero window -- the close handshake would
degenerate into a challenge-ACK loop until the linger deadline. The
16 KiB floor reuses step 2's constant, keeps every acceptance edge
untouched, and still turns a worst-case 16 MiB orphan into 32 KiB.
Non-orphaned sockets (shutdown(WR) with a live reader) keep full rings:
the release predicate is `rx_shutdown`, nothing else. If a ring is
unexpectedly non-empty the release is skipped (debug_assert in tests,
graceful skip in release builds).

**sys-io wiring.** `close_tcp_socket_inner` calls `set_rx_shutdown()` on
the non-abort paths; the shutdown(RD) handler does the same. No wire
format, RPC, or moto-rt change; no RT version bump.

## Patches (each 100-300 lines including tests, each 3+3 gated)

1. netstack: `SocketBuffer::release_to` + `set_rx_shutdown` + the RST
   arm + release-at-entry, with packet tests: RST on new data in
   FIN-WAIT-1 and FIN-WAIT-2; ACK (not RST) for a below-rcv_nxt
   retransmit; rings released at FIN-WAIT-2 and TIME-WAIT entry when
   orphaned; full rings retained and data accepted when not orphaned;
   peer FIN still accepted after release.
2. sys-io wiring + systest: peer observes ECONNRESET promptly when it
   writes after our close (event-ordered assertion -- write until error,
   assert the error kind -- not a host-timing SLO).

## Decisions (asked and answered 2026-08-11)

- Release target: the 16 KiB floor (over zero-capacity and over
  RST-only-without-release).
- RST trigger set: close and shutdown(RD) both -- full Linux
  RCV_SHUTDOWN parity.

## Found during implementation (2026-08-11)

The writing peer now fails promptly, but as `NotConnected`, not
`ConnectionReset`: moto-rt's error enum has no connection-reset code,
so every dead stream's write reports `E_NOT_CONNECTED` regardless of
why it died. Reporting ECONNRESET faithfully means a new moto-rt error
code plus carrying reset-cause through `EvtTcpStreamStateChanged`
(args_32[1] is free and zeroed, so it is wire-compatible) -- an RT
surface addition that needs its own vetting. Recorded as a step 6
decision item; the systest asserts promptness and tolerates either
kind.
