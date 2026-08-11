# RACK-TLP loss recovery (step 3 design)

2026-08-11. Design round for the step 3 series in
`networking-remaining-steps.md`. WAN paths with real loss are a product
target (2026-08-10 ruling), and step 2's per-socket sizing makes large
windows reachable -- which is exactly where go-back-N hurts most: one
lost segment in an 8 MiB window resends up to 8 MiB.

Ruling 2026-08-11: build RACK-TLP (RFC 8985) directly, at full RFC
fidelity -- adaptive reorder window with DSACK detection in this series,
not deferred -- rather than classic RFC 6675 recovery first. The
3-dupack fast retransmit stays as a fallback detector (RFC 8985 permits
both; Linux ships both), so a peer or path that starves RACK of
timestamps still recovers.

## Current state (verified in code 2026-08-11)

- The wire layer parses and emits SACK-permitted and up to 3 SACK
  ranges. The socket negotiates `remote_has_sack` from the handshake.
- Generation: our ACKs carry at most ONE range, taken from the rx
  assembler (`socket/tcp.rs` ~1679-1710). No DSACK generation.
- Reception: incoming `repr.sack_ranges` are never read. Parsed and
  discarded.
- Loss response is go-back-N: on RTO or fast retransmit (3 dupacks),
  `remote_last_seq` rewinds to `local_seq_no` and the entire unacked
  window retransmits, paced by cwnd. Fast retransmit does not re-charge
  the congestion controller (the once-per-loss fix, landed); RTO does.
- There is no socket-level recovery point: `local_rx_dup_acks` resets on
  any advancing ACK, so partial ACKs inside one loss event can trigger
  repeated full-window retransmits. Cubic's internal `recovery_start`
  shapes its growth curve only.
- The socket has one exclusive `Timer` slot (retransmit / fast
  retransmit / close / etc). RACK's reorder timer and TLP's PTO can be
  armed while a retransmission timer is pending, so they become separate
  `Option<Instant>` fields folded into `poll_at`, not new variants of
  the exclusive enum.
- Transmit history: the tx ring is bytes, segment boundaries are not
  retained anywhere, and nothing records transmit times. RACK needs
  both, so the scoreboard below is new state, not a view of something
  existing.
- The RTO floor is 200 ms, argued from Linux's default, never measured.
- The deterministic packet harness drives the socket directly with a
  virtual clock, so loss, reordering, delay, and every timer in RFC 8985
  are expressible and reproducible without host-level shaping.

## Design sketch

**Scoreboard.** A bounded per-socket array of transmitted ranges:
`(seq_start, seq_end, xmit_ts, sacked, lost, retransmitted)`. Ranges
sent in one dispatch burst share a timestamp; adjacent same-state
ranges merge. Bound: 64 entries. Degrade on overflow is always in the
safe direction: merging keeps the LATER timestamp (delays loss marking,
never fabricates it) and drops `sacked` knowledge rather than invent
coverage (worst case a spurious retransmit); non-adjacent sacked ranges
are never merged across a hole. Cumulative ACKs prune from the left.
`reset()` clears the board.

**SACK/DSACK processing.** Incoming ranges are validated against
snd.una/snd.nxt (RFC 2018) and marked on the board. DSACK (RFC 2883:
first block below the cumulative ACK, or contained in the second) is
recognized and feeds two consumers: the adaptive reorder window, and a
spurious-retransmission counter the harness reads. An ACK that SACKs
new data counts toward the dupack fallback threshold.

**RACK detection (RFC 8985).** On each delivery (cumulative or SACK),
`rack.xmit_ts`/`rack.end_seq` track the most recently transmitted
segment known delivered, and RACK RTT updates from it (skipping
retransmitted ranges unless TSopt proves the ACK matches the
retransmission). A range is lost when
`rack.xmit_ts - range.xmit_ts > reo_wnd` (with the sequence tiebreak);
ranges inside the window arm the reorder timer for the residue.
`reo_wnd` starts at `min_rtt / 4`, is DSACK-adaptively grown (one
`srtt` step per DSACK round, per the RFC's `reo_wnd` management), decays
back after sixteen recoveries without reordering evidence, and is
capped at `srtt`. Before any reordering has been observed and while no
recovery is in progress, `reo_wnd` is zero, as the RFC prescribes.

**Recovery episode.** The socket records `recovery_point = snd.nxt`
when entering recovery (whether RACK or the dupack fallback triggered
it); partial ACKs inside the episode never re-charge the congestion
controller (this generalizes the once-per-loss fix), and the episode
ends when the cumulative ACK passes the recovery point.

**Retransmission.** Lost-marked ranges retransmit first, lowest
sequence first, then new data; in-flight is bounded by cwnd, counting
retransmissions and excluding sacked bytes. This replaces go-back-N in
fast recovery. On RTO: mark all non-sacked outstanding ranges lost,
KEEP sacked marks (full-fidelity behavior, as Linux), and retransmit
skipping sacked ranges. Reneging guard: a second consecutive RTO with
snd.una unmoved clears the board and falls back to today's blanket
retransmit -- bounded and safe when a receiver discards what it SACKed.

**TLP.** When data is outstanding, no loss is marked, and the
retransmission timer would otherwise sit idle-long, a PTO of
`2 * srtt` (min 10 ms, capped by the RTO) arms; on fire, send one probe
-- new data if the window allows, else the highest-sequence segment --
and remember `tlp_high_seq`. A DSACK for the probe means the probe was
a duplicate: no congestion charge; a cumulative ACK past `tlp_high_seq`
without DSACK means the probe repaired a real tail loss: charge once.
Only one probe per flight.

## The series (each patch 100-300 lines including tests, each 3+3 gated)

1. Recovery-point episode + head-only fast retransmit. NewReno-complete
   by itself; the episode is the structure everything after reuses.
2. Scoreboard: transmit-range tracking with timestamps, pruning, merge
   policy, bound-degrade tests. Feature-inert (nothing consumes it yet).
3. SACK/DSACK processing onto the board + validation + the
   spurious-retransmit counter.
4. RACK detection: rack state, mark-lost rule, reorder timer as a
   parallel timer field in `poll_at`, adaptive `reo_wnd`.
5. RACK-driven retransmission replacing go-back-N in fast recovery;
   RTO keep-sacked behavior + the reneging guard.
6. TLP: PTO arming, the probe, episode accounting.
7. Generation: up to 3 blocks most-recently-changed-first (RFC 2018
   ordering) from the assembler, plus DSACK generation (RFC 2883) for
   duplicate arrivals. Independent of 2-6; helps peers and feeds our
   own tests.
8. Loss harness: a seeded lossy-link scheduler over the packet harness
   (scripted and PRNG-seeded drop/reorder/delay between a socket pair,
   virtual clock), with per-run counters: retransmitted bytes, spurious
   retransmits (via our own DSACK generation), time-to-drain a fixed
   transfer. Deterministic per seed; a handful of seeds run in the
   normal suite.
9. RTO floor round (ruling 2026-08-11: one tuning round): measure the
   200 ms floor against 100 ms and 50 ms across an RTT x loss matrix on
   the harness; adopt a clearly better floor or keep 200 ms and record
   why. The same matrix sanity-checks `reo_wnd` adaptation. Virtual
   clock, so rig-regime-independent.

Dependency chain: 1 first; 2 -> 3 -> 4 -> 5 -> 6; 7 any time after 3's
DSACK definitions; 8 after 5 (6 preferred); 9 after 8.

## Interactions

- Step 2 window scaling makes multi-MiB windows real; patch 5's
  skip-sacked retransmission is what keeps a single loss from resending
  them.
- Step 4 SYN cookies carry SACK-permitted through TSopt; RACK keys only
  on `remote_has_sack` and its own transmit history, so cookie-restored
  sockets need no special casing. TSopt (already landed) also gives
  RACK its retransmission-disambiguation input.
- Step 5 may later replace the fixed-array scoreboard; it stays behind
  insert/prune/next-lost accessors so a swap is local.

## Decisions (asked and answered 2026-08-11)

- Algorithm: RACK-TLP directly (over 6675-first and epoch-only).
- Fidelity: full RFC 8985 in this series -- adaptive reo_wnd + DSACK
  now, not as follow-ups. Dupack fast retransmit retained as fallback.
- RTO floor: one tuning round on the harness matrix, standing
  one-tuning-round policy applies.
