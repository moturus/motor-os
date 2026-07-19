# vdso rewrite: stage-0 baselines

Recorded 2026-07-19 per `vdso-rewrite-plan.md` stage 0, on the dev host
(itself a VM behind qemu user-mode networking; no external ICMP echo — see
the full-test.sh `ping_external` guard). All later stage gates compare
against the numbers here, measured on this same host. This host is not the
host of the historical perf-series numbers; only same-host deltas count.

Methodology (from the 2026-07 perf series): rnetbench server on-image
(`/sys/tests/rnetbench --server`), client on the host
(`rnetbench --client 192.168.4.2:40000 [-b 65536]`); each client run
reports TCP RR, client->server (Motor RX), server->client (Motor TX).
Default buf = 1KB avg random writes with NODELAY (per-message stress);
`-b 65536` = bulk. RR of a run is the host-steal gauge: distrust
throughput of runs whose RR is far out of band. Debug-build throughput is
additionally logging-bound (per-packet DEBUG console output) — use debug
numbers only for debug-vs-debug comparison.

## full-test.sh flake baseline (debug)

10 watchdog-wrapped runs (timeout 600s; typical green run 86-92s):

| Outcome | Count | Runs |
|---|---|---|
| Green | 8 | 1-3, 5, 6, 8-10 |
| Hang (600s timeout) | 1 | 4 |
| Fast fail | 1 | 7 |

Two setup-time environment failures excluded from the count, both fixed in
full-test.sh directly: test.key group-readable on fresh checkout (ssh
silently ignores the key), and blocked external ICMP on this host.

**Run 4 (hang):** tokio-tests output stopped after
`rt_common::threaded_scheduler_4_threads/test_io_driver_called_when_under_load`;
VM alive (ARP/keepalives answered until the kill), ssh channel open, but
all in-VM socket activity ceased at t=68.8s — green runs complete the whole
script by about that point. Anomalous console markers present only in this
run: (1) t=59.4 `Connect 127.0.0.1:49152 => 127.0.0.1:0 failed:
Unaddressable` + `ERROR Unexpected smoltcp connect error: ()` — a TCP
connect to **port 0**, suggesting a `local_addr()`-after-bind race or a
corrupted connect request; sys-io sends an error response on this path
(`net.rs` dispatch) but leaves the socket half-initialized (`connect_req`
stored, no connect task spawned). (2) t=68.8 `dropping socket 0x26c` +
pre-existing oddity `missing tcp_listener for socket 0x26c????`. Candidate
stall locations: the next test (`test_yield_defers_until_park`) hung in
tokio's park path over `poll_wait`, or the suite finished but russhd
(a tokio app; child stdio + process-exit readiness = the
`EventSourceUnmanaged` path) never saw the child's output/exit.
Discriminator for the next capture: in-VM `ps` (the watchdog now uses
`timeout --foreground` so qemu survives to be ssh'd into).

**Run 7 (fast fail):** `expect_ping_error does-not-exist.motor.invalid
NotFound` failed at t=11.6s — the captured ping output was empty rather
than a NotFound error. Either a transient DNS error-path divergence
(this host's slirp DNS proxy handling of NXDOMAIN is a suspect) or a
russhd output-delivery glitch.

**russhd channel-close anomalies (every run):** each green run ends with
`channel 0: protocol error: close rcvd twice` from the host ssh client;
run 6 also produced `ieof packet referred to nonexistent channel 0`.
Non-fatal, but evidence that russhd's channel-close path misbehaves —
relevant to the run-4 hypothesis (b).

## rnetbench, release build

| Run | RR usec | RX default | TX default | RX -b64K | TX -b64K |
|---|---|---|---|---|---|
| 1 | 113.6 / 148.5 | 524.9 | 332.1 | 559.1 | 607.1 |
| 2 | 121.9 / 143.9 | 524.9 | 326.1 | 537.0 | 626.7 |
| 3 | 142.6 / 150.9 | 501.6 | 338.0 | 551.2 | 617.0 |

(RR column: default-run RR / b64K-run RR; throughput in MiB/s.)
Gate reference values (medians): **RR ~122/148 usec, default RX ~525 /
TX ~332, bulk RX ~551 / TX ~617 MiB/s.**

## rnetbench, debug build

| Run | RR usec | RX default | TX default | RX -b64K | TX -b64K |
|---|---|---|---|---|---|
| 1 | 330.8 / 383.0 | 11.9 | 46.9 | 27.5 | 99.9 |
| 2 | 345.8 / 383.5 | 9.8 | 46.1 | 24.4 | 102.2 |
| 3 | 385.9 / 384.5 | 3.6 | 43.3 | 26.9 | 101.0 |

Debug default-RX is wildly noisy (3.6-11.9) — logging-bound; treat debug
throughput as a smoke check only.

## FS smoke (systest, first run in boot)

| Build | Write mbps | Read mbps | Samples |
|---|---|---|---|
| debug | 51.5-56.3 (median ~54) | 109.3-120.9 (median ~119) | 9 (flake runs) |
| release | 232.2 | 266.9 | 1 |

All samples are run-1-in-boot (the FS smoke run-number trap: later runs in
the same boot report roughly half the first-run numbers on cold paths).

## Reference points (prior rig, 2026-07 series)

Historical bests from the perf series, different host — context only, not
gates: bulk RX ~900-927, bulk TX ~628-734 MiB/s, RR 81-166 usec band
depending on scheduler rounds and steal.
