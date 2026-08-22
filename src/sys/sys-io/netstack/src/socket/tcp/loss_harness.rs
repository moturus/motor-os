//! A seeded lossy-link harness: two live sockets in one process, a
//! virtual clock, and a deterministic PRNG deciding per-segment drop
//! and delay jitter (jitter is what reorders). Every scenario replays
//! exactly from its seed, so these run in the normal suite; the same
//! driver carries the RTO-floor measurements.

use std::vec::Vec;

use super::{Socket, SocketBuffer};
use crate::iface::Context;
use crate::phy::Medium;
use crate::socket::PollAt;
use crate::time::{Duration, Instant};
use crate::wire::{IpEndpoint, IpListenEndpoint, IpRepr, Ipv4Address, TcpControl, TcpRepr};
use crate::wire::{TcpSeqNumber, TcpTimestampRepr};

// Both fixture interfaces own 192.168.1.1 (dispatch resets a socket
// whose local address the interface lost), so the pair is
// loopback-style: one address, two ports, and the harness routes by
// direction, not by address.
const A_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
const B_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
const A_PORT: u16 = 49500;
const B_PORT: u16 = 80;

/// xorshift64: deterministic, no_std-friendly, good enough to pick
/// which segments suffer.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn chance(&mut self, per_mille: u64) -> bool {
        self.next() % 1000 < per_mille
    }
    fn upto(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
}

/// An owned copy of an emitted segment, in flight on the link.
struct WireSeg {
    arrival: Instant,
    order: u64,
    to_b: bool,
    ip: IpRepr,
    src_port: u16,
    dst_port: u16,
    control: TcpControl,
    seq_number: TcpSeqNumber,
    ack_number: Option<TcpSeqNumber>,
    window_len: u16,
    window_scale: Option<u8>,
    max_seg_size: Option<u16>,
    sack_permitted: bool,
    sack_ranges: [Option<(u32, u32)>; 3],
    timestamp: Option<TcpTimestampRepr>,
    payload: Vec<u8>,
}

impl WireSeg {
    fn repr(&self) -> TcpRepr<'_> {
        TcpRepr {
            src_port: self.src_port,
            dst_port: self.dst_port,
            control: self.control,
            seq_number: self.seq_number,
            ack_number: self.ack_number,
            window_len: self.window_len,
            window_scale: self.window_scale,
            max_seg_size: self.max_seg_size,
            sack_permitted: self.sack_permitted,
            sack_ranges: self.sack_ranges,
            timestamp: self.timestamp,
            payload: &self.payload,
        }
    }
}

struct Endpoint {
    socket: Socket<'static>,
    cx: Context,
}

fn endpoint() -> Endpoint {
    let (iface, _, _) = crate::tests::setup(Medium::Ip);
    let socket = Socket::new(
        SocketBuffer::new(vec![0; 16384]),
        SocketBuffer::new(vec![0; 16384]),
    );
    Endpoint {
        socket,
        cx: iface.inner,
    }
}

struct LinkParams {
    delay: Duration,
    jitter_ms: u64,
    loss_per_mille: u64,
    /// Override for the sender's RTO floor; None keeps production's.
    min_rto: Option<Duration>,
}

struct Stats {
    /// Payload octets that crossed the link toward the reader,
    /// duplicates included.
    wire_payload: usize,
    /// DSACK reports the sender received: its spurious retransmissions.
    spurious: u32,
    /// Virtual time from first event to full delivery.
    elapsed: Duration,
}

fn expected_byte(i: usize) -> u8 {
    (i.wrapping_mul(31) >> 3) as u8
}

/// Drive a full transfer of `total` bytes from A to B across the lossy
/// link; panics if it stalls past `deadline` (virtual time) or the
/// delivered bytes differ.
fn run_transfer(seed: u64, params: LinkParams, total: usize, deadline: Duration) -> Stats {
    let mut a = endpoint();
    let mut b = endpoint();
    b.socket
        .listen(IpListenEndpoint {
            addr: Some(B_ADDR.into()),
            port: B_PORT,
        })
        .unwrap();
    a.socket
        .connect(
            &mut a.cx,
            IpEndpoint::new(B_ADDR.into(), B_PORT),
            IpEndpoint::new(A_ADDR.into(), A_PORT),
        )
        .unwrap();
    if let Some(floor) = params.min_rto {
        a.socket.rtte.set_min_rto(floor);
        b.socket.rtte.set_min_rto(floor);
    }

    let mut rng = Rng::new(seed);
    let mut now = Instant::ZERO;
    let deadline_at = now + deadline;
    let mut flights: Vec<WireSeg> = Vec::new();
    let mut order = 0u64;
    let mut sent = 0usize;
    let mut received: Vec<u8> = Vec::with_capacity(total);
    let mut wire_payload = 0usize;

    let mut spin = 0u32;
    let mut last_progress = (Instant::ZERO, 0usize);
    while received.len() < total {
        assert!(
            now < deadline_at,
            "transfer stalled at {} of {} bytes, t={}",
            received.len(),
            total,
            now
        );
        if last_progress == (now, received.len()) {
            spin += 1;
            if spin >= 10_000 {
                a.cx.set_now(now);
                let pa = a.socket.poll_at(&mut a.cx);
                b.cx.set_now(now);
                let pb = b.socket.poll_at(&mut b.cx);
                panic!(
                    "harness spin: t={} received={} a={:?}/{:?} b={:?}/{:?} \
                     flights={} a.resume={:?} a.timer={:?}",
                    now,
                    received.len(),
                    a.socket.state(),
                    pa,
                    b.socket.state(),
                    pb,
                    flights.len(),
                    a.socket.retransmit_resume,
                    a.socket.timer,
                );
            }
        } else {
            spin = 0;
            last_progress = (now, received.len());
        }

        // The application half: keep the writer full, the reader empty.
        while sent < total && a.socket.can_send() {
            let want = (total - sent).min(4096);
            let chunk: Vec<u8> = (sent..sent + want).map(expected_byte).collect();
            let n = a.socket.send_slice(&chunk).unwrap();
            if n == 0 {
                break;
            }
            sent += n;
        }
        while b.socket.can_recv() {
            b.socket
                .recv(|buf| {
                    received.extend_from_slice(buf);
                    (buf.len(), ())
                })
                .unwrap();
        }

        // Emit everything either socket wants to emit right now.
        for _ in 0..128 {
            let mut emitted = false;
            for a_side in [true, false] {
                let (ep, to_b) = if a_side {
                    (&mut a, true)
                } else {
                    (&mut b, false)
                };
                ep.cx.set_now(now);
                let poll = ep.socket.poll_at(&mut ep.cx);
                let due = match poll {
                    PollAt::Now => true,
                    PollAt::Time(t) => t <= now,
                    PollAt::Ingress => false,
                };
                if !due {
                    continue;
                }
                let mut out: Option<(IpRepr, WireSeg)> = None;
                ep.socket
                    .dispatch(&mut ep.cx, |_, _, (ip, tcp): (IpRepr, TcpRepr)| {
                        out = Some((
                            ip.clone(),
                            WireSeg {
                                arrival: Instant::ZERO,
                                order: 0,
                                to_b,
                                ip,
                                src_port: tcp.src_port,
                                dst_port: tcp.dst_port,
                                control: tcp.control,
                                seq_number: tcp.seq_number,
                                ack_number: tcp.ack_number,
                                window_len: tcp.window_len,
                                window_scale: tcp.window_scale,
                                max_seg_size: tcp.max_seg_size,
                                sack_permitted: tcp.sack_permitted,
                                sack_ranges: tcp.sack_ranges,
                                timestamp: tcp.timestamp,
                                payload: tcp.payload.to_vec(),
                            },
                        ));
                        Ok::<(), ()>(())
                    })
                    .unwrap();
                if std::env::var_os("HARNESS_TRACE").is_some() && order < 20 {
                    eprintln!(
                        "t={} post-dispatch {} state={:?} emitted={}",
                        now,
                        if a_side { "A" } else { "B" },
                        ep.socket.state(),
                        out.is_some(),
                    );
                }
                if let Some((_, mut seg)) = out {
                    emitted = true;
                    if seg.to_b {
                        wire_payload += seg.payload.len();
                    }
                    if !rng.chance(params.loss_per_mille) {
                        seg.arrival = now
                            + params.delay
                            + Duration::from_millis(rng.upto(params.jitter_ms + 1));
                        seg.order = order;
                        order += 1;
                        flights.push(seg);
                    }
                }
            }
            if !emitted {
                break;
            }
        }

        // Advance the clock to the next event: an arrival or a timer.
        let mut next = deadline_at;
        for f in &flights {
            if f.arrival < next {
                next = f.arrival;
            }
        }
        for ep in [&mut a, &mut b] {
            ep.cx.set_now(now);
            match ep.socket.poll_at(&mut ep.cx) {
                PollAt::Now => next = now,
                PollAt::Time(t) => {
                    if t < next {
                        next = t;
                    }
                }
                PollAt::Ingress => {}
            }
        }
        now = if next > now { next } else { now };

        // Deliver everything due, in arrival-then-emission order; the
        // jitter above is what makes that differ from send order.
        loop {
            let mut due: Option<usize> = None;
            for (i, f) in flights.iter().enumerate() {
                if f.arrival > now {
                    continue;
                }
                let better = match due {
                    None => true,
                    Some(j) => (f.arrival, f.order) < (flights[j].arrival, flights[j].order),
                };
                if better {
                    due = Some(i);
                }
            }
            let Some(i) = due else { break };
            let seg = flights.swap_remove(i);
            let ep = if seg.to_b { &mut b } else { &mut a };
            ep.cx.set_now(now);
            let repr = seg.repr();
            if std::env::var_os("HARNESS_TRACE").is_some() {
                eprintln!(
                    "t={} {} {:?} seq={} ack={:?} len={} accepts={}",
                    now,
                    if seg.to_b { "A->B" } else { "B->A" },
                    repr.control,
                    repr.seq_number,
                    repr.ack_number,
                    repr.payload.len(),
                    ep.socket.accepts(&mut ep.cx, &seg.ip, &repr),
                );
            }
            if ep.socket.accepts(&mut ep.cx, &seg.ip, &repr) {
                if let Some((rip, rtcp)) = ep.socket.process(&mut ep.cx, &seg.ip, &repr) {
                    let to_b = !seg.to_b;
                    if to_b {
                        wire_payload += rtcp.payload.len();
                    }
                    if !rng.chance(params.loss_per_mille) {
                        flights.push(WireSeg {
                            arrival: now
                                + params.delay
                                + Duration::from_millis(rng.upto(params.jitter_ms + 1)),
                            order: {
                                order += 1;
                                order - 1
                            },
                            to_b,
                            ip: rip,
                            src_port: rtcp.src_port,
                            dst_port: rtcp.dst_port,
                            control: rtcp.control,
                            seq_number: rtcp.seq_number,
                            ack_number: rtcp.ack_number,
                            window_len: rtcp.window_len,
                            window_scale: rtcp.window_scale,
                            max_seg_size: rtcp.max_seg_size,
                            sack_permitted: rtcp.sack_permitted,
                            sack_ranges: rtcp.sack_ranges,
                            timestamp: rtcp.timestamp,
                            payload: rtcp.payload.to_vec(),
                        });
                    }
                }
            }
        }
    }

    for (i, byte) in received.iter().enumerate() {
        assert_eq!(*byte, expected_byte(i), "corrupt delivery at offset {i}");
    }

    Stats {
        wire_payload,
        spurious: a.socket.rx_dsack_count,
        elapsed: now - Instant::ZERO,
    }
}

#[test]
fn clean_link_carries_exactly_the_data() {
    let stats = run_transfer(
        7,
        LinkParams {
            delay: Duration::from_millis(20),
            jitter_ms: 0,
            loss_per_mille: 0,
            min_rto: None,
        },
        64 * 1024,
        Duration::from_secs(60),
    );
    assert_eq!(stats.wire_payload, 64 * 1024, "clean link retransmitted");
    assert_eq!(stats.spurious, 0);
}

#[test]
fn two_percent_loss_recovers_across_seeds() {
    for seed in [1, 2, 3] {
        let stats = run_transfer(
            seed,
            LinkParams {
                delay: Duration::from_millis(20),
                jitter_ms: 0,
                loss_per_mille: 20,
                min_rto: None,
            },
            64 * 1024,
            Duration::from_secs(120),
        );
        // Recovery, not meltdown: bounded overhead over the unique bytes.
        assert!(
            stats.wire_payload < 64 * 1024 * 2,
            "seed {seed}: wire carried {} for 64 KiB",
            stats.wire_payload
        );
    }
}

#[test]
fn heavy_loss_with_reordering_still_completes() {
    for seed in [4, 5] {
        let stats = run_transfer(
            seed,
            LinkParams {
                delay: Duration::from_millis(20),
                jitter_ms: 15,
                loss_per_mille: 100,
                min_rto: None,
            },
            32 * 1024,
            Duration::from_secs(300),
        );
        assert!(
            stats.wire_payload < 32 * 1024 * 3,
            "seed {seed}: wire carried {} for 32 KiB",
            stats.wire_payload
        );
    }
}

/// The RTO-floor measurement matrix: not a regression test but the
/// instrument of the step 3 tuning round. Run it explicitly:
/// `cargo test -- --ignored rto_floor --nocapture`
#[test]
#[ignore = "measurement instrument; run explicitly with --ignored"]
fn rto_floor_matrix() {
    let total = 256 * 1024;
    eprintln!("floor_ms,delay_ms,loss_pm,seed,elapsed_ms,wire_payload,spurious");
    for floor_ms in [200u64, 100, 50] {
        for delay_ms in [5u64, 20, 100] {
            for loss_pm in [10u64, 50] {
                for seed in [11u64, 12, 13] {
                    let stats = run_transfer(
                        seed,
                        LinkParams {
                            delay: Duration::from_millis(delay_ms),
                            jitter_ms: 0,
                            loss_per_mille: loss_pm,
                            min_rto: Some(Duration::from_millis(floor_ms)),
                        },
                        total,
                        Duration::from_secs(600),
                    );
                    eprintln!(
                        "{},{},{},{},{},{},{}",
                        floor_ms,
                        delay_ms,
                        loss_pm,
                        seed,
                        stats.elapsed.total_millis(),
                        stats.wire_payload,
                        stats.spurious,
                    );
                }
            }
        }
    }
}

#[test]
fn pure_reordering_is_mostly_quiet() {
    let stats = run_transfer(
        6,
        LinkParams {
            delay: Duration::from_millis(20),
            jitter_ms: 8,
            loss_per_mille: 0,
            min_rto: None,
        },
        64 * 1024,
        Duration::from_secs(60),
    );
    // Nothing was lost; a reordering path should cost at most a few
    // spurious retransmissions while the reorder window adapts.
    assert!(
        stats.wire_payload <= 64 * 1024 + 16 * 1460,
        "reordering alone retransmitted {} extra",
        stats.wire_payload - 64 * 1024
    );
    let _ = stats.elapsed;
    let _ = stats.spurious;
}
