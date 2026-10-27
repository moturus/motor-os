use super::*;
use crate::crypto_tests::{config, inner, remote, wire};
use boringtun::noise::TunnResult;
use mock_instant::MockClock;
use std::collections::VecDeque;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Wake, Waker};

#[derive(Default)]
struct Fixture {
    outer: VecDeque<(Vec<u8>, SocketAddr)>,
    inner: VecDeque<Vec<u8>>,
    sent: Vec<(Vec<u8>, SocketAddr)>,
    directions: Vec<bool>,
    flood: bool,
    blocked: bool,
    fatal: bool,
    send_waker: Option<Waker>,
}

impl Io for Fixture {
    type Error = ();

    fn receive_outer(
        &mut self,
        _: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<std::result::Result<(usize, SocketAddr), ()>> {
        if let Some((packet, address)) = self.outer.pop_front() {
            let length = packet.len().min(buffer.len());
            buffer[..length].copy_from_slice(&packet[..length]);
            self.directions.push(true);
            Poll::Ready(Ok((length, address)))
        } else if self.flood {
            self.directions.push(true);
            buffer[0] = 0;
            Poll::Ready(Ok((1, "192.0.2.2:51820".parse().unwrap())))
        } else {
            Poll::Pending
        }
    }

    fn receive_inner(
        &mut self,
        _: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<std::result::Result<usize, ()>> {
        if let Some(packet) = self.inner.pop_front() {
            buffer[..packet.len()].copy_from_slice(&packet);
            self.directions.push(false);
            Poll::Ready(Ok(packet.len()))
        } else if self.flood {
            self.directions.push(false);
            buffer[0] = 0;
            Poll::Ready(Ok(1))
        } else {
            Poll::Pending
        }
    }

    fn send_outer(
        &mut self,
        cx: &mut Context<'_>,
        packet: &[u8],
        address: SocketAddr,
    ) -> Poll<std::result::Result<(), ()>> {
        if self.fatal {
            Poll::Ready(Err(()))
        } else if self.blocked {
            self.send_waker = Some(cx.waker().clone());
            Poll::Pending
        } else {
            self.sent.push((packet.to_vec(), address));
            Poll::Ready(Ok(()))
        }
    }

    fn submit_inner(&mut self, _: &[u8]) -> bool {
        false
    }
}

#[derive(Default)]
struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn bounded_fair_batches_preserve_deadlines_under_flood() {
    MockClock::set_time(Duration::ZERO);
    let start = Instant::now();
    let mut scheduler = Scheduler::new(&config(None, None), start).unwrap();
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    let mut io = Fixture {
        flood: true,
        ..Default::default()
    };
    assert!(
        scheduler
            .poll(&mut cx, &mut io, start + Duration::from_millis(249))
            .is_pending()
    );
    assert_eq!(io.directions.len(), BATCH);
    for pair in io.directions.as_chunks::<2>().0 {
        assert_eq!(*pair, [true, false]);
    }
    assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
    assert_eq!(scheduler.deadline(), start + TICK);
    assert!(scheduler.poll(&mut cx, &mut io, start + TICK).is_pending());
    assert_eq!(scheduler.counters.timer_ticks, 1);
    assert_eq!(
        io.directions.len(),
        2 * BATCH - scheduler.crypto.peer_count()
    );
    assert_eq!(scheduler.deadline(), start + 2 * TICK);
    assert!(
        scheduler
            .poll(&mut cx, &mut io, start + Duration::from_millis(1010))
            .is_pending()
    );
    assert_eq!(scheduler.counters.timer_ticks, 2);
    assert_eq!(scheduler.deadline(), start + 5 * TICK);
    assert_eq!(scheduler.counters.batches, 3);
}

#[test]
fn backpressure_keeps_one_datagram_and_resumes_queued_plaintext() {
    MockClock::set_time(Duration::ZERO);
    let now = Instant::now();
    let source: SocketAddr = "192.0.2.2:51820".parse().unwrap();
    let mut scheduler = Scheduler::new(&config(Some(source), None), now).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    let payload = inner(false, 1, 2, 60);
    let mut io = Fixture {
        blocked: true,
        ..Default::default()
    };
    io.inner.extend([payload.clone(), payload.clone()]);
    assert!(scheduler.poll(&mut cx, &mut io, now).is_pending());
    assert_eq!(
        io.inner.len(),
        1,
        "TX advanced while its ciphertext was pending"
    );
    assert!(io.send_waker.take().is_some());
    io.blocked = false;
    assert!(scheduler.poll(&mut cx, &mut io, now).is_pending());
    assert!(io.inner.is_empty());
    assert_eq!(io.sent.len(), 1);
    let mut remote = remote(8);
    let mut scratch = [0; BUFFER_SIZE];
    let response = wire(remote.decapsulate(None, &io.sent.remove(0).0, &mut scratch));
    io.outer.push_back((response, source));
    io.blocked = true;
    assert!(scheduler.poll(&mut cx, &mut io, now).is_pending());
    assert!(scheduler.crypto.needs_flush(0));
    assert!(io.sent.is_empty());
    io.blocked = false;
    assert!(scheduler.poll(&mut cx, &mut io, now).is_pending());
    assert_eq!(
        io.sent.len(),
        3,
        "keepalive plus two queued plaintext packets"
    );
    assert!(matches!(
        remote.decapsulate(None, &io.sent[0].0, &mut scratch),
        TunnResult::Done
    ));
    for (packet, address) in &io.sent[1..] {
        assert_eq!(*address, source);
        match remote.decapsulate(None, packet, &mut scratch) {
            TunnResult::WriteToTunnelV4(bytes, _) => assert_eq!(bytes, payload),
            _ => panic!("queued packet was lost during backpressure"),
        }
    }
    assert!(!scheduler.crypto.needs_flush(0));
    assert!(scheduler.pending.used.is_none());
}

#[test]
fn blocked_output_does_not_stop_rx_timers_or_change_pending_destination() {
    MockClock::set_time(Duration::ZERO);
    let now = Instant::now();
    let original: SocketAddr = "192.0.2.2:51820".parse().unwrap();
    let moved: SocketAddr = "192.0.2.2:51821".parse().unwrap();
    let mut scheduler = Scheduler::new(&config(Some(original), None), now).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    let mut io = Fixture {
        blocked: true,
        ..Default::default()
    };
    io.inner.push_back(inner(false, 1, 2, 60));
    assert!(scheduler.poll(&mut cx, &mut io, now).is_pending());
    let mut scratch = [0; BUFFER_SIZE];
    let init = wire(remote(8).format_handshake_initiation(&mut scratch, false));
    io.outer.push_back((init, moved));
    io.flood = true;
    assert!(scheduler.poll(&mut cx, &mut io, now + TICK).is_pending());
    assert_eq!(scheduler.crypto.endpoint(0), Some(moved));
    assert_eq!(scheduler.pending.used.unwrap().1, original);
    assert_eq!(scheduler.counters.outer_dropped, 1);
    assert_eq!(scheduler.counters.timer_ticks, 1);
    assert!(io.outer.is_empty());
    io.fatal = true;
    assert_eq!(
        scheduler.poll(&mut cx, &mut io, now + TICK),
        Poll::Ready(Err(()))
    );
    assert!(scheduler.pending.used.is_none());
    assert!(io.sent.is_empty());
    assert_eq!(scheduler.counters.transport_failures, 1);
}
