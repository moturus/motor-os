//! Poll registry delivery tests (vdso rewrite, stage B).

use moto_rt::poll;
use std::time::Duration;

fn poll_once(
    registry: moto_rt::RtFd,
    deadline: moto_rt::time::Instant,
    started: std::time::Instant,
) -> (Vec<u64>, Duration) {
    let mut events = [poll::Event::default(); 4];
    let n = poll::wait(registry, events.as_mut_ptr(), events.len(), Some(deadline)).unwrap();
    (
        events[..n].iter().map(|event| event.token).collect(),
        started.elapsed(),
    )
}

/// Two threads wait on one registry; two mio-Waker-style nested
/// registries raise one event each. The old single-slot wake protocol
/// let the second poller clobber the first one's wake slot, leaving it
/// asleep with a pending event until the deadline; with the overflow
/// waiter list every event must arrive promptly.
pub fn test_multi_poller() {
    let registry = poll::new().unwrap();
    let waker1 = poll::new().unwrap();
    let waker2 = poll::new().unwrap();
    poll::add(registry, waker1, 1, poll::POLL_READABLE).unwrap();
    poll::add(registry, waker2, 2, poll::POLL_READABLE).unwrap();

    let started = std::time::Instant::now();
    let deadline = moto_rt::time::Instant::now() + Duration::from_secs(10);

    let t1 = std::thread::spawn(move || poll_once(registry, deadline, started));
    let t2 = std::thread::spawn(move || poll_once(registry, deadline, started));

    std::thread::sleep(Duration::from_millis(50));
    poll::wake(waker1).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    poll::wake(waker2).unwrap();

    let (tokens_1, elapsed_1) = t1.join().unwrap();
    let (tokens_2, elapsed_2) = t2.join().unwrap();

    // Which poller gets which event is scheduling-dependent; what must
    // hold is that both events arrive, and that no event waits for the
    // poll deadline.
    let mut tokens = tokens_1.clone();
    tokens.extend(&tokens_2);
    tokens.sort();
    assert_eq!(tokens, vec![1, 2], "multi-poller lost an event");
    for (tokens, elapsed) in [(tokens_1, elapsed_1), (tokens_2, elapsed_2)] {
        assert!(
            tokens.is_empty() || elapsed < Duration::from_secs(5),
            "multi-poller event delivery took {elapsed:?}"
        );
    }

    println!("-- test_multi_poller PASS");
}

/// A refused nonblocking connect must poll as WRITABLE: Linux epoll
/// reports a failed connect as EPOLLOUT|EPOLLERR|EPOLLHUP, and mio's
/// `is_writable` requires the OUT bit, so an event carrying only the
/// CLOSED/ERROR bits strands a connect poller (the mio-test
/// `test_register_during_poll` under-load finding, 2026-08-08).
/// Registration usually lands before the error response, exercising the
/// async completion path; if the response wins the race, the
/// registration-time synthesis reports the same bits -- WRITABLE must
/// arrive either way.
pub fn test_refused_connect_reports_writable() {
    use std::net::SocketAddr;

    // Nothing listens on port 1; sys-io answers the SYN with RST.
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let fd = moto_rt::net::tcp_connect(&addr.into(), Duration::MAX, true).unwrap();

    let registry = poll::new().unwrap();
    poll::add(registry, fd, 7, poll::POLL_WRITABLE).unwrap();

    let deadline = moto_rt::time::Instant::now() + Duration::from_secs(10);
    let mut events = [poll::Event::default(); 4];
    let n = poll::wait(registry, events.as_mut_ptr(), events.len(), Some(deadline)).unwrap();
    assert!(n >= 1, "no event for a refused connect");
    assert_eq!(events[0].token, 7);
    assert_ne!(
        events[0].events & poll::POLL_WRITABLE,
        0,
        "refused-connect event lacks WRITABLE: 0x{:x}",
        events[0].events
    );

    moto_rt::fs::close(registry).unwrap();
    moto_rt::fs::close(fd).unwrap();
    println!("-- test_refused_connect_reports_writable PASS");
}

pub fn run_all_tests() {
    test_multi_poller();
    test_refused_connect_reports_writable();
}
