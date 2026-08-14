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

/// A deregistered source raises no more events, including the CLOSED and
/// ERROR bits nobody registers for.
///
/// mio's users take the token of an event as an authority on the source
/// still existing -- tokio's io driver dereferences it as a pointer to a
/// `ScheduledIo` it frees once the source is deregistered. Delivery ors
/// `POLL_READ_CLOSED | POLL_WRITE_CLOSED | POLL_ERROR` into the registered
/// interests, so a peer that closes leaves those bits queued under the
/// token; `poll::del` used to clear only the registered interests and left
/// them behind. The next poller was handed a token whose owner was gone,
/// which wedged russhd's whole runtime inside the freed object's lock
/// (docs/2026-08-12-stress-soak.md). A reregistration retires the old token
/// the same way, except that its queued readiness moves to the new one.
pub fn test_deregister_retires_closed_events() {
    use std::os::fd::AsRawFd;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let client = std::net::TcpStream::connect(addr).unwrap();
    let (server, _) = listener.accept().unwrap();
    let fd = client.as_raw_fd();

    // Three registries see one delivery pass: draining `observer` proves the
    // close reached the other two, so what follows cannot pass by never
    // having queued the event at all.
    let observer = poll::new().unwrap();
    let retired = poll::new().unwrap();
    let retargeted = poll::new().unwrap();
    let interests = poll::POLL_READABLE | poll::POLL_WRITABLE;
    poll::add(observer, fd, 11, interests).unwrap();
    poll::add(retired, fd, 22, interests).unwrap();
    poll::add(retargeted, fd, 33, interests).unwrap();

    // Nothing was sent, so the peer's FIN raises READ_CLOSED on its own:
    // the queued event carries only bits outside `interests`, which is
    // exactly what a clear limited to `interests` cannot retire.
    drop(server);

    let deadline = moto_rt::time::Instant::now() + Duration::from_secs(10);
    let mut events = [poll::Event::default(); 4];
    let mut closed = 0;
    while closed & poll::POLL_READ_CLOSED == 0 {
        let n = poll::wait(observer, events.as_mut_ptr(), events.len(), Some(deadline)).unwrap();
        assert!(n >= 1, "no READ_CLOSED for a peer that closed");
        for event in &events[..n] {
            assert_eq!(event.token, 11);
            closed |= event.events;
        }
    }

    poll::del(retired, fd).unwrap();

    let deadline = moto_rt::time::Instant::now() + Duration::from_millis(500);
    let n = poll::wait(retired, events.as_mut_ptr(), events.len(), Some(deadline)).unwrap();
    assert_eq!(
        n,
        0,
        "deregistered source raised token {} bits 0x{:x}",
        events[0].token,
        events[0].events
    );

    // A new token retires the old one the same way, but the readiness it had
    // queued is readiness the caller has still not seen: it moves over.
    poll::set(retargeted, fd, 44, interests).unwrap();
    let deadline = moto_rt::time::Instant::now() + Duration::from_millis(500);
    let n = poll::wait(retargeted, events.as_mut_ptr(), events.len(), Some(deadline)).unwrap();
    assert_eq!(n, 1, "reregistration lost the queued close");
    assert_eq!(events[0].token, 44, "close reported under the retired token");
    assert_ne!(events[0].events & poll::POLL_READ_CLOSED, 0);

    moto_rt::fs::close(observer).unwrap();
    moto_rt::fs::close(retired).unwrap();
    moto_rt::fs::close(retargeted).unwrap();
    println!("-- test_deregister_retires_closed_events PASS");
}

pub fn run_all_tests() {
    test_multi_poller();
    test_refused_connect_reports_writable();
    test_deregister_retires_closed_events();
}
