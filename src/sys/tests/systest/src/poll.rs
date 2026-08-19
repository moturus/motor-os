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
    assert_eq!(
        moto_rt::net::set_nodelay(fd, true),
        Err(moto_rt::Error::NotConnected)
    );
    assert_eq!(moto_rt::net::nodelay(fd), Err(moto_rt::Error::NotConnected));

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
        n, 0,
        "deregistered source raised token {} bits 0x{:x}",
        events[0].token, events[0].events
    );

    // A new token retires the old one the same way, but the readiness it had
    // queued is readiness the caller has still not seen: it moves over.
    poll::set(retargeted, fd, 44, interests).unwrap();
    let deadline = moto_rt::time::Instant::now() + Duration::from_millis(500);
    let n = poll::wait(
        retargeted,
        events.as_mut_ptr(),
        events.len(),
        Some(deadline),
    )
    .unwrap();
    assert_eq!(n, 1, "reregistration lost the queued close");
    assert_eq!(
        events[0].token, 44,
        "close reported under the retired token"
    );
    assert_ne!(events[0].events & poll::POLL_READ_CLOSED, 0);

    moto_rt::fs::close(observer).unwrap();
    moto_rt::fs::close(retired).unwrap();
    moto_rt::fs::close(retargeted).unwrap();
    println!("-- test_deregister_retires_closed_events PASS");
}

/// Reregistering with the same token still fully replaces the interests.
/// Deregistration succeeds however it lands against the I/O thread's
/// delivery pass.
///
/// `Registry::del` retires the registration and then removes its source-side
/// half; a delivery pass running in that window sees the just-retired
/// registration and garbage-collects it from the source map first. `del`
/// used to report that lost cleanup race as `InvalidArgument` for a
/// deregistration that had succeeded. The window is real: sources deliver to
/// registries in id order, so a waiter on an earlier registry wakes while
/// the same pass still owes delivery to a later one -- exactly one FIN is
/// enough. The loop replays that shape; the plain single-shot version above
/// tripped about one debug run in two.
pub fn test_deregister_races_the_delivery_pass() {
    use std::os::fd::AsRawFd;

    for _ in 0..100 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        let fd = client.as_raw_fd();

        // The observer's registry id is lower than the victim's, so the
        // close's one delivery pass visits the observer -- and wakes this
        // thread -- before it reaches the victim's registration.
        let observer = poll::new().unwrap();
        let victim = poll::new().unwrap();
        let interests = poll::POLL_READABLE | poll::POLL_WRITABLE;
        poll::add(observer, fd, 1, interests).unwrap();
        poll::add(victim, fd, 2, interests).unwrap();

        drop(server);

        let deadline = moto_rt::time::Instant::now() + Duration::from_secs(10);
        let mut events = [poll::Event::default(); 4];
        let mut closed = 0;
        while closed & poll::POLL_READ_CLOSED == 0 {
            let n =
                poll::wait(observer, events.as_mut_ptr(), events.len(), Some(deadline)).unwrap();
            assert!(n >= 1, "no READ_CLOSED for a peer that closed");
            for event in &events[..n] {
                closed |= event.events;
            }
        }

        poll::del(victim, fd).unwrap();

        moto_rt::fs::close(observer).unwrap();
        moto_rt::fs::close(victim).unwrap();
    }
    println!("-- test_deregister_races_the_delivery_pass PASS");
}

pub fn test_reregister_same_token_replaces_interests() {
    use std::io::Write;
    use std::os::fd::AsRawFd;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    let fd = client.as_raw_fd();

    let observer = poll::new().unwrap();
    let target = poll::new().unwrap();
    poll::add(observer, fd, 51, poll::POLL_READABLE).unwrap();
    poll::add(target, fd, 52, poll::POLL_READABLE).unwrap();

    server.write_all(b"ready").unwrap();
    let deadline = moto_rt::time::Instant::now() + Duration::from_secs(10);
    let mut events = [poll::Event::default(); 4];
    let n = poll::wait(observer, events.as_mut_ptr(), events.len(), Some(deadline)).unwrap();
    assert!(n >= 1, "observer did not receive readable event");
    assert_ne!(events[0].events & poll::POLL_READABLE, 0);

    // poll_set synchronizes with the source delivery witnessed above. The
    // queued READABLE bit must be removed even though the token is unchanged.
    poll::set(target, fd, 52, poll::POLL_WRITABLE).unwrap();
    let deadline = moto_rt::time::Instant::now() + Duration::from_secs(10);
    let n = poll::wait(target, events.as_mut_ptr(), events.len(), Some(deadline)).unwrap();
    assert_eq!(n, 1, "reregistration did not report writable state");
    assert_eq!(events[0].token, 52);
    assert_ne!(events[0].events & poll::POLL_WRITABLE, 0);
    assert_eq!(
        events[0].events & poll::POLL_READABLE,
        0,
        "old readable interest survived reregistration"
    );

    moto_rt::fs::close(observer).unwrap();
    moto_rt::fs::close(target).unwrap();
    println!("-- test_reregister_same_token_replaces_interests PASS");
}

/// Concurrent add/del cannot leave only the source half registered.
pub fn test_concurrent_add_del_consistent() {
    const ROUNDS: u64 = 10_000;

    let registry = poll::new().unwrap();
    let source = poll::new().unwrap();
    let start = std::sync::Arc::new(std::sync::Barrier::new(3));
    let done = std::sync::Arc::new(std::sync::Barrier::new(3));
    let (add_tx, add_rx) = std::sync::mpsc::channel();
    let (del_tx, del_rx) = std::sync::mpsc::channel();

    let add_start = start.clone();
    let add_done = done.clone();
    let add_thread = std::thread::spawn(move || {
        for token in 1..=ROUNDS {
            add_start.wait();
            add_tx
                .send(poll::add(registry, source, token, poll::POLL_READABLE).is_ok())
                .unwrap();
            add_done.wait();
        }
    });

    let del_start = start.clone();
    let del_done = done.clone();
    let del_thread = std::thread::spawn(move || {
        for _ in 0..ROUNDS {
            del_start.wait();
            del_tx.send(poll::del(registry, source).is_ok()).unwrap();
            del_done.wait();
        }
    });

    for round in 1..=ROUNDS {
        start.wait();
        done.wait();
        assert!(add_rx.recv().unwrap(), "poll_add failed in round {round}");
        if del_rx.recv().unwrap() {
            assert!(
                poll::del(registry, source).is_err(),
                "poll_del left a registry entry in round {round}"
            );
        } else {
            poll::del(registry, source)
                .unwrap_or_else(|_| panic!("poll_add left an orphan in round {round}"));
        }
    }

    add_thread.join().unwrap();
    del_thread.join().unwrap();
    moto_rt::fs::close(registry).unwrap();
    moto_rt::fs::close(source).unwrap();
    println!("-- test_concurrent_add_del_consistent PASS");
}

/// An unmanaged source cannot leave queued close bits after deregistration.
pub fn test_deregister_retires_unmanaged_tombstone() {
    use std::os::fd::AsRawFd;

    let mut child = crate::subcommand::spawn();
    let stdout = child.std_child().stdout.take().unwrap();
    let fd = stdout.as_raw_fd();
    let registry = poll::new().unwrap();
    poll::add(registry, fd, 61, poll::POLL_READABLE).unwrap();
    poll::del(registry, fd).unwrap();

    child.do_exit(0);
    child.wait().unwrap();
    let deadline = moto_rt::time::Instant::now() + Duration::from_millis(500);
    let mut events = [poll::Event::default(); 2];
    let n = poll::wait(registry, events.as_mut_ptr(), events.len(), Some(deadline)).unwrap();
    assert_eq!(n, 0, "unmanaged source left an event after deregistration");

    moto_rt::fs::close(registry).unwrap();
    println!("-- test_deregister_retires_unmanaged_tombstone PASS");
}

/// Closing a descriptor retires what a registry still holds under its number.
///
/// The old implementation returned the number to the free list before its
/// source sweep. Queued events then belonged to whatever opened next, and
/// `poll::add` found the stale pollee and aborted the process over it.
pub fn test_close_without_deregister_retires_registration() {
    use std::io::Write;
    use std::os::fd::AsRawFd;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let observer = poll::new().unwrap();
    let registry = poll::new().unwrap();

    let first = std::net::TcpStream::connect(addr).unwrap();
    let (server_first, _) = listener.accept().unwrap();
    let fd = first.as_raw_fd();
    let interests = poll::POLL_READABLE | poll::POLL_WRITABLE;
    poll::add(observer, fd, 80, interests).unwrap();
    poll::add(registry, fd, 81, interests).unwrap();

    // Queue a READ_CLOSED under token 81. Draining the observer proves the
    // close reached both registries, so the bit is really there to be left
    // behind.
    drop(server_first);
    let deadline = moto_rt::time::Instant::now() + Duration::from_secs(10);
    let mut events = [poll::Event::default(); 4];
    let mut closed = 0;
    while closed & poll::POLL_READ_CLOSED == 0 {
        let n = poll::wait(observer, events.as_mut_ptr(), events.len(), Some(deadline)).unwrap();
        assert!(n >= 1, "no READ_CLOSED for a peer that closed");
        for event in &events[..n] {
            assert_eq!(event.token, 80);
            closed |= event.events;
        }
    }

    // Close without deregistering first, which mio permits.
    drop(first);
    poll::del(registry, fd).unwrap();

    // Take the number back. The free list hands out the most recently closed
    // number first, but holding on to the sockets that miss makes that an
    // optimization rather than something this test rests on.
    let mut spares = Vec::new();
    let mut reused = None;
    for _ in 0..16 {
        let stream = std::net::TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        if stream.as_raw_fd() == fd {
            reused = Some((stream, server));
            break;
        }
        spares.push((stream, server));
    }
    let Some((second, mut server_second)) = reused else {
        panic!("descriptor {fd} was never handed out again");
    };

    poll::add(registry, fd, 82, poll::POLL_READABLE).unwrap();
    server_second.write_all(b"ready").unwrap();

    let deadline = moto_rt::time::Instant::now() + Duration::from_secs(10);
    let n = poll::wait(registry, events.as_mut_ptr(), events.len(), Some(deadline)).unwrap();
    assert!(n >= 1, "the reused descriptor reported nothing");
    for event in &events[..n] {
        assert_eq!(
            event.token, 82,
            "the closed descriptor's registration was reported"
        );
    }

    drop(second);
    drop(spares);
    moto_rt::fs::close(observer).unwrap();
    moto_rt::fs::close(registry).unwrap();
    println!("-- test_close_without_deregister_retires_registration PASS");
}

/// A tombstone already on its way when a registration was retired must not be
/// reported under the registration that replaced it.
///
/// Remote close walks every registration of a closed source. A `poll::del`
/// plus `poll::add` landing during that delivery gives a registry a new token
/// while close bits are in flight for the old registration. Only the shared
/// registration identity can distinguish them.
///
/// The walk goes in registry-ID order, so the last registry is the one still
/// waiting for its tombstone once the others have been delivered. A thread
/// retires and re-registers it throughout under a token it has never used
/// before, which is why the round does not depend on hitting one instant: the
/// tombstone lands somewhere in that cycle naming a registration already gone.
/// Each pass then drains what the registration it just made could have
/// produced, and an event under any earlier token is a retired registration
/// reporting -- which only the registration ID rules out, the descriptor
/// number being the same throughout.
pub fn test_stale_tombstone_is_dropped_after_reregistration() {
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    const REGISTRIES: usize = 16;
    const ROUNDS: usize = 8;
    const OLD_TOKEN: u64 = 91;
    const FIRST_NEW_TOKEN: u64 = 92;

    for _ in 0..ROUNDS {
        let mut child = crate::subcommand::spawn();
        let stdout = child.std_child().stdout.take().unwrap();
        let fd = stdout.as_raw_fd();

        let registries: Vec<moto_rt::RtFd> =
            (0..REGISTRIES).map(|_| poll::new().unwrap()).collect();
        for registry in &registries {
            poll::add(*registry, fd, OLD_TOKEN, poll::POLL_READABLE).unwrap();
        }
        let last = *registries.last().unwrap();

        let reregistered = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let churn = std::thread::spawn({
            let reregistered = reregistered.clone();
            let stop = stop.clone();
            move || {
                let mut events = [poll::Event::default(); 4];
                let mut token = FIRST_NEW_TOKEN;
                loop {
                    // Read before the pass, so the pass that sees it still
                    // finishes and leaves a registration behind.
                    let stopping = stop.load(Ordering::Relaxed);
                    let _ = poll::del(last, fd);
                    token += 1;
                    poll::add(last, fd, token, poll::POLL_READABLE).unwrap();
                    reregistered.store(true, Ordering::Relaxed);
                    let now = moto_rt::time::Instant::now();
                    let n = poll::wait(last, events.as_mut_ptr(), events.len(), Some(now)).unwrap();
                    for event in &events[..n] {
                        assert_eq!(event.token, token, "a retired registration was reported");
                    }
                    if stopping {
                        return token;
                    }
                }
            }
        });

        while !reregistered.load(Ordering::Relaxed) {
            std::hint::spin_loop();
        }
        child.do_exit(0);
        child.wait().unwrap();

        // Draining every earlier registry walks the delivery to the one this
        // test is about: its tombstone is the next one out.
        let deadline = moto_rt::time::Instant::now() + Duration::from_secs(10);
        let mut events = [poll::Event::default(); 4];
        for registry in &registries[..REGISTRIES - 1] {
            let mut seen = 0;
            while seen & poll::POLL_READ_CLOSED == 0 {
                let n = poll::wait(*registry, events.as_mut_ptr(), events.len(), Some(deadline))
                    .unwrap();
                assert!(n >= 1, "no close event for an exited child");
                for event in &events[..n] {
                    seen |= event.events;
                }
            }
        }

        stop.store(true, Ordering::Relaxed);
        let token = churn.join().unwrap();

        // Whatever the churn's last pass did not see is still queued.
        let now = moto_rt::time::Instant::now();
        let n = poll::wait(last, events.as_mut_ptr(), events.len(), Some(now)).unwrap();
        for event in &events[..n] {
            assert_eq!(event.token, token, "a retired registration was reported");
        }

        for registry in registries {
            moto_rt::fs::close(registry).unwrap();
        }
    }
    println!("-- test_stale_tombstone_is_dropped_after_reregistration PASS");
}

/// Closing a descriptor must serialize with an add already in flight.
///
/// Keep an alias to the old source alive after closing its registered
/// descriptor. If close misses an add between its descriptor lookup and source
/// publication, waking that alias later reports the retired token after the
/// descriptor number has been reused.
pub fn test_add_races_source_close() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier};

    const ROUNDS: u64 = 2_000;

    let registry = poll::new().unwrap();
    let hammered = poll::new().unwrap();
    let start = Arc::new(Barrier::new(3));
    let done = Arc::new(Barrier::new(3));
    let (add_fd_tx, add_fd_rx) = std::sync::mpsc::channel();
    let (close_fd_tx, close_fd_rx) = std::sync::mpsc::channel();
    let (add_result_tx, add_result_rx) = std::sync::mpsc::channel();
    let (close_result_tx, close_result_rx) = std::sync::mpsc::channel();

    // Keep ops contended so the old lookup-before-lock ordering has a wide
    // window in which close can detach and close the source.
    let stop = Arc::new(AtomicBool::new(false));
    let hammer = std::thread::spawn({
        let stop = stop.clone();
        move || {
            while !stop.load(Ordering::Relaxed) {
                poll::add(registry, hammered, u64::MAX, poll::POLL_READABLE).unwrap();
                poll::del(registry, hammered).unwrap();
            }
        }
    });

    let add_thread = std::thread::spawn({
        let start = start.clone();
        let done = done.clone();
        move || {
            for token in 1..=ROUNDS {
                let source = add_fd_rx.recv().unwrap();
                start.wait();
                add_result_tx
                    .send(poll::add(registry, source, token, poll::POLL_READABLE))
                    .unwrap();
                done.wait();
            }
        }
    });

    let close_thread = std::thread::spawn({
        let start = start.clone();
        let done = done.clone();
        move || {
            for _ in 0..ROUNDS {
                let source = close_fd_rx.recv().unwrap();
                start.wait();
                close_result_tx.send(moto_rt::fs::close(source)).unwrap();
                done.wait();
            }
        }
    });

    for token in 1..=ROUNDS {
        let source = poll::new().unwrap();
        let alias = moto_rt::fs::duplicate(source).unwrap();
        add_fd_tx.send(source).unwrap();
        close_fd_tx.send(source).unwrap();

        start.wait();
        // This edge may land while the registration is still Adding. Whether
        // add succeeds or loses to close, the old token must be unobservable
        // after close returns.
        poll::wake(alias).unwrap();
        close_result_rx.recv().unwrap().unwrap();

        // The fd becomes reusable only after the old source sweep. The delayed
        // add and this replacement add can now resolve the replacement object
        // in either order, but they must leave one consistent registration.
        let replacement = poll::new().unwrap();
        assert_eq!(replacement, source, "closed descriptor was not reused");
        let replacement_token = ROUNDS + token;
        let replacement_result = poll::add(
            registry,
            replacement,
            replacement_token,
            poll::POLL_READABLE,
        );

        done.wait();
        let delayed_result = add_result_rx.recv().unwrap();
        if let Err(err) = replacement_result {
            assert_eq!(
                err,
                moto_rt::E_INVALID_ARGUMENT.into(),
                "unexpected replacement add error"
            );
            assert!(
                delayed_result.is_ok(),
                "both adds failed: delayed={delayed_result:?}, replacement={err:?}"
            );

            // The delayed call registered the replacement under its old token.
            // Normalize the winner before checking that no retired event leaks.
            poll::del(registry, replacement).unwrap();
            poll::add(
                registry,
                replacement,
                replacement_token,
                poll::POLL_READABLE,
            )
            .unwrap();
        } else if let Err(err) = delayed_result {
            assert!(
                err == moto_rt::E_BAD_HANDLE.into() || err == moto_rt::E_INVALID_ARGUMENT.into(),
                "unexpected delayed add error: {err:?}"
            );
        }

        poll::wake(alias).unwrap();
        poll::wake(replacement).unwrap();
        let mut events = [poll::Event::default(); 4];
        let now = moto_rt::time::Instant::now();
        let n = poll::wait(registry, events.as_mut_ptr(), events.len(), Some(now)).unwrap();
        assert_eq!(n, 1, "the closed source left a registration behind");
        assert_eq!(events[0].token, replacement_token);

        poll::del(registry, replacement).unwrap();
        moto_rt::fs::close(replacement).unwrap();
        moto_rt::fs::close(alias).unwrap();
    }

    add_thread.join().unwrap();
    close_thread.join().unwrap();
    stop.store(true, Ordering::Relaxed);
    hammer.join().unwrap();
    moto_rt::fs::close(hammered).unwrap();
    moto_rt::fs::close(registry).unwrap();
    println!("-- test_add_races_source_close PASS");
}

/// Registration changes and a source closing on the I/O runtime must not
/// deadlock.
///
/// A registry's own locks and the registry map were taken in one order by
/// `poll::add`/`poll::del` and the other by the tombstone an expiring source
/// leaves, which is an inversion two spin locks cannot detect: both sides just
/// spin. This test wedges the process rather than failing if it comes back.
pub fn test_registration_races_source_close() {
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    const ROUNDS: usize = 32;

    let registry = poll::new().unwrap();
    // Something to add and remove that is not what the children close, so the
    // two threads meet on the registry rather than on one registration.
    let hammered = poll::new().unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let hammer = std::thread::spawn({
        let stop = stop.clone();
        move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = poll::add(registry, hammered, 101, poll::POLL_READABLE);
                let _ = poll::del(registry, hammered);
            }
        }
    });

    for _ in 0..ROUNDS {
        let mut child = crate::subcommand::spawn();
        let stdout = child.std_child().stdout.take().unwrap();
        let fd = stdout.as_raw_fd();
        poll::add(registry, fd, 102, poll::POLL_READABLE).unwrap();
        // The exit leaves a tombstone at this registry from the I/O runtime,
        // while the thread above is inside a registration change on it.
        child.do_exit(0);
        child.wait().unwrap();
        let _ = poll::del(registry, fd);
        drop(stdout);
    }

    stop.store(true, Ordering::Relaxed);
    hammer.join().unwrap();
    moto_rt::fs::close(hammered).unwrap();
    moto_rt::fs::close(registry).unwrap();
    println!("-- test_registration_races_source_close PASS");
}

/// Child exit and DEL race on the production unmanaged-close path. Once DEL
/// returns, no close bit for that registration may still become observable.
pub fn test_tombstone_vs_del_hammer() {
    use std::os::fd::AsRawFd;
    use std::sync::{Arc, Barrier};

    const ROUNDS: u64 = 32;

    let registry = poll::new().unwrap();
    let mut events = [poll::Event::default(); 2];
    for round in 0..ROUNDS {
        let mut child = crate::subcommand::spawn();
        let stdout = child.std_child().stdout.take().unwrap();
        let fd = stdout.as_raw_fd();
        poll::add(registry, fd, 200 + round, poll::POLL_READABLE).unwrap();

        let start = Arc::new(Barrier::new(2));
        let del_thread = std::thread::spawn({
            let start = start.clone();
            move || {
                start.wait();
                poll::del(registry, fd)
            }
        });
        start.wait();
        child.do_exit(0);
        child.wait().unwrap();
        del_thread.join().unwrap().unwrap();

        let now = moto_rt::time::Instant::now();
        let n = poll::wait(registry, events.as_mut_ptr(), events.len(), Some(now)).unwrap();
        assert_eq!(n, 0, "round {round} delivered close bits after DEL");
        drop(stdout);
    }

    moto_rt::fs::close(registry).unwrap();
    println!("-- test_tombstone_vs_del_hammer PASS");
}

/// Remote close may queue close bits, but a concurrent local close without
/// DEL must retire them before the descriptor number is released.
pub fn test_remote_close_races_local_close() {
    use std::os::fd::AsRawFd;
    use std::sync::{Arc, Barrier};

    const ROUNDS: u64 = 32;

    let registry = poll::new().unwrap();
    let mut events = [poll::Event::default(); 2];
    for round in 0..ROUNDS {
        let mut child = crate::subcommand::spawn();
        let stdout = child.std_child().stdout.take().unwrap();
        let fd = stdout.as_raw_fd();
        poll::add(registry, fd, 300 + round, poll::POLL_READABLE).unwrap();

        let start = Arc::new(Barrier::new(2));
        let close_thread = std::thread::spawn({
            let start = start.clone();
            move || {
                start.wait();
                drop(stdout);
            }
        });
        start.wait();
        child.do_exit(0);
        child.wait().unwrap();
        close_thread.join().unwrap();

        let now = moto_rt::time::Instant::now();
        let n = poll::wait(registry, events.as_mut_ptr(), events.len(), Some(now)).unwrap();
        assert_eq!(n, 0, "round {round} retained close bits after local close");
    }

    moto_rt::fs::close(registry).unwrap();
    println!("-- test_remote_close_races_local_close PASS");
}

/// Reusing a just-closed fd through another descriptor for the same source is
/// the case object-pointer checks alone cannot distinguish. Close must finish
/// its fd-keyed sweep before the number can be duplicated back into service.
pub fn test_same_source_dup_reuse() {
    let registry = poll::new().unwrap();
    let source = poll::new().unwrap();
    let alias = moto_rt::fs::duplicate(source).unwrap();

    poll::add(registry, source, 401, poll::POLL_READABLE).unwrap();
    poll::wake(source).unwrap();
    moto_rt::fs::close(source).unwrap();

    let replacement = moto_rt::fs::duplicate(alias).unwrap();
    assert_eq!(replacement, source, "closed descriptor was not reused");
    poll::add(registry, replacement, 402, poll::POLL_READABLE).unwrap();
    poll::wake(alias).unwrap();

    let deadline = moto_rt::time::Instant::now() + Duration::from_secs(10);
    let mut events = [poll::Event::default(); 2];
    let n = poll::wait(registry, events.as_mut_ptr(), events.len(), Some(deadline)).unwrap();
    assert_eq!(n, 1);
    assert_eq!(
        events[0].token, 402,
        "old same-source registration survived"
    );

    poll::del(registry, replacement).unwrap();
    moto_rt::fs::close(replacement).unwrap();
    moto_rt::fs::close(alias).unwrap();
    moto_rt::fs::close(registry).unwrap();
    println!("-- test_same_source_dup_reuse PASS");
}

/// Retiring a ready registration removes its queue node. This churns the path
/// without ever collecting, then verifies that a live event is still the only
/// event returned.
pub fn test_ready_close_churn() {
    const ROUNDS: usize = 10_000;

    let registry = poll::new().unwrap();
    for token in 0..ROUNDS {
        let source = poll::new().unwrap();
        poll::add(registry, source, token as u64, poll::POLL_READABLE).unwrap();
        poll::wake(source).unwrap();
        moto_rt::fs::close(source).unwrap();
    }

    let witness = poll::new().unwrap();
    poll::add(registry, witness, u64::MAX, poll::POLL_READABLE).unwrap();
    poll::wake(witness).unwrap();
    let deadline = moto_rt::time::Instant::now() + Duration::from_secs(10);
    let mut events = [poll::Event::default(); 2];
    let n = poll::wait(registry, events.as_mut_ptr(), events.len(), Some(deadline)).unwrap();
    assert_eq!(n, 1);
    assert_eq!(events[0].token, u64::MAX);

    poll::del(registry, witness).unwrap();
    moto_rt::fs::close(witness).unwrap();
    moto_rt::fs::close(registry).unwrap();
    println!("-- test_ready_close_churn PASS");
}

pub fn run_all_tests() {
    test_multi_poller();
    test_refused_connect_reports_writable();
    test_deregister_retires_closed_events();
    test_deregister_races_the_delivery_pass();
    test_reregister_same_token_replaces_interests();
    test_concurrent_add_del_consistent();
    test_deregister_retires_unmanaged_tombstone();
    test_close_without_deregister_retires_registration();
    test_stale_tombstone_is_dropped_after_reregistration();
    test_add_races_source_close();
    test_registration_races_source_close();
    test_tombstone_vs_del_hammer();
    test_remote_close_races_local_close();
    test_same_source_dup_reuse();
    test_ready_close_churn();
}
