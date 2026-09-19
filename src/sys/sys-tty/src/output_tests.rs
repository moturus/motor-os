use super::*;

pub(super) fn run() {
    stderr_snapshot_follows_stdout_read();
    pending_batch_is_bounded();
    sequence_owner_can_continue();
    sequence_owner_outranks_waiting_stderr();
    message_wake_is_retained();
}

fn stderr_snapshot_follows_stdout_read() {
    for stderr_was_ready in [false, true] {
        let mut state = State::new();
        let mut reads = Vec::new();
        let mut stderr = stderr_was_ready.then(|| b"error tail\n".to_vec());
        state.fill_screens(None, |source| {
            reads.push(source);
            match source {
                Source::Stdout => {
                    // Simulate stderr becoming visible while stdout is read.
                    stderr.get_or_insert_with(|| b"error tail\n".to_vec());
                    Some(b"prompt".to_vec())
                }
                Source::Stderr => stderr.take(),
            }
        });
        assert_eq!(reads, [Source::Stdout, Source::Stderr]);
        let mut arbiter = Arbiter::new();
        let now = Instant::now();
        assert_eq!(
            arbiter.take_ready(&mut state, now).unwrap(),
            b"error tail\n"
        );
        assert_eq!(arbiter.take_ready(&mut state, now).unwrap(), b"prompt");
    }
}

fn pending_batch_is_bounded() {
    let mut state = State::new();
    let mut arbiter = Arbiter::new();
    let now = Instant::now();
    // Both streams always have more, and the writer takes one chunk per turn.
    // New stderr must not delay the saved stdout indefinitely.
    for _ in 0..16 {
        state.fill_screens(None, |source| {
            Some(vec![
                if source == Source::Stderr { b'e' } else { b'o' };
                2048
            ])
        });
        assert_eq!(state.screens.len(), 2);
        assert_eq!(
            arbiter.take_ready(&mut state, now).unwrap(),
            vec![b'e'; 2048]
        );
        state.fill_screens(None, |_| panic!("read past a pending batch"));
        assert_eq!(state.screens.len(), 1);
        assert_eq!(
            arbiter.take_ready(&mut state, now).unwrap(),
            vec![b'o'; 2048]
        );
        assert!(state.screens.is_empty());
    }
}

fn sequence_owner_can_continue() {
    for owner in [Source::Stdout, Source::Stderr] {
        for (prefix, suffix) in [
            (b"\x1b[".as_slice(), b"31m".as_slice()),
            (b"\xc3".as_slice(), b"\xa9".as_slice()),
        ] {
            let mut state = State::new();
            let mut arbiter = Arbiter::new();
            let now = Instant::now();
            state.push_screen(owner, prefix.to_vec());
            assert_eq!(arbiter.take_ready(&mut state, now).unwrap(), prefix);
            state.push_screen(owner.other(), b"waiting".to_vec());
            assert!(arbiter.take_ready(&mut state, now).is_none());
            state.fill_screens(arbiter.owner, |source| {
                assert_eq!(source, owner);
                Some(suffix.to_vec())
            });
            assert_eq!(state.screens.len(), 2);
            assert_eq!(arbiter.take_ready(&mut state, now).unwrap(), suffix);
            assert_eq!(arbiter.take_ready(&mut state, now).unwrap(), b"waiting");
        }
    }
}

/// The documented limit of the stderr-first rule: framing outranks it. When a
/// child leaves stdout inside a sequence, the shell's next stdout chunk counts
/// as that sequence's continuation and passes the child's waiting stderr.
fn sequence_owner_outranks_waiting_stderr() {
    let mut state = State::new();
    let mut arbiter = Arbiter::new();
    let now = Instant::now();
    state.push_screen(Source::Stdout, b"child left \xc3".to_vec());
    assert!(arbiter.take_ready(&mut state, now).is_some());
    state.push_screen(Source::Stderr, b"error\n".to_vec());
    assert!(arbiter.take_ready(&mut state, now).is_none());
    state.fill_screens(arbiter.owner, |source| {
        assert_eq!(source, Source::Stdout, "the stderr tail stays unread");
        Some(b"prompt".to_vec())
    });
    assert_eq!(arbiter.take_ready(&mut state, now).unwrap(), b"prompt");
    assert_eq!(arbiter.take_ready(&mut state, now).unwrap(), b"error\n");
}

/// The pipe self-test's child: fills its stderr pipe, then reports on stdout
/// how many bytes that took.
pub(super) fn child() {
    moto_rt::net::set_nonblocking(moto_rt::FD_STDERR, true).unwrap();
    let mut filled = 0;
    loop {
        match moto_rt::fs::write(moto_rt::FD_STDERR, &[b'e'; 256]) {
            Ok(written) => filled += written,
            Err(moto_rt::Error::NotReady) => break,
            Err(err) => panic!("filling stderr: {err:?}"),
        }
    }
    println!("{filled}");
}

pub(super) fn closed_pipes_keep_their_tail() {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--output-test-child")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    assert!(child.wait().unwrap().success());
    let output = Output::new();
    output.attach(child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let poll = output.shared.poll.as_raw_fd();
    let mut state = output.shared.state.lock().unwrap();
    let mut pipes = state.pipes.take().unwrap();
    state.fill_screens(None, |source| pipes.read(source, poll));
    let (source, tail) = state.take_next_screen().unwrap();
    assert_eq!(source, Source::Stderr);
    let (source, filled) = state.take_next_screen().unwrap();
    assert_eq!(source, Source::Stdout);
    // The stderr sample that follows a prompt is one read, so the ordering
    // rule needs that read to take everything a full pipe holds.
    let filled: usize = std::str::from_utf8(&filled)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_ne!(filled, 0);
    assert_eq!(tail, vec![b'e'; filled], "one read must empty a full pipe");
    state.fill_screens(None, |source| pipes.read(source, poll));
    assert!(pipes.closed());
    state.pipes = Some(pipes);
    state.writing = true;
    assert!(!state.drained(), "EOF is not UART completion");
    state.writing = false;
    assert!(state.drained());
}

fn message_wake_is_retained() {
    let output = Output::new();
    // A send between checking the state and parking must wake the poll too.
    output.send(Source::Stdout, b"message".to_vec());
    let mut events = [moto_rt::poll::Event::default(); 1];
    let deadline = moto_rt::time::Instant::now() + Duration::from_secs(1);
    assert_eq!(
        moto_rt::poll::wait(
            output.shared.poll.as_raw_fd(),
            events.as_mut_ptr(),
            events.len(),
            Some(deadline)
        )
        .unwrap(),
        1
    );
    assert_eq!(events[0].token, 0);
}
