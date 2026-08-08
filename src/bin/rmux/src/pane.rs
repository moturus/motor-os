//! A pane: one child process, on a terminal rmux provides.
//!
//! What a terminal *is* differs completely between the two platforms — pipes
//! plus an environment variable on Motor, a real pty on the host (details.md
//! §3.1) — and none of that difference is here. `sys::spawn_pane` hands back a
//! `PaneIo`, and everything below pumps bytes through it without knowing which
//! it got. That is the whole point of the seam, and the reason this module has
//! no `cfg` in it.
//!
//! One reader thread per output stream, all funnelling into the caller's
//! channel (§4.5), plus a reaper that joins them and then says the pane has
//! drained. Draining comes *first*, because a dead child's pipes may still hold
//! its last output and closing a pane before reading it loses it — which for a
//! short command is all of it. That is russhd's discipline
//! (`local_session.rs:170-181`), in a second place.
//!
//! The **child stays here**, not in the reaper, which is what makes
//! [`Pane::kill`] possible: on Motor the only thing one process may do to
//! another is terminate it, and that is `Child::kill` on a handle somebody has
//! to be holding (§3.6). The cost is that the exit status is learned when the
//! pipes empty rather than when the child dies; a grandchild holding them open
//! delays both, and delayed either way.
//!
//! Panes are keyed by [`PaneId`] from rmux's own counter, never by pid: Motor
//! has no pid to key on here, since `Child::id()` returns 0 and
//! `std::process::id()` panics (§3.6).
//!
//! **Writing has a thread of its own too**, and the platforms want it for
//! opposite reasons. A pane's input on Motor is a 2 KiB ring that blocks its
//! writer once it is full (§4.5), so a paste (§7.6) into a program that is not
//! reading would stop the event loop — the one thread that must never stop. A
//! keystroke never comes close; a paste is exactly the case §4.5 says will.
//! The host does not block at all: measured here, a megabyte written at a
//! `sleep` came back `Ok(())` at once, because a pty *discards* what will not
//! fit in its input queue. So the channel below is what keeps Motor's event
//! loop moving, and the host's large pastes are lossy either way — a
//! divergence to record rather than something this can fix.
//!
//! A pane also owns the emulator its child writes to — a [`Parser`] and a
//! [`Grid`] — but it is *fed* from the event loop, never from a pump thread.
//! The pumps must never be stalled behind anything (§4.5): a pane blasting
//! output fills a 2 KiB pipe and blocks in `write`, so their only job is to get
//! bytes off the pipe and into the queue. Interpreting them, and painting what
//! they mean, happens once per drain (§6.4).

use std::io::Read;
use std::io::Write;
use std::process::Child;
use std::process::Command;

use crate::ansi::Parser;
use crate::grid::Grid;
use crate::server::Event;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::mpsc::Sender;
use std::thread::JoinHandle;

/// A pane's identity, allocated from rmux's own counter (§3.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PaneId(u64);

impl PaneId {
    /// The next identity nobody has had.
    ///
    /// Public because the split tree is keyed by these and holds no panes
    /// (`layout`), so its tests need identities and no processes.
    pub fn next() -> PaneId {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        PaneId(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

impl std::fmt::Display for PaneId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "%{}", self.0)
    }
}

/// One pane, and the child living in it.
pub struct Pane {
    id: PaneId,
    /// The way to the writer thread, and `None` once a pipe-backed pane's input
    /// has been closed — dropping this is what closes the pipe, once whatever
    /// was queued has gone out. A pty-backed pane keeps its handle and sends an
    /// EOF byte instead (`sys::END_OF_INPUT`).
    input: Option<Sender<Vec<u8>>>,
    parser: Parser,
    grid: Grid,
    /// How to tell the child's terminal it has changed size, where the platform
    /// has a way to say so (`sys::TellSize`).
    tell_size: crate::sys::TellSize,
    child: Child,
    /// Kept so [`Pane::join`] can wait for it. An `Option` because [`Drop`] and
    /// a method that consumes `self` cannot both move it — and `Drop` must not
    /// wait for this thread at all: a grandchild holding the pane's pipes open
    /// keeps the pumps reading, and waiting on that would hang the event loop.
    reaper: Option<JoinHandle<()>>,
    /// Whether the child has been collected already.
    ///
    /// **A pane's child is killed at most once, and waited for at most once.**
    /// The hazard that was measured is the kill: `SysCpu::OP_KILL` aimed at a
    /// process that has already been waited for does not return on Motor, and
    /// the server sat in it mid-teardown until the whole test suite stalled
    /// behind it. `mdbg` is what said so — the main thread in syscall `1:4`,
    /// which is `OP_KILL`, while the pane's shell showed no live threads at all.
    /// The wait is guarded for symmetry and the same suspicion; on the host a
    /// second one is merely redundant, since std hands back the status it cached.
    collected: bool,
}

impl Pane {
    /// Spawn `cmd` in a pane `size` big, and start pumping its output.
    ///
    /// `size` is `(rows, cols)`, and it is a decision rather than a question:
    /// the child is told the size of its *pane*, by `TIOCSWINSZ` on the host
    /// and `$COLUMNS`/`$LINES` on Motor (§3.2), and the emulator behind it is
    /// that size too. Which is also what makes `ESC[6n` answerable.
    pub fn spawn(cmd: Command, size: (u16, u16), events: Sender<Event>) -> std::io::Result<Pane> {
        let id = PaneId::next();
        let io = crate::sys::spawn_pane(cmd, size)?;
        let pumps = io
            .output
            .into_iter()
            .map(|stream| pump(id, stream, events.clone()))
            .collect();

        let input = feed_child(io.input);
        let reaper = std::thread::spawn(move || drain(id, pumps, events));
        // Where the platform has no line discipline, the pane is it (§3.3).
        let mut grid = Grid::new(size.0 as usize, size.1 as usize);
        grid.set_newline_mode(crate::sys::PANE_NEWLINE_MODE);
        Ok(Pane {
            id,
            input: Some(input),
            parser: Parser::new(),
            grid,
            tell_size: io.tell_size,
            child: io.child,
            reaper: Some(reaper),
            collected: false,
        })
    }

    pub fn id(&self) -> PaneId {
        self.id
    }

    /// How much of this pane's output is kept once it scrolls off (§7.5).
    pub fn set_history_limit(&mut self, limit: usize) {
        self.grid.set_history_limit(limit);
    }

    /// What this pane's child has painted.
    pub fn grid(&self) -> &Grid {
        &self.grid
    }

    /// Resize this pane's screen, and its child's terminal with it.
    ///
    /// A split halves a pane, so this is not only a console resize any more: it
    /// runs whenever the layout moves (`window`). What the child is told depends
    /// on the platform — a `TIOCSWINSZ` and a `SIGWINCH` on the host, nothing at
    /// all on Motor, where it finds out at its next `ESC[6n` instead
    /// (`sys::TellSize`, §3.2).
    ///
    /// **Nothing is written into the child's stdin unless the child asked for
    /// it**, and that is a rule rather than an omission (§3.2): a pane's stdin
    /// carries what the user typed, and rmux answers a program only when that
    /// program asked. Mode 2048 is how a program asks — once, standing until it
    /// says otherwise — so a subscriber is told here and everyone else finds out
    /// at their next probe or prompt.
    ///
    /// **Only when the size really changed**, which is what the answer says.
    /// Every split, kill and zoom refits every pane in the window, so a pane
    /// being handed the size it already has is the common case — and telling its
    /// child would be a `SIGWINCH` for nothing, repeatedly, at a shell that
    /// redraws its prompt whenever it gets one.
    pub fn resize(&mut self, size: (u16, u16)) -> bool {
        let (rows, cols) = (size.0.max(1) as usize, size.1.max(1) as usize);
        if (self.grid.rows(), self.grid.cols()) == (rows, cols) {
            return false;
        }
        self.grid.resize(rows, cols);
        (self.tell_size)(size);
        // After the grid, so the report is the size the child would now measure
        // for itself rather than the one it is replacing.
        if let Some(report) = self.grid.resize_report() {
            let _ = self.write(&report.bytes());
        }
        true
    }

    /// Interpret `bytes` the child wrote, and answer what they ask for.
    ///
    /// A `ESC[6n` is answered into the child's own **stdin** (§3.2), never onto
    /// rmux's console — the easy mistake to get backwards (§5.3), and the whole
    /// reason rush learns its pane's width and red its pane's geometry.
    pub fn feed(&mut self, bytes: &[u8]) {
        let mut replies = Vec::new();
        let grid = &mut self.grid;
        self.parser.feed(bytes, &mut |action| {
            if let Some(reply) = grid.apply(action) {
                replies.push(reply);
            }
        });
        for reply in replies {
            let _ = self.write(&reply.bytes());
        }
    }

    /// Send bytes to the child, as if typed at its terminal.
    ///
    /// **Queued, not written**: this hands the bytes to the pane's writer
    /// thread and returns, so a paste into a program that is not reading waits
    /// there rather than in the event loop (see the module docs). What comes
    /// back is whether there is still a child to write to, not whether the
    /// child took the bytes — nothing here could wait for that.
    pub fn write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match self.input.as_mut() {
            Some(input) => input
                .send(bytes.to_vec())
                .map_err(|_| std::io::ErrorKind::BrokenPipe.into()),
            None => Err(std::io::ErrorKind::BrokenPipe.into()),
        }
    }

    /// Tell the child there is no more input; a shell reading a script exits.
    ///
    /// Two platforms, two meanings, and the difference is real rather than
    /// cosmetic: a pipe is closed, a pty is sent the EOF character it would
    /// have got from a user pressing `^D` (`sys::END_OF_INPUT`).
    pub fn end_input(&mut self) {
        match crate::sys::END_OF_INPUT {
            Some(byte) => {
                let _ = self.write(&[byte]);
            }
            None => self.input = None,
        }
    }

    /// Collect the child's status, now that its output has drained.
    ///
    /// Called when the pane reports itself drained, at which point the child is
    /// already gone and this does not block.
    pub fn reap(&mut self) -> Option<i32> {
        let status = self.child.wait().ok();
        self.collected = true;
        status.and_then(|status| status.code())
    }

    /// Whether the child still has to be collected — see `collected`.
    #[cfg(test)]
    fn owes_a_wait(&self) -> bool {
        !self.collected
    }

    /// Terminate the child, unconditionally. Says whether there was one to kill.
    ///
    /// The only thing one process may do to another on Motor (§3.6): there are
    /// no signals, so nothing can be caught, ignored or negotiated. Its input
    /// is closed too, for the sake of anything downstream of it that is waiting
    /// on that rather than on the process.
    pub fn kill(&mut self) -> bool {
        self.input = None;
        // Nothing to kill once the child has been collected, and asking anyway is
        // not harmless: `SysCpu::OP_KILL` aimed at a process that has already
        // been waited for does not return on Motor, and the server sits in it
        // with the session half-ended. Found with `mdbg`, which put the main
        // thread in that syscall (`1:4`) while the pane's shell showed no live
        // threads at all.
        if self.collected {
            return false;
        }
        let _ = self.child.kill();
        true
    }

    /// Wait for the pane to finish shutting down.
    pub fn join(mut self) {
        if !self.collected {
            let _ = self.child.wait();
            self.collected = true;
        }
        if let Some(reaper) = self.reaper.take() {
            let _ = reaper.join();
        }
    }
}

impl Drop for Pane {
    /// Terminate the child, and **collect** it.
    ///
    /// Killing is not collecting. On the host an uncollected child is a zombie
    /// for as long as the server runs, which the test below pins. On Motor the
    /// stakes are higher in principle: process statistics live in a tree where a
    /// child's entry holds a *strong* reference to its parent's
    /// (`kernel/src/xray/stats.rs:376`), so an entry that is never freed keeps
    /// every ancestor in the table with it — a pane's shell would pin the
    /// server, the client that started it, and the login shell above that.
    /// Whether a missing `wait` can actually produce that there was *not*
    /// reproducible: Motor frees a dropped child's entry without one in every
    /// case that could be constructed. The discipline is right either way, and
    /// §3.6 is why: terminate is the only thing one process may do to another,
    /// so whoever terminates it has to collect it.
    ///
    /// This is the one place that is true of every pane however it went —
    /// exited, killed by `prefix x`, or dropped along with its session.
    fn drop(&mut self) {
        self.input = None;
        // Exactly once, whatever route the pane took here: a pane whose child
        // exited was collected when its output drained (`reap`), and waiting
        // again would not return on Motor (see `collected`).
        if self.collected {
            return;
        }
        // `kill` is unconditional on both platforms (§3.6), so the wait is short.
        self.kill();
        let _ = self.child.wait();
        self.collected = true;
    }
}

/// The writer thread: everything sent here reaches the child, in order.
///
/// It ends when the channel closes, and dropping `input` then is what closes a
/// pipe-backed pane's input ([`Pane::end_input`]). A child that has stopped
/// reading leaves this blocked in `write_all`, which is the point — it is
/// blocked here rather than in the event loop — and it comes back when the
/// child is killed and its terminal goes with it.
fn feed_child(mut input: Box<dyn Write + Send>) -> Sender<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        while let Ok(bytes) = rx.recv() {
            if input.write_all(&bytes).is_err() || input.flush().is_err() {
                break;
            }
        }
    });
    tx
}

/// Wait for every stream to end, then say so — in that order, per the module
/// docs: the last thing a program printed must be in the grid before anyone
/// hears that it is over.
fn drain(id: PaneId, pumps: Vec<JoinHandle<()>>, events: Sender<Event>) {
    for pump in pumps {
        let _ = pump.join();
    }
    let _ = events.send(Event::Drained { pane: id });
}

/// One reader thread: bytes to the event loop in whatever chunks arrive.
///
/// Chunks, not bytes: red sends one byte per channel message
/// (`red/src/input.rs:33`), which a pane under compiler output would drown in
/// (§4.5).
fn pump(
    pane: PaneId,
    mut src: impl Read + Send + 'static,
    events: Sender<Event>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        // A page. Motor's pipe ring is 2 KiB (`moto-ipc/src/stdio_pipe.rs:46`),
        // so one read empties a full one and the writer never stays blocked.
        // A pty master reports the child's exit as EIO rather than as EOF,
        // which the error arm below already treats as the end.
        let mut buf = [0_u8; 4096];
        loop {
            let n = match src.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            let bytes = buf[..n].to_vec();
            if events.send(Event::Output { pane, bytes }).is_err() {
                break;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;
    use std::time::Instant;

    /// Run `script` in a pane with `input` as its whole input, and return
    /// everything it wrote plus its exit code.
    ///
    /// The assertions below are `contains` rather than `==` wherever input is
    /// involved, because on the host a pane is a real pty and a pty echoes what
    /// is typed at it — which is a terminal doing its job, not noise.
    fn pane_run(script: &str, input: &[u8]) -> (String, Option<i32>) {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(script);

        let (tx, rx) = mpsc::channel();
        let mut pane = Pane::spawn(cmd, (24, 80), tx).unwrap();
        if !input.is_empty() {
            pane.write(input).unwrap();
        }

        let mut out = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        let code = loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(Event::Output { bytes, .. }) => out.extend_from_slice(&bytes),
                // The status comes from the child handle, which is here (§3.6).
                Ok(Event::Drained { .. }) => break pane.reap(),
                Ok(_) => unreachable!("a pane sends no client events"),
                Err(err) => panic!("the pane never exited: {err:?}"),
            }
        };
        pane.join();
        (String::from_utf8_lossy(&out).into_owned(), code)
    }

    #[test]
    fn a_pane_relays_everything_its_child_writes() {
        let (out, code) = pane_run("printf hello", b"");
        assert_eq!(out, "hello");
        assert_eq!(code, Some(0));
    }

    #[test]
    fn a_pane_told_its_input_is_over_sees_the_end_of_it() {
        // Two platforms, two mechanisms, one meaning (`sys::END_OF_INPUT`):
        // `cat` ends when its input does, whether that is a closed pipe or the
        // `^D` a pty needs instead.
        let (tx, rx) = mpsc::channel();
        let mut pane = Pane::spawn(Command::new("cat"), (24, 80), tx).unwrap();
        pane.write(b"line\n").unwrap();
        pane.end_input();

        let mut out = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        let code = loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(Event::Output { bytes, .. }) => out.extend_from_slice(&bytes),
                // The status comes from the child handle, which is here (§3.6).
                Ok(Event::Drained { .. }) => break pane.reap(),
                Ok(_) => unreachable!("a pane sends no client events"),
                Err(err) => panic!("the pane never saw the end of its input: {err:?}"),
            }
        };
        pane.join();
        assert_eq!(code, Some(0));
        assert!(String::from_utf8_lossy(&out).contains("line"));
    }

    #[test]
    fn writing_to_a_pane_does_not_wait_for_the_child_to_read() {
        // The mechanism rather than the platform, because the two platforms
        // fail differently and only one of them can be shown here: Motor's pane
        // input is a 2 KiB ring that blocks its writer when it fills (§4.5),
        // while the host's pty *drops* what will not fit and reports success --
        // measured, by writing a megabyte at a `sleep` and getting `Ok(())`
        // back at once. So a writer that is known to block is what this needs,
        // and `Never` is one.
        struct Never(mpsc::Receiver<()>);
        impl Write for Never {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                // Returns only when the test drops its end, which is what makes
                // this a blocked writer rather than a leaked thread.
                let _ = self.0.recv();
                Ok(0)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let (keep_it_blocked, blocked) = mpsc::channel::<()>();
        let input = feed_child(Box::new(Never(blocked)));
        let started = Instant::now();
        for _ in 0..64 {
            input.send(vec![b'x'; 4096]).unwrap();
        }
        let took = started.elapsed();
        drop(keep_it_blocked);
        assert!(
            took < Duration::from_secs(1),
            "a paste waited {took:?} for the pane to read it"
        );
    }

    #[test]
    fn a_pane_merges_its_childs_stderr_into_the_same_stream() {
        let (out, _) = pane_run("printf out; printf err >&2", b"");
        assert!(out.contains("out"), "{out:?}");
        assert!(out.contains("err"), "{out:?}");
    }

    #[test]
    fn a_pane_delivers_what_is_written_to_it_as_input() {
        let (out, _) = pane_run("read line; printf 'got:%s' \"$line\"", b"abc\n");
        assert!(out.contains("got:abc"), "{out:?}");
    }

    #[test]
    fn a_pane_reports_the_exit_code_of_its_child() {
        let (_, code) = pane_run("exit 7", b"");
        assert_eq!(code, Some(7));
    }

    #[test]
    fn output_written_just_before_exit_is_never_lost() {
        // The drain-before-close trap (§4.5): the child is gone long before its
        // pipes are empty, so a pane that reports the exit first truncates
        // whatever a short command wrote. Once is luck; the loop is the test.
        for _ in 0..20 {
            let (out, code) = pane_run("printf tail", b"");
            assert_eq!(out, "tail");
            assert_eq!(code, Some(0));
        }
    }

    #[test]
    fn a_pane_starts_the_next_line_wherever_its_platform_would() {
        // The wiring, not the rule: `grid` holds both behaviours and this is
        // what picks one. A pane whose platform has no line discipline turns
        // `\n` into a new line itself (§3.3); one on a pty leaves it to `ONLCR`,
        // which has already happened by the time the bytes arrive here.
        let (tx, _rx) = mpsc::channel();
        let mut pane = Pane::spawn(Command::new("cat"), (4, 10), tx).unwrap();
        pane.feed(b"aa\nbb");
        let second = pane.grid().line(1);
        pane.kill();
        pane.join();
        if crate::sys::PANE_NEWLINE_MODE {
            assert_eq!(second, "bb");
        } else {
            assert_eq!(second, "  bb");
        }
    }

    #[test]
    fn a_resized_pane_says_nothing_to_a_program_that_asked_once_before() {
        // A question is answered; a resize is not an answer (§3.2). rmux used to
        // take one `ESC[6n` as standing permission to report every later resize,
        // and since a shell asks at every prompt, the report went to whatever the
        // shell was running by then -- an `ESC` into `top`, which is how `top` is
        // told to quit (`sysbox/src/commands/top.rs:174`).
        //
        // `cat` echoes its input, so anything written into the pane comes back
        // out of it: the answer to the question, and nothing after it. All three
        // calls below queue on the same writer, so `marker` arriving proves an
        // unasked answer would have arrived already.
        let (tx, rx) = mpsc::channel();
        let mut pane = Pane::spawn(Command::new("cat"), (24, 80), tx).unwrap();
        pane.feed(b"\x1b[6n");
        pane.resize((10, 20));

        // Without the `ESC`, because a pty echoes a control byte as `^[` and a
        // pipe echoes nothing at all -- the needle has to be the part both
        // platforms agree on.
        let echoed = echoed_through_marker(pane, &rx);
        assert!(echoed.contains("[1;1R"), "no answer to the ask: {echoed:?}");
        assert!(
            !echoed.contains("[10;20R"),
            "the resize spoke unasked: {echoed:?}"
        );
    }

    #[test]
    fn a_resized_pane_says_nothing_to_a_program_that_never_asked() {
        // `cat` would print it, and a program that never asked has no reason to
        // expect an answer.
        let (tx, rx) = mpsc::channel();
        let mut pane = Pane::spawn(Command::new("cat"), (24, 80), tx).unwrap();
        pane.resize((10, 20));

        let echoed = echoed_through_marker(pane, &rx);
        assert!(
            echoed.contains("marker"),
            "the pane never echoed: {echoed:?}"
        );
        assert!(
            !echoed.contains('R'),
            "an unasked answer was sent: {echoed:?}"
        );
    }

    #[test]
    fn a_resized_pane_reports_to_a_program_that_subscribed() {
        // The other side of the rule above: mode 2048 is a standing request, so
        // this is the one case where rmux writes into a child's stdin without a
        // question in front of it. No probe, no prompt, no round trip -- the
        // report is there by the time the child next reads.
        let (tx, rx) = mpsc::channel();
        let mut pane = Pane::spawn(Command::new("cat"), (24, 80), tx).unwrap();
        pane.feed(b"\x1b[?2048h");
        pane.resize((10, 20));
        // A refit to the size it already has is the common case -- every split,
        // kill and zoom refits every pane in the window -- and reporting those
        // would be a stream of news to a program that has none.
        pane.resize((10, 20));

        // A pty echoes what is written at it and a pipe does not, so a report
        // comes back once or twice depending on the platform. Both reports take
        // the same path, so the subscription -- which rmux sent exactly once --
        // is the yardstick the resize is counted against.
        let echoed = echoed_through_marker(pane, &rx);
        let subscribed = echoed.matches("[48;24;80;0;0t").count();
        assert!(subscribed > 0, "no answer to the subscription: {echoed:?}");
        assert_eq!(
            echoed.matches("[48;10;20;0;0t").count(),
            subscribed,
            "the resize was not reported exactly once: {echoed:?}"
        );
    }

    #[test]
    fn an_unsubscribed_pane_is_told_nothing_when_it_is_resized() {
        // Unsubscribing has to stop the reports, or a program that turned the
        // mode off would go on being typed at.
        let (tx, rx) = mpsc::channel();
        let mut pane = Pane::spawn(Command::new("cat"), (24, 80), tx).unwrap();
        pane.feed(b"\x1b[?2048h\x1b[?2048l");
        pane.resize((10, 20));

        let echoed = echoed_through_marker(pane, &rx);
        assert!(
            !echoed.contains("[48;10;20"),
            "a cancelled subscription still reported: {echoed:?}"
        );
    }

    /// Everything `pane` echoed, up to a marker queued after whatever the test
    /// did to it.
    ///
    /// `cat` echoes its input, so anything written into the pane comes back out
    /// of it. Every write shares the one writer thread, which is what makes the
    /// marker a fence: if it arrived, anything rmux would have sent unasked
    /// arrived before it.
    fn echoed_through_marker(mut pane: Pane, rx: &mpsc::Receiver<Event>) -> String {
        pane.write(b"marker\n").unwrap();

        let mut echoed = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(Event::Output { bytes, .. }) => {
                    echoed.extend_from_slice(&bytes);
                    if echoed.windows(6).any(|seen| seen == b"marker") {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        // Killed before the caller asserts: a pane left behind by a failing test
        // is a child holding a pty for as long as the suite runs.
        pane.kill();
        pane.join();
        String::from_utf8_lossy(&echoed).into_owned()
    }

    #[test]
    fn a_pane_resized_to_the_size_it_already_has_is_left_alone() {
        let (tx, _rx) = mpsc::channel();
        let mut pane = Pane::spawn(Command::new("cat"), (24, 80), tx).unwrap();
        let answers = [
            pane.resize((24, 80)),
            pane.resize((10, 20)),
            pane.resize((10, 20)),
        ];
        // Killed *before* the assertion, because a pane left behind by a failing
        // test is a child holding a pty for as long as the suite runs.
        pane.kill();
        pane.join();
        assert_eq!(answers, [false, true, false]);
    }

    #[test]
    #[cfg(unix)]
    fn a_pane_tells_its_child_the_terminal_changed_size() {
        // A split halves a pane, so a child that was never told keeps line
        // editing as if it had the whole window. Only the host can be told at
        // all -- `stty` reads the pty, which is the thing `TIOCSWINSZ` sets --
        // and on Motor the answer comes from the pane's `ESC[6n` instead, which
        // `grid`'s own tests pin (§3.2).
        let (tx, rx) = mpsc::channel();
        let mut pane = Pane::spawn(Command::new("sh"), (24, 80), tx).unwrap();
        pane.resize((10, 20));
        pane.write(b"stty size\nexit\n").unwrap();

        let mut out = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(Event::Output { bytes, .. }) => out.extend_from_slice(&bytes),
                Ok(Event::Drained { .. }) => break,
                Ok(_) => unreachable!("a pane sends no client events"),
                Err(err) => panic!("the pane never exited: {err:?}"),
            }
        }
        pane.join();
        let out = String::from_utf8_lossy(&out);
        assert!(out.contains("10 20"), "{out:?}");
    }

    #[test]
    fn a_collected_child_is_not_killed_again() {
        // Because on Motor `SysCpu::OP_KILL` aimed at a process that has already
        // been waited for does not return -- it hung the server mid-teardown, and
        // the suite behind it. The host cannot show that (the syscall simply
        // fails here), so what this holds is the rule the hang taught.
        // A live child: there is something to kill.
        let (tx, _rx) = mpsc::channel();
        let mut live = Pane::spawn(Command::new("cat"), (24, 80), tx).unwrap();
        assert!(live.kill(), "a live child is there to be killed");
        live.join();

        // And one that has run its course and been collected: there is not.
        let (tx, rx) = mpsc::channel();
        let mut collected = Pane::spawn(Command::new("true"), (24, 80), tx).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(Event::Drained { .. }) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        collected.reap();
        assert!(
            !collected.kill(),
            "a child that has been collected was killed again"
        );
    }

    #[test]
    fn a_child_is_collected_once_and_not_twice() {
        // The count is what matters, not the outcome: on Motor a second
        // `Child::wait` never returns, and the server sat in one until the whole
        // suite stalled behind it. The host cannot show that -- std caches the
        // status here -- so what this holds is the bookkeeping that stops `Drop`
        // from asking again, which is where the bug was.
        let (tx, rx) = mpsc::channel();
        let mut pane = Pane::spawn(Command::new("true"), (24, 80), tx).unwrap();
        assert!(
            pane.owes_a_wait(),
            "a fresh pane has not collected anything"
        );

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(Event::Drained { .. }) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        assert_eq!(pane.reap(), Some(0));
        assert!(
            !pane.owes_a_wait(),
            "collecting the child did not record that it had been"
        );
        // And this is where Motor would hang if it did not know.
        drop(pane);
    }

    #[test]
    #[cfg(unix)]
    fn a_pane_that_goes_collects_its_child_and_does_not_leave_it() {
        // Killing is not collecting. A child nobody waited for stays in the
        // process table -- a zombie here, and on Motor an entry that pins every
        // ancestor with it, because a child's statistics hold a strong reference
        // to its parent's (see `Drop for Pane`). The pane is dropped here with
        // its child still running, which is what ending a session does to every
        // pane in it.
        //
        // `/proc` is the check because it is the one that cannot be faked: a
        // collected child is gone from it, an uncollected one is still there as
        // a zombie.
        let (tx, _rx) = mpsc::channel();
        let mut sleeper = Command::new("sleep");
        sleeper.arg("60");
        let pane = Pane::spawn(sleeper, (24, 80), tx).unwrap();
        let pid = pane.child.id();
        assert!(
            std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "the child never started"
        );

        drop(pane);
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "the pane left its child behind as a zombie"
        );
    }

    #[test]
    fn panes_are_identified_by_rmuxs_own_counter_not_by_pid() {
        let (tx, _rx) = mpsc::channel();
        let first = Pane::spawn(Command::new("true"), (24, 80), tx.clone()).unwrap();
        let second = Pane::spawn(Command::new("true"), (24, 80), tx).unwrap();
        assert_ne!(first.id(), second.id());
        first.join();
        second.join();
    }
}
