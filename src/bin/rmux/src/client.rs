//! The client: thin, and nearly stateless.
//!
//! Put the console in the alternate screen, relay input bytes to the server,
//! write the server's bytes to the console, and restore the console on the way
//! out (details.md §4.1). A few hundred lines, and no opinion about what any of
//! those bytes mean — the prefix, the key tables and the rendering all live in
//! the server, because that is where the state is.
//!
//! Two things do belong here, and only here, because they are properties of
//! *this* console rather than of the session:
//!
//! - **raw mode and the alternate screen**, which are what "taking over a
//!   terminal" means, and which have to be given back however rmux exits —
//!   including on a panic, since `panic = "abort"` means `Drop` does not run
//!   (§4.6);
//! - **the console's keys and its size**, which are crossterm's now. Its Motor
//!   OS backend is where §3.2 and §8.3 live: it asks `ESC[6n` on a clock,
//!   because nothing on the platform announces a resize, and it decodes keys off
//!   a console that delivers one byte at a time. A resize arrives among the keys
//!   and is passed straight on to the server -- except for the very first, which
//!   is worth waiting a moment for ([`settle_size`]) so that the opening frame is
//!   painted once, at the size the console really is.
//!
//! # Starting the server
//!
//! A client that finds no server starts one and waits for it. The server is
//! spawned **detached** (§4.4) with no stdio: on Motor an ordinary orphan is
//! killed when its parent is reaped, so detaching is the difference between a
//! session that survives a detach and one that does not.

use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::mpsc::channel;
use std::time::Duration;
use std::time::Instant;

use crossterm::event::DisableBracketedPaste;
use crossterm::event::EnableBracketedPaste;
use crossterm::event::Event;
use crossterm::event::KeyEventKind;
use crossterm::terminal::EnterAlternateScreen;
use crossterm::terminal::LeaveAlternateScreen;
use crossterm::terminal::disable_raw_mode;
use crossterm::terminal::enable_raw_mode;
use crossterm::{cursor, execute};

use crate::keys::Key;
use crate::proto;
use crate::proto::Frames;
use crate::proto::ToClient;
use crate::proto::ToServer;
use crate::sys;

/// The size to run at until the console says otherwise (§3.2).
const FALLBACK_CONSOLE_SIZE: (u16, u16) = (24, 80);

/// How long to give the console to say how big it is before opening a session.
///
/// Not a blocking round trip -- the answer arrives as an ordinary console event
/// and this is a window, not a wait for a reply (§3.2). What it buys is the
/// *first* frame being painted at the size the console really is: without it the
/// frame is painted at [`FALLBACK_CONSOLE_SIZE`] and then again when the answer
/// turns up, which is a full repaint of the whole screen twice over a console
/// where that costs about a second (§6.3), and a status line the user watches
/// jump. A console with nothing on the other end that answers costs this much
/// once, at startup, and never again.
const SIZE_ANSWER_TIMEOUT: Duration = Duration::from_millis(200);

/// How long to wait for a server that is starting up.
const SERVER_START_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a connected client waits to hear anything at all.
///
/// The port file names a port and nothing more, so what answers on it may not be
/// an rmux server: a file left behind by a server that was killed, a port some
/// other program has since been given, the client's own socket ([`join_server`]).
/// Every one of those looks identical from here -- a connection that was
/// accepted and then says nothing -- and the client used to wait on it forever,
/// sitting on a blank alternate screen with the cursor wherever the size probe
/// left it. Found on the VM, where exactly that happened: a client with both its
/// reader threads up and no server process anywhere on the machine.
///
/// A server answers an attach by rendering and a question by replying (§4.2's
/// "every question gets an answer"), so the first word always comes at once.
/// Generous enough that a busy machine cannot lose it, short enough that the
/// worst case -- a dead end, and then a server this client starts itself -- is a
/// pause rather than a wait.
const FIRST_WORD_TIMEOUT: Duration = Duration::from_secs(5);

/// How many ports a client will try before giving up.
///
/// Two: the one the port file named, and -- if whatever answered there turned
/// out not to be a server -- the one a server this client starts publishes
/// instead. A third would spend another [`FIRST_WORD_TIMEOUT`] of the user's
/// time on the same doubt, and by then the answer is that this machine cannot
/// run an rmux server at all.
const ATTEMPTS: usize = 2;

enum Local {
    Key(Key),
    /// The console is a different shape: rows, then columns.
    Resized(u16, u16),
    ConsoleEof,
    FromServer(ToClient),
    ServerGone,
}

/// Start a session and attach to it — `rmux new` (§7.3).
pub fn create(name: Option<String>) -> std::io::Result<i32> {
    run(|rows, cols| ToServer::NewSession { name, rows, cols })
}

/// Attach to `session`, optionally detaching its other clients first.
pub fn attach(session: Option<String>, detach_others: bool) -> std::io::Result<i32> {
    run(|rows, cols| ToServer::Attach {
        session,
        detach_others,
        rows,
        cols,
    })
}

/// Take over the console, join a server, and relay until it says stop.
///
/// `opening` is what to ask for once connected -- the one thing that differs
/// between attaching to a session and starting one.
fn run(opening: impl FnOnce(u16, u16) -> ToServer) -> std::io::Result<i32> {
    // `panic = "abort"` in the release profile means `Drop` will not run on a
    // panic (§4.6), so the hook is what puts the console back. It must leave
    // the alternate screen too, or a panic strands the user on a corrupted
    // one -- and it must do all of that before printing.
    std::panic::set_hook(Box::new(|info| {
        restore_console();
        eprintln!("rmux panicked: {info}");
    }));
    enter_console()?;

    let outcome = attached(opening);

    // However that ended, the console goes back to whoever had it. A client
    // that failed after taking it over used to return with the alternate
    // screen still on and raw mode still set, so its own "the rmux server did
    // not answer" was printed onto a blank screen the shell then inherited.
    match outcome {
        Ok(_) => leave_console(),
        Err(_) => restore_console(),
    }
    outcome
}

/// Everything between taking the console and giving it back.
fn attached(opening: impl FnOnce(u16, u16) -> ToServer) -> std::io::Result<i32> {
    // The size the platform can say, which on the host is `TIOCGWINSZ` and on
    // Motor OS is `$LINES`/`$COLUMNS` until an `ESC[6n` has been answered --
    // the first of which comes back a few milliseconds into the session and
    // arrives here as a resize like any other (§3.2).
    let size = crossterm::terminal::size()
        .map(|(cols, rows)| (rows, cols))
        .unwrap_or(FALLBACK_CONSOLE_SIZE);

    // The console reader starts before the connection, because anything typed
    // while the server is starting was typed at the session -- and because the
    // console's answer to crossterm's first size probe is console input like any
    // other, and is wanted before the first frame.
    let (events, queue) = channel();
    let from_console = events.clone();
    std::thread::spawn(move || read_console(from_console));

    let (size, early) = settle_size(size, &queue);

    let (mut server, opened_with, frames) = join_server(&opening(size.0, size.1))?;

    let reader = server.try_clone()?;
    std::thread::spawn(move || read_server(reader, events, frames));

    // The opening frame is already in hand: it is what proved this was a server
    // (see [`first_words`]), and painting it is what relay would have done with
    // it. It goes before the console's own early events, so the session appears
    // before a key typed into it is forwarded.
    let early = opened_with
        .into_iter()
        .map(Local::FromServer)
        .chain(early)
        .collect();

    relay(&mut server, &queue, size, early)
}

/// Wait briefly for the console to say how big it is, and hand back that size
/// along with whatever else arrived while waiting.
///
/// The fallback stands if nothing answers in [`SIZE_ANSWER_TIMEOUT`], which is
/// what keeps rmux's promise never to hang on a console that cannot answer
/// (§3.2). Keys typed in the meantime were typed at the session, so they are
/// kept, in order, for the session that does not exist yet.
fn settle_size(fallback: (u16, u16), queue: &Receiver<Local>) -> ((u16, u16), Vec<Local>) {
    let deadline = Instant::now() + SIZE_ANSWER_TIMEOUT;
    let mut early = Vec::new();
    loop {
        // **The clock decides, not the wakeup.** `recv_timeout` may report a
        // timeout before its duration is up -- a condition variable is allowed
        // to wake spuriously, and on Motor OS it does. Taking the first one at
        // face value is what made this window ineffective there: measured on the
        // VM, the answer arrived in 13ms and the frame was painted at the
        // fallback size 8ms later, then again 4ms after that.
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return (fallback, early);
        }
        match queue.recv_timeout(left) {
            Ok(Local::Resized(rows, cols)) => return ((rows, cols), early),
            Ok(event) => early.push(event),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            // The console reader is gone, and nothing else can arrive: the
            // server has not been spoken to yet.
            Err(_) => return (fallback, early),
        }
    }
}

/// Take the console over: raw mode, the alternate screen so that leaving
/// restores whatever the user was looking at, and bracketed paste off — as red
/// does, because the server is the thing interpreting keys now. A pane that
/// wants `?2004h` gets it inside its own emulator (§7.6); this is rmux's own
/// console.
fn enter_console() -> std::io::Result<()> {
    crossterm::event::enable_ctrl_c_events()?;
    enable_raw_mode()?;
    execute!(
        std::io::stdout(),
        EnterAlternateScreen,
        DisableBracketedPaste
    )
}

/// Give back everything [`enter_console`] took.
fn leave_console() {
    let _ = execute!(
        std::io::stdout(),
        cursor::Show,
        EnableBracketedPaste,
        LeaveAlternateScreen
    );
    let _ = disable_raw_mode();
}

/// The client's whole event loop: keys one way, bytes the other.
fn relay(
    server: &mut TcpStream,
    queue: &Receiver<Local>,
    opened_at: (u16, u16),
    early: Vec<Local>,
) -> std::io::Result<i32> {
    // The size the server has been told about. A `Resize` invalidates the
    // client's screen and buys a full repaint (§6.2), so a size that has not
    // changed is not worth sending -- and on Motor OS the console is asked once
    // a second, so most answers say nothing new.
    let mut known = opened_at;
    // The opening frame, and whatever arrived while the console was being asked
    // how big it is ([`settle_size`]): oldest first, and still owed.
    let mut early = early.into_iter();
    // Nothing here is on a clock. The one thing that was -- whether the port
    // file led to an rmux server at all -- is settled before a client gets
    // here ([`join_server`]), and an idle session is an idle session.
    loop {
        let event = match early.next() {
            Some(event) => event,
            None => match queue.recv() {
                Ok(event) => event,
                Err(_) => break,
            },
        };

        match event {
            Local::Key(key) => send(server, &ToServer::Key(key))?,
            Local::Resized(rows, cols) => {
                if (rows, cols) != known {
                    known = (rows, cols);
                    send(server, &ToServer::Resize { rows, cols })?;
                }
            }
            // The console is over, but the session is not: say so, so a shell
            // reading a script ends, and keep painting until the server says
            // the work is done.
            Local::ConsoleEof => send(server, &ToServer::EndInput)?,
            Local::FromServer(ToClient::Write(bytes)) => {
                // Not a held lock: crossterm's Motor OS backend writes its size
                // probe to stdout from the reader thread, and a lock this thread
                // never gave up would be one that thread never got.
                let mut console = std::io::stdout();
                console.write_all(&bytes)?;
                console.flush()?;
            }
            Local::FromServer(ToClient::Exit(code)) => return Ok(code),
            Local::FromServer(ToClient::Detached) => return Ok(0),
            Local::FromServer(ToClient::Failed(why)) => {
                restore_console();
                eprintln!("rmux: {why}");
                return Ok(1);
            }
            // An attached client asks nothing the server answers with `Done`.
            Local::FromServer(ToClient::Done) => {}
            Local::FromServer(ToClient::Sessions(lines)) => {
                restore_console();
                for line in lines {
                    println!("{line}");
                }
                return Ok(0);
            }
            Local::ServerGone => return Ok(1),
        }
    }
    Ok(0)
}

/// Ask a running server something that is not an attach, and print the answer.
///
/// `ls` and `kill-session` (§7.3) are M6's; this is the road they take, and it
/// deliberately never touches the console.
pub fn ask(request: ToServer) -> std::io::Result<i32> {
    // A question client starts no server: no server means no sessions, and for
    // a question about sessions that is the answer rather than an error. So it
    // gets one attempt at whatever the port file names, and if that turns out
    // not to be a server the file is forgotten and there is nothing to ask.
    let Some((mut server, port)) = try_connect() else {
        return Ok(0);
    };
    send(&mut server, &request)?;

    // The read timeout [`first_words`] set is left on for the rest of the
    // exchange, which is what keeps `rmux ls` in a script from becoming a stuck
    // script: every question gets an answer (§4.2), so a silence here is a
    // failure however far in it happens.
    let mut frames = Frames::new();
    let mut said = match first_words(&mut server, &mut frames, FIRST_WORD_TIMEOUT)? {
        Some(said) => said,
        None => {
            forget_port(port);
            return Err(no_answer());
        }
    };

    let mut buf = [0_u8; 4096];
    loop {
        for message in said.drain(..) {
            match message {
                ToClient::Sessions(lines) => {
                    for line in lines {
                        println!("{line}");
                    }
                    return Ok(0);
                }
                ToClient::Done => return Ok(0),
                ToClient::Failed(why) => {
                    eprintln!("rmux: {why}");
                    return Ok(1);
                }
                _ => {}
            }
        }
        let read = match server.read(&mut buf) {
            Ok(0) => return Ok(0),
            Ok(read) => read,
            Err(err) if proto::timed_out(&err) => return Err(no_answer()),
            Err(err) => return Err(err),
        };
        frames.feed(&buf[..read]);
        while let Some(message) = frames.take::<ToClient>() {
            said.extend(message);
        }
    }
}

fn send(server: &mut TcpStream, message: &ToServer) -> std::io::Result<()> {
    server.write_all(&proto::encode(message))?;
    server.flush()
}

/// Read the server for as long as it has anything to say.
///
/// `frames` is where [`first_words`] left off: whatever it read past the
/// opening frame is still in there, and a fresh buffer would take the tail of a
/// half-read frame for the head of a new one.
fn read_server(mut server: TcpStream, events: Sender<Local>, mut frames: Frames) {
    let mut buf = [0_u8; 4096];
    loop {
        let read = match server.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        frames.feed(&buf[..read]);
        while let Some(message) = frames.take::<ToClient>() {
            if let Some(message) = message
                && events.send(Local::FromServer(message)).is_err()
            {
                return;
            }
        }
    }
    let _ = events.send(Local::ServerGone);
}

/// The console reader thread: what the user pressed, and how big the console is.
///
/// Both come from the same place, because they arrive on the same stdin: the
/// serial console hands sys-tty one byte at a time (§8.3), and the only thing
/// on Motor OS that can say how big a terminal is answers `ESC[6n` on it. This
/// thread is where crossterm's event source runs, which is why the size probing
/// happens at all — it is done while waiting for a key.
fn read_console(events: Sender<Local>) {
    // A read error is the console going away, which is as final as EOF.
    while let Ok(event) = crossterm::event::read() {
        let local = match event {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                // A key rmux has no name for is not a key it can pass on (§8.1).
                match Key::from_event(key) {
                    Some(key) => Local::Key(key),
                    None => continue,
                }
            }
            Event::Resize(cols, rows) => Local::Resized(rows, cols),
            _ => continue,
        };
        if events.send(local).is_err() {
            return;
        }
    }
    let _ = events.send(Local::ConsoleEof);
}

fn restore_console() {
    leave_console();
    let _ = std::io::stdout().flush();
}

// ---- finding, or starting, the server ---------------------------------------

/// What to say when nothing rmux could find would serve.
fn no_answer() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "the rmux server did not answer; try again",
    )
}

/// Join a server that answers, starting one if the port file was a dead end.
///
/// **The port file is a hint, not a promise** (§4.2). It names a port and
/// nothing more, it outlives the server that wrote it -- a reboot with a
/// session running leaves one behind -- and on Motor OS the port it names is
/// very likely to be handed straight back out: `sys-io` allocates ephemeral
/// ports by taking the lowest free one from 49152 (`net/device.rs`), so the
/// first port bound after a boot is the same one the last boot's server had.
/// A client that connects to it therefore connects to *itself*, since its own
/// outgoing socket is given that same lowest free port; TCP allows that, the
/// connection succeeds, and the request goes into an ear that will never
/// answer. Measured on the VM: `rmux new` on a fresh boot failed this way about
/// half the time, and every failure needed the user to run it again.
///
/// So the first word decides. Whatever answered gets [`FIRST_WORD_TIMEOUT`] to
/// prove it is a server; if it does not, that port is forgotten and this tries
/// once more, which -- the file now gone -- means starting a server of its own.
fn join_server(opening: &ToServer) -> std::io::Result<(TcpStream, Vec<ToClient>, Frames)> {
    for _ in 0..ATTEMPTS {
        let (mut server, port) = connect_or_start()?;
        send(&mut server, opening)?;

        let mut frames = Frames::new();
        if let Some(said) = first_words(&mut server, &mut frames, FIRST_WORD_TIMEOUT)? {
            // Back to a plain blocking socket for the session itself: an idle
            // session must not look like a server that stopped answering. A
            // platform that cannot clear the timeout has to say so here rather
            // than by ending a working session five seconds into its first
            // silence.
            server.set_read_timeout(None)?;
            return Ok((server, said, frames));
        }
        forget_port(port);
    }
    Err(no_answer())
}

/// What the other end says first, or `None` if it is not an rmux server.
///
/// Three things say "not a server", and the point of asking is that they are
/// otherwise indistinguishable from one: silence for [`FIRST_WORD_TIMEOUT`], a
/// connection that ends without a word, and a frame that is not something a
/// server says. That last one is what a client that connected to itself reads:
/// its own request, coming back. It cannot be an rmux server one version ahead,
/// because the server *is* this binary -- [`spawn_server`] runs
/// `current_exe()`.
///
/// The read timeout is left set; a caller that means to wait longer than this
/// clears it. `patience` is [`FIRST_WORD_TIMEOUT`] in both callers and a
/// parameter only so that a test can ask a shorter question than a user would
/// sit through.
fn first_words(
    server: &mut TcpStream,
    frames: &mut Frames,
    patience: Duration,
) -> std::io::Result<Option<Vec<ToClient>>> {
    let deadline = Instant::now() + patience;
    server.set_read_timeout(Some(patience))?;

    let mut said = Vec::new();
    let mut buf = [0_u8; 4096];
    loop {
        match server.read(&mut buf) {
            Ok(0) => return Ok(None),
            Ok(read) => frames.feed(&buf[..read]),
            // A timeout is not a clock (`proto::timed_out`): it can be reported
            // early, so whether the time is really up is a question for
            // `Instant`.
            Err(err) if proto::timed_out(&err) => {
                if Instant::now() >= deadline {
                    return Ok(None);
                }
                continue;
            }
            // A host-side read can be interrupted by a signal (EINTR);
            // retry under the same deadline.
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                if Instant::now() >= deadline {
                    return Ok(None);
                }
                continue;
            }
            Err(err) => return Err(err),
        }

        while let Some(message) = frames.take::<ToClient>() {
            let Some(message) = message else {
                return Ok(None);
            };
            said.push(message);
        }
        if !said.is_empty() {
            return Ok(Some(said));
        }
        if frames.is_broken() {
            return Ok(None);
        }
    }
}

/// Forget a port that did not answer, so that the next attempt starts a server.
///
/// Only if the file still names it: by now it may have been rewritten by the
/// very server this client started, and deleting *that* would leave a server
/// running that nothing can ever find again.
fn forget_port(port: u16) {
    if named_port() == Some(port) {
        let _ = std::fs::remove_file(sys::port_file());
    }
}

/// The port the file names, if it names one.
fn named_port() -> Option<u16> {
    std::fs::read_to_string(sys::port_file())
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Connect to whatever the port file names, and say which port that was.
fn try_connect() -> Option<(TcpStream, u16)> {
    let port = named_port()?;
    let server = TcpStream::connect(("127.0.0.1", port)).ok()?;
    Some((server, port))
}

/// Connect to the server, starting one if there is none.
///
/// Exactly one client starts a server; the rest wait for it. The lock file is
/// what makes that true: two servers would mean two session lists and one port
/// file to name them by, so the loser of that race would hold sessions nobody
/// could ever reach.
fn connect_or_start() -> std::io::Result<(TcpStream, u16)> {
    if let Some(server) = try_connect() {
        return Ok(server);
    }

    let lock = sys::port_file().with_extension("lock");
    // rmux makes its own scratch space on Motor (`sys::port_file`), and the
    // lock lives in it: without this the lock cannot be created either, and a
    // client would read that failure as "somebody else is starting one".
    if let Some(parent) = lock.parent() {
        if !parent.is_dir() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let ours = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock)
    {
        Ok(_) => true,
        // Another client got there first; wait for its server rather than
        // starting a second one.
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => false,
        // Anything else is not evidence that somebody else is starting a
        // server, and waiting ten seconds on that mistake is worse than
        // trying and finding out.
        Err(_) => true,
    };
    if ours {
        spawn_server()?;
    }

    let deadline = Instant::now() + SERVER_START_TIMEOUT;
    while Instant::now() < deadline {
        if let Some(server) = try_connect() {
            return Ok(server);
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    // A lock left behind by a client that died would otherwise mean nobody
    // ever starts a server again.
    let _ = std::fs::remove_file(&lock);
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "the rmux server did not start",
    ))
}

/// Start the server, detached, and never wait for it.
///
/// `sys-init` is the precedent (`main.rs:77-88`): spawn with null stdio and
/// neither track nor wait. Detached matters on Motor, where the kernel kills a
/// process's children when it is reaped, so a plain orphan does not survive its
/// parent's exit (§4.4) — measured in M0, and the reason `CAP_SPAWN_DETACHED`
/// exists at all.
fn spawn_server() -> std::io::Result<()> {
    let mut server = std::process::Command::new(std::env::current_exe()?);
    server
        .arg(crate::SERVER_ARG)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    sys::detach(&mut server);
    server.spawn()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A relay whose console and server are both this test.
    ///
    /// What is worth holding here is the client's one rule about size: the
    /// server is told only when the console really changed shape. A `Resize`
    /// invalidates the client's screen and buys a full repaint (§6.2), and on
    /// Motor OS the console is asked once a second (`crossterm`'s Motor
    /// backend), so most of those answers say nothing new.
    fn resizes(opened_at: (u16, u16), reported: &[(u16, u16)]) -> Vec<ToServer> {
        let (events, queue) = channel();
        for (rows, cols) in reported {
            events.send(Local::Resized(*rows, *cols)).unwrap();
        }
        // Ends the relay, so the test does not wait for a server that is this
        // test itself.
        events.send(Local::ServerGone).unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let sent = std::thread::spawn(move || {
            let (mut server, _) = listener.accept().unwrap();
            server
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut frames = Frames::new();
            let mut buf = [0_u8; 4096];
            let mut out = Vec::new();
            while let Ok(read) = server.read(&mut buf) {
                if read == 0 {
                    break;
                }
                frames.feed(&buf[..read]);
                while let Some(Some(message)) = frames.take::<ToServer>() {
                    out.push(message);
                }
            }
            out
        });

        let mut server = TcpStream::connect(address).unwrap();
        relay(&mut server, &queue, opened_at, Vec::new()).unwrap();
        drop(server);
        sent.join().unwrap()
    }

    #[test]
    fn a_console_that_is_still_the_shape_it_was_costs_nothing() {
        let told = resizes((24, 80), &[(24, 80), (24, 80)]);
        assert!(told.is_empty(), "{told:?}");
    }

    #[test]
    fn a_console_that_changed_shape_is_reported_once() {
        let told = resizes((24, 80), &[(40, 100), (40, 100), (24, 80)]);
        assert_eq!(
            told,
            [
                ToServer::Resize {
                    rows: 40,
                    cols: 100
                },
                ToServer::Resize { rows: 24, cols: 80 },
            ]
        );
    }

    #[test]
    fn a_console_that_answers_opens_at_the_size_it_answered() {
        let (events, queue) = channel();
        events.send(Local::Key(Key::ctrl('a'))).unwrap();
        events.send(Local::Resized(40, 100)).unwrap();
        // Never looked at: the wait ends at the first thing the console says
        // about its size.
        events.send(Local::Resized(1, 1)).unwrap();

        let (size, early) = settle_size((24, 80), &queue);
        assert_eq!(size, (40, 100));
        // What was typed while the console was being asked was typed at the
        // session, and is still owed to it.
        assert!(matches!(early[..], [Local::Key(_)]), "{}", early.len());
    }

    #[test]
    fn a_console_that_says_nothing_opens_at_the_fallback() {
        // Nothing on the other end to answer `ESC[6n`: the promise is that this
        // costs one window and no hang (§3.2).
        let (events, queue) = channel();
        let opened_at = Instant::now();
        let (size, early) = settle_size((24, 80), &queue);
        assert_eq!(size, (24, 80));
        assert!(early.is_empty());
        assert!(opened_at.elapsed() >= SIZE_ANSWER_TIMEOUT);
        drop(events);
    }

    #[test]
    fn a_key_reaches_the_server_as_the_key_it_was() {
        // The client decodes and the server decides (§8.2), so what crosses the
        // wire is the key rather than the bytes it arrived as.
        let (events, queue) = channel();
        events.send(Local::Key(Key::ctrl('a'))).unwrap();
        events
            .send(Local::Key(Key::plain(crate::keys::Code::Char('|'))))
            .unwrap();
        events.send(Local::ServerGone).unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let sent = std::thread::spawn(move || {
            let (mut server, _) = listener.accept().unwrap();
            let mut frames = Frames::new();
            let mut buf = [0_u8; 4096];
            let mut out = Vec::new();
            while let Ok(read) = server.read(&mut buf) {
                if read == 0 {
                    break;
                }
                frames.feed(&buf[..read]);
                while let Some(Some(message)) = frames.take::<ToServer>() {
                    out.push(message);
                }
            }
            out
        });

        let mut server = TcpStream::connect(address).unwrap();
        relay(&mut server, &queue, (24, 80), Vec::new()).unwrap();
        drop(server);
        assert_eq!(
            sent.join().unwrap(),
            [
                ToServer::Key(Key::ctrl('a')),
                ToServer::Key(Key::plain(crate::keys::Code::Char('|'))),
            ]
        );
    }

    // ---- what answered on that port ----------------------------------------

    /// A connected pair: the end a client would hold, and whatever is on the
    /// other side of it.
    fn connected() -> (TcpStream, TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let ours = TcpStream::connect(address).unwrap();
        let theirs = listener.accept().unwrap().0;
        (ours, theirs)
    }

    /// Long enough that a loopback write cannot lose the race, short enough
    /// that a test which waits it out is still a test.
    const A_MOMENT: Duration = Duration::from_millis(200);

    #[test]
    fn a_server_is_what_says_something_a_server_says() {
        let (mut ours, mut theirs) = connected();
        theirs
            .write_all(&proto::encode(&ToClient::Write(b"hello".to_vec())))
            .unwrap();

        let mut frames = Frames::new();
        let said = first_words(&mut ours, &mut frames, A_MOMENT).unwrap();
        assert_eq!(said, Some(vec![ToClient::Write(b"hello".to_vec())]));
    }

    #[test]
    fn a_client_that_reached_itself_hears_its_own_request_back() {
        // What a connection to one's own socket returns, which on Motor OS is
        // what a stale port file leads to: `sys-io` hands out the lowest free
        // ephemeral port, and that is the port the last boot's server had.
        let (mut ours, mut theirs) = connected();
        theirs
            .write_all(&proto::encode(&ToServer::NewSession {
                name: None,
                rows: 30,
                cols: 100,
            }))
            .unwrap();

        let mut frames = Frames::new();
        assert_eq!(first_words(&mut ours, &mut frames, A_MOMENT).unwrap(), None);
    }

    #[test]
    fn a_port_that_says_nothing_at_all_is_not_a_server() {
        let (mut ours, _theirs) = connected();
        let asked_at = Instant::now();

        let mut frames = Frames::new();
        assert_eq!(first_words(&mut ours, &mut frames, A_MOMENT).unwrap(), None);
        // Waited it out rather than taking the first timeout for an answer: a
        // socket may report one early (`proto::timed_out`).
        assert!(asked_at.elapsed() >= A_MOMENT);
    }

    #[test]
    fn a_connection_that_ends_without_a_word_is_not_a_server() {
        let (mut ours, theirs) = connected();
        drop(theirs);

        let mut frames = Frames::new();
        assert_eq!(first_words(&mut ours, &mut frames, A_MOMENT).unwrap(), None);
    }

    #[test]
    fn what_arrived_behind_the_first_word_is_still_there() {
        // The reader thread carries on from this buffer (`read_server`), so a
        // frame that was half-read here must not be half-read there too.
        let (mut ours, mut theirs) = connected();
        let opening = proto::encode(&ToClient::Write(b"first".to_vec()));
        let following = proto::encode(&ToClient::Write(b"second".to_vec()));
        theirs.write_all(&opening).unwrap();
        theirs.write_all(&following[..3]).unwrap();

        let mut frames = Frames::new();
        let said = first_words(&mut ours, &mut frames, A_MOMENT).unwrap();
        assert_eq!(said, Some(vec![ToClient::Write(b"first".to_vec())]));

        frames.feed(&following[3..]);
        assert_eq!(
            frames.take::<ToClient>(),
            Some(Some(ToClient::Write(b"second".to_vec())))
        );
    }
}
