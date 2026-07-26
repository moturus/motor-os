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
//! - **the size probe** (§3.2). The platform is asked first; where it cannot
//!   say, which on Motor is always, the terminal is asked and the answer taken
//!   without waiting for it. The answer reaches the server as a `Resize`.
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

use crate::keys::SizeProbe;
use crate::proto;
use crate::proto::Frames;
use crate::proto::ToClient;
use crate::proto::ToServer;
use crate::sys;

/// What rmux writes to take the console over, and to give it back.
///
/// The alternate screen, so that leaving restores whatever the user was looking
/// at, and bracketed paste off — as red does (`terminal.rs:16`), because the
/// server is the thing interpreting keys now. A pane that wants `?2004h` gets
/// it inside its own emulator (§7.6); this is about rmux's own console.
const CONSOLE_ENTER: &[u8] = b"\x1b[?1049h\x1b[?2004l";
const CONSOLE_LEAVE: &[u8] = b"\x1b[?25h\x1b[?2004h\x1b[?1049l";

/// The size to run at until something says otherwise (§3.2).
const FALLBACK_CONSOLE_SIZE: (u16, u16) = (24, 80);

/// How long to wait for a server that is starting up.
const SERVER_START_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to give the console to answer the size probe before opening.
///
/// Not a blocking round trip -- the answer arrives as ordinary input and this is
/// a window, not a wait for a reply (§3.2). What it buys is the *first* frame
/// being painted at the size the console really is: without it the frame is
/// painted at [`FALLBACK_CONSOLE_SIZE`] and then again when the answer turns up,
/// which is a full repaint of the whole screen twice over a console where that
/// costs about a second (§6.3), and a status line the user watches jump. A
/// console with nothing on the other end that answers costs this much once, at
/// startup, and never again.
const SIZE_ANSWER_TIMEOUT: Duration = Duration::from_millis(200);

/// How long a connected client waits to hear anything at all.
///
/// The port file names a port and nothing more, so what answers on it may not be
/// an rmux server: a file left behind by a server that was killed, a port some
/// other program has since been given, a server that died between the connect
/// and the request. Every one of those looks identical from here -- a connection
/// that was accepted and then says nothing -- and the client used to wait on it
/// forever, sitting on a blank alternate screen with the cursor wherever the
/// size probe left it. Found on the VM, where exactly that happened: a client
/// with both its reader threads up, blocked in [`relay`], and no server process
/// anywhere on the machine.
///
/// A server answers an attach by rendering and a question by replying (§4.2's
/// "every question gets an answer"), so the first word always comes at once.
/// Generous enough that a busy machine cannot lose it, short enough that a user
/// is told rather than left looking at nothing.
const FIRST_WORD_TIMEOUT: Duration = Duration::from_secs(5);

enum Local {
    Console(Vec<u8>),
    ConsoleEof,
    FromServer(ToClient),
    ServerGone,
}

/// Start a session and attach to it — `rmux new` (§7.3).
pub fn create(name: Option<String>) -> std::io::Result<i32> {
    run(|rows, cols| ToServer::NewSession { name, rows, cols })
}

/// Attach to `session`, or to the most recent one, and run until told to stop.
pub fn attach(session: Option<String>) -> std::io::Result<i32> {
    run(|rows, cols| ToServer::Attach {
        session,
        rows,
        cols,
    })
}

/// Take over the console, join a server, and relay until it says stop.
///
/// `opening` is what to ask for once connected -- the one thing that differs
/// between attaching to a session and starting one.
fn run(opening: impl FnOnce(u16, u16) -> ToServer) -> std::io::Result<i32> {
    let _console = sys::RawConsole::enter();
    // `panic = "abort"` in the release profile means `Drop` will not run on a
    // panic (§4.6), so the hook is what puts the console back. It must leave
    // the alternate screen too, or a panic strands the user on a corrupted
    // one -- and it must do all of that before printing.
    std::panic::set_hook(Box::new(|info| {
        restore_console();
        eprintln!("rmux panicked: {info}");
    }));

    let mut console = std::io::stdout().lock();
    console.write_all(CONSOLE_ENTER)?;
    console.flush()?;

    let (size, mut probe) = match sys::console_size() {
        Some(size) => (size, SizeProbe::none()),
        None => {
            console.write_all(crate::keys::SIZE_PROBE)?;
            console.flush()?;
            (FALLBACK_CONSOLE_SIZE, SizeProbe::awaiting())
        }
    };

    // The console reader starts before the connection, because the probe's
    // answer is console input and it is wanted *before* the first frame.
    let (events, queue) = channel();
    let from_console = events.clone();
    std::thread::spawn(move || read_console(from_console));

    let mut early = Early::default();
    let size = settle_size(size, &mut probe, &queue, &mut early);

    let mut server = connect_or_start()?;
    send(&mut server, &opening(size.0, size.1))?;
    // Anything typed while the terminal was answering was typed at the session,
    // and in this order.
    if !early.typed.is_empty() {
        send(
            &mut server,
            &ToServer::Input(std::mem::take(&mut early.typed)),
        )?;
    }
    if early.ended {
        send(&mut server, &ToServer::EndInput)?;
    }

    let reader = server.try_clone()?;
    std::thread::spawn(move || read_server(reader, events));

    let code = relay(&mut server, &queue, &mut console, &mut probe)?;
    console.write_all(CONSOLE_LEAVE)?;
    console.flush()?;
    Ok(code)
}

/// What arrived from the console before there was a server to send it to.
#[derive(Default)]
struct Early {
    typed: Vec<u8>,
    ended: bool,
}

/// Wait briefly for the console to say how big it is, and hand back that size.
///
/// The fallback stands if nothing answers in [`SIZE_ANSWER_TIMEOUT`], which is
/// what keeps rmux's promise never to hang on a console that cannot answer
/// (§3.2). Whatever else arrived in the meantime is kept, in order, for the
/// session that does not exist yet.
fn settle_size(
    fallback: (u16, u16),
    probe: &mut SizeProbe,
    queue: &Receiver<Local>,
    early: &mut Early,
) -> (u16, u16) {
    let deadline = Instant::now() + SIZE_ANSWER_TIMEOUT;
    loop {
        // **The clock decides, not the wakeup.** `recv_timeout` may report a
        // timeout before its duration is up -- a condition variable is allowed
        // to wake spuriously, and on Motor OS it does. Taking the first one at
        // face value is what made this window ineffective there: measured on the
        // VM, the answer arrived in 13ms and the frame was painted at the
        // fallback size 8ms later, then again 4ms after that.
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return fallback;
        }
        match queue.recv_timeout(left) {
            Ok(Local::Console(bytes)) => {
                if let Some(size) = probe.filter(&bytes, &mut early.typed) {
                    return size;
                }
            }
            Ok(Local::ConsoleEof) => {
                early.ended = true;
                return fallback;
            }
            // Nothing else can arrive: the server has not been spoken to yet.
            Ok(_) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => return fallback,
        }
    }
}

/// The client's whole event loop: bytes one way, bytes the other.
fn relay(
    server: &mut TcpStream,
    queue: &Receiver<Local>,
    console: &mut impl Write,
    probe: &mut SizeProbe,
) -> std::io::Result<i32> {
    // Whatever the port file named has to say *something* first (see
    // `FIRST_WORD_TIMEOUT`). Only the first message is on a clock: after that
    // an idle session is an idle session, and waiting is the whole job.
    // An absolute deadline, not one per wait: a console that chatters -- the
    // probe's own answer, or a user typing -- must not be able to postpone it.
    let mut first_word_by = Some(Instant::now() + FIRST_WORD_TIMEOUT);
    loop {
        let event = match first_word_by {
            None => match queue.recv() {
                Ok(event) => event,
                Err(_) => break,
            },
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(no_answer());
                }
                match queue.recv_timeout(left) {
                    Ok(event) => event,
                    // A timeout is not a clock (`proto::timed_out`): go round and
                    // ask the clock. Trusting this one would take a working
                    // client down on a spurious wakeup, which is worse than the
                    // hang it is here to prevent.
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(_) => break,
                }
            }
        };
        if matches!(event, Local::FromServer(_) | Local::ServerGone) {
            first_word_by = None;
        }
        match event {
            Local::Console(bytes) => {
                let mut forward = Vec::new();
                if let Some((rows, cols)) = probe.filter(&bytes, &mut forward) {
                    send(server, &ToServer::Resize { rows, cols })?;
                }
                if !forward.is_empty() {
                    send(server, &ToServer::Input(forward))?;
                }
            }
            // The console is over, but the session is not: say so, so a shell
            // reading a script ends, and keep painting until the server says
            // the work is done.
            Local::ConsoleEof => send(server, &ToServer::EndInput)?,
            Local::FromServer(ToClient::Write(bytes)) => {
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
    let mut server = match try_connect() {
        Some(server) => server,
        // No server is not an error for a question about sessions: there are
        // none, and saying so is the answer.
        None => return Ok(0),
    };
    send(&mut server, &request)?;

    // The same deadline as an attaching client's, and for the same reason: what
    // answered on that port may not be a server at all (`FIRST_WORD_TIMEOUT`).
    // A question client has nowhere to show a hang, so it would simply never
    // return -- which is how `rmux ls` in a script becomes a stuck script.
    let _ = server.set_read_timeout(Some(FIRST_WORD_TIMEOUT));
    let mut frames = Frames::new();
    let mut buf = [0_u8; 4096];
    loop {
        let read = match server.read(&mut buf) {
            Ok(read) => read,
            Err(err) if proto::timed_out(&err) => return Err(no_answer()),
            Err(err) => return Err(err),
        };
        if read == 0 {
            return Ok(0);
        }
        frames.feed(&buf[..read]);
        while let Some(message) = frames.take::<ToClient>() {
            match message {
                Some(ToClient::Sessions(lines)) => {
                    for line in lines {
                        println!("{line}");
                    }
                    return Ok(0);
                }
                Some(ToClient::Done) => return Ok(0),
                Some(ToClient::Failed(why)) => {
                    eprintln!("rmux: {why}");
                    return Ok(1);
                }
                _ => {}
            }
        }
    }
}

fn send(server: &mut TcpStream, message: &ToServer) -> std::io::Result<()> {
    server.write_all(&proto::encode(message))?;
    server.flush()
}

fn read_server(mut server: TcpStream, events: Sender<Local>) {
    let mut frames = Frames::new();
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

/// The console reader thread: rmux's own stdin, in whatever chunks arrive.
///
/// The serial console hands sys-tty one byte at a time, so a sequence arrives
/// split at unpredictable points (§8.3). Nothing here cares: the bytes are
/// relayed, and the only thing that must be recognized -- the size probe's
/// answer -- is buffered by [`SizeProbe`].
fn read_console(events: Sender<Local>) {
    let mut console = std::io::stdin().lock();
    let mut buf = [0_u8; 1024];
    loop {
        let read = match console.read(&mut buf) {
            Ok(0) => break,
            Ok(read) => read,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if events.send(Local::Console(buf[..read].to_vec())).is_err() {
            return;
        }
    }
    let _ = events.send(Local::ConsoleEof);
}

fn restore_console() {
    sys::RawConsole::restore();
    let mut console = std::io::stdout().lock();
    let _ = console.write_all(CONSOLE_LEAVE);
    let _ = console.flush();
}

// ---- finding, or starting, the server ---------------------------------------

/// What to say when the port file named something that is not an rmux server.
///
/// The file is removed on the way out, so the next run starts a server of its
/// own rather than finding the same dead end. That is the difference between one
/// confusing failure and every later `rmux` failing the same way.
fn no_answer() -> std::io::Error {
    let _ = std::fs::remove_file(sys::port_file());
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "the rmux server did not answer; try again",
    )
}

fn try_connect() -> Option<TcpStream> {
    let port: u16 = std::fs::read_to_string(sys::port_file())
        .ok()?
        .trim()
        .parse()
        .ok()?;
    TcpStream::connect(("127.0.0.1", port)).ok()
}

/// Connect to the server, starting one if there is none.
///
/// Exactly one client starts a server; the rest wait for it. The lock file is
/// what makes that true: two servers would mean two session lists and one port
/// file to name them by, so the loser of that race would hold sessions nobody
/// could ever reach.
fn connect_or_start() -> std::io::Result<TcpStream> {
    if let Some(server) = try_connect() {
        return Ok(server);
    }

    let lock = sys::port_file().with_extension("lock");
    // rmux makes its own scratch space on Motor (`sys::port_file`), and the
    // lock lives in it: without this the lock cannot be created either, and a
    // client would read that failure as "somebody else is starting one".
    if let Some(parent) = lock.parent() {
        let _ = std::fs::create_dir_all(parent);
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

    /// The size the client opens with, when the console answers `after` a delay.
    ///
    /// The delay is the point: a report already sitting in the queue would be
    /// picked up by a client that does not wait at all, so a test that pre-loads
    /// it holds nothing. This one is only satisfied by waiting.
    fn settled(after: Duration, console: &[&[u8]]) -> ((u16, u16), Early) {
        let (events, queue) = channel();
        let sends: Vec<Vec<u8>> = console.iter().map(|bytes| bytes.to_vec()).collect();
        // Kept alive until `settle_size` has returned, so that what ends the wait
        // is the deadline rather than a closed channel.
        let held = events.clone();
        std::thread::spawn(move || {
            std::thread::sleep(after);
            for bytes in sends {
                let _ = events.send(Local::Console(bytes));
            }
        });

        let mut early = Early::default();
        let mut probe = SizeProbe::awaiting();
        let size = settle_size(FALLBACK_CONSOLE_SIZE, &mut probe, &queue, &mut early);
        drop(held);
        (size, early)
    }

    /// Comfortably inside the window, and comfortably not instant.
    const SOON: Duration = Duration::from_millis(40);

    #[test]
    fn the_first_frame_waits_for_the_console_to_say_how_big_it_is() {
        // Otherwise it is painted at the fallback and then again at the real
        // size: a full repaint of the whole screen, twice, on a console where
        // that costs about a second (§6.3).
        let (size, early) = settled(SOON, &[b"\x1b[45;160R"]);
        assert_eq!(size, (45, 160));
        assert!(early.typed.is_empty(), "the report reached the pane");
    }

    #[test]
    fn a_console_that_never_answers_costs_the_window_and_no_more() {
        // rmux must never hang on a console with nothing on the other end that
        // answers `CPR` (§3.2) -- the reason rush's discipline exists at all.
        let started = Instant::now();
        let (size, _) = settled(SIZE_ANSWER_TIMEOUT * 10, &[]);
        assert_eq!(size, FALLBACK_CONSOLE_SIZE);
        assert!(
            started.elapsed() < SIZE_ANSWER_TIMEOUT * 4,
            "waited {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn what_was_typed_while_the_terminal_answered_is_kept_in_order() {
        // A user who types before the first frame is typing at the session.
        let (size, early) = settled(SOON, &[b"ab", b"\x1b[45;160R"]);
        assert_eq!(size, (45, 160));
        assert_eq!(early.typed, b"ab");
    }
}
