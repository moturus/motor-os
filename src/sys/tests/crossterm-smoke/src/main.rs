//! Exercises the Motor OS backend of `crossterm` on the real thing.
//!
//! Everything here is scripted from `src/tests/full-test.sh`: a subcommand per
//! question, one line of output per answer, so an assertion can be a substring
//! match. What it is checking is the part of the port that no host test can
//! reach — a console that is a stdio pipe rather than a pty, mode 2048 with an
//! `ESC[6n` fallback in place of `TIOCGWINSZ`, and input that arrives a byte at
//! a time.
//!
//! Run it under `rmux` and over plain `ssh`: those are the two terminals Motor
//! OS has, and they differ in exactly the ways this port cares about.

use std::io::{self, Write};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode, size,
};
use crossterm::{cursor, execute};

/// How long the key and size subcommands wait for a driver that may say nothing.
const SESSION: Duration = Duration::from_secs(5);

/// One pass of the event loop. Every wait is bounded: Motor OS does not wake a
/// parked poll when the far end of stdin closes, and only reports it when the
/// next wait starts, so an unbounded `event::read()` would sleep through the end
/// of its own session.
const TICK: Duration = Duration::from_millis(200);

fn main() {
    let command = std::env::args().nth(1).unwrap_or_default();

    let result = match command.as_str() {
        "keys" => keys(),
        "size" => report_size(),
        "screen" => screen(),
        "panic" => screen_then_panic(),
        "ctrl-c" => ctrl_c(),
        other => {
            eprintln!("usage: crossterm-smoke keys|size|screen|panic|ctrl-c (got {other:?})");
            std::process::exit(2);
        }
    };

    if let Err(error) = result {
        eprintln!("crossterm-smoke {command}: {error}");
        std::process::exit(1);
    }
}

/// Confirms that the explicit adapter claims the process handler exactly once.
fn ctrl_c() -> io::Result<()> {
    event::enable_ctrl_c_events()?;
    println!("ctrl-c=enabled");

    if event::enable_ctrl_c_events().is_ok() {
        return Err(io::Error::other("a second Ctrl+C handler was accepted"));
    }
    println!("ctrl-c=already-enabled");
    Ok(())
}

/// Decodes whatever the driver types and prints one line per event.
///
/// The interesting inputs are Enter, which reaches a program here as CR LF and
/// must still be one key, and an escape sequence sent a byte at a time, which
/// must still be one key rather than `Esc` and its letters.
fn keys() -> io::Result<()> {
    event::enable_ctrl_c_events()?;
    // A real application enables raw mode; on Motor OS that changes nothing
    // about the console, but it does change how a bare `\n` is decoded, which is
    // the whole point of the CR LF check below.
    enable_raw_mode()?;
    println!("ready");
    io::stdout().flush()?;

    let outcome = read_keys();
    disable_raw_mode()?;
    println!("{outcome}");
    Ok(())
}

fn read_keys() -> String {
    let deadline = Instant::now() + SESSION;

    while Instant::now() < deadline {
        match event::poll(TICK) {
            Ok(false) => continue,
            // A read error here is the session ending, which is how this command
            // normally finishes: the driver closes the pipe.
            Err(error) => return format!("end={:?}", error.kind()),
            Ok(true) => {}
        }

        let event = match event::read() {
            Ok(event) => event,
            Err(error) => return format!("end={:?}", error.kind()),
        };

        println!("{}", describe(&event));
        let _ = io::stdout().flush();

        if let Event::Key(key) = event
            && key.code == KeyCode::Char('q')
        {
            return "end=quit".to_string();
        }
    }

    "end=timeout".to_string()
}

/// A one-line rendering of an event, chosen so that an assertion can be a plain
/// substring: `key=Enter`, `key=Char('h')`, `key=Up`, `resize=80x23`.
fn describe(event: &Event) -> String {
    match event {
        Event::Key(key) if key.kind != KeyEventKind::Press => {
            format!("key-{:?}={:?}", key.kind, key.code)
        }
        Event::Key(key) if key.modifiers.is_empty() => format!("key={:?}", key.code),
        Event::Key(key) => format!("key={:?}+{:?}", key.code, key.modifiers),
        Event::Resize(columns, rows) => format!("resize={columns}x{rows}"),
        other => format!("event={other:?}"),
    }
}

/// Prints the size before anything has been asked of the terminal, then runs
/// the event loop long enough for mode negotiation or a fallback size probe,
/// then prints it again.
///
/// Inside an `rmux` pane the two differ only if the environment lied; over plain
/// non-pty `ssh`, the event source emits no terminal queries and the second
/// reading is the same 80x24 fallback as the first.
fn report_size() -> io::Result<()> {
    let (columns, rows) = size()?;
    println!("size={columns}x{rows}");
    io::stdout().flush()?;

    // Negotiation and probing happen inside the event loop, because that is
    // where the one stdin that a reply could arrive on is being read.
    let deadline = Instant::now() + Duration::from_millis(2500);
    while Instant::now() < deadline {
        match event::poll(TICK) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                println!("end={:?}", error.kind());
                break;
            }
        }

        match event::read() {
            Ok(event) => println!("{}", describe(&event)),
            Err(error) => {
                println!("end={:?}", error.kind());
                break;
            }
        }
        io::stdout().flush()?;
    }

    let (columns, rows) = size()?;
    println!("size-after={columns}x{rows}");
    Ok(())
}

/// Takes the alternate screen and gives it back, which is the one thing every
/// full-screen application does first and last.
fn screen() -> io::Result<()> {
    install_panic_hook();

    execute!(io::stdout(), EnterAlternateScreen, cursor::Hide)?;
    enable_raw_mode()?;

    print!("on-alternate-screen");
    io::stdout().flush()?;

    disable_raw_mode()?;
    execute!(io::stdout(), cursor::Show, LeaveAlternateScreen)?;
    println!("screen=restored");
    Ok(())
}

/// Panics with the screen taken, to show that the hook gives it back.
///
/// Motor OS builds with `panic = "abort"`, so no destructor runs on the way out:
/// without a panic hook a crash would leave the terminal on the alternate screen
/// with its cursor hidden, and the user with no prompt.
fn screen_then_panic() -> io::Result<()> {
    install_panic_hook();

    execute!(io::stdout(), EnterAlternateScreen, cursor::Hide)?;
    enable_raw_mode()?;

    panic!("crossterm-smoke: deliberate panic with the screen taken");
}

fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), cursor::Show, LeaveAlternateScreen);
        let _ = io::stdout().flush();
        previous(info);
    }));
}
