//! Taking the terminal over, and giving it back.
//!
//! All of it is crossterm's, on both platforms red runs on. Motor OS has no
//! termios, no ioctl and no signals: a console there is always raw, its size is
//! whatever the last `ESC[6n` was answered with, and nothing pushes a resize at
//! a program — crossterm's Motor OS backend is where those facts live now, so
//! this file is just what red asks of it.

use std::io::{self, Write};

use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use crossterm::{cursor, execute};

/// The size assumed when there is no terminal to ask — under `cargo test`, or
/// with stdout redirected to a file.
const FALLBACK_SIZE: (usize, usize) = (24, 80);

pub struct TerminalGuard;

impl TerminalGuard {
    pub fn new() -> Self {
        enter();

        // `panic = "abort"` means `Drop` does not run on a panic, so the hook is
        // what gives the terminal back — before the message, or the user reads
        // it on the alternate screen and then loses it with the screen.
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            leave();
            default_hook(info);
        }));

        TerminalGuard
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        leave();
    }
}

/// Raw mode and the alternate screen, so that leaving restores whatever the
/// user was looking at.
///
/// Bracketed paste goes off with them: red reads keys one at a time and has no
/// use for a paste being wrapped in markers it would then type out.
fn enter() {
    let _ = enable_raw_mode();
    let _ = execute!(io::stdout(), EnterAlternateScreen, DisableBracketedPaste);
}

/// Put back everything [`enter`] took. Safe to call twice — the panic hook and
/// the guard both run on the ordinary path out.
fn leave() {
    let _ = execute!(
        io::stdout(),
        cursor::Show,
        EnableBracketedPaste,
        LeaveAlternateScreen
    );
    let _ = disable_raw_mode();
    let _ = io::stdout().flush();
}

/// The terminal's size as rows and columns.
///
/// On Motor OS this is the last answer to the `ESC[6n` crossterm asks on a clock
/// while red waits for a key, falling back to `$LINES`/`$COLUMNS` (which rmux
/// sets for a pane's child) and then to 80x24. It cannot block and it asks
/// nothing of the terminal here — a console that never answers costs nothing,
/// where red's old startup probe spent a tenth of a second finding that out.
///
/// `window_size` rather than `size` on purpose: crossterm's host `size()` falls
/// back to *spawning* `tput` when the ioctl has nothing to say, which under
/// `cargo test` would be a process per editor.
pub fn get_terminal_size() -> (usize, usize) {
    match crossterm::terminal::window_size() {
        Ok(size) if size.rows > 0 && size.columns > 0 => {
            (usize::from(size.rows), usize::from(size.columns))
        }
        _ => FALLBACK_SIZE,
    }
}
