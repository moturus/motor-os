use std::io::{self, Write, Read, IsTerminal};
use std::process::Command;
use std::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};

// Global flag to track if raw mode is active.
// Used to prevent blocking on stdin reads in environments where raw mode is not active (like cargo test).
static RAW_MODE_ENABLED: AtomicBool = AtomicBool::new(false);

pub struct TerminalGuard;

impl TerminalGuard {
    pub fn new() -> Self {
        enable_raw_mode();
        // Enter alternate screen buffer and disable bracketed paste mode
        print!("\x1b[?1049h\x1b[?2004l");
        let _ = io::stdout().flush();

        // Set panic hook to restore terminal on panic
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            // Exit alternate screen buffer and re-enable bracketed paste mode
            print!("\x1b[?1049l\x1b[?2004h");
            disable_raw_mode();
            let _ = io::stdout().flush();
            default_hook(info);
        }));

        TerminalGuard
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Exit alternate screen buffer and re-enable bracketed paste mode
        print!("\x1b[?1049l\x1b[?2004h");
        disable_raw_mode();
        let _ = io::stdout().flush();
    }
}

fn enable_raw_mode() {
    let _ = Command::new("stty")
        .arg("raw")
        .arg("-echo")
        .arg("min")
        .arg("1")
        .arg("time")
        .arg("0")
        .status();
    RAW_MODE_ENABLED.store(true, Ordering::SeqCst);
}

fn disable_raw_mode() {
    let _ = Command::new("stty")
        .arg("-raw")
        .arg("echo")
        .status();
    RAW_MODE_ENABLED.store(false, Ordering::SeqCst);
}

pub fn get_terminal_size() -> Option<(usize, usize)> {
    // If raw mode is not enabled (e.g. during cargo test), do not query as stdin will block!
    if !RAW_MODE_ENABLED.load(Ordering::SeqCst) {
        return Some((24, 80));
    }

    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Some((24, 80));
    }

    // 1. Hide cursor and write ANSI escape query sequence to stdout
    // We hide the cursor (\x1b[?25l) to prevent visible flashing at the bottom-right.
    if io::stdout().write_all(b"\x1b[?25l\x1b[9999;9999H\x1b[6n").is_err() {
        let _ = io::stdout().write_all(b"\x1b[?25h"); // Ensure shown on error
        return None;
    }
    if io::stdout().flush().is_err() {
        let _ = io::stdout().write_all(b"\x1b[?25h");
        return None;
    }

    // 2. Read response from stdin: \x1b[{row};{col}R
    let mut buf = Vec::new();
    let mut temp = [0u8; 1];
    let mut stdin = io::stdin();
    
    let mut attempts = 0;
    let mut success = false;
    while attempts < 10 {
        match stdin.read(&mut temp) {
            Ok(1) => {
                let b = temp[0];
                buf.push(b);
                if b == b'R' {
                    success = true;
                    break;
                }
            }
            Ok(0) => {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => break,
        }
    }

    // 3. ALWAYS restore cursor visibility before returning!
    let _ = io::stdout().write_all(b"\x1b[?25h");
    let _ = io::stdout().flush();

    if !success {
        return None;
    }

    // 4. Parse the response from the buffer
    let buf_str = String::from_utf8_lossy(&buf);
    let esc_idx = buf_str.rfind("\x1b[")?;
    let r_idx = buf_str.rfind('R')?;
    
    if esc_idx >= r_idx {
        return None;
    }

    let payload = &buf_str[esc_idx + 2..r_idx]; // "row;col"
    let mut parts = payload.split(';');
    let rows: usize = parts.next()?.parse().ok()?;
    let cols: usize = parts.next()?.parse().ok()?;

    Some((rows, cols))
}
