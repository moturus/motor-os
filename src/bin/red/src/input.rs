use std::io::{self, Read};
use std::sync::OnceLock;
use std::sync::mpsc::{channel, Receiver};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::cell::Cell;

#[derive(Debug, PartialEq, Clone)]
pub enum Key {
    Char(char),
    Esc,
    Backspace,
    Delete,
    Enter,
    Tab,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Ctrl(char),
    TerminalResponse(usize, usize), // (rows, cols)
    None, // Timeout or Error
}

thread_local! {
    static PENDING_BYTE: Cell<Option<u8>> = Cell::new(None);
}

static INPUT_RECEIVER: OnceLock<Mutex<Receiver<u8>>> = OnceLock::new();

fn get_input_receiver() -> &'static Mutex<Receiver<u8>> {
    INPUT_RECEIVER.get_or_init(|| {
        let (sender, receiver) = channel();
        thread::spawn(move || {
            let mut stdin = io::stdin();
            let mut buf = [0u8; 1];
            loop {
                match stdin.read(&mut buf) {
                    Ok(1) => {
                        if sender.send(buf[0]).is_err() {
                            break; // Main thread hung up (receiver dropped)
                        }
                    }
                    _ => {
                        // EOF or Error on stdin. Exit the thread.
                        break;
                    }
                }
            }
        });
        Mutex::new(receiver)
    })
}

pub fn read_key() -> Key {
    let rx = get_input_receiver().lock().unwrap();

    let b = if let Some(pb) = PENDING_BYTE.with(|p| p.take()) {
        pb
    } else {
        match rx.recv() {
            Ok(byte) => byte,
            Err(_) => return Key::None,
        }
    };

    if b == b'\x1b' {
        // Check if there is a subsequent byte (escape sequence starting)
        // We use 100ms timeout as requested.
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(b'[') => {
                // Read sequence payload until a terminating character
                let mut esc_buf = Vec::new();
                // We read with a timeout to prevent hanging on malformed sequences
                loop {
                    match rx.recv_timeout(Duration::from_millis(50)) {
                        Ok(c) => {
                            esc_buf.push(c);
                            if c.is_ascii_alphabetic() || c == b'~' {
                                break;
                            }
                        }
                        Err(_) => break, // Timeout, assume end of sequence or malformed
                    }
                }

                if esc_buf.is_empty() {
                    return Key::Esc;
                }

                let term_char = esc_buf[esc_buf.len() - 1];
                let payload = &esc_buf[..esc_buf.len() - 1];

                match term_char {
                    b'A' => Key::Up,
                    b'B' => Key::Down,
                    b'C' => Key::Right,
                    b'D' => Key::Left,
                    b'H' => Key::Home,
                    b'F' => Key::End,
                    b'~' => {
                        let s = String::from_utf8_lossy(payload);
                        match s.as_ref() {
                            "1" | "7" => Key::Home,
                            "3" => Key::Delete,
                            "4" | "8" => Key::End,
                            "5" => Key::PageUp,
                            "6" => Key::PageDown,
                            _ => Key::Esc,
                        }
                    }
                    b'R' => {
                        // Cursor Position Report: \x1b[{row};{col}R
                        let s = String::from_utf8_lossy(payload);
                        let mut parts = s.split(';');
                        if let (Some(r_str), Some(c_str)) = (parts.next(), parts.next()) {
                            if let (Ok(r), Ok(c)) = (r_str.parse::<usize>(), c_str.parse::<usize>()) {
                                return Key::TerminalResponse(r, c);
                            }
                        }
                        Key::Esc
                    }
                    _ => Key::Esc,
                }
            }
            Ok(next_byte) => {
                // Esc followed by something else (e.g. Alt+key).
                // Save it for next time and return Esc.
                PENDING_BYTE.with(|p| p.set(Some(next_byte)));
                Key::Esc
            }
            Err(_) => {
                // Timeout: it was just a standalone Esc
                Key::Esc
            }
        }
    } else if b == 127 {
        Key::Backspace
    } else if b == b'\r' || b == b'\n' {
        if b == b'\r' {
            // Coalesce \r\n
            if let Ok(next) = rx.recv_timeout(Duration::from_millis(10)) {
                if next != b'\n' {
                    PENDING_BYTE.with(|p| p.set(Some(next)));
                }
            }
        }
        Key::Enter
    } else if b == 8 {
        Key::Backspace
    } else if b == 9 {
        Key::Tab
    } else if b >= 1 && b <= 26 {
        Key::Ctrl((b - 1 + b'a') as char)
    } else {
        // Parse UTF-8 character
        if let Some(ch) = read_utf8_char(&rx, b) {
            Key::Char(ch)
        } else {
            Key::None
        }
    }
}

fn read_utf8_char(rx: &Receiver<u8>, first_byte: u8) -> Option<char> {
    let mut buf = vec![first_byte];
    let len = if first_byte & 0x80 == 0 {
        1
    } else if first_byte & 0xE0 == 0xC0 {
        2
    } else if first_byte & 0xF0 == 0xE0 {
        3
    } else if first_byte & 0xF8 == 0xF0 {
        4
    } else {
        return None;
    };

    while buf.len() < len {
        // Use a timeout to avoid hanging if the UTF-8 sequence is cut off
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(next) => buf.push(next),
            Err(_) => return None,
        }
    }

    String::from_utf8(buf).ok()?.chars().next()
}
