use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::Mutex;

use crate::autocomplete;

pub trait TermImpl: Send + Sync {
    fn make_raw(&mut self) {}
    fn make_cooked(&mut self) {}
    fn on_exit(&mut self) {}
}

#[cfg(unix)]
use crate::term_impl_unix as term_impl;

#[cfg(not(unix))]
mod term_impl {
    pub use super::PipedTerminal as ArchTerm;
}

pub struct PipedTerminal {}

impl PipedTerminal {
    pub fn new() -> Self {
        Self {}
    }
}

impl TermImpl for PipedTerminal {}

#[derive(Clone, PartialEq, Eq)]
enum ProcessingMode {
    Normal,
    Escape(Vec<char>),
    History(usize),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EscapesIn {
    UpArrow,
    DownArrow,
    LeftArrow,
    RightArrow,
    Backspace,
    Delete,
    Home,
    End,
    Tab,
    CtrlC,
    CtrlD,
}

enum ProcessedChar {
    Regular(char), // Normal character to add;
    Newline,       // Newline: finish processing the line;
    Continue,      // Continue processing input;
    Clear,         // Clear current input (e.g. an escape sequence not recognized);
    Escape(EscapesIn),
}

struct Term {
    history: Vec<String>,
    mode: ProcessingMode,
    prev_mode: ProcessingMode,
    line: String,
    typed_line: String, // What was typed before an Up arrow was hit.
    line_start: u32,    // Where the input starts after the prompt.
    current_pos: u32,   // Relative to line start.

    incoming: VecDeque<u8>,

    term_impl: Box<dyn TermImpl>,
    escapes_in: std::collections::BTreeMap<&'static [char], EscapesIn>,
    debug: bool,
}

impl Term {
    fn new(piped: bool) -> Self {
        let mut escapes_in: std::collections::BTreeMap<&'static [char], EscapesIn> =
            std::collections::BTreeMap::new();

        escapes_in.insert(&['\u{1B}', '\u{5B}', '\u{41}'], EscapesIn::UpArrow);
        escapes_in.insert(&['\u{1B}', '\u{5B}', '\u{42}'], EscapesIn::DownArrow);
        escapes_in.insert(&['\u{1B}', '\u{5B}', '\u{43}'], EscapesIn::RightArrow);
        escapes_in.insert(&['\u{1B}', '\u{5B}', '\u{44}'], EscapesIn::LeftArrow);
        escapes_in.insert(&['\u{1B}', '\u{5B}', '\u{33}', '\u{7E}'], EscapesIn::Delete);
        escapes_in.insert(&['\u{1B}', '\u{5B}', '\u{48}'], EscapesIn::Home);
        escapes_in.insert(&['\u{1B}', '\u{5B}', '\u{46}'], EscapesIn::End);

        Self {
            history: vec![],
            mode: ProcessingMode::Normal,
            prev_mode: ProcessingMode::Normal,
            line: String::new(),
            typed_line: String::new(),
            term_impl: if piped {
                Box::new(PipedTerminal::new())
            } else {
                Box::new(term_impl::ArchTerm::new())
            },
            escapes_in,
            line_start: 0,
            current_pos: 0,
            incoming: VecDeque::new(),

            debug: false,
        }
    }

    fn next_char(&mut self) -> char {
        if self.incoming.is_empty() {
            self.read_new_bytes();
        }
        let mut buf = vec![];
        while let Some(b) = self.incoming.pop_front() {
            buf.push(b);
            match std::str::from_utf8(&buf) {
                Ok(str) => {
                    // we're sure there's only 1 character, as we grow the buffer
                    let char = str.chars().next().unwrap();
                    return char;
                }
                Err(error) => {
                    if let Some(idx) = error.error_len() {
                        eprintln!("stdin(): invalid UTF-8 sequence at {idx}");
                        self.term_impl.make_raw();
                        std::process::exit(1);
                    }
                }
            }
        }

        eprintln!("stdin() EOF");
        self.term_impl.make_raw();
        std::process::exit(1);
    }

    /// obtain new bytes from stdin to the buffer
    fn read_new_bytes(&mut self) {
        let mut buf = [0_u8; 16];
        let sz = match std::io::stdin().read(&mut buf) {
            Ok(sz) => sz,
            Err(err) => {
                eprintln!("stdin() read failed with: {err:?}");
                self.term_impl.make_raw();
                std::process::exit(1);
            }
        };
        if sz == 0 {
            // stdlib sometimes converts stdio errors into zero reads
            eprintln!("stdin() EOF");
            self.term_impl.make_raw();
            std::process::exit(1);
        }
        assert!(sz > 0);
        self.incoming.extend(&buf[0..sz]);
    }

    fn process_next_char(&mut self, c: char) -> ProcessedChar {
        match &self.mode {
            ProcessingMode::Normal | ProcessingMode::History(_) => {
                match c {
                    '\u{3}' => ProcessedChar::Escape(EscapesIn::CtrlC),
                    '\u{4}' => 
                        ProcessedChar::Escape(EscapesIn::CtrlD),
                    '\u{8}' | '\u{7F}' /* BS */ => {
                        ProcessedChar::Escape(EscapesIn::Backspace)
                    },
                    '\u{D}' /* 13 | 10 */ /* CR/NL */ => {
                        ProcessedChar::Newline
                    }
                    '\u{9}' /* TAB */ => {
                        ProcessedChar::Escape(EscapesIn::Tab)
                    }
                    '\u{10}' => ProcessedChar::Continue, // Avoid double newlines
                    '\u{1B}' /* ESC */ => {
                        self.prev_mode = self.mode.clone();
                        self.mode = ProcessingMode::Escape(vec!['\u{1B}']);
                        ProcessedChar::Continue
                    }
                    _ => {
                        ProcessedChar::Regular(c)
                    }
                    // 128.. => {
                    //     // Ignore non-ascii bytes for now.
                    //     ProcessedChar::Continue
                    // }
                    // _ => {
                    //     self.debug_log(format!("unrecognized char: 0x{c:x}").as_str());
                    //     self.write(&[7_u8]);  // Beep.
                    //     ProcessedChar::Continue
                    // }
                }
            }
            ProcessingMode::Escape(v) => {
                let mut candidate_key = v.clone();
                candidate_key.push(c);

                if v.len() == 1 {
                    match c {
                        '[' => {
                            self.mode = ProcessingMode::Escape(candidate_key);
                            return ProcessedChar::Continue;
                        }
                        _ => {
                            // There are no recognized keys that start with anything other than "\x1b[".
                            self.debug_log(
                                format!("unknown escape sequence: 0x{:x?}", &candidate_key[0..])
                                    .as_str(),
                            );
                            self.mode = self.prev_mode.clone();
                            return ProcessedChar::Clear;
                        }
                    }
                }

                match c {
                    '0'..='9' | ';' => {
                        // Continue on numbers and ';'.
                        self.mode = ProcessingMode::Escape(candidate_key);
                        return ProcessedChar::Continue;
                    }
                    _ => {
                        // Break otherwise.
                    }
                }

                match self.escapes_in.get(&candidate_key[0..]) {
                    Some(val) => {
                        self.mode = self.prev_mode.clone();
                        ProcessedChar::Escape(*val)
                    }
                    None => {
                        // Not found.
                        self.debug_log(
                            format!("unknown escape sequence: 0x{:x?}", &candidate_key[0..])
                                .as_str(),
                        );
                        self.mode = self.prev_mode.clone();
                        ProcessedChar::Clear
                    }
                }
            }
        }
    }

    fn readline(&mut self) -> Option<String> {
        self.term_impl.make_raw();
        self.start_line();

        if !self.history.is_empty() {
            let msg = format!("cmd: {}", self.history.last().as_ref().unwrap());
            self.debug_log(msg.as_str());
        }

        loop {
            let char = self.next_char();
            // println!("got char U+{:04X}", char as u32);
            match self.process_next_char(char) {
                ProcessedChar::Regular(c) => {
                    match self.mode {
                        ProcessingMode::Normal => {}
                        ProcessingMode::Escape(_) | ProcessingMode::History(_) => {
                            self.mode = ProcessingMode::Normal;
                            self.show_cursor();
                        }
                    }
                    assert!(self.current_pos <= (self.line.chars().count() as u32));
                    if self.current_pos == (self.line.chars().count() as u32) {
                        self.line.push(c);
                        let mut buf = [0_u8;4];
                        self.write(c.encode_utf8(&mut buf).as_bytes());
                    } else {
                        self.line.insert(self.current_pos as usize, c);
                        self.redraw_line();
                        self.write(&[0x1b, b'[', b'1', b'C']); // Move right.
                    }
                    self.current_pos += 1;
                    self.debug_log(format!("got c {c}").as_str());
                }
                ProcessedChar::Newline => {
                    match self.mode {
                        ProcessingMode::Normal => {}
                        ProcessingMode::Escape(_) | ProcessingMode::History(_) => {
                            self.mode = ProcessingMode::Normal;
                            self.show_cursor();
                        }
                    }
                    let cmd = self.line.trim().to_owned();
                    if cmd.is_empty() {
                        self.write("\r\n".as_bytes());
                        self.start_line();
                        break;
                    }
                    if self.process_locally(cmd.as_str()) {
                        break;
                    } else {
                        self.write("\r\n".as_bytes());
                        self.term_impl.make_cooked();
                        self.maybe_add_to_history(cmd.as_str());
                        return Some(cmd);
                    }
                }
                ProcessedChar::Continue => {}
                ProcessedChar::Escape(e) => match e {
                    EscapesIn::UpArrow => match self.mode {
                        ProcessingMode::Normal => {
                            if !self.history.is_empty() {
                                self.mode = ProcessingMode::History(self.history.len() - 1);
                                self.show_cursor();
                                let prev = self.history.last().unwrap().clone();
                                if self.line == prev {
                                    continue;
                                }
                                self.typed_line = self.line.clone();
                                self.line = prev;
                                self.current_pos = self.line.chars().count() as u32;
                                self.redraw_line();
                            } else {
                                self.beep();
                            }
                        }
                        ProcessingMode::Escape(_) => {
                            panic!("UpArrow: unexpected 'Escape' mode.");
                        }
                        ProcessingMode::History(idx) => {
                            if idx > 0 {
                                self.mode = ProcessingMode::History(idx - 1);
                                self.line = self.history[idx - 1].clone();
                                self.current_pos = self.line.chars().count() as u32;
                                self.redraw_line();
                            } else {
                                self.beep();
                            }
                        }
                    },
                    EscapesIn::DownArrow => match self.mode {
                        ProcessingMode::Normal => self.beep(),
                        ProcessingMode::Escape(_) => {
                            panic!("DownArrow: unexpected 'Escape' mode.");
                        }
                        ProcessingMode::History(idx) => {
                            if idx == self.history.len() {
                                self.beep(); // typed_line
                            } else {
                                self.mode = ProcessingMode::History(idx + 1);
                                if idx == (self.history.len() - 1) {
                                    self.line = self.typed_line.clone();
                                } else {
                                    self.line = self.history[idx + 1].clone();
                                }
                                self.current_pos = self.line.chars().count() as u32;
                                self.redraw_line();
                            }
                        }
                    },
                    EscapesIn::LeftArrow => {
                        if self.current_pos == 0 {
                            self.beep();
                            continue;
                        }
                        self.current_pos -= 1;
                        self.write(&[0x1b, b'[', b'1', b'D']);
                        continue;
                    }
                    EscapesIn::RightArrow => {
                        if self.current_pos >= (self.line.chars().count() as u32) {
                            self.beep();
                            continue;
                        }
                        self.write(&[0x1b, b'[', b'1', b'C']);
                        self.current_pos += 1;
                        continue;
                    }
                    EscapesIn::Backspace => {
                        match self.mode {
                            ProcessingMode::Normal => {}
                            ProcessingMode::Escape(_) | ProcessingMode::History(_) => {
                                self.mode = ProcessingMode::Normal;
                                self.show_cursor();
                            }
                        }
                        if self.current_pos > 0 {
                            self.current_pos -= 1;
                            self.line.remove(self.current_pos as usize);
                            self.write(&[0x1b, b'[', b'1', b'D']);
                            self.redraw_line();
                        } else {
                            self.beep();
                        }
                        continue;
                    }
                    EscapesIn::Delete => {
                        match self.mode {
                            ProcessingMode::Normal => {}
                            ProcessingMode::Escape(_) | ProcessingMode::History(_) => {
                                self.mode = ProcessingMode::Normal;
                                self.show_cursor();
                            }
                        }
                        if self.current_pos < (self.line.chars().count() as u32) {
                            self.line.remove(self.current_pos as usize);
                            self.redraw_line();
                        } else {
                            self.beep();
                        }
                    }
                    EscapesIn::Home => {
                        if self.current_pos > 0 {
                            self.current_pos = 0;
                            let (row, _) = self.get_cursor_pos();
                            self.move_cursor(row, self.line_start);
                        }
                    }
                    EscapesIn::End => {
                        if self.current_pos < (self.line.chars().count() as u32) {
                            self.current_pos = self.line.chars().count() as u32;
                            let (row, _) = self.get_cursor_pos();
                            self.move_cursor(row, self.line_start + self.current_pos);
                        }
                    }
                    EscapesIn::Tab => {
                        match autocomplete::try_complete(&self.line[..]) {
                            Some(suggestion) => {
                                self.typed_line = self.line.clone();
                                self.line = suggestion;
                                self.current_pos = self.line.chars().count() as u32;
                                self.redraw_line();
                            }
                            None => self.beep(),
                        }
                    }
                    EscapesIn::CtrlC => {
                        match self.mode {
                            ProcessingMode::Normal => {}
                            ProcessingMode::Escape(_) | ProcessingMode::History(_) => {
                                self.mode = ProcessingMode::Normal;
                                self.show_cursor();
                            }
                        }
                        self.write("^C\n\r".as_bytes());
                        self.start_line();
                    }
                    EscapesIn::CtrlD => {
                        self.term_impl.make_raw();
                        std::process::exit(0);
                    }
                },
                ProcessedChar::Clear => {
                    self.beep();
                    break;
                }
            }
        } // loop

        None
    }

    fn beep(&mut self) {
        self.write(&[7_u8]); // Beep.
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(bytes).unwrap();
        stdout.flush().unwrap();
    }

    fn start_line(&mut self) {
        let col = prompt();
        self.line.clear();
        self.typed_line.clear();
        self.line_start = col as u32;
        self.current_pos = 0;
        self.mode = ProcessingMode::Normal;
    }

    fn debug_log(&mut self, _msg: &str) {
        if !self.debug {
            return;
        }
        todo!("lock stdout");
        /*
        let (row, col) = self.get_cursor_pos();
        assert_eq!(col, self.line_start + self.current_pos);

        self.hide_cursor();
        self.move_cursor(1, 1);
        self.write("\x1b[K".as_bytes());
        self.write(format!("\x1b[32m{}:{} | ", row, col).as_bytes());
        self.write(msg.as_bytes());
        self.move_cursor(2, 1);
        self.write("\x1b[K".as_bytes());
        self.write("----------------------\x1b[0m".as_bytes());
        self.move_cursor(row, col);
        self.show_cursor();
        */
    }

    fn hide_cursor(&mut self) {
        self.write("\x1b[?25l".as_bytes());
    }

    fn show_cursor(&mut self) {
        self.write("\x1b[?25h".as_bytes());
        /*
        CSI Ps SP q
          Set cursor style (DECSCUSR, VT520).
            Ps = 0  -> blinking block.
            Ps = 1  -> blinking block (default).
            Ps = 2  -> steady block.
            Ps = 3  -> blinking underline.
            Ps = 4  -> steady underline.
            Ps = 5  -> blinking bar (xterm).
            Ps = 6  -> steady bar (xterm).
        */
        match self.mode {
            ProcessingMode::Normal => self.write("\x1b[5 q".as_bytes()),
            ProcessingMode::Escape(_) => self.write("\x1b[1 q".as_bytes()),
            ProcessingMode::History(_) => self.write("\x1b[2 q".as_bytes()),
        };
    }

    fn move_cursor(&mut self, row: u32, col: u32) {
        if row == 1 && col == 1 {
            self.write("\x1b[H".as_bytes());
            return;
        }
        self.write(format!("\x1b[{row};{col}H").as_bytes());
    }

    fn redraw_line(&mut self) {
        let mut stdout_lock = std::io::stdout().lock();
        let (row, _) = self.get_cursor_pos();

        self.hide_cursor();
        self.move_cursor(row, self.line_start);

        self.write("\x1b[K".as_bytes());

        // Write to stdout instead of self.write() to avoid borrow checker complaints.
        stdout_lock.write_all(self.line.as_bytes()).unwrap();
        stdout_lock.flush().unwrap();

        self.move_cursor(row, self.line_start + self.current_pos);
        self.show_cursor();
    }

    fn extract_cursor_pos(bytes: &mut Vec<u8>) -> Option<(u32, u32)> {
        let mut curr_pos = 0_usize;
        let mut escape_pos: usize;
        let mut row_col_divider_pos: usize;

        if bytes.len() < 6 {
            return None;
        }
        // look for: 0x1b "[<ROW>;<COL>R"
        loop {
            // Look for 0x1b
            while curr_pos < bytes.len() && bytes[curr_pos] != 0x1b {
                curr_pos += 1;
                continue;
            }
            escape_pos = curr_pos;
            curr_pos += 1;
            if curr_pos >= bytes.len() {
                break;
            }

            // Confirm '['
            if bytes[curr_pos] != b'[' {
                continue;
            }

            curr_pos += 1;
            // Look for digits + ';'
            while curr_pos < bytes.len() && bytes[curr_pos].is_ascii_digit() {
                curr_pos += 1;
                continue;
            }

            if curr_pos >= bytes.len() {
                break;
            }

            if bytes[curr_pos] != b';' {
                continue;
            }

            row_col_divider_pos = curr_pos;
            if row_col_divider_pos == (escape_pos + 2) {
                continue; // No digits
            }

            curr_pos += 1;

            // Look for digits + 'R'
            while curr_pos < bytes.len() && bytes[curr_pos].is_ascii_digit() {
                curr_pos += 1;
                continue;
            }

            if curr_pos >= bytes.len() {
                break;
            }

            if bytes[curr_pos] != b'R' {
                continue;
            }

            if curr_pos == (row_col_divider_pos + 1) {
                continue; // No digits
            }

            // Got what we have been looking for.
            let mut row = 0_u32;
            for digit in &bytes[(escape_pos + 2)..row_col_divider_pos] {
                row = row * 10 + ((*digit - b'0') as u32);
            }

            let mut col = 0_u32;
            for digit in &bytes[row_col_divider_pos..curr_pos] {
                col = col * 10 + ((*digit - b'0') as u32);
            }

            // Remove the used bytes.
            let mut new_vec = vec![];
            new_vec.extend_from_slice(&bytes[0..escape_pos]);
            new_vec.extend_from_slice(&bytes[(curr_pos + 1)..]);
            core::mem::swap(&mut new_vec, bytes);

            return Some((row, col));
        }

        None
    }

    fn get_cursor_pos(&mut self) -> (u32, u32) {
        self.write(&[0x1b, b'[', b'6', b'n']); // Query the terminal for cursor position.

        let mut incoming_bytes = vec![];

        // wait for: 0x1b "[<ROW>;<COL>R"
        loop {
            let mut buf = [0; 32];
            let sz = std::io::stdin().read(&mut buf).unwrap();
            incoming_bytes.extend_from_slice(&buf[0..sz]);
            if let Some(result) = Self::extract_cursor_pos(&mut incoming_bytes) {
                for c in &incoming_bytes {
                    self.incoming.push_back(*c);
                }
                return result;
            }
        }
    }

    fn maybe_add_to_history(&mut self, cmd: &str) {
        if self.history.is_empty() || *self.history.last().unwrap() != cmd {
            self.history.push(cmd.to_string());
        }
    }

    fn process_locally(&mut self, cmd: &str) -> bool {
        match cmd {
            "clear" => {
                self.write("\x1b[2J".as_bytes()); // Clear screen.
                if self.debug {
                    self.move_cursor(3, 1);
                } else {
                    self.move_cursor(1, 1);
                }
                self.maybe_add_to_history(cmd);
                self.start_line();

                true
            }
            "history" => {
                let mut stdout_lock = std::io::stdout().lock();
                stdout_lock.write_all("\r\n".as_bytes()).unwrap();

                for line in &self.history {
                    let written = stdout_lock.write(line.as_bytes()).unwrap();
                    assert_eq!(written, line.len());
                    stdout_lock.write_all("\r\n".as_bytes()).unwrap();
                }
                stdout_lock.flush().unwrap();
                self.maybe_add_to_history(cmd);
                self.start_line();

                true
            }
            "--debug" => {
                self.debug = !self.debug;
                self.maybe_add_to_history(cmd);
                self.write("\r\n".as_bytes());
                self.start_line();
                true
            }
            _ => false,
        }
    }
}

fn prompt() -> usize {
    std::io::stderr().flush().unwrap();
    let prompt_str = crate::prompt();
    let bytes = format!("\r\x1b[32mrush:\x1b[0m {prompt_str}$ ");

    let mut stdout = std::io::stdout().lock();
    stdout.write_all(bytes.as_bytes()).unwrap();
    stdout.flush().unwrap();

    prompt_str.len() + 9 // "rush: <prompt>$ "
}

static TERM: Mutex<Option<Term>> = Mutex::new(None);

pub fn init(piped: bool) {
    debug_assert!(TERM.lock().unwrap().is_none());
    *TERM.lock().unwrap() = Some(Term::new(piped));
}

pub fn readline() -> String {
    let term = &mut *TERM.lock().unwrap();
    loop {
        if let Some(line) = term.as_mut().unwrap().readline() {
            return line;
        }
    }
}

pub fn on_exit() {
    if let Some(term) = &mut *TERM.lock().unwrap() {
        term.write("\x1b[ q".as_bytes()); // Reset the cursor.
        term.term_impl.on_exit();
    }
}
