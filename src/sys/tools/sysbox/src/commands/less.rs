//! `less`: a pager for a file or for standard input.
//!
//! The terminal is crossterm's, as it is for red and rmux: Motor OS has no
//! termios, no ioctl and no signals, so a console is always raw and a terminal
//! that changes shape says so in band, among the keys (docs/tui.md). What is
//! left here is what a pager does with them.
//!
//! Paging needs two terminal streams: stdout to paint on, and either terminal
//! stdin or Motor's synthesized fd 3 to read keys from. The latter keeps the
//! session terminal available when a pipeline or redirect supplies the data on
//! stdin.

use std::io::{IsTerminal, Read, Write};
use std::path::Path;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::style::{Attribute, Print, SetAttribute};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::{cursor, execute, queue};

/// VT100's geometry, and what crossterm answers with when nothing has said
/// otherwise: no report yet, and no `$COLUMNS`/`$LINES` from a terminal owner.
const FALLBACK_SIZE: (u16, u16) = (80, 24);
const TAB_WIDTH: usize = 8;

const KEY_HINT: &str = "  [space/b: page, j/k: line, g/G: top/end, q: quit]";

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tless [FILENAME]\n");
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "less");

    let args = &args[1..];
    for arg in args {
        if arg == "--help" {
            print_usage_and_exit(0);
        }
    }
    if args.len() > 1 {
        eprintln!("less: too many arguments.");
        print_usage_and_exit(1);
    }

    // Probe fd 3 before opening the document: when absent, an ordinary open is
    // allowed to reuse that descriptor number.
    let stdin_is_terminal = std::io::stdin().is_terminal();
    let page_output = std::io::stdout().is_terminal()
        && (stdin_is_terminal || moto_rt::fs::is_terminal(moto_rt::FD_TERMINAL));

    let (bytes, name) = match args.first() {
        Some(fname) => (read_file(fname), fname.as_str()),
        None => {
            // A terminal's stdin is a keyboard, not a document: there is
            // nothing to read and no way for the user to end it.
            if stdin_is_terminal {
                eprintln!("less: missing filename.");
                print_usage_and_exit(1);
            }
            (read_stdin(), "(stdin)")
        }
    };

    // The same input is accepted, or refused, whether it is paged or dumped.
    let Ok(text) = std::str::from_utf8(&bytes) else {
        eprintln!("less: can't display a binary file '{name}'.");
        std::process::exit(1);
    };

    if page_output {
        page(text, name);
    } else {
        dump(text);
    }
}

fn read_file(fname: &str) -> Vec<u8> {
    match std::fs::read(Path::new(fname)) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("less: error reading file '{fname}': {err:?}.");
            std::process::exit(1);
        }
    }
}

fn read_stdin() -> Vec<u8> {
    let mut bytes = Vec::new();
    match std::io::stdin().read_to_end(&mut bytes) {
        Ok(_) => bytes,
        Err(err) => {
            eprintln!("less: error reading stdin: {err:?}.");
            std::process::exit(1);
        }
    }
}

fn dump(text: &str) {
    let mut stdout = std::io::stdout().lock();
    if let Err(err) = stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.flush())
    {
        eprintln!("less: error writing to stdout: {err:?}.");
        std::process::exit(1);
    }
}

/// The terminal's size as columns and rows.
///
/// `window_size` rather than `size`, as red does: on Motor OS this is the last
/// size the terminal reported in band, failing that `$COLUMNS`/`$LINES`, which
/// a pane's or a session's owner sets before the program exists, and failing
/// both 80x24. It asks the terminal nothing and cannot block.
fn terminal_size() -> (u16, u16) {
    match crossterm::terminal::window_size() {
        Ok(size) if size.columns > 0 && size.rows > 0 => (size.columns, size.rows),
        _ => FALLBACK_SIZE,
    }
}

fn page(text: &str, name: &str) {
    if let Err(err) = event::enable_ctrl_c_events() {
        eprintln!("less: cannot enable Ctrl+C input: {err:?}.");
        std::process::exit(1);
    }
    let _guard = TerminalGuard::new();
    let (cols, rows) = terminal_size();
    let mut pager = Pager::new(name, text, cols, rows);

    loop {
        if !pager.paint() {
            return; // Nothing left to paint on.
        }

        match event::read() {
            Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => match command_of(key) {
                Some(Command::Quit) => return,
                Some(Command::Scroll(scroll)) => pager.scroll(scroll),
                None => (),
            },
            // No `SIGWINCH` and no size call here: a terminal that changed
            // shape says so among the keys, and re-wrapping is what answers.
            Ok(Event::Resize(cols, rows)) if cols > 0 && rows > 0 => pager.resize(cols, rows),
            Ok(_) => (),
            // A read error is the terminal going away, as it is for red.
            Err(_) => return,
        }
    }
}

/// One display row, and the input line it came from. The line is what keeps a
/// resize from losing the reader's place: every row index changes when the
/// text is re-wrapped, but the line at the top of the screen stays there.
struct Row {
    line: usize,
    text: String,
}

struct Pager<'a> {
    name: &'a str,
    text: &'a str,
    rows: Vec<Row>,
    cols: u16,
    /// Rows of text on screen: everything but the status line.
    height: usize,
    top: usize,
}

impl<'a> Pager<'a> {
    fn new(name: &'a str, text: &'a str, cols: u16, rows: u16) -> Self {
        Self {
            name,
            text,
            rows: wrap(text, cols),
            cols,
            height: usize::from(rows.max(2)) - 1,
            top: 0,
        }
    }

    fn max_top(&self) -> usize {
        self.rows.len().saturating_sub(self.height)
    }

    fn resize(&mut self, cols: u16, rows: u16) {
        let anchor = self.rows.get(self.top).map_or(0, |row| row.line);

        self.height = usize::from(rows.max(2)) - 1;
        if cols != self.cols {
            self.cols = cols;
            self.rows = wrap(self.text, cols);
        }

        self.top = self
            .rows
            .iter()
            .position(|row| row.line == anchor)
            .unwrap_or(0)
            .min(self.max_top());
    }

    fn scroll(&mut self, scroll: Scroll) {
        let half = (self.height / 2).max(1);
        self.top = match scroll {
            Scroll::PageDown => (self.top + self.height).min(self.max_top()),
            Scroll::PageUp => self.top.saturating_sub(self.height),
            Scroll::HalfPageDown => (self.top + half).min(self.max_top()),
            Scroll::HalfPageUp => self.top.saturating_sub(half),
            Scroll::LineDown => (self.top + 1).min(self.max_top()),
            Scroll::LineUp => self.top.saturating_sub(1),
            Scroll::Top => 0,
            Scroll::Bottom => self.max_top(),
        };
    }

    fn status(&self) -> String {
        let total = self.rows.len();
        let last = (self.top + self.height).min(total);
        let percent = (last * 100).checked_div(total).unwrap_or(100);

        let mut status = if last >= total {
            format!("{} (END) {total} lines", self.name)
        } else {
            format!("{} {last}/{total} lines ({percent}%)", self.name)
        };
        status.push_str(KEY_HINT);

        status.chars().take(usize::from(self.cols)).collect()
    }

    fn paint(&self) -> bool {
        self.render(&mut std::io::stdout().lock()).is_ok()
    }

    fn render(&self, out: &mut impl Write) -> std::io::Result<()> {
        for idx in 0..self.height {
            let text = self
                .rows
                .get(self.top + idx)
                .map_or("", |row| row.text.as_str());
            self.paint_row(out, idx, text)?;
        }

        queue!(out, cursor::MoveTo(0, self.height as u16))?;
        queue!(out, SetAttribute(Attribute::Reverse))?;
        let status = self.status();
        queue!(out, Print(&status))?;
        self.clear_tail(out, &status)?;
        queue!(out, SetAttribute(Attribute::Reset))?;

        out.flush()
    }

    fn paint_row(&self, out: &mut impl Write, row: usize, text: &str) -> std::io::Result<()> {
        queue!(out, cursor::MoveTo(0, row as u16), Print(text))?;
        self.clear_tail(out, text)
    }

    /// Clears what a shorter previous row left behind — and only then: erasing
    /// from the last column of a full-width row takes the character that was
    /// just written there, because the cursor is still standing on it.
    fn clear_tail(&self, out: &mut impl Write, painted: &str) -> std::io::Result<()> {
        if painted.chars().count() < usize::from(self.cols) {
            queue!(out, Clear(ClearType::UntilNewLine))?;
        }
        Ok(())
    }
}

/// Splits the text into the rows the terminal will show: control characters
/// spelled out, tabs expanded, and anything wider than the screen wrapped, so
/// that paging counts what is displayed rather than what the file contains.
fn wrap(text: &str, cols: u16) -> Vec<Row> {
    let cols = usize::from(cols).max(1);
    let mut rows = Vec::new();

    for (line, source) in text.lines().enumerate() {
        let source = expand(source);
        let mut chars = source.chars().peekable();
        if chars.peek().is_none() {
            rows.push(Row {
                line,
                text: String::new(),
            });
            continue;
        }
        while chars.peek().is_some() {
            rows.push(Row {
                line,
                text: chars.by_ref().take(cols).collect(),
            });
        }
    }

    rows
}

/// Tabs to the next stop, and every other control character as `^X`: what the
/// screen shows is the pager's decision, never the file's. Continuation bytes
/// of a UTF-8 sequence are all >= 0x80, so this can look at bytes.
fn expand(line: &str) -> String {
    fn is_control(byte: u8) -> bool {
        byte < 0x20 || byte == 0x7f
    }

    if !line.bytes().any(is_control) {
        return line.to_owned();
    }

    let mut expanded = String::with_capacity(line.len());
    let mut width = 0;
    for ch in line.chars() {
        if ch == '\t' {
            let advance = TAB_WIDTH - (width % TAB_WIDTH);
            for _ in 0..advance {
                expanded.push(' ');
            }
            width += advance;
        } else if (ch as u32) < 0x80 && is_control(ch as u8) {
            expanded.push('^');
            expanded.push(char::from((ch as u8) ^ 0x40));
            width += 2;
        } else {
            expanded.push(ch);
            width += 1;
        }
    }

    expanded
}

enum Command {
    Quit,
    Scroll(Scroll),
}

enum Scroll {
    PageDown,
    PageUp,
    HalfPageDown,
    HalfPageUp,
    LineDown,
    LineUp,
    Top,
    Bottom,
}

/// What the pager makes of one key, or `None` for one it has no use for.
fn command_of(key: KeyEvent) -> Option<Command> {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    Some(match key.code {
        KeyCode::Char('c') if ctrl => Command::Quit,
        KeyCode::Char('q' | 'Q') | KeyCode::Esc => Command::Quit,
        KeyCode::Char(' ' | 'f') | KeyCode::PageDown => Command::Scroll(Scroll::PageDown),
        KeyCode::Char('b') | KeyCode::PageUp => Command::Scroll(Scroll::PageUp),
        KeyCode::Char('d') => Command::Scroll(Scroll::HalfPageDown),
        KeyCode::Char('u') => Command::Scroll(Scroll::HalfPageUp),
        KeyCode::Char('j') | KeyCode::Down | KeyCode::Enter => Command::Scroll(Scroll::LineDown),
        KeyCode::Char('k') | KeyCode::Up => Command::Scroll(Scroll::LineUp),
        KeyCode::Char('g') | KeyCode::Home => Command::Scroll(Scroll::Top),
        KeyCode::Char('G') | KeyCode::End => Command::Scroll(Scroll::Bottom),
        _ => return None,
    })
}

struct TerminalGuard;

impl TerminalGuard {
    fn new() -> Self {
        enter();

        // `panic = "abort"` means `Drop` does not run on a panic, so the hook
        // is what gives the terminal back — before the message, or the user
        // reads it on the alternate screen and loses it with the screen.
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

/// The alternate screen, so that quitting gives back whatever the reader was
/// looking at, and no cursor, which a pager has no use for.
fn enter() {
    let _ = enable_raw_mode();
    let _ = execute!(std::io::stdout(), EnterAlternateScreen, cursor::Hide);
}

/// Put back everything [`enter`] took. Safe to call twice — the panic hook and
/// the guard both run on the ordinary path out.
fn leave() {
    let _ = execute!(std::io::stdout(), cursor::Show, LeaveAlternateScreen);
    let _ = disable_raw_mode();
    let _ = std::io::stdout().flush();
}
