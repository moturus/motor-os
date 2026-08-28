//! Full-screen terminal UI over the small runtime event vocabulary.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::mpsc;
use std::time::Duration;

use crossterm::cursor;
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event as InputEvent, KeyCode, KeyEvent,
    KeyEventKind, KeyModifiers,
};
use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
use crossterm::terminal::{self, Clear, ClearType, disable_raw_mode, enable_raw_mode};
use crossterm::{execute, queue};

use crate::runtime::{Approver, Event, Observer, Permission, Runtime, SessionSummary};
use crate::ui::tui_editor::{Edit, Editor};

const POLL: Duration = Duration::from_millis(50);
const TRANSCRIPT_BYTES: usize = 1024 * 1024;
// rmux `status::AMBER`: keep shared terminal chrome visually consistent.
const STATUS_COLOR: Color = Color::AnsiValue(222);

pub fn run(
    runtime: &mut Runtime,
    initial: Option<String>,
    interactive: bool,
    models: &[String],
) -> Result<(), String> {
    let mut screen = Screen::enter()?;
    let mut app = App::new(runtime);
    let result = (|| {
        for notice in runtime.take_startup_notices() {
            app.apply(Event::Notice(notice));
        }
        if let Some(prompt) = initial {
            app.push(Kind::User, prompt.clone(), false);
            run_turn(runtime, prompt, &mut app)?;
            if !interactive {
                app.render()?;
                return Ok(());
            }
        }
        while !app.quit {
            app.render()?;
            let input = event::read().map_err(|error| error.to_string())?;
            let Some(action) = app.edit(input) else {
                continue;
            };
            match action {
                Action::Quit => app.quit = true,
                Action::Submit(text) if text.starts_with('/') => {
                    handle_command(runtime, &mut app, &text, models)?
                }
                Action::Submit(text) if !text.trim().is_empty() => {
                    app.push(Kind::User, text.clone(), false);
                    if let Err(error) = run_turn(runtime, text, &mut app) {
                        app.push(Kind::Error, error, false);
                    }
                }
                Action::Submit(_) => {}
            }
        }
        Ok(())
    })();
    let leave = screen.leave(&app.session.id);
    result.and(leave)
}

enum Action {
    Submit(String),
    Quit,
}

struct Screen {
    left: bool,
}

impl Screen {
    fn enter() -> Result<Self, String> {
        crossterm::event::enable_ctrl_c_events().map_err(|error| error.to_string())?;
        enable_raw_mode().map_err(|error| error.to_string())?;
        if let Err(error) = execute!(io::stdout(), EnableBracketedPaste, cursor::Hide) {
            let _ = disable_raw_mode();
            return Err(error.to_string());
        }
        Ok(Self { left: false })
    }

    fn leave(&mut self, session: &str) -> Result<(), String> {
        let (width, height) = terminal::size().map_err(|error| error.to_string())?;
        let raw = disable_raw_mode();
        let output = {
            let mut output = io::stdout().lock();
            paint_exit(&mut output, width, height, session).and_then(|()| output.flush())
        };
        self.left = true;
        raw.and(output).map_err(|error| error.to_string())
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        if self.left {
            return;
        }
        let _ = disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            ResetColor,
            cursor::Show,
            DisableBracketedPaste
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    User,
    Assistant,
    Reasoning,
    Tool,
    ToolOutput,
    Notice,
    Error,
}

struct Entry {
    kind: Kind,
    text: String,
    live: bool,
}

struct App {
    transcript: VecDeque<Entry>,
    bytes: usize,
    editor: Editor,
    scroll: usize,
    status: String,
    model: String,
    session: SessionSummary,
    approval: Option<Permission>,
    input_enabled: bool,
    quit: bool,
    last_frame: Option<Frame>,
}

#[derive(Debug, PartialEq, Eq)]
struct Layout {
    transcript_rows: usize,
    approval_start: usize,
    approval_rows: usize,
    editor_start: usize,
    editor_rows: usize,
    status_row: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StyledChar {
    character: char,
    color: Color,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct StyledLine(Vec<StyledChar>);

impl StyledLine {
    fn push(&mut self, color: Color, text: &str, width: usize) {
        let remaining = width.saturating_sub(self.0.len());
        self.0.extend(
            text.chars()
                .take(remaining)
                .map(|character| StyledChar { character, color }),
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Frame {
    width: usize,
    lines: Vec<StyledLine>,
    cursor: Option<(u16, u16)>,
}

impl Frame {
    fn new(width: usize, height: usize) -> Self {
        Self {
            width,
            lines: vec![StyledLine::default(); height],
            cursor: None,
        }
    }
}

fn screen_layout(height: usize, editor_rows: usize, approval: bool) -> Layout {
    let status_row = height.saturating_sub(1);
    let available = status_row;
    let approval_rows = if approval {
        3.min(available.saturating_sub(1))
    } else {
        0
    };
    let editor_rows = editor_rows.min(available.saturating_sub(approval_rows));
    let editor_start = status_row.saturating_sub(editor_rows);
    let approval_start = editor_start.saturating_sub(approval_rows);
    Layout {
        transcript_rows: approval_start,
        approval_start,
        approval_rows,
        editor_start,
        editor_rows,
        status_row,
    }
}

impl App {
    fn new(runtime: &Runtime) -> Self {
        Self {
            transcript: VecDeque::new(),
            bytes: 0,
            editor: Editor::new(),
            scroll: 0,
            status: "idle".to_string(),
            model: runtime.model().to_string(),
            session: runtime.summary(),
            approval: None,
            input_enabled: true,
            quit: false,
            last_frame: None,
        }
    }

    fn apply(&mut self, event: Event) {
        match event {
            Event::Text(text) => {
                self.status = "responding".to_string();
                self.push(Kind::Assistant, text, true);
            }
            Event::Reasoning(text) => {
                self.status = "thinking".to_string();
                self.push(Kind::Reasoning, text, true);
            }
            Event::ToolStart { name, detail } => {
                self.status = format!("running {name}");
                self.push(Kind::Tool, format!("{name}> {detail}"), false);
            }
            Event::ToolOutput { name, stream, text } => {
                self.push(Kind::ToolOutput, format!("{name} {stream:?}> {text}"), true)
            }
            Event::ToolEnd {
                name,
                content,
                is_error,
            } => {
                self.status = if is_error {
                    format!("{name} failed")
                } else {
                    format!("{name} finished")
                };
                self.push(
                    if is_error { Kind::Error } else { Kind::Tool },
                    format!("{name}> {}", fold(&content)),
                    false,
                );
            }
            Event::Permission(_) => self.status = "checking permission".to_string(),
            Event::Notice(text) => self.push(Kind::Notice, text, false),
            Event::Usage(text) => self.status = text,
            Event::ModelChanged(model) => self.model = model,
            Event::SessionChanged(session) => self.session = session,
            Event::TurnEnd => self.status = "idle".to_string(),
        }
    }

    fn push(&mut self, kind: Kind, text: String, live: bool) {
        let text = clean(&text);
        if text.is_empty() {
            return;
        }
        if live
            && self
                .transcript
                .back()
                .is_some_and(|entry| entry.live && entry.kind == kind)
        {
            let entry = self.transcript.back_mut().expect("live entry exists");
            self.bytes -= entry.text.len();
            entry.text.push_str(&text);
            if entry.text.len() > TRANSCRIPT_BYTES {
                entry.text = suffix(&entry.text, TRANSCRIPT_BYTES);
            }
            self.bytes += entry.text.len();
        } else {
            for entry in &mut self.transcript {
                entry.live = false;
            }
            self.bytes += text.len();
            self.transcript.push_back(Entry { kind, text, live });
        }
        while self.bytes > TRANSCRIPT_BYTES {
            let removed = self.transcript.pop_front().expect("transcript has bytes");
            self.bytes -= removed.text.len();
        }
        if self.scroll == 0 {
            self.scroll = 0;
        }
    }

    fn edit(&mut self, input: InputEvent) -> Option<Action> {
        match input {
            InputEvent::Resize(_, _) => None,
            InputEvent::Paste(text) => {
                self.editor.insert_paste(&text);
                None
            }
            InputEvent::Key(key) if key.kind == KeyEventKind::Press => self.key(key),
            _ => None,
        }
    }

    fn key(&mut self, key: KeyEvent) -> Option<Action> {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('c') if control => {
                if self.editor.text().is_empty() {
                    Some(Action::Quit)
                } else {
                    self.editor.submit();
                    None
                }
            }
            KeyCode::Char('d') if control && self.editor.text().is_empty() => Some(Action::Quit),
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_add(10);
                None
            }
            KeyCode::PageDown => {
                self.scroll = self.scroll.saturating_sub(10);
                None
            }
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::ALT) => {
                self.editor.insert_char('\n');
                None
            }
            KeyCode::Char('j') if control => {
                self.editor.insert_char('\n');
                None
            }
            KeyCode::Enter => Some(Action::Submit(self.editor.submit())),
            KeyCode::Backspace => {
                self.editor.backspace();
                None
            }
            KeyCode::Delete => {
                self.editor.delete();
                None
            }
            KeyCode::Left => {
                self.editor.left();
                None
            }
            KeyCode::Right => {
                self.editor.right();
                None
            }
            KeyCode::Home => {
                self.editor.home();
                None
            }
            KeyCode::End => {
                self.editor.end();
                None
            }
            KeyCode::Up => {
                self.editor.older();
                None
            }
            KeyCode::Down => {
                self.editor.newer();
                None
            }
            KeyCode::Tab => {
                self.editor.insert_char('\t');
                None
            }
            KeyCode::Char(character) if !control && !character.is_control() => {
                self.editor.insert_char(character);
                None
            }
            _ => None,
        }
    }

    fn replace_draft(&mut self, draft: String) {
        if self.editor.replace(draft) == Edit::Full {
            self.push(
                Kind::Error,
                "selected prompt exceeds editor limit".to_string(),
                false,
            );
        }
    }

    fn refresh(&mut self, runtime: &Runtime) {
        self.model = runtime.model().to_string();
        self.session = runtime.summary();
    }

    fn render(&mut self) -> Result<(), String> {
        let (width, height) = terminal::size().map_err(|error| error.to_string())?;
        let next = self.frame(width, height);
        let mut output = io::stdout().lock();
        paint_frame(&mut output, self.last_frame.as_ref(), &next)
            .map_err(|error| error.to_string())?;
        output.flush().map_err(|error| error.to_string())?;
        self.last_frame = Some(next);
        Ok(())
    }

    fn invalidate(&mut self) {
        self.last_frame = None;
    }

    fn frame(&self, width: u16, height: u16) -> Frame {
        let width = usize::from(width).max(1);
        let height = usize::from(height);
        let mut frame = Frame::new(width, height);
        if height == 0 {
            return frame;
        }
        let editor_width = width.saturating_sub(2).max(1);
        let draft_lines = wrap(self.editor.text(), editor_width);
        let (cursor_row, cursor_column) =
            editor_cursor(self.editor.text(), self.editor.cursor(), editor_width);
        let layout = screen_layout(height, draft_lines.len(), self.approval.is_some());
        let lines = self.transcript_lines(width);
        let end = lines.len().saturating_sub(self.scroll);
        let start = end.saturating_sub(layout.transcript_rows);
        let transcript_start = layout.transcript_rows.saturating_sub(end - start);
        for (index, (kind, line)) in lines[start..end].iter().enumerate() {
            frame.lines[transcript_start + index].push(color(*kind), line, width);
        }
        if let Some(permission) = &self.approval {
            let approval = [
                clipped(
                    &single_line(&format!(
                        "Allow {} in {}?",
                        permission.tool,
                        permission.workspace.display()
                    )),
                    width,
                ),
                clipped(&single_line(&permission.detail), width),
                clipped("[y] allow  [n/esc] deny", width),
            ];
            for (index, line) in approval.iter().take(layout.approval_rows).enumerate() {
                frame.lines[layout.approval_start + index].push(Color::Yellow, line, width);
            }
        }
        let editor_first = cursor_row
            .saturating_add(1)
            .saturating_sub(layout.editor_rows)
            .min(draft_lines.len().saturating_sub(layout.editor_rows));
        for (shown, (index, line)) in draft_lines
            .iter()
            .enumerate()
            .skip(editor_first)
            .take(layout.editor_rows)
            .enumerate()
        {
            let prefix = if index == 0 { "> " } else { "  " };
            let target = &mut frame.lines[layout.editor_start + shown];
            target.push(
                if self.input_enabled {
                    STATUS_COLOR
                } else {
                    Color::DarkGrey
                },
                prefix,
                width,
            );
            target.push(Color::White, line, width);
        }
        let status = single_line(&format!(
            "gears | {} | {} | {}{}",
            self.status,
            self.model,
            self.session.name.as_deref().unwrap_or(&self.session.id),
            if self.session.ephemeral {
                " (ephemeral)"
            } else {
                ""
            }
        ));
        frame.lines[layout.status_row].push(STATUS_COLOR, &status, width);
        if layout.editor_rows != 0 {
            let row = layout.editor_start + cursor_row.saturating_sub(editor_first);
            let column = (cursor_column + 2).min(width.saturating_sub(1));
            frame.cursor = Some((column as u16, row as u16));
        }
        frame
    }

    fn transcript_lines(&self, width: usize) -> Vec<(Kind, String)> {
        let mut result = Vec::new();
        for entry in &self.transcript {
            let prefix = match entry.kind {
                Kind::User => "you> ",
                Kind::Assistant => "agent> ",
                Kind::Reasoning => "think> ",
                Kind::Tool => "tool> ",
                Kind::ToolOutput => "out> ",
                Kind::Notice => "note> ",
                Kind::Error => "error> ",
            };
            let available = width.saturating_sub(prefix.len()).max(1);
            for (index, line) in wrap(&entry.text, available).into_iter().enumerate() {
                result.push((
                    entry.kind,
                    format!("{}{line}", if index == 0 { prefix } else { "     " }),
                ));
            }
        }
        result
    }
}

fn paint_frame<W: Write>(output: &mut W, previous: Option<&Frame>, next: &Frame) -> io::Result<()> {
    let full = previous.is_none_or(|previous| {
        previous.width != next.width || previous.lines.len() != next.lines.len()
    });
    let changed = full
        || previous.is_some_and(|previous| {
            previous
                .lines
                .iter()
                .zip(&next.lines)
                .any(|(old, new)| old != new)
        });
    if changed {
        queue!(output, cursor::Hide)?;
    }
    if full {
        queue!(output, cursor::MoveTo(0, 0), Clear(ClearType::All))?;
    }
    for (row, new) in next.lines.iter().enumerate() {
        let old = (!full).then(|| &previous.expect("non-full frame exists").lines[row]);
        if old == Some(new) || full && new.0.is_empty() {
            continue;
        }
        paint_line(output, row as u16, old, new)?;
    }
    match next.cursor {
        Some((column, row)) => queue!(output, cursor::MoveTo(column, row), cursor::Show)?,
        None => queue!(output, cursor::Hide)?,
    }
    Ok(())
}

fn paint_exit<W: Write>(output: &mut W, width: u16, height: u16, session: &str) -> io::Result<()> {
    let message = single_line(&format!("Motor OS Gears session {session} exited."));
    queue!(
        output,
        cursor::MoveTo(0, height.saturating_sub(1)),
        Clear(ClearType::CurrentLine),
        SetForegroundColor(STATUS_COLOR),
        Print(clipped(&message, usize::from(width))),
        ResetColor,
        Print("\r\n\r\n"),
        cursor::Show,
        DisableBracketedPaste
    )
}

fn paint_line<W: Write>(
    output: &mut W,
    row: u16,
    previous: Option<&StyledLine>,
    next: &StyledLine,
) -> io::Result<()> {
    let common = previous.map_or(0, |previous| {
        previous
            .0
            .iter()
            .zip(&next.0)
            .take_while(|(old, new)| old == new)
            .count()
    });
    queue!(output, cursor::MoveTo(common as u16, row))?;
    let mut index = common;
    while index < next.0.len() {
        let color = next.0[index].color;
        let mut text = String::new();
        while index < next.0.len() && next.0[index].color == color {
            text.push(next.0[index].character);
            index += 1;
        }
        queue!(output, SetForegroundColor(color), Print(text))?;
    }
    if previous.is_some_and(|previous| previous.0.len() > next.0.len()) {
        queue!(output, Clear(ClearType::UntilNewLine))?;
    }
    queue!(output, ResetColor)
}

enum TurnMessage {
    Event(Event),
    Permission(Permission, mpsc::Sender<bool>),
    Done(Result<(), String>),
}

fn run_turn(runtime: &mut Runtime, prompt: String, app: &mut App) -> Result<(), String> {
    app.input_enabled = false;
    app.status = "working".to_string();
    app.render()?;
    let cancellation = runtime.cancellation();
    let (sender, receiver) = mpsc::channel();
    std::thread::scope(|scope| {
        let worker_sender = sender.clone();
        scope.spawn(move || {
            let mut observer = ChannelObserver {
                sender: worker_sender.clone(),
            };
            let mut approver = ChannelApprover {
                sender: worker_sender,
            };
            let result = runtime.turn(prompt, &mut approver, &mut observer);
            let _ = sender.send(TurnMessage::Done(result));
        });
        loop {
            let mut dirty = false;
            loop {
                match receiver.try_recv() {
                    Ok(message) => match message {
                        TurnMessage::Event(event) => {
                            app.apply(event);
                            dirty = true;
                        }
                        TurnMessage::Permission(permission, reply) => {
                            app.approval = Some(permission);
                            app.status = "waiting for permission".to_string();
                            app.render()?;
                            let allowed = permission_input(&cancellation, app)?;
                            app.approval = None;
                            app.status = if cancellation.cancelled() {
                                "cancelling"
                            } else {
                                "working"
                            }
                            .to_string();
                            app.render()?;
                            let _ = reply.send(allowed);
                        }
                        TurnMessage::Done(result) => {
                            app.input_enabled = true;
                            app.status = "idle".to_string();
                            app.render()?;
                            return result;
                        }
                    },
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        app.input_enabled = true;
                        return Err("agent worker stopped unexpectedly".to_string());
                    }
                }
            }
            if dirty {
                app.render()?;
            }
            if event::poll(POLL).map_err(|error| error.to_string())? {
                match event::read().map_err(|error| error.to_string())? {
                    InputEvent::Key(key)
                        if key.kind == KeyEventKind::Press
                            && key.code == KeyCode::Char('c')
                            && key.modifiers.contains(KeyModifiers::CONTROL) =>
                    {
                        cancellation.cancel();
                        app.status = "cancelling".to_string();
                    }
                    InputEvent::Key(key)
                        if key.kind == KeyEventKind::Press && key.code == KeyCode::PageUp =>
                    {
                        app.scroll = app.scroll.saturating_add(10);
                    }
                    InputEvent::Key(key)
                        if key.kind == KeyEventKind::Press && key.code == KeyCode::PageDown =>
                    {
                        app.scroll = app.scroll.saturating_sub(10);
                    }
                    InputEvent::Resize(_, _) => {}
                    _ => {}
                }
                app.render()?;
            }
        }
    })
}

fn run_compact(runtime: &mut Runtime, focus: Option<String>, app: &mut App) -> Result<(), String> {
    app.input_enabled = false;
    app.status = "compacting".to_string();
    app.render()?;
    let cancellation = runtime.cancellation();
    let (sender, receiver) = mpsc::channel();
    std::thread::scope(|scope| {
        let worker_sender = sender.clone();
        scope.spawn(move || {
            let mut observer = ChannelObserver {
                sender: worker_sender,
            };
            let result = runtime.compact(focus, &mut observer);
            let _ = sender.send(TurnMessage::Done(result));
        });
        loop {
            let mut dirty = false;
            loop {
                match receiver.try_recv() {
                    Ok(TurnMessage::Event(event)) => {
                        app.apply(event);
                        dirty = true;
                    }
                    Ok(TurnMessage::Done(result)) => {
                        app.input_enabled = true;
                        app.status = "idle".to_string();
                        app.render()?;
                        return result;
                    }
                    Ok(TurnMessage::Permission(_, reply)) => {
                        let _ = reply.send(false);
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        app.input_enabled = true;
                        return Err("compaction worker stopped unexpectedly".to_string());
                    }
                }
            }
            if dirty {
                app.render()?;
            }
            if event::poll(POLL).map_err(|error| error.to_string())? {
                match event::read().map_err(|error| error.to_string())? {
                    InputEvent::Key(key)
                        if key.kind == KeyEventKind::Press
                            && key.code == KeyCode::Char('c')
                            && key.modifiers.contains(KeyModifiers::CONTROL) =>
                    {
                        cancellation.cancel();
                        app.status = "cancelling".to_string();
                    }
                    InputEvent::Resize(_, _) => {}
                    _ => {}
                }
                app.render()?;
            }
        }
    })
}

fn permission_input(
    cancellation: &crate::process::Cancellation,
    app: &mut App,
) -> Result<bool, String> {
    loop {
        match event::read().map_err(|error| error.to_string())? {
            InputEvent::Resize(_, _) => app.render()?,
            InputEvent::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Char('y') if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Ok(true);
                }
                KeyCode::Char('n') | KeyCode::Esc | KeyCode::Enter => return Ok(false),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    cancellation.cancel();
                    return Ok(false);
                }
                _ => {}
            },
            _ => {}
        }
    }
}

struct ChannelObserver {
    sender: mpsc::Sender<TurnMessage>,
}

impl Observer for ChannelObserver {
    fn event(&mut self, event: Event) -> Result<(), String> {
        self.sender
            .send(TurnMessage::Event(event))
            .map_err(|_| "terminal UI closed".to_string())
    }
}

struct ChannelApprover {
    sender: mpsc::Sender<TurnMessage>,
}

impl Approver for ChannelApprover {
    fn approve(&mut self, request: &Permission) -> bool {
        let (sender, receiver) = mpsc::channel();
        if self
            .sender
            .send(TurnMessage::Permission(request.clone(), sender))
            .is_err()
        {
            return false;
        }
        receiver.recv().unwrap_or(false)
    }
}

fn handle_command(
    runtime: &mut Runtime,
    app: &mut App,
    text: &str,
    models: &[String],
) -> Result<(), String> {
    let (name, argument) = text[1..]
        .split_once(char::is_whitespace)
        .map_or((&text[1..], ""), |(name, rest)| (name, rest.trim()));
    match name {
        "quit" | "exit" => app.quit = true,
        "help" => app.push(
            Kind::Notice,
            "commands: /new /resume /name /session /tree /label /fork /clone /compact /model /status /help /quit"
                .to_string(),
            false,
        ),
        "status" => app.push(
            Kind::Notice,
            format!(
                "model: {}\nusage: {}\nsession: {}",
                runtime.model(),
                runtime.usage().summary(),
                runtime.summary().id
            ),
            false,
        ),
        "session" => {
            let session = runtime.summary();
            app.push(
                Kind::Notice,
                format!(
                    "id: {}\npath: {}\nname: {}\nentries: {}",
                    session.id,
                    session
                        .path
                        .as_deref()
                        .map_or("<ephemeral>".to_string(), |path| path.display().to_string()),
                    session.name.as_deref().unwrap_or(""),
                    session.entries
                ),
                false,
            );
        }
        "name" => runtime.set_name(argument)?,
        "new" => {
            runtime.new_session(argument == "--ephemeral", None)?;
            show_runtime_notices(runtime, app);
        }
        "resume" => {
            let selector = if argument.is_empty() {
                let sessions = runtime.list_sessions()?;
                let labels = sessions
                    .iter()
                    .map(|session| {
                        format!(
                            "{}  {}  {} messages",
                            session.id,
                            session.name.as_deref().unwrap_or(""),
                            session.messages
                        )
                    })
                    .collect::<Vec<_>>();
                let selected = picker(app, "Resume session", &labels)?
                    .ok_or("session selection cancelled")?;
                sessions[selected].id.clone()
            } else {
                argument.to_string()
            };
            runtime.resume(&selector)?;
            show_runtime_notices(runtime, app);
        }
        "label" => {
            let (entry, label) = argument
                .split_once(char::is_whitespace)
                .map_or((argument, ""), |(entry, label)| (entry, label.trim()));
            if entry.is_empty() {
                return Err("usage: /label ENTRY [TEXT]".to_string());
            }
            runtime.set_label(entry, (!label.is_empty()).then_some(label))?;
        }
        "tree" => {
            let id = if argument.is_empty() {
                let tree = runtime.tree();
                let labels = tree
                    .iter()
                    .map(|item| {
                        format!(
                            "{}{} [{}] {}",
                            if item.active { "* " } else { "  " },
                            item.id,
                            item.kind,
                            item.summary
                        )
                    })
                    .collect::<Vec<_>>();
                let selected =
                    picker(app, "Select branch (shell side effects are unchanged)", &labels)?
                        .ok_or("tree selection cancelled")?;
                tree[selected].id.clone()
            } else {
                argument.to_string()
            };
            if let Some(draft) = runtime.select_entry(&id)? {
                app.replace_draft(draft);
            }
            app.push(
                Kind::Notice,
                "conversation branch changed; shell side effects were not undone".to_string(),
                false,
            );
        }
        "fork" => {
            let id = if argument.is_empty() {
                let tree = runtime
                    .tree()
                    .into_iter()
                    .filter(|item| item.user_message)
                    .collect::<Vec<_>>();
                let labels = tree
                    .iter()
                    .map(|item| format!("{} {}", item.id, item.summary))
                    .collect::<Vec<_>>();
                let selected = picker(app, "Fork from user message", &labels)?
                    .ok_or("fork selection cancelled")?;
                tree[selected].id.clone()
            } else {
                argument.to_string()
            };
            let draft = runtime.fork_at(&id)?;
            show_runtime_notices(runtime, app);
            app.replace_draft(draft);
            app.push(
                Kind::Notice,
                "new session forked; shell side effects were not undone".to_string(),
                false,
            );
        }
        "clone" => {
            runtime.clone_session()?;
            show_runtime_notices(runtime, app);
            app.push(
                Kind::Notice,
                "active branch cloned; shell side effects were not undone".to_string(),
                false,
            );
        }
        "compact" => {
            app.status = "compacting".to_string();
            run_compact(
                runtime,
                (!argument.is_empty()).then(|| argument.to_string()),
                app,
            )?;
        }
        "model" => {
            let model = if argument.is_empty() {
                let mut choices = vec![runtime.model().to_string()];
                for model in models {
                    if !choices.contains(model) {
                        choices.push(model.clone());
                    }
                }
                let selected =
                    picker(app, "Select model", &choices)?.ok_or("model selection cancelled")?;
                choices[selected].clone()
            } else {
                argument.to_string()
            };
            runtime.set_model(model, &mut AppObserver(app))?;
        }
        "" => {}
        other => return Err(format!("unknown command /{other}")),
    }
    app.refresh(runtime);
    Ok(())
}

fn show_runtime_notices(runtime: &mut Runtime, app: &mut App) {
    for notice in runtime.take_startup_notices() {
        app.push(Kind::Notice, notice, false);
    }
}

struct AppObserver<'a>(&'a mut App);

impl Observer for AppObserver<'_> {
    fn event(&mut self, event: Event) -> Result<(), String> {
        self.0.apply(event);
        self.0.render()
    }
}

fn picker(app: &mut App, title: &str, items: &[String]) -> Result<Option<usize>, String> {
    if items.is_empty() {
        return Err("nothing to select".to_string());
    }
    let mut selected = 0;
    let mut previous = None;
    loop {
        render_picker(title, items, selected, &mut previous)?;
        match event::read().map_err(|error| error.to_string())? {
            InputEvent::Resize(_, _) => {}
            InputEvent::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Up => selected = selected.saturating_sub(1),
                KeyCode::Down => selected = (selected + 1).min(items.len() - 1),
                KeyCode::Enter => {
                    app.invalidate();
                    app.render()?;
                    return Ok(Some(selected));
                }
                KeyCode::Esc => {
                    app.invalidate();
                    app.render()?;
                    return Ok(None);
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.invalidate();
                    app.render()?;
                    return Ok(None);
                }
                _ => {}
            },
            _ => {}
        }
    }
}

fn render_picker(
    title: &str,
    items: &[String],
    selected: usize,
    previous: &mut Option<Frame>,
) -> Result<(), String> {
    let (width, height) = terminal::size().map_err(|error| error.to_string())?;
    let next = picker_frame(width, height, title, items, selected);
    let mut output = io::stdout().lock();
    paint_frame(&mut output, previous.as_ref(), &next).map_err(|error| error.to_string())?;
    output.flush().map_err(|error| error.to_string())?;
    *previous = Some(next);
    Ok(())
}

fn picker_frame(width: u16, height: u16, title: &str, items: &[String], selected: usize) -> Frame {
    let width = usize::from(width).max(1);
    let height = usize::from(height);
    let mut frame = Frame::new(width, height);
    if height == 0 {
        return frame;
    }
    let visible = height.saturating_sub(2).max(1);
    let start = selected.saturating_sub(visible / 2);
    let end = (start + visible).min(items.len());
    frame.lines[0].push(Color::Cyan, &single_line(title), width);
    for (index, item) in items[start..end].iter().enumerate() {
        let actual = start + index;
        let color = if actual == selected {
            Color::Yellow
        } else {
            Color::White
        };
        let line = &mut frame.lines[index + 1];
        line.push(color, if actual == selected { "> " } else { "  " }, width);
        line.push(color, &single_line(item), width);
    }
    frame
}

fn color(kind: Kind) -> Color {
    match kind {
        Kind::User => Color::Green,
        Kind::Assistant => Color::White,
        Kind::Reasoning => Color::DarkGrey,
        Kind::Tool => Color::Cyan,
        Kind::ToolOutput => Color::DarkCyan,
        Kind::Notice => Color::Yellow,
        Kind::Error => Color::Red,
    }
}

fn clean(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() && !matches!(character, '\n' | '\t') {
                '�'
            } else {
                character
            }
        })
        .collect()
}

fn single_line(text: &str) -> String {
    clean(text).replace('\n', "↵")
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut result = Vec::new();
    for original in text.split('\n') {
        let mut line = String::new();
        let mut columns = 0;
        for character in original.chars() {
            if columns == width {
                result.push(std::mem::take(&mut line));
                columns = 0;
            }
            if character == '\t' {
                line.push(' ');
            } else {
                line.push(character);
            }
            columns += 1;
        }
        result.push(line);
    }
    if result.is_empty() {
        result.push(String::new());
    }
    result
}

fn editor_cursor(text: &str, cursor: usize, width: usize) -> (usize, usize) {
    let mut row = 0;
    let mut column = 0;
    for character in text[..cursor].chars() {
        if character == '\n' || column == width {
            row += 1;
            column = 0;
            if character == '\n' {
                continue;
            }
        }
        column += 1;
    }
    (row, column)
}

fn clipped(text: &str, width: usize) -> String {
    text.chars().take(width).collect()
}

fn suffix(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    let start = text.len() - limit;
    let start = (start..text.len())
        .find(|index| text.is_char_boundary(*index))
        .unwrap_or(text.len());
    text[start..].to_string()
}

fn fold(text: &str) -> String {
    let text = text.trim();
    if text.len() <= 200 && !text.contains('\n') {
        text.to_string()
    } else {
        format!("{} bytes", text.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        App {
            transcript: VecDeque::new(),
            bytes: 0,
            editor: Editor::new(),
            scroll: 0,
            status: "working".to_string(),
            model: "test/model".to_string(),
            session: SessionSummary {
                id: "test-session".to_string(),
                path: None,
                name: None,
                entries: 0,
                ephemeral: true,
            },
            approval: None,
            input_enabled: true,
            quit: false,
            last_frame: None,
        }
    }

    #[test]
    fn wrapping_and_cursor_agree() {
        assert_eq!(wrap("abcdef", 3), ["abc", "def"]);
        assert_eq!(editor_cursor("abcdef", 6, 3), (1, 3));
        assert_eq!(editor_cursor("ab\ncd", 5, 3), (1, 2));
    }

    #[test]
    fn controls_are_not_rendered() {
        assert_eq!(clean("a\x1bb"), "a�b");
        assert_eq!(single_line("a\nb\x1bc"), "a↵b�c");
    }

    #[test]
    fn transcript_editor_and_status_are_anchored_from_the_bottom() {
        assert_eq!(
            screen_layout(24, 1, false),
            Layout {
                transcript_rows: 22,
                approval_start: 22,
                approval_rows: 0,
                editor_start: 22,
                editor_rows: 1,
                status_row: 23,
            }
        );
        assert_eq!(
            screen_layout(24, 1, true),
            Layout {
                transcript_rows: 19,
                approval_start: 19,
                approval_rows: 3,
                editor_start: 22,
                editor_rows: 1,
                status_row: 23,
            }
        );
    }

    #[test]
    fn incremental_paint_writes_only_the_changed_suffix() {
        let mut old = Frame::new(10, 3);
        old.lines[1].push(Color::Green, "> ", 10);
        old.lines[1].push(Color::White, "a", 10);
        old.cursor = Some((3, 1));
        let mut new = old.clone();
        new.lines[1].push(Color::White, "b", 10);
        new.cursor = Some((4, 1));
        let mut output = Vec::new();

        paint_frame(&mut output, Some(&old), &new).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(!output.contains("[2J"), "{output:?}");
        assert!(output.contains("[2;4H"), "{output:?}");
        assert!(!output.contains("> a"), "{output:?}");
        assert!(output.contains('b'), "{output:?}");
    }

    #[test]
    fn runtime_events_keep_the_activity_marker_current() {
        let mut app = app();
        let status = |app: &App| {
            app.frame(80, 24).lines[23]
                .0
                .iter()
                .map(|cell| cell.character)
                .collect::<String>()
        };

        assert!(status(&app).starts_with("gears | working |"));
        app.apply(Event::Reasoning("plan".to_string()));
        assert!(status(&app).starts_with("gears | thinking |"));
        app.apply(Event::Text("answer".to_string()));
        assert!(status(&app).starts_with("gears | responding |"));
        app.apply(Event::Permission(Permission {
            tool: "sh".to_string(),
            detail: "true".to_string(),
            workspace: "/tmp".into(),
        }));
        assert!(status(&app).starts_with("gears | checking permission |"));
        app.apply(Event::TurnEnd);
        assert!(status(&app).starts_with("gears | idle |"));
    }

    #[test]
    fn status_and_disabled_prompt_use_the_chrome_palette() {
        let mut app = app();
        let frame = app.frame(80, 24);
        assert!(
            frame.lines[23]
                .0
                .iter()
                .all(|cell| cell.color == STATUS_COLOR)
        );
        assert_eq!(STATUS_COLOR, Color::AnsiValue(222));
        assert!(
            frame.lines[22].0[..2]
                .iter()
                .all(|cell| cell.color == STATUS_COLOR)
        );

        app.input_enabled = false;
        let frame = app.frame(80, 24);
        assert!(
            frame.lines[22].0[..2]
                .iter()
                .all(|cell| cell.color == Color::DarkGrey)
        );
    }

    #[test]
    fn exit_replaces_only_the_status_row_and_leaves_a_shell_gap() {
        let mut output = Vec::new();
        paint_exit(&mut output, 80, 24, "session-42").unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(!output.contains("[2J"), "{output:?}");
        assert!(
            output.contains("Motor OS Gears session session-42 exited."),
            "{output:?}"
        );
        assert!(output.contains("\r\n\r\n"), "{output:?}");
        assert!(!output.contains("?1049"), "{output:?}");
    }
}
