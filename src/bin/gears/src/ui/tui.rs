//! Safe terminal lifecycle and minimal drawing for the interactive UI.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::ops::Range;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

use crossterm::cursor::{Hide, MoveTo, Show};
use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste};
use crossterm::style::{
    Color, Print, ResetColor, SetBackgroundColor, SetForegroundColor, force_color_output,
};
use crossterm::terminal::{
    Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, ScrollUp as TerminalScrollUp,
    disable_raw_mode, enable_raw_mode,
};
use crossterm::{SynchronizedUpdate, execute, queue};

use super::command::{Command as LocalCommand, Input as ParsedInput, parse};
use super::highlight::{Kind as HighlightKind, Markdown, Span as Highlight};
use super::repl::Ui;
use super::state::{Activity, ArtifactPage, State};
use super::transcript::{Source, Transcript};
use super::tui_input::{Action, Input};
use crate::agent::artifact::LazyStore;
use crate::agent::bus::{
    AgentId, Decision, Event, PermissionRequest, PermissionView, ROOT, ToolStream, question,
};
use crate::agent::context::Window;
use crate::agent::gate::Gate;
use crate::agent::harness::{Command as AgentCommand, Harness};
use crate::agent::task::{ItemState, Task};
use crate::tools::selfhost::Restart;

const INPUT_POLL: Duration = Duration::from_millis(20);
const EVENT_BURST: usize = 64;
const APPROVAL_PAGE_BYTES: usize = 4096;
const KEPT: usize = 256 * 1024;
const INPUT_BACKGROUND: Color = Color::Rgb {
    r: 24,
    g: 24,
    b: 24,
};

struct Expansion {
    call: String,
    text: String,
}

type StyledFrame = (
    Vec<String>,
    Vec<Vec<Highlight>>,
    Option<(u16, u16)>,
    Range<usize>,
);

pub trait Surface {
    fn enter(&mut self) -> io::Result<()>;
    fn size(&self) -> io::Result<(u16, u16)>;
    fn draw(
        &mut self,
        size: (u16, u16),
        lines: &[String],
        highlights: &[Vec<Highlight>],
        cursor: Option<(u16, u16)>,
        input_rows: Range<usize>,
    ) -> io::Result<()>;
    fn leave(&mut self) -> io::Result<()>;
}

/// An entered alternate screen. Every return path restores it through Drop.
pub struct Screen<S: Surface> {
    surface: S,
    active: bool,
}

impl<S: Surface> Screen<S> {
    pub fn open(mut surface: S, state: &State) -> io::Result<Screen<S>> {
        surface.enter()?;
        let mut screen = Screen {
            surface,
            active: true,
        };
        if let Err(error) = screen.redraw(state) {
            screen.close();
            return Err(error);
        }
        Ok(screen)
    }

    /// Redrawing also handles resize: the current dimensions are read once
    /// for this complete frame rather than retained across terminal events.
    pub fn redraw(&mut self, state: &State) -> io::Result<()> {
        let size = self.surface.size()?;
        let (lines, highlights, cursor, input_rows) = styled_frame(state, size);
        self.surface
            .draw(size, &lines, &highlights, cursor, input_rows)
    }

    pub fn close(&mut self) {
        if self.active {
            self.active = false;
            let _ = self.surface.leave();
        }
    }
}

impl<S: Surface> Drop for Screen<S> {
    fn drop(&mut self) {
        self.close();
    }
}

/// Supplies an answer only after the pending request has been rendered.
pub trait Decisions {
    fn decide(
        &mut self,
        agent: AgentId,
        request: &PermissionRequest,
        navigate: &mut dyn FnMut(ApprovalNavigation) -> bool,
    ) -> Decision;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalNavigation {
    PageUp,
    PageDown,
    Resize,
}

/// Connects the terminal-independent projection to one safe screen.
pub struct Controller<S: Surface, D: Decisions> {
    screen: Screen<S>,
    state: State,
    decisions: D,
    artifacts: Option<Arc<LazyStore>>,
    expansions: Vec<Expansion>,
    kept: usize,
    started: BTreeMap<AgentId, String>,
}

impl<S: Surface, D: Decisions> Controller<S, D> {
    pub fn open(surface: S, decisions: D, task: Option<Task>) -> io::Result<Controller<S, D>> {
        let mut state = State::new();
        let _ = state.set_task(task);
        Self::open_state(surface, decisions, state)
    }

    fn open_state(surface: S, decisions: D, state: State) -> io::Result<Controller<S, D>> {
        let screen = Screen::open(surface, &state)?;
        Ok(Controller {
            screen,
            state,
            decisions,
            artifacts: None,
            expansions: Vec::new(),
            kept: 0,
            started: BTreeMap::new(),
        })
    }

    fn with_artifacts(mut self, artifacts: Arc<LazyStore>) -> Controller<S, D> {
        self.artifacts = Some(artifacts);
        self
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn set_task(&mut self, task: Option<Task>) -> io::Result<()> {
        if self.state.set_task(task) {
            self.screen.redraw(&self.state)?;
        }
        Ok(())
    }

    fn set_runtime(
        &mut self,
        model: &str,
        paused: bool,
        context: Window,
        task: Option<Task>,
    ) -> io::Result<()> {
        let runtime_changed = self.state.set_runtime(model, paused, context);
        let task_changed = self.state.set_task(task);
        if runtime_changed || task_changed {
            self.screen.redraw(&self.state)?;
        }
        Ok(())
    }

    fn set_transcript(&mut self, transcript: Transcript) -> io::Result<()> {
        if self.state.set_transcript(transcript) {
            self.screen.redraw(&self.state)?;
        }
        Ok(())
    }

    fn scroll(&mut self, up: bool) -> io::Result<()> {
        let page = usize::from(self.screen.surface.size()?.1 / 2).max(1);
        let changed = match up {
            true => self.state.scroll_up(page),
            false => self.state.scroll_down(page),
        };
        if changed {
            self.screen.redraw(&self.state)?;
        }
        Ok(())
    }

    pub fn start_turn(&mut self, prompt: &str) -> io::Result<()> {
        self.state
            .record_message(&crate::provider::ChatMessage::user(prompt));
        let _ = self.state.start_turn();
        self.screen.redraw(&self.state)
    }

    fn start_operation(&mut self) -> io::Result<()> {
        let _ = self.state.start_turn();
        self.screen.redraw(&self.state)
    }

    fn local_input(&mut self, input: &str) -> io::Result<()> {
        self.state
            .record_message(&crate::provider::ChatMessage::user(input));
        self.screen.redraw(&self.state)
    }

    fn notice(&mut self, text: &str) -> io::Result<()> {
        let _ = self.state.apply(&Event::Notice {
            agent: ROOT,
            text: text.to_string(),
        });
        self.screen.redraw(&self.state)
    }

    fn keep(&mut self, agent: AgentId, text: &str) {
        let call = self.started.get(&agent).cloned().unwrap_or_default();
        self.keep_named(call, text);
    }

    fn keep_named(&mut self, call: String, text: &str) {
        self.kept += text.len();
        self.expansions.push(Expansion {
            call,
            text: text.to_string(),
        });
        while self.kept > KEPT && self.expansions.len() > 1 {
            self.kept -= self.expansions.remove(0).text.len();
        }
    }

    fn expansion(&self, nth: usize) -> Result<String, String> {
        let found = nth
            .checked_sub(1)
            .and_then(|back| self.expansions.len().checked_sub(back + 1))
            .and_then(|index| self.expansions.get(index));
        let Some(found) = found else {
            return Err(match self.expansions.len() {
                0 => "nothing to expand".to_string(),
                kept => format!("no result {nth}; {kept} kept"),
            });
        };
        Ok(format!(
            "--- {} ({} bytes) ---\n{}",
            found.call,
            found.text.len(),
            found.text.trim_end()
        ))
    }
}

impl<S: Surface> Controller<S, Input> {
    fn poll_input(&mut self, timeout: Duration, editing: bool) -> io::Result<Option<Action>> {
        let action = self.decisions.poll(timeout, editing)?;
        let redraw = match action {
            Some(Action::Changed | Action::Submit(_)) => self
                .state
                .set_draft(self.decisions.draft(), self.decisions.cursor()),
            Some(Action::Resize) => true,
            _ => false,
        };
        if redraw {
            self.screen.redraw(&self.state)?;
        }
        Ok(action)
    }
}

impl<S: Surface, D: Decisions> Ui for Controller<S, D> {
    fn render(&mut self, event: &Event) -> io::Result<()> {
        match event {
            Event::ToolStart { agent, detail } => {
                self.started.insert(*agent, label(*agent, detail));
            }
            Event::ToolEnd {
                agent,
                full: Some(text),
                ..
            } => self.keep(*agent, text),
            _ => {}
        }
        let mut changed = self.state.apply(event);
        if let Event::Permission { request, .. } = event
            && let (Some(id), Some(artifacts)) =
                (request.view.preview_artifact, self.artifacts.as_deref())
        {
            let page = read_artifact_page(artifacts, id, 0).map_err(io::Error::other)?;
            changed |= self.state.start_approval_artifact(page);
        }
        if changed {
            self.screen.redraw(&self.state)?;
        }
        Ok(())
    }

    fn decide(&mut self, agent: AgentId, request: &PermissionRequest) -> Decision {
        let screen = &mut self.screen;
        let state = &mut self.state;
        let artifacts = self.artifacts.as_deref();
        let decision =
            self.decisions
                .decide(agent, request, &mut |navigation| match navigate_approval(
                    screen, state, artifacts, navigation,
                ) {
                    Ok(()) => true,
                    Err(error) => {
                        crate::trace::log(
                            crate::trace::Level::Error,
                            &format!("cannot navigate TUI approval: {error}"),
                        );
                        false
                    }
                });
        if self.state.resolve_approval(agent)
            && let Err(error) = self.screen.redraw(&self.state)
        {
            crate::trace::log(
                crate::trace::Level::Error,
                &format!("cannot clear TUI approval view: {error}"),
            );
        }
        decision
    }
}

#[derive(Clone, PartialEq, Eq)]
struct TerminalLine {
    text: String,
    highlights: Vec<Highlight>,
    input: bool,
}

#[derive(Clone)]
struct TerminalFrame {
    size: (u16, u16),
    lines: Vec<TerminalLine>,
}

impl TerminalFrame {
    fn new(
        size: (u16, u16),
        lines: &[String],
        highlights: &[Vec<Highlight>],
        input_rows: Range<usize>,
    ) -> TerminalFrame {
        let lines = lines
            .iter()
            .enumerate()
            .map(|(row, text)| TerminalLine {
                text: text.clone(),
                highlights: highlights.get(row).cloned().unwrap_or_default(),
                input: input_rows.contains(&row),
            })
            .collect();
        TerminalFrame { size, lines }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UpwardShift {
    top: usize,
    bottom: usize,
    amount: usize,
}

pub struct Crossterm<W: Write> {
    out: W,
    entered: bool,
    frame: Option<TerminalFrame>,
}

impl<W: Write> Crossterm<W> {
    pub fn new(out: W) -> Crossterm<W> {
        force_color_output(true);
        Crossterm {
            out,
            entered: false,
            frame: None,
        }
    }
}

impl<W: Write> Surface for Crossterm<W> {
    fn enter(&mut self) -> io::Result<()> {
        enable_raw_mode()?;
        if let Err(error) = execute!(
            self.out,
            EnterAlternateScreen,
            EnableBracketedPaste,
            Hide,
            SetForegroundColor(Color::White),
            SetBackgroundColor(Color::Black)
        ) {
            let _ = execute!(
                self.out,
                ResetColor,
                Show,
                DisableBracketedPaste,
                LeaveAlternateScreen
            );
            let _ = disable_raw_mode();
            return Err(error);
        }
        self.entered = true;
        Ok(())
    }

    fn size(&self) -> io::Result<(u16, u16)> {
        crossterm::terminal::size()
    }

    fn draw(
        &mut self,
        size: (u16, u16),
        lines: &[String],
        highlights: &[Vec<Highlight>],
        cursor: Option<(u16, u16)>,
        input_rows: Range<usize>,
    ) -> io::Result<()> {
        let next = TerminalFrame::new(size, lines, highlights, input_rows);
        let previous = self.frame.as_ref();
        self.out.sync_update(|out| -> io::Result<()> {
            queue!(out, Hide)?;
            match previous {
                Some(previous)
                    if previous.size == next.size && previous.lines.len() == next.lines.len() =>
                {
                    paint_update(out, previous, &next)?;
                }
                _ => paint_full(out, &next)?,
            }
            match cursor {
                Some((col, row)) => queue!(out, MoveTo(col, row), Show)?,
                None => queue!(out, Hide)?,
            }
            Ok(())
        })??;
        self.frame = Some(next);
        Ok(())
    }

    fn leave(&mut self) -> io::Result<()> {
        if !self.entered {
            return Ok(());
        }
        self.entered = false;
        self.frame = None;
        let margins = self.out.write_all(b"\x1b[r");
        let terminal = execute!(
            self.out,
            ResetColor,
            Show,
            DisableBracketedPaste,
            LeaveAlternateScreen
        );
        let raw = disable_raw_mode();
        margins.and(terminal).and(raw)
    }
}

fn paint_full<W: Write>(out: &mut W, frame: &TerminalFrame) -> io::Result<()> {
    queue!(
        out,
        SetForegroundColor(Color::White),
        SetBackgroundColor(Color::Black),
        MoveTo(0, 0),
        Clear(ClearType::All)
    )?;
    for (row, line) in frame.lines.iter().enumerate() {
        if !line.text.is_empty() || line.input {
            paint_line(out, row, line, 0, false)?;
        }
    }
    Ok(())
}

fn paint_update<W: Write>(
    out: &mut W,
    previous: &TerminalFrame,
    next: &TerminalFrame,
) -> io::Result<()> {
    if let Some(shift) = upward_shift(previous, next) {
        scroll_up(out, shift)?;
        for row in shift.bottom - shift.amount..shift.bottom {
            paint_line(out, row, &next.lines[row], 0, false)?;
        }
        return Ok(());
    }
    for (row, (old, new)) in previous.lines.iter().zip(&next.lines).enumerate() {
        if old != new {
            let erase_tail = old.text.chars().count() > new.text.chars().count();
            paint_line(out, row, new, unchanged_prefix(old, new), erase_tail)?;
        }
    }
    Ok(())
}

fn upward_shift(previous: &TerminalFrame, next: &TerminalFrame) -> Option<UpwardShift> {
    let len = previous.lines.len();
    let top = previous
        .lines
        .iter()
        .zip(&next.lines)
        .take_while(|(old, new)| old == new)
        .count();
    let suffix = previous.lines[top..]
        .iter()
        .rev()
        .zip(next.lines[top..].iter().rev())
        .take_while(|(old, new)| old == new)
        .count();
    let bottom = len - suffix;
    let height = bottom - top;
    (1..height).find_map(|amount| {
        (previous.lines[top + amount..bottom] == next.lines[top..bottom - amount]).then_some(
            UpwardShift {
                top,
                bottom,
                amount,
            },
        )
    })
}

fn scroll_up<W: Write>(out: &mut W, shift: UpwardShift) -> io::Result<()> {
    queue!(
        out,
        SetForegroundColor(Color::White),
        SetBackgroundColor(Color::Black)
    )?;
    write!(out, "\x1b[{};{}r", shift.top + 1, shift.bottom)?;
    let scroll = queue!(
        out,
        MoveTo(0, shift.top as u16),
        TerminalScrollUp(shift.amount as u16)
    );
    let margins = out.write_all(b"\x1b[r");
    scroll.and(margins)
}

fn paint_line<W: Write>(
    out: &mut W,
    row: usize,
    line: &TerminalLine,
    from: usize,
    erase_tail: bool,
) -> io::Result<()> {
    let column = line.text[..from].chars().count() as u16;
    let background = if line.input {
        INPUT_BACKGROUND
    } else {
        Color::Black
    };
    queue!(
        out,
        MoveTo(column, row as u16),
        SetForegroundColor(Color::White),
        SetBackgroundColor(background)
    )?;
    if from == 0 {
        queue!(out, Clear(ClearType::CurrentLine))?;
    }
    print_highlighted(out, &line.text, &line.highlights, from)?;
    if erase_tail {
        queue!(out, Clear(ClearType::UntilNewLine))?;
    }
    queue!(out, SetBackgroundColor(Color::Black))
}

fn unchanged_prefix(old: &TerminalLine, new: &TerminalLine) -> usize {
    if old.input != new.input {
        return 0;
    }
    let mut prefix = 0;
    for ((old_at, old_char), (new_at, new_char)) in
        old.text.char_indices().zip(new.text.char_indices())
    {
        if old_char != new_char
            || highlight_at(&old.highlights, old_at) != highlight_at(&new.highlights, new_at)
        {
            break;
        }
        prefix = old_at + old_char.len_utf8();
    }
    prefix
}

fn highlight_at(highlights: &[Highlight], at: usize) -> Option<HighlightKind> {
    highlights
        .iter()
        .find(|highlight| highlight.start <= at && at < highlight.end)
        .map(|highlight| highlight.kind)
}

fn print_highlighted<W: Write>(
    out: &mut W,
    line: &str,
    highlights: &[Highlight],
    from: usize,
) -> io::Result<()> {
    let mut at = from;
    for highlight in highlights {
        if highlight.start > highlight.end
            || highlight.end > line.len()
            || !line.is_char_boundary(highlight.start)
            || !line.is_char_boundary(highlight.end)
            || highlight.end <= from
        {
            continue;
        }
        let start = highlight.start.max(from);
        if start < at {
            continue;
        }
        queue!(
            out,
            Print(&line[at..start]),
            SetForegroundColor(highlight_color(highlight.kind)),
            Print(&line[start..highlight.end]),
            SetForegroundColor(Color::White)
        )?;
        at = highlight.end;
    }
    queue!(out, Print(&line[at..]))
}

fn highlight_color(kind: HighlightKind) -> Color {
    match kind {
        HighlightKind::Keyword => Color::Magenta,
        HighlightKind::Type => Color::Cyan,
        HighlightKind::String => Color::Green,
        HighlightKind::Number => Color::Yellow,
        HighlightKind::Comment => Color::DarkGrey,
        HighlightKind::Macro => Color::Blue,
        HighlightKind::Lifetime => Color::DarkYellow,
        HighlightKind::Heading => Color::Cyan,
        HighlightKind::Quote => Color::DarkGrey,
        HighlightKind::ListMarker => Color::Yellow,
        HighlightKind::InlineCode => Color::Green,
        HighlightKind::Strong => Color::Yellow,
        HighlightKind::Emphasis => Color::Magenta,
        HighlightKind::Link => Color::Blue,
        HighlightKind::Strikethrough => Color::DarkGrey,
        HighlightKind::Fence => Color::DarkGrey,
        HighlightKind::CodeBlock => Color::Green,
    }
}

#[cfg(test)]
fn frame(
    state: &State,
    (width, height): (u16, u16),
) -> (Vec<String>, Option<(u16, u16)>, Range<usize>) {
    let (lines, _highlights, cursor, input_rows) = styled_frame(state, (width, height));
    (lines, cursor, input_rows)
}

fn styled_frame(state: &State, (width, height): (u16, u16)) -> StyledFrame {
    if let Some(approval) = state.approval() {
        let lines = approval_frame(approval, width, height);
        let highlights = vec![Vec::new(); lines.len()];
        return (lines, highlights, None, 0..0);
    }
    let height = usize::from(height);
    if height == 0 {
        return (Vec::new(), Vec::new(), None, 0..0);
    }
    let footer = runtime_status(state, state.model().unwrap_or("none"));
    if height == 1 {
        let lines = finish(vec![footer], width);
        let highlights = vec![Vec::new(); lines.len()];
        return (lines, highlights, None, 0..0);
    }

    let mut header = vec!["Motor OS Gears".to_string()];
    for (agent, activity) in state.agents() {
        let activity = activity_line(activity);
        header.push(match *agent {
            ROOT => activity,
            id => format!("[{id}] {activity}"),
        });
    }
    if state.model().is_some() {
        header.extend(status_lines(state));
    } else if let Some(task) = state.task() {
        header.push(task.compact());
    }
    if state.scroll() > 0 {
        header.push(format!("scroll: {} lines from latest", state.scroll()));
    }
    let draft = state.draft();
    let draft_cursor = state.draft_cursor();
    let (draft_lines, cursor_line, cursor_col) = wrap_draft(draft, draft_cursor, width);
    let body_height = height - 1;
    if draft_lines.len() > body_height {
        let mut shown: Vec<String> = draft_lines.into_iter().rev().take(body_height).collect();
        shown.reverse();
        shown.push(footer);
        let lines = finish(shown, width);
        let input_rows = 0..body_height;
        let highlights = vec![Vec::new(); lines.len()];
        return (lines, highlights, None, input_rows);
    }

    let room_above_draft = body_height - draft_lines.len();
    header.truncate(room_above_draft);
    let transcript_room = room_above_draft - header.len();
    let (transcript, transcript_highlights) =
        transcript_lines(state.transcript(), usize::from(width).max(1));
    let end = transcript.len().saturating_sub(state.scroll());
    let start = end.saturating_sub(transcript_room);
    let transcript_rows = end - start;
    let gap = transcript_room - transcript_rows;
    let mut lines = header;
    lines.resize(lines.len() + gap, String::new());
    let mut highlights = vec![Vec::new(); lines.len()];
    lines.extend(transcript.into_iter().skip(start).take(end - start));
    highlights.extend(
        transcript_highlights
            .into_iter()
            .skip(start)
            .take(end - start),
    );
    let draft_start_row = lines.len();
    lines.extend(draft_lines);
    highlights.resize(lines.len(), Vec::new());
    let input_rows = draft_start_row..lines.len();
    lines.push(footer);
    highlights.push(Vec::new());
    let (lines, highlights) = finish_highlighted(lines, highlights, width);
    let cursor = Some((
        cursor_col.min(usize::from(width).saturating_sub(1)) as u16,
        (draft_start_row + cursor_line) as u16,
    ));
    (lines, highlights, cursor, input_rows)
}

fn approval_frame(approval: &super::state::Approval, width: u16, height: u16) -> Vec<String> {
    let height = usize::from(height);
    if height == 0 {
        return Vec::new();
    }
    let content = approval_content(approval, usize::from(width).max(1));
    let room = height.saturating_sub(2);
    let scroll = approval.scroll().min(content.len().saturating_sub(room));
    let mut lines = vec![approval_title(approval)];
    lines.extend(content.into_iter().skip(scroll).take(room));
    if height > 1 {
        lines
            .push("PageUp/PageDown browse | [y]es / [n]o / [a]lways; Enter/Esc denies".to_string());
    }
    lines.truncate(height);
    finish(lines, width)
}

fn approval_title(approval: &super::state::Approval) -> String {
    match approval.artifact() {
        Some(page) => format!(
            "Motor OS Gears — approval — artifact bytes {}..{} of {}",
            page.start, page.end, page.total
        ),
        None => "Motor OS Gears — approval".to_string(),
    }
}

fn approval_content(approval: &super::state::Approval, width: usize) -> Vec<String> {
    let request = approval.request();
    let requester = match approval.agent() {
        ROOT => "root agent".to_string(),
        id => format!("agent {id}"),
    };
    let mut fields = vec![
        format!("requester: {requester}"),
        format!("action: {}", request.detail),
        format!("cwd: {}", request.view.cwd),
        format!("scope: {}", request.key),
    ];
    if let Some(command) = &request.view.command {
        fields.push(format!(
            "command argv: {}",
            serde_json::to_string(command).unwrap()
        ));
    }
    if let Some(digest) = &request.view.digest {
        fields.push(format!("digest: {digest}"));
    }
    if let Some(artifact) = request.view.preview_artifact {
        fields.push(format!("complete diff: artifact {artifact}"));
    }
    let body = approval
        .artifact()
        .map(|page| page.text.as_str())
        .or(request.preview.as_deref());
    if let Some(body) = body {
        fields.extend(body.split('\n').map(str::to_string));
    }
    fields
        .into_iter()
        .flat_map(|line| wrap_line(&line, width))
        .collect()
}

fn wrap_line(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for character in text.chars() {
        line.push(if character.is_control() {
            ' '
        } else {
            character
        });
        if line.chars().count() == width {
            lines.push(std::mem::take(&mut line));
        }
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

/// Wrap a single line segment to `width` columns by character count, without
/// scrubbing control characters (downstream `safe_width` does that). An empty
/// input yields one empty row so callers always have at least one row.
fn wrap_segment(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut rows = Vec::new();
    let mut row = String::new();
    for character in text.chars() {
        row.push(character);
        if row.chars().count() == width {
            rows.push(std::mem::take(&mut row));
        }
    }
    if !row.is_empty() || rows.is_empty() {
        rows.push(row);
    }
    rows
}

/// Wrap the draft into prompt-prefixed rows, tracking which row and column the
/// cursor lands on so the terminal cursor follows wrapping rather than being
/// clamped to the last column of a truncated line.
fn wrap_draft(draft: &str, draft_cursor: usize, width: u16) -> (Vec<String>, usize, usize) {
    let width = usize::from(width).max(1);
    let mut draft_lines = Vec::new();
    let mut cursor_line = 0;
    let mut cursor_col = 0;
    let mut found = false;
    let mut byte_index = 0;
    for (index, line) in draft.split('\n').enumerate() {
        let prompt = if index == 0 { "gears> " } else { "  ...> " };
        let prompt_len = prompt.chars().count();
        let inner = width.saturating_sub(prompt_len).max(1);
        let cursor_in_line =
            if !found && byte_index <= draft_cursor && draft_cursor <= byte_index + line.len() {
                draft[byte_index..draft_cursor].chars().count()
            } else {
                usize::MAX
            };
        let segments = wrap_segment(line, inner);
        for (wrap_row, segment) in segments.iter().enumerate() {
            let lead = if wrap_row == 0 {
                prompt.to_string()
            } else {
                " ".repeat(prompt_len)
            };
            draft_lines.push(format!("{lead}{segment}"));
            if cursor_in_line != usize::MAX
                && !found
                && (wrap_row * inner) <= cursor_in_line
                && cursor_in_line <= (wrap_row * inner) + segment.chars().count()
            {
                cursor_line = draft_lines.len() - 1;
                cursor_col = prompt_len + (cursor_in_line - wrap_row * inner);
                found = true;
            }
        }
        byte_index += line.len() + 1; // +1 for '\n'
    }
    if draft_lines.is_empty() {
        draft_lines.push("gears> ".to_string());
    }
    (draft_lines, cursor_line, cursor_col)
}

fn navigate_approval<S: Surface>(
    screen: &mut Screen<S>,
    state: &mut State,
    artifacts: Option<&LazyStore>,
    navigation: ApprovalNavigation,
) -> io::Result<()> {
    if navigation == ApprovalNavigation::Resize {
        return screen.redraw(state);
    }
    let size = screen.surface.size()?;
    let page_rows = usize::from(size.1 / 2).max(1);
    let max_scroll = approval_max_scroll(state, size);
    let approval = state
        .approval()
        .ok_or_else(|| io::Error::other("no approval"))?;
    let scroll = approval.scroll();
    let changed = match navigation {
        ApprovalNavigation::PageUp if scroll > 0 => {
            state.set_approval_scroll(scroll.saturating_sub(page_rows))
        }
        ApprovalNavigation::PageDown if scroll < max_scroll => {
            state.set_approval_scroll(scroll.saturating_add(page_rows).min(max_scroll))
        }
        ApprovalNavigation::PageDown => {
            let Some(page) = approval.artifact() else {
                return Ok(());
            };
            if page.end == page.total {
                return Ok(());
            }
            let id = approval
                .request()
                .view
                .preview_artifact
                .ok_or_else(|| io::Error::other("approval artifact has no identity"))?;
            let artifacts = artifacts.ok_or_else(|| io::Error::other("no artifact store"))?;
            let next = read_artifact_page(artifacts, id, page.end).map_err(io::Error::other)?;
            state.advance_approval_artifact(next)
        }
        ApprovalNavigation::PageUp => {
            let Some(start) = approval.previous_page() else {
                return Ok(());
            };
            let id = approval
                .request()
                .view
                .preview_artifact
                .ok_or_else(|| io::Error::other("approval artifact has no identity"))?;
            let artifacts = artifacts.ok_or_else(|| io::Error::other("no artifact store"))?;
            let previous = read_artifact_page(artifacts, id, start).map_err(io::Error::other)?;
            let changed = state.retreat_approval_artifact(previous);
            let max_scroll = approval_max_scroll(state, size);
            changed | state.set_approval_scroll(max_scroll)
        }
        ApprovalNavigation::Resize => unreachable!(),
    };
    if changed {
        screen.redraw(state)?;
    }
    Ok(())
}

fn approval_max_scroll(state: &State, (width, height): (u16, u16)) -> usize {
    let Some(approval) = state.approval() else {
        return 0;
    };
    approval_content(approval, usize::from(width).max(1))
        .len()
        .saturating_sub(usize::from(height).saturating_sub(2))
}

fn read_artifact_page(store: &LazyStore, id: u64, start: u64) -> Result<ArtifactPage, String> {
    let slice = store.get()?.read_bytes(id, start, APPROVAL_PAGE_BYTES)?;
    let at_end = start + slice.bytes.len() as u64 == slice.total_size;
    let length = match std::str::from_utf8(&slice.bytes) {
        Ok(_) => slice.bytes.len(),
        Err(error) if error.error_len().is_none() && !at_end => error.valid_up_to(),
        Err(error) => return Err(format!("artifact {id} is not valid UTF-8: {error}")),
    };
    if length == 0 && !slice.bytes.is_empty() {
        return Err(format!(
            "artifact {id} has no complete UTF-8 character in a page"
        ));
    }
    let text = std::str::from_utf8(&slice.bytes[..length])
        .map_err(|error| format!("artifact {id} is not valid UTF-8: {error}"))?
        .to_string();
    Ok(ArtifactPage {
        start,
        end: start + length as u64,
        total: slice.total_size,
        text,
    })
}

fn runtime_status(state: &State, model: &str) -> String {
    let mode = state
        .task()
        .map(|task| crate::agent::mode::profile(task.mode()).name)
        .unwrap_or("none");
    let run = if state.paused() {
        "paused"
    } else {
        state.activity(ROOT).map(activity_name).unwrap_or("idle")
    };
    let active_subagents = state
        .agents()
        .iter()
        .filter(|(agent, activity)| **agent != ROOT && activity_is_active(activity))
        .count();
    format!("state: {run} | mode: {mode} | sub-agents: {active_subagents} | model: {model}")
}

fn status_lines(state: &State) -> Vec<String> {
    vec![
        task_progress(state.task()),
        context_status(state.context()),
        format!("usage: {}", state.usage().summary()),
    ]
}

fn activity_name(activity: &Activity) -> &'static str {
    match activity {
        Activity::Idle => "idle",
        Activity::Model => "model",
        Activity::Tool { .. } => "tool",
        Activity::Permission { .. } => "approval",
        Activity::Cancelled => "cancelled",
        Activity::Failed { .. } => "failed",
        Activity::Completed => "completed",
        Activity::Exited => "exited",
    }
}

fn activity_is_active(activity: &Activity) -> bool {
    matches!(
        activity,
        Activity::Idle | Activity::Model | Activity::Tool { .. } | Activity::Permission { .. }
    )
}

fn task_progress(task: Option<&Task>) -> String {
    let Some(task) = task else {
        return "task: none".to_string();
    };
    let count = |state| {
        task.items()
            .iter()
            .filter(|item| item.state() == state)
            .count()
    };
    format!(
        "task: {}/{} complete | {} active | {} pending | {} blocked",
        count(ItemState::Completed),
        task.items().len(),
        count(ItemState::Active),
        count(ItemState::Pending),
        count(ItemState::Blocked),
    )
}

fn context_status(window: Window) -> String {
    match (window.used, window.budget) {
        (Some(used), Some(budget)) if used <= budget => {
            format!(
                "context: {used}/{budget} tokens | {} headroom",
                budget - used
            )
        }
        (Some(used), Some(budget)) => {
            format!(
                "context: {used}/{budget} tokens | {} over budget",
                used - budget
            )
        }
        (None, Some(budget)) => {
            format!("context: awaiting provider usage | budget {budget} tokens")
        }
        (Some(used), None) => format!("context: {used} tokens | limit off"),
        (None, None) => "context: usage unavailable | limit off".to_string(),
    }
}

fn finish(lines: Vec<String>, width: u16) -> Vec<String> {
    lines
        .into_iter()
        .map(|line| safe_width(&line, usize::from(width)))
        .collect()
}

fn finish_highlighted(
    lines: Vec<String>,
    highlights: Vec<Vec<Highlight>>,
    width: u16,
) -> (Vec<String>, Vec<Vec<Highlight>>) {
    let mut finished = Vec::with_capacity(lines.len());
    let mut kept = Vec::with_capacity(lines.len());
    for (line, mut highlights) in lines.into_iter().zip(highlights) {
        let line = safe_width(&line, usize::from(width));
        highlights.retain_mut(|highlight| {
            highlight.end = highlight.end.min(line.len());
            highlight.start < highlight.end && line.is_char_boundary(highlight.start)
        });
        finished.push(line);
        kept.push(highlights);
    }
    (finished, kept)
}

fn transcript_lines(transcript: &Transcript, width: usize) -> (Vec<String>, Vec<Vec<Highlight>>) {
    let mut lines = Vec::new();
    let mut highlighted = Vec::new();
    for entry in transcript.entries() {
        let model_markdown = matches!(entry.source, Source::Model(_) | Source::Reasoning(_));
        let prefix = source_prefix(entry.source);
        let prefix_len = prefix.chars().count();
        let continuation = " ".repeat(prefix_len);
        let inner = width.saturating_sub(prefix_len).max(1);
        let mut markdown = Markdown::default();
        for (index, line) in entry.text.split('\n').enumerate() {
            let first_lead = if index == 0 {
                prefix.clone()
            } else {
                continuation.clone()
            };
            let mut syntax = markdown.line(line);
            if !model_markdown {
                syntax.retain(|span| !span.kind.is_markdown());
            }
            let mut segment_start = 0;
            for (wrap_row, segment) in wrap_segment(line, inner).into_iter().enumerate() {
                let lead = if wrap_row == 0 {
                    first_lead.clone()
                } else {
                    continuation.clone()
                };
                let segment_end = segment_start + segment.len();
                highlighted.push(rebase_highlights(
                    &syntax,
                    segment_start..segment_end,
                    lead.len(),
                ));
                lines.push(format!("{lead}{segment}"));
                segment_start = segment_end;
            }
        }
    }
    (lines, highlighted)
}

fn rebase_highlights(
    highlights: &[Highlight],
    segment: Range<usize>,
    prefix_bytes: usize,
) -> Vec<Highlight> {
    highlights
        .iter()
        .filter_map(|highlight| {
            let start = highlight.start.max(segment.start);
            let end = highlight.end.min(segment.end);
            (start < end).then(|| Highlight {
                start: prefix_bytes + start - segment.start,
                end: prefix_bytes + end - segment.start,
                kind: highlight.kind,
            })
        })
        .collect()
}

fn source_prefix(source: Source) -> String {
    let agent = |id: AgentId, label: &str| match id {
        ROOT => format!("{label}> "),
        id => format!("[{id}] {label}> "),
    };
    match source {
        Source::User => "you> ".to_string(),
        Source::Model(id) => agent(id, "agent"),
        Source::Reasoning(id) => agent(id, "thinking"),
        Source::Tool(id) => agent(id, "tool"),
        Source::ToolOutput(id, ToolStream::Stdout) => agent(id, "out"),
        Source::ToolOutput(id, ToolStream::Stderr) => agent(id, "err"),
        Source::Notice(id) => agent(id, "note"),
        Source::Failed(id) => agent(id, "failed"),
        Source::Permission(id) => agent(id, "approval"),
    }
}

/// Run the interactive TUI over the same harness and local command policy as
/// line mode.
pub fn interact(harness: &Harness, gate: Gate, restart: &Restart) -> Result<ExitCode, String> {
    let surface = Crossterm::new(std::io::stdout());
    let input = Input::new(gate);
    let mut controller = Controller::open_state(surface, input, durable_state(harness)?)
        .map_err(|error| format!("cannot start TUI: {error}"))?
        .with_artifacts(harness.artifacts());
    run(harness, &mut controller, restart, None)
}

/// Run one explicitly requested TUI prompt without asking the unattended gate
/// for a decision it cannot receive.
pub fn once(
    harness: &Harness,
    gate: Gate,
    restart: &Restart,
    prompt: &str,
) -> Result<ExitCode, String> {
    let surface = Crossterm::new(std::io::stdout());
    let input = Input::new(gate).unattended();
    let mut controller = Controller::open_state(surface, input, durable_state(harness)?)
        .map_err(|error| format!("cannot start TUI: {error}"))?
        .with_artifacts(harness.artifacts());
    run(harness, &mut controller, restart, Some(prompt))
}

fn run<S: Surface>(
    harness: &Harness,
    controller: &mut Controller<S, Input>,
    restart: &Restart,
    initial: Option<&str>,
) -> Result<ExitCode, String> {
    let one_shot = initial.is_some();
    let mut active = false;
    let mut local_operation = false;
    let mut failed = false;
    if let Some(prompt) = initial {
        match submit(harness, controller, prompt)? {
            Submitted::Turn => active = true,
            Submitted::Operation => {
                active = true;
                local_operation = true;
            }
            Submitted::Local | Submitted::Exit => return Ok(ExitCode::SUCCESS),
        }
    }

    loop {
        if let Some(action) = controller
            .poll_input(INPUT_POLL, !active && !one_shot)
            .map_err(|error| format!("TUI input: {error}"))?
        {
            match action {
                Action::Submit(prompt) if !prompt.trim().is_empty() => {
                    match submit(harness, controller, &prompt)? {
                        Submitted::Turn => active = true,
                        Submitted::Operation => {
                            active = true;
                            local_operation = true;
                        }
                        Submitted::Local => {}
                        Submitted::Exit => return Ok(exit_code(failed)),
                    }
                }
                Action::Cancel if active => harness.cancel(),
                Action::Cancel | Action::End if !active => {
                    return Ok(exit_code(failed));
                }
                Action::Pause => {
                    let paused = harness.toggle_paused();
                    controller
                        .set_runtime(
                            harness.model(),
                            paused,
                            harness.context_window(),
                            harness.task(),
                        )
                        .map_err(|error| error.to_string())?;
                }
                Action::ScrollUp => controller.scroll(true).map_err(|error| error.to_string())?,
                Action::ScrollDown => controller
                    .scroll(false)
                    .map_err(|error| error.to_string())?,
                _ => {}
            }
        }

        for _ in 0..EVENT_BURST {
            let event = match harness.events().try_recv() {
                Ok(event) => event,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return Ok(exit_code(failed)),
            };
            failed |= matches!(event, Event::Failed { .. });
            if matches!(event, Event::Permission { .. }) {
                // Keys entered before the question was visible cannot answer
                // it. Controls still take effect while queued text is ignored.
                while let Some(action) = controller
                    .poll_input(Duration::ZERO, false)
                    .map_err(|error| format!("TUI input: {error}"))?
                {
                    match action {
                        Action::Cancel => harness.cancel(),
                        Action::Pause => {
                            let paused = harness.toggle_paused();
                            controller
                                .set_runtime(
                                    harness.model(),
                                    paused,
                                    harness.context_window(),
                                    harness.task(),
                                )
                                .map_err(|error| error.to_string())?;
                        }
                        Action::ScrollUp => {
                            controller.scroll(true).map_err(|error| error.to_string())?
                        }
                        Action::ScrollDown => controller
                            .scroll(false)
                            .map_err(|error| error.to_string())?,
                        _ => {}
                    }
                }
            }
            let done = super::repl::dispatch(event, controller);
            controller
                .set_runtime(
                    harness.model(),
                    harness.paused(),
                    harness.context_window(),
                    harness.task(),
                )
                .map_err(|error| error.to_string())?;
            match done {
                Some(super::repl::Pumped::Turn { ok, .. }) => {
                    // A cancelled or failed turn has no durable assistant
                    // message to replace its partial live output. Keep that
                    // projection on screen; replay would discard reasoning
                    // and replace folded calls with full tool records.
                    if !local_operation && ok {
                        controller
                            .set_transcript(durable_transcript(harness)?)
                            .map_err(|error| error.to_string())?;
                    }
                    active = false;
                    local_operation = false;
                    if one_shot || restart.pending() {
                        return Ok(exit_code(failed));
                    }
                }
                Some(super::repl::Pumped::Exit | super::repl::Pumped::Closed) => {
                    return Ok(exit_code(failed));
                }
                Some(super::repl::Pumped::Broken(error)) => return Err(error),
                None => {}
            }
        }
    }
}

enum Submitted {
    Turn,
    Operation,
    Local,
    Exit,
}

fn submit<S: Surface>(
    harness: &Harness,
    controller: &mut Controller<S, Input>,
    input: &str,
) -> Result<Submitted, String> {
    match parse(input) {
        Ok(ParsedInput::Prompt(prompt)) => {
            harness.send(AgentCommand::Prompt(prompt.clone()))?;
            controller
                .start_turn(&prompt)
                .map_err(|error| error.to_string())?;
            Ok(Submitted::Turn)
        }
        parsed => {
            controller
                .local_input(input.trim())
                .map_err(|error| error.to_string())?;
            let command = match parsed {
                Ok(ParsedInput::Command(command)) => command,
                Err(error) => {
                    controller
                        .notice(&format!("! {error}"))
                        .map_err(|error| error.to_string())?;
                    return Ok(Submitted::Local);
                }
                Ok(ParsedInput::Prompt(_)) => unreachable!(),
            };
            if let LocalCommand::Compact(focus) = command {
                harness.send(AgentCommand::Compact { focus })?;
                controller
                    .start_operation()
                    .map_err(|error| error.to_string())?;
                return Ok(Submitted::Operation);
            }
            match execute(harness, controller, command) {
                Ok(true) => Ok(Submitted::Local),
                Ok(false) => Ok(Submitted::Exit),
                Err(error) => {
                    controller
                        .notice(&format!("! {error}"))
                        .map_err(|error| error.to_string())?;
                    Ok(Submitted::Local)
                }
            }
        }
    }
}

fn execute<S: Surface>(
    harness: &Harness,
    controller: &mut Controller<S, Input>,
    command: LocalCommand,
) -> Result<bool, String> {
    let text = match command {
        LocalCommand::Quit => return Ok(false),
        LocalCommand::Help => super::terminal::HELP.to_string(),
        LocalCommand::Status => status(harness, controller)?,
        LocalCommand::Pause => {
            harness.set_paused(true);
            "- paused before the next operation".to_string()
        }
        LocalCommand::Resume => {
            harness.set_paused(false);
            "- resumed".to_string()
        }
        LocalCommand::Mode(mode) => format!("- {}", harness.select_mode(mode)?),
        LocalCommand::Expand(nth) => controller.expansion(nth)?,
        LocalCommand::Undo => undo(harness, controller)?,
        LocalCommand::Compact(_) => unreachable!("compaction is an active harness operation"),
    };
    controller
        .set_runtime(
            harness.model(),
            harness.paused(),
            harness.context_window(),
            harness.task(),
        )
        .map_err(|error| error.to_string())?;
    controller
        .notice(&text)
        .map_err(|error| error.to_string())?;
    Ok(true)
}

fn status<S: Surface>(
    harness: &Harness,
    controller: &Controller<S, Input>,
) -> Result<String, String> {
    let text = format!(
        "session {} | {} | {}\n{} | {} files changed",
        harness.session_id(),
        harness.model(),
        harness.workspace().display(),
        controller.state().usage().summary(),
        harness.changed_files()?.len(),
    );
    let paused = match harness.paused() {
        true => format!("{text} | paused"),
        false => text,
    };
    Ok(match harness.task() {
        Some(task) => format!("{paused}\n{}", task.compact()),
        None => paused,
    })
}

fn label(agent: AgentId, detail: &str) -> String {
    match agent {
        ROOT => detail.to_string(),
        id => format!("[{id}] {detail}"),
    }
}

fn undo<S: Surface>(
    harness: &Harness,
    controller: &mut Controller<S, Input>,
) -> Result<String, String> {
    match harness.initial_checkpoint()? {
        Some(id) => match harness.prepare_checkpoint_restore(id)? {
            Some(prepared) => restore_prepared(harness, controller, prepared),
            None => Ok("- nothing to undo".to_string()),
        },
        None => {
            let restored = harness.undo().restore()?;
            Ok(match restored.is_empty() {
                true => "- nothing to undo".to_string(),
                false => format!("- put back: {}", restored.join(", ")),
            })
        }
    }
}

fn restore_prepared<S: Surface>(
    harness: &Harness,
    controller: &mut Controller<S, Input>,
    prepared: crate::tools::mutation::Prepared,
) -> Result<String, String> {
    let request = PermissionRequest::new(
        prepared.permission_key().to_string(),
        "undo session changes",
    )
    .with_preview(prepared.preview())
    .with_view(PermissionView {
        digest: Some(prepared.digest().to_string()),
        ..PermissionView::default()
    });
    let (reply, _answer) = question();
    controller
        .render(&Event::Permission {
            agent: ROOT,
            request: request.clone(),
            reply,
        })
        .map_err(|error| error.to_string())?;
    let decision = controller.decide(ROOT, &request);
    let usage = controller.state().usage();
    controller
        .render(&Event::TurnEnd {
            agent: ROOT,
            usage,
            ok: true,
        })
        .map_err(|error| error.to_string())?;
    harness
        .restore_checkpoint(prepared, decision)
        .map(|result| format!("- {result}"))
}

fn durable_state(harness: &Harness) -> Result<State, String> {
    let mut state = State::with_transcript_limit(harness.live_render_limit());
    let _ = state.set_runtime(harness.model(), harness.paused(), harness.context_window());
    let _ = state.set_task(harness.task());
    let transcript = durable_transcript(harness)?;
    let _ = state.set_transcript(transcript);
    Ok(state)
}

fn durable_transcript(harness: &Harness) -> Result<Transcript, String> {
    let mut transcript = Transcript::new(harness.live_render_limit());
    let damaged = harness.replay_messages(|message| transcript.record(&message))?;
    if damaged > 0 {
        crate::trace::log(
            crate::trace::Level::Warn,
            &format!("session transcript contains {damaged} unreadable records"),
        );
    }
    Ok(transcript)
}

fn exit_code(failed: bool) -> ExitCode {
    match failed {
        true => ExitCode::FAILURE,
        false => ExitCode::SUCCESS,
    }
}

fn activity_line(activity: &Activity) -> String {
    match activity {
        Activity::Idle => "idle".to_string(),
        Activity::Model => "model".to_string(),
        Activity::Tool { detail, elapsed } => {
            format!("tool {:.1}s: {detail}", elapsed.as_secs_f64())
        }
        Activity::Permission { detail } => format!("allow {detail}? [y]es / [n]o / [a]lways"),
        Activity::Cancelled => "cancelled".to_string(),
        Activity::Failed { detail } => format!("failed: {detail}"),
        Activity::Completed => "completed".to_string(),
        Activity::Exited => "exited".to_string(),
    }
}

fn safe_width(text: &str, width: usize) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(width)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::agent::bus::question;
    use crate::provider::Usage;

    use super::super::repl::{Pumped, dispatch};

    type Asked = Rc<RefCell<Vec<(AgentId, String)>>>;

    #[derive(Default)]
    struct Calls {
        entered: usize,
        left: usize,
        frames: Vec<Vec<String>>,
    }

    struct Fake {
        calls: Rc<RefCell<Calls>>,
        size: (u16, u16),
        fail_enter: bool,
        fail_draw: bool,
    }

    impl Surface for Fake {
        fn enter(&mut self) -> io::Result<()> {
            if self.fail_enter {
                return Err(io::Error::other("setup failed"));
            }
            self.calls.borrow_mut().entered += 1;
            Ok(())
        }

        fn size(&self) -> io::Result<(u16, u16)> {
            Ok(self.size)
        }

        fn draw(
            &mut self,
            _size: (u16, u16),
            lines: &[String],
            _highlights: &[Vec<Highlight>],
            _cursor: Option<(u16, u16)>,
            _input_rows: Range<usize>,
        ) -> io::Result<()> {
            if self.fail_draw {
                return Err(io::Error::other("draw failed"));
            }
            self.calls.borrow_mut().frames.push(lines.to_vec());
            Ok(())
        }

        fn leave(&mut self) -> io::Result<()> {
            self.calls.borrow_mut().left += 1;
            Ok(())
        }
    }

    fn fake(calls: Rc<RefCell<Calls>>) -> Fake {
        Fake {
            calls,
            size: (80, 24),
            fail_enter: false,
            fail_draw: false,
        }
    }

    struct Scripted {
        answers: Vec<Decision>,
        asked: Asked,
    }

    struct Browsing {
        digest: Rc<RefCell<Option<String>>>,
    }

    impl Decisions for Browsing {
        fn decide(
            &mut self,
            _agent: AgentId,
            request: &PermissionRequest,
            navigate: &mut dyn FnMut(ApprovalNavigation) -> bool,
        ) -> Decision {
            request
                .view
                .digest
                .clone_into(&mut self.digest.borrow_mut());
            assert!(navigate(ApprovalNavigation::PageDown));
            assert!(navigate(ApprovalNavigation::PageUp));
            assert!(navigate(ApprovalNavigation::PageDown));
            Decision::Allow
        }
    }

    impl Decisions for Scripted {
        fn decide(
            &mut self,
            agent: AgentId,
            request: &PermissionRequest,
            _navigate: &mut dyn FnMut(ApprovalNavigation) -> bool,
        ) -> Decision {
            self.asked
                .borrow_mut()
                .push((agent, request.detail.clone()));
            self.answers.pop().unwrap_or(Decision::Deny)
        }
    }

    fn scripted(answer: Decision) -> (Scripted, Asked) {
        let asked = Rc::new(RefCell::new(Vec::new()));
        (
            Scripted {
                answers: vec![answer],
                asked: asked.clone(),
            },
            asked,
        )
    }

    #[test]
    fn setup_redraw_resize_and_drop_are_balanced() {
        let calls = Rc::new(RefCell::new(Calls::default()));
        let mut screen = Screen::open(fake(calls.clone()), &State::new()).unwrap();
        screen.surface.size = (5, 1);
        screen.redraw(&State::new()).unwrap();
        drop(screen);
        let calls = calls.borrow();
        assert_eq!((calls.entered, calls.left, calls.frames.len()), (1, 1, 2));
        assert_eq!(calls.frames[1], ["state"]);
    }

    #[test]
    fn setup_and_output_failures_restore_exactly_when_needed() {
        let calls = Rc::new(RefCell::new(Calls::default()));
        let mut setup = fake(calls.clone());
        setup.fail_enter = true;
        assert!(Screen::open(setup, &State::new()).is_err());
        assert_eq!(calls.borrow().left, 0);

        let mut output = fake(calls.clone());
        output.fail_draw = true;
        assert!(Screen::open(output, &State::new()).is_err());
        assert_eq!(calls.borrow().left, 1);
    }

    #[test]
    fn crossterm_draws_with_an_explicit_white_on_black_palette() {
        let mut surface = Crossterm::new(Vec::new());
        surface
            .draw((80, 1), &["frame".to_string()], &[Vec::new()], None, 0..0)
            .unwrap();

        let mut palette = Vec::new();
        queue!(
            &mut palette,
            SetForegroundColor(Color::White),
            SetBackgroundColor(Color::Black)
        )
        .unwrap();
        assert!(!palette.is_empty());
        assert!(
            surface
                .out
                .windows(palette.len())
                .any(|bytes| bytes == palette)
        );
    }

    #[test]
    fn crossterm_draws_the_input_panel_on_a_lighter_background() {
        let mut surface = Crossterm::new(Vec::new());
        surface
            .draw(
                (80, 2),
                &["transcript".to_string(), "gears> ".to_string()],
                &[Vec::new(), Vec::new()],
                Some((7, 1)),
                1..2,
            )
            .unwrap();

        let mut input_line = Vec::new();
        queue!(
            &mut input_line,
            SetBackgroundColor(INPUT_BACKGROUND),
            Clear(ClearType::CurrentLine),
            Print("gears> "),
            SetBackgroundColor(Color::Black)
        )
        .unwrap();
        assert!(!input_line.is_empty());
        assert!(
            surface
                .out
                .windows(input_line.len())
                .any(|bytes| bytes == input_line)
        );
    }

    #[test]
    fn streaming_appends_only_the_new_suffix_and_restores_the_cursor_last() {
        let mut surface = Crossterm::new(Vec::new());
        let old = ["header", "thinking> abc", "gears> ", "status"].map(str::to_string);
        let highlights = vec![Vec::new(); old.len()];
        surface
            .draw((80, 4), &old, &highlights, Some((7, 2)), 2..3)
            .unwrap();
        surface.out.clear();

        let new = ["header", "thinking> abcdef", "gears> ", "status"].map(str::to_string);
        surface
            .draw((80, 4), &new, &highlights, Some((7, 2)), 2..3)
            .unwrap();

        let output = String::from_utf8_lossy(&surface.out);
        assert!(output.contains("def"), "{output:?}");
        for unchanged in ["header", "thinking> abc", "gears> ", "status"] {
            assert!(
                !output.contains(unchanged),
                "repainted {unchanged:?}: {output:?}"
            );
        }
        assert!(!output.contains(&Clear(ClearType::All).to_string()));
        let move_cursor = MoveTo(7, 2).to_string();
        let show = Show.to_string();
        let move_at = output.rfind(&move_cursor).expect("final input cursor move");
        let show_at = output.rfind(&show).expect("final cursor show");
        assert!(
            move_at < show_at,
            "cursor shown before it was moved: {output:?}"
        );
    }

    #[test]
    fn viewport_scrolling_is_one_terminal_operation() {
        let mut surface = Crossterm::new(Vec::new());
        let old = ["header", "line a", "line b", "line c", "gears> ", "status"].map(str::to_string);
        let highlights = vec![Vec::new(); old.len()];
        surface
            .draw((80, 6), &old, &highlights, Some((7, 4)), 4..5)
            .unwrap();
        surface.out.clear();

        let new = ["header", "line b", "line c", "line d", "gears> ", "status"].map(str::to_string);
        surface
            .draw((80, 6), &new, &highlights, Some((7, 4)), 4..5)
            .unwrap();

        let output = String::from_utf8_lossy(&surface.out);
        assert!(
            output.contains("\x1b[2;4r\x1b[2;1H\x1b[1S\x1b[r"),
            "{output:?}"
        );
        assert!(output.contains("line d"), "{output:?}");
        for moved in ["header", "line b", "line c", "gears> ", "status"] {
            assert!(!output.contains(moved), "repainted {moved:?}: {output:?}");
        }
    }

    #[test]
    fn a_resize_invalidates_the_retained_frame() {
        let mut surface = Crossterm::new(Vec::new());
        let lines = ["frame".to_string()];
        let highlights = [Vec::new()];
        surface
            .draw((80, 1), &lines, &highlights, None, 0..0)
            .unwrap();
        surface.out.clear();
        surface
            .draw((79, 1), &lines, &highlights, None, 0..0)
            .unwrap();
        let output = String::from_utf8_lossy(&surface.out);
        assert!(output.contains(&Clear(ClearType::All).to_string()));
        assert!(output.contains("frame"));
    }

    #[test]
    fn fenced_rust_in_expanded_tool_output_reaches_the_terminal_as_semantic_colors() {
        let mut state = State::new();
        state.apply(&Event::Notice {
            agent: ROOT,
            text: "--- read_file (72 bytes) ---\n```rust\npub fn main() { println!(\"hello\", 42); } // done\n```".into(),
        });
        let (lines, highlights, _, _) = styled_frame(&state, (100, 24));
        let row = lines
            .iter()
            .position(|line| line.contains("pub fn main"))
            .expect("rendered Rust line");
        let kinds: Vec<_> = highlights[row]
            .iter()
            .map(|highlight| highlight.kind)
            .collect();
        assert_eq!(
            kinds,
            [
                HighlightKind::Keyword,
                HighlightKind::Keyword,
                HighlightKind::Macro,
                HighlightKind::String,
                HighlightKind::Number,
                HighlightKind::Comment,
            ]
        );

        let mut surface = Crossterm::new(Vec::new());
        surface
            .draw((100, 24), &lines, &highlights, None, 0..0)
            .expect("draw highlighted frame");
        for color in [
            Color::Magenta,
            Color::Blue,
            Color::Green,
            Color::Yellow,
            Color::DarkGrey,
        ] {
            let mut command = Vec::new();
            queue!(&mut command, SetForegroundColor(color)).unwrap();
            assert!(!command.is_empty());
            assert!(
                surface
                    .out
                    .windows(command.len())
                    .any(|bytes| bytes == command),
                "missing {color:?} in {:?}",
                surface.out
            );
        }
    }

    #[test]
    fn fenced_rust_in_reasoning_produces_highlights() {
        let mut state = State::new();
        state.apply(&Event::Reasoning {
            agent: ROOT,
            text: "```rust\nlet value: usize = 42;\n```".into(),
        });
        let (lines, highlights, _, _) = styled_frame(&state, (80, 24));
        let row = lines
            .iter()
            .position(|line| line.contains("let value"))
            .expect("rendered reasoning code");
        assert!(!highlights[row].is_empty(), "missing spans: {lines:?}");
    }

    #[test]
    fn rust_highlights_survive_transcript_wrapping() {
        let mut transcript = Transcript::new(1024);
        transcript.record(&crate::provider::ChatMessage::assistant(
            "```rust\nlet value: usize = 123456789;\n```",
        ));
        let (lines, highlights) = transcript_lines(&transcript, 14);
        assert!(lines.iter().all(|line| line.chars().count() <= 14));
        let kinds: Vec<_> = highlights
            .iter()
            .flatten()
            .map(|highlight| highlight.kind)
            .collect();
        assert_eq!(
            kinds,
            [
                HighlightKind::Fence,
                HighlightKind::Keyword,
                HighlightKind::Type,
                HighlightKind::Type,
                HighlightKind::Number,
                HighlightKind::Number,
                HighlightKind::Fence,
            ]
        );
    }

    #[test]
    fn model_markdown_is_colored_while_user_markers_stay_literal() {
        let mut transcript = Transcript::new(1024);
        transcript.record(&crate::provider::ChatMessage::user("- `literal`"));
        transcript.record(&crate::provider::ChatMessage::assistant(
            "- `transcript.record(...)` and **important**",
        ));
        let (lines, highlights) = transcript_lines(&transcript, 100);
        let user = lines
            .iter()
            .position(|line| line.contains("literal"))
            .expect("rendered user line");
        let model = lines
            .iter()
            .position(|line| line.contains("transcript.record"))
            .expect("rendered model line");
        assert!(highlights[user].is_empty());
        assert_eq!(
            highlights[model]
                .iter()
                .map(|highlight| highlight.kind)
                .collect::<Vec<_>>(),
            [
                HighlightKind::ListMarker,
                HighlightKind::InlineCode,
                HighlightKind::Strong,
            ]
        );

        let mut surface = Crossterm::new(Vec::new());
        surface
            .draw((100, 24), &lines, &highlights, None, 0..0)
            .unwrap();
        for color in [Color::Green, Color::Yellow] {
            let mut command = Vec::new();
            queue!(&mut command, SetForegroundColor(color)).unwrap();
            assert!(
                surface
                    .out
                    .windows(command.len())
                    .any(|bytes| bytes == command),
                "missing Markdown color {color:?}"
            );
        }
    }

    #[test]
    fn unwinding_restores_the_screen() {
        let calls = Rc::new(RefCell::new(Calls::default()));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _screen = Screen::open(fake(calls.clone()), &State::new()).unwrap();
            panic!("test panic");
        }));
        assert!(result.is_err());
        assert_eq!(calls.borrow().left, 1);
    }

    #[test]
    fn frame_text_cannot_inject_terminal_controls() {
        let mut state = State::new();
        state.apply(&crate::agent::bus::Event::Failed {
            agent: ROOT,
            text: "bad\x1b[2J\nnext".into(),
        });
        let rendered = frame(&state, (80, 24)).0.join("\n");
        assert!(!rendered.contains('\x1b'), "{rendered:?}");
        assert!(!rendered.contains("\nnext"), "{rendered:?}");
    }

    #[test]
    fn multiline_drafts_have_explicit_continuation_prompts() {
        let mut state = State::new();
        state.set_draft("first\nsecond", 0);
        let (rendered, _, input_rows) = frame(&state, (80, 24));
        assert_eq!(&rendered[input_rows], ["gears> first", "  ...> second"]);
        assert_eq!(
            rendered.last().unwrap(),
            "state: idle | mode: none | sub-agents: 0 | model: none"
        );
    }

    #[test]
    fn cursor_appears_at_the_right_column_and_row() {
        let mut state = State::new();
        // "gears> ab" — cursor after "ab" at column 9 (prompt is 7 chars).
        state.set_draft("ab", 2);
        let (lines, cursor, _) = frame(&state, (80, 24));
        assert_eq!(cursor, Some((9, lines.len() as u16 - 2)));
        assert!(lines[lines.len() - 2].starts_with("gears> ab"));

        // Empty draft — cursor right after the prompt at column 7.
        state.set_draft("", 0);
        let (lines, cursor, _) = frame(&state, (80, 24));
        assert_eq!(cursor, Some((7, lines.len() as u16 - 2)));

        // Multiline: cursor on the second line, between 'c' and 'd' at col 8.
        state.set_draft("ab\ncd", 4);
        let (lines, cursor, _) = frame(&state, (80, 24));
        let row = lines.len() as u16 - 2;
        assert_eq!(cursor, Some((8, row)));
        assert_eq!(lines[lines.len() - 2], "  ...> cd");
    }

    #[test]
    fn no_cursor_during_approval_or_when_draft_is_truncated() {
        let mut state = State::new();
        // When the draft itself cannot fit above the footer, its cursor is
        // suppressed rather than pointed at a row that is no longer visible.
        let mut big = State::new();
        big.set_draft("one\ntwo\nthree", 13);
        let (_lines, cursor, _) = frame(&big, (80, 3));
        assert_eq!(cursor, None);

        // During approval the cursor is also suppressed.
        let (reply, _answer) = question();
        state.apply(&Event::Permission {
            agent: ROOT,
            request: PermissionRequest::new("write_file", "write_file x").with_preview("diff"),
            reply,
        });
        let (_lines, cursor, _) = frame(&state, (80, 24));
        assert_eq!(cursor, None);
    }

    #[test]
    fn transcript_uses_labels_and_keeps_the_newest_lines_above_the_prompt() {
        let mut state = State::new();
        state.record_message(&crate::provider::ChatMessage::user("inspect\nthis"));
        state.apply(&Event::Token {
            agent: 3,
            text: "working".into(),
        });

        let rendered = frame(&state, (80, 7)).0;
        assert_eq!(rendered[3], "     this");
        assert_eq!(rendered[4], "[3] agent> working");
        assert_eq!(rendered[5], "gears> ");
        assert!(rendered[6].starts_with("state: idle"));
    }

    #[test]
    fn transcript_navigation_moves_away_and_returns_to_latest() {
        let mut state = State::new();
        for line in ["one", "two", "three", "four"] {
            state.record_message(&crate::provider::ChatMessage::user(line));
        }
        assert!(state.scroll_up(2));
        let rendered = frame(&state, (80, 6)).0;
        assert!(
            rendered.iter().any(|line| line == "you> two"),
            "{rendered:?}"
        );
        assert!(!rendered.iter().any(|line| line == "you> four"));

        assert!(state.scroll_down(usize::MAX));
        let rendered = frame(&state, (80, 6)).0;
        assert!(
            rendered.iter().any(|line| line == "you> four"),
            "{rendered:?}"
        );
    }

    #[test]
    fn status_reports_runtime_progress_and_provider_accounting() {
        let mut task = Task::new(
            "finish it".into(),
            vec!["done".into(), "working".into(), "stuck".into()],
            crate::agent::task::Mode::Code,
        )
        .unwrap();
        task.transition(1, ItemState::Pending, ItemState::Active, None)
            .unwrap();
        task.transition(1, ItemState::Active, ItemState::Completed, None)
            .unwrap();
        task.transition(2, ItemState::Pending, ItemState::Active, None)
            .unwrap();
        task.transition(3, ItemState::Pending, ItemState::Blocked, None)
            .unwrap();

        let mut usage = crate::provider::UsageMeter::new();
        usage.add(&Usage {
            prompt_tokens: 100,
            completion_tokens: 20,
            total_tokens: 120,
            cost: Some(0.0123),
        });
        let mut state = State::new();
        let _ = state.set_task(Some(task));
        assert!(state.set_runtime(
            "test/model",
            true,
            Window {
                used: Some(140),
                budget: Some(128),
            },
        ));
        assert!(!state.set_runtime(
            "test/model",
            true,
            Window {
                used: Some(140),
                budget: Some(128),
            },
        ));
        state.apply(&Event::TurnEnd {
            agent: ROOT,
            usage,
            ok: true,
        });
        state.apply(&Event::ToolStart {
            agent: ROOT,
            detail: "cargo test".into(),
        });
        state.apply(&Event::ToolProgress {
            agent: ROOT,
            elapsed: Duration::from_millis(2_300),
        });
        state.apply(&Event::Token {
            agent: 2,
            text: "reviewing".into(),
        });

        let rendered = frame(&state, (120, 24)).0;
        assert_eq!(
            rendered.last().unwrap(),
            "state: paused | mode: code | sub-agents: 1 | model: test/model"
        );
        assert!(
            rendered
                .iter()
                .any(|line| { line == "task: 1/3 complete | 1 active | 0 pending | 1 blocked" })
        );
        assert!(rendered.iter().any(|line| line == "tool 2.3s: cargo test"));
        assert!(
            rendered
                .iter()
                .any(|line| line == "context: 140/128 tokens | 12 over budget")
        );
        assert!(
            rendered
                .iter()
                .any(|line| line == "usage: 1 completions, 100 + 20 tokens, $0.0123")
        );
    }

    #[test]
    fn controller_reduces_activity_and_coalesces_streamed_transcript() {
        let calls = Rc::new(RefCell::new(Calls::default()));
        let (decisions, _) = scripted(Decision::Deny);
        let mut controller = Controller::open(fake(calls.clone()), decisions, None).unwrap();

        assert!(
            dispatch(
                Event::Token {
                    agent: ROOT,
                    text: "one".into(),
                },
                &mut controller
            )
            .is_none()
        );
        assert!(
            dispatch(
                Event::Token {
                    agent: ROOT,
                    text: "two".into(),
                },
                &mut controller
            )
            .is_none()
        );
        assert_eq!(controller.state().activity(ROOT), Some(&Activity::Model));
        assert_eq!(controller.state().transcript().entries()[0].text, "onetwo");
        // Initial frame and one redraw for each visible streamed chunk.
        assert_eq!(calls.borrow().frames.len(), 3);
    }

    #[test]
    fn permission_is_visible_before_the_controller_answers() {
        let calls = Rc::new(RefCell::new(Calls::default()));
        let (decisions, asked) = scripted(Decision::Always);
        let mut controller = Controller::open(fake(calls.clone()), decisions, None).unwrap();
        let (reply, answer) = question();

        assert!(
            dispatch(
                Event::Permission {
                    agent: 4,
                    request: PermissionRequest::new("write_file", "write_file src/main.rs")
                        .with_preview("prepared write_file\ndigest: sha256:abc\n+new")
                        .with_view(crate::agent::bus::PermissionView {
                            cwd: "crate".into(),
                            command: None,
                            digest: Some("sha256:abc".into()),
                            preview_artifact: Some(7),
                        }),
                    reply,
                },
                &mut controller,
            )
            .is_none()
        );

        assert_eq!(answer.wait(), Some(Decision::Always));
        assert_eq!(&*asked.borrow(), &[(4, "write_file src/main.rs".into())]);
        assert_eq!(controller.state().activity(4), Some(&Activity::Model));
        assert!(controller.state().approval().is_none());
        let calls = calls.borrow();
        let shown = calls.frames[1].join("\n");
        assert!(shown.contains("requester: agent 4"), "{shown}");
        assert!(shown.contains("cwd: crate"), "{shown}");
        assert!(shown.contains("scope: write_file"), "{shown}");
        assert!(shown.contains("digest: sha256:abc"), "{shown}");
        assert!(shown.contains("complete diff: artifact 7"), "{shown}");
        assert!(shown.contains("+new"), "{shown}");
    }

    #[test]
    fn approval_pages_the_complete_artifact_before_deciding() {
        let root = std::env::temp_dir().join(format!(
            "gears-tui-approval-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let artifacts = Arc::new(LazyStore::new(root.clone(), "1-1".into(), 8192, 16384).unwrap());
        let complete = format!("{}éSECOND-PAGE", "a".repeat(APPROVAL_PAGE_BYTES - 1));
        let metadata = artifacts
            .put_text(
                crate::agent::artifact::PATCH_PREVIEW,
                crate::agent::artifact::Origin {
                    producer: "write_file".into(),
                    reference: "test".into(),
                },
                &complete,
            )
            .unwrap();
        let calls = Rc::new(RefCell::new(Calls::default()));
        let digest = Rc::new(RefCell::new(None));
        let surface = Fake {
            calls: calls.clone(),
            size: (120, 100),
            fail_enter: false,
            fail_draw: false,
        };
        let mut controller = Controller::open(
            surface,
            Browsing {
                digest: digest.clone(),
            },
            None,
        )
        .unwrap()
        .with_artifacts(artifacts);
        let (reply, answer) = question();
        let request = PermissionRequest::new("write_file", "write_file large.txt")
            .with_preview("bounded")
            .with_view(crate::agent::bus::PermissionView {
                digest: Some("sha256:exact".into()),
                preview_artifact: Some(metadata.id),
                ..Default::default()
            });

        assert!(
            dispatch(
                Event::Permission {
                    agent: ROOT,
                    request,
                    reply,
                },
                &mut controller,
            )
            .is_none()
        );
        assert_eq!(answer.wait(), Some(Decision::Allow));
        assert_eq!(digest.borrow().as_deref(), Some("sha256:exact"));
        let shown = calls
            .borrow()
            .frames
            .iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            shown
                .iter()
                .any(|line| line.contains("digest: sha256:exact"))
        );
        assert!(shown.iter().any(|line| line.contains("SECOND-PAGE")));
        assert!(shown.iter().any(|line| line.contains("bytes 0..4095")));
        assert!(shown.iter().any(|line| line.contains("bytes 4095..")));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn controller_output_failure_breaks_the_pump_and_restores_on_drop() {
        let calls = Rc::new(RefCell::new(Calls::default()));
        let (decisions, _) = scripted(Decision::Deny);
        let mut controller = Controller::open(fake(calls.clone()), decisions, None).unwrap();
        controller.screen.surface.fail_draw = true;

        let result = dispatch(
            Event::Failed {
                agent: ROOT,
                text: "provider failed".into(),
            },
            &mut controller,
        );
        assert!(matches!(result, Some(Pumped::Broken(error)) if error == "draw failed"));
        drop(controller);
        assert_eq!(calls.borrow().left, 1);
    }

    #[test]
    fn long_draft_wraps_instead_of_truncating() {
        let mut state = State::new();
        let long = "x".repeat(30);
        state.set_draft(&long, long.len());
        let (lines, cursor, _) = frame(&state, (20, 24));
        // Prompt is 7 wide, so each row holds 13 x's. 30 x's wrap to three rows.
        assert!(lines.iter().any(|line| line == "gears> xxxxxxxxxxxxx"));
        assert!(lines.iter().any(|line| line == "       xxxxxxxxxxxxx"));
        assert!(lines.iter().any(|line| line == "       xxxx"));
        let (col, row) = cursor.unwrap();
        // Cursor lands right after the last 'x' on the final draft row.
        assert_eq!(row as usize, lines.len() - 2);
        assert_eq!(col as usize, 7 + 4);
    }

    #[test]
    fn long_transcript_lines_wrap_to_the_screen_width() {
        let mut state = State::new();
        let long = "y".repeat(30);
        state.apply(&Event::Token {
            agent: ROOT,
            text: long.clone(),
        });
        let rendered = frame(&state, (20, 24)).0;
        // "agent> " prefix is 7 chars; inner width is 13.
        assert!(rendered.iter().any(|line| line == "agent> yyyyyyyyyyyyy"));
        assert!(rendered.iter().any(|line| line == "       yyyyyyyyyyyyy"));
        assert!(rendered.iter().any(|line| line == "       yyyy"));
        // No rendered line exceeds the width.
        assert!(rendered.iter().all(|line| line.chars().count() <= 20));
    }
}
