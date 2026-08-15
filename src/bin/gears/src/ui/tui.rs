//! Safe terminal lifecycle and minimal drawing for the interactive UI.

use std::io::{self, Write};
use std::process::ExitCode;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

use crossterm::cursor::{Hide, MoveTo, Show};
use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste};
use crossterm::style::Print;
use crossterm::terminal::{
    Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use crossterm::{execute, queue};

use super::repl::Ui;
use super::state::{Activity, State};
use super::transcript::{Source, Transcript};
use super::tui_input::{Action, Input};
use crate::agent::bus::{AgentId, Decision, Event, PermissionRequest, ROOT, ToolStream};
use crate::agent::gate::Gate;
use crate::agent::harness::{Command, Harness};
use crate::agent::task::Task;
use crate::tools::selfhost::Restart;

const INPUT_POLL: Duration = Duration::from_millis(20);
const EVENT_BURST: usize = 64;

pub trait Surface {
    fn enter(&mut self) -> io::Result<()>;
    fn size(&self) -> io::Result<(u16, u16)>;
    fn draw(&mut self, lines: &[String]) -> io::Result<()>;
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
        self.surface.draw(&frame(state, size))
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
    fn decide(&mut self, agent: AgentId, request: &PermissionRequest) -> Decision;
}

/// Connects the terminal-independent projection to one safe screen.
pub struct Controller<S: Surface, D: Decisions> {
    screen: Screen<S>,
    state: State,
    decisions: D,
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
        })
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
}

impl<S: Surface> Controller<S, Input> {
    fn poll_input(&mut self, timeout: Duration, editing: bool) -> io::Result<Option<Action>> {
        let action = self.decisions.poll(timeout, editing)?;
        let redraw = match action {
            Some(Action::Changed | Action::Submit(_)) => {
                self.state.set_draft(self.decisions.draft())
            }
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
        if self.state.apply(event) {
            self.screen.redraw(&self.state)?;
        }
        Ok(())
    }

    fn decide(&mut self, agent: AgentId, request: &PermissionRequest) -> Decision {
        self.decisions.decide(agent, request)
    }
}

pub struct Crossterm<W: Write> {
    out: W,
    entered: bool,
}

impl<W: Write> Crossterm<W> {
    pub fn new(out: W) -> Crossterm<W> {
        Crossterm {
            out,
            entered: false,
        }
    }
}

impl<W: Write> Surface for Crossterm<W> {
    fn enter(&mut self) -> io::Result<()> {
        enable_raw_mode()?;
        if let Err(error) = execute!(self.out, EnterAlternateScreen, EnableBracketedPaste, Hide) {
            let _ = execute!(self.out, Show, DisableBracketedPaste, LeaveAlternateScreen);
            let _ = disable_raw_mode();
            return Err(error);
        }
        self.entered = true;
        Ok(())
    }

    fn size(&self) -> io::Result<(u16, u16)> {
        crossterm::terminal::size()
    }

    fn draw(&mut self, lines: &[String]) -> io::Result<()> {
        queue!(self.out, MoveTo(0, 0), Clear(ClearType::All))?;
        for (row, line) in lines.iter().enumerate() {
            queue!(self.out, MoveTo(0, row as u16), Print(line))?;
        }
        self.out.flush()
    }

    fn leave(&mut self) -> io::Result<()> {
        if !self.entered {
            return Ok(());
        }
        self.entered = false;
        let terminal = execute!(self.out, Show, DisableBracketedPaste, LeaveAlternateScreen);
        let raw = disable_raw_mode();
        terminal.and(raw)
    }
}

fn frame(state: &State, (width, height): (u16, u16)) -> Vec<String> {
    let mut status = vec!["Motor OS Gears".to_string()];
    for (agent, activity) in state.agents() {
        let activity = activity_line(activity);
        status.push(match *agent {
            ROOT => activity,
            id => format!("[{id}] {activity}"),
        });
    }
    if let Some(task) = state.task() {
        status.push(task.compact());
    }
    if state.scroll() > 0 {
        status.push(format!("scroll: {} lines from latest", state.scroll()));
    }
    let mut draft_lines = Vec::new();
    for (index, line) in state.draft().split('\n').enumerate() {
        let prompt = if index == 0 { "gears> " } else { "  ...> " };
        draft_lines.push(format!("{prompt}{line}"));
    }
    let height = usize::from(height);
    status.truncate(height);
    if status.len() == height {
        return finish(status, width);
    }
    let below_status = height - status.len();
    if draft_lines.len() >= below_status {
        let mut shown: Vec<String> = draft_lines.into_iter().rev().take(below_status).collect();
        shown.reverse();
        status.extend(shown);
        return finish(status, width);
    }
    let room = height - status.len() - draft_lines.len();
    let transcript = transcript_lines(state.transcript());
    let end = transcript.len().saturating_sub(state.scroll());
    let start = end.saturating_sub(room);
    let mut lines = status;
    lines.extend(transcript.into_iter().skip(start).take(end - start));
    lines.extend(draft_lines);
    finish(lines, width)
}

fn finish(lines: Vec<String>, width: u16) -> Vec<String> {
    lines
        .into_iter()
        .map(|line| safe_width(&line, usize::from(width)))
        .collect()
}

fn transcript_lines(transcript: &Transcript) -> Vec<String> {
    let mut lines = Vec::new();
    for entry in transcript.entries() {
        let prefix = source_prefix(entry.source);
        let continuation = " ".repeat(prefix.chars().count());
        for (index, line) in entry.text.split('\n').enumerate() {
            lines.push(format!(
                "{}{line}",
                if index == 0 { &prefix } else { &continuation }
            ));
        }
    }
    lines
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

/// Run the minimal interactive TUI. Rich editing, transcript rendering, and
/// slash commands are added by Step 13; this loop establishes safe ownership
/// and control while consuming the same agent events as line mode.
pub fn interact(harness: &Harness, gate: Gate, restart: &Restart) -> Result<ExitCode, String> {
    let surface = Crossterm::new(std::io::stdout());
    let input = Input::new(gate);
    let mut controller = Controller::open_state(surface, input, durable_state(harness)?)
        .map_err(|error| format!("cannot start TUI: {error}"))?;
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
        .map_err(|error| format!("cannot start TUI: {error}"))?;
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
    let mut failed = false;
    if let Some(prompt) = initial {
        harness.send(Command::Prompt(prompt.to_string()))?;
        active = true;
        controller
            .start_turn(prompt)
            .map_err(|error| error.to_string())?;
    }

    loop {
        if let Some(action) = controller
            .poll_input(INPUT_POLL, !active && !one_shot)
            .map_err(|error| format!("TUI input: {error}"))?
        {
            match action {
                Action::Submit(prompt) if !prompt.trim().is_empty() => {
                    harness.send(Command::Prompt(prompt.clone()))?;
                    active = true;
                    controller
                        .start_turn(&prompt)
                        .map_err(|error| error.to_string())?;
                }
                Action::Cancel if active => harness.cancel(),
                Action::Cancel | Action::End if !active => {
                    return Ok(exit_code(failed));
                }
                Action::Pause => {
                    harness.toggle_paused();
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
                            harness.toggle_paused();
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
                .set_task(harness.task())
                .map_err(|error| error.to_string())?;
            match done {
                Some(super::repl::Pumped::Turn { .. }) => {
                    controller
                        .set_transcript(durable_transcript(harness)?)
                        .map_err(|error| error.to_string())?;
                    active = false;
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

fn durable_state(harness: &Harness) -> Result<State, String> {
    let mut state = State::with_transcript_limit(harness.live_render_limit());
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

        fn draw(&mut self, lines: &[String]) -> io::Result<()> {
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

    impl Decisions for Scripted {
        fn decide(&mut self, agent: AgentId, request: &PermissionRequest) -> Decision {
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
        assert_eq!(calls.frames[1], ["Motor"]);
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
        let rendered = frame(&state, (80, 24)).join("\n");
        assert!(!rendered.contains('\x1b'), "{rendered:?}");
        assert!(!rendered.contains("\nnext"), "{rendered:?}");
    }

    #[test]
    fn multiline_drafts_have_explicit_continuation_prompts() {
        let mut state = State::new();
        state.set_draft("first\nsecond");
        let rendered = frame(&state, (80, 24));
        assert_eq!(rendered[2], "gears> first");
        assert_eq!(rendered[3], "  ...> second");
    }

    #[test]
    fn transcript_uses_labels_and_keeps_the_newest_lines_above_the_prompt() {
        let mut state = State::new();
        state.record_message(&crate::provider::ChatMessage::user("inspect\nthis"));
        state.apply(&Event::Token {
            agent: 3,
            text: "working".into(),
        });

        let rendered = frame(&state, (80, 6));
        assert_eq!(rendered[3], "     this");
        assert_eq!(rendered[4], "[3] agent> working");
        assert_eq!(rendered[5], "gears> ");
    }

    #[test]
    fn transcript_navigation_moves_away_and_returns_to_latest() {
        let mut state = State::new();
        for line in ["one", "two", "three", "four"] {
            state.record_message(&crate::provider::ChatMessage::user(line));
        }
        assert!(state.scroll_up(2));
        let rendered = frame(&state, (80, 6));
        assert!(
            rendered.iter().any(|line| line == "you> two"),
            "{rendered:?}"
        );
        assert!(!rendered.iter().any(|line| line == "you> four"));

        assert!(state.scroll_down(usize::MAX));
        let rendered = frame(&state, (80, 6));
        assert!(
            rendered.iter().any(|line| line == "you> four"),
            "{rendered:?}"
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
                    request: PermissionRequest {
                        key: "write_file".into(),
                        detail: "write_file src/main.rs".into(),
                        preview: None,
                    },
                    reply,
                },
                &mut controller,
            )
            .is_none()
        );

        assert_eq!(answer.wait(), Some(Decision::Always));
        assert_eq!(&*asked.borrow(), &[(4, "write_file src/main.rs".into())]);
        assert_eq!(
            controller.state().activity(4),
            Some(&Activity::Permission {
                detail: "write_file src/main.rs".into(),
            })
        );
        assert_eq!(
            calls.borrow().frames.last().unwrap()[2],
            "[4] allow write_file src/main.rs? [y]es / [n]o / [a]lways"
        );
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
}
