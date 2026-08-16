//! The interactive half of the line UI: the prompt, the permission question,
//! the slash commands, and the loop that ties them to an agent.
//!
//! Everything here runs on the one thread that owns the terminal. The agent is
//! elsewhere; what crosses between them is the bus and nothing else.

use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, Write};
use std::process::ExitCode;
use std::sync::mpsc::RecvTimeoutError;
use std::time::Duration;

use crate::agent::bus::{AgentId, Decision, Event, PermissionRequest, ROOT};
use crate::agent::gate::Gate;
use crate::agent::harness::{Command as AgentCommand, Harness};
use crate::ui::command::{Checkpoint, Command, Input, parse};
use crate::ui::input::{Action, Owner};
use crate::ui::repl::{Pumped, Renderer, Ui, dispatch, pump};

pub const HELP: &str = "\
  /status   what this session has cost and changed
  /mode M   start the next new task in ask, plan, code, or review mode
  /pause    stop before the next model or tool operation
  /resume   continue paused work
  /+ [N]    show a result marked [+] in full: the last, or the Nth back
  /checkpoint create NAME | list | inspect ID | restore ID
  /undo     put every file this session changed back
  /compact [INSTRUCTIONS] summarize old turns while keeping the newest exact
  /help     this
  /quit     leave (^C does too)
Anything else is a prompt for the model.
";

/// How much expandable output to keep for `/+`. A size rather than a count:
/// one build log is worth more than ten directory listings, and both land
/// here. The session transcript is the record; this is a convenience.
const KEPT: usize = 256 * 1024;
const INPUT_POLL: Duration = Duration::from_millis(20);

const BANNER: &str = "Motor OS Gears - agentic coding harness";

/// A result the screen only summarized, and the call it came from.
struct Expansion {
    call: String,
    text: String,
}

/// A terminal, a gate, and whether there is anybody there to answer.
pub struct Terminal<W: Write, R: BufRead> {
    renderer: Renderer<W>,
    input: Owner<R>,
    /// Complete lines typed during a turn, reserved for later prompts.
    pending: VecDeque<String>,
    input_closed: bool,
    gate: Gate,
    /// Whether a permission question can be put to a user at all. Without one
    /// — `gears -p` with a gate that is still asking — the answer is no.
    interactive: bool,
    /// Failures rendered so far: the one-shot exit code.
    failures: usize,
    /// The last accounting the agent reported, for `/status`. It arrives with
    /// the end of each turn, so the UI never has to reach across the bus.
    usage: crate::provider::UsageMeter,
    /// What `/+` can still show, oldest first, and their total size.
    expansions: Vec<Expansion>,
    kept: usize,
    /// The call each agent's next `ToolEnd` belongs to. Per agent, because
    /// two of them have calls in flight at the same time and the label on a
    /// kept result has to be the right one.
    started: BTreeMap<AgentId, String>,
    /// Where a `restart` call leaves its request. The loop below stops when
    /// one is waiting; performing it is the caller's, after the session has
    /// been closed (`tools/selfhost.rs`).
    restart: Option<crate::tools::selfhost::Restart>,
}

impl<W: Write, R: BufRead> Terminal<W, R> {
    pub fn new(out: W, input: R, gate: Gate, interactive: bool) -> Terminal<W, R> {
        Terminal {
            renderer: Renderer::new(out, interactive),
            input: Owner::new(input),
            pending: VecDeque::new(),
            input_closed: false,
            gate,
            interactive,
            failures: 0,
            usage: crate::provider::UsageMeter::new(),
            expansions: Vec::new(),
            kept: 0,
            started: BTreeMap::new(),
            restart: None,
        }
    }

    /// Watch for a restart request, which is what ends the loop early.
    pub fn watching(mut self, restart: crate::tools::selfhost::Restart) -> Terminal<W, R> {
        self.restart = Some(restart);
        self
    }

    /// Do our own echo and line editing, for a console that is always raw
    /// (`platform::raw_console`). Without this on such a console, typing at
    /// the prompt shows nothing at all.
    pub fn editing(mut self) -> Terminal<W, R> {
        self.input = self.input.editing();
        self
    }

    fn restarting(&self) -> bool {
        self.restart.as_ref().is_some_and(|r| r.pending())
    }

    pub fn failures(&self) -> usize {
        self.failures
    }

    /// Hold on to a result the screen summarized, dropping the oldest to stay
    /// under [`KEPT`]. The newest is never dropped, however big it is: it is
    /// the one a user who has just seen `[+]` is about to ask for.
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

    /// `/+`: print one kept result whole. `which` is empty for the last one,
    /// or a count back from it.
    fn expand(&mut self, nth: usize) -> Result<(), String> {
        let found = nth
            .checked_sub(1)
            .and_then(|back| self.expansions.len().checked_sub(back + 1))
            .and_then(|index| self.expansions.get(index))
            .map(|entry| (entry.call.clone(), entry.text.clone()));
        let Some((call, text)) = found else {
            return Err(match self.expansions.len() {
                0 => "nothing to expand".to_string(),
                kept => format!("no result {nth}; {kept} kept"),
            });
        };
        self.renderer
            .line(&format!("--- {call} ({} bytes) ---", text.len()))
            .map_err(|e| e.to_string())?;
        self.renderer
            .line(text.trim_end())
            .map_err(|e| e.to_string())
    }

    /// Read one line. `None` at end of input, or after a ^C.
    fn read_line(&mut self) -> Option<String> {
        if let Some(line) = self.pending.pop_front() {
            return Some(line);
        }
        self.read_fresh_line()
    }

    /// Read only the input owner's next line, bypassing future-prompt input.
    fn read_fresh_line(&mut self) -> Option<String> {
        // A signal can land just before the blocking readiness wait begins.
        if crate::platform::interrupt_pending() {
            return None;
        }
        match self.input.read(&mut self.renderer) {
            Action::Line(text) => Some(text),
            Action::End => None,
            Action::Cancel => {
                crate::platform::note_interrupt();
                None
            }
            // The live-turn loop handles pause. At an idle line prompt it has
            // no work to pause, so keep waiting for an actionable input.
            Action::Pause => self.read_fresh_line(),
        }
    }

    /// Put one call to the user, in the asking agent's own voice: with
    /// sub-agents running, *who* wants to write a file is part of the answer.
    fn ask_user(&mut self, agent: AgentId, request: &PermissionRequest) -> Decision {
        if !self.interactive {
            // Nobody to ask. Denying is the only answer that cannot do harm,
            // and the model is told, so it can say what it needed.
            let _ = self.renderer.line_from(
                agent,
                &format!("- denied, nobody to ask: {}", request.detail),
            );
            return Decision::Deny;
        }
        if let Some(preview) = &request.preview
            && self.renderer.line_from(agent, preview).is_err()
        {
            return Decision::Deny;
        }
        loop {
            let _ = self.renderer.prompt_from(
                agent,
                &format!("allow {}? [y]es / [n]o / [a]lways: ", request.detail),
            );
            let Some(answer) = self.read_fresh_line() else {
                return Decision::Deny;
            };
            match answer.trim() {
                "y" | "yes" => return Decision::Allow,
                "n" | "no" | "" => return Decision::Deny,
                "a" | "always" => return Decision::Always,
                _ => {
                    let _ = self.renderer.line_from(agent, "- answer y, n or a");
                }
            }
        }
    }
}

impl<W: Write> Terminal<W, std::io::Empty> {
    pub fn live(out: W, gate: Gate, interactive: bool) -> Result<Self, String> {
        Ok(Terminal {
            renderer: Renderer::new(out, interactive),
            input: Owner::live().map_err(|error| format!("cannot read terminal: {error}"))?,
            pending: VecDeque::new(),
            input_closed: false,
            gate,
            interactive,
            failures: 0,
            usage: crate::provider::UsageMeter::new(),
            expansions: Vec::new(),
            kept: 0,
            started: BTreeMap::new(),
            restart: None,
        })
    }

    /// Drain every complete action already waiting without blocking.
    fn collect_ready(&mut self, harness: &Harness) -> Result<(), String> {
        if self.input_closed {
            return Ok(());
        }
        loop {
            match self.input.poll(&mut self.renderer, Duration::ZERO) {
                Ok(Some(Action::Line(line))) if line.trim() == "/pause" => {
                    self.show_pause(harness, Some(true))?
                }
                Ok(Some(Action::Line(line))) if line.trim() == "/resume" => {
                    self.show_pause(harness, Some(false))?
                }
                Ok(Some(Action::Line(line))) => self.pending.push_back(line),
                Ok(Some(Action::Cancel)) => harness.cancel(),
                Ok(Some(Action::Pause)) => self.show_pause(harness, None)?,
                Ok(Some(Action::End)) => {
                    self.input_closed = true;
                    return Ok(());
                }
                Ok(None) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    harness.cancel();
                    return Ok(());
                }
                Err(error) => return Err(error.to_string()),
            }
        }
    }

    fn show_pause(&mut self, harness: &Harness, set: Option<bool>) -> Result<(), String> {
        let paused = match set {
            Some(paused) => {
                harness.set_paused(paused);
                paused
            }
            None => harness.toggle_paused(),
        };
        let text = match paused {
            true => "- paused after current operation",
            false => "- resumed",
        };
        self.renderer.line(text).map_err(|error| error.to_string())
    }
}

impl<W: Write, R: BufRead> Ui for Terminal<W, R> {
    fn render(&mut self, event: &Event) -> std::io::Result<()> {
        match event {
            Event::Failed { .. } => self.failures += 1,
            // The root's turn is the user's; a sub-agent's is its own.
            Event::TurnEnd {
                agent: ROOT, usage, ..
            } => self.usage = *usage,
            Event::ToolStart { agent, detail } => {
                self.started.insert(*agent, label(*agent, detail));
            }
            // Kept only where it can be asked for: `gears -p` prints no marker
            // and has no prompt, so holding on to the text would buy nothing.
            Event::ToolEnd {
                agent,
                full: Some(text),
                ..
            } if self.interactive => self.keep(*agent, text),
            _ => {}
        }
        self.renderer.event(event)
    }

    fn decide(&mut self, agent: AgentId, request: &PermissionRequest) -> Decision {
        // The gate answers on its own whenever it can; the user is only put to
        // the trouble for what it has never been told.
        if let Some(decision) = self.gate.known(request) {
            return decision;
        }
        let decision = self.ask_user(agent, request);
        if decision == Decision::Always {
            self.gate.remember(&request.key);
            if let Some(complaint) = self.gate.complaint() {
                let _ = self.renderer.line(&format!("! {complaint}"));
            }
        }
        crate::trace::log(
            crate::trace::Level::Info,
            &format!("permission {decision:?} for {}", request.key),
        );
        decision
    }
}

/// Run one prompt and leave: `gears -p`.
pub fn once<W: Write, R: BufRead>(
    harness: &Harness,
    ui: &mut Terminal<W, R>,
    prompt: &str,
) -> ExitCode {
    welcome(harness, ui);
    let prompt = match parse(prompt) {
        Ok(Input::Prompt(prompt)) => prompt,
        Ok(Input::Command(Command::Compact(focus))) => {
            if let Err(error) = harness.send(AgentCommand::Compact { focus }) {
                let _ = ui.renderer.line(&format!("! {error}"));
                return ExitCode::FAILURE;
            }
            return match pump(harness.events(), ui) {
                Pumped::Turn { ok: true, .. } if ui.failures() == 0 => ExitCode::SUCCESS,
                _ => ExitCode::FAILURE,
            };
        }
        Ok(Input::Command(command)) => {
            return match execute(harness, ui, command) {
                Ok(_) => exit_code(ui),
                Err(error) => {
                    let _ = ui.renderer.line(&format!("! {error}"));
                    ExitCode::FAILURE
                }
            };
        }
        Err(error) => {
            let _ = ui.renderer.line(&format!("! {error}"));
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = harness.send(AgentCommand::Prompt(prompt)) {
        let _ = ui.renderer.line(&format!("! {e}"));
        return ExitCode::FAILURE;
    }
    match pump(harness.events(), ui) {
        Pumped::Turn { ok: true, .. } if ui.failures() == 0 => ExitCode::SUCCESS,
        Pumped::Broken(e) => {
            eprintln!("gears: {e}");
            ExitCode::FAILURE
        }
        _ => ExitCode::FAILURE,
    }
}

/// The interactive loop.
pub fn interact<W: Write>(harness: &Harness, ui: &mut Terminal<W, std::io::Empty>) -> ExitCode {
    welcome(harness, ui);
    let _ = ui.renderer.line("- /help for commands");

    loop {
        if ui.renderer.prompt("gears> ").is_err() {
            return ExitCode::FAILURE;
        }
        let Some(line) = ui.read_line() else {
            // End of input, or a ^C at the prompt: either way, this is the
            // way out (the plan's "second ^C at idle exits").
            let _ = ui.renderer.break_line();
            crate::platform::take_interrupt();
            return exit_code(ui);
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match parse(line) {
            Ok(Input::Command(Command::Compact(focus))) => {
                if let Err(error) = harness.send(AgentCommand::Compact { focus }) {
                    let _ = ui.renderer.line(&format!("! {error}"));
                    return ExitCode::FAILURE;
                }
                match pump_live(harness, ui) {
                    Pumped::Turn { .. } => continue,
                    Pumped::Exit | Pumped::Closed => return exit_code(ui),
                    Pumped::Broken(error) => {
                        eprintln!("gears: {error}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            Ok(Input::Command(command)) => match execute(harness, ui, command) {
                Ok(true) => continue,
                Ok(false) => return exit_code(ui),
                Err(e) => {
                    let _ = ui.renderer.line(&format!("! {e}"));
                    continue;
                }
            },
            Err(error) => {
                let _ = ui.renderer.line(&format!("! {error}"));
                continue;
            }
            Ok(Input::Prompt(_)) => {}
        }
        if let Err(e) = harness.send(AgentCommand::Prompt(line.to_string())) {
            let _ = ui.renderer.line(&format!("! {e}"));
            return ExitCode::FAILURE;
        }
        match pump_live(harness, ui) {
            // A turn that asked for a restart is the last one this gears has:
            // there is another about to take the session over.
            Pumped::Turn { .. } if ui.restarting() => return exit_code(ui),
            Pumped::Turn { .. } => {}
            Pumped::Exit | Pumped::Closed => return exit_code(ui),
            Pumped::Broken(e) => {
                eprintln!("gears: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
}

/// Keep the one input owner active while the agent works.
fn pump_live<W: Write>(harness: &Harness, ui: &mut Terminal<W, std::io::Empty>) -> Pumped {
    loop {
        if let Err(error) = ui.collect_ready(harness) {
            return Pumped::Broken(error);
        }
        if crate::platform::interrupt_pending() {
            harness.cancel();
        }

        match harness.events().recv_timeout(INPUT_POLL) {
            Ok(event) => {
                // Anything already waiting when a permission question arrives
                // was typed for a later prompt, not as its answer.
                if matches!(event, Event::Permission { .. })
                    && let Err(error) = ui.collect_ready(harness)
                {
                    return Pumped::Broken(error);
                }
                if let Some(done) = dispatch(event, ui) {
                    return done;
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Pumped::Closed,
        }
    }
}

fn welcome<W: Write, R: BufRead>(harness: &Harness, ui: &mut Terminal<W, R>) {
    let _ = ui.renderer.line(BANNER);
    let _ = ui.renderer.line("");
    let _ = ui.renderer.line(&format!("- {}", harness.opening()));
    let _ = ui.renderer.line(&format!(
        "- {} in {}",
        harness.model(),
        harness.workspace().display()
    ));
}

/// What `/+` calls a kept result: the call it came from, and whose call that
/// was where the answer is not "the one you were talking to".
fn label(agent: AgentId, detail: &str) -> String {
    match agent {
        ROOT => detail.to_string(),
        id => format!("[{id}] {detail}"),
    }
}

fn exit_code<W: Write, R: BufRead>(ui: &Terminal<W, R>) -> ExitCode {
    match ui.failures() {
        0 => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

/// Execute one already-parsed local command; `false` means leave.
fn execute<W: Write, R: BufRead>(
    harness: &Harness,
    ui: &mut Terminal<W, R>,
    command: Command,
) -> Result<bool, String> {
    match command {
        Command::Quit => return Ok(false),
        Command::Expand(nth) => ui.expand(nth)?,
        Command::Help => {
            ui.renderer.line(HELP).map_err(|e| e.to_string())?;
        }
        Command::Status => {
            let changed = harness.changed_files()?;
            let text = format!(
                "session {} | {} | {}\n{} | {} files changed",
                harness.session_id(),
                harness.model(),
                harness.workspace().display(),
                ui.usage.summary(),
                changed.len(),
            );
            let paused = match harness.paused() {
                true => format!("{text} | paused"),
                false => text,
            };
            let status = match harness.task() {
                Some(task) => format!("{paused}\n{}", task.compact()),
                None => paused,
            };
            ui.renderer.line(&status).map_err(|e| e.to_string())?;
        }
        Command::Pause => {
            harness.set_paused(true);
            ui.renderer
                .line("- paused before the next operation")
                .map_err(|e| e.to_string())?;
        }
        Command::Resume => {
            harness.set_paused(false);
            ui.renderer.line("- resumed").map_err(|e| e.to_string())?;
        }
        Command::Mode(mode) => {
            let selected = harness.select_mode(mode)?;
            ui.renderer
                .line(&format!("- {selected}"))
                .map_err(|error| error.to_string())?;
        }
        Command::Checkpoint(command) => checkpoint(harness, ui, command)?,
        Command::Undo => match harness.initial_checkpoint()? {
            Some(id) => restore_checkpoint(harness, ui, id)?,
            None => {
                let restored = harness.undo().restore()?;
                let text = match restored.is_empty() {
                    true => "nothing to undo".to_string(),
                    false => format!("put back: {}", restored.join(", ")),
                };
                ui.renderer
                    .line(&format!("- {text}"))
                    .map_err(|e| e.to_string())?;
            }
        },
        Command::Compact(_) => unreachable!("compaction is pumped by the interactive loop"),
    }
    Ok(true)
}

fn checkpoint<W: Write, R: BufRead>(
    harness: &Harness,
    ui: &mut Terminal<W, R>,
    command: Checkpoint,
) -> Result<(), String> {
    match command {
        Checkpoint::Create(name) => {
            let metadata = harness.create_checkpoint(&name)?;
            ui.renderer
                .line(&format!(
                    "- checkpoint {} created: {}",
                    metadata.id, metadata.name
                ))
                .map_err(|error| error.to_string())?;
        }
        Checkpoint::List => {
            let (checkpoints, more) = harness.checkpoints(0, 100)?;
            if checkpoints.is_empty() {
                ui.renderer
                    .line("- no checkpoints")
                    .map_err(|error| error.to_string())?;
            }
            for metadata in checkpoints {
                ui.renderer
                    .line(&format!("checkpoint {}: {}", metadata.id, metadata.name))
                    .map_err(|error| error.to_string())?;
            }
            if more {
                ui.renderer
                    .line("- more than 100 checkpoints; use the checkpoints tool to paginate")
                    .map_err(|error| error.to_string())?;
            }
        }
        Checkpoint::Inspect(id) | Checkpoint::Restore(id) => {
            let inspect = matches!(command, Checkpoint::Inspect(_));
            let prepared = harness.prepare_checkpoint_restore(id)?;
            match prepared {
                None => ui
                    .renderer
                    .line(&format!("- checkpoint {id} matches the workspace"))
                    .map_err(|error| error.to_string())?,
                Some(prepared) if inspect => {
                    show_checkpoint_diff(ui, id, &prepared.preview())?;
                }
                Some(prepared) => {
                    restore_prepared_checkpoint(harness, ui, id, prepared)?;
                }
            }
        }
    }
    Ok(())
}

fn restore_checkpoint<W: Write, R: BufRead>(
    harness: &Harness,
    ui: &mut Terminal<W, R>,
    id: u64,
) -> Result<(), String> {
    match harness.prepare_checkpoint_restore(id)? {
        None => ui
            .renderer
            .line("- nothing to undo")
            .map_err(|error| error.to_string()),
        Some(prepared) => restore_prepared_checkpoint(harness, ui, id, prepared),
    }
}

fn restore_prepared_checkpoint<W: Write, R: BufRead>(
    harness: &Harness,
    ui: &mut Terminal<W, R>,
    id: u64,
    prepared: crate::tools::mutation::Prepared,
) -> Result<(), String> {
    ui.renderer
        .line(prepared.preview().trim_end())
        .map_err(|error| error.to_string())?;
    let decision = confirm_checkpoint_restore(ui, id)?;
    let result = harness.restore_checkpoint(prepared, decision)?;
    ui.renderer
        .line(&format!("- {result}"))
        .map_err(|error| error.to_string())
}

fn show_checkpoint_diff<W: Write, R: BufRead>(
    ui: &mut Terminal<W, R>,
    id: u64,
    diff: &str,
) -> Result<(), String> {
    if diff.len() <= crate::tools::DEFAULT_CAP {
        return ui
            .renderer
            .line(diff.trim_end())
            .map_err(|error| error.to_string());
    }
    ui.keep_named(format!("checkpoint {id} diff"), diff);
    let shown = crate::tools::clamp(diff, crate::tools::DEFAULT_CAP);
    ui.renderer
        .line(&format!(
            "{}\n[+] complete checkpoint diff",
            shown.trim_end()
        ))
        .map_err(|error| error.to_string())
}

fn confirm_checkpoint_restore<W: Write, R: BufRead>(
    ui: &mut Terminal<W, R>,
    id: u64,
) -> Result<Decision, String> {
    if !ui.interactive {
        return Ok(Decision::Deny);
    }
    loop {
        ui.renderer
            .prompt(&format!("restore checkpoint {id}? [y/N]: "))
            .map_err(|error| error.to_string())?;
        match ui.read_line().as_deref().map(str::trim) {
            Some("y" | "yes") => return Ok(Decision::Allow),
            Some("" | "n" | "no") | None => return Ok(Decision::Deny),
            Some(_) => ui
                .renderer
                .line("- answer y or n")
                .map_err(|error| error.to_string())?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::bus::{ROOT, event_channel};
    use crate::agent::gate::Mode;
    use crate::provider::UsageMeter;

    fn terminal(input: &str, mode: Mode, interactive: bool) -> Terminal<Vec<u8>, &[u8]> {
        Terminal::new(Vec::new(), input.as_bytes(), Gate::new(mode), interactive)
    }

    fn text<R: BufRead>(ui: &Terminal<Vec<u8>, R>) -> String {
        String::from_utf8(ui.renderer.get_ref().clone()).unwrap()
    }

    fn request() -> PermissionRequest {
        PermissionRequest::new("write_file", "write_file notes.txt")
    }

    #[test]
    fn the_user_is_asked_and_their_answer_is_taken() {
        for (typed, expected) in [
            ("y\n", Decision::Allow),
            ("yes\n", Decision::Allow),
            ("n\n", Decision::Deny),
            ("\n", Decision::Deny),
            ("a\n", Decision::Always),
            ("", Decision::Deny), // stdin closed mid-question
        ] {
            let mut ui = terminal(typed, Mode::Ask, true);
            assert_eq!(ui.decide(ROOT, &request()), expected, "{typed:?}");
            if !typed.is_empty() {
                assert!(text(&ui).contains("write_file notes.txt"), "{typed:?}");
            }
        }
    }

    #[test]
    fn a_mutation_preview_is_shown_before_the_question() {
        let mut request = request();
        request.preview =
            Some("digest: sha256:abc\n--- /dev/null\n+++ b/notes.txt\n+hello".to_string());
        let mut ui = terminal("y\n", Mode::Ask, true);
        assert_eq!(ui.decide(ROOT, &request), Decision::Allow);
        let shown = text(&ui);
        let preview = shown.find("digest: sha256:abc").unwrap();
        let question = shown.find("allow write_file notes.txt?").unwrap();
        assert!(preview < question, "{shown}");
        assert!(shown.contains("+++ b/notes.txt"), "{shown}");
    }

    #[test]
    fn an_unreadable_answer_is_asked_again() {
        let mut ui = terminal("maybe\ny\n", Mode::Ask, true);
        assert_eq!(ui.decide(ROOT, &request()), Decision::Allow);
        let shown = text(&ui);
        assert!(shown.contains("answer y, n or a"), "{shown}");
        assert_eq!(shown.matches("allow write_file").count(), 2, "{shown}");
    }

    #[test]
    fn always_is_asked_once_and_then_never_again() {
        let mut ui = terminal("a\n", Mode::Ask, true);
        assert_eq!(ui.decide(ROOT, &request()), Decision::Always);
        // The second call has no input left to read: an answer that had to be
        // asked for would come back a denial.
        assert_eq!(ui.decide(ROOT, &request()), Decision::Allow);
    }

    #[test]
    fn with_nobody_to_ask_the_answer_is_no() {
        let mut ui = terminal("y\n", Mode::Ask, false);
        assert_eq!(ui.decide(ROOT, &request()), Decision::Deny);
        assert!(text(&ui).contains("nobody to ask"), "{}", text(&ui));

        // Unless the gate was told not to ask in the first place.
        let mut ui = terminal("", Mode::AutoApprove, false);
        assert_eq!(ui.decide(ROOT, &request()), Decision::Allow);
        assert_eq!(text(&ui), "");
    }

    #[test]
    fn a_failure_is_counted_for_the_exit_code() {
        let mut ui = terminal("", Mode::Ask, false);
        assert_eq!(ui.failures(), 0);
        ui.render(&Event::Failed {
            agent: ROOT,
            text: "authentication failed".to_string(),
        })
        .unwrap();
        ui.render(&Event::TurnEnd {
            agent: ROOT,
            usage: UsageMeter::new(),
            ok: false,
        })
        .unwrap();
        assert_eq!(ui.failures(), 1);
    }

    /// One tool call, summarized on screen and kept whole for `/+`.
    fn ran(call: &str, full: &str) -> [Event; 2] {
        [
            Event::ToolStart {
                agent: ROOT,
                detail: call.to_string(),
            },
            Event::ToolEnd {
                agent: ROOT,
                outcome: crate::tools::ToolOutcome::Completed,
                detail: format!("{} bytes", full.len()),
                full: Some(full.to_string()),
            },
        ]
    }

    fn showing(ui: &mut Terminal<Vec<u8>, &[u8]>, events: [Event; 2]) {
        for event in events {
            ui.render(&event).unwrap();
        }
    }

    #[test]
    fn a_summarized_result_can_be_opened_up() {
        let mut ui = terminal("", Mode::Ask, true);
        showing(&mut ui, ran("build", "exit status 101\nmismatched types\n"));
        assert!(text(&ui).contains("[+] 33 bytes"), "{}", text(&ui));

        ui.expand(1).unwrap();
        let shown = text(&ui);
        assert!(shown.contains("--- build (33 bytes) ---"), "{shown}");
        assert!(
            shown.ends_with("exit status 101\nmismatched types\n"),
            "{shown}"
        );
    }

    #[test]
    fn results_are_counted_back_from_the_last_one() {
        let mut ui = terminal("", Mode::Ask, true);
        assert_eq!(ui.expand(1), Err("nothing to expand".to_string()));
        showing(&mut ui, ran("grep todo", "first"));
        showing(&mut ui, ran("build", "second"));

        for (which, expected) in [(1, "second"), (1, "second"), (2, "first")] {
            let mut ui = terminal("", Mode::Ask, true);
            showing(&mut ui, ran("grep todo", "first"));
            showing(&mut ui, ran("build", "second"));
            ui.expand(which).unwrap();
            assert!(text(&ui).ends_with(&format!("{expected}\n")), "{which:?}");
        }

        assert_eq!(ui.expand(3), Err("no result 3; 2 kept".to_string()));
    }

    #[test]
    fn the_oldest_results_are_dropped_and_the_newest_never_is() {
        let mut ui = terminal("", Mode::Ask, true);
        let big = "x".repeat(100 * 1024);
        for _ in 0..5 {
            showing(&mut ui, ran("build", &big));
        }
        assert!(ui.kept <= KEPT, "{} bytes", ui.kept);
        assert_eq!(ui.expansions.len(), 2);

        // Even one that will not fit on its own, since it is the one the user
        // has just been told about.
        showing(&mut ui, ran("build", &"y".repeat(2 * KEPT)));
        assert_eq!(ui.expansions.len(), 1);
        ui.expand(1).unwrap();
        assert!(text(&ui).contains(&format!("({} bytes)", 2 * KEPT)));
    }

    /// A sub-agent asks through the same gate, and the question says which
    /// one is asking: "allow write_file notes.txt?" is a different question
    /// depending on who wants it.
    #[test]
    fn a_sub_agents_question_says_whose_it_is() {
        let mut ui = terminal("y\n", Mode::Ask, true);
        assert_eq!(ui.decide(2, &request()), Decision::Allow);
        assert!(
            text(&ui).starts_with("[2] allow write_file notes.txt?"),
            "{}",
            text(&ui)
        );

        // And what it did is labelled the same way where `/+` keeps it.
        let mut ui = terminal("", Mode::Ask, true);
        for event in ran("grep TODO", "one\ntwo") {
            let event = match event {
                Event::ToolStart { detail, .. } => Event::ToolStart { agent: 2, detail },
                Event::ToolEnd {
                    outcome,
                    detail,
                    full,
                    ..
                } => Event::ToolEnd {
                    agent: 2,
                    outcome,
                    detail,
                    full,
                },
                other => other,
            };
            ui.render(&event).unwrap();
        }
        ui.expand(1).unwrap();
        assert!(
            text(&ui).contains("--- [2] grep TODO (7 bytes) ---"),
            "{}",
            text(&ui)
        );
    }

    /// Nothing to type `/+` at means nothing to keep for it either.
    #[test]
    fn a_one_shot_run_keeps_nothing() {
        let mut ui = terminal("", Mode::Ask, false);
        showing(&mut ui, ran("build", "exit status 101\nmismatched types\n"));
        assert!(ui.expansions.is_empty());
        assert!(!text(&ui).contains("[+]"), "{}", text(&ui));
    }

    /// The prompt is written before the answer is read, not after: a prompt
    /// that only appears once the user has typed is no prompt at all.
    #[test]
    fn the_question_is_flushed_before_the_read() {
        let (tx, rx) = event_channel();
        let bus = crate::agent::bus::Bus::new(ROOT, tx);
        let asking = std::thread::spawn(move || {
            let decision = bus.ask(request());
            bus.turn_end(UsageMeter::new(), true).unwrap();
            decision
        });
        let mut ui = terminal("y\n", Mode::Ask, true);
        assert!(matches!(pump(&rx, &mut ui), Pumped::Turn { ok: true, .. }));
        assert_eq!(asking.join().unwrap(), Decision::Allow);
        assert!(text(&ui).starts_with("allow write_file"), "{}", text(&ui));
    }
}
