//! The interactive half of the line UI: the prompt, the permission question,
//! the slash commands, and the loop that ties them to an agent.
//!
//! Everything here runs on the one thread that owns the terminal. The agent is
//! elsewhere; what crosses between them is the bus and nothing else.

use std::io::{BufRead, Write};
use std::process::ExitCode;

use crate::agent::bus::{Decision, Event, PermissionRequest};
use crate::agent::gate::Gate;
use crate::agent::harness::{Command, Harness};
use crate::ui::repl::{Pumped, Renderer, Ui, pump};

pub const HELP: &str = "\
  /status   what this session has cost and changed
  /undo     put every file this session changed back
  /help     this
  /quit     leave (^C does too)
Anything else is a prompt for the model.
";

/// A terminal, a gate, and whether there is anybody there to answer.
pub struct Terminal<W: Write, R: BufRead> {
    renderer: Renderer<W>,
    input: R,
    gate: Gate,
    /// Whether a permission question can be put to a user at all. Without one
    /// — `gears -p` with a gate that is still asking — the answer is no.
    interactive: bool,
    /// Failures rendered so far: the one-shot exit code.
    failures: usize,
    /// The last accounting the agent reported, for `/status`. It arrives with
    /// the end of each turn, so the UI never has to reach across the bus.
    usage: crate::provider::UsageMeter,
}

impl<W: Write, R: BufRead> Terminal<W, R> {
    pub fn new(out: W, input: R, gate: Gate, interactive: bool) -> Terminal<W, R> {
        Terminal {
            renderer: Renderer::new(out),
            input,
            gate,
            interactive,
            failures: 0,
            usage: crate::provider::UsageMeter::new(),
        }
    }

    pub fn failures(&self) -> usize {
        self.failures
    }

    /// Read one line. `None` at end of input, or after a ^C.
    fn read_line(&mut self) -> Option<String> {
        let mut line = String::new();
        let read = self.input.read_line(&mut line);
        self.renderer.user_typed();
        match read {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(line.trim_end_matches(['\r', '\n']).to_string()),
        }
    }

    fn ask_user(&mut self, request: &PermissionRequest) -> Decision {
        if !self.interactive {
            // Nobody to ask. Denying is the only answer that cannot do harm,
            // and the model is told, so it can say what it needed.
            let _ = self
                .renderer
                .line(&format!("- denied, nobody to ask: {}", request.detail));
            return Decision::Deny;
        }
        loop {
            let _ = self.renderer.prompt(&format!(
                "allow {}? [y]es / [n]o / [a]lways: ",
                request.detail
            ));
            let Some(answer) = self.read_line() else {
                return Decision::Deny;
            };
            match answer.trim() {
                "y" | "yes" => return Decision::Allow,
                "n" | "no" | "" => return Decision::Deny,
                "a" | "always" => return Decision::Always,
                _ => {
                    let _ = self.renderer.line("- answer y, n or a");
                }
            }
        }
    }
}

impl<W: Write, R: BufRead> Ui for Terminal<W, R> {
    fn render(&mut self, event: &Event) -> std::io::Result<()> {
        match event {
            Event::Failed { .. } => self.failures += 1,
            Event::TurnEnd { usage, .. } => self.usage = *usage,
            _ => {}
        }
        self.renderer.event(event)
    }

    fn decide(&mut self, request: &PermissionRequest) -> Decision {
        // The gate answers on its own whenever it can; the user is only put to
        // the trouble for what it has never been told.
        if let Some(decision) = self.gate.known(request) {
            return decision;
        }
        let decision = self.ask_user(request);
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
    let _ = ui.renderer.line(&format!("- {}", harness.opening()));
    if let Err(e) = harness.send(Command::Prompt(prompt.to_string())) {
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
pub fn interact<W: Write, R: BufRead>(harness: &Harness, ui: &mut Terminal<W, R>) -> ExitCode {
    let _ = ui.renderer.line(&format!("- {}", harness.opening()));
    let _ = ui.renderer.line(&format!(
        "- {} in {}",
        harness.model(),
        harness.workspace().display()
    ));
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
        if let Some(command) = line.strip_prefix('/') {
            match slash(harness, ui, command) {
                Ok(true) => continue,
                Ok(false) => return exit_code(ui),
                Err(e) => {
                    let _ = ui.renderer.line(&format!("! {e}"));
                    continue;
                }
            }
        }
        if let Err(e) = harness.send(Command::Prompt(line.to_string())) {
            let _ = ui.renderer.line(&format!("! {e}"));
            return ExitCode::FAILURE;
        }
        match pump(harness.events(), ui) {
            Pumped::Turn { .. } => {}
            Pumped::Exit | Pumped::Closed => return exit_code(ui),
            Pumped::Broken(e) => {
                eprintln!("gears: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
}

fn exit_code<W: Write, R: BufRead>(ui: &Terminal<W, R>) -> ExitCode {
    match ui.failures() {
        0 => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

/// Handle a slash command; `false` means leave.
fn slash<W: Write, R: BufRead>(
    harness: &Harness,
    ui: &mut Terminal<W, R>,
    command: &str,
) -> Result<bool, String> {
    match command.split_whitespace().next().unwrap_or("") {
        "quit" | "exit" | "q" => return Ok(false),
        "help" | "?" => {
            ui.renderer.line(HELP).map_err(|e| e.to_string())?;
        }
        "status" => {
            let changed = harness.undo().files();
            let text = format!(
                "session {} | {} | {}\n{} | {} files changed",
                harness.session_id(),
                harness.model(),
                harness.workspace().display(),
                ui.usage.summary(),
                changed.len(),
            );
            ui.renderer.line(&text).map_err(|e| e.to_string())?;
        }
        "undo" => {
            let restored = harness.undo().restore()?;
            let text = match restored.is_empty() {
                true => "nothing to undo".to_string(),
                false => format!("put back: {}", restored.join(", ")),
            };
            ui.renderer
                .line(&format!("- {text}"))
                .map_err(|e| e.to_string())?;
        }
        other => return Err(format!("no such command '/{other}'; try /help")),
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::bus::ROOT;
    use crate::agent::gate::Mode;
    use crate::provider::UsageMeter;
    use std::sync::mpsc::channel;

    fn terminal(input: &str, mode: Mode, interactive: bool) -> Terminal<Vec<u8>, &[u8]> {
        Terminal::new(Vec::new(), input.as_bytes(), Gate::new(mode), interactive)
    }

    fn text<R: BufRead>(ui: &Terminal<Vec<u8>, R>) -> String {
        String::from_utf8(ui.renderer.get_ref().clone()).unwrap()
    }

    fn request() -> PermissionRequest {
        PermissionRequest {
            key: "write_file".to_string(),
            detail: "write_file notes.txt".to_string(),
        }
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
            assert_eq!(ui.decide(&request()), expected, "{typed:?}");
            if !typed.is_empty() {
                assert!(text(&ui).contains("write_file notes.txt"), "{typed:?}");
            }
        }
    }

    #[test]
    fn an_unreadable_answer_is_asked_again() {
        let mut ui = terminal("maybe\ny\n", Mode::Ask, true);
        assert_eq!(ui.decide(&request()), Decision::Allow);
        let shown = text(&ui);
        assert!(shown.contains("answer y, n or a"), "{shown}");
        assert_eq!(shown.matches("allow write_file").count(), 2, "{shown}");
    }

    #[test]
    fn always_is_asked_once_and_then_never_again() {
        let mut ui = terminal("a\n", Mode::Ask, true);
        assert_eq!(ui.decide(&request()), Decision::Always);
        // The second call has no input left to read: an answer that had to be
        // asked for would come back a denial.
        assert_eq!(ui.decide(&request()), Decision::Allow);
    }

    #[test]
    fn with_nobody_to_ask_the_answer_is_no() {
        let mut ui = terminal("y\n", Mode::Ask, false);
        assert_eq!(ui.decide(&request()), Decision::Deny);
        assert!(text(&ui).contains("nobody to ask"), "{}", text(&ui));

        // Unless the gate was told not to ask in the first place.
        let mut ui = terminal("", Mode::AutoApprove, false);
        assert_eq!(ui.decide(&request()), Decision::Allow);
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

    /// The prompt is written before the answer is read, not after: a prompt
    /// that only appears once the user has typed is no prompt at all.
    #[test]
    fn the_question_is_flushed_before_the_read() {
        let (tx, rx) = channel();
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
