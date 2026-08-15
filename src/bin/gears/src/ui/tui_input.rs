//! The TUI's single owner of crossterm input and permission decisions.

use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use super::tui::Decisions;
use crate::agent::bus::{AgentId, Decision, PermissionRequest};
use crate::agent::gate::Gate;

const INPUT_POLL: Duration = Duration::from_millis(200);

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Changed,
    Submit(String),
    Cancel,
    Pause,
    End,
    Resize,
}

pub struct Input {
    draft: String,
    gate: Gate,
}

impl Input {
    pub fn new(gate: Gate) -> Input {
        Input {
            draft: String::new(),
            gate,
        }
    }

    pub fn draft(&self) -> &str {
        &self.draft
    }

    /// Read at most one actionable terminal event.
    pub fn poll(&mut self, timeout: Duration) -> io::Result<Option<Action>> {
        if !event::poll(timeout)? {
            return Ok(None);
        }
        Ok(self.apply(event::read()?))
    }

    fn apply(&mut self, event: Event) -> Option<Action> {
        match event {
            Event::Resize(_, _) => Some(Action::Resize),
            Event::Key(key) if key.kind == KeyEventKind::Press => self.key(key),
            // Step 13 owns paste, mouse, focus, and richer editing behavior.
            _ => None,
        }
    }

    fn key(&mut self, key: KeyEvent) -> Option<Action> {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('c') if control => Some(Action::Cancel),
            KeyCode::Char('p') if control => Some(Action::Pause),
            KeyCode::Char('d') if control && self.draft.is_empty() => Some(Action::End),
            // Motor may deliver a bare LF as Ctrl+J for the Enter key.
            KeyCode::Char('j') if control => Some(Action::Submit(std::mem::take(&mut self.draft))),
            KeyCode::Enter => Some(Action::Submit(std::mem::take(&mut self.draft))),
            KeyCode::Char('h') if control => {
                self.draft.pop();
                Some(Action::Changed)
            }
            KeyCode::Backspace => {
                self.draft.pop();
                Some(Action::Changed)
            }
            KeyCode::Char(character) if !control && !character.is_control() => {
                self.draft.push(character);
                Some(Action::Changed)
            }
            _ => None,
        }
    }

    fn ask(&mut self, request: &PermissionRequest) -> Decision {
        if let Some(decision) = self.gate.known(request) {
            return decision;
        }
        let decision = loop {
            match event::poll(INPUT_POLL) {
                Ok(false) => continue,
                Err(_) => break Decision::Deny,
                Ok(true) => {}
            }
            match event::read() {
                Ok(event) => {
                    if let Some(decision) = permission_key(event) {
                        break decision;
                    }
                }
                Err(_) => break Decision::Deny,
            }
        };
        if decision == Decision::Always {
            self.gate.remember(&request.key);
            if let Some(complaint) = self.gate.complaint() {
                crate::trace::log(crate::trace::Level::Error, &complaint);
            }
        }
        crate::trace::log(
            crate::trace::Level::Info,
            &format!("permission {decision:?} for {}", request.key),
        );
        decision
    }
}

impl Decisions for Input {
    fn decide(&mut self, _agent: AgentId, request: &PermissionRequest) -> Decision {
        self.ask(request)
    }
}

fn permission_key(event: Event) -> Option<Decision> {
    let Event::Key(key) = event else {
        return None;
    };
    if key.kind != KeyEventKind::Press {
        return None;
    }
    let control = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Char('y') if !control => Some(Decision::Allow),
        KeyCode::Char('a') if !control => Some(Decision::Always),
        KeyCode::Char('n') if !control => Some(Decision::Deny),
        KeyCode::Char('c') if control => Some(Decision::Deny),
        KeyCode::Enter | KeyCode::Esc => Some(Decision::Deny),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::gate::Mode;

    fn key(code: KeyCode, modifiers: KeyModifiers) -> Event {
        Event::Key(KeyEvent::new(code, modifiers))
    }

    fn request() -> PermissionRequest {
        PermissionRequest {
            key: "write_file".into(),
            detail: "write_file src/main.rs".into(),
            preview: None,
        }
    }

    #[test]
    fn simple_prompt_and_control_keys_are_distinct() {
        let mut input = Input::new(Gate::new(Mode::Ask));
        assert_eq!(
            input.apply(key(KeyCode::Char('h'), KeyModifiers::NONE)),
            Some(Action::Changed)
        );
        assert_eq!(
            input.apply(key(KeyCode::Char('i'), KeyModifiers::NONE)),
            Some(Action::Changed)
        );
        assert_eq!(input.draft(), "hi");
        assert_eq!(
            input.apply(key(KeyCode::Backspace, KeyModifiers::NONE)),
            Some(Action::Changed)
        );
        assert_eq!(
            input.apply(key(KeyCode::Enter, KeyModifiers::NONE)),
            Some(Action::Submit("h".into()))
        );
        assert_eq!(input.draft(), "");
        assert_eq!(
            input.apply(key(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Some(Action::Cancel)
        );
        assert_eq!(
            input.apply(key(KeyCode::Char('p'), KeyModifiers::CONTROL)),
            Some(Action::Pause)
        );
        assert_eq!(
            input.apply(key(KeyCode::Char('d'), KeyModifiers::CONTROL)),
            Some(Action::End)
        );
        assert_eq!(input.apply(Event::Resize(100, 40)), Some(Action::Resize));
    }

    #[test]
    fn permission_keys_are_explicit_and_press_only() {
        assert_eq!(
            permission_key(key(KeyCode::Char('y'), KeyModifiers::NONE)),
            Some(Decision::Allow)
        );
        assert_eq!(
            permission_key(key(KeyCode::Char('a'), KeyModifiers::NONE)),
            Some(Decision::Always)
        );
        assert_eq!(
            permission_key(key(KeyCode::Char('n'), KeyModifiers::NONE)),
            Some(Decision::Deny)
        );
        assert_eq!(
            permission_key(key(KeyCode::Esc, KeyModifiers::NONE)),
            Some(Decision::Deny)
        );
        assert_eq!(
            permission_key(key(KeyCode::Char('x'), KeyModifiers::NONE)),
            None
        );
        let mut release = KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE);
        release.kind = KeyEventKind::Release;
        assert_eq!(permission_key(Event::Key(release)), None);
    }

    #[test]
    fn known_permissions_need_no_terminal_event() {
        let mut gate = Gate::new(Mode::Ask);
        gate.remember("write_file");
        let mut input = Input::new(gate);
        assert_eq!(input.ask(&request()), Decision::Allow);

        let mut automatic = Input::new(Gate::new(Mode::AutoApprove));
        assert_eq!(automatic.ask(&request()), Decision::Allow);
    }
}
