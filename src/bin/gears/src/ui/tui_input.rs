//! The TUI's single owner of crossterm input and permission decisions.

use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use super::tui::Decisions;
use super::tui_editor::{Edit, Editor};
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
    ScrollUp,
    ScrollDown,
}

pub struct Input {
    editor: Editor,
    gate: Gate,
    attended: bool,
}

impl Input {
    pub fn new(gate: Gate) -> Input {
        Input {
            editor: Editor::new(),
            gate,
            attended: true,
        }
    }

    pub fn unattended(mut self) -> Input {
        self.attended = false;
        self
    }

    pub fn draft(&self) -> &str {
        self.editor.text()
    }

    /// Read at most one actionable terminal event.
    pub fn poll(&mut self, timeout: Duration, editing: bool) -> io::Result<Option<Action>> {
        let mut wait = timeout;
        loop {
            if !event::poll(wait)? {
                return Ok(None);
            }
            if let Some(action) = self.apply(event::read()?, editing) {
                return Ok(Some(action));
            }
            // Ignore inapplicable events already in the queue without turning
            // one of them into a false timeout.
            wait = Duration::ZERO;
        }
    }

    fn apply(&mut self, event: Event, editing: bool) -> Option<Action> {
        match event {
            Event::Resize(_, _) => Some(Action::Resize),
            Event::Key(key) if key.kind == KeyEventKind::Press => self.key(key, editing),
            Event::Paste(text) if editing => Self::edited(self.editor.insert_paste(&text)),
            _ => None,
        }
    }

    fn key(&mut self, key: KeyEvent, editing: bool) -> Option<Action> {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('c') if control => Some(Action::Cancel),
            KeyCode::Char('p') if control => Some(Action::Pause),
            KeyCode::PageUp => Some(Action::ScrollUp),
            KeyCode::PageDown => Some(Action::ScrollDown),
            _ if !editing => None,
            KeyCode::Char('d') if control && self.editor.text().is_empty() => Some(Action::End),
            KeyCode::Char('j') if control => Self::edited(self.editor.insert_char('\n')),
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::ALT) => {
                Self::edited(self.editor.insert_char('\n'))
            }
            KeyCode::Enter => Some(Action::Submit(self.editor.submit())),
            KeyCode::Char('h') if control => Self::edited(self.editor.backspace()),
            KeyCode::Backspace => Self::edited(self.editor.backspace()),
            KeyCode::Delete => Self::edited(self.editor.delete()),
            KeyCode::Up => Self::edited(self.editor.older()),
            KeyCode::Down => Self::edited(self.editor.newer()),
            KeyCode::Tab => Self::edited(self.editor.insert_char('\t')),
            KeyCode::Char(character) if !control && !character.is_control() => {
                Self::edited(self.editor.insert_char(character))
            }
            _ => None,
        }
    }

    fn edited(edit: Edit) -> Option<Action> {
        match edit {
            Edit::Unchanged => None,
            Edit::Changed => Some(Action::Changed),
            Edit::Sanitized => {
                crate::trace::log(
                    crate::trace::Level::Warn,
                    "discarded unsupported control input from TUI prompt",
                );
                Some(Action::Changed)
            }
            Edit::Full => {
                crate::trace::log(
                    crate::trace::Level::Warn,
                    "refused TUI prompt input beyond the 1 MiB editor bound",
                );
                None
            }
        }
    }

    fn ask(&mut self, request: &PermissionRequest) -> Decision {
        if let Some(decision) = self.gate.known(request) {
            return decision;
        }
        if !self.attended {
            return Decision::Deny;
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
        PermissionRequest::new("write_file", "write_file src/main.rs")
    }

    #[test]
    fn simple_prompt_and_control_keys_are_distinct() {
        let mut input = Input::new(Gate::new(Mode::Ask));
        assert_eq!(
            input.apply(key(KeyCode::Char('h'), KeyModifiers::NONE), true),
            Some(Action::Changed)
        );
        assert_eq!(
            input.apply(key(KeyCode::Char('i'), KeyModifiers::NONE), true),
            Some(Action::Changed)
        );
        assert_eq!(input.draft(), "hi");
        assert_eq!(
            input.apply(key(KeyCode::Backspace, KeyModifiers::NONE), true),
            Some(Action::Changed)
        );
        assert_eq!(
            input.apply(key(KeyCode::Enter, KeyModifiers::NONE), true),
            Some(Action::Submit("h".into()))
        );
        assert_eq!(input.draft(), "");
        assert_eq!(
            input.apply(key(KeyCode::Char('c'), KeyModifiers::CONTROL), true),
            Some(Action::Cancel)
        );
        assert_eq!(
            input.apply(key(KeyCode::Char('p'), KeyModifiers::CONTROL), true),
            Some(Action::Pause)
        );
        assert_eq!(
            input.apply(key(KeyCode::Char('d'), KeyModifiers::CONTROL), true),
            Some(Action::End)
        );
        assert_eq!(
            input.apply(Event::Resize(100, 40), true),
            Some(Action::Resize)
        );
    }

    #[test]
    fn active_turns_accept_controls_but_not_future_prompts() {
        let mut input = Input::new(Gate::new(Mode::Ask));
        assert_eq!(
            input.apply(key(KeyCode::Char('y'), KeyModifiers::NONE), false),
            None
        );
        assert_eq!(input.draft(), "");
        assert_eq!(input.apply(Event::Paste("future".into()), false), None);
        assert_eq!(input.draft(), "");
        assert_eq!(
            input.apply(key(KeyCode::PageUp, KeyModifiers::NONE), false),
            Some(Action::ScrollUp)
        );
        assert_eq!(
            input.apply(key(KeyCode::PageDown, KeyModifiers::NONE), false),
            Some(Action::ScrollDown)
        );
        assert_eq!(
            input.apply(key(KeyCode::Char('c'), KeyModifiers::CONTROL), false),
            Some(Action::Cancel)
        );
        assert_eq!(
            input.apply(key(KeyCode::Char('p'), KeyModifiers::CONTROL), false),
            Some(Action::Pause)
        );
    }

    #[test]
    fn multiline_paste_bindings_and_history_are_distinct() {
        let mut input = Input::new(Gate::new(Mode::Ask));
        assert_eq!(
            input.apply(Event::Paste("one\r\ntwo\x1b".into()), true),
            Some(Action::Changed)
        );
        assert_eq!(input.draft(), "one\ntwo");
        assert_eq!(
            input.apply(key(KeyCode::Char('j'), KeyModifiers::CONTROL), true),
            Some(Action::Changed)
        );
        assert_eq!(
            input.apply(key(KeyCode::Enter, KeyModifiers::ALT), true),
            Some(Action::Changed)
        );
        assert_eq!(
            input.apply(key(KeyCode::Enter, KeyModifiers::NONE), true),
            Some(Action::Submit("one\ntwo\n\n".into()))
        );

        input.apply(Event::Paste("draft".into()), true);
        assert_eq!(
            input.apply(key(KeyCode::Up, KeyModifiers::NONE), true),
            Some(Action::Changed)
        );
        assert_eq!(input.draft(), "one\ntwo\n\n");
        assert_eq!(
            input.apply(key(KeyCode::Down, KeyModifiers::NONE), true),
            Some(Action::Changed)
        );
        assert_eq!(input.draft(), "draft");
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

        let mut unattended = Input::new(Gate::new(Mode::Ask)).unattended();
        assert_eq!(unattended.ask(&request()), Decision::Deny);
    }
}
