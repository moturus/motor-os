//! Terminal input has one owner, independent of the UI that presents it.
//!
//! Line mode currently asks this owner for completed lines. During a live turn
//! it will also poll the same owner for control actions; the crossterm UI can
//! later implement the same small vocabulary from key events instead of raw
//! bytes. Keeping ownership here prevents prompts, permission questions, and
//! cancellation from becoming competing stdin readers.

use std::io::{BufRead, Write};

use crate::ui::line;
use crate::ui::repl::Renderer;

/// A complete piece of user intent from the terminal.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Line(String),
    End,
    Cancel,
    Pause,
}

/// The only component allowed to read a line-mode terminal.
pub struct Owner<R> {
    input: R,
    editor: Option<line::Editor>,
}

impl<R: BufRead> Owner<R> {
    pub fn new(input: R) -> Owner<R> {
        Owner {
            input,
            editor: None,
        }
    }

    /// Use the byte editor needed by Motor's always-raw console.
    pub fn editing(mut self) -> Owner<R> {
        self.editor = Some(line::Editor::new());
        self
    }

    /// Wait for one completed line or control action.
    pub fn read<W: Write>(&mut self, renderer: &mut Renderer<W>) -> Action {
        if let Some(editor) = &mut self.editor {
            let action = match editor.read(&mut self.input, renderer) {
                line::Read::Line(text) => Action::Line(text),
                line::Read::End => Action::End,
                line::Read::Interrupted => Action::Cancel,
            };
            renderer.user_typed();
            return action;
        }

        let mut text = String::new();
        let action = match self.input.read_line(&mut text) {
            Ok(0) | Err(_) => Action::End,
            Ok(_) => Action::Line(text.trim_end_matches(['\r', '\n']).to_string()),
        };
        renderer.user_typed();
        action
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cooked_and_raw_sources_have_the_same_actions() {
        let mut cooked = Owner::new(&b"hello\n"[..]);
        let mut raw = Owner::new(&b"hello\r"[..]).editing();
        let mut cooked_out = Renderer::new(Vec::new(), true);
        let mut raw_out = Renderer::new(Vec::new(), true);

        assert_eq!(cooked.read(&mut cooked_out), Action::Line("hello".into()));
        assert_eq!(raw.read(&mut raw_out), Action::Line("hello".into()));
    }

    #[test]
    fn raw_ctrl_c_is_a_control_action_not_a_line() {
        let mut owner = Owner::new(&b"discard me\x03"[..]).editing();
        let mut out = Renderer::new(Vec::new(), true);

        assert_eq!(owner.read(&mut out), Action::Cancel);
    }
}
