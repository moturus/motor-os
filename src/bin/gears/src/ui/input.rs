//! Terminal input has one owner, independent of the UI that presents it.
//!
//! Line mode currently asks this owner for completed lines. During a live turn
//! it will also poll the same owner for control actions; the crossterm UI can
//! later implement the same small vocabulary from key events instead of raw
//! bytes. Keeping ownership here prevents prompts, permission questions, and
//! cancellation from becoming competing stdin readers.

use std::collections::VecDeque;
use std::io::{BufRead, Write};
use std::time::Duration;

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
    source: Source<R>,
    editor: Option<line::Editor>,
}

enum Source<R> {
    Blocking(R),
    Live(Live),
}

struct Live {
    source: crate::platform::TerminalInput,
    cooked: Vec<u8>,
    queued: VecDeque<Action>,
}

impl<R: BufRead> Owner<R> {
    pub fn new(input: R) -> Owner<R> {
        Owner {
            source: Source::Blocking(input),
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
        if matches!(self.source, Source::Live(_)) {
            loop {
                match self.poll_live(renderer, None) {
                    Ok(Some(action)) => return action,
                    Ok(None) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                        return Action::Cancel;
                    }
                    Err(_) => return Action::End,
                }
            }
        }

        let Source::Blocking(input) = &mut self.source else {
            unreachable!()
        };
        if let Some(editor) = &mut self.editor {
            let action = match editor.read(input, renderer) {
                line::Read::Line(text) => Action::Line(text),
                line::Read::End => Action::End,
                line::Read::Interrupted => Action::Cancel,
            };
            renderer.user_typed();
            return action;
        }

        let mut text = String::new();
        let action = match input.read_line(&mut text) {
            Ok(0) | Err(_) => Action::End,
            Ok(_) => Action::Line(text.trim_end_matches(['\r', '\n']).to_string()),
        };
        renderer.user_typed();
        action
    }

    fn poll_live<W: Write>(
        &mut self,
        renderer: &mut Renderer<W>,
        timeout: Option<Duration>,
    ) -> std::io::Result<Option<Action>> {
        let Source::Live(live) = &mut self.source else {
            return Ok(None);
        };
        if let Some(action) = live.queued.pop_front() {
            renderer.user_typed();
            return Ok(Some(action));
        }

        let mut bytes = [0u8; 2048];
        let Some(read) = live.source.read(&mut bytes, timeout)? else {
            return Ok(None);
        };
        if read == 0 {
            return Ok(Some(Action::End));
        }
        if let Some(editor) = &mut self.editor {
            let mut echo = Vec::new();
            for &byte in &bytes[..read] {
                if let Some(action) = editor.feed(byte, &mut echo) {
                    live.queued.push_back(match action {
                        line::Read::Line(text) => Action::Line(text),
                        line::Read::End => Action::End,
                        line::Read::Interrupted => Action::Cancel,
                    });
                }
            }
            renderer.echo(&echo)?;
        } else {
            live.cooked.extend_from_slice(&bytes[..read]);
            while let Some(end) = live.cooked.iter().position(|byte| *byte == b'\n') {
                let mut line = live.cooked.drain(..=end).collect::<Vec<_>>();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                live.queued
                    .push_back(Action::Line(String::from_utf8_lossy(&line).into_owned()));
            }
        }
        let action = live.queued.pop_front();
        if action.is_some() {
            renderer.user_typed();
        }
        Ok(action)
    }
}

impl Owner<std::io::Empty> {
    /// Own the process terminal through the platform readiness API.
    pub fn live() -> std::io::Result<Owner<std::io::Empty>> {
        Ok(Owner {
            source: Source::Live(Live {
                source: crate::platform::TerminalInput::new()?,
                cooked: Vec::new(),
                queued: VecDeque::new(),
            }),
            editor: None,
        })
    }

    pub fn poll<W: Write>(
        &mut self,
        renderer: &mut Renderer<W>,
        timeout: Duration,
    ) -> std::io::Result<Option<Action>> {
        self.poll_live(renderer, Some(timeout))
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
