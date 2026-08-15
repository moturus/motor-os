//! Bounded, terminal-independent editing for TUI prompts.

use std::collections::VecDeque;

const MAX_DRAFT_BYTES: usize = 1_048_576;
const MAX_HISTORY_ENTRIES: usize = 100;
const MAX_HISTORY_BYTES: usize = 1_048_576;

#[derive(Debug, PartialEq, Eq)]
pub enum Edit {
    Unchanged,
    Changed,
    Sanitized,
    Full,
}

pub struct Editor {
    text: String,
    cursor: usize,
    history: VecDeque<String>,
    history_bytes: usize,
    selected: Option<usize>,
    saved: Option<String>,
    limits: Limits,
}

#[derive(Clone, Copy)]
struct Limits {
    draft: usize,
    history_entries: usize,
    history_bytes: usize,
}

impl Default for Editor {
    fn default() -> Self {
        Self::new()
    }
}

impl Editor {
    pub fn new() -> Editor {
        Editor::with_limits(Limits {
            draft: MAX_DRAFT_BYTES,
            history_entries: MAX_HISTORY_ENTRIES,
            history_bytes: MAX_HISTORY_BYTES,
        })
    }

    fn with_limits(limits: Limits) -> Editor {
        Editor {
            text: String::new(),
            cursor: 0,
            history: VecDeque::new(),
            history_bytes: 0,
            selected: None,
            saved: None,
            limits,
        }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn insert_char(&mut self, character: char) -> Edit {
        if character.is_control() && !matches!(character, '\n' | '\t') {
            return Edit::Sanitized;
        }
        let mut encoded = [0; 4];
        self.insert_clean(character.encode_utf8(&mut encoded))
    }

    /// Normalize newlines and discard terminal controls before retaining a paste.
    pub fn insert_paste(&mut self, pasted: &str) -> Edit {
        let mut clean = String::with_capacity(pasted.len());
        let mut sanitized = false;
        let mut characters = pasted.chars().peekable();
        while let Some(character) = characters.next() {
            match character {
                '\r' => {
                    if characters.peek() == Some(&'\n') {
                        characters.next();
                    }
                    clean.push('\n');
                    sanitized = true;
                }
                '\n' | '\t' => clean.push(character),
                _ if character.is_control() => sanitized = true,
                _ => clean.push(character),
            }
        }
        match self.insert_clean(&clean) {
            Edit::Changed if sanitized => Edit::Sanitized,
            Edit::Unchanged if sanitized => Edit::Sanitized,
            edit => edit,
        }
    }

    fn insert_clean(&mut self, text: &str) -> Edit {
        if text.is_empty() {
            return Edit::Unchanged;
        }
        let Some(size) = self.text.len().checked_add(text.len()) else {
            return Edit::Full;
        };
        if size > self.limits.draft {
            return Edit::Full;
        }
        self.detach_history();
        self.text.insert_str(self.cursor, text);
        self.cursor += text.len();
        Edit::Changed
    }

    pub fn backspace(&mut self) -> Edit {
        let Some(previous) = self.text[..self.cursor]
            .char_indices()
            .next_back()
            .map(|(at, _)| at)
        else {
            return Edit::Unchanged;
        };
        self.detach_history();
        self.text.drain(previous..self.cursor);
        self.cursor = previous;
        Edit::Changed
    }

    pub fn delete(&mut self) -> Edit {
        let Some(character) = self.text[self.cursor..].chars().next() else {
            return Edit::Unchanged;
        };
        self.detach_history();
        self.text
            .drain(self.cursor..self.cursor + character.len_utf8());
        Edit::Changed
    }

    pub fn left(&mut self) -> Edit {
        let Some(previous) = self.text[..self.cursor]
            .char_indices()
            .next_back()
            .map(|(at, _)| at)
        else {
            return Edit::Unchanged;
        };
        self.cursor = previous;
        Edit::Changed
    }

    pub fn right(&mut self) -> Edit {
        let Some(character) = self.text[self.cursor..].chars().next() else {
            return Edit::Unchanged;
        };
        self.cursor += character.len_utf8();
        Edit::Changed
    }

    pub fn home(&mut self) -> Edit {
        let target = self.text[..self.cursor].rfind('\n').map_or(0, |at| at + 1);
        self.move_to(target)
    }

    pub fn end(&mut self) -> Edit {
        let target = self.text[self.cursor..]
            .find('\n')
            .map_or(self.text.len(), |at| self.cursor + at);
        self.move_to(target)
    }

    fn move_to(&mut self, target: usize) -> Edit {
        if target == self.cursor {
            Edit::Unchanged
        } else {
            self.cursor = target;
            Edit::Changed
        }
    }

    pub fn older(&mut self) -> Edit {
        let target = match self.selected {
            Some(0) => return Edit::Unchanged,
            Some(index) => index - 1,
            None if self.history.is_empty() => return Edit::Unchanged,
            None => {
                self.saved = Some(self.text.clone());
                self.history.len() - 1
            }
        };
        self.selected = Some(target);
        self.text = self.history[target].clone();
        self.cursor = self.text.len();
        Edit::Changed
    }

    pub fn newer(&mut self) -> Edit {
        let Some(index) = self.selected else {
            return Edit::Unchanged;
        };
        if index + 1 < self.history.len() {
            self.selected = Some(index + 1);
            self.text = self.history[index + 1].clone();
        } else {
            self.selected = None;
            self.text = self.saved.take().unwrap_or_default();
        }
        self.cursor = self.text.len();
        Edit::Changed
    }

    pub fn submit(&mut self) -> String {
        let text = std::mem::take(&mut self.text);
        self.cursor = 0;
        self.selected = None;
        self.saved = None;
        if !text.is_empty() && self.history.back() != Some(&text) {
            self.history_bytes += text.len();
            self.history.push_back(text.clone());
            while self.history.len() > self.limits.history_entries
                || self.history_bytes > self.limits.history_bytes
            {
                if let Some(removed) = self.history.pop_front() {
                    self.history_bytes -= removed.len();
                }
            }
        }
        text
    }

    fn detach_history(&mut self) {
        self.selected = None;
        self.saved = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small() -> Editor {
        Editor::with_limits(Limits {
            draft: 12,
            history_entries: 2,
            history_bytes: 12,
        })
    }

    #[test]
    fn unicode_editing_uses_valid_boundaries() {
        let mut editor = small();
        assert_eq!(editor.insert_paste("aδz"), Edit::Changed);
        assert_eq!(editor.left(), Edit::Changed);
        assert_eq!(editor.backspace(), Edit::Changed);
        assert_eq!(editor.insert_char('界'), Edit::Changed);
        assert_eq!(editor.text(), "a界z");
        assert_eq!(editor.cursor(), 4);
        assert_eq!(editor.delete(), Edit::Changed);
        assert_eq!(editor.text(), "a界");
    }

    #[test]
    fn paste_normalizes_newlines_and_removes_controls_atomically() {
        let mut editor = small();
        assert_eq!(editor.insert_paste("a\r\nb\rc\x1b[2J"), Edit::Sanitized);
        assert_eq!(editor.text(), "a\nb\nc[2J");
        assert_eq!(editor.insert_paste("toolong"), Edit::Full);
        assert_eq!(editor.text(), "a\nb\nc[2J");
    }

    #[test]
    fn home_and_end_follow_the_current_line() {
        let mut editor = small();
        editor.insert_paste("ab\ncd");
        assert_eq!(editor.home(), Edit::Changed);
        assert_eq!(editor.cursor(), 3);
        assert_eq!(editor.home(), Edit::Unchanged);
        assert_eq!(editor.end(), Edit::Changed);
        assert_eq!(editor.cursor(), 5);
    }

    #[test]
    fn history_is_session_local_deduplicated_and_bounded() {
        let mut editor = small();
        for prompt in ["one", "two", "two", "three"] {
            editor.insert_paste(prompt);
            assert_eq!(editor.submit(), prompt);
        }
        editor.insert_paste("draft");
        assert_eq!(editor.older(), Edit::Changed);
        assert_eq!(editor.text(), "three");
        assert_eq!(editor.older(), Edit::Changed);
        assert_eq!(editor.text(), "two");
        assert_eq!(editor.older(), Edit::Unchanged);
        assert_eq!(editor.newer(), Edit::Changed);
        assert_eq!(editor.text(), "three");
        assert_eq!(editor.newer(), Edit::Changed);
        assert_eq!(editor.text(), "draft");
    }
}
