use crate::buffer::{HighlightType, LexerState};
use crate::syntax::SyntaxHighlighter;

pub struct PlainHighlighter;

impl PlainHighlighter {
    pub fn new() -> Self {
        PlainHighlighter
    }
}

impl SyntaxHighlighter for PlainHighlighter {
    fn name(&self) -> &str {
        "Plain Text"
    }

    fn file_extensions(&self) -> &[&str] {
        &[]
    }

    fn highlight_line(&self, chars: &[char], _start_state: LexerState) -> (Vec<HighlightType>, LexerState) {
        (vec![HighlightType::Normal; chars.len()], LexerState::Normal)
    }
}
