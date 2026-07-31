pub mod bash;
pub mod c;
pub mod plain;
pub mod rust;
pub mod toml;

use crate::buffer::{HighlightType, LexerState};
use bash::BashHighlighter;
use c::CHighlighter;
use plain::PlainHighlighter;
use rust::RustHighlighter;
use toml::TomlHighlighter;

pub trait SyntaxHighlighter {
    fn name(&self) -> &str;
    fn file_extensions(&self) -> &[&str];
    fn highlight_line(
        &self,
        chars: &[char],
        start_state: LexerState,
    ) -> (Vec<HighlightType>, LexerState);
}

pub struct SyntaxManager {
    highlighters: Vec<Box<dyn SyntaxHighlighter + Send + Sync>>,
    plain_highlighter: PlainHighlighter,
}

impl SyntaxManager {
    pub fn new() -> Self {
        SyntaxManager {
            highlighters: vec![
                Box::new(RustHighlighter::new()),
                Box::new(BashHighlighter::new()),
                Box::new(CHighlighter::new()),
                Box::new(TomlHighlighter::new()),
            ],
            plain_highlighter: PlainHighlighter::new(),
        }
    }

    pub fn get_highlighter(&self, filename: &Option<String>) -> &dyn SyntaxHighlighter {
        if let Some(name) = filename {
            if let Some(ext) = name.split('.').last() {
                for h in &self.highlighters {
                    if h.file_extensions().contains(&ext) {
                        return h.as_ref();
                    }
                }
            }
        }
        &self.plain_highlighter
    }
}

// What a highlight looks like is the editor's to say (`editor::paint_style`):
// it is the only thing that writes to the terminal, and there is one table of
// colours rather than two that can disagree.
