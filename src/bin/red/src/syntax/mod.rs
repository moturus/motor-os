pub mod rust;
pub mod bash;
pub mod c;
pub mod toml;
pub mod plain;

use crate::buffer::{HighlightType, LexerState};
use rust::RustHighlighter;
use bash::BashHighlighter;
use c::CHighlighter;
use toml::TomlHighlighter;
use plain::PlainHighlighter;

pub trait SyntaxHighlighter {
    fn name(&self) -> &str;
    fn file_extensions(&self) -> &[&str];
    fn highlight_line(&self, chars: &[char], start_state: LexerState) -> (Vec<HighlightType>, LexerState);
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

pub fn get_ansi_style(hl: HighlightType) -> &'static str {
    match hl {
        HighlightType::Normal => "\x1b[m",             // Reset
        HighlightType::Keyword => "\x1b[1;33m",        // Bold Yellow
        HighlightType::Type => "\x1b[36m",             // Cyan
        HighlightType::StringLiteral => "\x1b[32m",    // Green
        HighlightType::Comment => "\x1b[90m",          // Dark Gray
        HighlightType::Number => "\x1b[35m",           // Magenta
        HighlightType::Macro => "\x1b[1;36m",          // Bold Cyan
        HighlightType::Preprocessor => "\x1b[1;35m",   // Bold Magenta
    }
}
