#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HighlightType {
    Normal,
    Keyword,
    Type,
    StringLiteral,
    Comment,
    Number,
    Macro,
    Preprocessor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LexerState {
    Normal,
    InBlockComment,
    InMultiLineString,
}

/// Columns occupied by `ch` when it starts at display column `rx`: a tab
/// stretches to the next multiple of `tab_stop`, everything else is one column.
/// `tab_stop` must be > 0, which `Config` guarantees.
pub fn char_width(ch: char, rx: usize, tab_stop: usize) -> usize {
    if ch == '\t' {
        tab_stop - (rx % tab_stop)
    } else {
        1
    }
}

#[derive(Clone)]
pub struct Line {
    pub chars: Vec<char>,
    pub highlights: Vec<HighlightType>,
    pub end_state: LexerState,
}

impl Line {
    pub fn new(s: &str) -> Self {
        let chars: Vec<char> = s.chars().collect();
        let len = chars.len();
        Line {
            chars,
            highlights: vec![HighlightType::Normal; len],
            end_state: LexerState::Normal,
        }
    }

    /// Display width of the first `cx` characters: the column the cursor sits at
    /// when it is at character index `cx`.
    pub fn display_width_to(&self, cx: usize, tab_stop: usize) -> usize {
        let mut rx = 0;
        for &ch in self.chars.iter().take(cx) {
            rx += char_width(ch, rx, tab_stop);
        }
        rx
    }

    pub fn wrapped_segments(
        &self,
        text_cols: usize,
        tab_stop: usize,
    ) -> Vec<(Vec<char>, Vec<HighlightType>)> {
        if text_cols == 0 {
            return vec![(self.chars.clone(), self.highlights.clone())];
        }

        let mut segments = Vec::new();
        let mut current_chars = Vec::new();
        let mut current_hl = Vec::new();
        let mut rx = 0;

        for (i, &ch) in self.chars.iter().enumerate() {
            let char_w = char_width(ch, rx, tab_stop);

            if rx > 0 && rx + char_w > text_cols && !current_chars.is_empty() {
                segments.push((current_chars, current_hl));
                current_chars = Vec::new();
                current_hl = Vec::new();
                rx = 0;
            }

            current_chars.push(ch);
            let hl = self.highlights.get(i).copied().unwrap_or(HighlightType::Normal);
            current_hl.push(hl);

            // Recomputed rather than reusing char_w: a wrap just above may have
            // reset rx, and a tab that starts a segment spans a full tab stop.
            rx += char_width(ch, rx, tab_stop);

            if rx >= text_cols {
                segments.push((current_chars, current_hl));
                current_chars = Vec::new();
                current_hl = Vec::new();
                rx = 0;
            }
        }

        if !current_chars.is_empty() || segments.is_empty() {
            segments.push((current_chars, current_hl));
        }

        segments
    }

    pub fn wrapped_segments_count(&self, text_cols: usize, tab_stop: usize) -> usize {
        if text_cols == 0 {
            return 1;
        }
        if self.chars.is_empty() {
            return 1;
        }

        let mut count = 0;
        let mut rx = 0;
        let mut has_chars_in_current = false;

        for &ch in self.chars.iter() {
            let char_w = char_width(ch, rx, tab_stop);

            if rx > 0 && rx + char_w > text_cols && has_chars_in_current {
                count += 1;
                rx = 0;
            }

            has_chars_in_current = true;

            // Recomputed: rx may have just been reset by the wrap above.
            rx += char_width(ch, rx, tab_stop);

            if rx >= text_cols {
                count += 1;
                rx = 0;
                has_chars_in_current = false;
            }
        }

        if has_chars_in_current || count == 0 {
            count += 1;
        }

        count
    }
}

#[derive(Clone)]
pub struct Buffer {
    pub id: usize,
    pub lines: Vec<Line>,
    pub dirty: bool,
    pub filename: Option<String>,
    pub cx: usize,
    pub cy: usize,
    pub rx: usize,
    pub row_offset: usize,
    pub col_offset: usize,
}

impl Buffer {
    pub fn new(id: usize, filename: Option<String>) -> Self {
        let mut lines = Vec::new();
        if let Some(ref path) = filename {
            if let Ok(content) = std::fs::read_to_string(path) {
                for line in content.lines() {
                    lines.push(Line::new(line));
                }
            }
        }

        if lines.is_empty() {
            lines.push(Line::new(""));
        }

        Buffer {
            id,
            lines,
            dirty: false,
            filename,
            cx: 0,
            cy: 0,
            rx: 0,
            row_offset: 0,
            col_offset: 0,
        }
    }
}
