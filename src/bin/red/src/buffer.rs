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
    /// The bytes to write out for this buffer.
    ///
    /// Follows vim's default (`'fixendofline'` on): every line is *terminated*
    /// by a newline rather than separated by one, so a file keeps its final
    /// newline, keeps its trailing blank lines, and gains a final newline if it
    /// was missing one. A buffer with no lines writes an empty file.
    ///
    /// Where this parts ways with vim: vim's buffer can hold zero lines, which
    /// is how it tells an empty file from a file containing a single newline.
    /// red always keeps at least one line, so a lone empty line has to stand in
    /// for "no lines" -- and an empty file is far commoner than a file that is
    /// just a newline. A file containing exactly "\n" therefore saves as empty.
    pub fn to_file_content(&self) -> String {
        if self.lines.len() == 1 && self.lines[0].chars.is_empty() {
            return String::new();
        }

        let mut content = String::new();
        for line in &self.lines {
            content.extend(line.chars.iter());
            content.push('\n');
        }
        content
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    fn buffer_of(lines: &[&str]) -> Buffer {
        let mut buf = Buffer::new(1, None);
        buf.lines = lines.iter().map(|l| Line::new(l)).collect();
        buf
    }

    // The expectations below are what vim 9.1 actually writes, measured by
    // round-tripping each file through `vim -es -u NONE -c wq`.

    #[test]
    fn test_lines_are_terminated_not_separated() {
        // The whole point: the final newline must survive a save.
        assert_eq!(buffer_of(&["hello", "world"]).to_file_content(), "hello\nworld\n");
    }

    #[test]
    fn test_single_line_gets_a_newline() {
        assert_eq!(buffer_of(&["hello"]).to_file_content(), "hello\n");
    }

    #[test]
    fn test_trailing_blank_lines_survive() {
        // "a\n\n" loads as ["a", ""] and must write back as "a\n\n".
        assert_eq!(buffer_of(&["a", ""]).to_file_content(), "a\n\n");
        assert_eq!(buffer_of(&["a", "", ""]).to_file_content(), "a\n\n\n");
    }

    #[test]
    fn test_leading_and_interior_blank_lines_survive() {
        assert_eq!(buffer_of(&["", "a", "", "b"]).to_file_content(), "\na\n\nb\n");
    }

    #[test]
    fn test_empty_buffer_writes_an_empty_file() {
        // vim writes 0 bytes for a buffer with no lines; red's lone empty line
        // stands in for that, so a new/empty file does not gain a newline.
        assert_eq!(buffer_of(&[""]).to_file_content(), "");
        assert_eq!(Buffer::new(1, None).to_file_content(), "");
    }

    #[test]
    fn test_line_of_only_whitespace_is_not_an_empty_buffer() {
        // A space is content: this is a real line and gets terminated.
        assert_eq!(buffer_of(&[" "]).to_file_content(), " \n");
    }
}
