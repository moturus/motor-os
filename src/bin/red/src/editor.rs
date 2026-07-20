use crate::buffer::{char_width, Line, Buffer, HighlightType, LexerState};
use crate::config::Config;
use crate::input::Key;
use crate::terminal::get_terminal_size;
use crate::syntax::SyntaxManager;
use std::io::{self, Write};
use std::time::{Duration, Instant};

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Mode {
    Normal,
    Insert,
    Command,
    Search,
    VisualChar,
    VisualLine,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Clipboard {
    pub content: String,
    pub is_line_wise: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RedrawTarget {
    None,
    StatusOnly,
    Line(usize),
    FromLine(usize),
    Everything,
}

// Unified representation of a visible row on the screen
#[derive(Clone)]
pub struct VisibleRow {
    pub buffer_line_idx: usize,
    pub segment_idx: usize,
    pub chars: Vec<char>,
    pub highlights: Vec<HighlightType>,
    pub is_wrapped_continuation: bool,
}

// One rendered screen cell: the displayed character plus the self-contained SGR
// sequence (always reset-prefixed) that establishes its styling. Cheap to copy
// and compare, which lets draw() diff frames at column granularity and repaint
// only the characters that actually changed (e.g. the cursor readout in the
// status bar) instead of the whole line.
#[derive(Clone, Copy, PartialEq)]
struct Cell {
    ch: char,
    style: &'static str,
}

const STYLE_NORMAL: &str = "\x1b[m";
const STYLE_INVERT: &str = "\x1b[m\x1b[7m"; // reset, then reverse-video
const STYLE_GUTTER: &str = "\x1b[m\x1b[90m"; // reset, then dim gray

// Reset-prefixed SGR for each syntax color. Mirrors syntax::get_ansi_style but
// includes a leading reset so a cell can be repainted in isolation without
// depending on whatever style preceded it on screen. Returns &'static str so
// building a frame allocates no per-cell strings.
fn cell_syntax_style(hl: HighlightType) -> &'static str {
    match hl {
        HighlightType::Normal => "\x1b[m",
        HighlightType::Keyword => "\x1b[m\x1b[1;33m",
        HighlightType::Type => "\x1b[m\x1b[36m",
        HighlightType::StringLiteral => "\x1b[m\x1b[32m",
        HighlightType::Comment => "\x1b[m\x1b[90m",
        HighlightType::Number => "\x1b[m\x1b[35m",
        HighlightType::Macro => "\x1b[m\x1b[1;36m",
        HighlightType::Preprocessor => "\x1b[m\x1b[1;35m",
    }
}

pub struct Editor {
    pub config: Config,

    pub buffers: Vec<Buffer>,
    pub current_buffer_idx: usize,
    pub next_buffer_id: usize,

    pub screen_rows: usize,
    pub screen_cols: usize,

    pub mode: Mode,
    pub command_buffer: String,
    pub status_message: String,
    pub status_time: Instant,

    pub redraw_target: RedrawTarget,
    pub quit_requested: bool,
    pub show_line_numbers: bool,
    pub wrap: bool, // Soft line wrapping toggle

    // Visual Mode Anchor
    pub visual_anchor_x: usize,
    pub visual_anchor_y: usize,

    // Clipboard for yank and paste
    pub clipboard: Clipboard,

    // Syntax Highlighting Manager
    pub syntax_manager: SyntaxManager,

    // Search Mode State
    pub search_query: String,
    pub search_backward: bool,
    pub search_matches: Vec<(usize, usize)>,
    pub current_match_idx: Option<usize>,

    // Damage-tracking cache: the cells last emitted to each physical terminal
    // row (text rows, then the status bar, then the message bar). draw() diffs
    // the freshly rendered frame against this and repaints only the columns that
    // actually changed, so neither a keystroke nor a cursor move repaints a whole
    // line.
    prev_frame: Vec<Vec<Cell>>,
}

impl Editor {
    /// The config is passed in rather than loaded here so that `new` does no
    /// file I/O and tests are not at the mercy of the config file on the machine
    /// running them. `main` loads it via `Config::load`.
    pub fn new(filenames: Vec<String>, config: Config) -> Self {
        let (rows, cols) = get_terminal_size().unwrap_or((24, 80));
        let screen_rows = if rows > 2 { rows - 2 } else { 1 };
        let screen_cols = cols;

        let mut buffers = Vec::new();
        let mut next_buffer_id = 1;

        if filenames.is_empty() {
            buffers.push(Buffer::new(next_buffer_id, None));
            next_buffer_id += 1;
        } else {
            for filename in filenames {
                buffers.push(Buffer::new(next_buffer_id, Some(filename)));
                next_buffer_id += 1;
            }
        }

        let mut editor = Editor {
            config,
            buffers,
            current_buffer_idx: 0,
            next_buffer_id,
            screen_rows,
            screen_cols,
            mode: Mode::Normal,
            command_buffer: String::new(),
            status_message: "Welcome to red! Type :q to exit.".to_string(),
            status_time: Instant::now(),
            redraw_target: RedrawTarget::Everything,
            quit_requested: false,
            show_line_numbers: true,
            wrap: true, // Enabled by default!
            visual_anchor_x: 0,
            visual_anchor_y: 0,
            clipboard: Clipboard {
                content: String::new(),
                is_line_wise: false,
            },
            syntax_manager: SyntaxManager::new(),
            search_query: String::new(),
            search_backward: false,
            search_matches: Vec::new(),
            current_match_idx: None,
            prev_frame: Vec::new(),
        };

        // Highlight all loaded buffers
        for idx in 0..editor.buffers.len() {
            let prev_idx = editor.current_buffer_idx;
            editor.current_buffer_idx = idx;
            editor.highlight_buffer_from(0, true);
            editor.current_buffer_idx = prev_idx;
        }

        editor
    }

    pub fn current_buffer(&self) -> &Buffer {
        &self.buffers[self.current_buffer_idx]
    }

    pub fn current_buffer_mut(&mut self) -> &mut Buffer {
        &mut self.buffers[self.current_buffer_idx]
    }

    pub fn any_buffer_dirty(&self) -> bool {
        self.buffers.iter().any(|b| b.dirty)
    }

    pub fn set_status(&mut self, msg: &str) {
        self.status_message = msg.to_string();
        self.status_time = Instant::now();
        if matches!(self.redraw_target, RedrawTarget::None) {
            self.redraw_target = RedrawTarget::StatusOnly;
        }
    }

    pub fn update_rx(&mut self) {
        let tab_stop = self.config.tabstop;
        let buf = self.current_buffer_mut();
        buf.rx = if buf.cy < buf.lines.len() {
            buf.lines[buf.cy].display_width_to(buf.cx, tab_stop)
        } else {
            0
        };
    }

    pub fn scroll(&mut self) {
        self.update_rx();
        let mut changed = false;

        let gutter_w = self.get_gutter_width();
        let text_cols = self.screen_cols.saturating_sub(gutter_w);
        let screen_rows = self.screen_rows;
        let wrap = self.wrap; // Copy wrap to avoid borrow conflict
        let tab_stop = self.config.tabstop;

        let buf = self.current_buffer_mut();
        
        // 1. If cursor is above the top of the screen, scroll up immediately
        if buf.cy < buf.row_offset {
            buf.row_offset = buf.cy;
            changed = true;
        }
        
        // 2. Vertical scrolling constraints (if cursor is below the bottom of the screen)
        if text_cols > 0 {
            if !wrap {
                // Non-wrapped vertical scrolling is simple
                if buf.cy >= buf.row_offset + screen_rows {
                    buf.row_offset = buf.cy - screen_rows + 1;
                    changed = true;
                }
            } else {
                // Wrapped vertical scrolling: check if cursor visual segment is below viewport.
                
                // First, compute the cursor's segment index on its own line
                let mut cursor_segment_idx = 0;
                if buf.cy < buf.lines.len() {
                    let line = &buf.lines[buf.cy];
                    let mut current_segment_rx = 0;
                    for (i, &ch) in line.chars.iter().enumerate() {
                        if i == buf.cx {
                            break;
                        }
                        let char_w = char_width(ch, current_segment_rx, tab_stop);
                        if current_segment_rx > 0 && current_segment_rx + char_w > text_cols {
                            cursor_segment_idx += 1;
                            current_segment_rx = 0;
                        }
                        current_segment_rx += char_width(ch, current_segment_rx, tab_stop);
                    }
                }

                // Super fast check: is the cursor line index at least screen_rows lines below row_offset?
                // If yes, it is guaranteed to be off-screen. If no, we count the exact visual rows to be sure.
                let is_off_screen = if buf.cy >= buf.row_offset + screen_rows {
                    true
                } else {
                    let mut screen_y = 0;
                    for r in buf.row_offset..buf.cy {
                        if r < buf.lines.len() {
                            screen_y += buf.lines[r].wrapped_segments_count(text_cols, tab_stop);
                        }
                    }
                    screen_y += cursor_segment_idx;
                    screen_y >= screen_rows
                };

                if is_off_screen {
                    // Backwards scanning algorithm to find the new target_row_offset in O(screen_rows) time!
                    let mut remaining_rows = screen_rows;
                    
                    // The cursor line itself takes some rows. We only care about rows up to the cursor's segment.
                    let cursor_line_rows_needed = cursor_segment_idx + 1;
                    
                    if cursor_line_rows_needed >= remaining_rows {
                        // If the cursor line alone takes up the whole screen, the top-most visible line is just buf.cy
                        buf.row_offset = buf.cy;
                        changed = true;
                    } else {
                        remaining_rows -= cursor_line_rows_needed;
                        let mut target_row_offset = buf.cy;
                        
                        // Scan upwards from buf.cy - 1
                        while target_row_offset > 0 {
                            let r = target_row_offset - 1;
                            let line_rows = buf.lines[r].wrapped_segments_count(text_cols, tab_stop);
                            if line_rows <= remaining_rows {
                                remaining_rows -= line_rows;
                                target_row_offset = r;
                            } else {
                                // This line doesn't fit, so target_row_offset must be target_row_offset (which is r + 1)
                                break;
                            }
                        }
                        
                        if buf.row_offset != target_row_offset {
                            buf.row_offset = target_row_offset;
                            changed = true;
                        }
                    }
                }
            }
        }

        // Horizontal scrolling constraints (only used when wrap is false)
        if !wrap {
            if buf.rx < buf.col_offset {
                buf.col_offset = buf.rx;
                changed = true;
            }
            if buf.rx >= buf.col_offset + text_cols {
                buf.col_offset = buf.rx - text_cols + 1;
                changed = true;
            }
        } else if buf.col_offset != 0 {
            buf.col_offset = 0;
            changed = true;
        }

        if changed {
            self.redraw_target = RedrawTarget::Everything;
        }
    }

    // --- High-Performance Cascading Highlight Algorithm ---

    pub fn highlight_buffer_from(&mut self, start_row: usize, force: bool) {
        let filename = self.buffers[self.current_buffer_idx].filename.clone();
        
        // Split borrow: borrow syntax_manager immutably
        let highlighter = self.syntax_manager.get_highlighter(&filename);

        // Split borrow: borrow buffers mutably
        let buf = &mut self.buffers[self.current_buffer_idx];
        let mut row = start_row;
        let mut current_state = if row > 0 && row - 1 < buf.lines.len() {
            buf.lines[row - 1].end_state
        } else {
            LexerState::Normal
        };

        while row < buf.lines.len() {
            let line = &mut buf.lines[row];
            let old_end_state = line.end_state;

            let (new_highlights, new_end_state) = highlighter.highlight_line(&line.chars, current_state);
            line.highlights = new_highlights;
            line.end_state = new_end_state;

            // If not forcing, we can stop if the ending state did not change!
            if !force && line.end_state == old_end_state {
                break;
            }

            current_state = line.end_state;
            row += 1;
        }
    }

    // --- Screen Layout & Cursor Coordinate Translators ---

    fn gather_visible_rows(&self) -> Vec<VisibleRow> {
        let buf = self.current_buffer();
        let gutter_w = self.get_gutter_width();
        let text_cols = self.screen_cols.saturating_sub(gutter_w);
        
        let mut visible = Vec::new();
        if text_cols == 0 {
            return visible;
        }

        let mut r = buf.row_offset;
        while r < buf.lines.len() && visible.len() < self.screen_rows {
            let line = &buf.lines[r];
            if self.wrap {
                let segments = line.wrapped_segments(text_cols, self.config.tabstop);
                for (seg_idx, (seg_chars, seg_hl)) in segments.into_iter().enumerate() {
                    if visible.len() >= self.screen_rows {
                        break;
                    }
                    visible.push(VisibleRow {
                        buffer_line_idx: r,
                        segment_idx: seg_idx,
                        chars: seg_chars,
                        highlights: seg_hl,
                        is_wrapped_continuation: seg_idx > 0,
                    });
                }
            } else {
                let mut seg_chars = Vec::new();
                let mut seg_hl = Vec::new();
                let mut rx = 0;
                
                for (i, &ch) in line.chars.iter().enumerate() {
                    if rx >= buf.col_offset && rx < buf.col_offset + text_cols {
                        seg_chars.push(ch);
                        seg_hl.push(line.highlights.get(i).copied().unwrap_or(HighlightType::Normal));
                    }

                    rx += char_width(ch, rx, self.config.tabstop);
                }
                
                visible.push(VisibleRow {
                    buffer_line_idx: r,
                    segment_idx: 0,
                    chars: seg_chars,
                    highlights: seg_hl,
                    is_wrapped_continuation: false,
                });
            }
            r += 1;
        }
        visible
    }

    fn get_cursor_screen_position(&self) -> (usize, usize) {
        let buf = self.current_buffer();
        let gutter_w = self.get_gutter_width();
        let text_cols = self.screen_cols.saturating_sub(gutter_w);
        if text_cols == 0 {
            return (1 + gutter_w, 1);
        }

        // 1. Calculate screen_y by counting segments of all lines from row_offset to cy
        let mut screen_y = 0;
        for r in buf.row_offset..buf.cy {
            if r < buf.lines.len() {
                let segments = buf.lines[r].wrapped_segments(text_cols, self.config.tabstop);
                screen_y += segments.len();
            }
        }

        // 2. Find which segment of buf.cy the cursor cx is in, and its visual offset rx within that segment
        let mut segment_idx = 0;
        let mut rx_in_segment = 0;
        if buf.cy < buf.lines.len() {
            let line = &buf.lines[buf.cy];
            let mut current_segment_rx = 0;
            
            for (i, &ch) in line.chars.iter().enumerate() {
                if i == buf.cx {
                    break;
                }
                
                let char_w = char_width(ch, current_segment_rx, self.config.tabstop);

                if current_segment_rx > 0 && current_segment_rx + char_w > text_cols {
                    segment_idx += 1;
                    current_segment_rx = 0;
                }

                current_segment_rx += char_width(ch, current_segment_rx, self.config.tabstop);
            }
            rx_in_segment = current_segment_rx;
        }

        screen_y += segment_idx;

        let final_x = 1 + gutter_w + rx_in_segment;
        let final_y = 1 + screen_y;

        (final_x, final_y)
    }

    // --- Rendering Engine (Highly Optimized) ---

    // Render the entire frame into cells, one row per physical terminal row: the
    // text area, then the status bar, then the message bar. Pure and cheap (no
    // per-cell allocation); the expensive part is terminal I/O, which draw()
    // minimizes by diffing this against the previous frame.
    fn build_frame(&self) -> Vec<Vec<Cell>> {
        let gutter_w = self.get_gutter_width();
        let text_cols = self.screen_cols.saturating_sub(gutter_w);

        let visible_rows = self.gather_visible_rows();
        let mut frame: Vec<Vec<Cell>> = Vec::with_capacity(self.screen_rows + 2);
        for screen_row in 0..self.screen_rows {
            frame.push(self.render_text_row(screen_row, &visible_rows, text_cols, gutter_w));
        }
        frame.push(self.render_status_bar());
        frame.push(self.render_message_bar());
        frame
    }

    // Append the escape sequence that repaints only the columns of `new` that
    // differ from `old`, at 1-based terminal row `term_row`. Returns whether
    // anything was emitted.
    fn diff_row_into(out: &mut String, term_row: usize, old: &[Cell], new: &[Cell]) -> bool {
        // First column that differs.
        let common = old.len().min(new.len());
        let mut start = 0;
        while start < common && old[start] == new[start] {
            start += 1;
        }
        if start == common && old.len() == new.len() {
            return false; // rows identical
        }

        // Repaint from the first divergent column to the end of the new row,
        // then clear any tail left over from a previously longer row. Each cell
        // style is self-contained, so starting mid-row is safe.
        out.push_str(&format!("\x1b[{};{}H", term_row, start + 1));
        let mut active = "";
        for cell in &new[start..] {
            if cell.style != active {
                out.push_str(cell.style);
                active = cell.style;
            }
            out.push(cell.ch);
        }
        out.push_str(STYLE_NORMAL); // reset so a shorter tail clears with default bg
        if old.len() > new.len() {
            out.push_str("\x1b[K");
        }
        true
    }

    pub fn draw(&mut self) {
        let gutter_w = self.get_gutter_width();

        // 1. Render the full frame as cells, one row per physical terminal row.
        let frame = self.build_frame();
        let total_rows = frame.len();

        // 2. Damage tracking. If the row count changed (first paint or resize),
        //    clear once and repaint everything; otherwise diff each row at column
        //    granularity so a cursor move only rewrites the digits that changed
        //    in the status bar, and a keystroke only rewrites its line.
        let cache_valid = self.prev_frame.len() == total_rows;
        let mut out = String::new();
        if !cache_valid {
            out.push_str("\x1b[2J");
        }
        let mut repainted = false;
        let empty: Vec<Cell> = Vec::new();
        for (r, row) in frame.iter().enumerate() {
            let old = if cache_valid { &self.prev_frame[r] } else { &empty };
            if Self::diff_row_into(&mut out, r + 1, old, row) {
                repainted = true;
            }
        }

        // 3. Determine where to place the cursor.
        let buf = self.current_buffer();
        let (screen_x, screen_y) = match self.mode {
            Mode::Command => (self.command_buffer.chars().count() + 2, self.screen_rows + 2),
            _ => {
                if self.wrap {
                    self.get_cursor_screen_position()
                } else {
                    (buf.rx - buf.col_offset + 1 + gutter_w, buf.cy - buf.row_offset + 1)
                }
            }
        };

        // 4. Flush a single batched write. The cursor is hidden only while cells
        //    are actually repainted, so it doesn't visibly skip around; it is
        //    always re-shown (the periodic size probe hides it).
        let mut batch = String::new();
        if repainted || !cache_valid {
            batch.push_str("\x1b[?25l");
            batch.push_str(&out);
        }
        batch.push_str(&format!("\x1b[{};{}H", screen_y, screen_x));
        batch.push_str("\x1b[?25h");
        print!("{}", batch);
        let _ = io::stdout().flush();

        self.prev_frame = frame;
        self.redraw_target = RedrawTarget::None;
    }

    // Render one physical text-area row (0-based `screen_row`) into cells: the
    // gutter plus the visible text segment, or "~" past the buffer. Each cell
    // carries its own self-contained style, so draw() can repaint any subset of
    // columns; positioning/clearing is added by draw().
    fn render_text_row(&self, screen_row: usize, visible_rows: &[VisibleRow], text_cols: usize, gutter_w: usize) -> Vec<Cell> {
        if screen_row >= visible_rows.len() {
            return vec![Cell { ch: '~', style: STYLE_NORMAL }];
        }
        let vr = &visible_rows[screen_row];
        let mut cells: Vec<Cell> = Vec::new();

        // 1. Gutter (line numbers / wrap-continuation marker)
        if self.show_line_numbers {
            let g = if vr.is_wrapped_continuation {
                format!("{:>width$} ", "↳", width = gutter_w - 2)
            } else {
                format!("{:>width$} ", vr.buffer_line_idx + 1, width = gutter_w - 1)
            };
            for ch in g.chars() {
                cells.push(Cell { ch, style: STYLE_GUTTER });
            }
        }

        // 2. Text segment
        let selection = self.get_selection_range();

        if vr.chars.is_empty() {
            let should_highlight = match self.mode {
                Mode::VisualChar => {
                    if let Some((start, end)) = selection {
                        let y = vr.buffer_line_idx;
                        if y > start.1 && y < end.1 {
                            true
                        } else if y == start.1 && y == end.1 {
                            start.0 == 0
                        } else if y == start.1 {
                            start.0 == 0
                        } else if y == end.1 {
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                Mode::VisualLine => {
                    if let Some((start, end)) = selection {
                        vr.buffer_line_idx >= start.1 && vr.buffer_line_idx <= end.1
                    } else {
                        false
                    }
                }
                _ => false,
            };
            if should_highlight {
                cells.push(Cell { ch: ' ', style: STYLE_INVERT });
            }
        } else {
            // Find absolute character index in buffer line for selection matching
            let mut char_start_idx = 0;
            if self.wrap {
                let buf = self.current_buffer();
                let segments = buf.lines[vr.buffer_line_idx].wrapped_segments(text_cols, self.config.tabstop);
                for seg in segments.iter().take(vr.segment_idx) {
                    char_start_idx += seg.0.len();
                }
            } else {
                let buf = self.current_buffer();
                let line = &buf.lines[vr.buffer_line_idx];
                let mut rx = 0;
                for (idx, &ch) in line.chars.iter().enumerate() {
                    if rx >= buf.col_offset {
                        char_start_idx = idx;
                        break;
                    }
                    rx += char_width(ch, rx, self.config.tabstop);
                }
            }

            let mut rx = 0;
            for (seg_char_idx, &ch) in vr.chars.iter().enumerate() {
                let actual_char_idx = char_start_idx + seg_char_idx;

                let is_selected = match self.mode {
                    Mode::VisualChar => {
                        if let Some((start, end)) = selection {
                            let y = vr.buffer_line_idx;
                            let x = actual_char_idx;
                            if y > start.1 && y < end.1 {
                                true
                            } else if y == start.1 && y == end.1 {
                                x >= start.0 && x <= end.0
                            } else if y == start.1 {
                                x >= start.0
                            } else if y == end.1 {
                                x <= end.0
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    }
                    Mode::VisualLine => {
                        if let Some((start, end)) = selection {
                            vr.buffer_line_idx >= start.1 && vr.buffer_line_idx <= end.1
                        } else {
                            false
                        }
                    }
                    _ => false,
                };

                let char_hl = vr.highlights.get(seg_char_idx).copied().unwrap_or(HighlightType::Normal);
                let style = if is_selected { STYLE_INVERT } else { cell_syntax_style(char_hl) };

                if ch == '\t' {
                    let spaces = char_width(ch, rx, self.config.tabstop);
                    for _ in 0..spaces {
                        cells.push(Cell { ch: ' ', style });
                        rx += 1;
                    }
                } else {
                    cells.push(Cell { ch, style });
                    rx += 1;
                }
            }

            // Extend a line-wise selection across the rest of the row width.
            if self.mode == Mode::VisualLine {
                if let Some((start, end)) = selection {
                    if vr.buffer_line_idx >= start.1 && vr.buffer_line_idx <= end.1 {
                        for _ in rx..text_cols {
                            cells.push(Cell { ch: ' ', style: STYLE_INVERT });
                        }
                    }
                }
            }
        }

        cells
    }

    // Render the status bar (inverted, full width) as cells. Positioning added by draw().
    fn render_status_bar(&self) -> Vec<Cell> {
        let buf = self.current_buffer();
        let filename = buf.filename.as_deref().unwrap_or("[No Name]");
        let dirty_str = if buf.dirty { " (modified)" } else { "" };
        let left_status = format!(" [{}] {}{} - {} lines", buf.id, filename, dirty_str, buf.lines.len());

        let mode_str = match self.mode {
            Mode::Normal => "NORMAL",
            Mode::Insert => "INSERT",
            Mode::Command => "COMMAND",
            Mode::Search => "SEARCH",
            Mode::VisualChar => "VISUAL",
            Mode::VisualLine => "V-LINE",
        };
        let right_status = format!("{} | {}:{} ", mode_str, buf.cy + 1, buf.cx + 1);

        let total_width = self.screen_cols;
        let left_len = left_status.len();
        let right_len = right_status.len();

        let mut line = if left_len + right_len <= total_width {
            let padding = total_width - left_len - right_len;
            format!("{}{}{}", left_status, " ".repeat(padding), right_status)
        } else {
            left_status.chars().take(total_width).collect()
        };
        // Pad to full width so the inverted bar always covers the row.
        let cur = line.chars().count();
        if cur < total_width {
            line.push_str(&" ".repeat(total_width - cur));
        }
        line.chars().map(|ch| Cell { ch, style: STYLE_INVERT }).collect()
    }

    // Render the message bar as cells. Positioning/clear added by draw().
    fn render_message_bar(&self) -> Vec<Cell> {
        let msg = match self.mode {
            Mode::Command => format!(":{}", self.command_buffer),
            Mode::Search => {
                let prefix = if self.search_backward { "?" } else { "/" };
                format!("{}{}", prefix, self.command_buffer)
            }
            _ => {
                if self.status_time.elapsed() < Duration::from_secs(5) {
                    self.status_message.clone()
                } else {
                    String::new()
                }
            }
        };
        msg.chars().map(|ch| Cell { ch, style: STYLE_NORMAL }).collect()
    }

    pub fn handle_resize(&mut self) {
        if let Some((rows, cols)) = get_terminal_size() {
            self.apply_terminal_size(rows, cols);
        }
    }

    /// Apply a terminal size (raw rows/cols as reported by the terminal, e.g. from
    /// the async `\x1b[6n` cursor-position query). Only forces a full redraw when
    /// the derived dimensions actually change, so routine size polling while the
    /// window is stable never triggers a screen-wide redraw (and thus no flicker).
    pub fn apply_terminal_size(&mut self, rows: usize, cols: usize) {
        let new_rows = if rows > 2 { rows - 2 } else { 1 };
        let new_cols = cols;

        if new_rows != self.screen_rows || new_cols != self.screen_cols {
            self.screen_rows = new_rows;
            self.screen_cols = new_cols;
            self.redraw_target = RedrawTarget::Everything;
        }
    }

    pub fn get_gutter_width(&self) -> usize {
        if self.show_line_numbers {
            let num_lines = self.current_buffer().lines.len();
            let mut width = 1;
            let mut temp = num_lines;
            while temp >= 10 {
                temp /= 10;
                width += 1;
            }
            std::cmp::max(width, 3) + 1
        } else {
            0
        }
    }

    // --- Input Processing & Motions ---

    pub fn process_keypress(&mut self, key: Key) {
        match self.mode {
            Mode::Normal => self.process_normal_key(key),
            Mode::Insert => self.process_insert_key(key),
            Mode::Command => self.process_command_key(key),
            Mode::Search => self.process_search_key(key),
            Mode::VisualChar | Mode::VisualLine => self.process_visual_key(key),
        }
    }

    fn process_normal_key(&mut self, key: Key) {
        match key {
            // Mode shifts
            Key::Char('i') => {
                self.mode = Mode::Insert;
                self.set_status("-- INSERT --");
            }
            Key::Char('a') => {
                self.mode = Mode::Insert;
                let buf = self.current_buffer_mut();
                if buf.cy < buf.lines.len() {
                    let len = buf.lines[buf.cy].chars.len();
                    if buf.cx < len {
                        buf.cx += 1;
                    }
                }
                self.set_status("-- INSERT --");
            }
            Key::Char(':') => {
                self.mode = Mode::Command;
                self.command_buffer.clear();
                self.redraw_target = RedrawTarget::StatusOnly;
            }
            Key::Char('/') => {
                self.search_backward = false;
                self.mode = Mode::Search;
                self.command_buffer.clear();
                self.redraw_target = RedrawTarget::StatusOnly;
            }
            Key::Char('?') => {
                self.search_backward = true;
                self.mode = Mode::Search;
                self.command_buffer.clear();
                self.redraw_target = RedrawTarget::StatusOnly;
            }
            Key::Char('v') => {
                let (cx, cy) = {
                    let buf = self.current_buffer();
                    (buf.cx, buf.cy)
                };
                self.mode = Mode::VisualChar;
                self.visual_anchor_x = cx;
                self.visual_anchor_y = cy;
                self.set_status("-- VISUAL --");
                self.redraw_target = RedrawTarget::Everything;
            }
            Key::Char('V') => {
                let (cx, cy) = {
                    let buf = self.current_buffer();
                    (buf.cx, buf.cy)
                };
                self.mode = Mode::VisualLine;
                self.visual_anchor_x = cx;
                self.visual_anchor_y = cy;
                self.set_status("-- VISUAL LINE --");
                self.redraw_target = RedrawTarget::Everything;
            }
            Key::Char('p') => {
                let clipboard = self.clipboard.clone();
                if !clipboard.content.is_empty() {
                    if clipboard.is_line_wise {
                        self.paste_line_wise(&clipboard.content);
                    } else {
                        self.paste_char_wise(&clipboard.content);
                    }
                }
            }

            // Search navigation
            Key::Char('n') => {
                if !self.search_query.is_empty() {
                    self.jump_to_next_match();
                } else {
                    self.set_status("No previous search pattern");
                }
            }
            Key::Char('N') => {
                if !self.search_query.is_empty() {
                    self.jump_to_prev_match();
                } else {
                    self.set_status("No previous search pattern");
                }
            }

            // Navigation (classic hjkl)
            Key::Char('h') => {
                let buf = self.current_buffer_mut();
                if buf.cx > 0 {
                    buf.cx -= 1;
                    self.redraw_target = RedrawTarget::StatusOnly;
                }
            }
            Key::Char('l') => {
                let buf = self.current_buffer_mut();
                if buf.cy < buf.lines.len() {
                    let len = buf.lines[buf.cy].chars.len();
                    let limit = if len == 0 { 0 } else { len - 1 };
                    if buf.cx < limit {
                        buf.cx += 1;
                        self.redraw_target = RedrawTarget::StatusOnly;
                    }
                }
            }
            Key::Char('k') | Key::Up => {
                let buf = self.current_buffer_mut();
                if buf.cy > 0 {
                    buf.cy -= 1;
                    self.adjust_cx_to_line_limit();
                    self.redraw_target = RedrawTarget::StatusOnly;
                }
            }
            Key::Char('j') | Key::Down => {
                let buf = self.current_buffer_mut();
                if buf.cy + 1 < buf.lines.len() {
                    buf.cy += 1;
                    self.adjust_cx_to_line_limit();
                    self.redraw_target = RedrawTarget::StatusOnly;
                }
            }

            // Arrow keys in Normal Mode switch buffers!
            Key::Left => {
                self.switch_to_prev_buffer(false);
            }
            Key::Right => {
                self.switch_to_next_buffer(false);
            }

            // Word/Line Bounds
            Key::Char('0') => {
                let buf = self.current_buffer_mut();
                buf.cx = 0;
                self.redraw_target = RedrawTarget::StatusOnly;
            }
            Key::Char('$') => {
                let buf = self.current_buffer_mut();
                if buf.cy < buf.lines.len() {
                    let len = buf.lines[buf.cy].chars.len();
                    buf.cx = if len > 0 { len - 1 } else { 0 };
                    self.redraw_target = RedrawTarget::StatusOnly;
                }
            }
            Key::Char('g') => {
                let buf = self.current_buffer_mut();
                buf.cy = 0;
                buf.cx = 0;
                self.redraw_target = RedrawTarget::Everything;
            }
            Key::Char('G') => {
                let buf = self.current_buffer_mut();
                if !buf.lines.is_empty() {
                    buf.cy = buf.lines.len() - 1;
                    buf.cx = 0;
                    self.redraw_target = RedrawTarget::Everything;
                }
            }

            // Page scrolling (Ctrl-F, Ctrl-B, PageUp, PageDown)
            Key::Ctrl('f') | Key::PageDown => {
                self.page_scroll_down();
            }
            Key::Ctrl('b') | Key::PageUp => {
                self.page_scroll_up();
            }

            Key::Char('J') => {
                self.join_lines();
            }

            // Deletions
            Key::Char('x') | Key::Delete => {
                let (cy, redraw) = {
                    let buf = self.current_buffer_mut();
                    if buf.cy < buf.lines.len() && !buf.lines[buf.cy].chars.is_empty() {
                        buf.lines[buf.cy].chars.remove(buf.cx);
                        buf.dirty = true;
                        let len = buf.lines[buf.cy].chars.len();
                        if buf.cx >= len && buf.cx > 0 {
                            buf.cx -= 1;
                        }
                        (Some(buf.cy), Some(RedrawTarget::Line(buf.cy)))
                    } else {
                        (None, None)
                    }
                };
                if let Some(target) = redraw {
                    self.redraw_target = target;
                }
                if let Some(row) = cy {
                    self.highlight_buffer_from(row, false);
                }
            }

            // Open line
            Key::Char('o') => {
                let cy = {
                    let buf = self.current_buffer_mut();
                    buf.lines.insert(buf.cy + 1, Line::new(""));
                    buf.cy += 1;
                    buf.cx = 0;
                    buf.dirty = true;
                    buf.cy
                };
                self.mode = Mode::Insert;
                self.set_status("-- INSERT --");
                self.redraw_target = RedrawTarget::FromLine(cy);
                self.highlight_buffer_from(cy, false);
            }
            Key::Char('O') => {
                let cy = {
                    let buf = self.current_buffer_mut();
                    buf.lines.insert(buf.cy, Line::new(""));
                    buf.cx = 0;
                    buf.dirty = true;
                    buf.cy
                };
                self.mode = Mode::Insert;
                self.set_status("-- INSERT --");
                self.redraw_target = RedrawTarget::FromLine(cy);
                self.highlight_buffer_from(cy, false);
            }

            _ => {}
        }
    }

    pub fn get_selection_range(&self) -> Option<((usize, usize), (usize, usize))> {
        match self.mode {
            Mode::VisualChar | Mode::VisualLine => {
                let buf = self.current_buffer();
                let p1 = (self.visual_anchor_x, self.visual_anchor_y);
                let p2 = (buf.cx, buf.cy);
                if p1.1 < p2.1 || (p1.1 == p2.1 && p1.0 <= p2.0) {
                    Some((p1, p2))
                } else {
                    Some((p2, p1))
                }
            }
            _ => None,
        }
    }

    fn yank_selection(&mut self) {
        if let Some((start, end)) = self.get_selection_range() {
            let is_line_wise = self.mode == Mode::VisualLine;
            let buf = self.current_buffer();

            let content = if is_line_wise {
                let mut yanked_lines = Vec::new();
                for y in start.1..=end.1 {
                    let line_str: String = buf.lines[y].chars.iter().collect();
                    yanked_lines.push(line_str);
                }
                self.set_status(&format!("{} lines yanked", yanked_lines.len()));
                yanked_lines.join("\n")
            } else {
                let text = if start.1 == end.1 {
                    let line = &buf.lines[start.1];
                    let selected_chars = &line.chars[start.0..=std::cmp::min(end.0, line.chars.len() - 1)];
                    selected_chars.iter().collect::<String>()
                } else {
                    let mut selected_parts = Vec::new();

                    let first_line = &buf.lines[start.1];
                    if start.0 < first_line.chars.len() {
                        let part: String = first_line.chars[start.0..].iter().collect();
                        selected_parts.push(part);
                    } else {
                        selected_parts.push(String::new());
                    }

                    for y in (start.1 + 1)..end.1 {
                        let part: String = buf.lines[y].chars.iter().collect();
                        selected_parts.push(part);
                    }

                    let last_line = &buf.lines[end.1];
                    let limit = std::cmp::min(end.0 + 1, last_line.chars.len());
                    let part: String = last_line.chars[..limit].iter().collect();
                    selected_parts.push(part);

                    selected_parts.join("\n")
                };
                self.set_status(&format!("{} characters yanked", text.len()));
                text
            };

            self.clipboard = Clipboard {
                content,
                is_line_wise,
            };
        }
    }

    fn delete_selection(&mut self) {
        if let Some((start, end)) = self.get_selection_range() {
            self.yank_selection();

            let is_line_wise = self.mode == Mode::VisualLine;
            let buf = self.current_buffer_mut();

            if is_line_wise {
                let num_to_remove = end.1 - start.1 + 1;
                for _ in 0..num_to_remove {
                    buf.lines.remove(start.1);
                }
                if buf.lines.is_empty() {
                    buf.lines.push(Line::new(""));
                }
                buf.cy = std::cmp::min(start.1, buf.lines.len() - 1);
                buf.cx = 0;
            } else {
                if start.1 == end.1 {
                    let line = &mut buf.lines[start.1];
                    let remove_limit = std::cmp::min(end.0 + 1, line.chars.len());
                    line.chars.drain(start.0..remove_limit);
                    buf.cy = start.1;
                    buf.cx = std::cmp::min(start.0, line.chars.len().saturating_sub(1));
                } else {
                    let first_chars = buf.lines[start.1].chars.clone();
                    let last_chars = buf.lines[end.1].chars.clone();

                    let left = &first_chars[..start.0];
                    let limit = std::cmp::min(end.0 + 1, last_chars.len());
                    let right = &last_chars[limit..];

                    let mut merged_chars = left.to_vec();
                    merged_chars.extend(right.to_vec());

                    let num_to_remove = end.1 - start.1 + 1;
                    for _ in 0..num_to_remove {
                        buf.lines.remove(start.1);
                    }

                    buf.lines.insert(start.1, Line {
                        chars: merged_chars,
                        highlights: Vec::new(),
                        end_state: LexerState::Normal,
                    });

                    buf.cy = start.1;
                    buf.cx = std::cmp::min(start.0, buf.lines[buf.cy].chars.len().saturating_sub(1));
                }
            }

            buf.dirty = true;
            self.set_status("Selection deleted");

            let start_row = start.1;
            self.highlight_buffer_from(start_row, false);
        }
    }

    fn paste_char_wise(&mut self, content: &str) {
        let (redraw_target, paste_row) = {
            let buf = self.current_buffer_mut();
            if buf.lines.is_empty() {
                buf.lines.push(Line::new(""));
            }
            let paste_row = buf.cy;
            let current_line = &mut buf.lines[buf.cy];
            let paste_idx = if current_line.chars.is_empty() {
                0
            } else {
                std::cmp::min(buf.cx + 1, current_line.chars.len())
            };

            let parts: Vec<&str> = content.split('\n').collect();
            let redraw = if parts.len() == 1 {
                let chs: Vec<char> = parts[0].chars().collect();
                for (i, ch) in chs.into_iter().enumerate() {
                    buf.lines[buf.cy].chars.insert(paste_idx + i, ch);
                }
                buf.cx += parts[0].chars().count();
                RedrawTarget::Line(buf.cy)
            } else {
                let current_chars = buf.lines[buf.cy].chars.clone();
                let (left, right) = current_chars.split_at(paste_idx);

                buf.lines[buf.cy].chars = left.to_vec();
                buf.lines[buf.cy].chars.extend(parts[0].chars());

                for i in 1..(parts.len() - 1) {
                    buf.lines.insert(buf.cy + i, Line::new(parts[i]));
                }

                let last_idx = buf.cy + parts.len() - 1;
                let mut last_line_chars: Vec<char> = parts[parts.len() - 1].chars().collect();
                last_line_chars.extend(right.to_vec());
                let len = last_line_chars.len();
                buf.lines.insert(last_idx, Line {
                    chars: last_line_chars,
                    highlights: vec![HighlightType::Normal; len],
                    end_state: LexerState::Normal,
                });

                buf.cy = last_idx;
                buf.cx = parts[parts.len() - 1].chars().count();
                RedrawTarget::FromLine(buf.cy - parts.len() + 1)
            };
            buf.dirty = true;
            (redraw, paste_row)
        };
        self.redraw_target = redraw_target;
        self.highlight_buffer_from(paste_row, false);
    }

    fn paste_line_wise(&mut self, content: &str) {
        let (insert_row, _num_parts) = {
            let buf = self.current_buffer_mut();
            let parts: Vec<&str> = content.split('\n').collect();
            let insert_row = buf.cy + 1;

            for (i, part) in parts.iter().enumerate() {
                buf.lines.insert(insert_row + i, Line::new(part));
            }

            buf.cy = insert_row;
            buf.cx = 0;
            buf.dirty = true;
            self.redraw_target = RedrawTarget::FromLine(buf.cy - 1);
            (insert_row, parts.len())
        };
        self.highlight_buffer_from(insert_row, false);
    }

    pub fn page_scroll_down(&mut self) {
        let screen_rows = self.screen_rows;
        {
            let buf = self.current_buffer_mut();
            if buf.lines.is_empty() {
                return;
            }
            buf.row_offset = buf.row_offset.saturating_add(screen_rows);
            let max_offset = buf.lines.len().saturating_sub(screen_rows);
            if buf.row_offset > max_offset {
                buf.row_offset = max_offset;
            }

            buf.cy = buf.cy.saturating_add(screen_rows);
            if buf.cy >= buf.lines.len() {
                buf.cy = buf.lines.len() - 1;
            }

            if buf.cy < buf.row_offset {
                buf.cy = buf.row_offset;
            }
            let screen_end = buf.row_offset + screen_rows;
            if buf.cy >= screen_end {
                buf.cy = screen_end.saturating_sub(1);
            }
        }
        self.adjust_cx_to_line_limit();
        self.redraw_target = RedrawTarget::Everything;
    }

    pub fn page_scroll_up(&mut self) {
        let screen_rows = self.screen_rows;
        {
            let buf = self.current_buffer_mut();
            if buf.lines.is_empty() {
                return;
            }
            buf.row_offset = buf.row_offset.saturating_sub(screen_rows);
            buf.cy = buf.cy.saturating_sub(screen_rows);

            if buf.cy < buf.row_offset {
                buf.cy = buf.row_offset;
            }
            let screen_end = buf.row_offset + screen_rows;
            if buf.cy >= screen_end {
                buf.cy = screen_end.saturating_sub(1);
            }
        }
        self.adjust_cx_to_line_limit();
        self.redraw_target = RedrawTarget::Everything;
    }

    fn process_visual_key(&mut self, key: Key) {
        match key {
            Key::Esc => {
                self.mode = Mode::Normal;
                self.redraw_target = RedrawTarget::Everything;
                self.set_status("");
            }
            Key::Char('y') => {
                self.yank_selection();
                self.mode = Mode::Normal;
                self.redraw_target = RedrawTarget::Everything;
            }
            Key::Char('d') | Key::Char('x') | Key::Delete => {
                self.delete_selection();
                self.mode = Mode::Normal;
                self.redraw_target = RedrawTarget::Everything;
            }

            Key::Char('h') | Key::Left => {
                let buf = self.current_buffer_mut();
                if buf.cx > 0 {
                    buf.cx -= 1;
                    self.redraw_target = RedrawTarget::Everything;
                }
            }
            Key::Char('l') | Key::Right => {
                let buf = self.current_buffer_mut();
                if buf.cy < buf.lines.len() {
                    let len = buf.lines[buf.cy].chars.len();
                    let limit = if len == 0 { 0 } else { len - 1 };
                    if buf.cx < limit {
                        buf.cx += 1;
                        self.redraw_target = RedrawTarget::Everything;
                    }
                }
            }
            Key::Char('k') | Key::Up => {
                let buf = self.current_buffer_mut();
                if buf.cy > 0 {
                    buf.cy -= 1;
                    self.adjust_cx_to_line_limit();
                    self.redraw_target = RedrawTarget::Everything;
                }
            }
            Key::Char('j') | Key::Down => {
                let buf = self.current_buffer_mut();
                if buf.cy + 1 < buf.lines.len() {
                    buf.cy += 1;
                    self.adjust_cx_to_line_limit();
                    self.redraw_target = RedrawTarget::Everything;
                }
            }
            Key::Char('0') => {
                let buf = self.current_buffer_mut();
                buf.cx = 0;
                self.redraw_target = RedrawTarget::Everything;
            }
            Key::Char('$') => {
                let buf = self.current_buffer_mut();
                if buf.cy < buf.lines.len() {
                    let len = buf.lines[buf.cy].chars.len();
                    buf.cx = if len > 0 { len - 1 } else { 0 };
                    self.redraw_target = RedrawTarget::Everything;
                }
            }
            Key::Char('g') => {
                let buf = self.current_buffer_mut();
                buf.cy = 0;
                buf.cx = 0;
                self.redraw_target = RedrawTarget::Everything;
            }
            Key::Char('G') => {
                let buf = self.current_buffer_mut();
                if !buf.lines.is_empty() {
                    buf.cy = buf.lines.len() - 1;
                    buf.cx = 0;
                    self.redraw_target = RedrawTarget::Everything;
                }
            }
            Key::Ctrl('f') | Key::PageDown => {
                self.page_scroll_down();
            }
            Key::Ctrl('b') | Key::PageUp => {
                self.page_scroll_up();
            }
            _ => {}
        }
    }

    fn adjust_cx_to_line_limit(&mut self) {
        let buf = self.current_buffer_mut();
        if buf.cy < buf.lines.len() {
            let len = buf.lines[buf.cy].chars.len();
            let limit = if len == 0 { 0 } else { len - 1 };
            if buf.cx > limit {
                buf.cx = limit;
            }
        }
    }

    fn adjust_cx_to_line_limit_insert(&mut self) {
        let buf = self.current_buffer_mut();
        if buf.cy < buf.lines.len() {
            let len = buf.lines[buf.cy].chars.len();
            if buf.cx > len {
                buf.cx = len;
            }
        }
    }

    fn process_insert_key(&mut self, key: Key) {
        match key {
            Key::Esc => {
                self.mode = Mode::Normal;
                let buf = self.current_buffer_mut();
                if buf.cx > 0 {
                    let len = buf.lines[buf.cy].chars.len();
                    if buf.cx >= len {
                        buf.cx = len - 1;
                    }
                }
                self.set_status("");
            }
            Key::Char(ch) => {
                let (cy, redraw) = {
                    let buf = self.current_buffer_mut();
                    if buf.cy < buf.lines.len() {
                        buf.lines[buf.cy].chars.insert(buf.cx, ch);
                        buf.cx += 1;
                        buf.dirty = true;
                        (Some(buf.cy), Some(RedrawTarget::Line(buf.cy)))
                    } else {
                        (None, None)
                    }
                };
                if let Some(target) = redraw {
                    self.redraw_target = target;
                }
                if let Some(row) = cy {
                    self.highlight_buffer_from(row, false);
                }
            }
            Key::Backspace => {
                let (highlight_row, redraw) = {
                    let buf = self.current_buffer_mut();
                    if buf.cx > 0 {
                        buf.cx -= 1;
                        buf.lines[buf.cy].chars.remove(buf.cx);
                        buf.dirty = true;
                        (Some(buf.cy), Some(RedrawTarget::Line(buf.cy)))
                    } else if buf.cy > 0 {
                        let prev_row = buf.cy - 1;
                        let current_line_chars = buf.lines[buf.cy].chars.clone();
                        let prev_line_len = buf.lines[prev_row].chars.len();

                        buf.lines[prev_row].chars.extend(current_line_chars);
                        buf.lines.remove(buf.cy);

                        buf.cy = prev_row;
                        buf.cx = prev_line_len;
                        buf.dirty = true;
                        (Some(buf.cy), Some(RedrawTarget::FromLine(buf.cy)))
                    } else {
                        (None, None)
                    }
                };
                if let Some(target) = redraw {
                    self.redraw_target = target;
                }
                if let Some(row) = highlight_row {
                    self.highlight_buffer_from(row, false);
                }
            }
            Key::Delete => {
                let (highlight_row, redraw) = {
                    let buf = self.current_buffer_mut();
                    if buf.cx < buf.lines[buf.cy].chars.len() {
                        buf.lines[buf.cy].chars.remove(buf.cx);
                        buf.dirty = true;
                        (Some(buf.cy), Some(RedrawTarget::Line(buf.cy)))
                    } else if buf.cy + 1 < buf.lines.len() {
                        let next_chars = buf.lines[buf.cy + 1].chars.clone();
                        buf.lines[buf.cy].chars.extend(next_chars);
                        buf.lines.remove(buf.cy + 1);
                        buf.dirty = true;
                        (Some(buf.cy), Some(RedrawTarget::FromLine(buf.cy)))
                    } else {
                        (None, None)
                    }
                };
                if let Some(target) = redraw {
                    self.redraw_target = target;
                }
                if let Some(row) = highlight_row {
                    self.highlight_buffer_from(row, false);
                }
            }
            Key::Enter => {
                let highlight_row = {
                    let buf = self.current_buffer_mut();
                    let current_line_chars = buf.lines[buf.cy].chars.clone();
                    let (left, right) = current_line_chars.split_at(buf.cx);

                    buf.lines[buf.cy].chars = left.to_vec();
                    buf.lines.insert(buf.cy + 1, Line {
                        chars: right.to_vec(),
                        highlights: vec![HighlightType::Normal; right.len()],
                        end_state: LexerState::Normal,
                    });

                    let original_cy = buf.cy;
                    buf.cy += 1;
                    buf.cx = 0;
                    buf.dirty = true;
                    self.redraw_target = RedrawTarget::FromLine(original_cy);
                    original_cy
                };
                self.highlight_buffer_from(highlight_row, false);
            }
            Key::Tab => {
                let (cy, redraw) = {
                    let (tab_stop, expandtab) = (self.config.tabstop, self.config.expandtab);
                    let buf = self.current_buffer_mut();
                    if buf.cy < buf.lines.len() {
                        if expandtab {
                            // Fill to the next tab stop, as vim does: with
                            // tabstop=4, Tab at column 2 inserts 2 spaces, not 4.
                            let rx = buf.lines[buf.cy].display_width_to(buf.cx, tab_stop);
                            for _ in 0..(tab_stop - (rx % tab_stop)) {
                                buf.lines[buf.cy].chars.insert(buf.cx, ' ');
                                buf.cx += 1;
                            }
                        } else {
                            buf.lines[buf.cy].chars.insert(buf.cx, '\t');
                            buf.cx += 1;
                        }
                        buf.dirty = true;
                        (Some(buf.cy), Some(RedrawTarget::Line(buf.cy)))
                    } else {
                        (None, None)
                    }
                };
                if let Some(target) = redraw {
                    self.redraw_target = target;
                }
                if let Some(row) = cy {
                    self.highlight_buffer_from(row, false);
                }
            }
            Key::Left => {
                let buf = self.current_buffer_mut();
                if buf.cx > 0 {
                    buf.cx -= 1;
                    self.redraw_target = RedrawTarget::StatusOnly;
                }
            }
            Key::Right => {
                let buf = self.current_buffer_mut();
                if buf.cy < buf.lines.len() {
                    let len = buf.lines[buf.cy].chars.len();
                    if buf.cx < len {
                        buf.cx += 1;
                        self.redraw_target = RedrawTarget::StatusOnly;
                    }
                }
            }
            Key::Up => {
                let buf = self.current_buffer_mut();
                if buf.cy > 0 {
                    buf.cy -= 1;
                    self.adjust_cx_to_line_limit_insert();
                    self.redraw_target = RedrawTarget::StatusOnly;
                }
            }
            Key::Down => {
                let buf = self.current_buffer_mut();
                if buf.cy + 1 < buf.lines.len() {
                    buf.cy += 1;
                    self.adjust_cx_to_line_limit_insert();
                    self.redraw_target = RedrawTarget::StatusOnly;
                }
            }
            _ => {}
        }
    }

    fn process_command_key(&mut self, key: Key) {
        match key {
            Key::Esc => {
                self.mode = Mode::Normal;
                self.command_buffer.clear();
                self.redraw_target = RedrawTarget::StatusOnly;
            }
            Key::Char(ch) => {
                self.command_buffer.push(ch);
                self.redraw_target = RedrawTarget::StatusOnly;
            }
            Key::Backspace => {
                if !self.command_buffer.is_empty() {
                    self.command_buffer.pop();
                    self.redraw_target = RedrawTarget::StatusOnly;
                } else {
                    self.mode = Mode::Normal;
                    self.redraw_target = RedrawTarget::StatusOnly;
                }
            }
            Key::Enter => {
                let cmd = self.command_buffer.clone();
                self.execute_command(&cmd);
                if self.mode == Mode::Command {
                    self.mode = Mode::Normal;
                }
                self.command_buffer.clear();
                self.redraw_target = RedrawTarget::Everything;
            }
            _ => {}
        }
    }

    fn join_lines(&mut self) {
        let (cy, next_row, first_non_ws, insert_space, junction_idx, appended_len) = {
            let buf = self.current_buffer();
            if buf.cy + 1 >= buf.lines.len() {
                return;
            }

            let next_row = buf.cy + 1;
            let line2_chars = &buf.lines[next_row].chars;

            let mut first_non_ws = 0;
            while first_non_ws < line2_chars.len() && (line2_chars[first_non_ws] == ' ' || line2_chars[first_non_ws] == '\t') {
                first_non_ws += 1;
            }

            let line1 = &buf.lines[buf.cy];
            let line2_remaining_len = line2_chars.len() - first_non_ws;

            let insert_space = if !line1.chars.is_empty()
                && line2_remaining_len > 0
                && *line1.chars.last().unwrap() != ' '
                && *line1.chars.last().unwrap() != '\t'
            {
                true
            } else {
                false
            };

            (buf.cy, next_row, first_non_ws, insert_space, line1.chars.len(), line2_remaining_len)
        };

        // Mutate the buffer line
        {
            let next_row_chars = self.buffers[self.current_buffer_idx].lines[next_row].chars.clone();
            let line2_trimmed = &next_row_chars[first_non_ws..];

            let line1 = &mut self.buffers[self.current_buffer_idx].lines[cy];
            if insert_space {
                line1.chars.push(' ');
            }
            line1.chars.extend_from_slice(line2_trimmed);
        }

        // Remove the joined line
        self.buffers[self.current_buffer_idx].lines.remove(next_row);

        // Update cursor positions on the buffer
        let new_len = junction_idx + (if insert_space { 1 } else { 0 }) + appended_len;
        let final_buf = self.current_buffer_mut();
        final_buf.cx = std::cmp::min(junction_idx, new_len.saturating_sub(1));
        final_buf.dirty = true;

        self.redraw_target = RedrawTarget::FromLine(final_buf.cy);
        self.highlight_buffer_from(cy, false);
    }

    // --- Search Mode Helper Actions ---

    fn process_search_key(&mut self, key: Key) {
        match key {
            Key::Esc => {
                self.mode = Mode::Normal;
                self.command_buffer.clear();
                self.redraw_target = RedrawTarget::StatusOnly;
            }
            Key::Char(ch) => {
                self.command_buffer.push(ch);
                self.redraw_target = RedrawTarget::StatusOnly;
            }
            Key::Backspace => {
                if !self.command_buffer.is_empty() {
                    self.command_buffer.pop();
                    self.redraw_target = RedrawTarget::StatusOnly;
                } else {
                    self.mode = Mode::Normal;
                    self.redraw_target = RedrawTarget::StatusOnly;
                }
            }
            Key::Enter => {
                let query = self.command_buffer.clone();
                self.execute_search(&query);
                self.mode = Mode::Normal;
                self.command_buffer.clear();
                self.redraw_target = RedrawTarget::Everything;
            }
            _ => {}
        }
    }

    fn execute_search(&mut self, query: &str) {
        if query.is_empty() {
            return;
        }
        self.search_query = query.to_string();
        self.search_matches.clear();
        self.current_match_idx = None;

        // Split borrow: borrow self.buffers directly to avoid conflict with self.search_matches
        let lines = &self.buffers[self.current_buffer_idx].lines;
        for r in 0..lines.len() {
            let line_str: String = lines[r].chars.iter().collect();
            let mut start = 0;
            while let Some(idx) = line_str[start..].find(query) {
                let actual_col = start + idx;
                self.search_matches.push((r, actual_col));
                start = actual_col + std::cmp::max(1, query.len());
            }
        }

        if self.search_matches.is_empty() {
            self.set_status(&format!("Pattern not found: {}", query));
            return;
        }

        let cursor_y = self.buffers[self.current_buffer_idx].cy;
        let cursor_x = self.buffers[self.current_buffer_idx].cx;
        
        let idx = if self.search_backward {
            // Find the last match at or before the cursor
            let mut target_idx = None;
            for (i, &(r, c)) in self.search_matches.iter().enumerate().rev() {
                if r < cursor_y || (r == cursor_y && c <= cursor_x) {
                    target_idx = Some(i);
                    break;
                }
            }
            target_idx.unwrap_or(self.search_matches.len() - 1) // Wrap to bottom
        } else {
            // Find the first match at or after the cursor
            let mut target_idx = None;
            for (i, &(r, c)) in self.search_matches.iter().enumerate() {
                if r > cursor_y || (r == cursor_y && c >= cursor_x) {
                    target_idx = Some(i);
                    break;
                }
            }
            target_idx.unwrap_or(0) // Wrap to top
        };

        self.current_match_idx = Some(idx);

        let (target_row, target_col) = self.search_matches[idx];
        let final_buf = &mut self.buffers[self.current_buffer_idx];
        final_buf.cy = target_row;
        final_buf.cx = target_col;
        self.redraw_target = RedrawTarget::Everything;
        self.set_status(&format!("Found match {} of {}", idx + 1, self.search_matches.len()));
    }

    fn jump_to_next_match(&mut self) {
        let query = self.search_query.clone();
        self.search_matches.clear();

        // Split borrow: borrow self.buffers directly
        let lines = &self.buffers[self.current_buffer_idx].lines;
        for r in 0..lines.len() {
            let line_str: String = lines[r].chars.iter().collect();
            let mut start = 0;
            while let Some(idx) = line_str[start..].find(&query) {
                let actual_col = start + idx;
                self.search_matches.push((r, actual_col));
                start = actual_col + std::cmp::max(1, query.len());
            }
        }

        if self.search_matches.is_empty() {
            self.set_status(&format!("Pattern not found: {}", query));
            return;
        }

        let cursor_y = self.buffers[self.current_buffer_idx].cy;
        let cursor_x = self.buffers[self.current_buffer_idx].cx;

        let idx = if self.search_backward {
            // Jump backward: find last match strictly before cursor
            let mut target_idx = None;
            for (i, &(r, c)) in self.search_matches.iter().enumerate().rev() {
                if r < cursor_y || (r == cursor_y && c < cursor_x) {
                    target_idx = Some(i);
                    break;
                }
            }
            target_idx.unwrap_or(self.search_matches.len() - 1) // Wrap to bottom
        } else {
            // Jump forward: find first match strictly after cursor
            let mut target_idx = None;
            for (i, &(r, c)) in self.search_matches.iter().enumerate() {
                if r > cursor_y || (r == cursor_y && c > cursor_x) {
                    target_idx = Some(i);
                    break;
                }
            }
            target_idx.unwrap_or(0) // Wrap to top
        };

        self.current_match_idx = Some(idx);

        let (target_row, target_col) = self.search_matches[idx];
        let final_buf = &mut self.buffers[self.current_buffer_idx];
        final_buf.cy = target_row;
        final_buf.cx = target_col;
        self.redraw_target = RedrawTarget::Everything;
        self.set_status(&format!("Found match {} of {}", idx + 1, self.search_matches.len()));
    }

    fn jump_to_prev_match(&mut self) {
        let query = self.search_query.clone();
        self.search_matches.clear();

        // Split borrow: borrow self.buffers directly
        let lines = &self.buffers[self.current_buffer_idx].lines;
        for r in 0..lines.len() {
            let line_str: String = lines[r].chars.iter().collect();
            let mut start = 0;
            while let Some(idx) = line_str[start..].find(&query) {
                let actual_col = start + idx;
                self.search_matches.push((r, actual_col));
                start = actual_col + std::cmp::max(1, query.len());
            }
        }

        if self.search_matches.is_empty() {
            self.set_status(&format!("Pattern not found: {}", query));
            return;
        }

        let cursor_y = self.buffers[self.current_buffer_idx].cy;
        let cursor_x = self.buffers[self.current_buffer_idx].cx;

        let idx = if self.search_backward {
            // Jump forward: find first match strictly after cursor
            let mut target_idx = None;
            for (i, &(r, c)) in self.search_matches.iter().enumerate() {
                if r > cursor_y || (r == cursor_y && c > cursor_x) {
                    target_idx = Some(i);
                    break;
                }
            }
            target_idx.unwrap_or(0) // Wrap to top
        } else {
            // Jump backward: find last match strictly before cursor
            let mut target_idx = None;
            for (i, &(r, c)) in self.search_matches.iter().enumerate().rev() {
                if r < cursor_y || (r == cursor_y && c < cursor_x) {
                    target_idx = Some(i);
                    break;
                }
            }
            target_idx.unwrap_or(self.search_matches.len() - 1) // Wrap to bottom
        };

        self.current_match_idx = Some(idx);

        let (target_row, target_col) = self.search_matches[idx];
        let final_buf = &mut self.buffers[self.current_buffer_idx];
        final_buf.cy = target_row;
        final_buf.cx = target_col;
        self.redraw_target = RedrawTarget::Everything;
        self.set_status(&format!("Found match {} of {}", idx + 1, self.search_matches.len()));
    }

    // --- Buffer Management Actions ---

    fn switch_to_next_buffer(&mut self, force: bool) {
        if self.buffers.len() <= 1 {
            self.set_status("No other buffers");
            return;
        }
        if !force && self.current_buffer().dirty {
            self.set_status("No write since last change (add ! to override)");
            return;
        }
        self.current_buffer_idx = (self.current_buffer_idx + 1) % self.buffers.len();
        self.redraw_target = RedrawTarget::Everything;
        let name = self.current_buffer().filename.as_deref().unwrap_or("[No Name]");
        self.set_status(&format!("Switched to buffer [{}]: {}", self.current_buffer().id, name));
    }

    fn switch_to_prev_buffer(&mut self, force: bool) {
        if self.buffers.len() <= 1 {
            self.set_status("No other buffers");
            return;
        }
        if !force && self.current_buffer().dirty {
            self.set_status("No write since last change (add ! to override)");
            return;
        }
        if self.current_buffer_idx == 0 {
            self.current_buffer_idx = self.buffers.len() - 1;
        } else {
            self.current_buffer_idx -= 1;
        }
        self.redraw_target = RedrawTarget::Everything;
        let name = self.current_buffer().filename.as_deref().unwrap_or("[No Name]");
        self.set_status(&format!("Switched to buffer [{}]: {}", self.current_buffer().id, name));
    }

    fn switch_to_buffer_by_id(&mut self, id: usize, force: bool) {
        if !force && self.current_buffer().dirty {
            self.set_status("No write since last change (add ! to override)");
            return;
        }
        if let Some(pos) = self.buffers.iter().position(|b| b.id == id) {
            self.current_buffer_idx = pos;
            self.redraw_target = RedrawTarget::Everything;
            let name = self.current_buffer().filename.as_deref().unwrap_or("[No Name]");
            self.set_status(&format!("Switched to buffer [{}]: {}", id, name));
        } else {
            self.set_status(&format!("Buffer {} not found", id));
        }
    }

    fn switch_to_buffer_by_name(&mut self, name: &str, force: bool) {
        if !force && self.current_buffer().dirty {
            self.set_status("No write since last change (add ! to override)");
            return;
        }
        if let Some(pos) = self.buffers.iter().position(|b| {
            b.filename.as_ref().map_or(false, |f| f.contains(name) || f.ends_with(name))
        }) {
            self.current_buffer_idx = pos;
            self.redraw_target = RedrawTarget::Everything;
            let actual_name = self.current_buffer().filename.as_deref().unwrap_or("[No Name]");
            self.set_status(&format!("Switched to buffer [{}]: {}", self.current_buffer().id, actual_name));
        } else {
            self.set_status(&format!("No buffer matching: {}", name));
        }
    }

    fn delete_current_buffer(&mut self, force: bool) {
        if !force && self.current_buffer().dirty {
            self.set_status("No write since last change (add ! to override)");
            return;
        }

        let id_removed = self.current_buffer().id;

        if self.buffers.len() == 1 {
            self.buffers[0] = Buffer::new(self.next_buffer_id, None);
            self.next_buffer_id += 1;
            self.current_buffer_idx = 0;
            self.set_status("Buffer closed, opened empty buffer");
        } else {
            self.buffers.remove(self.current_buffer_idx);
            if self.current_buffer_idx >= self.buffers.len() {
                self.current_buffer_idx = self.buffers.len() - 1;
            }
            self.set_status(&format!("Buffer [{}] closed", id_removed));
        }
        self.redraw_target = RedrawTarget::Everything;
    }

    fn load_file_into_new_buffer(&mut self, filename: String) {
        if let Some(pos) = self.buffers.iter().position(|b| {
            b.filename.as_ref().map_or(false, |f| f == &filename)
        }) {
            self.current_buffer_idx = pos;
            self.redraw_target = RedrawTarget::Everything;
            self.set_status(&format!("Buffer already loaded, switched to [{}]", self.buffers[pos].id));
            return;
        }

        let new_buf = Buffer::new(self.next_buffer_id, Some(filename.clone()));
        self.next_buffer_id += 1;
        self.buffers.push(new_buf);
        self.current_buffer_idx = self.buffers.len() - 1;
        self.redraw_target = RedrawTarget::Everything;
        self.set_status(&format!("Opened buffer [{}]: {}", self.current_buffer().id, filename));
        
        self.highlight_buffer_from(0, true);
    }

    fn list_buffers(&mut self) {
        let mut parts = Vec::new();
        let active_id = self.current_buffer().id;
        for b in &self.buffers {
            let name = b.filename.as_deref().unwrap_or("[No Name]");
            let dirty_char = if b.dirty { "+" } else { "" };
            let active_char = if b.id == active_id { "%" } else { " " };
            parts.push(format!("{}{}: \"{}\"{}", active_char, b.id, name, dirty_char));
        }
        let msg = parts.join("  |  ");
        self.set_status(&msg);
    }

    fn execute_command(&mut self, cmd: &str) {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            return;
        }

        let mut cmd_name = parts[0];
        let mut force = false;
        if cmd_name.ends_with('!') {
            force = true;
            cmd_name = &cmd_name[..cmd_name.len() - 1];
        }

        // If the command is a line number (e.g. :10), jump to it!
        if let Ok(line_num) = cmd_name.parse::<usize>() {
            let buf = self.current_buffer_mut();
            if !buf.lines.is_empty() {
                let target_y = if line_num == 0 {
                    0
                } else {
                    std::cmp::min(line_num - 1, buf.lines.len() - 1)
                };
                buf.cy = target_y;
                buf.cx = 0;
                self.redraw_target = RedrawTarget::Everything;
                self.set_status(&format!("Jumped to line {}", target_y + 1));
            }
            return;
        }

        match cmd_name {
            "q" => {
                if !force && self.any_buffer_dirty() {
                    if self.current_buffer().dirty {
                        self.set_status("No write since last change (add ! to override)");
                    } else {
                        self.set_status("Warning: other buffers have unsaved changes (add ! to override)");
                    }
                } else {
                    self.quit_requested = true;
                }
            }
            "q!" => {
                self.quit_requested = true;
            }
            "w" => {
                if parts.len() > 1 {
                    self.save_to_file(Some(parts[1]));
                } else {
                    self.save_to_file(None);
                }
            }
            "wq" | "x" => {
                if self.save_to_file(None) {
                    self.quit_requested = true;
                }
            }
            "ls" | "buffers" | "files" => {
                self.list_buffers();
            }
            "bn" | "bnext" => {
                self.switch_to_next_buffer(force);
            }
            "bp" | "bprev" => {
                self.switch_to_prev_buffer(force);
            }
            "bd" | "bdelete" => {
                self.delete_current_buffer(force);
            }
            "b" | "buffer" => {
                if parts.len() > 1 {
                    let arg = parts[1];
                    if let Ok(id) = arg.parse::<usize>() {
                        self.switch_to_buffer_by_id(id, force);
                    } else {
                        self.switch_to_buffer_by_name(arg, force);
                    }
                } else {
                    self.set_status("Buffer name or ID required");
                }
            }
            "e" | "edit" => {
                if parts.len() > 1 {
                    self.load_file_into_new_buffer(parts[1].to_string());
                } else {
                    self.set_status("Filename required for edit");
                }
            }
            "set" => {
                if parts.len() > 1 {
                    match parts[1] {
                        "nu" | "number" => {
                            self.show_line_numbers = true;
                            self.redraw_target = RedrawTarget::Everything;
                        }
                        "nonu" | "nonumber" => {
                            self.show_line_numbers = false;
                            self.redraw_target = RedrawTarget::Everything;
                        }
                        "wrap" => {
                            self.wrap = true;
                            self.redraw_target = RedrawTarget::Everything;
                        }
                        "nowrap" => {
                            self.wrap = false;
                            self.redraw_target = RedrawTarget::Everything;
                        }
                        _ => {
                            self.set_status(&format!("Unknown option: {}", parts[1]));
                        }
                    }
                } else {
                    self.set_status("Argument required for set");
                }
            }
            _ => {
                self.set_status(&format!("Not an editor command: {}", parts[0]));
            }
        }
    }

    fn save_to_file(&mut self, alternative_filename: Option<&str>) -> bool {
        let buf = self.current_buffer_mut();
        let path_to_save = alternative_filename
            .map(|s| s.to_string())
            .or_else(|| buf.filename.clone());

        match path_to_save {
            Some(path) => {
                let content = buf.to_file_content();

                match std::fs::write(&path, content) {
                    Ok(_) => {
                        buf.dirty = false;
                        if buf.filename.is_none() {
                            buf.filename = Some(path.clone());
                        }
                        self.set_status(&format!("\"{}\" written", path));
                        true
                    }
                    Err(e) => {
                        self.set_status(&format!("Can't write file: {}", e));
                        false
                    }
                }
            }
            None => {
                self.set_status("No file name");
                false
            }
        }
    }
}

// --- Comprehensive Unit Testing ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_editor_initial_state() {
        let editor = Editor::new(Vec::new(), Config::default());
        assert_eq!(editor.buffers.len(), 1);
        let buf = editor.current_buffer();
        assert_eq!(buf.lines.len(), 1);
        assert_eq!(buf.lines[0].chars.len(), 0);
        assert_eq!(buf.cx, 0);
        assert_eq!(buf.cy, 0);
        assert_eq!(editor.mode, Mode::Normal);
        assert!(!buf.dirty);
    }

    #[test]
    fn test_insert_mode_typing() {
        let mut editor = Editor::new(Vec::new(), Config::default());
        editor.process_keypress(Key::Char('i'));
        assert_eq!(editor.mode, Mode::Insert);

        for ch in "hello".chars() {
            editor.process_keypress(Key::Char(ch));
        }

        let buf = editor.current_buffer();
        let line_content: String = buf.lines[0].chars.iter().collect();
        assert_eq!(line_content, "hello");
        assert_eq!(buf.cx, 5);
        assert!(buf.dirty);
    }

    #[test]
    fn test_backspace() {
        let mut editor = Editor::new(Vec::new(), Config::default());
        editor.process_keypress(Key::Char('i'));
        for ch in "hello".chars() {
            editor.process_keypress(Key::Char(ch));
        }

        editor.process_keypress(Key::Backspace);
        let buf = editor.current_buffer();
        let line_content: String = buf.lines[0].chars.iter().collect();
        assert_eq!(line_content, "hell");
        assert_eq!(buf.cx, 4);
    }

    #[test]
    fn test_enter_splits_lines() {
        let mut editor = Editor::new(Vec::new(), Config::default());
        editor.process_keypress(Key::Char('i'));
        for ch in "hello".chars() {
            editor.process_keypress(Key::Char(ch));
        }

        editor.current_buffer_mut().cx = 3;
        editor.process_keypress(Key::Enter);

        let buf = editor.current_buffer();
        assert_eq!(buf.lines.len(), 2);
        let line1: String = buf.lines[0].chars.iter().collect();
        let line2: String = buf.lines[1].chars.iter().collect();
        assert_eq!(line1, "hel");
        assert_eq!(line2, "lo");
        assert_eq!(buf.cy, 1);
        assert_eq!(buf.cx, 0);
    }

    #[test]
    fn test_backspace_merges_lines() {
        let mut editor = Editor::new(Vec::new(), Config::default());
        editor.process_keypress(Key::Char('i'));
        for ch in "hello".chars() {
            editor.process_keypress(Key::Char(ch));
        }
        editor.current_buffer_mut().cx = 3;
        editor.process_keypress(Key::Enter);

        editor.process_keypress(Key::Backspace);

        let buf = editor.current_buffer();
        assert_eq!(buf.lines.len(), 1);
        let line_content: String = buf.lines[0].chars.iter().collect();
        assert_eq!(line_content, "hello");
        assert_eq!(buf.cy, 0);
        assert_eq!(buf.cx, 3);
    }

    #[test]
    fn test_normal_mode_motions() {
        let mut editor = Editor::new(Vec::new(), Config::default());
        editor.current_buffer_mut().lines = vec![
            Line::new("line one"),
            Line::new("line two"),
        ];

        let buf = editor.current_buffer();
        assert_eq!(buf.cx, 0);
        assert_eq!(buf.cy, 0);

        editor.process_keypress(Key::Char('l'));
        assert_eq!(editor.current_buffer().cx, 1);

        editor.process_keypress(Key::Char('j'));
        assert_eq!(editor.current_buffer().cy, 1);
        assert_eq!(editor.current_buffer().cx, 1);

        editor.process_keypress(Key::Char('$'));
        assert_eq!(editor.current_buffer().cx, 7);

        editor.process_keypress(Key::Char('k'));
        assert_eq!(editor.current_buffer().cy, 0);
        assert_eq!(editor.current_buffer().cx, 7);

        editor.process_keypress(Key::Char('0'));
        assert_eq!(editor.current_buffer().cx, 0);
    }

    #[test]
    fn test_page_scrolling() {
        let mut editor = Editor::new(Vec::new(), Config::default());
        editor.wrap = false; // Disable wrap to test classic page scrolling
        editor.screen_rows = 5;
        editor.current_buffer_mut().lines = (1..=20)
            .map(|i| Line::new(&format!("line {}", i)))
            .collect();
            
        assert_eq!(editor.current_buffer().cy, 0);
        assert_eq!(editor.current_buffer().row_offset, 0);
        
        editor.process_keypress(Key::Ctrl('f'));
        assert_eq!(editor.current_buffer().row_offset, 5);
        assert_eq!(editor.current_buffer().cy, 5);
        
        editor.process_keypress(Key::Ctrl('f'));
        assert_eq!(editor.current_buffer().row_offset, 10);
        assert_eq!(editor.current_buffer().cy, 10);
        
        editor.process_keypress(Key::Ctrl('b'));
        assert_eq!(editor.current_buffer().row_offset, 5);
        assert_eq!(editor.current_buffer().cy, 5);
        
        editor.process_keypress(Key::Ctrl('b'));
        assert_eq!(editor.current_buffer().row_offset, 0);
        assert_eq!(editor.current_buffer().cy, 0);
    }

    #[test]
    fn test_command_mode_transition() {
        let mut editor = Editor::new(Vec::new(), Config::default());
        assert_eq!(editor.mode, Mode::Normal);
        
        editor.process_keypress(Key::Char(':'));
        assert_eq!(editor.mode, Mode::Command);
        assert!(editor.command_buffer.is_empty());
        assert!(matches!(editor.redraw_target, RedrawTarget::StatusOnly));
    }

    #[test]
    fn test_line_numbers() {
        let mut editor = Editor::new(Vec::new(), Config::default());
        assert!(editor.show_line_numbers);
        assert_eq!(editor.get_gutter_width(), 4);

        editor.execute_command("set nonu");
        assert!(!editor.show_line_numbers);
        assert_eq!(editor.get_gutter_width(), 0);

        editor.execute_command("set nu");
        assert!(editor.show_line_numbers);
        assert_eq!(editor.get_gutter_width(), 4);

        editor.current_buffer_mut().lines = vec![Line::new(""); 105];
        assert_eq!(editor.get_gutter_width(), 4);

        editor.current_buffer_mut().lines = vec![Line::new(""); 1005];
        assert_eq!(editor.get_gutter_width(), 5);
    }

    #[test]
    fn test_visual_char_mode_yank_paste() {
        let mut editor = Editor::new(Vec::new(), Config::default());
        editor.current_buffer_mut().lines = vec![Line::new("hello world")];
        
        editor.process_keypress(Key::Char('v'));
        assert_eq!(editor.mode, Mode::VisualChar);
        assert_eq!(editor.visual_anchor_x, 0);
        assert_eq!(editor.visual_anchor_y, 0);
        
        for _ in 0..4 {
            editor.process_keypress(Key::Right);
        }
        assert_eq!(editor.current_buffer().cx, 4);
        
        editor.process_keypress(Key::Char('y'));
        assert_eq!(editor.mode, Mode::Normal);
        assert_eq!(editor.clipboard.content, "hello");
        assert!(!editor.clipboard.is_line_wise);
        
        editor.process_keypress(Key::Char('p'));
        let line_content: String = editor.current_buffer().lines[0].chars.iter().collect();
        assert_eq!(line_content, "hellohello world");
    }

    #[test]
    fn test_visual_line_mode_yank_paste() {
        let mut editor = Editor::new(Vec::new(), Config::default());
        editor.current_buffer_mut().lines = vec![
            Line::new("line one"),
            Line::new("line two"),
        ];
        
        editor.process_keypress(Key::Char('V'));
        assert_eq!(editor.mode, Mode::VisualLine);
        
        editor.process_keypress(Key::Char('y'));
        assert_eq!(editor.mode, Mode::Normal);
        assert_eq!(editor.clipboard.content, "line one");
        assert!(editor.clipboard.is_line_wise);
        
        editor.process_keypress(Key::Char('j'));
        editor.process_keypress(Key::Char('p'));
        
        assert_eq!(editor.current_buffer().lines.len(), 3);
        let line3: String = editor.current_buffer().lines[2].chars.iter().collect();
        assert_eq!(line3, "line one");
    }

    #[test]
    fn test_visual_mode_delete() {
        let mut editor = Editor::new(Vec::new(), Config::default());
        editor.current_buffer_mut().lines = vec![Line::new("hello world")];
        
        editor.process_keypress(Key::Char('v'));
        for _ in 0..5 {
            editor.process_keypress(Key::Right);
        }
        
        editor.process_keypress(Key::Char('d'));
        let line_content: String = editor.current_buffer().lines[0].chars.iter().collect();
        assert_eq!(line_content, "world");
        assert_eq!(editor.current_buffer().cx, 0);
        assert_eq!(editor.mode, Mode::Normal);
    }

    #[test]
    fn test_insert_mode_arrow_navigation() {
        let mut editor = Editor::new(Vec::new(), Config::default());
        editor.current_buffer_mut().lines = vec![
            Line::new("hello"),
            Line::new("world"),
        ];
        
        editor.process_keypress(Key::Char('i'));
        assert_eq!(editor.mode, Mode::Insert);
        assert_eq!(editor.current_buffer().cx, 0);
        assert_eq!(editor.current_buffer().cy, 0);
        
        for _ in 0..5 {
            editor.process_keypress(Key::Right);
        }
        assert_eq!(editor.current_buffer().cx, 5);
        
        editor.process_keypress(Key::Right);
        assert_eq!(editor.current_buffer().cx, 5);
        
        editor.process_keypress(Key::Down);
        assert_eq!(editor.current_buffer().cy, 1);
        assert_eq!(editor.current_buffer().cx, 5);
        
        editor.process_keypress(Key::Left);
        assert_eq!(editor.current_buffer().cx, 4);
        
        editor.process_keypress(Key::Up);
        assert_eq!(editor.current_buffer().cy, 0);
        assert_eq!(editor.current_buffer().cx, 4);
    }

    #[test]
    fn test_join_lines() {
        let mut editor = Editor::new(Vec::new(), Config::default());
        editor.current_buffer_mut().lines = vec![
            Line::new("hello"),
            Line::new("   world"),
        ];
        
        editor.process_keypress(Key::Char('J'));
        
        assert_eq!(editor.current_buffer().lines.len(), 1);
        let line_content: String = editor.current_buffer().lines[0].chars.iter().collect();
        assert_eq!(line_content, "hello world");
        assert_eq!(editor.current_buffer().cx, 5);
        assert!(editor.current_buffer().dirty);
        
        editor.current_buffer_mut().lines = vec![
            Line::new("hello "),
            Line::new("world"),
        ];
        editor.current_buffer_mut().cy = 0;
        editor.current_buffer_mut().cx = 0;
        editor.current_buffer_mut().dirty = false;
        
        editor.process_keypress(Key::Char('J'));
        let line_content2: String = editor.current_buffer().lines[0].chars.iter().collect();
        assert_eq!(line_content2, "hello world");
        assert_eq!(editor.current_buffer().cx, 6);
    }

    // --- Multi-Buffer Specific Unit Tests ---

    #[test]
    fn test_multi_buffer_switching_and_editing() {
        let mut editor = Editor::new(vec!["file1.rs".to_string(), "file2.rs".to_string()], Config::default());
        assert_eq!(editor.buffers.len(), 2);
        assert_eq!(editor.current_buffer_idx, 0);
        assert_eq!(editor.current_buffer().id, 1);
        assert_eq!(editor.current_buffer().filename.as_deref(), Some("file1.rs"));

        // Type in buffer 1
        editor.process_keypress(Key::Char('i'));
        for ch in "buffer one".chars() {
            editor.process_keypress(Key::Char(ch));
        }
        editor.process_keypress(Key::Esc);
        assert!(editor.current_buffer().dirty);

        // Try to switch without force (should fail since it's dirty!)
        editor.execute_command("bn");
        assert_eq!(editor.current_buffer_idx, 0); // Didn't switch!
        assert!(editor.status_message.contains("No write since last change"));

        // Switch WITH force
        editor.execute_command("bn!");
        assert_eq!(editor.current_buffer_idx, 1); // Switched!
        assert_eq!(editor.current_buffer().id, 2);
        assert_eq!(editor.current_buffer().filename.as_deref(), Some("file2.rs"));

        // Buffer 2 should be empty and clean
        assert_eq!(editor.current_buffer().lines[0].chars.len(), 0);
        assert!(!editor.current_buffer().dirty);

        // Edit Buffer 2
        editor.process_keypress(Key::Char('i'));
        for ch in "buffer two".chars() {
            editor.process_keypress(Key::Char(ch));
        }
        editor.process_keypress(Key::Esc);
        assert!(editor.current_buffer().dirty);

        // Switch back using ID
        editor.execute_command("b! 1");
        assert_eq!(editor.current_buffer_idx, 0);
        // Verify buffer 1 contents and cursor are preserved!
        let content1: String = editor.current_buffer().lines[0].chars.iter().collect();
        assert_eq!(content1, "buffer one");
        assert_eq!(editor.current_buffer().cx, 9);
    }

    #[test]
    fn test_buffer_deletion() {
        let mut editor = Editor::new(vec!["file1.rs".to_string(), "file2.rs".to_string()], Config::default());
        assert_eq!(editor.buffers.len(), 2);

        // Delete buffer 1 (it's clean, so it should succeed immediately)
        editor.execute_command("bd");
        assert_eq!(editor.buffers.len(), 1);
        assert_eq!(editor.current_buffer().id, 2); // Buffer 2 is now active
        assert_eq!(editor.current_buffer().filename.as_deref(), Some("file2.rs"));

        // Edit buffer 2
        editor.process_keypress(Key::Char('i'));
        editor.process_keypress(Key::Char('x'));
        editor.process_keypress(Key::Esc);

        // Try to delete dirty buffer (should fail)
        editor.execute_command("bd");
        assert_eq!(editor.buffers.len(), 1); // Still here

        // Force delete the last buffer (should open a new empty unsaved buffer)
        editor.execute_command("bd!");
        assert_eq!(editor.buffers.len(), 1);
        assert_eq!(editor.current_buffer().filename, None); // Empty unsaved buffer
        assert!(!editor.current_buffer().dirty);
    }

    #[test]
    fn test_normal_mode_arrow_buffer_switching() {
        let mut editor = Editor::new(vec!["file1.rs".to_string(), "file2.rs".to_string()], Config::default());
        assert_eq!(editor.current_buffer_idx, 0);

        // Press Right arrow in Normal Mode -> switch to next buffer
        editor.process_keypress(Key::Right);
        assert_eq!(editor.current_buffer_idx, 1);
        assert_eq!(editor.current_buffer().id, 2);

        // Press Left arrow in Normal Mode -> switch back to previous buffer
        editor.process_keypress(Key::Left);
        assert_eq!(editor.current_buffer_idx, 0);
        assert_eq!(editor.current_buffer().id, 1);
    }

    // --- Syntax Highlighting Specific Unit Test ---

    #[test]
    fn test_syntax_highlighting_rust() {
        let mut editor = Editor::new(vec!["test.rs".to_string()], Config::default());
        editor.process_keypress(Key::Char('i'));
        
        // Type a Rust keyword: "let"
        for ch in "let x = 123; // comment".chars() {
            editor.process_keypress(Key::Char(ch));
        }
        editor.process_keypress(Key::Esc);

        let buf = editor.current_buffer();
        
        // Let's verify the characters typed match their highlight types:
        // "let" -> Keyword
        assert_eq!(buf.lines[0].highlights[0], HighlightType::Keyword);
        assert_eq!(buf.lines[0].highlights[1], HighlightType::Keyword);
        assert_eq!(buf.lines[0].highlights[2], HighlightType::Keyword);
        
        // " " -> Normal
        assert_eq!(buf.lines[0].highlights[3], HighlightType::Normal);
        
        // "x" -> Normal
        assert_eq!(buf.lines[0].highlights[4], HighlightType::Normal);
        
        // "123" -> Number
        assert_eq!(buf.lines[0].highlights[8], HighlightType::Number);
        assert_eq!(buf.lines[0].highlights[9], HighlightType::Number);
        assert_eq!(buf.lines[0].highlights[10], HighlightType::Number);
        
        // "// comment" -> Comment
        assert_eq!(buf.lines[0].highlights[13], HighlightType::Comment);
        assert_eq!(buf.lines[0].highlights[17], HighlightType::Comment);
    }

    #[test]
    fn test_syntax_highlighting_rust_lifetimes() {
        let mut editor = Editor::new(vec!["test.rs".to_string()], Config::default());
        editor.process_keypress(Key::Char('i'));
        
        // Type a line containing both a lifetime and a character literal
        // "impl<'a> MyStruct { let c = 'a'; }"
        for ch in "impl<'a> MyStruct { let c = 'a'; }".chars() {
            editor.process_keypress(Key::Char(ch));
        }
        editor.process_keypress(Key::Esc);

        let buf = editor.current_buffer();
        
        // Verify lifetime 'a -> Type highlight:
        // "impl<" is index 0..5
        // "'" is index 5 -> Type
        // "a" is index 6 -> Type
        assert_eq!(buf.lines[0].highlights[5], HighlightType::Type);
        assert_eq!(buf.lines[0].highlights[6], HighlightType::Type);
        assert_eq!(buf.lines[0].highlights[7], HighlightType::Normal); // ">"

        // Verify character literal 'a' -> StringLiteral highlight:
        // "impl<'a> MyStruct { let c = " is index 0..28
        // "'" at index 28 -> StringLiteral
        // "a" at index 29 -> StringLiteral
        // "'" at index 30 -> StringLiteral
        assert_eq!(buf.lines[0].highlights[28], HighlightType::StringLiteral);
        assert_eq!(buf.lines[0].highlights[29], HighlightType::StringLiteral);
        assert_eq!(buf.lines[0].highlights[30], HighlightType::StringLiteral);
    }

    #[test]
    fn test_syntax_highlighting_toml() {
        let mut editor = Editor::new(vec!["Cargo.toml".to_string()], Config::default());
        editor.process_keypress(Key::Char('i'));
        
        for ch in "[package]".chars() {
            editor.process_keypress(Key::Char(ch));
        }
        editor.process_keypress(Key::Enter);
        
        for ch in "name = \"red\" # comment".chars() {
            editor.process_keypress(Key::Char(ch));
        }
        editor.process_keypress(Key::Enter);
        
        for ch in "version = 0.1.0".chars() {
            editor.process_keypress(Key::Char(ch));
        }
        editor.process_keypress(Key::Enter);
        
        for ch in "inline = { key = true }".chars() {
            editor.process_keypress(Key::Char(ch));
        }
        editor.process_keypress(Key::Esc);

        let buf = editor.current_buffer();
        
        assert_eq!(buf.lines[0].highlights[0], HighlightType::Keyword);
        assert_eq!(buf.lines[0].highlights[1], HighlightType::Keyword);
        assert_eq!(buf.lines[0].highlights[8], HighlightType::Keyword);
        
        assert_eq!(buf.lines[1].highlights[0], HighlightType::Type);
        assert_eq!(buf.lines[1].highlights[3], HighlightType::Type);
        assert_eq!(buf.lines[1].highlights[4], HighlightType::Normal);
        assert_eq!(buf.lines[1].highlights[5], HighlightType::Normal);
        assert_eq!(buf.lines[1].highlights[6], HighlightType::Normal);
        assert_eq!(buf.lines[1].highlights[7], HighlightType::StringLiteral);
        assert_eq!(buf.lines[1].highlights[8], HighlightType::StringLiteral);
        assert_eq!(buf.lines[1].highlights[11], HighlightType::StringLiteral);
        assert_eq!(buf.lines[1].highlights[13], HighlightType::Comment);
        assert_eq!(buf.lines[1].highlights[21], HighlightType::Comment);
        
        assert_eq!(buf.lines[2].highlights[0], HighlightType::Type);
        assert_eq!(buf.lines[2].highlights[10], HighlightType::Number);
        
        assert_eq!(buf.lines[3].highlights[0], HighlightType::Type);
        assert_eq!(buf.lines[3].highlights[11], HighlightType::Type);
        assert_eq!(buf.lines[3].highlights[17], HighlightType::Keyword);
    }

    // --- Soft Line Wrapping Specific Unit Test ---

    #[test]
    fn test_soft_line_wrapping() {
        let mut editor = Editor::new(vec!["test.rs".to_string()], Config::default());
        editor.wrap = true;
        editor.show_line_numbers = true; // Gutter width = 4
        editor.screen_cols = 14;         // text_cols = 14 - 4 = 10
        
        // Long buffer line of length 25
        editor.current_buffer_mut().lines = vec![Line::new("abcdefghijklmnopqrstuvwxy")];
        
        // Verify wrapping segment lengths
        let segments = editor.current_buffer().lines[0].wrapped_segments(10, editor.config.tabstop);
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].0.len(), 10); // "abcdefghij"
        assert_eq!(segments[1].0.len(), 10); // "klmnopqrst"
        assert_eq!(segments[2].0.len(), 5);  // "uvwxy"
        
        // Case 1: cx = 5 (char 'f' on segment 0)
        editor.current_buffer_mut().cx = 5;
        let (sx1, sy1) = editor.get_cursor_screen_position();
        assert_eq!(sx1, 1 + 4 + 5); // x = 10
        assert_eq!(sy1, 1 + 0);     // y = 1 (segment 0)

        // Case 2: cx = 15 (char 'p' on segment 1)
        editor.current_buffer_mut().cx = 15;
        let (sx2, sy2) = editor.get_cursor_screen_position();
        assert_eq!(sx2, 1 + 4 + 5); // x = 10
        assert_eq!(sy2, 1 + 1);     // y = 2 (segment 1)

        // Case 3: cx = 22 (char 'w' on segment 2)
        editor.current_buffer_mut().cx = 22;
        let (sx3, sy3) = editor.get_cursor_screen_position();
        assert_eq!(sx3, 1 + 4 + 2); // x = 7
        assert_eq!(sy3, 1 + 2);     // y = 3 (segment 2)
    }

    #[test]
    fn test_line_jump_command() {
        let mut editor = Editor::new(Vec::new(), Config::default());
        editor.current_buffer_mut().lines = vec![
            Line::new("line one"),
            Line::new("line two"),
            Line::new("line three"),
        ];
        
        // Starts at (0, 0)
        assert_eq!(editor.current_buffer().cy, 0);
        
        // Jump to line 2
        editor.execute_command("2");
        assert_eq!(editor.current_buffer().cy, 1);
        assert_eq!(editor.current_buffer().cx, 0);
        
        // Jump to line 1
        editor.execute_command("1");
        assert_eq!(editor.current_buffer().cy, 0);
        
        // Jump past the end (should clamp to line 3)
        editor.execute_command("10");
        assert_eq!(editor.current_buffer().cy, 2);
    }

    #[test]
    fn test_search_mode_and_navigation() {
        let mut editor = Editor::new(Vec::new(), Config::default());
        editor.current_buffer_mut().lines = vec![
            Line::new("rust rust rust"),
            Line::new("cpp"),
            Line::new("rust"),
        ];
        
        // Press '/' to enter Search mode
        editor.process_keypress(Key::Char('/'));
        assert_eq!(editor.mode, Mode::Search);
        
        // Type "rust"
        for ch in "rust".chars() {
            editor.process_keypress(Key::Char(ch));
        }
        // Press Enter to search
        editor.process_keypress(Key::Enter);
        
        // Mode should return to Normal, and cursor should jump to the first match at (0, 0)
        assert_eq!(editor.mode, Mode::Normal);
        assert_eq!(editor.current_buffer().cy, 0);
        assert_eq!(editor.current_buffer().cx, 0);
        
        // Jump to next match -> index 5 in line 0
        editor.process_keypress(Key::Char('n'));
        assert_eq!(editor.current_buffer().cy, 0);
        assert_eq!(editor.current_buffer().cx, 5); // "rust [r]ust rust"
        
        // Jump to next match -> index 10 in line 0
        editor.process_keypress(Key::Char('n'));
        assert_eq!(editor.current_buffer().cy, 0);
        assert_eq!(editor.current_buffer().cx, 10); // "rust rust [r]ust"
        
        // Jump to next match -> line 2 index 0
        editor.process_keypress(Key::Char('n'));
        assert_eq!(editor.current_buffer().cy, 2);
        assert_eq!(editor.current_buffer().cx, 0); // Line 2: "[r]ust"
        
        // Next match wraps around to line 0 index 0
        editor.process_keypress(Key::Char('n'));
        assert_eq!(editor.current_buffer().cy, 0);
        assert_eq!(editor.current_buffer().cx, 0);
        
        // Prev match wraps around to line 2 index 0
        editor.process_keypress(Key::Char('N'));
        assert_eq!(editor.current_buffer().cy, 2);
        assert_eq!(editor.current_buffer().cx, 0);
        
        // Prev match to line 0 index 10
        editor.process_keypress(Key::Char('N'));
        assert_eq!(editor.current_buffer().cy, 0);
        assert_eq!(editor.current_buffer().cx, 10);
    }

    #[test]
    fn test_backward_search_mode_and_navigation() {
        let mut editor = Editor::new(Vec::new(), Config::default());
        editor.current_buffer_mut().lines = vec![
            Line::new("rust"),
            Line::new("cpp"),
            Line::new("rust rust"),
        ];
        
        // Put cursor at the end of the file: line 2, index 9 (end of "rust rust")
        editor.current_buffer_mut().cy = 2;
        editor.current_buffer_mut().cx = 9;
        
        // Press '?' to enter Search mode (backward)
        editor.process_keypress(Key::Char('?'));
        assert_eq!(editor.mode, Mode::Search);
        assert!(editor.search_backward);
        
        // Type "rust"
        for ch in "rust".chars() {
            editor.process_keypress(Key::Char(ch));
        }
        editor.process_keypress(Key::Enter);
        
        // Should jump to the match at line 2 index 5 ("rust [r]ust")
        assert_eq!(editor.current_buffer().cy, 2);
        assert_eq!(editor.current_buffer().cx, 5);
        
        // Press 'n' (jump backward) -> line 2 index 0 ("[r]ust rust")
        editor.process_keypress(Key::Char('n'));
        assert_eq!(editor.current_buffer().cy, 2);
        assert_eq!(editor.current_buffer().cx, 0);
        
        // Press 'n' (jump backward) -> line 0 index 0 (Line 0: "[r]ust")
        editor.process_keypress(Key::Char('n'));
        assert_eq!(editor.current_buffer().cy, 0);
        assert_eq!(editor.current_buffer().cx, 0);
        
        // Press 'n' (wraps around to the bottom-most match) -> line 2 index 5 ("rust [r]ust")
        editor.process_keypress(Key::Char('n'));
        assert_eq!(editor.current_buffer().cy, 2);
        assert_eq!(editor.current_buffer().cx, 5);
        
        // Press 'N' (jump forward) -> wraps around to the top-most match -> line 0 index 0
        editor.process_keypress(Key::Char('N'));
        assert_eq!(editor.current_buffer().cy, 0);
        assert_eq!(editor.current_buffer().cx, 0);
    }

    #[test]
    fn test_unchanged_terminal_size_does_not_force_full_redraw() {
        // During tests get_terminal_size() reports (24, 80) -> screen_rows 22, cols 80.
        let mut editor = Editor::new(Vec::new(), Config::default());
        let (rows, cols) = (editor.screen_rows, editor.screen_cols);

        // Simulate the periodic size poll returning the *same* dimensions.
        // (rows + 2 because apply_terminal_size subtracts the 2 status/message rows.)
        editor.redraw_target = RedrawTarget::None;
        editor.apply_terminal_size(rows + 2, cols);
        assert_eq!(
            editor.redraw_target,
            RedrawTarget::None,
            "a same-size report must not schedule a full redraw"
        );
        assert_eq!(editor.screen_rows, rows);
        assert_eq!(editor.screen_cols, cols);

        // A genuine size change must still force a full redraw.
        editor.redraw_target = RedrawTarget::None;
        editor.apply_terminal_size(rows + 2 + 5, cols + 3);
        assert_eq!(editor.redraw_target, RedrawTarget::Everything);
        assert_eq!(editor.screen_rows, rows + 5);
        assert_eq!(editor.screen_cols, cols + 3);
    }

    #[test]
    fn test_typing_only_repaints_current_line() {
        // Regression guard: with soft-wrap on (the default), typing a character
        // must not cause every screen row to be repainted. The damage-tracked
        // renderer should only change the edited line's row (and the status bar,
        // whose cursor readout moves).
        let mut editor = Editor::new(Vec::new(), Config::default());
        assert!(editor.wrap, "test assumes wrap defaults to on");

        // A handful of distinct lines so a full repaint would be obvious.
        editor.current_buffer_mut().lines = vec![
            Line::new("first line"),
            Line::new("second line"),
            Line::new("third line"),
            Line::new("fourth line"),
        ];
        editor.current_buffer_mut().cy = 1;
        editor.current_buffer_mut().cx = 0;

        // Enter insert mode and take the baseline frame (mode/message already set,
        // so they won't spuriously differ on the next keystroke).
        editor.process_keypress(Key::Char('i'));
        let before = editor.build_frame();

        // Type one character on line index 1.
        editor.process_keypress(Key::Char('X'));
        let after = editor.build_frame();

        assert_eq!(before.len(), after.len());
        let status_row = editor.screen_rows; // index of the status bar row

        let changed: Vec<usize> = (0..after.len())
            .filter(|&r| before[r] != after[r])
            .collect();

        // The edited line lives on screen row 1 (row_offset 0). Only it and the
        // status bar (cursor column moved) may change.
        assert!(
            changed.contains(&1),
            "the edited line's row should be repainted, changed = {:?}",
            changed
        );
        for &r in &changed {
            assert!(
                r == 1 || r == status_row,
                "unexpected row {} repainted on a single keystroke (changed = {:?})",
                r,
                changed
            );
        }
    }

    #[test]
    fn test_cursor_move_repaints_only_changed_status_columns() {
        // Regression guard for status-bar flicker: moving the cursor changes only
        // the "row:col" readout near the right edge, so the diff must reposition
        // into the right half of the bar and rewrite just a couple of characters
        // -- never the whole inverted line.
        let mut editor = Editor::new(Vec::new(), Config::default());
        editor.screen_cols = 40;
        editor.current_buffer_mut().lines = vec![Line::new("abcdefghij")];

        editor.current_buffer_mut().cx = 0;
        let old = editor.render_status_bar();
        editor.current_buffer_mut().cx = 3;
        let new = editor.render_status_bar();

        let mut out = String::new();
        let changed = Editor::diff_row_into(&mut out, editor.screen_rows + 1, &old, &new);
        assert!(changed);

        // Parse the leading `\x1b[row;colH` reposition and the visible characters.
        assert!(out.starts_with("\x1b["));
        let semi = out.find(';').unwrap();
        let h = out.find('H').unwrap();
        let col: usize = out[semi + 1..h].parse().unwrap();

        // Strip escape sequences to count how many glyphs were actually drawn.
        let mut visible = 0usize;
        let mut chars = out.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for e in chars.by_ref() {
                    if e.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                visible += 1;
            }
        }

        assert!(
            col > editor.screen_cols / 2,
            "status repaint should start in the right half (col = {})",
            col
        );
        assert!(
            visible <= 4,
            "status cursor move should redraw only a couple of glyphs, drew {}",
            visible
        );
        // The unchanged left portion must not be re-emitted.
        assert!(!out.contains("No Name"));
    }

    // --- Saving ---

    fn temp_path(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        #[cfg(target_os = "motor")]
        let temp_dir = std::path::PathBuf::from("/user/tmp");
        #[cfg(not(target_os = "motor"))]
        let temp_dir = std::env::temp_dir();
        temp_dir.join(format!("red_save_{}_{tag}_{n}", std::process::id()))
    }

    /// Load `original` from a real file, save it back, return the bytes on disk.
    fn round_trip(tag: &str, original: &str) -> String {
        let path = temp_path(tag);
        std::fs::write(&path, original).unwrap();
        let mut editor = Editor::new(
            vec![path.to_string_lossy().into_owned()],
            Config::default(),
        );
        assert!(editor.save_to_file(None), "save failed for {tag}");
        let got = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).ok();
        got
    }

    #[test]
    fn test_saving_an_untouched_file_leaves_it_byte_identical() {
        // The bug this guards: red used to join lines with "\n", so every save
        // silently ate the file's final newline.
        for (tag, original) in [
            ("plain", "hello\nworld\n"),
            ("single", "hello\n"),
            ("trailing_blank", "a\n\n"),
            ("leading_blank", "\na\n"),
            ("interior_blanks", "a\n\nb\n"),
            ("empty", ""),
        ] {
            assert_eq!(round_trip(tag, original), original, "case: {tag}");
        }
    }

    #[test]
    fn test_saving_restores_a_missing_final_newline() {
        // vim's 'fixendofline' default restores the EOL rather than preserving
        // its absence -- measured against vim 9.1, which does exactly this.
        assert_eq!(round_trip("no_eol", "hello\nworld"), "hello\nworld\n");
    }

    #[test]
    fn test_saving_an_edited_buffer_terminates_the_last_line() {
        let path = temp_path("edited");
        let mut editor = Editor::new(Vec::new(), Config::default());
        editor.process_keypress(Key::Char('i'));
        for ch in "abc".chars() {
            editor.process_keypress(Key::Char(ch));
        }
        assert!(editor.save_to_file(Some(&path.to_string_lossy())));
        let got = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(got, "abc\n");
    }

    // --- Configuration ---

    fn editor_with(config: Config) -> Editor {
        Editor::new(Vec::new(), config)
    }

    #[test]
    fn test_tabstop_drives_cursor_column() {
        // A tab renders as a jump to the next tab stop, whatever the width.
        for (tabstop, expected_rx) in [(4, 4), (8, 8), (2, 2), (3, 3)] {
            let mut editor = editor_with(Config {
                tabstop,
                expandtab: false,
            });
            editor.current_buffer_mut().lines = vec![Line::new("\tx")];
            editor.current_buffer_mut().cx = 1; // just past the tab
            editor.update_rx();
            assert_eq!(editor.current_buffer().rx, expected_rx, "tabstop {tabstop}");
        }
    }

    #[test]
    fn test_tab_advances_to_next_tab_stop_not_a_full_width() {
        // With tabstop=4, a tab in column 2 is 2 columns wide, not 4.
        let mut editor = editor_with(Config {
            tabstop: 4,
            expandtab: false,
        });
        editor.current_buffer_mut().lines = vec![Line::new("ab\tc")];
        editor.current_buffer_mut().cx = 3; // past 'a', 'b', tab
        editor.update_rx();
        assert_eq!(editor.current_buffer().rx, 4);
    }

    #[test]
    fn test_expandtab_inserts_spaces() {
        let mut editor = editor_with(Config {
            tabstop: 4,
            expandtab: true,
        });
        editor.process_keypress(Key::Char('i'));
        editor.process_keypress(Key::Tab);

        let line: String = editor.current_buffer().lines[0].chars.iter().collect();
        assert_eq!(line, "    ");
        assert_eq!(editor.current_buffer().cx, 4);
        assert!(editor.current_buffer().dirty);
    }

    #[test]
    fn test_expandtab_fills_only_to_the_next_tab_stop() {
        // vim's behavior: with tabstop=4, Tab at column 2 inserts 2 spaces.
        let mut editor = editor_with(Config {
            tabstop: 4,
            expandtab: true,
        });
        editor.process_keypress(Key::Char('i'));
        for ch in "ab".chars() {
            editor.process_keypress(Key::Char(ch));
        }
        editor.process_keypress(Key::Tab);

        let line: String = editor.current_buffer().lines[0].chars.iter().collect();
        assert_eq!(line, "ab  ");
        assert_eq!(editor.current_buffer().cx, 4);

        // A second Tab spans a whole tab stop.
        editor.process_keypress(Key::Tab);
        let line: String = editor.current_buffer().lines[0].chars.iter().collect();
        assert_eq!(line, "ab      ");
        assert_eq!(editor.current_buffer().cx, 8);
    }

    #[test]
    fn test_noexpandtab_inserts_a_tab_character() {
        let mut editor = editor_with(Config {
            tabstop: 4,
            expandtab: false,
        });
        editor.process_keypress(Key::Char('i'));
        editor.process_keypress(Key::Tab);

        let line: String = editor.current_buffer().lines[0].chars.iter().collect();
        assert_eq!(line, "\t");
        assert_eq!(editor.current_buffer().cx, 1);
    }

    #[test]
    fn test_expandtab_inserts_at_the_cursor_not_the_line_end() {
        let mut editor = editor_with(Config {
            tabstop: 4,
            expandtab: true,
        });
        editor.current_buffer_mut().lines = vec![Line::new("abcd")];
        editor.current_buffer_mut().cx = 0;
        editor.process_keypress(Key::Char('i'));
        editor.process_keypress(Key::Tab);

        let line: String = editor.current_buffer().lines[0].chars.iter().collect();
        assert_eq!(line, "    abcd");
        assert_eq!(editor.current_buffer().cx, 4);
    }

    #[test]
    fn test_tabstop_drives_rendered_width() {
        // The tab must paint as spaces up to the next tab stop.
        let mut editor = editor_with(Config {
            tabstop: 4,
            expandtab: false,
        });
        editor.show_line_numbers = false;
        editor.screen_cols = 12;
        editor.current_buffer_mut().lines = vec![Line::new("\tx")];
        editor.highlight_buffer_from(0, true);

        let rows = editor.gather_visible_rows();
        let cells = editor.render_text_row(0, &rows, 12, 0);
        let painted: String = cells.iter().map(|c| c.ch).collect();
        assert!(painted.starts_with("    x"), "painted: {painted:?}");
    }
}
