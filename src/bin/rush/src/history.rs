//! Command history: the in-memory list and its `$HISTFILE` persistence.
//!
//! POSIX does not specify an interactive history list — it only mentions
//! `$HISTFILE`/`$HISTSIZE` in the context of `fc` (XCU `fc`), which rush does
//! not implement. What is here is therefore a documented rush extension, kept
//! deliberately close to what every other shell does: `$HISTFILE` names the file
//! (unset ⇒ history is in-memory only, as rush was before Phase 8), `$HISTSIZE`
//! caps the number of entries kept, and consecutive duplicates and blank lines
//! are not recorded.
//!
//! # The file format is rush's own
//!
//! One entry per line, with `\` and newline **escaped** (`\\` and `\n`). Every
//! other shell writes entries raw, one line each, which silently corrupts a
//! multi-line command: bash reads `for i in 1 2` and `do echo $i; done` back as
//! two separate entries, neither of which runs. rush records a multi-line
//! command as one entry (`lib.rs` merges the continuation lines before adding
//! it), so it escapes on the way out and unescapes on the way in, and the entry
//! round-trips exactly. The cost is that a history file shared with another
//! shell shows the escapes; on Motor OS there is no other shell to share with.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Entries kept when `$HISTSIZE` is unset or unusable. Matches bash's default.
pub const DEFAULT_HISTSIZE: usize = 500;

pub struct History {
    entries: Vec<String>,
    /// Cap on `entries`; the oldest are dropped first.
    max: usize,
    /// Where to persist, from `$HISTFILE`. `None` ⇒ in-memory only.
    file: Option<PathBuf>,
    /// Whether anything was added since the last load/save, so an unchanged
    /// session does not rewrite the file (and cannot truncate it on a crash).
    dirty: bool,
}

impl History {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            max: DEFAULT_HISTSIZE,
            file: None,
            dirty: false,
        }
    }

    /// Point the history at `$HISTFILE` with a `$HISTSIZE` cap and read what is
    /// already there. A missing or unreadable file is not an error: history is a
    /// convenience, and a shell that refused to start because `$HISTFILE` names
    /// a bad path would be worse than one with no history.
    pub fn open(&mut self, file: Option<&str>, size: Option<&str>) {
        self.max = match size.and_then(|s| s.trim().parse::<usize>().ok()) {
            Some(n) => n,
            None => DEFAULT_HISTSIZE,
        };
        let Some(file) = file.filter(|f| !f.is_empty()) else {
            return;
        };
        self.file = Some(PathBuf::from(file));
        if let Ok(text) = std::fs::read_to_string(file) {
            for line in text.lines() {
                if line.is_empty() {
                    continue;
                }
                self.entries.push(unescape(line));
            }
            self.trim();
        }
        self.dirty = false;
    }

    /// Write the history back to `$HISTFILE`, replacing it.
    ///
    /// Called on exit. Errors are silent for the same reason `open` tolerates
    /// them: the shell is on its way out and has nowhere useful to complain to
    /// (its stderr may be the very terminal it is releasing).
    pub fn save(&mut self) {
        let (Some(file), true) = (self.file.as_ref(), self.dirty) else {
            return;
        };
        let _ = write_atomically(file, &self.serialize());
        self.dirty = false;
    }

    fn serialize(&self) -> String {
        let mut text = String::new();
        for e in &self.entries {
            text.push_str(&escape(e));
            text.push('\n');
        }
        text
    }

    /// `history -c`: forget everything. The empty list is what gets saved on
    /// exit, so this clears `$HISTFILE` too rather than leaving the old entries
    /// to come back next session.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.dirty = true;
    }

    /// Record `line`, unless it is blank or repeats the previous entry.
    pub fn add(&mut self, line: &str) {
        if line.trim().is_empty() {
            return;
        }
        if self.entries.last().map(String::as_str) == Some(line) {
            return;
        }
        if self.max == 0 {
            return;
        }
        self.entries.push(line.to_string());
        self.dirty = true;
        self.trim();
    }

    fn trim(&mut self) {
        if self.entries.len() > self.max {
            let excess = self.entries.len() - self.max;
            self.entries.drain(..excess);
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn get(&self, idx: usize) -> Option<&str> {
        self.entries.get(idx).map(String::as_str)
    }

    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// The newest entry at or before `from` containing `needle` — the search
    /// `^R` walks backwards. `from` is an index into [`Self::entries`].
    pub fn search_back(&self, needle: &str, from: usize) -> Option<usize> {
        let from = from.min(self.entries.len().saturating_sub(1));
        if self.entries.is_empty() {
            return None;
        }
        (0..=from).rev().find(|&i| self.entries[i].contains(needle))
    }
}

/// Replace `file`'s contents, without leaving a half-written file behind if the
/// write fails partway: write a sibling temp file, then rename over the target.
///
/// Motor OS has no `mkstemp`, and rush has no random source it wants to pull in
/// for this, so the temp name is derived from the shell's pid — unique among
/// concurrent shells, which is the only collision that matters here.
fn write_atomically(file: &Path, text: &str) -> std::io::Result<()> {
    let mut tmp = file.as_os_str().to_os_string();
    tmp.push(format!(".{}.tmp", crate::sys::pid()));
    let tmp = PathBuf::from(tmp);
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.flush()?;
    }
    match std::fs::rename(&tmp, file) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Encode one entry onto a single line: `\` → `\\`, newline → `\n`.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// The inverse of [`escape`]. An unknown escape (`\x`) keeps both characters, so
/// a hand-written or foreign history file is read back as literally as possible
/// rather than losing text.
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            // A trailing lone backslash.
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_skips_blanks_and_consecutive_duplicates() {
        let mut h = History::new();
        h.add("ls");
        h.add("ls");
        h.add("   ");
        h.add("");
        h.add("pwd");
        h.add("ls");
        assert_eq!(h.entries(), ["ls", "pwd", "ls"]);
    }

    #[test]
    fn histsize_caps_and_drops_the_oldest() {
        let mut h = History::new();
        h.max = 2;
        h.add("one");
        h.add("two");
        h.add("three");
        assert_eq!(h.entries(), ["two", "three"]);
    }

    #[test]
    fn histsize_zero_records_nothing() {
        let mut h = History::new();
        h.max = 0;
        h.add("one");
        assert_eq!(h.len(), 0);
    }

    #[test]
    fn search_back_finds_the_newest_match_at_or_before_from() {
        let mut h = History::new();
        for e in ["echo one", "ls -l", "echo two"] {
            h.add(e);
        }
        assert_eq!(h.search_back("echo", 2), Some(2));
        assert_eq!(h.search_back("echo", 1), Some(0));
        assert_eq!(h.search_back("nope", 2), None);
    }

    #[test]
    fn search_back_on_an_empty_history_finds_nothing() {
        let h = History::new();
        assert_eq!(h.search_back("x", 0), None);
    }

    #[test]
    fn escaping_round_trips_multiline_entries_and_backslashes() {
        for s in [
            "echo hi",
            "for i in 1 2\ndo echo $i\ndone",
            r"printf 'a\nb\n'",
            r"echo \\",
            "trailing\\",
        ] {
            assert_eq!(unescape(&escape(s)), s, "round-trip of {s:?}");
        }
    }

    #[test]
    fn an_entry_never_spans_two_lines_on_disk() {
        let mut h = History::new();
        h.add("for i in 1 2\ndo echo $i\ndone");
        assert_eq!(h.serialize().lines().count(), 1);
    }

    #[test]
    fn clearing_empties_the_saved_file_too() {
        let dir = std::env::temp_dir().join(format!("rush-histc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("histfile");
        let path_str = path.to_str().unwrap();

        let mut h = History::new();
        h.open(Some(path_str), None);
        h.add("echo one");
        h.save();
        assert!(!std::fs::read_to_string(&path).unwrap().is_empty());

        h.clear();
        h.save();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unknown_escapes_survive_a_foreign_history_file() {
        assert_eq!(unescape(r"echo \t"), r"echo \t");
    }

    #[test]
    fn open_reads_back_what_save_wrote() {
        let dir = std::env::temp_dir().join(format!("rush-hist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("histfile");
        let path_str = path.to_str().unwrap();

        let mut h = History::new();
        h.open(Some(path_str), Some("10"));
        h.add("echo one");
        h.add("for i in 1 2\ndo echo $i\ndone");
        h.save();

        let mut h2 = History::new();
        h2.open(Some(path_str), Some("10"));
        assert_eq!(h2.entries(), ["echo one", "for i in 1 2\ndo echo $i\ndone"]);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn open_tolerates_a_missing_file_and_a_bad_histsize() {
        let mut h = History::new();
        h.open(Some("/nonexistent/dir/histfile"), Some("not-a-number"));
        assert_eq!(h.max, DEFAULT_HISTSIZE);
        assert_eq!(h.len(), 0);
        // No file to save to is not an error either.
        h.add("echo hi");
        h.save();
    }

    #[test]
    fn no_histfile_means_memory_only() {
        let mut h = History::new();
        h.open(None, None);
        h.add("echo hi");
        h.save();
        assert_eq!(h.entries(), ["echo hi"]);
    }
}
