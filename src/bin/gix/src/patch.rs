//! Reading patches, and applying the hunks of a patch to the contents of a file.
//!
//! This follows `apply.c` of Git, so that a patch means here what it means to `git apply`:
//! the same lines are a header, the same text is a file name, and a hunk is looked for in
//! the same places. Nothing in this file looks at a repository or at the worktree.

use std::io;

use gix::bstr::{BStr, BString, ByteSlice, ByteVec};

/// One change to one file, as a patch describes it.
#[derive(Debug, Default)]
pub struct Patch<'a> {
    pub old_name: Option<BString>,
    pub new_name: Option<BString>,
    /// The modes that the patch names, or zero.
    pub old_mode: u32,
    pub new_mode: u32,
    /// Whether the patch creates the file. `None` if the patch does not say, which only a
    /// patch without Git's header can leave open.
    pub is_new: Option<bool>,
    pub is_delete: Option<bool>,
    pub is_rename: bool,
    pub is_copy: bool,
    /// The object names of the `index` line, as written.
    pub old_id: &'a [u8],
    pub new_id: &'a [u8],
    pub hunks: Vec<Hunk<'a>>,
}

/// The kind of a line in a hunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Line {
    Context,
    Remove,
    Add,
}

#[derive(Debug)]
pub struct Hunk<'a> {
    /// The first line and the number of lines of each side, as the header has them.
    pub old_start: usize,
    pub old_lines: usize,
    pub new_start: usize,
    pub new_lines: usize,
    /// Every line with its text. The text has its newline, unless the patch says that the
    /// file has none there.
    pub lines: Vec<(Line, &'a [u8])>,
}

impl Patch<'_> {
    /// The name that messages about this patch use.
    pub fn name(&self) -> &BStr {
        self.old_name
            .as_ref()
            .or(self.new_name.as_ref())
            .map_or(BStr::new(""), |name| name.as_bstr())
    }

    /// Whether the patch does something although it has no hunk.
    fn changes_metadata(&self) -> bool {
        self.is_rename
            || self.is_copy
            || self.is_new == Some(true)
            || self.is_delete != Some(false)
            || self.old_mode != 0 && self.new_mode != 0 && self.old_mode != self.new_mode
    }

    /// Turn the patch into the one that undoes it, as `git apply -R` does.
    pub fn reverse(&mut self) {
        std::mem::swap(&mut self.old_name, &mut self.new_name);
        if self.new_mode != 0 || self.is_delete == Some(true) {
            std::mem::swap(&mut self.old_mode, &mut self.new_mode);
        }
        std::mem::swap(&mut self.is_new, &mut self.is_delete);
        std::mem::swap(&mut self.old_id, &mut self.new_id);
        for hunk in &mut self.hunks {
            std::mem::swap(&mut hunk.old_start, &mut hunk.new_start);
            std::mem::swap(&mut hunk.old_lines, &mut hunk.new_lines);
            for (kind, _) in &mut hunk.lines {
                *kind = match kind {
                    Line::Context => Line::Context,
                    Line::Remove => Line::Add,
                    Line::Add => Line::Remove,
                };
            }
        }
    }
}

/// The patch text that is still to be read, and the number of its first line.
#[derive(Clone, Copy)]
struct Cursor<'a> {
    rest: &'a [u8],
    line: usize,
}

impl<'a> Cursor<'a> {
    /// The next line, with its newline if it has one.
    fn peek(&self) -> Option<&'a [u8]> {
        let end = self
            .rest
            .find_byte(b'\n')
            .map_or(self.rest.len(), |at| at + 1);
        (end != 0).then(|| &self.rest[..end])
    }

    fn advance(&mut self) {
        if let Some(line) = self.peek() {
            self.rest = &self.rest[line.len()..];
            self.line += 1;
        }
    }
}

/// Reads the patches of one `git apply` run. What it learns about the number of leading
/// directories from one patch holds for the patches after it, as in Git.
pub struct Parser<'p> {
    /// How many leading directories are removed from a name: the value of `-p`.
    strip: usize,
    /// Whether `strip` was given, or found out from a patch without Git's header.
    strip_known: bool,
    /// The directory that the command was started in: empty, or ending in `/`.
    prefix: &'p [u8],
}

impl<'p> Parser<'p> {
    pub fn new(strip: Option<usize>, prefix: &'p [u8]) -> Self {
        Parser {
            strip: strip.unwrap_or(1),
            strip_known: strip.is_some(),
            prefix,
        }
    }

    /// Read every patch in `input`. Text that is no patch is skipped, as a commit message
    /// in front of a patch has to be.
    pub fn parse<'a>(&mut self, input: &'a [u8]) -> crate::Result<Vec<Patch<'a>>> {
        let mut cursor = Cursor {
            rest: input,
            line: 1,
        };
        let mut patches = Vec::new();
        while let Some(mut patch) = self.find_header(&mut cursor)? {
            parse_hunks(&mut cursor, &mut patch)?;
            if patch.hunks.is_empty() {
                check_hunkless_patch(&cursor, &patch)?;
            }
            // Git removes the old file and writes the new one whenever the names differ.
            // That is found out only here, after the check for a patch without a change:
            // to Git, names that differ are no change, and such a header is garbage.
            patch.is_rename |= !patch.is_copy
                && patch.old_name.is_some()
                && patch.new_name.is_some()
                && patch.old_name != patch.new_name;
            patches.try_reserve(1)?;
            patches.push(patch);
        }
        Ok(patches)
    }

    /// Skip to the next header and read it. `None` if there is no further patch.
    fn find_header<'a>(&mut self, cursor: &mut Cursor<'a>) -> crate::Result<Option<Patch<'a>>> {
        while let Some(line) = cursor.peek() {
            // Git's shortcut: no line of a header is shorter than this.
            if line.len() < 6 {
                cursor.advance();
                continue;
            }
            // A hunk here was cut off from its header: the patch is damaged.
            if line.starts_with(b"@@ -") {
                if hunk_header(line).is_some() {
                    return Err(invalid(format!(
                        "patch fragment without header at line {}: {}",
                        cursor.line,
                        line.trim_end().to_str_lossy().escape_debug()
                    )));
                }
                cursor.advance();
                continue;
            }
            if cursor.rest.len() < line.len() + 6 {
                break;
            }
            if line.starts_with(b"diff --git ") {
                // Without a header line after it, this is no patch, only text.
                if let Some(patch) = self.git_header(cursor, line)? {
                    return Ok(Some(patch));
                }
                continue;
            }
            let mut after = *cursor;
            after.advance();
            let second = after.peek().unwrap_or_default();
            after.advance();
            // The shortest hunk header, "@@ -0,0 +1 @@", has 14 bytes with its newline.
            if !line.starts_with(b"--- ")
                || !second.starts_with(b"+++ ")
                || cursor.rest.len() < second.len() + 14
                || !after.rest.starts_with(b"@@ -")
            {
                cursor.advance();
                continue;
            }
            let patch = self.traditional_header(&line[4..], &second[4..], cursor.line)?;
            *cursor = after;
            return Ok(Some(patch));
        }
        Ok(None)
    }

    /// Read the header that `git diff` writes. `first` is its `diff --git` line. `None`,
    /// with only that line consumed, if no header line follows it.
    fn git_header<'a>(
        &self,
        cursor: &mut Cursor<'a>,
        first: &'a [u8],
    ) -> crate::Result<Option<Patch<'a>>> {
        // A patch from Git says when it creates or deletes a file.
        let mut patch = Patch {
            is_new: Some(false),
            is_delete: Some(false),
            ..Default::default()
        };
        // The names of a rename or copy have no `a/` or `b/` in front.
        let unprefixed = self.strip.saturating_sub(1);
        let default_name = git_header_name(self.strip, first);
        let default = || default_name.clone();
        cursor.advance();
        let mut header_lines = 0;
        let mut extension_line = None;
        while let Some(line) = cursor.peek() {
            if !line.ends_with(b"\n") || line.starts_with(b"@@ -") {
                break;
            }
            let number = cursor.line;
            if let Some(rest) = line.strip_prefix(b"--- ") {
                let is_new = patch.is_new == Some(true);
                verify_name(self.strip, rest, is_new, &mut patch.old_name, "old", number)?;
            } else if let Some(rest) = line.strip_prefix(b"+++ ") {
                let is_delete = patch.is_delete == Some(true);
                verify_name(
                    self.strip,
                    rest,
                    is_delete,
                    &mut patch.new_name,
                    "new",
                    number,
                )?;
            } else if let Some(rest) = line.strip_prefix(b"old mode ") {
                patch.old_mode = mode(rest, number)?;
            } else if let Some(rest) = line.strip_prefix(b"new mode ") {
                patch.new_mode = mode(rest, number)?;
            } else if let Some(rest) = line.strip_prefix(b"deleted file mode ") {
                patch.is_delete = Some(true);
                patch.old_name = default();
                patch.old_mode = mode(rest, number)?;
            } else if let Some(rest) = line.strip_prefix(b"new file mode ") {
                patch.is_new = Some(true);
                patch.new_name = default();
                patch.new_mode = mode(rest, number)?;
            } else if let Some(rest) = line.strip_prefix(b"copy from ") {
                patch.is_copy = true;
                patch.old_name = find_name(rest, unprefixed, End::Line);
            } else if let Some(rest) = line.strip_prefix(b"copy to ") {
                patch.is_copy = true;
                patch.new_name = find_name(rest, unprefixed, End::Line);
            } else if let Some(rest) = line
                .strip_prefix(b"rename old ")
                .or_else(|| line.strip_prefix(b"rename from "))
            {
                patch.is_rename = true;
                patch.old_name = find_name(rest, unprefixed, End::Line);
            } else if let Some(rest) = line
                .strip_prefix(b"rename new ")
                .or_else(|| line.strip_prefix(b"rename to "))
            {
                patch.is_rename = true;
                patch.new_name = find_name(rest, unprefixed, End::Line);
            } else if line.starts_with(b"similarity index ")
                || line.starts_with(b"dissimilarity index ")
            {
            } else if let Some(rest) = line.strip_prefix(b"index ") {
                index_line(rest, &mut patch, number)?;
            } else {
                break;
            }
            let extensions = [
                patch.is_delete == Some(true),
                patch.is_new == Some(true),
                patch.is_rename,
                patch.is_copy,
            ];
            if extensions.into_iter().filter(|set| *set).count() > 1 {
                return Err(invalid(format!(
                    "inconsistent header lines {} and {number}",
                    extension_line.unwrap_or(number)
                )));
            }
            if extensions.contains(&true) {
                extension_line.get_or_insert(number);
            }
            header_lines += 1;
            cursor.advance();
        }

        if patch.old_name.is_none() && patch.new_name.is_none() {
            let Some(name) = default_name else {
                return Err(invalid(format!(
                    "git diff header lacks filename information when removing {} leading \
                     pathname component{} (line {})",
                    self.strip,
                    if self.strip == 1 { "" } else { "s" },
                    cursor.line
                )));
            };
            patch.old_name = Some(name.clone());
            patch.new_name = Some(name);
        }
        if patch.new_name.is_none() && patch.is_delete != Some(true)
            || patch.old_name.is_none() && patch.is_new != Some(true)
        {
            return Err(invalid(format!(
                "git diff header lacks filename information (line {})",
                cursor.line
            )));
        }
        Ok((header_lines != 0).then_some(patch))
    }

    /// Read the two name lines of a patch that `diff -u` wrote. `first` and `second` are
    /// what follows `--- ` and `+++ `.
    fn traditional_header<'a>(
        &mut self,
        first: &[u8],
        second: &[u8],
        number: usize,
    ) -> crate::Result<Patch<'a>> {
        if !self.strip_known {
            let old = self.guess_strip(first);
            let new = self.guess_strip(second);
            if let Some(strip) = old.or(new).filter(|strip| Some(*strip) == new) {
                self.strip = strip;
                self.strip_known = true;
            }
        }
        let mut patch = Patch::default();
        let name;
        if is_dev_null(first) {
            patch.is_new = Some(true);
            patch.is_delete = Some(false);
            name = find_name_traditional(second, None, self.strip);
            patch.new_name = name.clone();
        } else if is_dev_null(second) {
            patch.is_new = Some(false);
            patch.is_delete = Some(true);
            name = find_name_traditional(first, None, self.strip);
            patch.old_name = name.clone();
        } else {
            let first_name = find_name_traditional(first, None, self.strip);
            name = find_name_traditional(second, first_name.as_ref(), self.strip);
            // A file dated at the start of 1970 is one that does not exist.
            if has_epoch_timestamp(first) {
                patch.is_new = Some(true);
                patch.is_delete = Some(false);
                patch.new_name = name.clone();
            } else if has_epoch_timestamp(second) {
                patch.is_new = Some(false);
                patch.is_delete = Some(true);
                patch.old_name = name.clone();
            } else {
                patch.old_name = name.clone();
                patch.new_name = name.clone();
            }
        }
        if name.is_none() {
            return Err(invalid(format!(
                "unable to find filename in patch at line {number}"
            )));
        }
        // The names of Git's header are relative to the top of the worktree. These are
        // relative to the directory that the command was started in.
        for name in [&mut patch.old_name, &mut patch.new_name]
            .into_iter()
            .flatten()
        {
            name.insert_str(0, self.prefix);
        }
        Ok(patch)
    }

    /// Tell from a name how many leading directories a patch without Git's header has.
    fn guess_strip(&self, line: &[u8]) -> Option<usize> {
        if is_dev_null(line) {
            return None;
        }
        let name = find_name_traditional(line, None, 0)?;
        let Some(slash) = name.find_byte(b'/') else {
            return Some(0);
        };
        if self.prefix.is_empty() {
            return None;
        }
        // A name that begins with the invocation directory, or with `a/` and then that
        // directory, is very likely relative to the top of the worktree.
        let depth = self.prefix.iter().filter(|byte| **byte == b'/').count();
        if name.starts_with(self.prefix) {
            Some(depth)
        } else if name[slash + 1..].starts_with(self.prefix) {
            Some(depth + 1)
        } else {
            None
        }
    }
}

/// Read the hunks that follow a header, and settle what the header left open.
fn parse_hunks<'a>(cursor: &mut Cursor<'a>, patch: &mut Patch<'a>) -> crate::Result {
    let (mut old_lines, mut new_lines) = (0, 0);
    while cursor.rest.len() > 4 && cursor.rest.starts_with(b"@@ -") {
        let Some(hunk) = parse_hunk(cursor)? else {
            return Err(invalid(format!("corrupt patch at line {}", cursor.line)));
        };
        old_lines += hunk.old_lines;
        new_lines += hunk.new_lines;
        patch.hunks.try_reserve(1)?;
        patch.hunks.push(hunk);
    }
    // A file with old lines is not created, and one with new lines is not deleted. More
    // than one hunk means neither, as creating and deleting have no context to split at.
    if patch.is_new.is_none() && (old_lines != 0 || patch.hunks.len() > 1) {
        patch.is_new = Some(false);
    }
    if patch.is_delete.is_none() && (new_lines != 0 || patch.hunks.len() > 1) {
        patch.is_delete = Some(false);
    }
    if patch.is_new == Some(true) && old_lines != 0 {
        return Err(invalid(format!(
            "new file {} depends on old contents",
            display(patch.new_name.as_ref())
        )));
    }
    if patch.is_delete == Some(true) && new_lines != 0 {
        return Err(invalid(format!(
            "deleted file {} still has contents",
            display(patch.old_name.as_ref())
        )));
    }
    Ok(())
}

/// Parse `@@ -START[,LINES] +START[,LINES] @@`. A missing count is one.
fn hunk_header(line: &[u8]) -> Option<(usize, usize, usize, usize)> {
    fn range<'a>(text: &'a [u8], expect: &[u8]) -> Option<(usize, usize, &'a [u8])> {
        let (start, mut text) = number(text)?;
        let mut lines = 1;
        if let Some(rest) = text.strip_prefix(b",") {
            (lines, text) = number(rest)?;
        }
        Some((start, lines, text.strip_prefix(expect)?))
    }
    if !line.ends_with(b"\n") {
        return None;
    }
    let (old_start, old_lines, rest) = range(line.strip_prefix(b"@@ -")?, b" +")?;
    let (new_start, new_lines, _) = range(rest, b" @@")?;
    Some((old_start, old_lines, new_start, new_lines))
}

/// Parse the decimal number at the start of `text`.
fn number(text: &[u8]) -> Option<(usize, &[u8])> {
    let digits = text.iter().take_while(|byte| byte.is_ascii_digit()).count();
    let value = text[..digits].to_str().ok()?.parse().ok()?;
    Some((value, &text[digits..]))
}

/// Read one hunk. `None` if it is damaged; the cursor is then at the line that is wrong.
fn parse_hunk<'a>(cursor: &mut Cursor<'a>) -> crate::Result<Option<Hunk<'a>>> {
    let header = cursor.peek().and_then(hunk_header);
    let Some((old_start, old_lines, new_start, new_lines)) = header else {
        return Ok(None);
    };
    let mut hunk = Hunk {
        old_start,
        old_lines,
        new_start,
        new_lines,
        lines: Vec::new(),
    };
    cursor.advance();
    let (mut old_left, mut new_left) = (old_lines, new_lines);
    let mut changes = false;
    while old_left != 0 || new_left != 0 {
        let Some(line) = cursor.peek() else {
            break;
        };
        if !line.ends_with(b"\n") {
            return Ok(None);
        }
        let kind = match line[0] {
            // Newer GNU diff writes an empty context line without its leading space.
            b' ' | b'\n' => Line::Context,
            b'-' => Line::Remove,
            b'+' => Line::Add,
            // "\ No newline at end of file", in whatever language: the line before it
            // has no newline.
            b'\\' if line.len() >= 12 && line.starts_with(b"\\ ") => {
                strip_newline(&mut hunk);
                cursor.advance();
                continue;
            }
            _ => return Ok(None),
        };
        // A side that has all its lines takes no further one.
        if kind != Line::Add && old_left == 0 || kind != Line::Remove && new_left == 0 {
            return Ok(None);
        }
        old_left -= usize::from(kind != Line::Add);
        new_left -= usize::from(kind != Line::Remove);
        changes |= kind != Line::Context;
        let text = if line[0] == b'\n' { line } else { &line[1..] };
        hunk.lines.try_reserve(1)?;
        hunk.lines.push((kind, text));
        cursor.advance();
    }
    if old_left != 0 || new_left != 0 || !changes {
        return Ok(None);
    }
    // The last line of the hunk may be one without a newline.
    if cursor.rest.len() > 12 && cursor.rest.starts_with(b"\\ ") {
        strip_newline(&mut hunk);
        cursor.advance();
    }
    Ok(Some(hunk))
}

fn strip_newline(hunk: &mut Hunk<'_>) {
    if let Some((_, text)) = hunk.lines.last_mut() {
        *text = text.strip_suffix(b"\n").unwrap_or(text);
    }
}

/// A text patch without hunks must change the name or mode, create a file, or delete it.
fn check_hunkless_patch(cursor: &Cursor<'_>, patch: &Patch<'_>) -> crate::Result {
    let line = cursor.peek().unwrap_or_default();
    if line == b"GIT binary patch\n"
        || line.ends_with(b" differ\n")
            && (line.starts_with(b"Binary files ") || line.starts_with(b"Files "))
    {
        return Err(invalid(format!(
            "binary patch at line {} is unsupported",
            cursor.line
        )));
    }
    if !patch.changes_metadata() {
        return Err(invalid(format!(
            "patch with only garbage at line {}",
            cursor.line
        )));
    }
    Ok(())
}

/// Read `index OLD..NEW[ MODE]`. A line of another form is ignored, as in Git.
fn index_line<'a>(rest: &'a [u8], patch: &mut Patch<'a>, number: usize) -> crate::Result {
    const HEX_LEN: usize = 40;
    let Some(dots) = rest
        .find_byte(b'.')
        .filter(|dots| *dots <= HEX_LEN && rest.get(dots + 1) == Some(&b'.'))
    else {
        return Ok(());
    };
    let (old, new) = (&rest[..dots], &rest[dots + 2..]);
    let end = new
        .find_byteset(b" \n")
        .expect("a header line ends with a newline");
    if end > HEX_LEN {
        return Ok(());
    }
    patch.old_id = old;
    patch.new_id = &new[..end];
    if new[end] == b' ' {
        patch.old_mode = mode(&new[end + 1..], number)?;
    }
    Ok(())
}

/// Parse an octal mode and bring it to one of the forms that Git stores.
fn mode(text: &[u8], number: usize) -> crate::Result<u32> {
    let digits = text
        .iter()
        .take_while(|byte| (b'0'..=b'7').contains(byte))
        .count();
    let value = text[..digits]
        .to_str()
        .ok()
        .and_then(|digits| u32::from_str_radix(digits, 8).ok())
        .filter(|_| text.get(digits).is_some_and(u8::is_ascii_whitespace));
    let Some(value) = value else {
        return Err(invalid(format!(
            "invalid mode on line {number}: {}",
            text.trim_end().to_str_lossy().escape_debug()
        )));
    };
    Ok(match kind(value) {
        0o100000 if value & 0o100 != 0 => 0o100755,
        0o100000 => 0o100644,
        0o120000 => 0o120000,
        0o040000 => 0o040000,
        _ => 0o160000,
    })
}

/// The type bits of a mode: a regular file, a link, or a submodule.
pub fn kind(mode: u32) -> u32 {
    mode & 0o170000
}

/// Check a `---` or `+++` line of Git's header against the name known so far.
/// `absent` says that the file does not exist on this side.
fn verify_name(
    strip: usize,
    line: &[u8],
    absent: bool,
    name: &mut Option<BString>,
    side: &str,
    number: usize,
) -> crate::Result {
    let Some(known) = name else {
        if absent {
            if !is_dev_null(line) {
                return Err(invalid(format!(
                    "bad git-diff - expected /dev/null on line {number}"
                )));
            }
        } else {
            *name = find_name(line, strip, End::Tab);
        }
        return Ok(());
    };
    if absent {
        return Err(invalid(format!(
            "bad git-diff - expected /dev/null, got {} on line {number}",
            known.to_str_lossy().escape_debug()
        )));
    }
    if find_name(line, strip, End::Tab).as_ref() != Some(known) {
        return Err(invalid(format!(
            "bad git-diff - inconsistent {side} filename on line {number}"
        )));
    }
    Ok(())
}

/// Where a name that is not in quotes ends.
#[derive(Clone, Copy)]
enum End {
    /// At the end of the line.
    Line,
    /// At a tab, or at the end of the line.
    Tab,
    /// After this many bytes of the line.
    At(usize),
}

/// Read the name at the start of `line` and remove `strip` leading directories from it.
fn find_name(line: &[u8], strip: usize, end: End) -> Option<BString> {
    if line.starts_with(b"\"")
        && let Some(name) = find_name_quoted(line, strip)
    {
        return Some(name);
    }
    find_name_common(line, None, strip, end)
}

/// Read a name that Git put in double quotes.
fn find_name_quoted(line: &[u8], strip: usize) -> Option<BString> {
    let (name, _) = gix_quote::ansi_c::undo(line.as_bstr()).ok()?;
    let mut start = 0;
    for _ in 0..strip {
        start += name[start..].find_byte(b'/')? + 1;
    }
    Some(squash_slashes(&name[start..]))
}

/// Read a name that is not in quotes, up to `end`. `default` is returned for a line
/// without a name, or if it is a shorter form of the name: the line may name a backup
/// such as `file.orig`.
fn find_name_common(
    line: &[u8],
    default: Option<&BString>,
    strip: usize,
    end: End,
) -> Option<BString> {
    let mut start = (strip == 0).then_some(0);
    let mut slashes = 0;
    let mut at = 0;
    while let Some(&byte) = line.get(at) {
        let ends = match end {
            End::Line => matches!(byte, b'\n' | b'\r'),
            End::Tab => matches!(byte, b'\n' | b'\r' | b'\t'),
            End::At(len) => at == len,
        };
        if ends {
            break;
        }
        at += 1;
        if byte == b'/' {
            slashes += 1;
            if slashes == strip {
                start = Some(at);
            }
        }
    }
    let Some(start) = start.filter(|start| *start != at) else {
        return default.cloned();
    };
    let name = &line[start..at];
    if let Some(default) = default
        && default.len() < name.len()
        && name.starts_with(default)
    {
        return Some(default.clone());
    }
    Some(squash_slashes(name))
}

/// Read the name of a `---` or `+++` line of `diff -u`, which may have a time after it.
fn find_name_traditional(line: &[u8], default: Option<&BString>, strip: usize) -> Option<BString> {
    if line.starts_with(b"\"")
        && let Some(name) = find_name_quoted(line, strip)
    {
        return Some(name);
    }
    let len = line.find_byte(b'\n').unwrap_or(line.len());
    match timestamp_len(&line[..len]) {
        0 => find_name_common(line, default, strip, End::Tab),
        date => find_name_common(line, default, strip, End::At(len - date)),
    }
}

fn squash_slashes(name: &[u8]) -> BString {
    let mut out = BString::default();
    for &byte in name {
        if byte != b'/' || out.last() != Some(&b'/') {
            out.push(byte);
        }
    }
    out
}

fn is_dev_null(line: &[u8]) -> bool {
    line.strip_prefix(b"/dev/null")
        .is_some_and(|rest| rest.first().is_some_and(u8::is_ascii_whitespace))
}

/// The name that both sides of a `diff --git` line have, if they have the same one. Only
/// a header without any other line that names the file needs it.
fn git_header_name(strip: usize, line: &[u8]) -> Option<BString> {
    let line = line.strip_prefix(b"diff --git ")?;
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    if line.starts_with(b"\"") {
        let (first, used) = gix_quote::ansi_c::undo(line.as_bstr()).ok()?;
        let first = skip_tree_prefix(strip, &first)?;
        let second = line[used..].trim_start();
        let second = if second.starts_with(b"\"") {
            gix_quote::ansi_c::undo(second.as_bstr()).ok()?.0
        } else {
            second.as_bstr().into()
        };
        return (skip_tree_prefix(strip, &second)? == first).then(|| first.into());
    }
    let name = skip_tree_prefix(strip, line)?;
    // The first name has no quotes, so a quote starts the second one.
    if let Some(quote) = name.find_byte(b'"') {
        let (second, _) = gix_quote::ansi_c::undo(name[quote..].as_bstr()).ok()?;
        let second = skip_tree_prefix(strip, &second)?;
        let same = second.len() < quote
            && name.starts_with(second)
            && name[second.len()].is_ascii_whitespace();
        return same.then(|| second.into());
    }
    // Without quotes a name may have spaces. The line is "NAME NAME": try every space.
    for (len, _) in name
        .iter()
        .enumerate()
        .filter(|(_, byte)| matches!(byte, b' ' | b'\t'))
    {
        if let Some(second) = skip_tree_prefix(strip, &name[len + 1..])
            && second == &name[..len]
        {
            return Some(second.into());
        }
    }
    None
}

/// Remove `strip` leading directories from a name of a `diff --git` line.
fn skip_tree_prefix(strip: usize, name: &[u8]) -> Option<&[u8]> {
    if strip == 0 {
        return (!name.starts_with(b"/")).then_some(name);
    }
    let slash = name
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'/')
        .nth(strip - 1)?
        .0;
    (slash != 0).then(|| &name[slash + 1..])
}

/// The length of the date and time at the end of `line`, with the blank in front of it:
/// `2010-07-05 19:41:17`, or with a fraction and a zone as GNU diff writes it.
fn timestamp_len(line: &[u8]) -> usize {
    // In a pattern, `0` stands for any digit and `+` for either sign.
    let ends_with = |end: usize, pattern: &[u8]| {
        end >= pattern.len()
            && line[end - pattern.len()..end]
                .iter()
                .zip(pattern)
                .all(|(byte, expected)| match expected {
                    b'0' => byte.is_ascii_digit(),
                    b'+' => matches!(byte, b'+' | b'-'),
                    _ => byte == expected,
                })
    };
    if !line.last().is_some_and(u8::is_ascii_digit) {
        return 0;
    }
    let mut end = line.len();
    // The time zone, with or without a colon.
    if ends_with(end, b" +0000") {
        end -= 6;
    } else if ends_with(end, b" +00:00") {
        end -= 7;
    }
    // The time, with or without a fraction of a second.
    if ends_with(end, b" 00:00:00") {
        end -= 9;
    } else {
        let fraction = line[..end]
            .iter()
            .rposition(|byte| !byte.is_ascii_digit())
            .filter(|dot| line[*dot] == b'.' && *dot + 1 < end && ends_with(*dot, b" 00:00:00"));
        if let Some(dot) = fraction {
            end = dot - 9;
        }
    }
    // The date, with a year of two or four digits.
    if !ends_with(end, b"00-00-00") {
        return 0;
    }
    end -= 8;
    if end >= 2 && line[end - 2..end].iter().all(u8::is_ascii_digit) {
        end -= 2;
    }
    match line[..end].last() {
        Some(b'\t') => line.len() - (end - 1),
        // Spaces where a tab was: the patch went through a mail program.
        Some(b' ') => {
            let name_end = line[..end]
                .iter()
                .rposition(|byte| *byte != b' ')
                .map_or(0, |last| last + 1);
            line.len() - name_end
        }
        _ => 0,
    }
}

/// Whether the time on a `---` or `+++` line is the first second of 1970 in its zone,
/// which is how `diff` dates a file that does not exist.
fn has_epoch_timestamp(line: &[u8]) -> bool {
    let line = &line[..line.find_byte(b'\n').unwrap_or(line.len())];
    let Some(tab) = line.rfind_byte(b'\t') else {
        return false;
    };
    let stamp = &line[tab + 1..];
    let (epoch_hour, time) = if let Some(time) = stamp.strip_prefix(b"1969-12-31 ") {
        (24, time)
    } else if let Some(time) = stamp.strip_prefix(b"1970-01-01 ") {
        (0, time)
    } else {
        return false;
    };
    // HH:MM:00, an optional fraction of zeros, a blank, and the zone as +HHMM or +HH:MM.
    // Hours start with a digit up to 2 and minutes with one up to 5.
    let two = |text: &[u8], first: u8| match text.get(..2)? {
        [tens @ b'0'..=b'9', ones @ b'0'..=b'9'] if *tens <= first => {
            Some(i32::from(tens - b'0') * 10 + i32::from(ones - b'0'))
        }
        _ => None,
    };
    let (Some(hour), Some(minute)) = (two(time, b'2'), time.get(3..).and_then(|m| two(m, b'5')))
    else {
        return false;
    };
    if time.get(2) != Some(&b':') || time.get(5..8) != Some(b":00") {
        return false;
    }
    let mut zone = &time[8..];
    if let Some(fraction) = zone.strip_prefix(b".") {
        let zeros = fraction.iter().take_while(|byte| **byte == b'0').count();
        if zeros == 0 {
            return false;
        }
        zone = &fraction[zeros..];
    }
    let (negative, zone) = match zone {
        [b' ', b'+', zone @ ..] => (false, zone),
        [b' ', b'-', zone @ ..] => (true, zone),
        _ => return false,
    };
    let zone_minutes = match zone.len() {
        4 => two(zone, b'2').zip(two(&zone[2..], b'5')),
        5 if zone[2] == b':' => two(zone, b'2').zip(two(&zone[3..], b'5')),
        _ => None,
    };
    let Some((zone_hour, zone_minute)) = zone_minutes else {
        return false;
    };
    let offset = zone_hour * 60 + zone_minute;
    hour * 60 + minute - if negative { -offset } else { offset } == epoch_hour * 60
}

/// The lines of a file while hunks are applied to it, one hunk after the other.
pub struct Image<'a> {
    lines: Vec<&'a [u8]>,
    /// The lines that a hunk has put there. No later hunk may match them.
    patched: Vec<bool>,
}

impl<'a> Image<'a> {
    /// The lines of a file that has `contents`.
    pub fn new(contents: &'a [u8]) -> crate::Result<Self> {
        let newlines = contents.iter().filter(|byte| **byte == b'\n').count();
        let count = newlines + usize::from(!contents.is_empty() && !contents.ends_with(b"\n"));
        let mut lines = Vec::new();
        lines.try_reserve_exact(count)?;
        lines.extend(contents.split_inclusive(|byte| *byte == b'\n'));
        let mut patched = Vec::new();
        patched.try_reserve_exact(count)?;
        patched.resize(count, false);
        Ok(Image { lines, patched })
    }

    /// Apply `hunk`. `false`, with nothing changed, if its lines are not found.
    pub fn apply(&mut self, hunk: &Hunk<'a>) -> crate::Result<bool> {
        let side = |skip: Line| -> crate::Result<Vec<&'a [u8]>> {
            let mut lines = Vec::new();
            lines.try_reserve_exact(hunk.lines.len())?;
            let kept = hunk.lines.iter().filter(|(kind, _)| *kind != skip);
            lines.extend(kept.map(|(_, text)| *text));
            Ok(lines)
        };
        let (preimage, postimage) = (side(Line::Add)?, side(Line::Remove)?);
        // A hunk at the first line has to be at the start of the file, and a hunk
        // without context after its last change at the end.
        let at_start = hunk.old_start <= 1;
        let at_end = !matches!(hunk.lines.last(), Some((Line::Context, _)));
        let line = hunk.new_start.saturating_sub(1);
        let Some(at) = self.find(&preimage, line, at_start, at_end) else {
            return Ok(false);
        };
        let end = at + preimage.len();
        let growth = postimage.len().saturating_sub(preimage.len());
        self.lines.try_reserve(growth)?;
        self.patched.try_reserve(growth)?;
        self.lines.splice(at..end, postimage.iter().copied());
        self.patched.splice(at..end, postimage.iter().map(|_| true));
        Ok(true)
    }

    /// The contents of the file as the hunks leave it.
    pub fn into_contents(self) -> crate::Result<Vec<u8>> {
        let mut contents = Vec::new();
        contents.try_reserve_exact(self.lines.iter().map(|line| line.len()).sum())?;
        for line in self.lines {
            contents.extend_from_slice(line);
        }
        Ok(contents)
    }

    /// Whether the lines of `preimage` are at line `at`, and no hunk has put them there.
    fn matches(&self, preimage: &[&[u8]], at: usize) -> bool {
        let end = at + preimage.len();
        end <= self.lines.len()
            && !self.patched[at..end].contains(&true)
            && self.lines[at..end] == *preimage
    }

    /// Look for `preimage`, first at `line`, then one line down, one line up, two lines
    /// down, and so on. A hunk that has to be at the start or at the end of the file has
    /// one place only.
    fn find(&self, preimage: &[&[u8]], line: usize, at_start: bool, at_end: bool) -> Option<usize> {
        let last = self.lines.len();
        if at_start || at_end {
            let at = match at_start {
                true => 0,
                false => last.saturating_sub(preimage.len()),
            };
            // A hunk at the end has to end with the last line. At both ends at once, that
            // makes it the whole file.
            let fits = !at_end || at + preimage.len() == last;
            return (fits && self.matches(preimage, at)).then_some(at);
        }
        let line = line.min(last);
        if self.matches(preimage, line) {
            return Some(line);
        }
        (1..=last)
            .flat_map(|distance| [line.checked_add(distance), line.checked_sub(distance)])
            .flatten()
            .filter(|at| *at <= last)
            .find(|at| self.matches(preimage, *at))
    }
}

fn display(name: Option<&BString>) -> String {
    name.map_or_else(String::new, |name| {
        name.to_str_lossy().escape_debug().to_string()
    })
}

fn invalid(message: String) -> Box<dyn std::error::Error + Send + Sync> {
    io::Error::new(io::ErrorKind::InvalidData, message).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &str) -> crate::Result<Vec<Patch<'_>>> {
        Parser::new(None, b"").parse(input.as_bytes())
    }

    fn error(input: &str) -> String {
        let accepted = format!("the patch was accepted: {input}");
        parse(input).expect_err(&accepted).to_string()
    }

    fn names<'a>(patch: &'a Patch<'_>) -> (Option<&'a str>, Option<&'a str>) {
        let text = |name: &'a Option<BString>| name.as_ref().map(|name| name.to_str().unwrap());
        (text(&patch.old_name), text(&patch.new_name))
    }

    // The headers that `git diff` writes, with text around them as in a mail.
    #[test]
    fn git_headers() -> crate::Result {
        let patches = parse(concat!(
            "From: someone\nSubject: a change\n---\n file | 2 +-\n\n",
            "diff --git a/dir/file b/dir/file\nindex 1234567..89abcde 100755\n",
            "--- a/dir/file\n+++ b/dir/file\n@@ -1 +1 @@ heading\n-old\n+new\n",
            "diff --git a/with space b/with space\nnew file mode 100644\nindex 0000000..e69de29\n",
            "diff --git \"a/caf\\303\\251\" \"b/caf\\303\\251\"\ndeleted file mode 100644\n",
            "--- \"a/caf\\303\\251\"\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-one\n-two\n",
            "diff --git a/old name b/new name\nsimilarity index 90%\n",
            "rename from old name\nrename to new name\n",
            "--- a/old name\t\n+++ b/new name\t\n@@ -3,2 +3,3 @@\n context\n+added\n \n",
            "diff --git a/from b/to\ncopy from from\ncopy to to\n",
            "diff --git a/mode b/mode\nold mode 100644\nnew mode 100755\n",
            "-- \n2.43.0\n",
        ))?;
        let [modify, create, delete, rename, copy, mode] = &patches[..] else {
            panic!("{patches:?}");
        };
        assert_eq!(names(modify), (Some("dir/file"), Some("dir/file")));
        assert_eq!((modify.old_mode, modify.new_mode), (0o100755, 0));
        assert_eq!(
            (modify.old_id, modify.new_id),
            (&b"1234567"[..], &b"89abcde"[..])
        );
        assert_eq!(
            modify.hunks[0].lines,
            [(Line::Remove, &b"old\n"[..]), (Line::Add, b"new\n")]
        );

        assert_eq!(names(create), (None, Some("with space")));
        assert_eq!((create.is_new, create.new_mode), (Some(true), 0o100644));
        assert!(create.hunks.is_empty());
        assert_eq!(names(delete), (Some("caf\u{e9}"), None));
        assert_eq!((delete.is_delete, delete.old_mode), (Some(true), 0o100644));
        assert_eq!(names(rename), (Some("old name"), Some("new name")));
        assert!(rename.is_rename && !rename.is_copy);
        // An empty context line may come without its leading space.
        assert_eq!(rename.hunks[0].lines[2], (Line::Context, &b"\n"[..]));
        assert_eq!(names(copy), (Some("from"), Some("to")));
        assert!(copy.is_copy);
        assert_eq!((mode.old_mode, mode.new_mode), (0o100644, 0o100755));

        // `-p` removes that many leading directories.
        let stripped = Parser::new(Some(2), b"").parse(
            b"diff --git a/x/dir/file b/x/dir/file\n--- a/x/dir/file\n+++ b/x/dir/file\n@@ -1 +1 @@\n-a\n+b\n",
        )?;
        assert_eq!(names(&stripped[0]), (Some("dir/file"), Some("dir/file")));

        // Names that differ move the file, also without `rename from` and `rename to`.
        let moved = parse("diff --git a/f b/g\n--- a/f\n+++ b/g\n@@ -1 +1 @@\n-a\n+b\n")?;
        assert_eq!(names(&moved[0]), (Some("f"), Some("g")));
        assert!(moved[0].is_rename);
        Ok(())
    }

    #[test]
    fn hunk_headers_and_lines_without_newline() -> crate::Result {
        let patches = parse(concat!(
            "diff --git a/f b/f\n--- a/f\n+++ b/f\n",
            "@@ -1,2 +1,2 @@\n one\n-two\n\\ No newline at end of file\n+TWO\n",
            "@@ -7,0 +8 @@\n+last\n\\ No newline at end of file\n",
        ))?;
        let hunks = &patches[0].hunks;
        assert_eq!((hunks[0].old_start, hunks[0].old_lines), (1, 2));
        assert_eq!(
            hunks[0].lines,
            [
                (Line::Context, &b"one\n"[..]),
                (Line::Remove, b"two"),
                (Line::Add, b"TWO\n")
            ]
        );
        assert_eq!((hunks[1].old_start, hunks[1].old_lines), (7, 0));
        assert_eq!((hunks[1].new_start, hunks[1].new_lines), (8, 1));
        assert_eq!(hunks[1].lines, [(Line::Add, &b"last"[..])]);
        Ok(())
    }

    // Patches as `diff -u` writes them have no header from Git.
    #[test]
    fn traditional_headers() -> crate::Result {
        let read_hunk = |prefix: &[u8], strip, header: &str, hunk: &str| -> crate::Result<_> {
            let text = format!("{header}{hunk}");
            let patches = Parser::new(strip, prefix).parse(text.as_bytes())?;
            let (old, new) = names(&patches[0]);
            Ok((
                old.map(str::to_owned),
                new.map(str::to_owned),
                patches[0].is_new,
                patches[0].is_delete,
            ))
        };
        let read = |prefix: &[u8], strip, header: &str| {
            read_hunk(prefix, strip, header, "@@ -1 +1 @@\n-a\n+b\n")
        };
        let both = |name: &str| {
            let name = Some(name.to_owned());
            (name.clone(), name, Some(false), Some(false))
        };
        // One leading directory goes by default. A time after the name is not part of it.
        let stamp = "2026-01-02 03:04:05.123456789 +0100";
        assert_eq!(
            read(
                b"",
                None,
                &format!("--- a/dir/f\t{stamp}\n+++ b/dir/f\t{stamp}\n")
            )?,
            both("dir/f")
        );
        assert_eq!(
            read(
                b"",
                None,
                "--- old/f 2026-01-02 03:04:05\n+++ new/f 2026-01-02 03:04:06\n"
            )?,
            both("f")
        );
        // The shorter name is the file: the other one is a backup of it.
        assert_eq!(read(b"", None, "--- f.orig\n+++ f\n")?, both("f"));
        assert_eq!(read(b"", None, "--- a/f\n+++ b/f.new\n")?, both("f"));
        // A name without a directory keeps all of it, and it is relative to the
        // directory that the command was started in.
        assert_eq!(read(b"sub/", None, "--- f\n+++ f\n")?, both("sub/f"));
        assert_eq!(
            read(b"sub/", None, "--- a/sub/f\n+++ b/sub/f\n")?,
            both("sub/f")
        );
        assert_eq!(read(b"", Some(0), "--- a/f\n+++ a/f\n")?, both("a/f"));
        // `/dev/null`, or the first second of 1970, stands for a file that is not there.
        let created = (None, Some("f".to_owned()), Some(true), Some(false));
        let create = "@@ -0,0 +1 @@\n+b\n";
        assert_eq!(
            read_hunk(b"", None, "--- /dev/null\n+++ b/f\n", create)?,
            created
        );
        let epoch =
            "--- a/f\t1970-01-01 01:00:00.000000000 +0100\n+++ b/f\t2026-01-02 03:04:05 +0000\n";
        assert_eq!(read_hunk(b"", None, epoch, create)?, created);
        let west = "--- a/f\t2026-01-02 03:04:05 +0000\n+++ b/f\t1969-12-31 16:00:00 -0800\n";
        assert_eq!(
            read_hunk(b"", None, west, "@@ -1 +0,0 @@\n-a\n")?,
            (Some("f".to_owned()), None, Some(false), Some(true))
        );
        // Another time on that day is a time like any other.
        let later = "--- a/f\t1970-01-01 01:00:00 +0000\n+++ b/f\t2026-01-02 03:04:05 +0000\n";
        assert_eq!(read(b"", None, later)?, both("f"));
        // A patch without old lines may create its file. Whether it does shows later.
        let patches = parse("--- a/f\n+++ b/f\n@@ -0,0 +1 @@\n+a\n")?;
        assert_eq!(
            (patches[0].is_new, patches[0].is_delete),
            (None, Some(false))
        );
        Ok(())
    }

    #[test]
    fn damaged_patches_are_refused() {
        let binary = "diff --git a/bin b/bin\nnew file mode 100644\nGIT binary patch\n";
        assert_eq!(error(binary), "binary patch at line 3 is unsupported");
        let header = "diff --git a/f b/f\n--- a/f\n+++ b/f\n";
        for (patch, expected) in [
            (
                format!("{header}@@ -1 +1 @@\n-a\n+b"),
                "corrupt patch at line 6",
            ),
            (
                format!("{header}@@ -1,2 +1 @@\n-a\n+b\n"),
                "corrupt patch at line 7",
            ),
            (
                format!("{header}@@ -1 +1 @@\n a\n"),
                "corrupt patch at line 6",
            ),
            (
                format!("{header}@@ -1 +1 @@\n-a\nb\n"),
                "corrupt patch at line 6",
            ),
            (
                "@@ -1 +1 @@\n-a\n+b\n".to_owned(),
                "patch fragment without header at line 1: @@ -1 +1 @@",
            ),
            (
                "diff --git a/f b/f\nindex 1234567..89abcde 100644\ntext\n".to_owned(),
                "patch with only garbage at line 3",
            ),
            // The newline after the name was lost: names that differ, and no hunk.
            (
                "diff --git a/f b/f\n--- a/f\n+++ b/f@@ -1 +1 @@\n-a\n+b\n".to_owned(),
                "patch with only garbage at line 4",
            ),
            (
                "diff --git a/f b/g\nsome text\n".to_owned(),
                "git diff header lacks filename information when removing 1 leading pathname component (line 2)",
            ),
            (
                "diff --git a/f b/f\nnew file mode 100644\n--- /dev/null\n+++ b/g\n".to_owned(),
                "bad git-diff - inconsistent new filename on line 4",
            ),
            (
                "diff --git a/f b/f\nnew file mode 100644\n--- a/f\n+++ b/f\n".to_owned(),
                "bad git-diff - expected /dev/null on line 3",
            ),
            (
                "diff --git a/f b/f\nnew file mode 100644\ndeleted file mode 100644\n".to_owned(),
                "inconsistent header lines 2 and 3",
            ),
            (
                "diff --git a/f b/f\nold mode 10x\n".to_owned(),
                "invalid mode on line 2: 10x",
            ),
            (
                format!(
                    "{}@@ -1 +1 @@\n-a\n+b\n",
                    header.replace("--- a/f", "new file mode 100644\n--- /dev/null")
                ),
                "new file f depends on old contents",
            ),
        ] {
            assert_eq!(error(&patch), expected, "{patch}");
        }
        // Text that only looks like a header is no patch.
        assert!(parse("diff --git a/f b/f\nsome text\n").unwrap().is_empty());
        assert!(
            parse("--- a/f\n+++ b/f\nsome text, no hunk\n")
                .unwrap()
                .is_empty()
        );
    }

    /// Apply `hunks` to `contents`. The error is where the hunk that does not match starts.
    fn apply<'a>(contents: &'a [u8], hunks: &[Hunk<'a>]) -> Result<Vec<u8>, usize> {
        let mut image = Image::new(contents).unwrap();
        for hunk in hunks {
            if !image.apply(hunk).unwrap() {
                return Err(hunk.old_start);
            }
        }
        Ok(image.into_contents().unwrap())
    }

    fn patched(contents: &str, hunks: &str) -> Result<String, usize> {
        let text = format!("diff --git a/f b/f\n--- a/f\n+++ b/f\n{hunks}");
        let patches = parse(&text).unwrap();
        apply(contents.as_bytes(), &patches[0].hunks)
            .map(|result| String::from_utf8(result).unwrap())
    }

    #[test]
    fn hunks_are_found_where_git_finds_them() {
        let file = "1\n2\n3\n4\n5\n6\n7\n8\n9\n";
        // Where the header says.
        assert_eq!(
            patched(file, "@@ -4,3 +4,3 @@\n 4\n-5\n+five\n 6\n").unwrap(),
            "1\n2\n3\n4\nfive\n6\n7\n8\n9\n"
        );
        // Further down and further up than the header says.
        assert_eq!(
            patched(file, "@@ -2,3 +2,3 @@\n 6\n-7\n+seven\n 8\n").unwrap(),
            "1\n2\n3\n4\n5\n6\nseven\n8\n9\n"
        );
        assert_eq!(
            patched(file, "@@ -40,3 +40,2 @@\n 2\n-3\n 4\n").unwrap(),
            "1\n2\n4\n5\n6\n7\n8\n9\n"
        );
        // Of two places, the one nearer to the header; below it if both are as near.
        let twice = "a\nx\nb\nc\nd\na\nx\nb\n";
        assert_eq!(
            patched(twice, "@@ -5,3 +5,3 @@\n a\n-x\n+X\n b\n").unwrap(),
            "a\nx\nb\nc\nd\na\nX\nb\n"
        );
        assert_eq!(
            patched(twice, "@@ -3,3 +3,3 @@\n a\n-x\n+X\n b\n").unwrap(),
            "a\nX\nb\nc\nd\na\nx\nb\n"
        );
        // A hunk at line 1 has to be at the start, and one without context after its
        // last change at the end.
        assert_eq!(patched(file, "@@ -1,2 +1,2 @@\n-6\n+six\n 7\n"), Err(1));
        assert_eq!(patched(file, "@@ -5,2 +5,2 @@\n 5\n-6\n+six\n"), Err(5));
        assert_eq!(
            patched(file, "@@ -8,2 +8,3 @@\n 8\n 9\n+10\n").unwrap(),
            "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n"
        );
        // Context that differs, also by a blank, does not match.
        assert_eq!(
            patched(file, "@@ -4,3 +4,3 @@\n 4 \n-5\n+five\n 6\n"),
            Err(4)
        );
        // A later hunk does not match lines that an earlier one has written.
        let repeated = "x\ny\nx\ny\n";
        let hunk = "@@ -2,3 +2,3 @@\n y\n-x\n+X\n y\n";
        assert_eq!(patched(repeated, &format!("{hunk}{hunk}")), Err(2));
        // Creating, emptying, and the newline at the end.
        assert_eq!(patched("", "@@ -0,0 +1,2 @@\n+a\n+b\n").unwrap(), "a\nb\n");
        assert_eq!(patched("a\nb\n", "@@ -1,2 +0,0 @@\n-a\n-b\n").unwrap(), "");
        assert_eq!(patched("a\nb\nc\n", "@@ -1,2 +0,0 @@\n-a\n-b\n"), Err(1));
        let no_newline = "\\ No newline at end of file\n";
        assert_eq!(
            patched(
                "a\nb",
                &format!("@@ -1,2 +1,2 @@\n a\n-b\n{no_newline}+b\n")
            )
            .unwrap(),
            "a\nb\n"
        );
        assert_eq!(
            patched(
                "a\nb\n",
                &format!("@@ -1,2 +1,2 @@\n a\n-b\n+B\n{no_newline}")
            )
            .unwrap(),
            "a\nB"
        );
        // A line that the patch has without a newline is the last line of the file only.
        assert_eq!(
            patched(
                "a\nb\nc\n",
                &format!("@@ -1,2 +1,2 @@\n-a\n+A\n b\n{no_newline}")
            ),
            Err(1)
        );
    }

    #[test]
    fn reversed_patches_undo() {
        let before = "1\n2\n3\n4\n5\n";
        let text = "diff --git a/f b/g\nold mode 100644\nnew mode 100755\nrename from f\nrename to g\n\
                    --- a/f\n+++ b/g\n@@ -2,3 +2,4 @@\n 2\n-3\n+three\n+more\n 4\n";
        let mut patches = parse(text).unwrap();
        let after = apply(before.as_bytes(), &patches[0].hunks).unwrap();
        assert_eq!(after, b"1\n2\nthree\nmore\n4\n5\n");
        patches[0].reverse();
        let patch = &patches[0];
        assert_eq!(names(patch), (Some("g"), Some("f")));
        assert_eq!((patch.old_mode, patch.new_mode), (0o100755, 0o100644));
        assert_eq!((patch.hunks[0].old_lines, patch.hunks[0].new_lines), (4, 3));
        assert_eq!(apply(&after, &patch.hunks).unwrap(), before.as_bytes());

        let mut created = parse(
            "diff --git a/f b/f\nnew file mode 100644\n--- /dev/null\n+++ b/f\n@@ -0,0 +1 @@\n+a\n",
        )
        .unwrap();
        created[0].reverse();
        assert_eq!(names(&created[0]), (Some("f"), None));
        assert_eq!(
            (created[0].is_new, created[0].is_delete),
            (Some(false), Some(true))
        );
        assert_eq!(created[0].old_mode, 0o100644);
    }
}
