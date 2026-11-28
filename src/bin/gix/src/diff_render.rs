use std::io::{self, Write};

use gix::{
    bstr::{BStr, ByteSlice},
    diff::blob::{
        Algorithm, InternedInput, TokenSource, UnifiedDiff, diff_with_slider_heuristics, sources,
        unified_diff::{ConsumeHunk, ContextSize, DiffLineKind, HunkHeader},
    },
};

use crate::cancellation::Cancellation;

pub const MAX_TEXT_LINES: u32 = 262_144;

#[derive(Clone, Copy)]
struct ExactLines<'a> {
    bytes: &'a [u8],
    count: u32,
}

impl<'a> TokenSource for ExactLines<'a> {
    type Token = &'a [u8];
    type Tokenizer = sources::ByteLines<'a>;

    fn tokenize(&self) -> Self::Tokenizer {
        sources::byte_lines(self.bytes)
    }

    fn estimate_tokens(&self) -> u32 {
        self.count
    }
}

/// A bounded text diff whose validation and computation completed before output.
pub struct PreparedText<'a> {
    input: InternedInput<&'a [u8]>,
    diff: gix::diff::blob::Diff,
}

/// Validate and compute one bounded text pair without producing output.
///
/// `before` and `after` must come from [`crate::diff_input::Loader`]. Callers may safely write
/// this file's metadata only after this function succeeds.
pub fn prepare_text<'a>(
    path: &BStr,
    before: &'a [u8],
    after: &'a [u8],
    algorithm: Algorithm,
    cancellation: &Cancellation,
) -> crate::Result<PreparedText<'a>> {
    cancellation.check()?;
    if algorithm == Algorithm::MyersMinimal {
        return Err(
            unsupported(path, "the configured minimal diff algorithm is unsupported").into(),
        );
    }
    let before = exact_lines(path, "before", before)?;
    let after = exact_lines(path, "after", after)?;
    cancellation.check()?;
    let input = InternedInput::new(before, after);
    cancellation.check()?;
    let diff = diff_with_slider_heuristics(algorithm, &input);
    cancellation.check()?;
    Ok(PreparedText { input, diff })
}

impl PreparedText<'_> {
    pub fn is_empty(&self) -> bool {
        self.diff.count_removals() == 0 && self.diff.count_additions() == 0
    }

    /// Stream this diff with already-quoted labels to buffered output.
    pub fn write_to(
        self,
        labels: (&[u8], &[u8]),
        cancellation: &Cancellation,
        out: &mut impl Write,
    ) -> crate::Result {
        if self.is_empty() {
            return cancellation.check();
        }

        for (marker, label) in [(b"--- ", labels.0), (b"+++ ", labels.1)] {
            cancellation.check()?;
            out.write_all(marker)?;
            out.write_all(label)?;
            // As Git: a tab ends a name with a space, so that `patch` does not stop at the space.
            if label.contains(&b' ') {
                out.write_all(b"\t")?;
            }
            out.write_all(b"\n")?;
        }
        UnifiedDiff::new(
            &self.diff,
            &self.input,
            HunkWriter {
                out: &mut *out,
                cancellation,
                input: &self.input,
                searched: 0,
                heading: b"",
            },
            ContextSize::symmetrical(3),
        )
        .consume()?;
        out.flush()?;
        cancellation.check()
    }
}

fn exact_lines<'a>(path: &BStr, side: &str, bytes: &'a [u8]) -> io::Result<ExactLines<'a>> {
    let newline_count = bytes.iter().filter(|byte| **byte == b'\n').count();
    let count = newline_count + usize::from(!bytes.is_empty() && !bytes.ends_with(b"\n"));
    if count > MAX_TEXT_LINES as usize {
        return Err(unsupported(
            path,
            &format!("{side} text exceeds the {MAX_TEXT_LINES}-line limit"),
        ));
    }
    Ok(ExactLines {
        bytes,
        count: count as u32,
    })
}

/// Git's `xdl_emit_hunk_hdr()` builds a hunk header in a buffer of this size.
const HEADER_BYTES: usize = 128;
/// Git keeps this much of the line that it shows after the second `@@`.
const HEADING_BYTES: usize = 80;

struct HunkWriter<'a, W> {
    out: &'a mut W,
    cancellation: &'a Cancellation,
    input: &'a InternedInput<&'a [u8]>,
    /// How many of the old lines have been searched for a heading.
    searched: usize,
    /// The heading of the hunks so far, which a hunk keeps if it finds none of its own.
    heading: &'a [u8],
}

impl<'a, W> HunkWriter<'a, W> {
    /// Find the line that Git shows after the second `@@`: the nearest line before the
    /// hunk that starts with a letter, `_` or `$`, as most function definitions do.
    fn find_heading(&mut self, hunk_start: usize) {
        for line in (self.searched..hunk_start).rev() {
            let text = self.input.interner[self.input.before[line]];
            if text
                .first()
                .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$'))
            {
                let text = &text[..text.len().min(HEADING_BYTES)];
                let end = text
                    .iter()
                    .rposition(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
                    .map_or(0, |last| last + 1);
                self.heading = &text[..end];
                break;
            }
        }
        self.searched = self.searched.max(hunk_start);
    }
}

/// Format one side of a hunk header as Git does: a side without lines names the line
/// before it, and a count of one is left out.
fn range(start: u32, lines: u32) -> String {
    match lines {
        0 => format!("{},0", start - 1),
        1 => start.to_string(),
        _ => format!("{start},{lines}"),
    }
}

impl<W: Write> ConsumeHunk for HunkWriter<'_, W> {
    type Out = ();

    fn consume_hunk(
        &mut self,
        header: HunkHeader,
        lines: &[(DiffLineKind, &[u8])],
    ) -> io::Result<()> {
        check(self.cancellation)?;
        let ranges = format!(
            "@@ -{} +{} @@",
            range(header.before_hunk_start, header.before_hunk_len),
            range(header.after_hunk_start, header.after_hunk_len)
        );
        self.out.write_all(ranges.as_bytes())?;
        self.find_heading(header.before_hunk_start as usize - 1);
        // The space, the heading and the newline have to fit into Git's buffer.
        let room = HEADER_BYTES.saturating_sub(ranges.len() + 2);
        let heading = &self.heading[..self.heading.len().min(room)];
        if !heading.is_empty() {
            self.out.write_all(b" ")?;
            self.out.write_all(heading)?;
        }
        self.out.write_all(b"\n")?;
        for &(kind, line) in lines {
            check(self.cancellation)?;
            self.out.write_all(&[kind.to_prefix() as u8])?;
            self.out.write_all(line)?;
            if !line.ends_with(b"\n") {
                check(self.cancellation)?;
                self.out.write_all(b"\n\\ No newline at end of file\n")?;
            }
        }
        check(self.cancellation)
    }

    fn finish(self) {}
}

fn check(cancellation: &Cancellation) -> io::Result<()> {
    cancellation.check().map_err(io::Error::other)
}

fn unsupported(path: &BStr, message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "cannot diff '{}': {message}",
            path.to_str_lossy().escape_debug()
        ),
    )
}
