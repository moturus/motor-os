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

/// Render one bounded text pair as a unified diff.
///
/// `labels` must already be escaped for terminal output, and `before` and `after` must come from
/// the bounded [`crate::diff_input::Loader`] (at most 16 MiB per side). The caller should provide
/// buffered output.
pub fn render_text(
    path: &BStr,
    labels: (&[u8], &[u8]),
    before: &[u8],
    after: &[u8],
    algorithm: Algorithm,
    cancellation: &Cancellation,
    out: &mut impl Write,
) -> crate::Result {
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
    if diff.count_removals() == 0 && diff.count_additions() == 0 {
        return Ok(());
    }

    let (before_label, after_label) = labels;
    cancellation.check()?;
    out.write_all(b"--- ")?;
    out.write_all(before_label)?;
    out.write_all(b"\n")?;
    cancellation.check()?;
    out.write_all(b"+++ ")?;
    out.write_all(after_label)?;
    out.write_all(b"\n")?;
    UnifiedDiff::new(
        &diff,
        &input,
        HunkWriter {
            out: &mut *out,
            cancellation,
        },
        ContextSize::symmetrical(3),
    )
    .consume()?;
    out.flush()?;
    cancellation.check()
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

struct HunkWriter<'a, W> {
    out: &'a mut W,
    cancellation: &'a Cancellation,
}

impl<W: Write> ConsumeHunk for HunkWriter<'_, W> {
    type Out = ();

    fn consume_hunk(
        &mut self,
        header: HunkHeader,
        lines: &[(DiffLineKind, &[u8])],
    ) -> io::Result<()> {
        check(self.cancellation)?;
        writeln!(self.out, "{header}")?;
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
