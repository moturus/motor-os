use std::io::{self, Write};

use gix::{
    bstr::{BStr, ByteSlice},
    index::entry::Mode,
};

use crate::{
    cancellation::Cancellation,
    diff_input::{Loaded, Pair},
    diff_policy::{BinaryMode, PathPolicy, Resolver},
    diff_render,
};

/// Render one pair obtained from the bounded diff loader.
///
/// Text validation and computation complete before this function writes the file preamble.
pub fn render_pair(
    path: &BStr,
    pair: Pair,
    resolver: &mut Resolver<'_>,
    cancellation: &Cancellation,
    out: &mut impl Write,
) -> crate::Result {
    cancellation.check()?;
    if pair.old == pair.new {
        return Ok(());
    }

    let old_mode = mode(&pair.old);
    let new_mode = mode(&pair.new);
    let escaped = path.to_str_lossy().escape_debug().to_string();
    let labels = (
        label(&pair.old, 'a', &escaped),
        label(&pair.new, 'b', &escaped),
    );

    if matches!(&pair.old, Loaded::Gitlink { .. }) || matches!(&pair.new, Loaded::Gitlink { .. }) {
        write_header(&escaped, old_mode, new_mode, cancellation, out)?;
        writeln!(
            out,
            "Gitlinks {} ({}) and {} ({}) differ",
            labels.0,
            gitlink_state(&pair.old),
            labels.1,
            gitlink_state(&pair.new)
        )?;
        return cancellation.check();
    }

    let before = bytes(&pair.old);
    let after = bytes(&pair.new);
    if before == after {
        write_header(&escaped, old_mode, new_mode, cancellation, out)?;
        return cancellation.check();
    }

    let raw_symlink = old_mode == Some(Mode::SYMLINK) || new_mode == Some(Mode::SYMLINK);
    let policy = if raw_symlink {
        PathPolicy {
            algorithm: resolver.default_algorithm(),
            binary: BinaryMode::Text,
        }
    } else {
        resolver.resolve(
            path,
            new_mode.or(old_mode).expect("a changed pair has one side"),
            cancellation,
        )?
    };
    if policy.binary.is_binary(before, after) {
        write_header(&escaped, old_mode, new_mode, cancellation, out)?;
        writeln!(out, "Binary files {} and {} differ", labels.0, labels.1)?;
        return cancellation.check();
    }

    let prepared = diff_render::prepare_text(path, before, after, policy.algorithm, cancellation)?;
    write_header(&escaped, old_mode, new_mode, cancellation, out)?;
    prepared.write_to(
        (labels.0.as_bytes(), labels.1.as_bytes()),
        cancellation,
        out,
    )
}

fn mode(input: &Loaded) -> Option<Mode> {
    match input {
        Loaded::Missing => None,
        Loaded::Gitlink { .. } => Some(Mode::COMMIT),
        Loaded::Blob { mode, .. } => Some(*mode),
    }
}

fn bytes(input: &Loaded) -> &[u8] {
    match input {
        Loaded::Missing => b"",
        Loaded::Blob { bytes, .. } => bytes,
        Loaded::Gitlink { .. } => unreachable!("gitlinks are handled before content"),
    }
}

fn label(input: &Loaded, side: char, escaped: &str) -> String {
    if matches!(input, Loaded::Missing) {
        "/dev/null".into()
    } else {
        format!("{side}/{escaped}")
    }
}

fn gitlink_state(input: &Loaded) -> String {
    match input {
        Loaded::Missing => "absent".into(),
        Loaded::Gitlink { id } => id.to_string(),
        Loaded::Blob { .. } => "non-gitlink".into(),
    }
}

fn write_header(
    escaped: &str,
    old_mode: Option<Mode>,
    new_mode: Option<Mode>,
    cancellation: &Cancellation,
    out: &mut impl Write,
) -> io::Result<()> {
    check(cancellation)?;
    writeln!(out, "diff --git a/{escaped} b/{escaped}")?;
    match (old_mode, new_mode) {
        (None, Some(mode)) => writeln!(out, "new file mode {:o}", mode.bits())?,
        (Some(mode), None) => writeln!(out, "deleted file mode {:o}", mode.bits())?,
        (Some(old), Some(new)) if old != new => {
            writeln!(out, "old mode {:o}", old.bits())?;
            check(cancellation)?;
            writeln!(out, "new mode {:o}", new.bits())?;
        }
        _ => {}
    }
    check(cancellation)
}

fn check(cancellation: &Cancellation) -> io::Result<()> {
    cancellation.check().map_err(io::Error::other)
}
