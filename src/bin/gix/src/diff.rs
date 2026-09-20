use std::{
    cmp::Ordering,
    io::{self, BufWriter, Write},
};

use gix::{
    bstr::{BStr, ByteSlice},
    index::entry::{Mode, Stage},
    worktree::stack::state::attributes::Source as AttributeSource,
};

use crate::{
    cancellation::Cancellation,
    diff_input::{Loaded, Loader, Pair, Source as DiffSource},
    diff_policy::{BinaryMode, PathPolicy, Resolver},
    diff_render,
    repository::OpenedRepository,
    selection::{self, Selection},
    tracked_filters, tree_index,
};

/// Write selected worktree-versus-index or index-versus-HEAD differences.
pub fn run(
    opened: &OpenedRepository,
    staged: bool,
    paths: &[String],
    cancellation: &Cancellation,
    out: impl Write,
) -> crate::Result {
    let repo = &opened.repo;
    let workdir = repo
        .workdir()
        .ok_or_else(|| invalid("diff requires a worktree"))?;
    let selection = if paths.is_empty() {
        Selection::all()
    } else {
        Selection::from_paths(workdir, paths)?
    };

    cancellation.check()?;
    let index = repo.index_or_empty()?;
    index.verify_entries()?;
    let head = if staged {
        let tree = repo.head_tree_id_or_empty()?.detach();
        let head = tree_index::build(repo, &tree, workdir, cancellation)?;
        Some(head)
    } else {
        None
    };

    let mut matched = Vec::new();
    matched.try_reserve_exact(selection.paths().len())?;
    matched.resize(selection.paths().len(), false);
    preflight_index(&index, &selection, workdir, &mut matched, cancellation)?;
    if let Some(head) = &head {
        preflight_index(head, &selection, workdir, &mut matched, cancellation)?;
    }
    for (path, matched) in selection.paths().iter().zip(matched) {
        if !matched {
            return Err(invalid(format!(
                "explicit path '{}' did not match a tracked path",
                path.to_str_lossy().escape_debug()
            ))
            .into());
        }
    }
    if !staged {
        reject_worktree_filters(opened, &index, &selection, workdir, cancellation)?;
    }

    let mut out = BufWriter::new(out);
    let mut loader = Loader::new(opened, &index);
    let mut resolver = Resolver::new(opened, &index)?;
    if let Some(head) = &head {
        render_staged(
            head,
            &index,
            &selection,
            &mut loader,
            &mut resolver,
            cancellation,
            &mut out,
        )?;
    } else {
        render_worktree(
            &index,
            &selection,
            &mut loader,
            &mut resolver,
            cancellation,
            &mut out,
        )?;
    }
    cancellation.check()?;
    out.flush()?;
    cancellation.check()
}

fn preflight_index(
    index: &gix::index::State,
    selection: &Selection,
    workdir: &std::path::Path,
    matched: &mut [bool],
    cancellation: &Cancellation,
) -> crate::Result {
    for entry in index.entries() {
        cancellation.check()?;
        let path = entry.path(index);
        if !selection.selects(path) {
            continue;
        }
        selection::validate_normalized(path, workdir)?;
        for (requested, matched) in selection.paths().iter().zip(&mut *matched) {
            if selection::contains(requested.as_bstr(), path) {
                *matched = true;
            }
        }
        // verify_entries() already rejects duplicate path/stage pairs and enforces stage order.
        if entry.stage() != Stage::Unconflicted {
            return Err(path_error(path, "the index entry is conflicted").into());
        }
    }
    Ok(())
}

fn reject_worktree_filters(
    opened: &OpenedRepository,
    index: &gix::index::State,
    selection: &Selection,
    workdir: &std::path::Path,
    cancellation: &Cancellation,
) -> crate::Result {
    let mut candidates = Vec::new();
    for entry in index.entries() {
        cancellation.check()?;
        let path = entry.path(index);
        if selection.selects(path)
            && matches!(entry.mode, Mode::FILE | Mode::FILE_EXECUTABLE)
            && selection::checked_symlink_metadata(workdir, path)?
                .is_some_and(|meta| meta.is_file())
        {
            candidates.try_reserve(1)?;
            candidates.push(entry);
        }
    }
    tracked_filters::reject_unsupported_selected(
        opened,
        index,
        AttributeSource::WorktreeThenIdMapping,
        candidates
            .into_iter()
            .map(|entry| (entry.path(index), entry.mode)),
        cancellation,
    )
}

fn render_worktree(
    index: &gix::index::State,
    selection: &Selection,
    loader: &mut Loader<'_, '_>,
    resolver: &mut Resolver<'_>,
    cancellation: &Cancellation,
    out: &mut impl Write,
) -> crate::Result {
    for entry in index.entries() {
        cancellation.check()?;
        let path = entry.path(index);
        if !selection.selects(path) {
            continue;
        }
        let pair = loader.load_pair(
            path,
            object(entry),
            DiffSource::Worktree {
                index_id: entry.id,
                index_mode: entry.mode,
            },
            cancellation,
        )?;
        render_pair(path, pair, resolver, cancellation, out)?;
    }
    Ok(())
}

fn render_staged(
    head: &gix::index::State,
    index: &gix::index::State,
    selection: &Selection,
    loader: &mut Loader<'_, '_>,
    resolver: &mut Resolver<'_>,
    cancellation: &Cancellation,
    out: &mut impl Write,
) -> crate::Result {
    // Advance unselected entries here too so every scan step checks cancellation.
    let mut old = head.entries().iter().peekable();
    let mut new = index.entries().iter().peekable();
    loop {
        cancellation.check()?;
        let ordering = match (old.peek(), new.peek()) {
            (None, None) => break,
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some(old), Some(new)) => old.path(head).cmp(new.path(index)),
        };
        let (path, old_source, new_source) = match ordering {
            Ordering::Less => {
                let old = old.next().expect("peeked above");
                (old.path(head), object(old), DiffSource::Missing)
            }
            Ordering::Greater => {
                let new = new.next().expect("peeked above");
                (new.path(index), DiffSource::Missing, object(new))
            }
            Ordering::Equal => {
                let old = old.next().expect("peeked above");
                let new = new.next().expect("peeked above");
                if old.id == new.id && old.mode == new.mode {
                    continue;
                }
                (old.path(head), object(old), object(new))
            }
        };
        if !selection.selects(path) {
            continue;
        }
        let pair = loader.load_pair(path, old_source, new_source, cancellation)?;
        render_pair(path, pair, resolver, cancellation, out)?;
    }
    Ok(())
}

fn object(entry: &gix::index::Entry) -> DiffSource {
    DiffSource::Object {
        id: entry.id,
        mode: entry.mode,
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn path_error(path: &BStr, message: &str) -> io::Error {
    invalid(format!(
        "cannot diff '{}': {message}",
        path.to_str_lossy().escape_debug()
    ))
}

/// Render one pair obtained from the diff loader.
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
