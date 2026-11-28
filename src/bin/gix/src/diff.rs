use std::{
    borrow::Cow,
    cmp::Ordering,
    io::{self, BufWriter, Write},
};

use gix::{
    bstr::{BStr, ByteSlice},
    index::entry::{Flags, Mode, Stage},
    worktree::stack::state::attributes::Source as AttributeSource,
};

use crate::{
    cancellation::Cancellation,
    diff_input::{Loaded, Loader, Pair, Source as DiffSource},
    diff_policy::{BinaryMode, PathPolicy, Resolver},
    diff_render, patch,
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
        Selection::from_paths(workdir, opened.prefix.as_bstr(), paths)?
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
    let sparse_checkout = !staged
        && repo
            .config_snapshot()
            .try_boolean("core.sparseCheckout")?
            .unwrap_or(false);
    // In a sparse checkout, a file brought back into the worktree is visible to Git.
    let worktree_entries = index.entries().iter().filter(|entry| {
        selection.selects(entry.path(&index))
            && (sparse_checkout || !entry.flags.contains(Flags::SKIP_WORKTREE))
    });
    if !staged {
        reject_worktree_filters(
            opened,
            &index,
            worktree_entries.clone(),
            workdir,
            cancellation,
        )?;
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
            worktree_entries,
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

fn reject_worktree_filters<'a>(
    opened: &OpenedRepository,
    index: &gix::index::State,
    entries: impl Iterator<Item = &'a gix::index::Entry>,
    workdir: &std::path::Path,
    cancellation: &Cancellation,
) -> crate::Result {
    let mut candidates = Vec::new();
    for entry in entries {
        cancellation.check()?;
        let path = entry.path(index);
        if matches!(entry.mode, Mode::FILE | Mode::FILE_EXECUTABLE)
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

fn render_worktree<'a>(
    index: &gix::index::State,
    entries: impl Iterator<Item = &'a gix::index::Entry>,
    loader: &mut Loader<'_, '_>,
    resolver: &mut Resolver<'_>,
    cancellation: &Cancellation,
    out: &mut impl Write,
) -> crate::Result {
    for entry in entries {
        cancellation.check()?;
        let path = entry.path(index);
        let new = loader.load_source(
            path,
            DiffSource::Worktree {
                index_id: entry.id,
                index_mode: entry.mode,
            },
            cancellation,
        )?;
        if new == Loaded::Missing && entry.flags.contains(Flags::SKIP_WORKTREE) {
            continue;
        }
        // Git shows an intent-to-add file as new while present. Once removed,
        // the deletion has the empty blob and mode recorded in the index.
        let source = if entry.flags.contains(Flags::INTENT_TO_ADD) && new != Loaded::Missing {
            DiffSource::Missing
        } else {
            object(entry)
        };
        let old = loader.load_source(path, source, cancellation)?;
        render(
            path,
            Pair { old, new },
            (known_id(source), None),
            resolver,
            cancellation,
            out,
        )?;
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
    // As Git: a file that `git add -N` only announced is not staged.
    let staged = |entry: &&gix::index::Entry| !entry.flags.contains(Flags::INTENT_TO_ADD);
    let mut new = index.entries().iter().filter(staged).peekable();
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
        let ids = (known_id(old_source), known_id(new_source));
        render(path, pair, ids, resolver, cancellation, out)?;
    }
    Ok(())
}

/// The name of the object that a side is, if it is one. A file has to be hashed.
fn known_id(source: DiffSource) -> Option<gix::ObjectId> {
    match source {
        DiffSource::Object { id, .. } => Some(id),
        DiffSource::Missing | DiffSource::Worktree { .. } => None,
    }
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

/// Render one pair obtained from the diff loader, in the format of `git diff`.
///
/// Text validation and computation complete before this function writes the file preamble.
pub fn render_pair(
    path: &BStr,
    pair: Pair,
    resolver: &mut Resolver<'_>,
    cancellation: &Cancellation,
    out: &mut impl Write,
) -> crate::Result {
    render(path, pair, (None, None), resolver, cancellation, out)
}

/// As `render_pair()`. `ids` has the names of the sides that are known to be objects of
/// the repository, which saves hashing them for the `index` line.
fn render(
    path: &BStr,
    pair: Pair,
    ids: (Option<gix::ObjectId>, Option<gix::ObjectId>),
    resolver: &mut Resolver<'_>,
    cancellation: &Cancellation,
    out: &mut impl Write,
) -> crate::Result {
    cancellation.check()?;
    if pair.old == pair.new {
        return Ok(());
    }
    let (old, new) = ((&pair.old, ids.0), (&pair.new, ids.1));
    // As Git: a file, a link and a submodule are never compared with one another. The
    // old one is deleted and the new one is created.
    if let (Some(old_mode), Some(new_mode)) = (mode(&pair.old), mode(&pair.new))
        && patch::kind(old_mode.bits()) != patch::kind(new_mode.bits())
    {
        // Both halves are made before either is written, so that an error leaves none.
        let missing = (&Loaded::Missing, None);
        let mut halves = Vec::new();
        render_change(path, old, missing, resolver, cancellation, &mut halves)?;
        render_change(path, missing, new, resolver, cancellation, &mut halves)?;
        out.write_all(&halves)?;
        return cancellation.check();
    }
    render_change(path, old, new, resolver, cancellation, out)
}

/// Write the patch of one change. Each side comes with its object name, if that is known.
fn render_change(
    path: &BStr,
    (old, old_id): (&Loaded, Option<gix::ObjectId>),
    (new, new_id): (&Loaded, Option<gix::ObjectId>),
    resolver: &mut Resolver<'_>,
    cancellation: &Cancellation,
    out: &mut impl Write,
) -> crate::Result {
    let (old_mode, new_mode) = (mode(old), mode(new));
    let (before, after) = (content(old), content(new));
    let names = (
        patch_name("a/", path, resolver.quote_path()),
        patch_name("b/", path, resolver.quote_path()),
    );

    let mut header = Vec::new();
    header.extend_from_slice(b"diff --git ");
    header.extend_from_slice(&names.0);
    header.push(b' ');
    header.extend_from_slice(&names.1);
    header.push(b'\n');
    match (old_mode, new_mode) {
        (None, Some(mode)) => writeln!(header, "new file mode {:06o}", mode.bits())?,
        (Some(mode), None) => writeln!(header, "deleted file mode {:06o}", mode.bits())?,
        (Some(old), Some(new)) if old != new => {
            writeln!(header, "old mode {:06o}", old.bits())?;
            writeln!(header, "new mode {:06o}", new.bits())?;
        }
        _ => {}
    }
    let ids = (
        object_id(old, old_id, resolver)?,
        object_id(new, new_id, resolver)?,
    );
    if ids.0 != ids.1 {
        let abbreviated = (resolver.abbreviate(&ids.0)?, resolver.abbreviate(&ids.1)?);
        write!(header, "index {}..{}", abbreviated.0, abbreviated.1)?;
        if let Some(mode) = old_mode.filter(|mode| Some(*mode) == new_mode) {
            write!(header, " {:06o}", mode.bits())?;
        }
        header.push(b'\n');
    }
    let labels = (
        if old_mode.is_some() {
            &names.0[..]
        } else {
            b"/dev/null"
        },
        if new_mode.is_some() {
            &names.1[..]
        } else {
            b"/dev/null"
        },
    );

    cancellation.check()?;
    if before == after {
        out.write_all(&header)?;
        return cancellation.check();
    }
    // The text of a link or of a submodule is never binary and has no attributes.
    let mode = new_mode.or(old_mode).expect("a changed pair has one side");
    let policy = if matches!(mode, Mode::FILE | Mode::FILE_EXECUTABLE) {
        resolver.resolve(path, mode, cancellation)?
    } else {
        PathPolicy {
            algorithm: resolver.default_algorithm(),
            binary: BinaryMode::Text,
        }
    };
    if policy.binary.is_binary(&before, &after) {
        out.write_all(&header)?;
        out.write_all(b"Binary files ")?;
        out.write_all(labels.0)?;
        out.write_all(b" and ")?;
        out.write_all(labels.1)?;
        out.write_all(b" differ\n")?;
        return cancellation.check();
    }

    let prepared =
        diff_render::prepare_text(path, &before, &after, policy.algorithm, cancellation)?;
    out.write_all(&header)?;
    prepared.write_to(labels, cancellation, out)
}

fn mode(input: &Loaded) -> Option<Mode> {
    match input {
        Loaded::Missing => None,
        Loaded::Gitlink { .. } => Some(Mode::COMMIT),
        Loaded::Blob { mode, .. } => Some(*mode),
    }
}

/// What Git compares: the bytes of a file, the target of a link, or the line that
/// stands for the commit of a submodule.
fn content(input: &Loaded) -> Cow<'_, [u8]> {
    match input {
        Loaded::Missing => Cow::Borrowed(b""),
        Loaded::Blob { bytes, .. } => Cow::Borrowed(bytes),
        Loaded::Gitlink { id } => Cow::Owned(format!("Subproject commit {id}\n").into_bytes()),
    }
}

fn object_id(
    input: &Loaded,
    known: Option<gix::ObjectId>,
    resolver: &Resolver<'_>,
) -> crate::Result<gix::ObjectId> {
    let hash = resolver.object_hash();
    Ok(match (input, known) {
        (Loaded::Missing, _) => gix::ObjectId::null(hash),
        (Loaded::Gitlink { id }, _) => *id,
        (Loaded::Blob { .. }, Some(id)) => id,
        (Loaded::Blob { bytes, .. }, None) => {
            gix::objs::compute_hash(hash, gix::objs::Kind::Blob, bytes)?
        }
    })
}

/// Write a name the way Git writes it in a patch: as it is, or in double quotes with C
/// escapes if a byte needs one. `quote_path` is `core.quotePath`, which also escapes
/// every byte that is not ASCII.
fn patch_name(prefix: &str, path: &[u8], quote_path: bool) -> Vec<u8> {
    let escaped =
        |byte: u8| byte < 0x20 || matches!(byte, b'"' | b'\\' | 0x7f) || quote_path && byte >= 0x80;
    let mut name = Vec::with_capacity(prefix.len() + path.len() + 2);
    if !path.iter().copied().any(escaped) {
        name.extend_from_slice(prefix.as_bytes());
        name.extend_from_slice(path);
        return name;
    }
    name.push(b'"');
    name.extend_from_slice(prefix.as_bytes());
    for &byte in path {
        let letter = match byte {
            b'"' | b'\\' => byte,
            0x07 => b'a',
            0x08 => b'b',
            b'\t' => b't',
            b'\n' => b'n',
            0x0b => b'v',
            0x0c => b'f',
            b'\r' => b'r',
            _ if escaped(byte) => {
                name.extend_from_slice(format!("\\{byte:03o}").as_bytes());
                continue;
            }
            _ => {
                name.push(byte);
                continue;
            }
        };
        name.extend_from_slice(&[b'\\', letter]);
    }
    name.push(b'"');
    name
}
