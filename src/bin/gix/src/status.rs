use std::{
    collections::BTreeMap,
    convert::Infallible,
    io::{self, Write},
    ops::ControlFlow,
    sync::atomic::Ordering,
};

use gix::{
    bstr::{BStr, BString, ByteSlice},
    index::entry::Mode,
    status::plumbing::index_as_worktree_with_renames::{Recorder, Summary},
};

use crate::{cancellation::Cancellation, repository::OpenedRepository};

struct Change {
    staged: char,
    worktree: char,
}

impl Default for Change {
    fn default() -> Self {
        Change {
            staged: ' ',
            worktree: ' ',
        }
    }
}

pub struct Report {
    operation: Option<&'static str>,
    changes: BTreeMap<BString, Change>,
}

impl Report {
    pub fn write_to(&self, mut out: impl Write, cancellation: &Cancellation) -> crate::Result {
        cancellation.check()?;
        if let Some(operation) = self.operation {
            writeln!(out, "operation {operation}")?;
        }
        for (path, change) in &self.changes {
            cancellation.check()?;
            writeln!(
                out,
                "{}{} {}",
                change.staged,
                change.worktree,
                path.to_str_lossy().escape_debug()
            )?;
        }
        cancellation.check()?;
        out.flush()?;
        cancellation.check()
    }
}

pub fn collect(opened: &OpenedRepository, cancellation: &Cancellation) -> crate::Result<Report> {
    cancellation.check()?;
    let repo = &opened.repo;
    let index = repo.index_or_empty()?;
    reject_configured_filters(opened, &index, cancellation)?;

    let mut changes = BTreeMap::<BString, Change>::new();
    let head_tree = repo.head_tree_id_or_empty()?;
    let mut pathspec = repo.pathspec(
        false,
        std::iter::empty::<&str>(),
        false,
        &index,
        gix::worktree::stack::state::attributes::Source::IdMapping,
    )?;
    repo.tree_index_status(
        &head_tree,
        &index,
        Some(&mut pathspec),
        gix::status::tree_index::TrackRenames::Disabled,
        |change, _, _| {
            if cancellation.flag().load(Ordering::Acquire) {
                return Ok::<_, Infallible>(ControlFlow::Break(()));
            }
            let code = match change {
                gix::diff::index::ChangeRef::Addition { .. } => 'A',
                gix::diff::index::ChangeRef::Deletion { .. } => 'D',
                gix::diff::index::ChangeRef::Modification { .. } => 'M',
                gix::diff::index::ChangeRef::Rewrite { .. } => unreachable!("renames are disabled"),
            };
            changes
                .entry(change.location().to_owned())
                .or_default()
                .staged = code;
            Ok::<_, Infallible>(ControlFlow::Continue(()))
        },
    )?;
    cancellation.check()?;

    let mut recorder = Recorder::default();
    let options = gix::status::index_worktree::Options {
        sorting: None,
        dirwalk_options: Some(
            repo.dirwalk_options()?
                .emit_untracked(gix::dir::walk::EmissionMode::Matching),
        ),
        rewrites: None,
        thread_limit: None,
    };
    let status = repo.index_worktree_status(
        &index,
        std::iter::empty::<&str>(),
        &mut recorder,
        gix::status::plumbing::index_as_worktree::traits::FastEq,
        IgnoreSubmodules,
        &mut gix::progress::Discard,
        cancellation.flag(),
        options,
    );
    cancellation.check()?;
    status?;
    for entry in recorder.records {
        cancellation.check()?;
        let Some(summary) = entry.summary() else {
            continue;
        };
        let path = entry.destination_rela_path();
        if summary == Summary::Removed
            && index
                .entry_by_path(path)
                .is_some_and(|entry| entry.mode == Mode::COMMIT)
        {
            continue;
        }
        let change = changes.entry(path.to_owned()).or_default();
        match summary {
            Summary::Added => {
                if change.staged == ' ' {
                    change.staged = '?';
                }
                change.worktree = '?';
            }
            Summary::Conflict => {
                change.staged = 'U';
                change.worktree = 'U';
            }
            Summary::Removed => change.worktree = 'D',
            Summary::Modified => change.worktree = 'M',
            Summary::TypeChange => change.worktree = 'T',
            Summary::IntentToAdd => change.worktree = 'I',
            Summary::Renamed | Summary::Copied => unreachable!("rewrites are disabled"),
        }
    }
    cancellation.check()?;

    Ok(Report {
        operation: repo.state().map(operation_name),
        changes,
    })
}

fn reject_configured_filters(
    opened: &OpenedRepository,
    index: &gix::index::State,
    cancellation: &Cancellation,
) -> crate::Result {
    let policy = &opened.command_policy;
    if policy.external_filters.is_empty() && policy.required_filters.is_empty() {
        return Ok(());
    }

    let mut attributes = opened.repo.attributes_only(
        index,
        gix::worktree::stack::state::attributes::Source::WorktreeThenIdMapping,
    )?;
    let mut matches = attributes.selected_attribute_matches(["filter"]);
    for entry in index.entries() {
        cancellation.check()?;
        if !matches!(entry.mode, Mode::FILE | Mode::FILE_EXECUTABLE) {
            continue;
        }
        let path = entry.path(index);
        attributes
            .at_entry(path, Some(entry.mode))?
            .matching_attributes(&mut matches);
        let filter = matches.iter_selected().next().and_then(|item| {
            if let gix::attrs::StateRef::Value(value) = item.assignment.state {
                Some(value.as_bstr())
            } else {
                None
            }
        });
        let Some(filter) = filter else {
            continue;
        };
        if policy.external_filters.contains(filter) || policy.required_filters.contains(filter) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "tracked path '{}' uses unsupported filter '{}'",
                    path.to_str_lossy().escape_debug(),
                    filter.to_str_lossy().escape_debug()
                ),
            )
            .into());
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct IgnoreSubmodules;

impl gix::status::plumbing::index_as_worktree::traits::SubmoduleStatus for IgnoreSubmodules {
    type Output = ();
    type Error = Infallible;

    fn status(
        &mut self,
        _entry: &gix::index::Entry,
        _path: &BStr,
    ) -> Result<Option<Self::Output>, Self::Error> {
        Ok(None)
    }
}

fn operation_name(state: gix::state::InProgress) -> &'static str {
    match state {
        gix::state::InProgress::ApplyMailbox => "apply-mailbox",
        gix::state::InProgress::ApplyMailboxRebase => "apply-mailbox-rebase",
        gix::state::InProgress::Bisect => "bisect",
        gix::state::InProgress::CherryPick => "cherry-pick",
        gix::state::InProgress::CherryPickSequence => "cherry-pick-sequence",
        gix::state::InProgress::Merge => "merge",
        gix::state::InProgress::Rebase => "rebase",
        gix::state::InProgress::RebaseInteractive => "rebase-interactive",
        gix::state::InProgress::Revert => "revert",
        gix::state::InProgress::RevertSequence => "revert-sequence",
    }
}
