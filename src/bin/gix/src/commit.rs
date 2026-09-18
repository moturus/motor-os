use std::{error::Error as StdError, fmt, io};

use gix::{
    bstr::ByteSlice,
    refs::{
        Target,
        transaction::{Change, LogChange, PreviousValue, RefEdit, RefLog},
    },
};

use crate::{
    cancellation::Cancellation,
    mutation::Guard,
    operation::{Record, State},
    repository::OpenedRepository,
    tree_index,
};

pub(crate) struct Identities {
    author: gix::actor::Signature,
    committer: gix::actor::Signature,
}

/// Commit the held index, completing a validated ready merge when present.
pub fn run(opened: &OpenedRepository, message: &str, cancellation: &Cancellation) -> crate::Result {
    cancellation.check()?;
    let repo = &opened.repo;
    let identities = identities(repo)?;
    cancellation.check()?;

    let (guard, ready) = Guard::acquire_for_ready_mutation(repo)?;
    if let Some(ready) = ready {
        guard.require_ready_merge(repo, &ready, cancellation)?;
        let tree = tree_index::write(repo, guard.index(), cancellation)?;
        return finish_ready(
            opened,
            &guard,
            &ready,
            tree,
            message,
            &identities,
            cancellation,
        );
    }
    cancellation.check()?;
    let head = repo.head()?;
    if head.referent_name().and_then(|name| name.category())
        != Some(gix::refs::Category::LocalBranch)
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "commit requires HEAD attached to a local branch",
        )
        .into());
    }
    let parent = head.id().map(|id| id.detach());
    let previous_tree = match parent {
        Some(id) => repo.find_commit(id)?.tree_id()?.detach(),
        None => gix::ObjectId::empty_tree(repo.object_hash()),
    };

    let tree = tree_index::write(repo, guard.index(), cancellation)?;
    if tree == previous_tree {
        return Err(invalid("nothing to commit; the index is unchanged").into());
    }
    cancellation.check()?;
    let mut author_time = gix::date::parse::TimeBuf::default();
    let mut committer_time = gix::date::parse::TimeBuf::default();
    let author = identities.author.to_ref(&mut author_time);
    let committer = identities.committer.to_ref(&mut committer_time);
    let commit_id = repo
        .new_commit_as(committer, author, message, tree, parent)?
        .id;

    let expected = match parent {
        Some(id) => PreviousValue::MustExistAndMatch(Target::Object(id)),
        None => PreviousValue::MustNotExist,
    };
    let edit = RefEdit {
        name: "HEAD".try_into().expect("HEAD is a valid reference name"),
        deref: true,
        change: Change::Update {
            new: Target::Object(commit_id),
            expected,
            log: LogChange {
                mode: RefLog::AndReference,
                force_create_reflog: false,
                message: gix::reference::log::message(
                    "commit",
                    message.as_bytes().as_bstr(),
                    usize::from(parent.is_some()),
                ),
            },
        },
    };
    cancellation.check()?;
    repo.edit_references_as([edit], Some(committer))?;
    drop(guard);
    Ok(())
}

/// Finish a persisted Ready merge while retaining the caller's mutation guard.
pub(crate) fn finish_ready(
    opened: &OpenedRepository,
    guard: &Guard,
    ready: &Record,
    tree: gix::ObjectId,
    message: &str,
    identities: &Identities,
    cancellation: &Cancellation,
) -> crate::Result {
    let repo = &opened.repo;
    guard.require_ready_merge(repo, ready, cancellation)?;
    let original = ready
        .original
        .id
        .expect("a validated Ready merge has a born original");
    let mut author_time = gix::date::parse::TimeBuf::default();
    let mut committer_time = gix::date::parse::TimeBuf::default();
    let author = identities.author.to_ref(&mut author_time);
    let committer = identities.committer.to_ref(&mut committer_time);
    let commit_id = repo
        .new_commit_as(
            committer,
            author,
            message,
            tree,
            [original, ready.target_commit],
        )?
        .id;

    let mut publishing = ready.clone();
    publishing.state = State::Publishing;
    publishing.intended_commit = Some(commit_id);
    guard.require_ready_merge(repo, ready, cancellation)?;
    guard.replace_operation(ready, &publishing)?;

    let result: crate::Result = (|| {
        let reflog = gix::reference::log::message("commit", message.as_bytes().as_bstr(), 2);
        crate::head_ref::advance_attached(
            repo,
            &ready.original,
            commit_id,
            committer,
            reflog.as_bstr(),
            cancellation,
        )?;
        guard.cleanup_operation(&publishing, cancellation)
    })();
    result.map_err(|source| {
        Box::new(ReadyPublicationError {
            source: cancellation.normalize_error(source),
        }) as Box<dyn StdError + Send + Sync>
    })
}

pub(crate) fn identities(repo: &gix::Repository) -> crate::Result<Identities> {
    let author = repo
        .author()
        .ok_or_else(|| invalid("author identity is not configured"))??;
    validate_identity(author, "author")?;
    let author = author.to_owned()?;
    let committer = repo
        .committer()
        .ok_or_else(|| invalid("committer identity is not configured"))??;
    validate_identity(committer, "committer")?;
    let committer = committer.to_owned()?;
    Ok(Identities { author, committer })
}

fn validate_identity(signature: gix::actor::SignatureRef<'_>, role: &str) -> crate::Result {
    let trimmed = signature.trim();
    if trimmed.name.is_empty() || trimmed.email.is_empty() {
        return Err(invalid(format!(
            "{role} identity requires a nonempty name and email"
        ))
        .into());
    }
    signature.write_to(&mut io::sink())?;
    Ok(())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[derive(Debug)]
struct ReadyPublicationError {
    source: Box<dyn StdError + Send + Sync>,
}

impl fmt::Display for ReadyPublicationError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("merge commit publication is incomplete; run 'gix recover'")
    }
}

impl StdError for ReadyPublicationError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.source.as_ref())
    }
}
