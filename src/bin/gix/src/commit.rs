use std::io;

use gix::{
    bstr::ByteSlice,
    refs::{
        Target,
        transaction::{Change, LogChange, PreviousValue, RefEdit, RefLog},
    },
};

use crate::{
    cancellation::Cancellation, mutation::Guard, repository::OpenedRepository, tree_index,
};

/// Create an ordinary commit from the complete held index and advance attached HEAD.
pub fn run(opened: &OpenedRepository, message: &str, cancellation: &Cancellation) -> crate::Result {
    cancellation.check()?;
    let repo = &opened.repo;
    let author = repo
        .author()
        .ok_or_else(|| invalid("author identity is not configured"))??;
    validate_identity(author, "author")?;
    let committer = repo
        .committer()
        .ok_or_else(|| invalid("committer identity is not configured"))??;
    validate_identity(committer, "committer")?;
    cancellation.check()?;

    let guard = Guard::acquire(repo)?;
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
    let commit_id = repo.new_commit(message, tree, parent)?.id;

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
