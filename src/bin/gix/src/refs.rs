use std::io::Write;

use gix::bstr::ByteSlice;

use crate::{cancellation::Cancellation, mutation::Guard, repository::OpenedRepository};

#[derive(Clone, Copy)]
pub enum Kind {
    Branch,
    Tag,
}

impl Kind {
    fn prefix(self) -> &'static str {
        match self {
            Kind::Branch => "refs/heads/",
            Kind::Tag => "refs/tags/",
        }
    }

    fn noun(self) -> &'static str {
        match self {
            Kind::Branch => "branch",
            Kind::Tag => "tag",
        }
    }
}

/// List short names in the ref store's stable bytewise order.
///
/// This path intentionally avoids the mutation guard: inspection must not
/// create the persistent operation-lock file.
pub fn list(
    repo: &gix::Repository,
    kind: Kind,
    mut out: impl Write,
    cancellation: &Cancellation,
) -> crate::Result {
    cancellation.check()?;
    let platform = repo.references()?;
    let references = match kind {
        Kind::Branch => platform.local_branches()?,
        Kind::Tag => platform.tags()?,
    };
    for reference in references {
        cancellation.check()?;
        let reference = reference?;
        out.write_all(reference.name().shorten())?;
        out.write_all(b"\n")?;
    }
    out.flush()?;
    cancellation.check()
}

/// Create a branch or lightweight tag without replacing an existing ref.
pub fn create(
    opened: &mut OpenedRepository,
    kind: Kind,
    name: &str,
    revision: Option<&str>,
    cancellation: &Cancellation,
) -> crate::Result {
    let full_name = qualified_name(kind, name)?;
    cancellation.check()?;

    let repo = &mut opened.repo;
    let _guard = Guard::acquire(repo)?;
    cancellation.check()?;

    let revision = revision.unwrap_or("HEAD");
    let id = repo.rev_parse_single(revision.as_bytes().as_bstr())?;
    let target = match kind {
        Kind::Branch => id.object()?.peel_to_commit()?.id,
        Kind::Tag => {
            id.header()?;
            id.detach()
        }
    };
    cancellation.check()?;

    // Ref creation is not authorship. Supply gix's generic committer only
    // when configured identity is absent so an applicable reflog can be made.
    repo.committer_or_set_generic_fallback()?;
    cancellation.check()?;
    repo.reference(
        full_name,
        target,
        gix::refs::transaction::PreviousValue::MustNotExist,
        format!("{}: Created from {revision}", kind.noun()),
    )?;
    Ok(())
}

pub(crate) fn qualified_name(kind: Kind, name: &str) -> crate::Result<gix::refs::FullName> {
    if matches!(kind, Kind::Branch) && name.starts_with('-') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "branch name must not start with '-'",
        )
        .into());
    }
    let full_name = format!("{}{name}", kind.prefix());
    let full_name: gix::refs::FullName = full_name.try_into()?;
    if matches!(kind, Kind::Branch) {
        gix::validate::reference::branch_name(full_name.as_bstr())?;
    }
    Ok(full_name)
}
