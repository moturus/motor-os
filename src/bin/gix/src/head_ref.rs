use std::io;

use gix::bstr::ByteSlice;

use crate::{
    operation::Original,
    refs::{self, Kind},
};

/// Capture HEAD's exact raw attachment and direct commit ID.
pub fn capture(repo: &gix::Repository) -> crate::Result<Original> {
    let head = repo.find_reference("HEAD")?;
    match head.target() {
        gix::refs::TargetRef::Object(id) => Ok(Original {
            reference: None,
            id: Some(require_commit(repo, id)?),
        }),
        gix::refs::TargetRef::Symbolic(name) => Ok(Original {
            reference: Some(name.to_owned()),
            id: direct_branch_id(repo, name)?,
        }),
    }
}

/// Require HEAD to retain an exact previously captured state.
pub fn require(repo: &gix::Repository, expected: &Original) -> crate::Result {
    let actual = capture(repo)?;
    if actual != *expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("HEAD changed: expected {expected:?}, observed {actual:?}"),
        )
        .into());
    }
    Ok(())
}

/// Resolve an existing local branch to its exact direct commit ID.
pub fn existing_local_branch(
    repo: &gix::Repository,
    short_name: &str,
) -> crate::Result<(gix::refs::FullName, gix::ObjectId)> {
    let name = refs::qualified_name(Kind::Branch, short_name)?;
    let id = direct_branch_id(repo, name.as_ref())?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("local branch '{short_name}' does not exist"),
        )
    })?;
    Ok((name, id))
}

fn direct_branch_id(
    repo: &gix::Repository,
    name: &gix::refs::FullNameRef,
) -> crate::Result<Option<gix::ObjectId>> {
    validate_local_branch(name)?;
    let Some(reference) = repo.try_find_reference(name)? else {
        return Ok(None);
    };
    match reference.target() {
        gix::refs::TargetRef::Object(id) => require_commit(repo, id).map(Some),
        gix::refs::TargetRef::Symbolic(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "local branch '{}' is symbolic",
                name.as_bstr().to_str_lossy()
            ),
        )
        .into()),
    }
}

fn require_commit(repo: &gix::Repository, id: &gix::oid) -> crate::Result<gix::ObjectId> {
    let id = id.to_owned();
    repo.find_commit(id)?;
    Ok(id)
}

fn validate_local_branch(name: &gix::refs::FullNameRef) -> crate::Result {
    if name.category() != Some(gix::refs::Category::LocalBranch) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "HEAD target '{}' is not a local branch",
                name.as_bstr().to_str_lossy()
            ),
        )
        .into());
    }
    gix::validate::reference::branch_name(name.as_bstr())?;
    Ok(())
}
