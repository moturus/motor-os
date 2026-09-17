use std::{error::Error as StdError, fmt, io, time::Duration};

use gix::{
    bstr::{BStr, ByteSlice},
    refs::{
        Target,
        transaction::{Change, LogChange, PreviousValue, RefEdit, RefLog},
    },
};

use crate::{
    cancellation::Cancellation,
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

/// Preflight the fallible identity and ref-lock policy used by HEAD publication.
pub(crate) fn preflight_publication(
    repo: &mut gix::Repository,
) -> crate::Result<(gix::lock::acquire::Fail, gix::lock::acquire::Fail)> {
    repo.committer_or_set_generic_fallback()?
        .write_to(&mut io::sink())?;
    ref_lock_policy(repo)
}

/// Attach HEAD to an observed local branch without moving that branch.
///
/// The caller retains its mutation guard and operation record through this publication.
/// The repository must use the application's strict configuration and standard trust policy.
pub fn attach(
    repo: &mut gix::Repository,
    expected_head: &Original,
    target_ref: &gix::refs::FullName,
    target_commit: gix::ObjectId,
    message: &BStr,
    cancellation: &Cancellation,
) -> crate::Result<Original> {
    cancellation.check()?;
    require_local_branch(repo, target_ref.as_ref(), Some(target_commit))?;
    require(repo, expected_head)?;
    let previous_oid = expected_head
        .id
        .unwrap_or_else(|| gix::ObjectId::null(repo.object_hash()));
    let expected_target = raw_target(expected_head)?;
    let (file_lock_fail, packed_lock_fail) = preflight_publication(repo)?;
    let committer = repo
        .committer()
        .expect("generic committer fallback was installed")?;

    let edit = RefEdit {
        name: "HEAD".try_into().expect("HEAD is a valid reference name"),
        deref: false,
        change: Change::Update {
            log: LogChange {
                mode: RefLog::AndReference,
                force_create_reflog: false,
                message: message.to_owned(),
            },
            expected: PreviousValue::MustExistAndMatch(expected_target),
            new: Target::Symbolic(target_ref.clone()),
        },
    };
    let result: crate::Result<Original> = (|| {
        let transaction =
            repo.refs
                .transaction()
                .prepare(Some(edit), file_lock_fail, packed_lock_fail)?;
        require_local_branch(repo, target_ref.as_ref(), Some(target_commit))?;
        require(repo, expected_head)?;
        cancellation.check()?;
        transaction.commit_with_reflog_ids(committer, previous_oid, target_commit)?;

        let actual = capture(repo)?;
        let destination = direct_branch_id(repo, target_ref.as_ref())?;
        let expected = Original {
            reference: Some(target_ref.clone()),
            id: Some(target_commit),
        };
        if actual != expected || destination != Some(target_commit) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "published HEAD state differs: expected {expected:?}, observed {actual:?}, destination {destination:?}"
                ),
            )
            .into());
        }
        cancellation.check()?;
        Ok(actual)
    })();
    result.map_err(|source| {
        publication_error(
            repo,
            target_ref.as_ref(),
            cancellation.normalize_error(source),
        )
    })
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

pub(crate) fn require_local_branch(
    repo: &gix::Repository,
    name: &gix::refs::FullNameRef,
    expected: Option<gix::ObjectId>,
) -> crate::Result {
    let actual = direct_branch_id(repo, name)?;
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "local branch '{}' changed: expected {expected:?}, observed {actual:?}",
                name.as_bstr().to_str_lossy()
            ),
        )
        .into());
    }
    Ok(())
}

fn raw_target(original: &Original) -> crate::Result<Target> {
    match (&original.reference, original.id) {
        (Some(reference), _) => Ok(Target::Symbolic(reference.clone())),
        (None, Some(id)) => Ok(Target::Object(id)),
        (None, None) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected HEAD has neither a reference nor an object",
        )
        .into()),
    }
}

fn ref_lock_policy(
    repo: &gix::Repository,
) -> crate::Result<(gix::lock::acquire::Fail, gix::lock::acquire::Fail)> {
    let config = repo.config_snapshot();
    let file_key = &gix::config::tree::Core::FILES_REF_LOCK_TIMEOUT;
    let packed_key = &gix::config::tree::Core::PACKED_REFS_TIMEOUT;
    let file = file_key
        .try_into_lock_timeout(
            config
                .plumbing()
                .integer_filter(file_key, &mut gix::config::section::is_trusted),
        )?
        .unwrap_or_else(|| {
            gix::lock::acquire::Fail::AfterDurationWithBackoff(Duration::from_millis(100))
        });
    let packed = packed_key
        .try_into_lock_timeout(
            config
                .plumbing()
                .integer_filter(packed_key, &mut gix::config::section::is_trusted),
        )?
        .unwrap_or_else(|| {
            gix::lock::acquire::Fail::AfterDurationWithBackoff(Duration::from_millis(1_000))
        });
    Ok((file, packed))
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

fn publication_error(
    repo: &gix::Repository,
    target_ref: &gix::refs::FullNameRef,
    source: Box<dyn StdError + Send + Sync>,
) -> Box<dyn StdError + Send + Sync> {
    let head = capture(repo).map_err(|error| error.to_string());
    let destination = direct_branch_id(repo, target_ref).map_err(|error| error.to_string());
    Box::new(PublicationError {
        source,
        observed: format!("HEAD {head:?}, destination {destination:?}"),
    })
}

#[derive(Debug)]
struct PublicationError {
    source: Box<dyn StdError + Send + Sync>,
    observed: String,
}

impl fmt::Display for PublicationError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "HEAD attachment failed; HEAD or its reflog may already be updated; observed {}",
            self.observed
        )
    }
}

impl StdError for PublicationError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.source.as_ref())
    }
}
