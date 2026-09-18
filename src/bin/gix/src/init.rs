use std::{io, path::Path};

use gix::bstr::{BStr, ByteSlice};

use crate::{cancellation::Cancellation, repository};

/// Initialize an ordinary SHA-1 worktree repository without replacing existing worktree files.
pub fn run(
    directory: &Path,
    overrides: &[&str],
    report_config_paths: bool,
    cancellation: &Cancellation,
) -> crate::Result {
    cancellation.check()?;
    let selected = gix::path::realpath(directory)?;
    let mut options = repository::open_options(overrides)?;

    // Validate before init creates the destination or its .git directory.
    let config = gix::config(Some(&selected.join(".git")), &options)?;
    let branch = config
        .string("init.defaultBranch")
        .unwrap_or_else(|| gix::init::DEFAULT_BRANCH_NAME.into());
    let branch_text = branch.as_bstr().to_str().map_err(|source| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("init.defaultBranch must be UTF-8: {source}"),
        )
    })?;
    validate_branch(branch.as_bstr())?;

    // Freeze the validated effective value across init's second configuration load.
    let branch_override = format!("init.defaultBranch={branch_text}");
    options = options.cli_overrides(
        overrides
            .iter()
            .copied()
            .chain(std::iter::once(branch_override.as_str())),
    );

    cancellation.check()?;
    let repo = gix::ThreadSafeRepository::init_opts(
        &selected,
        gix::create::Kind::WithWorktree,
        gix::create::Options {
            destination_must_be_empty: Some(false),
            object_hash: Some(gix::hash::Kind::Sha1),
            ..Default::default()
        },
        options,
    );
    let mut repo = repo?.to_thread_local();
    cancellation.check()?;
    repository::apply_policy(&mut repo, &selected, report_config_paths)?;
    cancellation.check()
}

fn validate_branch(branch: &BStr) -> io::Result<()> {
    let full_name = gix::refs::Category::LocalBranch
        .to_full_name(branch)
        .map_err(|source| invalid_branch(branch, source))?;
    gix::validate::reference::branch_name(full_name.as_bstr())
        .map_err(|source| invalid_branch(branch, source))?;
    Ok(())
}

fn invalid_branch(branch: &BStr, source: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid init.defaultBranch {branch:?}: {source}"),
    )
}
