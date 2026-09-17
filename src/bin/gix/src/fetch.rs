use std::io;

use gix::{bstr::ByteSlice, remote::Direction};

use crate::{cancellation::Cancellation, mutation::Guard, network, repository::OpenedRepository};

pub fn run(
    opened: &mut OpenedRepository,
    name: &str,
    policy: &network::Policy,
    cancellation: &Cancellation,
) -> crate::Result {
    cancellation.check()?;
    let repo = &mut opened.repo;
    let _guard = Guard::acquire(repo)?;
    repo.committer_or_set_generic_fallback()?;
    let mut remote = repo
        .try_find_remote_without_url_rewrite(name.as_bytes().as_bstr())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("remote '{name}' is not configured"),
            )
        })??;
    if remote.name().and_then(gix::remote::Name::as_symbol) != Some(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fetch requires a configured remote name",
        )
        .into());
    }
    network::validate_url(
        remote
            .url(Direction::Fetch)
            .ok_or_else(|| io::Error::other("remote has no fetch URL"))?,
    )?;
    remote.rewrite_urls()?;
    network::validate_url(
        remote
            .url(Direction::Fetch)
            .ok_or_else(|| io::Error::other("remote has no fetch URL"))?,
    )?;
    let (url, _) = remote.sanitized_url_and_version(Direction::Fetch)?;
    let transport = policy.transport(url, repo.git_dir())?;
    let pending = remote
        .to_connection_with_transport(transport)
        .prepare_fetch(gix::progress::Discard, Default::default())?;
    cancellation.check()?;
    for mapping in &pending.ref_map().mappings {
        if let Some(name) = &mapping.local
            && !name.starts_with(b"refs/remotes/")
            && !name.starts_with(b"refs/tags/")
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "fetch destination '{}' is not a tracking reference or tag",
                    name.to_str_lossy().escape_debug()
                ),
            )
            .into());
        }
    }
    let result = pending.receive(gix::progress::Discard, cancellation.flag());
    let outcome = result.map_err(|error| {
        network::Failure::new(
            "fetch failed; downloaded objects or some references may already have changed"
                .to_owned(),
            cancellation.normalize_error(error.into()),
        )
    })?;
    network::check_outcome(&outcome)?;
    cancellation.check().map_err(|source| {
        network::Failure::new(
            "fetch failed; downloaded objects or some references may already have changed"
                .to_owned(),
            source,
        )
    })?;
    Ok(())
}
