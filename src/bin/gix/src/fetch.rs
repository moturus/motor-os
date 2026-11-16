use std::io;

use gix::{
    bstr::{BString, ByteSlice},
    remote::Direction,
};

use crate::{
    cancellation::Cancellation, mutation::Guard, network, repository::OpenedRepository, ssh,
};

pub fn run(
    opened: &mut OpenedRepository,
    name: &str,
    policy: &network::Policy,
    cancellation: &Cancellation,
) -> crate::Result {
    cancellation.check()?;
    let _guard = Guard::acquire(&opened.repo)?;
    fetch(&mut opened.repo, name, None, policy, cancellation)?;
    Ok(())
}

/// What a fetch learned beyond updating the tracking references.
pub(crate) struct Fetched {
    /// The URL the objects came from.
    pub url: gix::Url,
    /// Every remote ref the caller's own refspec matched: its full name and peeled object.
    pub wanted: Vec<(BString, gix::ObjectId)>,
}

/// Fetch the configured remote `name`. The caller holds the mutation guard.
///
/// `wanted` names one more remote ref to fetch, without a destination; `gix pull` merges it
/// even if no configured refspec covers it. `repo` gets a generic committer for the reflogs
/// if it has none.
pub(crate) fn fetch(
    repo: &mut gix::Repository,
    name: &str,
    wanted: Option<gix::refspec::RefSpec>,
    policy: &network::Policy,
    cancellation: &Cancellation,
) -> crate::Result<Fetched> {
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
    let fetched_url = url.clone();
    let (operation, registrar) = ssh::Operation::new(cancellation);
    let transfer = (|| -> crate::Result<_> {
        let transport = policy.transport(url, repo.git_dir(), &registrar)?;
        let options = gix::remote::ref_map::Options {
            extra_refspecs: wanted.iter().cloned().collect(),
            ..Default::default()
        };
        let pending = remote
            .to_connection_with_transport(transport)
            .prepare_fetch(gix::progress::Discard, options)?;
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
        Ok(pending.receive(gix::progress::Discard, cancellation.flag())?)
    })();
    let outcome = network::finish(operation, transfer, cancellation).map_err(|source| {
        network::Failure::new(
            "fetch failed; downloaded objects or some references may already have changed"
                .to_owned(),
            source,
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

    let map = &outcome.ref_map;
    let mut found = Vec::new();
    for mapping in &map.mappings {
        let spec = mapping.spec_index.get(&map.refspecs, &map.extra_refspecs);
        if wanted.is_none() || spec != wanted.as_ref() {
            continue;
        }
        // An unborn remote ref has no object; it is not something to merge.
        if let (Some(name), Some(id)) = (mapping.remote.as_name(), mapping.remote.peeled_id()) {
            found.push((name.to_owned(), id.to_owned()));
        }
    }
    // A configured refspec equal to `wanted` maps the same ref a second time.
    found.dedup();
    Ok(Fetched {
        url: fetched_url,
        wanted: found,
    })
}
