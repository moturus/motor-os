use std::{fs, path::Path};

use crate::{
    cancellation::Cancellation,
    checkout,
    https_url::HttpsUrl,
    mutation::{Guard, INCOMPLETE_CLONE_FILE},
    network, repository,
};

pub fn run(
    url: &str,
    destination: &Path,
    overrides: &[&str],
    report_config_paths: bool,
    cancellation: &Cancellation,
) -> crate::Result {
    cancellation.check()?;
    HttpsUrl::parse(url)?;
    let policy = network::Policy::new(overrides, cancellation)?;
    let options = repository::open_options(overrides)?;
    // This is the ownership boundary. Never adopt or remove a preexisting directory.
    fs::create_dir(destination)?;
    let result = clone_created(
        url,
        destination,
        options,
        policy,
        report_config_paths,
        cancellation,
    );
    cancellation.check().and(result).map_err(|source| network::Failure::new(format!(
            "clone did not complete; owned destination '{}' is retained for inspection; remove it explicitly before cloning again",
            destination.display()
        ), source).into())
}

fn clone_created(
    url: &str,
    destination: &Path,
    options: gix::open::Options,
    policy: network::Policy,
    report_config_paths: bool,
    cancellation: &Cancellation,
) -> crate::Result {
    let destination = destination.canonicalize()?;
    let staging = destination.join(".git");
    let mut prepare = gix::clone::PrepareFetch::new(
        url,
        &destination,
        gix::create::Kind::WithWorktree,
        gix::create::Options {
            object_hash: Some(gix::hash::Kind::Sha1),
            ..Default::default()
        },
        options,
    )?
    .with_remote_name("origin")
    .expect("the fixed remote name is valid")
    .configure_remote(|remote| {
        // Check the rewritten URL before gix's connector can inspect a file URL.
        network::validate_url(
            remote
                .url(gix::remote::Direction::Fetch)
                .ok_or_else(|| std::io::Error::other("clone remote has no URL"))?,
        )?;
        Ok(remote)
    })
    .with_transport_factory(move |url, _| Ok(Box::new(policy.transport(url, &staging)?)));

    // PrepareFetch normally deletes unsuccessful clones on drop. Preserve every
    // owned partial clone explicitly; it must remain inspectable after an error.
    let result = (|| -> crate::Result {
        let repo = prepare.repository_mut().expect("fetch has not run");
        let command_policy = repository::apply_policy(repo, &destination, report_config_paths)?;
        let mut guard = Guard::acquire(repo)?;
        let marker = repo.git_dir().join(INCOMPLETE_CLONE_FILE);
        fs::File::create_new(&marker)?;
        cancellation.check()?;
        let fetched = prepare.fetch_only(gix::progress::Discard, cancellation.flag());
        cancellation.check()?;
        let (mut repo, outcome) = fetched?;
        network::check_outcome(&outcome)?;
        repo.objects.ignore_replacements = true;
        let opened = repository::OpenedRepository {
            repo,
            command_policy,
        };
        let state = checkout::initial(&opened, cancellation)?;
        cancellation.check()?;
        guard.publish_fresh_index(state)?;
        cancellation.check()?;
        fs::remove_file(marker)?;
        Ok(())
    })();
    if result.is_err() && prepare.repository_mut().is_some() {
        prepare.persist();
    }
    result
}
