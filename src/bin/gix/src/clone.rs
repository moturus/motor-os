use std::{
    fs,
    path::{Path, PathBuf},
};

use gix::bstr::ByteSlice;

use crate::{
    cancellation::Cancellation,
    checkout,
    https_url::HttpsUrl,
    mutation::{Guard, INCOMPLETE_CLONE_FILE},
    network, repository, ssh,
};

pub fn run(
    url: &str,
    destination: Option<&Path>,
    overrides: &[&str],
    report_config_paths: bool,
    cancellation: &Cancellation,
) -> crate::Result {
    cancellation.check()?;
    let parsed = gix::url::parse(url.as_bytes().as_bstr())?;
    if parsed.scheme == gix::url::Scheme::Https {
        HttpsUrl::parse(url)?;
    }
    network::validate_url(&parsed)?;
    let derived;
    let destination = match destination {
        Some(destination) => destination,
        None => {
            derived = default_destination(&parsed)?;
            eprintln!("Cloning into '{}'...", derived.display());
            &derived
        }
    };
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
    result.map_err(|source| {
        network::Failure::new(format!(
            "clone did not complete; owned destination '{}' is retained for inspection; remove it explicitly before cloning again",
            destination.display()
        ), source)
    })?;
    cancellation.check()
}

/// Name the destination after the repository as Git does: the last URL path
/// component without a trailing `/.git` or `.git`, or the host if there is none.
fn default_destination(url: &gix::url::Url) -> crate::Result<PathBuf> {
    let path = url.path.trim_end_with(|c| c == '/');
    let path = path.strip_suffix(b"/.git").unwrap_or(path);
    let path = path.trim_end_with(|c| c == '/');
    let name = path.rsplit_str("/").next().unwrap_or(path);
    let name = name.strip_suffix(b".git").unwrap_or(name);
    let name = match (name.to_str(), url.host()) {
        (Ok(""), Some(host)) => host,
        (Ok(name), _) => name,
        (Err(_), _) => "",
    };
    // The name comes from the remote URL. It must stay one new entry here.
    if matches!(name, "" | "." | "..")
        || name.contains(['/', '\\'])
        || name.contains(char::is_control)
    {
        return Err(format!(
            "cannot derive a directory name from '{}'; pass DIR explicitly",
            url.to_bstring()
        )
        .into());
    }
    Ok(name.into())
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
    let (operation, registrar) = ssh::Operation::new(cancellation);
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
    .with_transport_factory(move |url, _| policy.transport(url, &staging, &registrar));

    // PrepareFetch normally deletes unsuccessful clones on drop. Preserve every
    // owned partial clone explicitly; it must remain inspectable after an error.
    let result = (|| -> crate::Result {
        let repo = prepare.repository_mut().expect("fetch has not run");
        let command_policy = repository::apply_policy(repo, &destination, report_config_paths)?;
        let mut guard = Guard::acquire(repo)?;
        let marker = repo.git_dir().join(INCOMPLETE_CLONE_FILE);
        fs::File::create_new(&marker)?;
        cancellation.check()?;
        let fetched = prepare
            .fetch_only(gix::progress::Discard, cancellation.flag())
            .map_err(Into::into);
        let (mut repo, outcome) = network::finish(operation, fetched, cancellation)?;
        network::check_outcome(&outcome)?;
        cancellation.check()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn derive(url: &str) -> crate::Result<PathBuf> {
        default_destination(&gix::url::parse(url.as_bytes().as_bstr())?)
    }

    #[test]
    fn default_destination_follows_git() -> crate::Result {
        for (url, expected) in [
            ("https://example.test/group/project.git", "project"),
            ("https://example.test/group/project", "project"),
            ("https://example.test/group/project.git/", "project"),
            ("https://example.test/group/project/.git", "project"),
            ("https://example.test/group/.git", "group"),
            ("https://example.test:8443/project.git", "project"),
            ("https://example.test:8443/", "example.test"),
            ("https://example.test", "example.test"),
            ("ssh://git@example.test/~user/project.git", "project"),
            ("git@example.test:group/project.git", "project"),
            ("git@example.test:project.git", "project"),
        ] {
            assert_eq!(derive(url)?, Path::new(expected), "{url}");
        }
        Ok(())
    }

    #[test]
    fn default_destination_is_one_new_entry() -> crate::Result {
        // The URL path is percent-decoded before the last component is taken.
        assert_eq!(derive("https://example.test/group/a%2fb")?, Path::new("b"));
        for url in [
            "https://example.test/group/..",
            "https://example.test/group/.",
            "https://example.test/group/%2e%2e",
            "https://example.test/group/a%0ab",
            "https://example.test/group/a%5cb",
        ] {
            assert!(derive(url).is_err(), "{url}");
        }
        Ok(())
    }
}
