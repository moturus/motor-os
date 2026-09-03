use std::collections::BTreeSet;
use std::fs;
use std::sync::{Arc, Mutex};

use crate::atomic::AtomicDirectory;
use crate::config::{NetworkConfig, PolicyLimits};
use crate::curl::Client;
use crate::diagnostic::{Error, Result};
use crate::manifest::{GitDependency, GitSelector, Manifest, PatchSource};
use crate::redirect::TrustPolicy;

use super::LockedSource;
use super::direct::object_root;
use super::http::Remote;
use super::materialize::gix_error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PatchRefresh {
    pub(crate) alias: String,
    pub(crate) package: String,
    pub(crate) previous: LockedSource,
    pub(crate) candidate: LockedSource,
    pub(crate) needs_materialization: bool,
    pub(crate) retargeted_tag: bool,
}

impl PatchRefresh {
    pub(crate) fn changed(&self) -> bool {
        self.previous.commit != self.candidate.commit
    }
}

pub(crate) fn resolve_patch_refreshes(
    manifest: &Manifest,
    network: &NetworkConfig,
    policy: &PolicyLimits,
    verbose: bool,
) -> Result<Vec<PatchRefresh>> {
    let patches = locked_patches(manifest)?;
    if patches.is_empty() {
        return Ok(Vec::new());
    }
    let needs_remote = patches
        .iter()
        .any(|(_, _, dependency, _)| !is_pinned(&dependency.selector));
    let client = needs_remote
        .then(|| Client::discover(network))
        .transpose()?;
    let trust = needs_remote
        .then(TrustPolicy::load_default)
        .transpose()?
        .map(|trust| Arc::new(Mutex::new(trust)));
    let staging = needs_remote
        .then(|| {
            AtomicDirectory::new(
                &manifest.workspace_root.join(".lorry/vendor/git"),
                "git-refresh",
            )
        })
        .transpose()?;
    let mut refreshes = Vec::with_capacity(patches.len());
    for (index, (alias, package, dependency, previous)) in patches.into_iter().enumerate() {
        let commit = if is_pinned(&dependency.selector) {
            if !previous
                .commit
                .get(..requested(&dependency.selector).len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(requested(&dependency.selector)))
            {
                return Err(Error::failure(format!(
                    "locked Git patch `{alias}` does not match its pinned revision"
                )));
            }
            previous.commit.clone()
        } else {
            resolve_remote_commit(
                &dependency,
                client.as_ref().expect("mutable selector discovers curl"),
                trust.as_ref().expect("mutable selector loads trust policy"),
                staging
                    .as_ref()
                    .expect("mutable selector creates staging")
                    .path()
                    .join(index.to_string()),
                policy.max_transaction_bytes,
                verbose,
            )?
        };
        let candidate = with_commit(&previous, commit);
        let changed = previous.commit != candidate.commit;
        refreshes.push(PatchRefresh {
            alias,
            package,
            needs_materialization: !object_root(&manifest.workspace_root, &candidate.cargo_source)
                .exists(),
            retargeted_tag: changed && matches!(dependency.selector, GitSelector::Tag(_)),
            previous,
            candidate,
        });
    }
    Ok(refreshes)
}

fn locked_patches(
    manifest: &Manifest,
) -> Result<Vec<(String, String, GitDependency, LockedSource)>> {
    let lock = manifest
        .lock
        .as_ref()
        .ok_or_else(|| Error::failure("Git patches require Cargo.lock"))?;
    let mut patches = Vec::new();
    for patch in &manifest.patches {
        let PatchSource::Git(dependency) = &patch.source else {
            continue;
        };
        let matches = lock
            .packages
            .iter()
            .filter(|package| package.name == patch.package)
            .filter_map(|package| package.source.as_deref())
            .filter_map(|source| super::parse_locked_source(source).ok())
            .filter(|locked| locked.matches(dependency))
            .collect::<Vec<_>>();
        let [previous] = matches.as_slice() else {
            return Err(Error::failure(format!(
                "Git patch `{}` has {} matching packages in Cargo.lock",
                patch.alias,
                matches.len()
            ))
            .with_help("generate a Cargo.lock that selects the declared Git patch"));
        };
        patches.push((
            patch.alias.clone(),
            patch.package.clone(),
            dependency.clone(),
            previous.clone(),
        ));
    }
    Ok(patches)
}

fn resolve_remote_commit(
    dependency: &GitDependency,
    client: &Client,
    trust: &Arc<Mutex<TrustPolicy>>,
    staging: std::path::PathBuf,
    max_response_bytes: u64,
    verbose: bool,
) -> Result<String> {
    fs::create_dir(&staging).map_err(|error| {
        Error::failure(format!("failed to create Git refresh staging: {error}"))
    })?;
    let repository = gix::ThreadSafeRepository::init_opts(
        staging.join("repository.git"),
        gix::create::Kind::Bare,
        gix::create::Options::default(),
        gix::open::Options::isolated(),
    )
    .map_err(gix_error)?
    .to_thread_local();
    let refspecs = refspecs(&dependency.selector)
        .into_iter()
        .map(gix::bstr::BString::from)
        .collect::<Vec<_>>();
    let remote = repository
        .remote_at(dependency.url.as_str())
        .map_err(gix_error)?
        .with_refspecs(refspecs, gix::remote::Direction::Fetch)
        .map_err(gix_error)?;
    let (url, protocol) = remote
        .sanitized_url_and_version(gix::remote::Direction::Fetch)
        .map_err(gix_error)?;
    let http = Remote::new(
        client.clone(),
        trust.clone(),
        staging.join("http"),
        max_response_bytes,
        verbose,
    )
    .map_err(|error| Error::failure(format!("failed to start Git refresh transport: {error}")))?;
    let transport =
        gix_transport::client::blocking_io::http::Transport::new_http(http, url, protocol, false);
    let connection = remote.to_connection_with_transport(transport);
    let (map, _) = connection
        .ref_map(
            gix::progress::Discard,
            gix::remote::ref_map::Options::default(),
        )
        .map_err(gix_error)?;
    let refs = map
        .remote_refs
        .iter()
        .filter_map(advertised_ref)
        .collect::<Vec<_>>();
    select_commit(&dependency.selector, &refs)
}

fn advertised_ref(reference: &gix::protocol::handshake::Ref) -> Option<(String, String)> {
    use gix::protocol::handshake::Ref;
    let (name, object) = match reference {
        Ref::Peeled {
            full_ref_name,
            object,
            ..
        }
        | Ref::Direct {
            full_ref_name,
            object,
        }
        | Ref::Symbolic {
            full_ref_name,
            object,
            ..
        } => (full_ref_name, object),
        Ref::Unborn { .. } => return None,
    };
    Some((
        std::str::from_utf8(name.as_ref()).ok()?.to_owned(),
        object.to_string(),
    ))
}

fn refspecs(selector: &GitSelector) -> Vec<String> {
    match selector {
        GitSelector::Head => vec!["+HEAD:refs/remotes/lorry/HEAD".to_owned()],
        GitSelector::Branch(value) => {
            vec![format!("+refs/heads/{value}:refs/remotes/lorry/branch")]
        }
        GitSelector::Tag(value) => vec![format!("+refs/tags/{value}:refs/remotes/lorry/tag")],
        GitSelector::Revision(value) if value.starts_with("refs/") => {
            vec![format!("+{value}:refs/remotes/lorry/revision")]
        }
        GitSelector::Revision(_) => vec![
            "+refs/heads/*:refs/remotes/lorry/heads/*".to_owned(),
            "+refs/tags/*:refs/remotes/lorry/tags/*".to_owned(),
            "+HEAD:refs/remotes/lorry/HEAD".to_owned(),
        ],
    }
}

fn select_commit(selector: &GitSelector, refs: &[(String, String)]) -> Result<String> {
    let names = match selector {
        GitSelector::Head => vec!["HEAD".to_owned()],
        GitSelector::Branch(value) => vec![format!("refs/heads/{value}")],
        GitSelector::Tag(value) => vec![format!("refs/tags/{value}")],
        GitSelector::Revision(value) if value.starts_with("refs/") => vec![value.clone()],
        GitSelector::Revision(value) => vec![
            value.clone(),
            format!("refs/{value}"),
            format!("refs/tags/{value}"),
            format!("refs/heads/{value}"),
        ],
    };
    let commits = refs
        .iter()
        .filter(|(name, _)| names.contains(name))
        .map(|(_, commit)| commit.clone())
        .collect::<BTreeSet<_>>();
    let commits = commits.iter().collect::<Vec<_>>();
    let [commit] = commits.as_slice() else {
        return Err(Error::failure(format!(
            "Git selector `{}` resolved to {} commits",
            requested(selector),
            commits.len()
        )));
    };
    if commit.len() != 40
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::failure(
            "Git remote resolved to a non-SHA-1 object ID",
        ));
    }
    Ok((*commit).clone())
}

fn is_pinned(selector: &GitSelector) -> bool {
    matches!(selector, GitSelector::Revision(value) if (7..=40).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn requested(selector: &GitSelector) -> &str {
    match selector {
        GitSelector::Head => "HEAD",
        GitSelector::Branch(value) | GitSelector::Tag(value) | GitSelector::Revision(value) => {
            value
        }
    }
}

fn with_commit(previous: &LockedSource, commit: String) -> LockedSource {
    let remote = previous
        .cargo_source
        .rsplit_once('#')
        .expect("parsed Git source contains commit")
        .0;
    LockedSource {
        cargo_source: format!("{remote}#{commit}"),
        url: previous.url.clone(),
        selector: previous.selector.clone(),
        commit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = "0123456789abcdef0123456789abcdef01234567";
    const NEW: &str = "fedcba9876543210fedcba9876543210fedcba98";

    fn selected(selector: GitSelector, name: &str) -> String {
        select_commit(&selector, &[(name.to_owned(), NEW.to_owned())]).unwrap()
    }

    #[test]
    fn resolves_every_mutable_selector_from_advertised_refs() {
        assert_eq!(selected(GitSelector::Head, "HEAD"), NEW);
        assert_eq!(
            selected(GitSelector::Branch("main".to_owned()), "refs/heads/main"),
            NEW
        );
        assert_eq!(
            selected(GitSelector::Tag("v1".to_owned()), "refs/tags/v1"),
            NEW
        );
        assert_eq!(
            selected(
                GitSelector::Revision("refs/pull/493/head".to_owned()),
                "refs/pull/493/head"
            ),
            NEW
        );
        assert_eq!(
            selected(
                GitSelector::Revision("topic".to_owned()),
                "refs/heads/topic"
            ),
            NEW
        );
    }

    #[test]
    fn only_cargo_style_commit_revisions_are_pinned() {
        for value in ["0123456", OLD, "ABCDEF0"] {
            assert!(is_pinned(&GitSelector::Revision(value.to_owned())));
        }
        for value in ["012345", "refs/heads/0123456", "main", &"a".repeat(41)] {
            assert!(!is_pinned(&GitSelector::Revision(value.to_owned())));
        }
    }

    #[test]
    fn candidate_records_unchanged_first_materialization_and_tag_movement() {
        let previous = LockedSource {
            cargo_source: format!("git+https://example.com/repo?tag=v1#{OLD}"),
            url: "https://example.com/repo".to_owned(),
            selector: GitSelector::Tag("v1".to_owned()),
            commit: OLD.to_owned(),
        };
        let unchanged = with_commit(&previous, OLD.to_owned());
        assert_eq!(unchanged, previous);
        let moved = with_commit(&previous, NEW.to_owned());
        assert_eq!(moved.commit, NEW);
        assert_ne!(moved.cargo_source, previous.cargo_source);
    }

    #[test]
    fn ambiguous_or_missing_named_revisions_fail_closed() {
        let selector = GitSelector::Revision("same".to_owned());
        assert!(select_commit(&selector, &[]).is_err());
        assert!(
            select_commit(
                &selector,
                &[
                    ("refs/heads/same".to_owned(), OLD.to_owned()),
                    ("refs/tags/same".to_owned(), NEW.to_owned()),
                ],
            )
            .is_err()
        );
    }
}
