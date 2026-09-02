use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::atomic::AtomicDirectory;
use crate::config::{NetworkConfig, PolicyLimits};
use crate::curl::Client;
use crate::diagnostic::{Error, Result};
use crate::hash::hex;
use crate::manifest::Manifest;
use crate::redirect::TrustPolicy;
use crate::source_tree::{EntryKind, Exclusions, Limits, Tree};
use crate::toml::Document;

use super::http::Remote;
use super::{GitPatch, Materialized, Selector};

pub(super) fn materialize_one(
    root: &Path,
    patch: &GitPatch,
    network: &NetworkConfig,
    policy: &PolicyLimits,
    accept_all: bool,
    verbose: bool,
) -> Result<Materialized> {
    let relative = format!(".lorry/vendor/{}/source", patch.alias);
    let destination = root.join(".lorry/vendor").join(&patch.alias);
    if destination.exists() {
        return Err(Error::failure(format!(
            "Git patch destination `{}` already exists while Cargo.toml still declares Git",
            destination.display()
        ))
        .with_help(
            "remove the incomplete destination after review, or restore its matching local path patch",
        ));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| Error::failure("Git patch destination has no parent"))?;
    let staging = AtomicDirectory::new(parent, &format!("git-{}", patch.alias))?;
    let repository_path = staging.path().join("repository.git");
    let source = staging.path().join("source");
    fs::create_dir(&source)
        .map_err(|error| Error::failure(format!("failed to create Git source staging: {error}")))?;

    let limits = tree_limits(policy)?;
    let max_response_bytes = policy.max_transaction_bytes;
    let client = Client::discover(network)?;
    let trust = Arc::new(Mutex::new(TrustPolicy::load_default()?));
    let counter = Arc::new(AtomicU64::new(0));
    let factory_root = staging.path().join("http");
    let worker_root = factory_root.clone();
    fs::create_dir(&factory_root)
        .map_err(|error| Error::failure(format!("failed to create Git HTTP staging: {error}")))?;
    let open = gix::open::Options::isolated().config_overrides([format!(
        "gitoxide.objects.allocLimit={}",
        limits.max_file_bytes
    )]);
    let mut prepare = gix::clone::PrepareFetch::new(
        patch.url.as_str(),
        &repository_path,
        gix::create::Kind::Bare,
        gix::create::Options::default(),
        open,
    )
    .map_err(gix_error)?;
    prepare = select_revision(prepare, patch)?;
    if can_fetch_shallow(patch) {
        prepare = prepare.with_shallow(gix::remote::fetch::Shallow::DepthAtRemote(
            1_u32.try_into().expect("one is nonzero"),
        ));
    }
    prepare = prepare.with_transport_factory(move |url, protocol| {
        let id = counter.fetch_add(1, Ordering::Relaxed);
        let remote = Remote::new(
            client.clone(),
            trust.clone(),
            worker_root.join(id.to_string()),
            max_response_bytes,
            verbose,
        )?;
        Ok(Box::new(
            gix_transport::client::blocking_io::http::Transport::new_http(
                remote, url, protocol, false,
            ),
        ))
    });
    let (repository, _) = prepare
        .fetch_only(gix::progress::Discard, &AtomicBool::default())
        .map_err(gix_error)?;
    fs::remove_dir(&factory_root)
        .map_err(|error| Error::failure(format!("failed to remove Git HTTP staging: {error}")))?;
    let commit = repository.head_commit().map_err(gix_error)?;
    let commit_id = commit.id.to_string();
    if let Some(locked) = &patch.locked_commit
        && &commit_id != locked
    {
        return Err(Error::failure(format!(
            "Git patch `{}` resolved to {commit_id}, not locked commit {locked}",
            patch.alias
        )));
    }
    let tree_id = commit.tree_id().map_err(gix_error)?.to_string();
    let tree = commit.tree().map_err(gix_error)?;
    extract_tree(&repository, &tree, &source, limits)?;
    drop(tree);
    drop(commit);
    drop(repository);
    fs::remove_dir_all(&repository_path).map_err(|error| {
        Error::failure(format!(
            "failed to remove private Git object staging: {error}"
        ))
    })?;

    let source_tree = Tree::scan(&source, limits, Exclusions::None)?;
    let package_path = locate_patch_package(patch, &source, &source_tree)?;
    approve(patch, &commit_id, &tree_id, &source_tree, accept_all)?;
    let provenance = format!(
        "format-version = 1\nalias = {:?}\ngit-url = {:?}\nrequested-revision = {:?}\nresolved-commit = {:?}\ngit-tree = {:?}\nsource-tree-sha256 = {:?}\n",
        patch.alias,
        patch.url,
        patch.selector.requested(),
        commit_id,
        tree_id,
        hex(&source_tree.sha256),
    );
    fs::write(staging.path().join("git.toml"), provenance)
        .map_err(|error| Error::failure(format!("failed to write Git provenance: {error}")))?;
    staging.commit(&destination)?;
    Ok(Materialized {
        path: if package_path.is_empty() {
            relative
        } else {
            format!("{relative}/{package_path}")
        },
    })
}

fn locate_patch_package(patch: &GitPatch, source: &Path, tree: &Tree) -> Result<String> {
    let package = patch.package.as_deref().unwrap_or(&patch.alias);
    let mut matches = Vec::new();
    for entry in &tree.entries {
        if entry.kind != EntryKind::File
            || (entry.path != "Cargo.toml" && !entry.path.ends_with("/Cargo.toml"))
        {
            continue;
        }
        let path = source.join(&entry.path);
        let Ok(document) = Document::load(&path, "Git package manifest") else {
            continue;
        };
        if document
            .root()
            .get("package")
            .and_then(|item| item.as_table())
            .and_then(|table| table.get("name"))
            .and_then(|item| item.as_str())
            != Some(package)
        {
            continue;
        }
        matches.push(
            entry
                .path
                .strip_suffix("/Cargo.toml")
                .unwrap_or_default()
                .to_owned(),
        );
    }
    let [package_path] = matches.as_slice() else {
        return Err(Error::failure(format!(
            "Git patch `{}` contains {} manifests for package `{package}`",
            patch.alias,
            matches.len()
        )));
    };
    let package_root = if package_path.is_empty() {
        source.to_owned()
    } else {
        source.join(package_path)
    };
    Manifest::load_path_dependency(&package_root)?;
    Ok(package_path.clone())
}

fn select_revision(
    prepare: gix::clone::PrepareFetch,
    patch: &GitPatch,
) -> Result<gix::clone::PrepareFetch> {
    let revision = patch
        .locked_commit
        .as_deref()
        .map(str::to_owned)
        .or_else(|| match &patch.selector {
            Selector::Head => Some("HEAD".to_owned()),
            Selector::Branch(value) => Some(format!("refs/heads/{value}")),
            Selector::Tag(value) => Some(format!("refs/tags/{value}")),
            Selector::Revision(value) if is_object_id(value) => Some(value.clone()),
            Selector::Revision(_) => None,
        });
    if let Some(revision) = revision {
        return prepare.with_revision(Some(revision)).map_err(gix_error);
    }
    let Selector::Revision(revision) = &patch.selector else {
        unreachable!()
    };
    prepare
        .with_ref_name(Some(revision.as_str()))
        .map_err(gix_error)
}

fn can_fetch_shallow(patch: &GitPatch) -> bool {
    patch.locked_commit.is_none()
        && !matches!(&patch.selector, Selector::Revision(value) if is_object_id(value))
}

pub(super) fn extract_tree(
    repository: &gix::Repository,
    tree: &gix::Tree<'_>,
    root: &Path,
    limits: Limits,
) -> Result<()> {
    let entries = tree.traverse().breadthfirst.files().map_err(gix_error)?;
    if entries.len() > limits.max_entries {
        return Err(Error::failure(format!(
            "Git source exceeds the entry-count limit of {}",
            limits.max_entries
        )));
    }
    let mut indexed = BTreeMap::new();
    for entry in &entries {
        let relative = portable_git_path(entry.filepath.as_ref(), limits)?.to_owned();
        let kind = if entry.mode.is_tree() {
            ExtractKind::Directory
        } else if entry.mode.is_blob() {
            ExtractKind::File {
                oid: entry.oid,
                executable: entry.mode.is_executable(),
            }
        } else if entry.mode.is_link() {
            let object = repository.find_object(entry.oid).map_err(gix_error)?;
            if object.kind != gix::objs::Kind::Blob {
                return Err(Error::failure(format!(
                    "Git symbolic link `{relative}` is not a valid blob"
                )));
            }
            if object.data.len() > limits.max_path_bytes {
                return Err(Error::failure(format!(
                    "Git symbolic link `{relative}` exceeds the path-byte limit of {}",
                    limits.max_path_bytes
                )));
            }
            let target = std::str::from_utf8(&object.data).map_err(|_| {
                Error::failure(format!(
                    "Git symbolic link `{relative}` target is not valid UTF-8"
                ))
            })?;
            ExtractKind::Link(target.to_owned())
        } else {
            return Err(Error::failure(format!(
                "Git source entry `{relative}` has unsupported mode {:o}",
                entry.mode
            )));
        };
        indexed.insert(relative, kind);
    }

    for (relative, kind) in &indexed {
        if matches!(kind, ExtractKind::Directory) {
            let path = root.join(relative);
            fs::create_dir(&path).map_err(|error| {
                Error::failure(format!(
                    "failed to create Git source directory `{relative}`: {error}"
                ))
            })?;
        }
    }

    let mut total = 0_u64;
    for (relative, kind) in &indexed {
        if matches!(kind, ExtractKind::Directory) {
            continue;
        }
        let (oid, executable) = resolve_materialized_file(relative, &indexed, limits)?;
        let header = repository.find_header(*oid).map_err(gix_error)?;
        if header.size() > limits.max_file_bytes {
            return Err(Error::failure(format!(
                "Git source file `{relative}` exceeds the byte limit of {}",
                limits.max_file_bytes
            )));
        }
        total = total
            .checked_add(header.size())
            .filter(|total| *total <= limits.max_tree_bytes)
            .ok_or_else(|| {
                Error::failure(format!(
                    "Git source exceeds the byte limit of {}",
                    limits.max_tree_bytes
                ))
            })?;
        let object = repository.find_object(*oid).map_err(gix_error)?;
        if object.kind != gix::objs::Kind::Blob || object.data.len() as u64 != header.size() {
            return Err(Error::failure(format!(
                "Git source entry `{relative}` is not a valid blob"
            )));
        }
        let path = root.join(relative);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                Error::failure(format!(
                    "failed to create Git source file `{relative}`: {error}"
                ))
            })?;
        file.write_all(&object.data).map_err(|error| {
            Error::failure(format!(
                "failed to write Git source file `{relative}`: {error}"
            ))
        })?;
        file.flush().map_err(|error| {
            Error::failure(format!(
                "failed to flush Git source file `{relative}`: {error}"
            ))
        })?;
        set_file_mode(&file, &path, executable)?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
enum ExtractKind {
    Directory,
    File {
        oid: gix::ObjectId,
        executable: bool,
    },
    Link(String),
}

fn resolve_materialized_file<'a>(
    path: &str,
    entries: &'a BTreeMap<String, ExtractKind>,
    limits: Limits,
) -> Result<(&'a gix::ObjectId, bool)> {
    let mut current = path.to_owned();
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(current.clone()) {
            return Err(Error::failure(format!(
                "Git symbolic link `{path}` contains a cycle at `{current}`"
            )));
        }
        match entries.get(&current) {
            Some(ExtractKind::File { oid, executable }) => return Ok((oid, *executable)),
            Some(ExtractKind::Link(target)) => {
                current = normalize_link_target(&current, target, limits)?;
            }
            Some(ExtractKind::Directory) => {
                return Err(Error::failure(format!(
                    "Git symbolic link `{path}` resolves to directory `{current}`"
                )));
            }
            None => {
                return Err(Error::failure(format!(
                    "Git symbolic link `{path}` resolves to missing entry `{current}`"
                )));
            }
        }
    }
}

fn normalize_link_target(link: &str, target: &str, limits: Limits) -> Result<String> {
    if target.is_empty()
        || target.len() > limits.max_path_bytes
        || target.starts_with('/')
        || target.contains('\\')
        || target
            .bytes()
            .any(|byte| byte == 0 || byte < 0x20 || byte == 0x7f)
    {
        return Err(Error::failure(format!(
            "Git symbolic link `{link}` has non-portable target `{target}`"
        )));
    }
    let mut components = link
        .rsplit_once('/')
        .map_or(Vec::new(), |(parent, _)| parent.split('/').collect());
    for component in target.split('/') {
        match component {
            "" => {
                return Err(Error::failure(format!(
                    "Git symbolic link `{link}` has non-portable target `{target}`"
                )));
            }
            "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(Error::failure(format!(
                        "Git symbolic link `{link}` escapes the source tree through `{target}`"
                    )));
                }
            }
            _ => components.push(component),
        }
    }
    let resolved = components.join("/");
    if resolved.is_empty() || resolved.len() > limits.max_path_bytes {
        return Err(Error::failure(format!(
            "Git symbolic link `{link}` has non-portable target `{target}`"
        )));
    }
    Ok(resolved)
}

fn portable_git_path(bytes: &[u8], limits: Limits) -> Result<&str> {
    let path = std::str::from_utf8(bytes)
        .map_err(|_| Error::failure("Git source path is not valid UTF-8"))?;
    if path.is_empty()
        || path.len() > limits.max_path_bytes
        || path.contains('\\')
        || path
            .bytes()
            .any(|byte| byte == 0 || byte < 0x20 || byte == 0x7f)
        || Path::new(path)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Error::failure(format!(
            "non-portable Git source path `{path}`"
        )));
    }
    Ok(path)
}

fn approve(
    patch: &GitPatch,
    commit: &str,
    tree: &str,
    source: &Tree,
    accept_all: bool,
) -> Result<()> {
    eprintln!(
        "Git patch {}\n  URL: {}\n  requested: {}\n  commit: {}\n  tree: {}\n  source SHA-256: {}\n  files: {}; bytes: {}",
        patch.alias,
        patch.url,
        patch.selector.requested(),
        commit,
        tree,
        hex(&source.sha256),
        source.file_count,
        source.total_bytes,
    );
    if accept_all {
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        return Err(Error::failure(format!(
            "Git patch `{}` requires approval on non-interactive input",
            patch.alias
        ))
        .with_help("review the evidence, then rerun `lorry vendor --accept-all`"));
    }
    eprint!("Materialize this Git patch? [y/N] ");
    io::stderr()
        .flush()
        .map_err(|error| Error::failure(format!("failed to flush Git approval prompt: {error}")))?;
    let answer = crate::prompt::read_answer(
        &mut io::stdin().lock(),
        &mut io::stderr().lock(),
        crate::prompt::echo_required(true),
    )
    .map_err(|error| Error::failure(format!("failed to read Git approval: {error}")))?;
    if answer.trim().eq_ignore_ascii_case("y") || answer.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        Err(Error::failure(format!(
            "Git patch `{}` was not approved",
            patch.alias
        )))
    }
}

pub(super) fn tree_limits(policy: &PolicyLimits) -> Result<Limits> {
    Ok(Limits {
        max_entries: usize::try_from(policy.max_package_files)
            .map_err(|_| Error::failure("Git source file limit does not fit this platform"))?,
        max_path_bytes: 4096,
        max_file_bytes: policy.max_extracted_package_bytes,
        max_tree_bytes: policy.max_extracted_package_bytes,
    })
}

fn is_object_id(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn gix_error(error: impl std::error::Error) -> Error {
    use std::fmt::Write as _;

    let mut message = format!("Git operation failed: {error}");
    let mut source = error.source();
    while let Some(error) = source {
        let _ = write!(message, ": {error}");
        source = error.source();
    }
    Error::failure(message)
}

fn set_file_mode(_file: &File, _path: &Path, executable: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        _file
            .set_permissions(fs::Permissions::from_mode(if executable {
                0o700
            } else {
                0o600
            }))
            .map_err(|error| {
                Error::failure(format!(
                    "failed to set Git file permissions `{}`: {error}",
                    _path.display()
                ))
            })?;
    }
    #[cfg(target_os = "motor")]
    {
        use std::os::fd::AsRawFd;
        let permissions = if executable {
            moto_rt::fs::PERM_READ | moto_rt::fs::PERM_EXEC
        } else {
            moto_rt::fs::PERM_READ | moto_rt::fs::PERM_WRITE
        };
        moto_rt::fs::set_file_perm(_file.as_raw_fd(), permissions).map_err(|error| {
            Error::failure(format!(
                "failed to set Git file permissions `{}`: {error}",
                _path.display()
            ))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_tree::DEFAULT_LIMITS;

    fn file() -> ExtractKind {
        ExtractKind::File {
            oid: gix::ObjectId::null(gix::hash::Kind::Sha1),
            executable: false,
        }
    }

    #[test]
    fn resolves_only_internal_regular_file_links() {
        let mut entries = BTreeMap::new();
        entries.insert("LICENSE-MIT".to_owned(), file());
        entries.insert(
            "crate/LICENSE-MIT".to_owned(),
            ExtractKind::Link("../LICENSE-MIT".to_owned()),
        );
        entries.insert(
            "crate/COPYING".to_owned(),
            ExtractKind::Link("./LICENSE-MIT".to_owned()),
        );
        entries.insert(
            "crate/LICENSE-APACHE".to_owned(),
            ExtractKind::Link("COPYING".to_owned()),
        );

        assert!(resolve_materialized_file("crate/LICENSE-MIT", &entries, DEFAULT_LIMITS).is_ok());
        assert!(
            resolve_materialized_file("crate/LICENSE-APACHE", &entries, DEFAULT_LIMITS).is_ok()
        );
        assert_eq!(
            normalize_link_target("crate/LICENSE-MIT", "../LICENSE-MIT", DEFAULT_LIMITS).unwrap(),
            "LICENSE-MIT"
        );
    }

    #[test]
    fn rejects_unsafe_or_unresolvable_links() {
        let mut entries = BTreeMap::new();
        entries.insert("directory".to_owned(), ExtractKind::Directory);
        entries.insert(
            "cycle-a".to_owned(),
            ExtractKind::Link("cycle-b".to_owned()),
        );
        entries.insert(
            "cycle-b".to_owned(),
            ExtractKind::Link("cycle-a".to_owned()),
        );
        entries.insert(
            "directory-link".to_owned(),
            ExtractKind::Link("directory".to_owned()),
        );
        entries.insert(
            "missing-link".to_owned(),
            ExtractKind::Link("missing".to_owned()),
        );

        assert!(resolve_materialized_file("cycle-a", &entries, DEFAULT_LIMITS).is_err());
        assert!(resolve_materialized_file("directory-link", &entries, DEFAULT_LIMITS).is_err());
        assert!(resolve_materialized_file("missing-link", &entries, DEFAULT_LIMITS).is_err());
        for target in ["/absolute", "../../escape", "bad\\path", "bad\npath", ""] {
            assert!(normalize_link_target("crate/link", target, DEFAULT_LIMITS).is_err());
        }
    }

    #[test]
    fn locates_a_patch_package_below_a_virtual_workspace() {
        let source =
            std::env::temp_dir().join(format!("lorry-git-patch-package-{}", std::process::id()));
        let _ = fs::remove_dir_all(&source);
        fs::create_dir_all(source.join("tokio/src")).unwrap();
        fs::write(
            source.join("Cargo.toml"),
            "[workspace]\nmembers = [\"tokio\"]\n",
        )
        .unwrap();
        fs::write(
            source.join("tokio/Cargo.toml"),
            "[package]\nname = \"tokio\"\nversion = \"1.47.1\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(source.join("tokio/src/lib.rs"), "pub fn runtime() {}\n").unwrap();
        let patch = GitPatch {
            alias: "tokio".to_owned(),
            package: None,
            url: "https://example.com/tokio.git".to_owned(),
            selector: Selector::Branch("motor".to_owned()),
            locked_commit: None,
            span: 0..0,
        };
        let tree = Tree::scan(&source, DEFAULT_LIMITS, Exclusions::None).unwrap();

        assert_eq!(
            locate_patch_package(&patch, &source, &tree).unwrap(),
            "tokio"
        );
        fs::remove_dir_all(source).unwrap();
    }

    #[test]
    fn only_named_unlocked_revisions_use_shallow_fetches() {
        let patch = |selector, locked_commit| GitPatch {
            alias: "patched".to_owned(),
            package: None,
            url: "https://example.com/patched.git".to_owned(),
            selector,
            locked_commit,
            span: 0..0,
        };

        assert!(can_fetch_shallow(&patch(Selector::Head, None)));
        assert!(can_fetch_shallow(&patch(
            Selector::Branch("main".to_owned()),
            None,
        )));
        assert!(!can_fetch_shallow(&patch(
            Selector::Revision("0123456789abcdef0123456789abcdef01234567".to_owned()),
            None,
        )));
        assert!(!can_fetch_shallow(&patch(
            Selector::Branch("main".to_owned()),
            Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
        )));
    }

    #[test]
    fn locates_the_motor_tokio_patch_when_requested() {
        let Some(source) = std::env::var_os("LORRY_TEST_TOKIO_CHECKOUT") else {
            return;
        };
        let source = Path::new(&source);
        let tree = Tree::scan(source, DEFAULT_LIMITS, Exclusions::GitAndTarget).unwrap();
        let patch = GitPatch {
            alias: "tokio".to_owned(),
            package: None,
            url: "https://github.com/moturus/tokio.git".to_owned(),
            selector: Selector::Branch("tokio-motor-1.47.1_2025-10-07".to_owned()),
            locked_commit: Some("f9d26ea874753c0b5126401e77daee9e6222c359".to_owned()),
            span: 0..0,
        };
        assert_eq!(
            locate_patch_package(&patch, source, &tree).unwrap(),
            "tokio"
        );
    }
}
