use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use toml_edit::ImDocument;

use crate::atomic::AtomicDirectory;
use crate::config::{NetworkConfig, PolicyLimits};
use crate::curl::Client;
use crate::diagnostic::{Error, Result};
use crate::hash::{Sha256, decode_hex, hex};
use crate::lockfile::write_toml_string;
use crate::manifest::{
    DependencySource, GitDependency, GitSelector, LockedPackage, Manifest, PatchSource,
};
use crate::policy::{PackageEvidence, check_evidence_identity};
use crate::progress::Progress;
use crate::redirect::TrustPolicy;
use crate::resolver::{Catalog, PackageKey, PackageSourceKey, ResolvedPackage, ResolvedSource};
use crate::source_tree::{EntryKind, Exclusions, Tree};

use super::LockedSource;
use super::http::Remote;
use super::materialize::{extract_tree, gix_error, tree_limits};

#[derive(Clone)]
struct Object {
    source: PathBuf,
    locked: LockedSource,
    git_tree: String,
    source_tree: Tree,
    package_roots: BTreeMap<String, BTreeMap<String, Vec<PathBuf>>>,
}

#[derive(Clone, Default)]
pub(crate) struct DirectCatalog {
    packages: Vec<(Manifest, ResolvedSource)>,
    evidence: BTreeMap<PackageKey, PackageEvidence>,
}

impl DirectCatalog {
    pub(crate) fn configure(&self, catalog: &mut Catalog) -> Result<()> {
        for (manifest, source) in &self.packages {
            if matches!(
                source,
                ResolvedSource::Git {
                    patched_crates_io: true,
                    ..
                }
            ) {
                catalog.insert_git_patch(manifest.clone(), source.clone())?;
            } else {
                catalog.insert_git(manifest.clone(), source.clone())?;
            }
        }
        Ok(())
    }

    pub(crate) fn evidence(&self, package: &ResolvedPackage) -> Result<PackageEvidence> {
        let evidence = self.evidence.get(&package.key).ok_or_else(|| {
            Error::failure(format!(
                "verified Git catalog has no evidence for `{} {}`",
                package.key.name, package.key.version
            ))
        })?;
        check_evidence_identity(package, evidence)?;
        Ok(evidence.clone())
    }
}

pub(crate) fn materialize_locked_dependencies(
    manifest: &Manifest,
    network: &NetworkConfig,
    policy: &PolicyLimits,
    accept_all: bool,
    verbose: bool,
    progress: Progress,
) -> Result<DirectCatalog> {
    if !has_git_dependency(manifest) {
        return Ok(DirectCatalog::default());
    }
    for refresh in super::resolve_patch_refreshes(manifest, network, policy, verbose)? {
        if refresh.changed() {
            return Err(Error::failure(format!(
                "Git patch `{}` (`{}`) moved from {} to {}",
                refresh.alias, refresh.package, refresh.previous.commit, refresh.candidate.commit
            ))
            .with_help("review support for Git patch updates is not available yet"));
        }
    }
    let mut objects = BTreeMap::new();
    for locked in locked_sources(manifest)? {
        let destination = object_root(&manifest.workspace_root, &locked.cargo_source);
        let object = if destination.exists() {
            load_object(&manifest.workspace_root, &locked, policy)?
        } else {
            progress.report(format_args!("Fetching Git source `{}`", locked.url))?;
            materialize_one(
                &manifest.workspace_root,
                &locked,
                network,
                policy,
                accept_all,
                verbose,
            )?
        };
        objects.insert(locked.cargo_source.clone(), object);
    }
    direct_catalog(manifest, policy, &objects)
}

pub(crate) fn configure_direct(
    manifest: &Manifest,
    policy: &PolicyLimits,
    catalog: &mut Catalog,
) -> Result<()> {
    load_locked_dependencies(manifest, policy)?.configure(catalog)
}

pub(crate) fn load_locked_dependencies(
    manifest: &Manifest,
    policy: &PolicyLimits,
) -> Result<DirectCatalog> {
    if !has_git_dependency(manifest) {
        return Ok(DirectCatalog::default());
    }
    let mut objects = BTreeMap::new();
    let lock = manifest
        .lock
        .as_ref()
        .ok_or_else(|| Error::failure("Git sources require Cargo.lock"))?;
    validate_git_patches_locked(manifest, lock)?;
    for package in &lock.packages {
        let Some(source) = package.source.as_deref() else {
            continue;
        };
        let Ok(locked) = super::parse_locked_source(source) else {
            continue;
        };
        if !objects.contains_key(source) {
            objects.insert(
                source.to_owned(),
                load_object(&manifest.workspace_root, &locked, policy)?,
            );
        }
    }
    direct_catalog(manifest, policy, &objects)
}

fn direct_catalog(
    manifest: &Manifest,
    policy: &PolicyLimits,
    objects: &BTreeMap<String, Object>,
) -> Result<DirectCatalog> {
    let mut packages = Vec::new();
    let mut evidence = BTreeMap::new();
    let lock = manifest
        .lock
        .as_ref()
        .ok_or_else(|| Error::failure("Git sources require Cargo.lock"))?;
    validate_git_patches_locked(manifest, lock)?;
    for package in &lock.packages {
        let Some(source) = package.source.as_deref() else {
            continue;
        };
        if super::parse_locked_source(source).is_err() {
            continue;
        }
        let object = objects
            .get(source)
            .ok_or_else(|| Error::failure(format!("Git source `{source}` was not prepared")))?;
        let patched_crates_io = is_git_patch(manifest, package, &object.locked);
        let (inspected, source, tree) =
            locked_package(manifest, package, object, policy, patched_crates_io)?;
        let version = semver::Version::parse(&package.version.original).map_err(|error| {
            Error::failure(format!(
                "invalid locked Git version `{} {}`: {error}",
                package.name, package.version.original
            ))
        })?;
        let key = PackageKey {
            name: package.name.clone(),
            version,
            source: PackageSourceKey::Git(object.locked.cargo_source.clone()),
        };
        if evidence
            .insert(key, PackageEvidence::from_verified_git(&inspected, &tree))
            .is_some()
        {
            return Err(Error::failure(format!(
                "Git source repeats locked package `{} {}`",
                package.name, package.version.original
            )));
        }
        packages.push((inspected, source));
    }
    Ok(DirectCatalog { packages, evidence })
}

fn has_git_dependency(manifest: &Manifest) -> bool {
    manifest
        .dependencies
        .iter()
        .any(|dependency| matches!(dependency.source, DependencySource::Git(_)))
        || manifest
            .patches
            .iter()
            .any(|patch| matches!(patch.source, PatchSource::Git(_)))
}

fn validate_git_patches_locked(
    manifest: &Manifest,
    lock: &crate::manifest::Lockfile,
) -> Result<()> {
    for patch in &manifest.patches {
        let PatchSource::Git(git) = &patch.source else {
            continue;
        };
        let found = lock.packages.iter().any(|package| {
            package.name == patch.package
                && package
                    .source
                    .as_deref()
                    .and_then(|source| super::parse_locked_source(source).ok())
                    .is_some_and(|locked| locked.matches(git))
        });
        if !found {
            return Err(Error::failure(format!(
                "Git patch `{}` has no matching package in Cargo.lock",
                patch.alias
            ))
            .with_help("generate a Cargo.lock that selects the declared Git patch"));
        }
    }
    Ok(())
}

fn is_git_patch(manifest: &Manifest, package: &LockedPackage, locked: &LockedSource) -> bool {
    manifest.patches.iter().any(|patch| {
        patch.package == package.name
            && matches!(&patch.source, PatchSource::Git(git) if locked.matches(git))
    })
}

fn locked_sources(manifest: &Manifest) -> Result<Vec<LockedSource>> {
    let mut sources = BTreeSet::new();
    let lock = manifest
        .lock
        .as_ref()
        .ok_or_else(|| Error::failure("Git sources require Cargo.lock"))?;
    validate_git_patches_locked(manifest, lock)?;
    for package in &lock.packages {
        let Some(source) = package.source.as_deref() else {
            continue;
        };
        if super::parse_locked_source(source).is_ok() {
            sources.insert(source.to_owned());
        }
    }
    sources
        .into_iter()
        .map(|source| super::parse_locked_source(&source))
        .collect()
}

fn materialize_one(
    workspace: &Path,
    locked: &LockedSource,
    network: &NetworkConfig,
    policy: &PolicyLimits,
    accept_all: bool,
    verbose: bool,
) -> Result<Object> {
    let destination = object_root(workspace, &locked.cargo_source);
    let parent = destination
        .parent()
        .ok_or_else(|| Error::failure("Git object destination has no parent"))?;
    let staging = AtomicDirectory::new(parent, "git-source")?;
    let repository_path = staging.path().join("repository.git");
    let source = staging.path().join("source");
    fs::create_dir(&source)
        .map_err(|error| Error::failure(format!("failed to create Git source staging: {error}")))?;

    let limits = tree_limits(policy)?;
    let client = Client::discover(network)?;
    let trust = Arc::new(Mutex::new(TrustPolicy::load_default()?));
    let counter = Arc::new(AtomicU64::new(0));
    let http_root = staging.path().join("http");
    let worker_root = http_root.clone();
    fs::create_dir(&http_root)
        .map_err(|error| Error::failure(format!("failed to create Git HTTP staging: {error}")))?;
    let open = gix::open::Options::isolated().config_overrides([format!(
        "gitoxide.objects.allocLimit={}",
        limits.max_file_bytes
    )]);
    let mut prepare = gix::clone::PrepareFetch::new(
        locked.url.as_str(),
        &repository_path,
        gix::create::Kind::Bare,
        gix::create::Options::default(),
        open,
    )
    .map_err(gix_error)?
    .with_revision(Some(locked.commit.clone()))
    .map_err(gix_error)?;
    let max_response_bytes = policy.max_transaction_bytes;
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
    fs::remove_dir(&http_root)
        .map_err(|error| Error::failure(format!("failed to remove Git HTTP staging: {error}")))?;
    let commit = repository.head_commit().map_err(gix_error)?;
    let commit_id = commit.id.to_string();
    if commit_id != locked.commit {
        return Err(Error::failure(format!(
            "Git source resolved to {commit_id}, not locked commit {}",
            locked.commit
        )));
    }
    let git_tree = commit.tree_id().map_err(gix_error)?.to_string();
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
    approve(locked, &git_tree, &source_tree, accept_all)?;
    fs::write(
        staging.path().join("git.toml"),
        provenance(locked, &git_tree, &source_tree),
    )
    .map_err(|error| Error::failure(format!("failed to write Git provenance: {error}")))?;
    staging.commit(&destination)?;
    let source = destination.join("source");
    let package_roots = index_package_roots(&source, &source_tree);
    Ok(Object {
        source,
        locked: locked.clone(),
        git_tree,
        source_tree,
        package_roots,
    })
}

fn load_object(workspace: &Path, locked: &LockedSource, policy: &PolicyLimits) -> Result<Object> {
    let root = object_root(workspace, &locked.cargo_source);
    let metadata = fs::symlink_metadata(&root).map_err(|error| {
        Error::failure(format!(
            "Git source is not materialized\n  source: `{}`\n  reason: {error}",
            locked.cargo_source
        ))
        .with_help("run `lorry vendor [--accept-all]` to materialize the locked Git source")
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Error::failure(format!(
            "Git object `{}` is not a directory",
            root.display()
        )));
    }
    let document = ImDocument::parse(
        fs::read_to_string(root.join("git.toml"))
            .map_err(|error| Error::failure(format!("failed to read Git provenance: {error}")))?,
    )
    .map_err(|error| Error::failure(format!("invalid Git provenance: {error}")))?;
    let allowed = [
        "format-version",
        "cargo-source",
        "git-url",
        "requested-revision",
        "resolved-commit",
        "git-tree",
        "source-tree-sha256",
    ];
    if document.iter().any(|(key, _)| !allowed.contains(&key))
        || document
            .get("format-version")
            .and_then(|item| item.as_integer())
            != Some(1)
        || string(&document, "cargo-source")? != locked.cargo_source
        || string(&document, "git-url")? != locked.url
        || string(&document, "requested-revision")? != requested(&locked.selector)
        || string(&document, "resolved-commit")? != locked.commit
    {
        return Err(Error::failure(format!(
            "Git provenance for `{}` does not match Cargo.lock",
            locked.cargo_source
        )));
    }
    let git_tree = string(&document, "git-tree")?;
    if git_tree.len() != 40 || !git_tree.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::failure(
            "Git provenance tree is not a full object ID",
        ));
    }
    let expected = decode_hex::<32>(&string(&document, "source-tree-sha256")?)?;
    let source = root.join("source");
    let source_tree = Tree::scan(&source, tree_limits(policy)?, Exclusions::None)?;
    if source_tree.sha256 != expected {
        return Err(Error::failure(format!(
            "materialized Git source `{}` changed after approval",
            locked.cargo_source
        )));
    }
    let package_roots = index_package_roots(&source, &source_tree);
    Ok(Object {
        source,
        locked: locked.clone(),
        git_tree,
        source_tree,
        package_roots,
    })
}

fn index_package_roots(
    source: &Path,
    source_tree: &Tree,
) -> BTreeMap<String, BTreeMap<String, Vec<PathBuf>>> {
    let mut packages = BTreeMap::<String, BTreeMap<String, Vec<PathBuf>>>::new();
    for entry in &source_tree.entries {
        if entry.kind != EntryKind::File
            || (entry.path != "Cargo.toml" && !entry.path.ends_with("/Cargo.toml"))
        {
            continue;
        }
        let path = source.join(&entry.path);
        let Some(document) = fs::read_to_string(&path)
            .ok()
            .and_then(|source| ImDocument::parse(source).ok())
        else {
            continue;
        };
        let Some(table) = document.get("package").and_then(|item| item.as_table()) else {
            continue;
        };
        let (Some(name), Some(version)) = (
            table.get("name").and_then(|item| item.as_str()),
            table.get("version").and_then(|item| item.as_str()),
        ) else {
            continue;
        };
        packages
            .entry(name.to_owned())
            .or_default()
            .entry(version.to_owned())
            .or_default()
            .push(path.parent().expect("Cargo.toml has a parent").to_owned());
    }
    packages
}

fn locked_package(
    manifest: &Manifest,
    package: &LockedPackage,
    object: &Object,
    policy: &PolicyLimits,
    patched_crates_io: bool,
) -> Result<(Manifest, ResolvedSource, Tree)> {
    let matches = object
        .package_roots
        .get(&package.name)
        .and_then(|versions| versions.get(&package.version.original))
        .map(Vec::as_slice)
        .unwrap_or_default();
    let [root] = matches else {
        return Err(Error::failure(format!(
            "Git source `{}` contains {} manifests for locked package `{} {}`",
            object.locked.cargo_source,
            matches.len(),
            package.name,
            package.version.original
        )));
    };
    let relative = root.strip_prefix(&object.source).map_err(|_| {
        Error::failure("Git package root escaped its materialized repository source")
    })?;
    let package_path = relative
        .to_str()
        .ok_or_else(|| Error::failure("Git package path is not valid UTF-8"))?;
    let mut inspected = Manifest::load_path_dependency(root)?;
    bind_internal_dependencies(&mut inspected, object)?;
    let package_tree = object
        .source_tree
        .subtree(package_path, tree_limits(policy)?)?;
    let mut source_identity = Sha256::new();
    source_identity.update(object.locked.cargo_source.as_bytes());
    let mut logical_root = manifest
        .workspace_root
        .join(".lorry/git/sha256")
        .join(hex(&source_identity.finish()))
        .join("source");
    if !package_path.is_empty() {
        logical_root.push(package_path);
    }
    Ok((
        inspected,
        ResolvedSource::Git {
            cargo_source: object.locked.cargo_source.clone(),
            git_url: object.locked.url.clone(),
            requested_revision: requested(&object.locked.selector).to_owned(),
            resolved_commit: object.locked.commit.clone(),
            git_tree: object.git_tree.clone(),
            repository_tree_sha256: object.source_tree.sha256,
            package_path: package_path.to_owned(),
            logical_root,
            physical_root: root.clone(),
            source_tree_sha256: package_tree.sha256,
            patched_crates_io,
        },
        package_tree,
    ))
}

fn bind_internal_dependencies(manifest: &mut Manifest, object: &Object) -> Result<()> {
    for dependency in &mut manifest.dependencies {
        let DependencySource::Path(path) = &dependency.source else {
            continue;
        };
        let canonical = fs::canonicalize(path).map_err(|error| {
            Error::failure(format!(
                "failed to resolve Git package path dependency `{}`: {error}",
                path.display()
            ))
        })?;
        if canonical.strip_prefix(&object.source).is_ok() {
            dependency.source = DependencySource::Git(GitDependency {
                url: object.locked.url.clone(),
                selector: object.locked.selector.clone(),
            });
        }
    }
    Ok(())
}

pub(super) fn object_root(workspace: &Path, cargo_source: &str) -> PathBuf {
    let mut digest = Sha256::new();
    digest.update(cargo_source.as_bytes());
    workspace
        .join(".lorry/vendor/git")
        .join(hex(&digest.finish()))
}

fn provenance(locked: &LockedSource, git_tree: &str, source_tree: &Tree) -> String {
    let mut output = String::from("format-version = 1\n");
    for (name, value) in [
        ("cargo-source", locked.cargo_source.as_str()),
        ("git-url", locked.url.as_str()),
        ("requested-revision", requested(&locked.selector)),
        ("resolved-commit", locked.commit.as_str()),
        ("git-tree", git_tree),
    ] {
        output.push_str(name);
        output.push_str(" = ");
        write_toml_string(&mut output, value);
        output.push('\n');
    }
    output.push_str("source-tree-sha256 = ");
    write_toml_string(&mut output, &hex(&source_tree.sha256));
    output.push('\n');
    output
}

fn string(document: &ImDocument<String>, key: &str) -> Result<String> {
    document
        .get(key)
        .and_then(|item| item.as_str())
        .map(str::to_owned)
        .ok_or_else(|| Error::failure(format!("Git provenance `{key}` must be a string")))
}

fn requested(selector: &GitSelector) -> &str {
    match selector {
        GitSelector::Head => "HEAD",
        GitSelector::Branch(value) | GitSelector::Tag(value) | GitSelector::Revision(value) => {
            value
        }
    }
}

fn approve(locked: &LockedSource, git_tree: &str, source: &Tree, accept_all: bool) -> Result<()> {
    eprintln!(
        "Git source\n  URL: {}\n  requested: {}\n  commit: {}\n  tree: {}\n  source SHA-256: {}\n  files: {}; bytes: {}",
        locked.url,
        requested(&locked.selector),
        locked.commit,
        git_tree,
        hex(&source.sha256),
        source.file_count,
        source.total_bytes,
    );
    if accept_all {
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        return Err(
            Error::failure("Git source requires approval on non-interactive input")
                .with_help("review the evidence, then rerun `lorry vendor --accept-all`"),
        );
    }
    eprint!("Materialize this Git source? [y/N] ");
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
        Err(Error::failure("Git source was not approved"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(label: &str) -> PathBuf {
        let mut digest = Sha256::new();
        digest.update(label.as_bytes());
        digest.update(&std::process::id().to_le_bytes());
        let root =
            std::env::temp_dir().join(format!("lorry-git-{label}-{}", hex(&digest.finish())));
        fs::create_dir(&root).expect("test root is created");
        root
    }

    fn locked() -> LockedSource {
        LockedSource {
            cargo_source: "git+https://example.com/repository.git?branch=main#0123456789abcdef0123456789abcdef01234567"
                .to_owned(),
            url: "https://example.com/repository.git".to_owned(),
            selector: GitSelector::Branch("main".to_owned()),
            commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        }
    }

    #[test]
    fn internal_path_dependencies_keep_the_locked_git_source() {
        let source = root("internal-path-source");
        fs::create_dir_all(source.join("first/src")).unwrap();
        fs::create_dir_all(source.join("second/src")).unwrap();
        fs::write(
            source.join("first/Cargo.toml"),
            "[package]\nname = \"first\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\
             [dependencies]\nsecond = { path = \"../second\" }\n",
        )
        .unwrap();
        fs::write(source.join("first/src/lib.rs"), "pub fn first() {}\n").unwrap();
        fs::write(
            source.join("second/Cargo.toml"),
            "[package]\nname = \"second\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        fs::write(source.join("second/src/lib.rs"), "pub fn second() {}\n").unwrap();

        let source_tree = Tree::scan(
            &source,
            crate::source_tree::DEFAULT_LIMITS,
            Exclusions::None,
        )
        .unwrap();
        let package_roots = index_package_roots(&source, &source_tree);
        let object = Object {
            source: source.clone(),
            locked: locked(),
            git_tree: "0".repeat(40),
            source_tree,
            package_roots,
        };
        let mut manifest = Manifest::load_path_dependency(&source.join("first")).unwrap();
        bind_internal_dependencies(&mut manifest, &object).unwrap();

        assert!(matches!(
            &manifest.dependencies[0].source,
            DependencySource::Git(git)
                if git.url == object.locked.url && git.selector == object.locked.selector
        ));
        let package_tree = Tree::scan(
            &source.join("first"),
            crate::source_tree::DEFAULT_LIMITS,
            Exclusions::None,
        )
        .unwrap();
        let cargo_source = object.locked.cargo_source.clone();
        let resolved = ResolvedSource::Git {
            cargo_source: cargo_source.clone(),
            git_url: object.locked.url.clone(),
            requested_revision: requested(&object.locked.selector).to_owned(),
            resolved_commit: object.locked.commit.clone(),
            git_tree: object.git_tree.clone(),
            repository_tree_sha256: object.source_tree.sha256,
            package_path: "first".to_owned(),
            logical_root: source.join("first"),
            physical_root: source.join("first"),
            source_tree_sha256: package_tree.sha256,
            patched_crates_io: false,
        };
        let key = PackageKey {
            name: "first".to_owned(),
            version: semver::Version::parse("1.0.0").unwrap(),
            source: PackageSourceKey::Git(cargo_source),
        };
        let recorded = PackageEvidence::from_verified_git(&manifest, &package_tree);
        let package = ResolvedPackage {
            key: key.clone(),
            source: resolved.clone(),
            local_manifest: Some(manifest.clone()),
            feature_sets: BTreeMap::new(),
            compile_kinds: [crate::resolver::CompileKind::Target].into(),
            target_features: BTreeSet::new(),
            host_features: BTreeSet::new(),
            edges: Vec::new(),
            lock_edges: Vec::new(),
        };
        let direct = DirectCatalog {
            packages: vec![(manifest, resolved)],
            evidence: BTreeMap::from([(key, recorded.clone())]),
        };
        direct.configure(&mut Catalog::default()).unwrap();
        assert_eq!(direct.evidence(&package).unwrap(), recorded);
        fs::remove_dir_all(source).unwrap();
    }

    #[test]
    fn verifies_materialized_objects_and_detects_source_changes() {
        let workspace = root("object");
        let locked = locked();
        let root = object_root(&workspace, &locked.cargo_source);
        let source = root.join("source");
        fs::create_dir_all(&source).expect("source directory is created");
        fs::write(
            source.join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"1.0.0\"\n",
        )
        .expect("manifest is written");
        let limits = PolicyLimits::default();
        let tree = Tree::scan(&source, tree_limits(&limits).unwrap(), Exclusions::None).unwrap();
        fs::write(
            root.join("git.toml"),
            provenance(&locked, &"a".repeat(40), &tree),
        )
        .expect("provenance is written");

        let object = load_object(&workspace, &locked, &limits).unwrap();
        assert_eq!(object.source_tree.sha256, tree.sha256);
        assert_eq!(object.git_tree, "a".repeat(40));

        fs::write(
            source.join("Cargo.toml"),
            "[package]\nname = \"changed\"\nversion = \"1.0.0\"\n",
        )
        .expect("manifest is changed");
        let error = load_object(&workspace, &locked, &limits)
            .err()
            .expect("tampered object must fail");
        assert!(error.to_string().contains("changed after approval"));
        fs::remove_dir_all(workspace).expect("test root is removed");
    }

    #[test]
    fn missing_object_diagnostic_is_structured_and_actionable() {
        let workspace = root("missing-object");
        let locked = locked();

        let error = load_object(&workspace, &locked, &PolicyLimits::default())
            .err()
            .expect("missing object must fail")
            .render();

        assert!(error.starts_with("error: Git source is not materialized\n"));
        assert!(error.contains(&format!("  source: `{}`\n", locked.cargo_source)));
        assert!(error.contains("  reason: "));
        assert!(error.contains("\nhelp: run `lorry vendor [--accept-all]`"));
        fs::remove_dir_all(workspace).expect("test root is removed");
    }

    #[test]
    fn loads_a_git_patch_offline_without_changing_its_manifest() {
        let workspace = root("patch-object");
        fs::create_dir_all(workspace.join("src")).unwrap();
        fs::write(workspace.join("src/lib.rs"), "").unwrap();
        let manifest_source = "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
            [dependencies]\nrenamed = { package = \"demo\", version = \"=1.2.3\" }\n\
            [patch.crates-io]\nrenamed = { package = \"demo\", git = \"https://example.com/repository.git\", branch = \"main\" }\n";
        fs::write(workspace.join("Cargo.toml"), manifest_source).unwrap();
        let locked = locked();
        fs::write(
            workspace.join("Cargo.lock"),
            format!(
                "version = 4\n\n[[package]]\nname = \"demo\"\nversion = \"1.2.3\"\nsource = {:?}\n\n\
                 [[package]]\nname = \"root\"\nversion = \"0.1.0\"\ndependencies = [\n \"demo 1.2.3 ({})\",\n]\n",
                locked.cargo_source, locked.cargo_source
            ),
        )
        .unwrap();
        let root = object_root(&workspace, &locked.cargo_source);
        let source = root.join("source");
        fs::create_dir_all(source.join("src")).unwrap();
        fs::write(
            source.join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"1.2.3\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(source.join("src/lib.rs"), "pub fn demo() {}\n").unwrap();
        let limits = PolicyLimits::default();
        let tree = Tree::scan(&source, tree_limits(&limits).unwrap(), Exclusions::None).unwrap();
        fs::write(
            root.join("git.toml"),
            provenance(&locked, &"a".repeat(40), &tree),
        )
        .unwrap();
        let mut permissions = fs::metadata(workspace.join("Cargo.toml"))
            .unwrap()
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(workspace.join("Cargo.toml"), permissions).unwrap();

        let manifest = Manifest::load(&workspace).unwrap();
        let direct = load_locked_dependencies(&manifest, &limits).unwrap();
        let mut catalog = Catalog::default();
        direct.configure(&mut catalog).unwrap();
        let options = crate::resolver::Options {
            resolver: crate::manifest::Resolver::V2,
            incompatible_rust_versions: None,
            rust_version: semver::Version::parse("1.85.0").unwrap(),
            max_packages: 16,
            max_depth: 8,
        };
        let resolution = crate::resolver::resolve(&manifest, &catalog, &options, &[]).unwrap();
        assert!(resolution.packages.iter().any(|package| {
            matches!(
                package.source,
                ResolvedSource::Git {
                    patched_crates_io: true,
                    ref cargo_source,
                    ..
                } if cargo_source == &locked.cargo_source
            )
        }));
        let review = crate::admission_state::Review::from_graph(
            &manifest,
            manifest.lock.as_ref().unwrap(),
            vec![crate::admission_state::Context {
                host: "x86_64-unknown-linux-gnu".to_owned(),
                target: "x86_64-unknown-linux-gnu".to_owned(),
            }],
        )
        .unwrap();
        assert_eq!(review.locked_git[0].source, locked.cargo_source);
        assert_eq!(
            fs::read_to_string(workspace.join("Cargo.toml")).unwrap(),
            manifest_source
        );
        assert!(!workspace.join(".lorry/vendor/renamed").exists());
        fs::remove_dir_all(workspace).unwrap();
    }
}
