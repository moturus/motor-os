use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::Path;

use semver::Version;

use crate::admission_state::{self, CompactState, Context};
use crate::archive::{ExtractedArchive, Limits as ArchiveLimits, extract_crate};
use crate::atomic::AtomicFile;
use crate::change_review;
use crate::cli::{Cli, VendorMode, VendorOptions, Verbosity};
use crate::config::{Config, PolicyLimits};
use crate::curl::{Client, archive_url, sparse_url};
use crate::dependency;
use crate::diagnostic::{Error, Result};
use crate::hash::hex;
use crate::lockfile;
use crate::manifest::Manifest;
use crate::policy::{self, PackageEvidence};
use crate::progress::Progress;
use crate::redirect::TrustPolicy;
use crate::repository::{RepositorySet, RepositoryTransaction, RepositoryWriter};
use crate::resolver::{
    self, Catalog, LockedPreference, PackageKey, PackageSourceKey, Resolution, ResolvedPackage,
    ResolvedSource, TargetSelection,
};
use crate::source_tree::Limits as TreeLimits;
use crate::sparse;
use crate::toolchain::{TargetInfo, Toolchain};
use crate::upgrade;
use crate::vendor_lock::ProjectVendorLock;

mod migration;
pub(crate) mod workspace;

pub fn execute(cli: &Cli, options: &VendorOptions) -> Result<i32> {
    if options.locked {
        if !matches!(options.mode, VendorMode::Sync) {
            return Err(Error::usage(
                "a locked vendor cannot upgrade dependencies",
                "remove the upgrade request or --locked",
            ));
        }
        return workspace::vendor_workspace(cli, options);
    }
    if options.offline {
        return Err(Error::usage(
            "offline workspace admission requires --locked",
            "use `lorry vendor --locked --offline`",
        ));
    }
    workspace::vendor_workspace(cli, options)
}

fn apply_patch_refreshes(
    manifest: &Manifest,
    refreshes: &[crate::git::PatchRefresh],
) -> Result<Manifest> {
    let mut candidate = manifest.clone();
    if !refreshes.iter().any(crate::git::PatchRefresh::changed) {
        return Ok(candidate);
    }
    let lock = candidate
        .lock
        .as_mut()
        .ok_or_else(|| Error::failure("Git patches require Cargo.lock"))?;
    for refresh in refreshes.iter().filter(|refresh| refresh.changed()) {
        let mut replaced = false;
        for package in &mut lock.packages {
            if package.source.as_deref() == Some(&refresh.previous.cargo_source) {
                package.source = Some(refresh.candidate.cargo_source.clone());
                replaced = true;
            }
            for dependency in &mut package.dependencies {
                if dependency.contains(&refresh.previous.cargo_source) {
                    *dependency = dependency.replace(
                        &refresh.previous.cargo_source,
                        &refresh.candidate.cargo_source,
                    );
                }
            }
        }
        if !replaced {
            return Err(Error::failure(format!(
                "Git patch `{}` has no locked source to refresh",
                refresh.alias
            )));
        }
    }
    Ok(candidate)
}

fn vendor_contexts(
    toolchain: &Toolchain,
    config: &Config,
    host: &TargetInfo,
    previous: Option<&CompactState>,
) -> Result<Vec<VendorContext>> {
    let mut triples = config
        .vendor
        .targets
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if config.vendor.include_host {
        triples.insert(host.triple.clone());
    }
    if triples.is_empty() {
        return Err(
            Error::failure("the candidate vendor context set for this host is empty")
                .with_help("configure `[vendor].targets` or set `include-host = true`"),
        );
    }
    // The current host's context set is replaced by the configured set;
    // contexts reviewed on every other host are preserved exactly. Contexts
    // dropped from the current host's set are still resolved once so the
    // committed baseline stays reconstructible during this run.
    let mut recorded = BTreeMap::new();
    for triple in triples {
        recorded.insert((host.triple.clone(), triple), true);
    }
    if let Some(previous) = previous {
        for context in &previous.contexts {
            let key = (context.host.clone(), context.target.clone());
            if context.host != host.triple {
                recorded.insert(key, true);
            } else {
                recorded.entry(key).or_insert(false);
            }
        }
    }
    let mut infos: BTreeMap<String, TargetInfo> = BTreeMap::new();
    infos.insert(host.triple.clone(), host.clone());
    for (context_host, context_target) in recorded.keys() {
        for triple in [context_host, context_target] {
            if !infos.contains_key(triple) {
                infos.insert(triple.clone(), toolchain.target_info(Some(triple))?);
            }
        }
    }
    Ok(recorded
        .into_iter()
        .map(|((context_host, context_target), recorded)| VendorContext {
            context: Context {
                host: context_host.clone(),
                target: context_target.clone(),
            },
            host: infos[&context_host].clone(),
            target: infos[&context_target].clone(),
            recorded,
        })
        .collect())
}

struct VendorContext {
    context: Context,
    host: TargetInfo,
    target: TargetInfo,
    recorded: bool,
}

struct Acquisition<'a> {
    config: &'a Config,
    /// Shared across the whole vendor run so each repository object is
    /// verified once, not re-hashed by every inventory, resolution, and
    /// evidence pass.
    repositories: RepositorySet,
    records: BTreeMap<(String, Version), sparse::Record>,
    fetched: BTreeSet<String>,
    inspections: Vec<ExtractedArchive>,
    state: Option<AcquisitionState>,
    progress: Progress,
    /// Prints warnings about index entries Cargo skips or reads leniently.
    verbose: bool,
}

struct AcquisitionState {
    client: Client,
    trust: TrustPolicy,
    transaction: RepositoryTransaction,
}

impl<'a> Acquisition<'a> {
    fn new(
        config: &'a Config,
        manifest: &Manifest,
        progress: Progress,
        verbose: bool,
    ) -> Result<Self> {
        let repositories = RepositorySet::open(
            &config.repositories,
            repository_tree_limits(&config.policy.limits)?,
            config.policy.limits.max_package_bytes,
        )?;
        let mut locked = Vec::new();
        for package in manifest.lock.iter().flat_map(|lock| &lock.packages) {
            let (Some(_source), Some(checksum)) = (&package.source, &package.checksum) else {
                continue;
            };
            let version = Version::parse(&package.version.original).map_err(|error| {
                Error::failure(format!(
                    "locked package has invalid version `{} {}`: {error}",
                    package.name, package.version.original
                ))
            })?;
            locked.push((package.name.clone(), version, checksum.clone()));
        }
        let objects = repositories.lookup_registries(
            &locked
                .iter()
                .map(|(_, _, checksum)| checksum.clone())
                .collect::<Vec<_>>(),
        )?;
        let mut records = BTreeMap::new();
        for (name, version, checksum) in locked {
            let record = match &objects[&checksum] {
                Some(object) => object.index.clone(),
                None => {
                    let Some(record) = repositories.lookup_registry_record(&checksum)? else {
                        continue;
                    };
                    record
                }
            };
            if record.name != name || record.version != version {
                return Err(Error::failure(format!(
                    "repository object `{checksum}` does not match locked package `{} {}`",
                    name, version
                )));
            }
            let key = (record.name.clone(), record.version.clone());
            if let Some(existing) = records.insert(key, record.clone())
                && existing != record
            {
                return Err(Error::failure(format!(
                    "repositories disagree about locked package `{} {}`",
                    name, version
                )));
            }
        }
        Ok(Self {
            config,
            repositories,
            records,
            fetched: BTreeSet::new(),
            inspections: Vec::new(),
            state: None,
            progress,
            verbose,
        })
    }

    fn load_locked_sparse(
        &mut self,
        manifest: &Manifest,
        name: &str,
        catalog: &mut Catalog,
        offline: bool,
    ) -> Result<()> {
        let locked = manifest
            .lock
            .iter()
            .flat_map(|lock| &lock.packages)
            .filter(|package| {
                package.name == name
                    && package.source.as_deref()
                        == Some("registry+https://github.com/rust-lang/crates.io-index")
            })
            .collect::<Vec<_>>();
        if locked.is_empty() {
            // A locked path or Git patch supplies the crates.io requirement
            // without any registry package or sparse-index input in the lock.
            if catalog.contains_crates_io_candidate(name, &semver::VersionReq::STAR) {
                return Ok(());
            }
            return Err(
                Error::failure(format!("Cargo.lock has no crates.io package `{name}`"))
                    .with_help("run `lorry vendor` to reconcile the workspace lock"),
            );
        }
        for package in locked {
            let version = Version::parse(&package.version.original)
                .map_err(|error| Error::failure(format!("invalid locked version: {error}")))?;
            let key = (name.to_owned(), version.clone());
            if !self.records.contains_key(&key) {
                if offline {
                    return Err(Error::failure(format!(
                        "verified index evidence for `{name} {version}` is unavailable offline"
                    ))
                    .with_help("run `lorry fetch` to acquire the locked sources"));
                }
                let exact = semver::VersionReq::parse(&format!("={version}")).map_err(|error| {
                    Error::failure(format!("invalid locked requirement: {error}"))
                })?;
                // Downloading an index must not admit candidates outside the lock.
                self.load_sparse(name, &exact, &mut Catalog::default())?;
            }
            let record = self.records.get(&key).ok_or_else(|| {
                Error::failure(format!(
                    "crates.io index has no locked package `{name} {version}`"
                ))
                .with_help("`lorry -v vendor` names index entries that Lorry skipped")
            })?;
            if package.checksum.as_deref() != Some(hex(&record.checksum).as_str()) {
                return Err(Error::failure(format!(
                    "crates.io index checksum disagrees with Cargo.lock for `{name} {version}`"
                )));
            }
            if !catalog.contains_registry(name, &version) {
                catalog.insert(record.clone())?;
            }
        }
        Ok(())
    }

    fn repositories(&self) -> &RepositorySet {
        &self.repositories
    }

    fn load_sparse(
        &mut self,
        name: &str,
        requirement: &semver::VersionReq,
        catalog: &mut Catalog,
    ) -> Result<()> {
        let expected = name.to_ascii_lowercase();
        for record in self
            .records
            .iter()
            .filter(|((name, _), _)| name == &expected)
            .map(|(_, record)| record.clone())
            .collect::<Vec<_>>()
        {
            if !catalog.contains_registry(&record.name, &record.version) {
                catalog.insert(record)?;
            }
        }
        if self.fetched.contains(&expected)
            || catalog.contains_crates_io_candidate(&expected, requirement)
        {
            return Ok(());
        }
        let url = sparse_url(&expected)?;
        self.progress
            .report(format_args!("Updating crates.io index for `{expected}`"))?;
        let state = self.state()?;
        let download = state.client.download(
            &url,
            &mut state.trust,
            state.transaction.path(),
            sparse::MAX_RESPONSE_BYTES,
        )?;
        let response = sparse::load_response(download.path(), &expected)?;
        if self.verbose {
            for warning in &response.warnings {
                eprintln!("warning: {warning}");
            }
        }
        for record in response.records {
            let key = (record.name.clone(), record.version.clone());
            if let Some(existing) = self.records.get(&key) {
                if existing != &record {
                    return Err(Error::failure(format!(
                        "sparse acquisition changed package version `{} {}`",
                        record.name, record.version
                    )));
                }
            } else {
                catalog.insert(record.clone())?;
                self.records.insert(key, record);
            }
        }
        self.fetched.insert(expected);
        Ok(())
    }

    fn stage_resolution_inputs(&mut self, resolution: &Resolution) -> Result<()> {
        let mut total = 0_u64;
        for package in &resolution.packages {
            let ResolvedSource::CratesIo { checksum } = &package.source else {
                continue;
            };
            if self
                .repositories
                .lookup_registry_record(&hex(checksum))?
                .is_some()
            {
                continue;
            }
            let record = self
                .records
                .get(&(package.key.name.clone(), package.key.version.clone()))
                .ok_or_else(|| Error::failure("resolved package has no acquired index record"))?
                .clone();
            if record.checksum != *checksum {
                return Err(Error::failure(
                    "resolved index record disagrees with the source checksum",
                ));
            }
            total = total
                .checked_add(record.exact_bytes.len() as u64)
                .ok_or_else(|| Error::failure("resolution input byte count overflowed"))?;
            if total > self.config.policy.limits.max_transaction_bytes {
                return Err(Error::failure(
                    "resolution inputs exceed the policy transaction byte limit",
                ));
            }
            self.state()?.transaction.stage_index_record(&record)?;
        }
        Ok(())
    }

    fn stage_selected(&mut self, resolution: &Resolution) -> Result<usize> {
        let max_package_bytes = self.config.policy.limits.max_package_bytes;
        self.stage_selected_with(resolution, |state, package, record| {
            let url = archive_url(&package.key.name, &package.key.version)?;
            let download = state.client.download(
                &url,
                &mut state.trust,
                state.transaction.path(),
                max_package_bytes,
            )?;
            state
                .transaction
                .stage_registry_description(record, download.path())?;
            Ok(())
        })
    }

    fn evidence(
        &mut self,
        resolution: &Resolution,
        direct: &crate::git::DirectCatalog,
    ) -> Result<BTreeMap<PackageKey, PackageEvidence>> {
        let repositories = self.repositories.clone();
        let git_packages = resolution
            .packages
            .iter()
            .filter(|package| matches!(package.source, ResolvedSource::Git { .. }))
            .collect::<Vec<_>>();
        let mut evidence = git_packages
            .iter()
            .map(|package| Ok((package.key.clone(), direct.evidence(package)?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        for package in &resolution.packages {
            let package_evidence = match &package.source {
                ResolvedSource::Path { .. } => PackageEvidence::from_path(package)?,
                ResolvedSource::Git { .. } => continue,
                ResolvedSource::CratesIo { checksum } => {
                    let staged = self.state.as_ref().and_then(|state| {
                        state
                            .transaction
                            .objects()
                            .iter()
                            .find(|object| object.object().checksum == *checksum)
                    });
                    if let Some(staged) = staged {
                        PackageEvidence::from_registry(
                            package,
                            staged.object(),
                            staged.manifest(),
                            staged.source_tree()?,
                            true,
                        )?
                    } else {
                        let object = repositories.lookup_registry(&hex(checksum))?.ok_or_else(
                            || {
                                Error::failure(format!(
                                    "selected crates.io package `{} {}` was not staged or present",
                                    package.key.name, package.key.version
                                ))
                            },
                        )?;
                        let (source, tree) = if object.retained_source {
                            let tree = object.source_tree.clone().ok_or_else(|| {
                                Error::failure(format!(
                                    "verified object for `{} {}` retains no source tree",
                                    package.key.name, package.key.version
                                ))
                            })?;
                            (object.root.join("source"), tree)
                        } else {
                            let extracted = extract_crate(
                                &object.root.join("package.crate"),
                                object.checksum,
                                &env::temp_dir(),
                                &object.name,
                                &object.version,
                                ArchiveLimits::from_policy(&self.config.policy.limits),
                            )?;
                            let source = extracted.path().to_owned();
                            let tree = extracted.tree().clone();
                            self.inspections.push(extracted);
                            (source, tree)
                        };
                        let manifest = Manifest::load_registry_dependency(&source, true)?;
                        PackageEvidence::from_registry(package, &object, &manifest, &tree, false)?
                    }
                }
            };
            evidence.insert(package.key.clone(), package_evidence);
        }
        Ok(evidence)
    }

    fn publish(self) -> Result<()> {
        if let Some(state) = self.state {
            state.transaction.publish()?;
        }
        Ok(())
    }

    fn stage_selected_with(
        &mut self,
        resolution: &Resolution,
        mut stage: impl FnMut(&mut AcquisitionState, &ResolvedPackage, &sparse::Record) -> Result<()>,
    ) -> Result<usize> {
        let repositories = RepositorySet::open(
            &self.config.repositories,
            repository_tree_limits(&self.config.policy.limits)?,
            self.config.policy.limits.max_package_bytes,
        )?;
        let mut staged = 0;
        for package in &resolution.packages {
            let ResolvedSource::CratesIo { checksum } = package.source else {
                continue;
            };
            if repositories.lookup_registry(&hex(&checksum))?.is_some()
                || self.has_staged_registry(checksum)
            {
                continue;
            }
            let key = (package.key.name.clone(), package.key.version.clone());
            let record = self.records.get(&key).cloned().ok_or_else(|| {
                Error::failure(format!(
                    "resolved crates.io package `{} {}` has no acquired sparse index record",
                    package.key.name, package.key.version
                ))
            })?;
            if record.checksum != checksum {
                return Err(Error::failure(format!(
                    "acquired sparse index checksum changed for resolved package `{} {}`",
                    package.key.name, package.key.version
                )));
            }
            self.progress.report(format_args!(
                "Downloading {} v{}",
                package.key.name, package.key.version
            ))?;
            stage(self.state()?, package, &record)?;
            staged += 1;
        }
        Ok(staged)
    }

    fn has_staged_registry(&self, checksum: [u8; 32]) -> bool {
        self.state.as_ref().is_some_and(|state| {
            state
                .transaction
                .objects()
                .iter()
                .any(|object| object.object().checksum == checksum)
        })
    }

    fn state(&mut self) -> Result<&mut AcquisitionState> {
        if self.state.is_none() {
            let client = Client::discover(&self.config.network)?;
            let trust = TrustPolicy::load_default()?;
            let tree = repository_tree_limits(&self.config.policy.limits)?;
            let writer = RepositoryWriter::open(
                &self.config.repositories,
                tree,
                ArchiveLimits::from_policy(&self.config.policy.limits),
            )?;
            self.state = Some(AcquisitionState {
                client,
                trust,
                transaction: writer.begin()?,
            });
        }
        Ok(self.state.as_mut().unwrap())
    }
}

fn write_git_review(
    refreshes: &[crate::git::PatchRefresh],
    direct: &crate::git::DirectCatalog,
    include_all: bool,
    output: &mut impl Write,
) -> Result<()> {
    let mut covered = BTreeSet::new();
    for refresh in refreshes {
        if !include_all
            && !refresh.changed()
            && !direct.was_materialized(&refresh.candidate.cargo_source)
        {
            continue;
        }
        let source = direct.source(&refresh.candidate.cargo_source)?;
        writeln!(
            output,
            "Git patch candidate: {} (`{}`){}\n  canonical source: {}\n  URL: {}\n  selector: {}\n  old commit: {}\n  new commit: {}\n  Git tree: {}\n  source SHA-256: {}\n  files: {}; bytes: {}",
            refresh.alias,
            refresh.package,
            if refresh.retargeted_tag {
                " [WARNING: RETARGETED TAG]"
            } else {
                ""
            },
            source.locked.cargo_source,
            source.locked.url,
            git_selector(&source.locked.selector),
            refresh.previous.commit,
            refresh.candidate.commit,
            source.git_tree,
            hex(&source.source_tree_sha256),
            source.file_count,
            source.total_bytes,
        )
        .map_err(|error| Error::failure(format!("failed to write vendor review: {error}")))?;
        covered.insert(refresh.candidate.cargo_source.as_str());
    }
    for source in direct
        .sources()
        .filter(|source| include_all || direct.was_materialized(&source.locked.cargo_source))
    {
        if covered.contains(source.locked.cargo_source.as_str()) {
            continue;
        }
        writeln!(
            output,
            "Git source candidate:\n  canonical source: {}\n  URL: {}\n  selector: {}\n  commit: {}\n  Git tree: {}\n  source SHA-256: {}\n  files: {}; bytes: {}",
            source.locked.cargo_source,
            source.locked.url,
            git_selector(&source.locked.selector),
            source.locked.commit,
            source.git_tree,
            hex(&source.source_tree_sha256),
            source.file_count,
            source.total_bytes,
        )
        .map_err(|error| Error::failure(format!("failed to write vendor review: {error}")))?;
    }
    Ok(())
}

fn git_selector(selector: &crate::manifest::GitSelector) -> &str {
    match selector {
        crate::manifest::GitSelector::Head => "HEAD",
        crate::manifest::GitSelector::Branch(value)
        | crate::manifest::GitSelector::Tag(value)
        | crate::manifest::GitSelector::Revision(value) => value,
    }
}

fn stage_lockfile(path: &Path, bytes: &[u8]) -> Result<Option<AtomicFile>> {
    match fs::read(path) {
        Ok(existing) if existing == bytes => {
            return Ok(None);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(Error::failure(format!(
                "failed to read lockfile `{}`: {error}",
                path.display()
            )));
        }
    }
    let mut staged = AtomicFile::new(path)?;
    staged.write_all(bytes)?;
    staged.persist()?;
    Ok(Some(staged))
}

fn repository_tree_limits(policy: &PolicyLimits) -> Result<TreeLimits> {
    let entries = usize::try_from(policy.max_package_files).map_err(|_| {
        Error::failure("policy max-package-files does not fit this platform's address space")
    })?;
    Ok(TreeLimits {
        max_tree_bytes: policy.max_extracted_package_bytes,
        max_entries: entries,
        max_path_bytes: 4096,
        max_file_bytes: policy.max_extracted_package_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(label: &str) -> Self {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let root =
                env::temp_dir().join(format!("lorry-vendor-{label}-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("src")).unwrap();
            fs::write(root.join("src/lib.rs"), "pub fn root() {}\n").unwrap();
            Self(root)
        }

        fn manifest(&self) -> Manifest {
            Manifest::load_for_vendor(&self.0).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_changed_lock_without_a_version_line_is_staged() {
        let root = std::env::temp_dir().join(format!("lorry-stage-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let path = root.join("Cargo.lock");
        // Lock formats 1 and 2 have no version line.
        fs::write(&path, "[[package]]\nname = \"old\"\nversion = \"1.0.0\"\n").unwrap();
        let candidate = b"[[package]]\nname = \"new\"\nversion = \"1.0.0\"\n";
        assert!(stage_lockfile(&path, candidate).unwrap().is_some());
        fs::write(&path, candidate).unwrap();
        assert!(stage_lockfile(&path, candidate).unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn git_patch_refresh_changes_only_the_in_memory_lock() {
        const OLD: &str = "0123456789abcdef0123456789abcdef01234567";
        const NEW: &str = "fedcba9876543210fedcba9876543210fedcba98";
        let fixture = Fixture::new("git-refresh-lock");
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\ndemo = \"=1.2.3\"\n\
             [patch.crates-io]\ndemo = { git = \"https://example.com/repo\", branch = \"main\" }\n",
        )
        .unwrap();
        let old_source = format!("git+https://example.com/repo?branch=main#{OLD}");
        let new_source = format!("git+https://example.com/repo?branch=main#{NEW}");
        let lock = format!(
            "version = 4\n\n[[package]]\nname = \"root\"\nversion = \"0.1.0\"\n\
             dependencies = [\"demo 1.2.3 ({old_source})\"]\n\n\
             [[package]]\nname = \"demo\"\nversion = \"1.2.3\"\nsource = \"{old_source}\"\n"
        );
        fs::write(fixture.0.join("Cargo.lock"), &lock).unwrap();
        let manifest = fixture.manifest();
        let refresh = crate::git::PatchRefresh {
            alias: "demo".to_owned(),
            package: "demo".to_owned(),
            previous: crate::git::parse_locked_source(&old_source).unwrap(),
            candidate: crate::git::parse_locked_source(&new_source).unwrap(),
            retargeted_tag: false,
        };

        let candidate = apply_patch_refreshes(&manifest, &[refresh]).unwrap();
        let packages = &candidate.lock.as_ref().unwrap().packages;
        assert!(packages.iter().all(|package| {
            package.source.as_deref() != Some(&old_source)
                && package
                    .dependencies
                    .iter()
                    .all(|dependency| !dependency.contains(&old_source))
        }));
        assert!(packages.iter().any(|package| {
            package.source.as_deref() == Some(&new_source)
                || package
                    .dependencies
                    .iter()
                    .any(|dependency| dependency.contains(&new_source))
        }));
        assert_eq!(
            fs::read_to_string(fixture.0.join("Cargo.lock")).unwrap(),
            lock
        );
        assert_eq!(manifest.lock.unwrap().packages[1].source, Some(old_source));
    }
}
