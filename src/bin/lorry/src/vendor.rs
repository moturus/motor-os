use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::Path;

use semver::Version;

use crate::archive::Limits as ArchiveLimits;
use crate::atomic::AtomicFile;
use crate::cli::{Cli, Verbosity};
use crate::config::{Config, PolicyLimits};
use crate::curl::{Client, archive_url, sparse_url};
use crate::diagnostic::{Error, Result};
use crate::engine;
use crate::hash::hex;
use crate::lockfile;
use crate::manifest::Manifest;
use crate::patch;
use crate::policy::{self, PackageEvidence};
use crate::redirect::TrustPolicy;
use crate::repository::{RepositorySet, RepositoryTransaction, RepositoryWriter};
use crate::resolver::{
    self, Catalog, LockedPreference, Options, PackageKey, PackageSourceKey, Resolution,
    ResolvedPackage, ResolvedSource, TargetSelection,
};
use crate::source_tree::Limits as TreeLimits;
use crate::sparse;
use crate::toolchain::{TargetInfo, Toolchain};
use crate::vendor_lock::ProjectVendorLock;

pub fn execute(cli: &Cli, _accept_all: bool) -> Result<i32> {
    if cli.use_cargo_registry {
        return Err(Error::usage(
            "`--use-cargo-registry` cannot be combined with `vendor`",
            "remove `--use-cargo-registry`; vendoring uses only Lorry repositories",
        ));
    }
    let current = env::current_dir()
        .map_err(|error| Error::failure(format!("failed to read current directory: {error}")))?;
    let initial_manifest = Manifest::load_for_vendor(&current)?;
    let config = Config::load(&initial_manifest.root)?;
    let toolchain = Toolchain::discover(cli.toolchain.as_deref(), &config)?;
    engine::check_rust_version(&initial_manifest, &toolchain)?;
    let host = toolchain.target_info(None)?;
    let targets = vendor_targets(&toolchain, &config, &host)?;

    let lock = ProjectVendorLock::acquire(&initial_manifest.root)?;
    if cli.verbosity == Verbosity::Verbose {
        eprintln!("Locked {}", lock.path().display());
    }
    let manifest = Manifest::load_for_vendor(&initial_manifest.root)?;
    let lock_bytes = prepare_networked(&manifest, &config, &toolchain, &host, &targets)?;
    let lock_path = manifest.root.join("Cargo.lock");
    let staged = stage_lockfile(&lock_path, &lock_bytes)?;
    let changed = staged.is_some();
    if let Some(staged) = staged {
        staged.commit()?;
    }
    Manifest::load(&manifest.root)?;

    if cli.verbosity != Verbosity::Quiet {
        eprintln!(
            "{} Cargo.lock",
            if changed { "Updated" } else { "Verified" }
        );
    }
    Ok(0)
}

fn vendor_targets(
    toolchain: &Toolchain,
    config: &Config,
    host: &TargetInfo,
) -> Result<Vec<TargetInfo>> {
    let mut triples = config
        .vendor
        .targets
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if config.vendor.include_host {
        triples.insert(host.triple.clone());
    }
    triples
        .into_iter()
        .map(|triple| {
            if triple == host.triple {
                Ok(host.clone())
            } else {
                toolchain.target_info(Some(&triple))
            }
        })
        .collect()
}

#[cfg(test)]
fn prepare_path_only(
    manifest: &Manifest,
    config: &Config,
    toolchain: &Toolchain,
    host: &TargetInfo,
    targets: &[TargetInfo],
) -> Result<Vec<u8>> {
    let locked_registry_names = manifest
        .lock
        .iter()
        .flat_map(|lock| &lock.packages)
        .filter(|package| package.source.is_some())
        .map(|package| package.name.clone())
        .collect::<BTreeSet<_>>();
    let mut loader = |name: &str, _catalog: &mut Catalog| {
        if locked_registry_names.contains(name) {
            Ok(())
        } else {
            Err(fetch_pending(name))
        }
    };
    let (lock, selected) = prepare_with_loader(
        manifest,
        config,
        toolchain,
        host,
        targets,
        &mut loader,
        &reject_registry_packages,
    )?;
    inspect_path_policy(config, &selected)?;
    Ok(lock)
}

fn prepare_networked(
    manifest: &Manifest,
    config: &Config,
    toolchain: &Toolchain,
    host: &TargetInfo,
    targets: &[TargetInfo],
) -> Result<Vec<u8>> {
    let mut acquisition = Acquisition::new(config);
    let mut loader = |name: &str, catalog: &mut Catalog| acquisition.load_sparse(name, catalog);
    let (lock, selected) = prepare_with_loader(
        manifest,
        config,
        toolchain,
        host,
        targets,
        &mut loader,
        &|_| Ok(()),
    )?;
    reject_registry_packages(&selected)?;
    inspect_path_policy(config, &selected)?;
    Ok(lock)
}

fn prepare_with_loader(
    manifest: &Manifest,
    config: &Config,
    toolchain: &Toolchain,
    host: &TargetInfo,
    targets: &[TargetInfo],
    loader: &mut dyn FnMut(&str, &mut Catalog) -> Result<()>,
    after_complete: &dyn Fn(&Resolution) -> Result<()>,
) -> Result<(Vec<u8>, Resolution)> {
    let repositories = RepositorySet::open(
        &config.repositories,
        repository_tree_limits(&config.policy.limits)?,
        config.policy.limits.max_package_bytes,
    )?;
    let mut catalog = if manifest.lock.is_some() {
        Catalog::from_locked_repository(manifest, &repositories)?
    } else {
        Catalog::default()
    };
    patch::configure(manifest, config, &repositories, &mut catalog)?;
    let locked = LockedPreference::from_lockfile(manifest.lock.as_ref())?;
    let options = resolver_options(manifest, config, toolchain)?;
    let complete = resolver::resolve_dynamic(manifest, &mut catalog, &options, &locked, loader)?;
    after_complete(&complete)?;

    let selected_locked = LockedPreference::from_resolution(&complete);
    let mut selected = Vec::new();
    for target in targets {
        selected.push(resolver::resolve_selected_dynamic(
            manifest,
            &mut catalog,
            &options,
            &selected_locked,
            TargetSelection {
                target_triple: &target.triple,
                target_cfg: &target.cfg,
                host_triple: &host.triple,
                host_cfg: &host.cfg,
            },
            loader,
        )?);
    }
    let selected = resolver::merge_resolutions(selected)?;
    Ok((lockfile::render(manifest, &complete)?, selected))
}

struct Acquisition<'a> {
    config: &'a Config,
    records: BTreeMap<(String, Version), sparse::Record>,
    state: Option<AcquisitionState>,
}

struct AcquisitionState {
    client: Client,
    trust: TrustPolicy,
    transaction: RepositoryTransaction,
}

impl<'a> Acquisition<'a> {
    fn new(config: &'a Config) -> Self {
        Self {
            config,
            records: BTreeMap::new(),
            state: None,
        }
    }

    fn load_sparse(&mut self, name: &str, catalog: &mut Catalog) -> Result<()> {
        let url = sparse_url(name)?;
        let expected = name.to_ascii_lowercase();
        let state = self.state()?;
        let download = state.client.download(
            &url,
            &mut state.trust,
            state.transaction.path(),
            sparse::MAX_RESPONSE_BYTES,
        )?;
        for record in sparse::load_response(download.path(), &expected)? {
            catalog.insert(record.clone())?;
            let key = (record.name.clone(), record.version.clone());
            if self.records.insert(key, record).is_some() {
                return Err(Error::failure(format!(
                    "sparse acquisition repeated package version `{name}`"
                )));
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
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
            state.transaction.stage_registry(record, download.path())?;
            Ok(())
        })
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
            if repositories.lookup_registry(&hex(&checksum))?.is_some() {
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
            stage(self.state()?, package, &record)?;
            staged += 1;
        }
        Ok(staged)
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

fn resolver_options(
    manifest: &Manifest,
    config: &Config,
    toolchain: &Toolchain,
) -> Result<Options> {
    let rust_version = Version::parse(&toolchain.release).map_err(|error| {
        Error::failure(format!(
            "selected rustc release `{}` is not a semantic version: {error}",
            toolchain.release
        ))
    })?;
    Ok(Options {
        resolver: manifest.resolver,
        incompatible_rust_versions: config.incompatible_rust_versions,
        rust_version,
        max_packages: config.policy.limits.max_packages,
        max_depth: config.policy.limits.max_depth,
    })
}

fn inspect_path_policy(config: &Config, resolution: &Resolution) -> Result<()> {
    let preflight = policy::preflight(&config.policy, resolution)?;
    let evidence = resolution
        .packages
        .iter()
        .map(|package| Ok((package.key.clone(), PackageEvidence::from_path(package)?)))
        .collect::<Result<BTreeMap<PackageKey, PackageEvidence>>>()?;
    policy::inspect(&preflight, resolution, &evidence)?;
    Ok(())
}

fn reject_registry_packages(resolution: &Resolution) -> Result<()> {
    let packages = resolution
        .packages
        .iter()
        .filter(|package| package.key.source == PackageSourceKey::CratesIo)
        .map(|package| format!("{} {}", package.key.name, package.key.version))
        .collect::<Vec<_>>();
    if packages.is_empty() {
        return Ok(());
    }
    Err(Error::failure(format!(
        "crates.io archive acquisition is not enabled yet; the resolved graph requires {}",
        packages.join(", ")
    ))
    .with_help("sparse metadata was acquired; the next Stage-2 increment stages crate archives"))
}

#[cfg(test)]
fn fetch_pending(name: &str) -> Error {
    Error::failure(format!(
        "sparse-index metadata for crates.io package `{name}` is unavailable because the \
         direct curl acquisition path is not implemented yet"
    ))
}

fn stage_lockfile(path: &Path, bytes: &[u8]) -> Result<Option<AtomicFile>> {
    match fs::read(path) {
        Ok(existing) if existing == bytes => return Ok(None),
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
    use crate::config::CargoCompat;
    use crate::hash::Sha256;
    use crate::resolver::{CompileKind, PackageSourceKey};
    use crate::toolchain::CfgSet;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write as _;
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

    fn toolchain() -> Toolchain {
        Toolchain {
            rustc: "/rustc".into(),
            verbose_version: String::new(),
            release: "1.98.0-nightly".to_owned(),
            host: "x86_64-unknown-linux-gnu".to_owned(),
            compatibility: CargoCompat::V1_98,
        }
    }

    fn target() -> TargetInfo {
        TargetInfo {
            triple: "x86_64-unknown-linux-gnu".to_owned(),
            cfg: CfgSet::parse(
                "target_arch=\"x86_64\"\ntarget_os=\"linux\"\ntarget_family=\"unix\"\nunix\n",
            )
            .unwrap(),
        }
    }

    fn crate_archive(name: &str, version: &str) -> Vec<u8> {
        fn octal(field: &mut [u8], value: u64) {
            let text = format!("{value:0width$o}", width = field.len() - 1);
            field[..text.len()].copy_from_slice(text.as_bytes());
        }
        fn append(tar: &mut Vec<u8>, path: &str, contents: &[u8]) {
            let mut header = [0_u8; 512];
            header[..path.len()].copy_from_slice(path.as_bytes());
            octal(&mut header[100..108], 0o644);
            octal(&mut header[124..136], contents.len() as u64);
            header[148..156].fill(b' ');
            header[156] = b'0';
            header[257..263].copy_from_slice(b"ustar\0");
            header[263..265].copy_from_slice(b"00");
            let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
            header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
            tar.extend_from_slice(&header);
            tar.extend_from_slice(contents);
            tar.resize((tar.len() + 511) / 512 * 512, 0);
        }

        let root = format!("{name}-{version}");
        let mut tar = Vec::new();
        append(
            &mut tar,
            &format!("{root}/Cargo.toml"),
            format!(
                "[package]\nname = \"{name}\"\nversion = \"{version}\"\n\
                 edition = \"2021\"\nlicense = \"MIT\"\n"
            )
            .as_bytes(),
        );
        append(
            &mut tar,
            &format!("{root}/src/lib.rs"),
            b"pub fn fixture() {}\n",
        );
        tar.resize(tar.len() + 1024, 0);
        let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
        gzip.write_all(&tar).unwrap();
        gzip.finish().unwrap()
    }

    fn registry_package(name: &str, version: &Version, checksum: [u8; 32]) -> ResolvedPackage {
        ResolvedPackage {
            key: PackageKey {
                name: name.to_owned(),
                version: version.clone(),
                source: PackageSourceKey::CratesIo,
            },
            source: ResolvedSource::CratesIo { checksum },
            local_manifest: None,
            feature_sets: BTreeMap::new(),
            compile_kinds: BTreeSet::from([CompileKind::Target]),
            target_features: BTreeSet::new(),
            host_features: BTreeSet::new(),
            edges: Vec::new(),
            lock_edges: Vec::new(),
        }
    }

    #[test]
    fn dependency_free_vendor_persists_before_atomic_lock_commit() {
        let fixture = Fixture::new("empty");
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        let manifest = fixture.manifest();
        let config = Config::default();
        let target = target();
        let bytes = prepare_path_only(
            &manifest,
            &config,
            &toolchain(),
            &target,
            std::slice::from_ref(&target),
        )
        .unwrap();
        assert_eq!(
            prepare_networked(
                &manifest,
                &config,
                &toolchain(),
                &target,
                std::slice::from_ref(&target),
            )
            .unwrap(),
            bytes
        );

        let lock_path = fixture.0.join("Cargo.lock");
        let staged = stage_lockfile(&lock_path, &bytes).unwrap().unwrap();
        assert!(!lock_path.exists());
        staged.commit().unwrap();
        Manifest::load(&fixture.0).unwrap();
        assert!(stage_lockfile(&lock_path, &bytes).unwrap().is_none());
    }

    #[test]
    fn path_only_vendor_repairs_a_stale_lock_and_enforces_policy_first() {
        let fixture = Fixture::new("path");
        fs::create_dir_all(fixture.0.join("local/src")).unwrap();
        fs::write(
            fixture.0.join("local/Cargo.toml"),
            "[package]\nname = \"local\"\nversion = \"1.2.3\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(fixture.0.join("local/src/lib.rs"), "pub fn local() {}\n").unwrap();
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\nlocal = { path = \"local\" }\n",
        )
        .unwrap();
        let stale = b"version = 4\n\n[[package]]\nname = \"root\"\nversion = \"0.0.1\"\n";
        fs::write(fixture.0.join("Cargo.lock"), stale).unwrap();
        let manifest = fixture.manifest();
        let target = target();
        let mut denied = Config::default();
        denied.policy.path_roots = vec![fixture.0.join("elsewhere")];
        let error = prepare_path_only(
            &manifest,
            &denied,
            &toolchain(),
            &target,
            std::slice::from_ref(&target),
        )
        .unwrap_err();
        assert!(error.to_string().contains("policy.path-roots"));
        assert_eq!(fs::read(fixture.0.join("Cargo.lock")).unwrap(), stale);

        let bytes = prepare_path_only(
            &manifest,
            &Config::default(),
            &toolchain(),
            &target,
            std::slice::from_ref(&target),
        )
        .unwrap();
        stage_lockfile(&fixture.0.join("Cargo.lock"), &bytes)
            .unwrap()
            .unwrap()
            .commit()
            .unwrap();
        let repaired = Manifest::load(&fixture.0).unwrap();
        assert_eq!(repaired.lock.unwrap().packages.len(), 2);
    }

    #[test]
    fn registry_graph_waits_for_curl_acquisition_without_writing_a_lock() {
        let fixture = Fixture::new("registry");
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\nserde = \"1\"\n",
        )
        .unwrap();
        let manifest = fixture.manifest();
        let target = target();
        let error = prepare_path_only(
            &manifest,
            &Config::default(),
            &toolchain(),
            &target,
            std::slice::from_ref(&target),
        )
        .unwrap_err();
        assert!(error.render().contains("curl acquisition"));
        assert!(!fixture.0.join("Cargo.lock").exists());
    }

    #[test]
    fn stages_only_missing_selected_registry_archives() {
        let fixture = Fixture::new("acquire");
        let repository = fixture.0.join("repository");
        let mut config = Config::default();
        config.repositories.local = Some(repository);
        let bytes = crate_archive("demo", "1.2.3");
        let archive = fixture.0.join("demo.crate");
        fs::write(&archive, &bytes).unwrap();
        let mut digest = Sha256::new();
        digest.update(&bytes);
        let checksum = digest.finish();
        let version = Version::parse("1.2.3").unwrap();
        let record = sparse::Record::parse(
            Path::new("/demo-index"),
            format!(
                "{{\"name\":\"demo\",\"vers\":\"{version}\",\"deps\":[],\
                 \"cksum\":\"{}\",\"features\":{{}},\"yanked\":false}}\n",
                hex(&checksum)
            )
            .as_bytes(),
        )
        .unwrap();
        let resolution = Resolution {
            root_edges: Vec::new(),
            packages: vec![registry_package("demo", &version, checksum)],
        };
        let mut acquisition = Acquisition::new(&config);
        acquisition
            .records
            .insert(("demo".to_owned(), version.clone()), record.clone());

        let staged = acquisition
            .stage_selected_with(&resolution, |state, _, record| {
                state.transaction.stage_registry(record, &archive)?;
                Ok(())
            })
            .unwrap();
        assert_eq!(staged, 1);
        assert_eq!(
            acquisition.state.as_ref().unwrap().transaction.objects()[0]
                .object()
                .name,
            "demo"
        );
        acquisition
            .state
            .take()
            .unwrap()
            .transaction
            .publish()
            .unwrap();

        let mut warm = Acquisition::new(&config);
        warm.records.insert(("demo".to_owned(), version), record);
        assert_eq!(
            warm.stage_selected_with(&resolution, |_, _, _| {
                panic!("an existing verified object must not be downloaded")
            })
            .unwrap(),
            0
        );
        assert!(warm.state.is_none());
    }
}
