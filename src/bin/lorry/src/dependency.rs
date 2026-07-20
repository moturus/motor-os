#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::Path;

use crate::archive::{ExtractedArchive, Limits as ArchiveLimits, extract_crate};
use crate::config::Config;
use crate::diagnostic::{Error, Result};
use crate::hash::hex;
use crate::manifest::Manifest;
use crate::offline;
use crate::patch;
use crate::policy::{self, Admission, PackageEvidence};
use crate::repository::RepositorySet;
use crate::resolver::{
    Catalog, LockedPreference, Options, PackageKey, Resolution, ResolvedSource, TargetSelection,
    resolve_selected,
};
use crate::unit::{
    CompilationPlan, PlanOptions, UnitGraph, dependency_units, plan_dependency_units,
};

#[derive(Debug)]
pub struct PreparedGraph {
    pub resolution: Resolution,
    pub admission: Admission,
    pub packages: BTreeMap<PackageKey, PreparedPackage>,
}

#[derive(Debug)]
pub struct PreparedPackage {
    pub manifest: Manifest,
    pub evidence: PackageEvidence,
    extracted: Option<ExtractedArchive>,
}

impl PreparedGraph {
    pub fn dependency_units(&self) -> Result<UnitGraph> {
        let manifests = self
            .packages
            .iter()
            .map(|(key, package)| (key.clone(), package.manifest.clone()))
            .collect();
        dependency_units(&self.resolution, &manifests)
    }

    pub fn dependency_plan(&self, options: &PlanOptions<'_>) -> Result<CompilationPlan> {
        let manifests = self
            .packages
            .iter()
            .map(|(key, package)| (key.clone(), package.manifest.clone()))
            .collect();
        let graph = dependency_units(&self.resolution, &manifests)?;
        plan_dependency_units(&graph, &manifests, options)
    }
}

impl PreparedPackage {
    pub fn source_root(&self) -> &Path {
        &self.manifest.root
    }

    pub fn is_ephemeral(&self) -> bool {
        self.extracted.is_some()
    }
}

pub fn prepare_locked(
    manifest: &Manifest,
    config: &Config,
    repositories: &RepositorySet,
    options: &Options,
    selection: TargetSelection<'_>,
    staging_parent: &Path,
) -> Result<PreparedGraph> {
    let mut catalog = Catalog::from_locked_repository(manifest, repositories)?;
    patch::configure(manifest, config, repositories, &mut catalog)?;
    let locked = LockedPreference::from_lockfile(manifest.lock.as_ref())?;
    let resolution = resolve_selected(manifest, &catalog, options, &locked, selection)?;
    offline::validate_selected_resolution(manifest, &resolution)?;
    let preflight = policy::preflight(&config.policy, &resolution)?;

    let mut evidence = BTreeMap::new();
    let mut packages = BTreeMap::new();
    for package in &resolution.packages {
        let prepared = match &package.source {
            ResolvedSource::CratesIo { checksum } => {
                let checksum = hex(checksum);
                let object = repositories.lookup_registry(&checksum)?.ok_or_else(|| {
                    Error::failure(format!(
                        "locked crates.io package `{} {}` became unavailable while preparing its source",
                        package.key.name, package.key.version
                    ))
                    .with_help("run `lorry vendor` to acquire the missing package")
                })?;
                let (source_root, extracted) = if object.retained_source {
                    (object.root.join("source"), None)
                } else {
                    let extracted = extract_crate(
                        &object.root.join("package.crate"),
                        object.checksum,
                        staging_parent,
                        &object.name,
                        &object.version,
                        ArchiveLimits::from_policy(&config.policy.limits),
                    )?;
                    (extracted.path().to_owned(), Some(extracted))
                };
                let inspected_manifest = Manifest::load_path_dependency(&source_root)?;
                let package_evidence =
                    PackageEvidence::from_registry(package, &object, &inspected_manifest, false)?;
                PreparedPackage {
                    manifest: inspected_manifest,
                    evidence: package_evidence,
                    extracted,
                }
            }
            ResolvedSource::Path { .. } => {
                let inspected_manifest = package.local_manifest.clone().ok_or_else(|| {
                    Error::failure(format!(
                        "resolved path package `{} {}` has no inspected manifest",
                        package.key.name, package.key.version
                    ))
                })?;
                let package_evidence = PackageEvidence::from_path(package)?;
                PreparedPackage {
                    manifest: inspected_manifest,
                    evidence: package_evidence,
                    extracted: None,
                }
            }
        };
        evidence.insert(package.key.clone(), prepared.evidence.clone());
        if packages.insert(package.key.clone(), prepared).is_some() {
            return Err(Error::failure(format!(
                "prepared dependency graph contains duplicate package `{} {}`",
                package.key.name, package.key.version
            )));
        }
    }
    let admission = policy::inspect(&preflight, &resolution, &evidence)?;
    Ok(PreparedGraph {
        resolution,
        admission,
        packages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CargoCompat, IncompatibleRustVersions, Repositories};
    use crate::resolver::PackageSourceKey;
    use crate::source_tree::DEFAULT_LIMITS;
    use crate::toolchain::{CfgSet, Toolchain};
    use semver::Version;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("lorry-dependency-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(path.join("src")).unwrap();
            fs::write(path.join("src/lib.rs"), "pub fn root() {}\n").unwrap();
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn options(manifest: &Manifest) -> Options {
        Options {
            resolver: manifest.resolver,
            incompatible_rust_versions: Some(IncompatibleRustVersions::Allow),
            rust_version: Version::parse("1.98.0").unwrap(),
            max_packages: 64,
            max_depth: 16,
        }
    }

    fn toolchain() -> Toolchain {
        Toolchain {
            rustc: "/rustc".into(),
            verbose_version: "rustc 1.98.0-nightly (bc2112ed5 2026-06-18)\n\
                              binary: rustc\n\
                              commit-hash: bc2112ed56c99fa649e09ab3ab286afab3d9059a\n\
                              commit-date: 2026-06-18\n\
                              host: x86_64-unknown-linux-gnu\n\
                              release: 1.98.0-nightly\n\
                              LLVM version: 22.1.7\n"
                .to_owned(),
            release: "1.98.0-nightly".to_owned(),
            host: "x86_64-unknown-linux-gnu".to_owned(),
            compatibility: CargoCompat::V1_98,
        }
    }

    fn copy_tree(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let file_type = entry.file_type().unwrap();
            let output = destination.join(entry.file_name());
            if file_type.is_dir() {
                copy_tree(&entry.path(), &output);
            } else {
                assert!(file_type.is_file());
                fs::copy(entry.path(), output).unwrap();
            }
        }
    }

    #[test]
    fn prepares_a_path_only_graph_without_a_repository_or_staging() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.0.join("local/src")).unwrap();
        fs::write(
            fixture.0.join("local/Cargo.toml"),
            "[package]\nname = \"local\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\
             license = \"MIT\"\n",
        )
        .unwrap();
        fs::write(fixture.0.join("local/src/lib.rs"), "pub fn local() {}\n").unwrap();
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\nlocal = { path = \"local\" }\n",
        )
        .unwrap();
        fs::write(
            fixture.0.join("Cargo.lock"),
            "version = 4\n\
             [[package]]\nname = \"local\"\nversion = \"1.0.0\"\n\
             [[package]]\nname = \"root\"\nversion = \"0.1.0\"\ndependencies = [\"local\"]\n",
        )
        .unwrap();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let config = Config::default();
        let repositories =
            RepositorySet::open(&Repositories::default(), DEFAULT_LIMITS, 16 * 1024 * 1024)
                .unwrap();
        let cfg = CfgSet::parse("unix\n").unwrap();
        let staging = fixture.0.join("unused-staging");
        let graph = prepare_locked(
            &manifest,
            &config,
            &repositories,
            &options(&manifest),
            TargetSelection {
                target_triple: "x86_64-unknown-linux-musl",
                target_cfg: &cfg,
                host_triple: "x86_64-unknown-linux-gnu",
                host_cfg: &cfg,
            },
            &staging,
        )
        .unwrap();

        assert!(!staging.exists());
        assert_eq!(graph.packages.len(), 1);
        let (key, package) = graph.packages.first_key_value().unwrap();
        assert!(matches!(key.source, PackageSourceKey::Path(_)));
        assert_eq!(package.source_root(), fixture.0.join("local"));
        assert!(!package.is_ephemeral());
        assert!(graph.admission.packages.contains_key(key));
    }

    #[test]
    fn prepares_and_admits_the_selected_seeded_lorry_graph_when_requested() {
        let Some(repository) = std::env::var_os("LORRY_TEST_SEEDED_REPOSITORY") else {
            return;
        };
        let repository = PathBuf::from(repository);
        let generated = repository.parent().unwrap().join("lorry.toml");
        let fixture = Fixture::new();
        let home_config = fixture.0.join("home/.config/lorry");
        fs::create_dir_all(&home_config).unwrap();
        fs::copy(generated, home_config.join("lorry.toml")).unwrap();
        let config = Config::load_for_test(
            Path::new("."),
            &BTreeMap::from([(
                "HOME".to_owned(),
                fixture.0.join("home").display().to_string(),
            )]),
        )
        .unwrap();
        let repositories = RepositorySet::open(
            &config.repositories,
            DEFAULT_LIMITS,
            config.policy.limits.max_package_bytes,
        )
        .unwrap();
        let manifest = Manifest::load(Path::new(".")).unwrap();
        let linux = CfgSet::parse(
            "debug_assertions\npanic=\"unwind\"\ntarget_arch=\"x86_64\"\n\
             target_endian=\"little\"\ntarget_env=\"gnu\"\ntarget_family=\"unix\"\n\
             target_os=\"linux\"\ntarget_pointer_width=\"64\"\ntarget_vendor=\"unknown\"\nunix\n",
        )
        .unwrap();
        let graph = prepare_locked(
            &manifest,
            &config,
            &repositories,
            &options(&manifest),
            TargetSelection {
                target_triple: "x86_64-unknown-linux-gnu",
                target_cfg: &linux,
                host_triple: "x86_64-unknown-linux-gnu",
                host_cfg: &linux,
            },
            &fixture.0.join("staging"),
        )
        .unwrap();

        assert_eq!(graph.packages.len(), graph.resolution.packages.len());
        assert_eq!(graph.packages.len(), graph.admission.packages.len());
        assert!(
            graph
                .packages
                .values()
                .all(|package| package.source_root().is_dir() && !package.is_ephemeral())
        );
        let units = graph.dependency_units().unwrap();
        assert_eq!(units.units.len(), units.order.len());
        assert!(units.units.keys().any(|unit| {
            unit.package.name == "crc32fast" && unit.kind == crate::unit::UnitKind::BuildScriptRun
        }));
        assert!(units.units.keys().any(|unit| {
            unit.package.name == "generic-array"
                && unit.kind == crate::unit::UnitKind::BuildScriptRun
        }));
        let plan = graph
            .dependency_plan(&PlanOptions {
                workspace_root: &manifest.root,
                release: true,
                release_profile: &manifest.release,
                rustc: &toolchain(),
                logical_target: None,
                rustflags: &[],
            })
            .unwrap();
        assert_eq!(plan.units.len(), units.units.len());
        assert_eq!(plan.order, units.order);
    }

    #[test]
    fn privately_extracts_an_archive_only_selected_object_when_requested() {
        let Some(repository) = std::env::var_os("LORRY_TEST_SEEDED_REPOSITORY") else {
            return;
        };
        const CHECKSUM: &str = "320119579fcad9c21884f5c4861d16174d0e06250625266f50fe6898340abefa";
        let repository = PathBuf::from(repository);
        let generated = repository.parent().unwrap().join("lorry.toml");
        let fixture = Fixture::new();
        let copied_repository = fixture.0.join("archive-repository");
        fs::create_dir_all(&copied_repository).unwrap();
        fs::copy(
            repository.join("repository.toml"),
            copied_repository.join("repository.toml"),
        )
        .unwrap();
        let source_object = repository
            .join("objects/crates-io/sha256")
            .join(&CHECKSUM[..2])
            .join(CHECKSUM);
        let copied_object = copied_repository
            .join("objects/crates-io/sha256")
            .join(&CHECKSUM[..2])
            .join(CHECKSUM);
        copy_tree(&source_object, &copied_object);
        fs::remove_dir_all(copied_object.join("source")).unwrap();
        fs::remove_file(copied_object.join("source-manifest.json")).unwrap();
        let metadata = fs::read_to_string(copied_object.join("package.toml"))
            .unwrap()
            .replace("retained-source = true", "retained-source = false");
        fs::write(copied_object.join("package.toml"), metadata).unwrap();

        fs::write(
            fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\nadler2 = \"=2.0.1\"\n",
        )
        .unwrap();
        fs::write(
            fixture.0.join("Cargo.lock"),
            format!(
                "version = 4\n\
                 [[package]]\nname = \"adler2\"\nversion = \"2.0.1\"\n\
                 source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                 checksum = \"{CHECKSUM}\"\n\
                 [[package]]\nname = \"root\"\nversion = \"0.1.0\"\n\
                 dependencies = [\"adler2\"]\n"
            ),
        )
        .unwrap();
        let home_config = fixture.0.join("home/.config/lorry");
        fs::create_dir_all(&home_config).unwrap();
        fs::copy(generated, home_config.join("lorry.toml")).unwrap();
        let mut config = Config::load_for_test(
            &fixture.0,
            &BTreeMap::from([(
                "HOME".to_owned(),
                fixture.0.join("home").display().to_string(),
            )]),
        )
        .unwrap();
        config.repositories.system = Some(copied_repository);
        config.repositories.user = None;
        let repositories = RepositorySet::open(
            &config.repositories,
            DEFAULT_LIMITS,
            config.policy.limits.max_package_bytes,
        )
        .unwrap();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let linux = CfgSet::parse("unix\ntarget_os=\"linux\"\n").unwrap();
        let staging = fixture.0.join("staging");
        let graph = prepare_locked(
            &manifest,
            &config,
            &repositories,
            &options(&manifest),
            TargetSelection {
                target_triple: "x86_64-unknown-linux-gnu",
                target_cfg: &linux,
                host_triple: "x86_64-unknown-linux-gnu",
                host_cfg: &linux,
            },
            &staging,
        )
        .unwrap();

        let package = graph.packages.values().next().unwrap();
        assert!(package.is_ephemeral());
        assert!(package.source_root().join("src/lib.rs").is_file());
        let extracted = package.source_root().to_owned();
        drop(graph);
        assert!(!extracted.exists());
    }
}
