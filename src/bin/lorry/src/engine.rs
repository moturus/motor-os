use crate::atomic::AtomicDirectory;
use crate::cache;
use crate::cargo_registry::CargoRegistry;
use crate::cli::{Cli, Color, Command, Verbosity};
use crate::config::{Config, PolicyLimits, TargetOptions, TargetSelector, environment_rustflags};
use crate::dependency;
use crate::diagnostic::{Error, Result};
use crate::executor;
use crate::hash::{hex, sha256_file};
use crate::identity::{
    CargoUnitLto, Identity, IdentityInput, RootTargetKind, cargo_identity, root_lto,
};
use crate::manifest::{
    BinaryTarget, Edition, IntegrationTestTarget, LibraryTarget, Manifest, Strip,
};
use crate::process::{self, RustcCommand};
use crate::repository::RepositorySet;
use crate::resolver::{
    Options as ResolverOptions, Resolution, TargetSelection, selected_root_features,
};
use crate::source_tree::{DEFAULT_LIMITS, Limits as TreeLimits};
use crate::toolchain::{TargetInfo, Toolchain};
use crate::unit::{CompilationPlan, PlanOptions, UnitKind};
use semver::Version;
use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MOTOR_TARGET: &str = "x86_64-unknown-motor";

pub fn execute(cli: &Cli) -> Result<i32> {
    let current = env::current_dir()
        .map_err(|error| Error::failure(format!("failed to read current directory: {error}")))?;
    let manifest = Manifest::load(&current)?;
    let config = Config::load(&current)?;
    let toolchain = Toolchain::discover(cli.toolchain.as_deref(), &config)?;
    check_rust_version(&manifest, &toolchain)?;
    if cli.verbosity == Verbosity::Verbose {
        eprintln!(
            "Using {} (rustc {}, Cargo {:?} compatibility)",
            toolchain.rustc.display(),
            toolchain.release,
            toolchain.compatibility
        );
    }

    let (release, command_target) = match &cli.command {
        Command::Build(options) => (options.release, options.target.as_deref()),
        Command::Run(options) => (options.build.release, options.build.target.as_deref()),
        Command::Test(options) => (options.build.release, options.build.target.as_deref()),
        _ => unreachable!("non-build command passed to engine"),
    };
    let physical_target = config.selected_target(command_target)?;
    let target_info = toolchain.target_info(physical_target.as_deref())?;
    let host_info = if physical_target.is_some() {
        toolchain.target_info(None)?
    } else {
        target_info.clone()
    };
    let target_matching_cfgs = matching_cfgs(&config, &target_info)?;
    let target_options = config.target_options(&target_info.triple, &target_matching_cfgs)?;
    let host_matching_cfgs = matching_cfgs(&config, &host_info)?;
    let host_options = config.target_options(&host_info.triple, &host_matching_cfgs)?;
    let rustflags = environment_rustflags()?.unwrap_or_else(|| {
        let mut flags = config.build_rustflags.clone();
        flags.extend(target_options.rustflags.iter().cloned());
        flags
    });
    let logical_target = if physical_target.is_some() {
        physical_target.as_deref()
    } else if cfg!(target_os = "motor") {
        Some(MOTOR_TARGET)
    } else {
        None
    };
    let color = use_color(cli.color);

    match &cli.command {
        Command::Build(_) => {
            build(Build {
                manifest: &manifest,
                config: &config,
                toolchain: &toolchain,
                host: &host_info,
                target: &target_info,
                host_options: &host_options,
                target_options: &target_options,
                physical_target: physical_target.as_deref(),
                logical_target,
                rustflags: &rustflags,
                release,
                test: false,
                test_name: None,
                color,
                verbosity: cli.verbosity,
                use_cargo_registry: cli.use_cargo_registry,
            })?;
            Ok(0)
        }
        Command::Run(options) => {
            let artifacts = build(Build {
                manifest: &manifest,
                config: &config,
                toolchain: &toolchain,
                host: &host_info,
                target: &target_info,
                host_options: &host_options,
                target_options: &target_options,
                physical_target: physical_target.as_deref(),
                logical_target,
                rustflags: &rustflags,
                release,
                test: false,
                test_name: None,
                color,
                verbosity: cli.verbosity,
                use_cargo_registry: cli.use_cargo_registry,
            })?;
            let artifact = artifacts.binary.as_deref().ok_or_else(|| {
                Error::failure(format!(
                    "package `{}` has no binary target to run",
                    manifest.name
                ))
            })?;
            run_artifact(
                artifact,
                &options.arguments,
                &manifest.root,
                physical_target.as_deref(),
                &target_options,
                cli.verbosity,
            )
        }
        Command::Test(options) => {
            if options.bundle {
                return Err(Error::failure(
                    "test bundles are not implemented in the current Stage-2 sub-stage",
                )
                .with_help(
                    "remove `--bundle` to build or run separate Cargo-compatible harnesses",
                ));
            }
            if cli.verbosity != Verbosity::Quiet {
                eprintln!("note: documentation tests are not supported");
            }
            let artifacts = build(Build {
                manifest: &manifest,
                config: &config,
                toolchain: &toolchain,
                host: &host_info,
                target: &target_info,
                host_options: &host_options,
                target_options: &target_options,
                physical_target: physical_target.as_deref(),
                logical_target,
                rustflags: &rustflags,
                release,
                test: true,
                test_name: options.test.as_deref(),
                color,
                verbosity: cli.verbosity,
                use_cargo_registry: cli.use_cargo_registry,
            })?;
            if options.no_run {
                for harness in &artifacts.harnesses {
                    println!("{}", harness.display());
                }
                return Ok(0);
            }
            for harness in &artifacts.harnesses {
                let status = run_artifact(
                    harness,
                    &options.arguments,
                    &manifest.root,
                    physical_target.as_deref(),
                    &target_options,
                    cli.verbosity,
                )?;
                if status != 0 {
                    return Ok(status);
                }
            }
            Ok(0)
        }
        _ => unreachable!(),
    }
}

struct Build<'a> {
    manifest: &'a Manifest,
    config: &'a Config,
    toolchain: &'a Toolchain,
    host: &'a TargetInfo,
    target: &'a TargetInfo,
    host_options: &'a TargetOptions,
    target_options: &'a TargetOptions,
    physical_target: Option<&'a str>,
    logical_target: Option<&'a str>,
    rustflags: &'a [String],
    release: bool,
    test: bool,
    test_name: Option<&'a str>,
    color: bool,
    verbosity: Verbosity,
    use_cargo_registry: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BuildArtifacts {
    primary: PathBuf,
    binary: Option<PathBuf>,
    harnesses: Vec<PathBuf>,
}

fn build(build: Build<'_>) -> Result<BuildArtifacts> {
    if let Some(name) = build.test_name
        && !build
            .manifest
            .integration_tests
            .iter()
            .any(|target| target.name == name)
    {
        return Err(unknown_integration_test(build.manifest, name));
    }
    if build.verbosity != Verbosity::Quiet {
        eprintln!(
            "Compiling {} v{} ({})",
            build.manifest.name,
            build.manifest.version.original,
            build.manifest.root.display()
        );
    }

    let target_root = build.manifest.root.join("target/lorry");
    let profile_name = if build.release { "release" } else { "debug" };
    let profile_parent = match build.physical_target {
        Some(target) => target_root.join(target),
        None => target_root.clone(),
    };
    let destination = profile_parent.join(profile_name);
    let staging = AtomicDirectory::new(&profile_parent, profile_name)?;
    let dependencies = staging.path().join("deps");
    fs::create_dir(&dependencies).map_err(|error| {
        Error::failure(format!(
            "failed to create dependency output `{}`: {error}",
            dependencies.display()
        ))
    })?;

    let rust_version = Version::parse(&build.toolchain.release).map_err(|error| {
        Error::failure(format!(
            "selected rustc release `{}` is not a semantic version: {error}",
            build.toolchain.release
        ))
    })?;
    let resolver_options = ResolverOptions {
        resolver: build.manifest.resolver,
        incompatible_rust_versions: build.config.incompatible_rust_versions,
        rust_version,
        max_packages: build.config.policy.limits.max_packages,
        max_depth: build.config.policy.limits.max_depth,
    };
    let selection = TargetSelection {
        target_triple: &build.target.triple,
        target_cfg: &build.target.cfg,
        host_triple: &build.host.triple,
        host_cfg: &build.host.cfg,
    };
    let prepared = if build.use_cargo_registry {
        let registry = CargoRegistry::discover(staging.path(), &build.config.policy.limits)?;
        dependency::prepare_locked_cargo_registry(
            build.manifest,
            build.config,
            &registry,
            &resolver_options,
            selection,
            staging.path(),
        )?
    } else {
        let repositories = RepositorySet::open(
            &build.config.repositories,
            repository_tree_limits(&build.config.policy.limits)?,
            build.config.policy.limits.max_package_bytes,
        )?;
        dependency::prepare_locked(
            build.manifest,
            build.config,
            &repositories,
            &resolver_options,
            selection,
            staging.path(),
        )?
    };
    let manifests = prepared
        .packages
        .iter()
        .map(|(key, package)| (key.clone(), package.manifest.clone()))
        .collect::<BTreeMap<_, _>>();
    let dependency_plan = |test_profile| {
        prepared.dependency_plan(&PlanOptions {
            workspace_root: &build.manifest.root,
            release: build.release,
            test_profile,
            release_profile: &build.manifest.release,
            rustc: build.toolchain,
            logical_target: build.logical_target,
            rustflags: build.rustflags,
        })
    };
    let host_profile = if build.physical_target.is_some() {
        staging.path().join(".host")
    } else {
        staging.path().to_owned()
    };
    let cargo = env::current_exe()
        .map_err(|error| Error::failure(format!("failed to locate Lorry executable: {error}")))?;
    let source_limits = repository_tree_limits(&build.config.policy.limits)?;
    let cache = cache::BuildCache::new(&cache::Options {
        root: &target_root.join(".cache"),
        cargo: &cargo,
        toolchain: build.toolchain,
        host: build.host,
        target: build.target,
        host_linker: build.host_options.linker.as_deref(),
        target_linker: build.target_options.linker.as_deref(),
        root_manifest: build.manifest,
        source_limits,
    })?;
    let executor_options = executor::Options {
        cargo: &cargo,
        toolchain: build.toolchain,
        host: build.host,
        target: build.target,
        host_profile: &host_profile,
        target_profile: staging.path(),
        physical_target: build.physical_target,
        host_linker: build.host_options.linker.as_deref(),
        target_linker: build.target_options.linker.as_deref(),
        release: build.release,
        verbose: build.verbosity == Verbosity::Verbose,
        color: build.color,
        build_script_timeout: Duration::from_secs(build.config.policy.limits.build_script_seconds),
        build_script_output_bytes: build.config.policy.limits.build_script_output_bytes,
        out_dir_limits: source_limits,
        cache: Some(&cache),
    };
    let selected_integration =
        build.test && (build.test_name.is_some() || !build.manifest.integration_tests.is_empty());
    let needs_normal_plan =
        !build.test || (selected_integration && !build.manifest.binaries.is_empty());
    let normal = if needs_normal_plan {
        let plan = dependency_plan(false)?;
        let outputs = executor::execute(&plan, &manifests, &executor_options)?;
        let dependencies = root_dependencies(&prepared.resolution, &plan, &outputs)?;
        Some((plan, outputs, dependencies))
    } else {
        None
    };
    let test_dependencies = if build.test {
        let test_plan = dependency_plan(true)?;
        let outputs = match normal.as_ref() {
            Some((normal_plan, normal_outputs, _)) => executor::execute_reusing(
                &test_plan,
                &manifests,
                &executor_options,
                normal_plan,
                normal_outputs,
            )?,
            None => executor::execute(&test_plan, &manifests, &executor_options)?,
        };
        Some(root_dependencies(
            &prepared.resolution,
            &test_plan,
            &outputs,
        )?)
    } else {
        None
    };
    let normal_dependencies = normal
        .as_ref()
        .map(|(_, _, dependencies)| dependencies.as_slice())
        .unwrap_or(&[]);
    prepared
        .revalidate_cargo_registry_sources(repository_tree_limits(&build.config.policy.limits)?)?;
    let compiled = if build.test {
        compile_test_targets(
            &build,
            staging.path(),
            &host_profile,
            normal_dependencies,
            test_dependencies.as_ref().unwrap(),
            &destination,
            &target_root,
        )?
    } else {
        compile_root_targets(&build, staging.path(), &host_profile, normal_dependencies)?
    };

    drop(prepared);
    if build.physical_target.is_some() {
        fs::remove_dir_all(&host_profile).map_err(|error| {
            Error::failure(format!(
                "failed to remove temporary host dependency output `{}`: {error}",
                host_profile.display()
            ))
        })?;
    }

    let relative_primary = compiled
        .primary
        .strip_prefix(staging.path())
        .unwrap()
        .to_path_buf();
    let relative_binary = compiled
        .binary
        .as_ref()
        .map(|artifact| artifact.strip_prefix(staging.path()).unwrap().to_path_buf());
    let relative_harnesses = compiled
        .harnesses
        .iter()
        .map(|artifact| artifact.strip_prefix(staging.path()).unwrap().to_path_buf())
        .collect::<Vec<_>>();
    staging.commit(&destination)?;
    let artifacts = BuildArtifacts {
        primary: destination.join(relative_primary),
        binary: relative_binary.map(|artifact| destination.join(artifact)),
        harnesses: relative_harnesses
            .into_iter()
            .map(|artifact| destination.join(artifact))
            .collect(),
    };

    if build.verbosity != Verbosity::Quiet {
        eprintln!(
            "Finished `{}` profile",
            if build.release { "release" } else { "dev" }
        );
    }
    if build.verbosity == Verbosity::Verbose {
        eprintln!(
            "Artifact {} sha256={}",
            artifacts.primary.display(),
            hex(&sha256_file(&artifacts.primary)?)
        );
    }
    Ok(artifacts)
}

struct RootDependency {
    alias: String,
    identity: Identity,
    rlib: PathBuf,
    rmeta: PathBuf,
}

fn root_dependencies(
    resolution: &Resolution,
    plan: &CompilationPlan,
    outputs: &executor::Outputs,
) -> Result<Vec<RootDependency>> {
    let mut result = Vec::new();
    for edge in &resolution.root_edges {
        let mut matches = plan.units.iter().filter(|(key, _)| {
            key.package == edge.package
                && key.kind == UnitKind::Library
                && key.compile_kind == edge.compile_kind
        });
        let (key, planned) = matches.next().ok_or_else(|| {
            Error::failure(format!(
                "root dependency `{} {}` has no target library unit",
                edge.package.name, edge.package.version
            ))
        })?;
        if matches.next().is_some() {
            return Err(Error::failure(format!(
                "root dependency `{} {}` has more than one target library unit",
                edge.package.name, edge.package.version
            )));
        }
        let (rlib, rmeta) = match outputs.artifacts.get(key) {
            Some(crate::compile::RustcOutput::Library { rlib, rmeta, .. }) => {
                (rlib.clone(), rmeta.clone())
            }
            _ => {
                return Err(Error::failure(format!(
                    "root dependency `{} {}` did not produce a library artifact",
                    edge.package.name, edge.package.version
                )));
            }
        };
        let alias = edge.alias.replace('-', "_");
        if result
            .iter()
            .any(|existing: &RootDependency| existing.alias == alias)
        {
            return Err(Error::failure(format!(
                "selected root dependency alias `{alias}` is ambiguous"
            )));
        }
        result.push(RootDependency {
            alias,
            identity: planned.identity.clone(),
            rlib,
            rmeta,
        });
    }
    Ok(result)
}

#[derive(Clone, Copy)]
enum RootTarget<'a> {
    Library(&'a LibraryTarget),
    Binary(&'a BinaryTarget),
    IntegrationTest(&'a IntegrationTestTarget),
}

impl<'a> RootTarget<'a> {
    fn name(self) -> &'a str {
        match self {
            Self::Library(target) => &target.name,
            Self::Binary(target) => &target.name,
            Self::IntegrationTest(target) => &target.name,
        }
    }

    fn crate_name(self) -> String {
        self.name().replace('-', "_")
    }

    fn path(self) -> &'a Path {
        match self {
            Self::Library(target) => &target.path,
            Self::Binary(target) => &target.path,
            Self::IntegrationTest(target) => &target.path,
        }
    }

    fn kind(self) -> RootTargetKind {
        match self {
            Self::Library(_) => RootTargetKind::Library,
            Self::Binary(_) => RootTargetKind::Binary,
            Self::IntegrationTest(_) => RootTargetKind::IntegrationTest,
        }
    }
}

struct RootLibraryArtifact {
    identity: Identity,
    rlib: PathBuf,
}

struct StagedArtifacts {
    primary: PathBuf,
    binary: Option<PathBuf>,
    harnesses: Vec<PathBuf>,
}

fn compile_root_targets(
    build: &Build<'_>,
    staging: &Path,
    host_profile: &Path,
    dependencies: &[RootDependency],
) -> Result<StagedArtifacts> {
    let features = selected_root_features(build.manifest)?
        .into_iter()
        .collect::<Vec<_>>();
    let library = build
        .manifest
        .library
        .as_ref()
        .map(|target| {
            compile_root_library(
                build,
                target,
                staging,
                host_profile,
                dependencies,
                &features,
                false,
            )
        })
        .transpose()?;
    let binary = build
        .manifest
        .binaries
        .first()
        .map(|target| {
            compile_root_binary(
                build,
                target,
                false,
                staging,
                host_profile,
                dependencies,
                library.as_ref(),
                &features,
                false,
            )
        })
        .transpose()?;
    if let Some(binary) = binary {
        install_primary(&binary.hashed, &binary.primary)?;
        return Ok(StagedArtifacts {
            primary: binary.primary.clone(),
            binary: Some(binary.primary),
            harnesses: Vec::new(),
        });
    }
    let library = library.ok_or_else(|| {
        Error::failure(format!(
            "package `{}` has no supported root target",
            build.manifest.name
        ))
    })?;
    Ok(StagedArtifacts {
        primary: library.rlib,
        binary: None,
        harnesses: Vec::new(),
    })
}

fn compile_test_targets(
    build: &Build<'_>,
    staging: &Path,
    host_profile: &Path,
    normal_dependencies: &[RootDependency],
    test_dependencies: &[RootDependency],
    destination: &Path,
    target_root: &Path,
) -> Result<StagedArtifacts> {
    let features = selected_root_features(build.manifest)?
        .into_iter()
        .collect::<Vec<_>>();
    let integration_tests = match build.test_name {
        Some(name) => vec![
            build
                .manifest
                .integration_tests
                .iter()
                .find(|target| target.name == name)
                .ok_or_else(|| unknown_integration_test(build.manifest, name))?,
        ],
        None => build.manifest.integration_tests.iter().collect::<Vec<_>>(),
    };

    let normal_library = if integration_tests.is_empty() || build.manifest.binaries.is_empty() {
        None
    } else {
        build
            .manifest
            .library
            .as_ref()
            .map(|target| {
                compile_root_library(
                    build,
                    target,
                    staging,
                    host_profile,
                    normal_dependencies,
                    &features,
                    false,
                )
            })
            .transpose()?
    };
    let program = if integration_tests.is_empty() {
        None
    } else {
        let compiled = build
            .manifest
            .binaries
            .first()
            .map(|target| {
                compile_root_binary(
                    build,
                    target,
                    false,
                    staging,
                    host_profile,
                    normal_dependencies,
                    normal_library.as_ref(),
                    &features,
                    false,
                )
            })
            .transpose()?;
        match compiled {
            Some(binary) => {
                install_primary(&binary.hashed, &binary.primary)?;
                Some(binary)
            }
            None => None,
        }
    };

    let test_library = build
        .manifest
        .library
        .as_ref()
        .map(|target| {
            compile_root_library(
                build,
                target,
                staging,
                host_profile,
                test_dependencies,
                &features,
                true,
            )
        })
        .transpose()?;
    let mut harnesses = Vec::new();
    if build.test_name.is_none() {
        if let Some(library) = build.manifest.library.as_ref().filter(|target| target.test) {
            harnesses.push(compile_root_harness(
                build,
                RootTarget::Library(library),
                staging,
                host_profile,
                test_dependencies,
                None,
                &features,
                None,
                None,
            )?);
        }
        if let Some(binary) = build.manifest.binaries.first().filter(|target| target.test) {
            harnesses.push(compile_root_harness(
                build,
                RootTarget::Binary(binary),
                staging,
                host_profile,
                test_dependencies,
                test_library.as_ref(),
                &features,
                None,
                None,
            )?);
        }
    }

    if !integration_tests.is_empty() {
        let temporary_directory = target_root.join("tmp");
        fs::create_dir_all(&temporary_directory).map_err(|error| {
            Error::failure(format!(
                "failed to create test temporary directory `{}`: {error}",
                temporary_directory.display()
            ))
        })?;
        for target in integration_tests {
            harnesses.push(compile_root_harness(
                build,
                RootTarget::IntegrationTest(target),
                staging,
                host_profile,
                test_dependencies,
                test_library.as_ref(),
                &features,
                Some(IntegrationEnvironment {
                    binary: build
                        .manifest
                        .binaries
                        .first()
                        .map(|target| (target.name.as_str(), destination.join(&target.name))),
                    temporary_directory: &temporary_directory,
                }),
                program.as_ref().map(|binary| &binary.identity),
            )?);
        }
    }

    let primary = harnesses.first().cloned().ok_or_else(|| {
        Error::failure(format!(
            "package `{}` has no enabled test targets",
            build.manifest.name
        ))
    })?;
    Ok(StagedArtifacts {
        primary,
        binary: program.map(|binary| binary.primary),
        harnesses,
    })
}

fn unknown_integration_test(manifest: &Manifest, name: &str) -> Error {
    let available = manifest
        .integration_tests
        .iter()
        .map(|target| target.name.as_str())
        .collect::<Vec<_>>();
    let help = if available.is_empty() {
        "this package has no discovered integration-test targets".to_owned()
    } else {
        format!(
            "available integration-test targets: {}",
            available.join(", ")
        )
    };
    Error::failure(format!("no integration-test target named `{name}`")).with_help(help)
}

fn compile_root_library(
    build: &Build<'_>,
    target: &LibraryTarget,
    staging: &Path,
    host_profile: &Path,
    dependencies: &[RootDependency],
    features: &[String],
    test_profile: bool,
) -> Result<RootLibraryArtifact> {
    let identities = dependencies
        .iter()
        .map(|dependency| dependency.identity.clone())
        .collect::<Vec<_>>();
    let target = RootTarget::Library(target);
    let identity = root_identity(build, target, false, test_profile, features, &identities);
    let arguments = rustc_arguments(
        build,
        target,
        false,
        &identity,
        staging,
        host_profile,
        dependencies,
        None,
        features,
        test_profile,
    );
    run_root_rustc(build, target, host_profile, &arguments, None)?;
    let stem = format!("{}{}", target.crate_name(), identity.extra_filename);
    let rlib = staging.join("deps").join(format!("lib{stem}.rlib"));
    let rmeta = staging.join("deps").join(format!("lib{stem}.rmeta"));
    verify_artifacts([&rlib, &rmeta])?;
    Ok(RootLibraryArtifact { identity, rlib })
}

fn compile_root_binary(
    build: &Build<'_>,
    target: &BinaryTarget,
    test: bool,
    staging: &Path,
    host_profile: &Path,
    dependencies: &[RootDependency],
    library: Option<&RootLibraryArtifact>,
    features: &[String],
    test_profile: bool,
) -> Result<RootBinaryArtifact> {
    let mut identities = dependencies
        .iter()
        .map(|dependency| dependency.identity.clone())
        .collect::<Vec<_>>();
    if let Some(library) = library {
        identities.push(library.identity.clone());
    }
    let target = RootTarget::Binary(target);
    let identity = root_identity(build, target, test, test_profile, features, &identities);
    let arguments = rustc_arguments(
        build,
        target,
        test,
        &identity,
        staging,
        host_profile,
        dependencies,
        library,
        features,
        test_profile,
    );
    run_root_rustc(build, target, host_profile, &arguments, None)?;
    let hashed = staging.join("deps").join(format!(
        "{}{}",
        target.crate_name(),
        identity.extra_filename
    ));
    verify_artifacts([&hashed])?;
    Ok(RootBinaryArtifact {
        identity,
        hashed,
        primary: staging.join(target.name()),
    })
}

struct RootBinaryArtifact {
    identity: Identity,
    hashed: PathBuf,
    primary: PathBuf,
}

#[derive(Clone)]
struct IntegrationEnvironment<'a> {
    binary: Option<(&'a str, PathBuf)>,
    temporary_directory: &'a Path,
}

fn compile_root_harness(
    build: &Build<'_>,
    target: RootTarget<'_>,
    staging: &Path,
    host_profile: &Path,
    dependencies: &[RootDependency],
    library: Option<&RootLibraryArtifact>,
    features: &[String],
    integration_environment: Option<IntegrationEnvironment<'_>>,
    artifact_dependency: Option<&Identity>,
) -> Result<PathBuf> {
    let mut identities = dependencies
        .iter()
        .map(|dependency| dependency.identity.clone())
        .collect::<Vec<_>>();
    if let Some(library) = library {
        identities.push(library.identity.clone());
    }
    if let Some(artifact_dependency) = artifact_dependency {
        identities.push(artifact_dependency.clone());
    }
    let identity = root_identity(build, target, true, true, features, &identities);
    let arguments = rustc_arguments(
        build,
        target,
        true,
        &identity,
        staging,
        host_profile,
        dependencies,
        library,
        features,
        true,
    );
    run_root_rustc(
        build,
        target,
        host_profile,
        &arguments,
        integration_environment,
    )?;
    let artifact = staging.join("deps").join(format!(
        "{}{}",
        target.crate_name(),
        identity.extra_filename
    ));
    verify_artifacts([&artifact])?;
    Ok(artifact)
}

fn root_identity(
    build: &Build<'_>,
    target: RootTarget<'_>,
    test: bool,
    test_profile: bool,
    features: &[String],
    dependencies: &[Identity],
) -> Identity {
    cargo_identity(&IdentityInput {
        package_name: &build.manifest.name,
        version: &build.manifest.version,
        target_name: target.name(),
        target_kind: target.kind(),
        features,
        release: build.release,
        test,
        test_profile,
        logical_target: build.logical_target,
        release_profile: &build.manifest.release,
        rustc: build.toolchain,
        rustflags: build.rustflags,
        dependencies,
    })
}

fn run_root_rustc(
    build: &Build<'_>,
    target: RootTarget<'_>,
    host_profile: &Path,
    arguments: &[OsString],
    integration_environment: Option<IntegrationEnvironment<'_>>,
) -> Result<()> {
    let environment = rustc_environment(
        build,
        host_profile,
        target,
        integration_environment.as_ref(),
    )?;
    RustcCommand {
        program: &build.toolchain.rustc,
        arguments,
        environment: &environment,
        current_dir: &build.manifest.root,
        verbose: build.verbosity == Verbosity::Verbose,
        color: build.color,
    }
    .run()
}

fn verify_artifacts<'a>(artifacts: impl IntoIterator<Item = &'a PathBuf>) -> Result<()> {
    for artifact in artifacts {
        if !artifact.is_file() {
            return Err(Error::failure(format!(
                "rustc succeeded but expected artifact `{}` is missing",
                artifact.display()
            )));
        }
    }
    Ok(())
}

fn install_primary(source: &Path, destination: &Path) -> Result<()> {
    match fs::hard_link(source, destination) {
        Ok(()) => Ok(()),
        Err(_) => fs::copy(source, destination).map(|_| ()).map_err(|error| {
            Error::failure(format!(
                "failed to install primary artifact `{}`: {error}",
                destination.display()
            ))
        }),
    }
}

fn rustc_arguments(
    build: &Build<'_>,
    target: RootTarget<'_>,
    test: bool,
    identity: &Identity,
    staging: &Path,
    host_profile: &Path,
    root_dependencies: &[RootDependency],
    root_library: Option<&RootLibraryArtifact>,
    features: &[String],
    test_profile: bool,
) -> Vec<OsString> {
    let mut args = Vec::new();
    push(&mut args, "--crate-name");
    push(&mut args, &target.crate_name());
    push(
        &mut args,
        &format!("--edition={}", edition_name(build.manifest.edition)),
    );
    args.push(
        target
            .path()
            .strip_prefix(&build.manifest.root)
            .expect("root target path came from a validated relative manifest path")
            .as_os_str()
            .to_owned(),
    );
    push(&mut args, "--error-format=json");
    push(
        &mut args,
        "--json=diagnostic-rendered-ansi,artifacts,future-incompat",
    );
    if !test {
        push(&mut args, "--crate-type");
        push(
            &mut args,
            match target.kind() {
                RootTargetKind::Library => "lib",
                RootTargetKind::Binary | RootTargetKind::IntegrationTest => "bin",
            },
        );
    }
    push(
        &mut args,
        if target.kind() == RootTargetKind::Library && !test {
            "--emit=dep-info,metadata,link"
        } else {
            "--emit=dep-info,link"
        },
    );

    if build.release {
        codegen(&mut args, "opt-level=3");
        if build.manifest.release.panic_abort && !test_profile {
            codegen(&mut args, "panic=abort");
        }
        root_lto_arguments(
            &mut args,
            root_lto(
                build.release,
                build.manifest.release.lto,
                target.kind(),
                test,
            ),
        );
        if let Some(units) = build.manifest.release.codegen_units {
            codegen(&mut args, &format!("codegen-units={units}"));
        }
    } else {
        codegen(&mut args, "embed-bitcode=no");
        codegen(&mut args, "debuginfo=2");
    }
    args.extend(crate::compile::lint_arguments(build.manifest));
    for feature in features {
        push(&mut args, "--cfg");
        push(&mut args, &format!("feature=\"{feature}\""));
    }
    if test {
        push(&mut args, "--test");
    }
    push(&mut args, "--check-cfg");
    push(&mut args, "cfg(docsrs,test)");
    push(&mut args, "--check-cfg");
    push(
        &mut args,
        &format!(
            "cfg(feature, values({}))",
            crate::compile::declared_features(build.manifest)
                .iter()
                .map(|feature| format!("\"{feature}\""))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    );
    codegen(&mut args, &format!("metadata={}", identity.metadata));
    codegen(
        &mut args,
        &format!("extra-filename={}", identity.extra_filename),
    );
    push(&mut args, "--out-dir");
    args.push(staging.join("deps").into_os_string());
    if let Some(target) = build.physical_target {
        push(&mut args, "--target");
        push(&mut args, target);
    }
    if !build.release && !cfg!(target_os = "motor") {
        codegen(
            &mut args,
            &format!("incremental={}", staging.join("incremental").display()),
        );
    }
    if build.release {
        match build.manifest.release.strip {
            Strip::None => {}
            Strip::Debuginfo => codegen(&mut args, "strip=debuginfo"),
            Strip::Symbols => codegen(&mut args, "strip=symbols"),
        }
    }
    if let Some(linker) = &build.target_options.linker {
        codegen(&mut args, &format!("linker={}", linker.display()));
    }
    push(&mut args, "-L");
    args.push(format!("dependency={}", staging.join("deps").display()).into());
    if build.physical_target.is_some() {
        let host_dependencies = host_profile.join("deps");
        push(&mut args, "-L");
        args.push(format!("dependency={}", host_dependencies.display()).into());
    }
    for dependency in root_dependencies {
        push(&mut args, "--extern");
        let artifact = if target.kind() == RootTargetKind::Library && !test {
            &dependency.rmeta
        } else {
            &dependency.rlib
        };
        args.push(format!("{}={}", dependency.alias, artifact.display()).into());
    }
    if let Some(library) = root_library {
        let name = build
            .manifest
            .library
            .as_ref()
            .unwrap()
            .name
            .replace('-', "_");
        push(&mut args, "--extern");
        args.push(format!("{name}={}", library.rlib.display()).into());
    }
    args.extend(build.rustflags.iter().map(OsString::from));
    push(&mut args, "--verbose");
    args
}

fn root_lto_arguments(arguments: &mut Vec<OsString>, lto: CargoUnitLto<'_>) {
    match lto {
        CargoUnitLto::Run(None) => codegen(arguments, "lto"),
        CargoUnitLto::Run(Some(mode)) => codegen(arguments, &format!("lto={mode}")),
        CargoUnitLto::Off => {
            codegen(arguments, "lto=off");
            codegen(arguments, "embed-bitcode=no");
        }
        CargoUnitLto::OnlyBitcode => codegen(arguments, "linker-plugin-lto"),
        CargoUnitLto::ObjectAndBitcode => {}
        CargoUnitLto::OnlyObject => codegen(arguments, "embed-bitcode=no"),
    }
}

fn rustc_environment(
    build: &Build<'_>,
    host_profile: &Path,
    target: RootTarget<'_>,
    integration_environment: Option<&IntegrationEnvironment<'_>>,
) -> Result<BTreeMap<String, OsString>> {
    let manifest = build.manifest;
    let version = &manifest.version;
    let mut values = BTreeMap::new();
    let current_exe = env::current_exe()
        .map_err(|error| Error::failure(format!("failed to locate Lorry executable: {error}")))?;
    value(&mut values, "CARGO", current_exe.as_os_str());
    if let RootTarget::Binary(binary) = target {
        value(&mut values, "CARGO_BIN_NAME", &binary.name);
    }
    if let Some(integration) = integration_environment {
        if let Some((name, path)) = &integration.binary {
            value(
                &mut values,
                &format!("CARGO_BIN_EXE_{name}"),
                path.as_os_str(),
            );
        }
        value(
            &mut values,
            "CARGO_TARGET_TMPDIR",
            integration.temporary_directory.as_os_str(),
        );
    }
    value(&mut values, "CARGO_CRATE_NAME", target.crate_name());
    value(&mut values, "CARGO_MANIFEST_DIR", manifest.root.as_os_str());
    value(
        &mut values,
        "CARGO_MANIFEST_PATH",
        manifest.path.as_os_str(),
    );
    value(
        &mut values,
        "CARGO_PKG_AUTHORS",
        &manifest.metadata.authors.join(":"),
    );
    value(
        &mut values,
        "CARGO_PKG_DESCRIPTION",
        &manifest.metadata.description,
    );
    value(
        &mut values,
        "CARGO_PKG_HOMEPAGE",
        &manifest.metadata.homepage,
    );
    value(&mut values, "CARGO_PKG_LICENSE", &manifest.metadata.license);
    value(
        &mut values,
        "CARGO_PKG_LICENSE_FILE",
        &manifest.metadata.license_file,
    );
    value(&mut values, "CARGO_PKG_NAME", &manifest.name);
    value(&mut values, "CARGO_PKG_README", &manifest.metadata.readme);
    value(
        &mut values,
        "CARGO_PKG_REPOSITORY",
        &manifest.metadata.repository,
    );
    value(
        &mut values,
        "CARGO_PKG_RUST_VERSION",
        &manifest.metadata.rust_version,
    );
    value(&mut values, "CARGO_PKG_VERSION", &version.original);
    value(
        &mut values,
        "CARGO_PKG_VERSION_MAJOR",
        &version.major.to_string(),
    );
    value(
        &mut values,
        "CARGO_PKG_VERSION_MINOR",
        &version.minor.to_string(),
    );
    value(
        &mut values,
        "CARGO_PKG_VERSION_PATCH",
        &version.patch.to_string(),
    );
    value(&mut values, "CARGO_PKG_VERSION_PRE", &version.pre);
    value(&mut values, "CARGO_PRIMARY_PACKAGE", "1");
    value(
        &mut values,
        dynamic_library_path_variable(),
        host_profile.join("deps").as_os_str(),
    );
    Ok(values)
}

fn repository_tree_limits(policy: &PolicyLimits) -> Result<TreeLimits> {
    let max_entries = policy
        .max_package_files
        .checked_mul(2)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| Error::failure("policy package file limit does not fit this platform"))?;
    Ok(TreeLimits {
        max_entries,
        max_path_bytes: DEFAULT_LIMITS.max_path_bytes,
        max_file_bytes: policy.max_extracted_package_bytes,
        max_tree_bytes: policy.max_extracted_package_bytes,
    })
}

fn run_artifact(
    artifact: &Path,
    arguments: &[String],
    package_root: &Path,
    physical_target: Option<&str>,
    target_options: &TargetOptions,
    verbosity: Verbosity,
) -> Result<i32> {
    let mut child_arguments: Vec<OsString> = Vec::new();
    let program: &OsStr;
    if physical_target.is_some() {
        if let Some(runner) = &target_options.runner {
            let (runner_program, runner_arguments) = runner
                .split_first()
                .ok_or_else(|| Error::failure("configured target runner has no executable"))?;
            program = OsStr::new(runner_program);
            child_arguments.extend(runner_arguments.iter().map(OsString::from));
            child_arguments.push(artifact.as_os_str().to_owned());
        } else {
            program = artifact.as_os_str();
        }
    } else {
        program = artifact.as_os_str();
    }
    child_arguments.extend(arguments.iter().map(OsString::from));
    process::run_child(
        program,
        &child_arguments,
        package_root,
        verbosity == Verbosity::Verbose,
    )
}

fn matching_cfgs(config: &Config, target: &TargetInfo) -> Result<Vec<String>> {
    let selectors = config.targets.keys().filter_map(|selector| match selector {
        TargetSelector::Cfg(expression) => Some(expression.as_str()),
        TargetSelector::Triple(_) => None,
    });
    target.cfg.matching_selectors(selectors)
}

fn check_rust_version(manifest: &Manifest, toolchain: &Toolchain) -> Result<()> {
    let requested = manifest.metadata.rust_version.trim();
    if requested.is_empty() {
        return Ok(());
    }
    let mut requested_parts = requested.split('.');
    let requested_major = requested_parts
        .next()
        .and_then(|value| value.parse::<u64>().ok());
    let requested_minor = requested_parts
        .next()
        .and_then(|value| value.parse::<u64>().ok());
    if requested_major.is_none() || requested_minor.is_none() {
        return Err(
            Error::failure(format!("unsupported package rust-version `{requested}`"))
                .with_help("use a major.minor Rust version such as `1.85`"),
        );
    }
    let release = toolchain.release.split('-').next().unwrap_or("");
    let mut release_parts = release.split('.');
    let actual = (
        release_parts
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0),
        release_parts
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0),
    );
    let requested = (requested_major.unwrap(), requested_minor.unwrap());
    if actual < requested {
        return Err(Error::failure(format!(
            "package requires rustc {}.{} or newer, selected rustc is {}",
            requested.0, requested.1, toolchain.release
        )));
    }
    Ok(())
}

fn edition_name(edition: Edition) -> &'static str {
    match edition {
        Edition::E2015 => "2015",
        Edition::E2018 => "2018",
        Edition::E2021 => "2021",
        Edition::E2024 => "2024",
    }
}

fn use_color(color: Color) -> bool {
    match color {
        Color::Always => true,
        Color::Never => false,
        Color::Auto => env::var_os("NO_COLOR").is_none() && std::io::stderr().is_terminal(),
    }
}

fn dynamic_library_path_variable() -> &'static str {
    if cfg!(target_os = "macos") {
        "DYLD_FALLBACK_LIBRARY_PATH"
    } else if cfg!(windows) {
        "PATH"
    } else {
        "LD_LIBRARY_PATH"
    }
}

fn value(values: &mut BTreeMap<String, OsString>, key: &str, value: impl AsRef<OsStr>) {
    values.insert(key.to_owned(), value.as_ref().to_owned());
}

fn push(args: &mut Vec<OsString>, value: &str) {
    args.push(value.into());
}

fn codegen(args: &mut Vec<OsString>, value: &str) {
    push(args, "-C");
    push(args, value);
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::config::{CargoCompat, PolicyAction, PolicyRule};
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "lorry-engine-dependencies-{}-{id}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("src")).unwrap();
            fs::create_dir_all(root.join("local/src")).unwrap();
            fs::write(
                root.join("Cargo.toml"),
                "[package]\nname = \"root-bin\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\
                 [dependencies]\nlocal-dependency = { package = \"local-dependency\", path = \"local\" }\n",
            )
            .unwrap();
            fs::write(
                root.join("Cargo.lock"),
                "version = 4\n\
                 [[package]]\nname = \"local-dependency\"\nversion = \"1.2.3\"\n\
                 [[package]]\nname = \"root-bin\"\nversion = \"0.1.0\"\ndependencies = [\"local-dependency\"]\n",
            )
            .unwrap();
            fs::write(
                root.join("src/main.rs"),
                "fn main() { print!(\"{}\", local_dependency::VALUE); }\n",
            )
            .unwrap();
            fs::write(
                root.join("local/Cargo.toml"),
                "[package]\nname = \"local-dependency\"\nversion = \"1.2.3\"\nedition = \"2024\"\nlicense = \"MIT\"\n",
            )
            .unwrap();
            fs::write(
                root.join("local/src/lib.rs"),
                "pub const VALUE: &str = \"dependency-ok\";\n",
            )
            .unwrap();
            Self(root)
        }

        fn add_build_script(&self) {
            fs::write(
                self.0.join("local/Cargo.toml"),
                "[package]\nname = \"local-dependency\"\nversion = \"1.2.3\"\nedition = \"2024\"\nlicense = \"MIT\"\nbuild = \"build.rs\"\n",
            )
            .unwrap();
            fs::write(
                self.0.join("local/build.rs"),
                "fn main() {\n\
                     let out = std::env::var_os(\"OUT_DIR\").unwrap();\n\
                     std::fs::write(std::path::Path::new(&out).join(\"generated.rs\"), \"pub const VALUE: &str = \\\"build-script-ok\\\";\\n\").unwrap();\n\
                     println!(\"cargo:rerun-if-changed=build.rs\");\n\
                 }\n",
            )
            .unwrap();
            fs::write(
                self.0.join("local/src/lib.rs"),
                "include!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));\n",
            )
            .unwrap();
        }

        fn add_root_library(&self) {
            let mut manifest = fs::read_to_string(self.0.join("Cargo.toml")).unwrap();
            manifest.push_str("[features]\ndefault = [\"enabled\"]\nenabled = []\n");
            fs::write(self.0.join("Cargo.toml"), manifest).unwrap();
            fs::write(
                self.0.join("src/lib.rs"),
                "#[cfg(not(feature = \"enabled\"))]\ncompile_error!(\"default feature missing\");\n\
                 pub fn value() -> &'static str { local_dependency::VALUE }\n",
            )
            .unwrap();
            fs::write(
                self.0.join("src/main.rs"),
                "fn main() { print!(\"{}\", root_bin::value()); }\n",
            )
            .unwrap();
        }

        fn add_test_targets(&self) {
            self.add_root_library();
            let library = fs::read_to_string(self.0.join("src/lib.rs")).unwrap();
            fs::write(
                self.0.join("src/lib.rs"),
                format!(
                    "{library}\n#[cfg(test)]\nmod tests {{\n    #[test]\n    fn library_unit() {{ assert_eq!(super::value(), \"dependency-ok\"); }}\n}}\n"
                ),
            )
            .unwrap();
            let binary = fs::read_to_string(self.0.join("src/main.rs")).unwrap();
            fs::write(
                self.0.join("src/main.rs"),
                format!(
                    "{binary}\n#[cfg(test)]\nmod tests {{\n    #[test]\n    fn binary_unit() {{ assert_eq!(root_bin::value(), \"dependency-ok\"); }}\n}}\n"
                ),
            )
            .unwrap();
            fs::create_dir(self.0.join("tests")).unwrap();
            for name in ["first", "second"] {
                fs::write(
                    self.0.join("tests").join(format!("{name}.rs")),
                    "#[test]\nfn integration() {\n\
                         assert!(std::path::Path::new(env!(\"CARGO_TARGET_TMPDIR\")).is_dir());\n\
                         let output = std::process::Command::new(env!(\"CARGO_BIN_EXE_root-bin\")).output().unwrap();\n\
                         assert!(output.status.success());\n\
                         assert_eq!(output.stdout, b\"dependency-ok\");\n\
                     }\n",
                )
                .unwrap();
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn cache_entry_count(root: &Path) -> usize {
        let units = root.join("target/lorry/.cache/v1/units/sha256");
        fs::read_dir(units)
            .unwrap()
            .map(|prefix| fs::read_dir(prefix.unwrap().path()).unwrap().count())
            .sum()
    }

    #[test]
    fn reuses_verified_libraries_but_relinks_roots_and_invalidates_sources() {
        use std::os::unix::fs::MetadataExt;

        let fixture = Fixture::new();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_98);
        let toolchain = Toolchain::discover(None, &config).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let build_once = || {
            build(Build {
                manifest: &manifest,
                config: &config,
                toolchain: &toolchain,
                host: &target,
                target: &target,
                host_options: &target_options,
                target_options: &target_options,
                physical_target: None,
                logical_target: None,
                rustflags: &[],
                release: false,
                test: false,
                test_name: None,
                color: false,
                verbosity: Verbosity::Quiet,
                use_cargo_registry: false,
            })
            .unwrap()
        };

        let cold = build_once();
        let cold_binary = cold.binary.unwrap();
        let cold_inode = fs::metadata(&cold_binary).unwrap().ino();
        let cold_hash = sha256_file(&cold_binary).unwrap();
        assert_eq!(cache_entry_count(&fixture.0), 1);

        let warm = build_once();
        let warm_binary = warm.binary.unwrap();
        assert_ne!(fs::metadata(&warm_binary).unwrap().ino(), cold_inode);
        assert_eq!(sha256_file(&warm_binary).unwrap(), cold_hash);
        assert_eq!(cache_entry_count(&fixture.0), 1);

        fs::write(
            fixture.0.join("local/src/lib.rs"),
            "pub const VALUE: &str = \"source-changed\";\n",
        )
        .unwrap();
        let invalidated = build_once();
        assert_eq!(cache_entry_count(&fixture.0), 2);
        let output = std::process::Command::new(invalidated.binary.unwrap())
            .output()
            .unwrap();
        assert_eq!(output.stdout, b"source-changed");
    }

    #[test]
    fn builds_a_root_binary_with_an_unversioned_path_dependency() {
        let fixture = Fixture::new();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_98);
        let toolchain = Toolchain::discover(None, &config).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let artifact = build(Build {
            manifest: &manifest,
            config: &config,
            toolchain: &toolchain,
            host: &target,
            target: &target,
            host_options: &target_options,
            target_options: &target_options,
            physical_target: None,
            logical_target: None,
            rustflags: &[],
            release: false,
            test: false,
            test_name: None,
            color: false,
            verbosity: Verbosity::Quiet,
            use_cargo_registry: false,
        })
        .unwrap();
        let output = std::process::Command::new(artifact.binary.unwrap())
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"dependency-ok");
    }

    #[test]
    fn builds_the_root_library_before_the_binary() {
        let fixture = Fixture::new();
        fixture.add_root_library();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_98);
        let toolchain = Toolchain::discover(None, &config).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let artifacts = build(Build {
            manifest: &manifest,
            config: &config,
            toolchain: &toolchain,
            host: &target,
            target: &target,
            host_options: &target_options,
            target_options: &target_options,
            physical_target: None,
            logical_target: None,
            rustflags: &[],
            release: false,
            test: false,
            test_name: None,
            color: false,
            verbosity: Verbosity::Quiet,
            use_cargo_registry: false,
        })
        .unwrap();
        let output = std::process::Command::new(artifacts.binary.unwrap())
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"dependency-ok");
        assert!(
            fs::read_dir(fixture.0.join("target/lorry/debug/deps"))
                .unwrap()
                .any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("libroot_bin-"))
        );
    }

    #[test]
    fn builds_a_library_only_root_package() {
        let fixture = Fixture::new();
        fs::remove_file(fixture.0.join("src/main.rs")).unwrap();
        fs::write(
            fixture.0.join("src/lib.rs"),
            "pub fn value() -> &'static str { local_dependency::VALUE }\n",
        )
        .unwrap();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_98);
        let toolchain = Toolchain::discover(None, &config).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let artifacts = build(Build {
            manifest: &manifest,
            config: &config,
            toolchain: &toolchain,
            host: &target,
            target: &target,
            host_options: &target_options,
            target_options: &target_options,
            physical_target: None,
            logical_target: None,
            rustflags: &[],
            release: false,
            test: false,
            test_name: None,
            color: false,
            verbosity: Verbosity::Quiet,
            use_cargo_registry: false,
        })
        .unwrap();
        assert!(artifacts.binary.is_none());
        assert!(artifacts.primary.is_file());
        assert!(
            artifacts
                .primary
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("libroot_bin-")
        );
    }

    #[test]
    fn executes_an_admitted_dependency_build_script_from_the_engine() {
        let fixture = Fixture::new();
        fixture.add_build_script();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_98);
        config.policy.rules.insert(
            "local-build-script".to_owned(),
            PolicyRule {
                action: PolicyAction::Allow,
                name: Some("local-dependency".to_owned()),
                version: None,
                source: Some("path".to_owned()),
                checksum: None,
                source_tree_sha256: None,
                license: Some("MIT".to_owned()),
                allow_build_script: true,
                native_tools: BTreeSet::new(),
                provenance: fixture.0.join("lorry.toml"),
            },
        );
        let toolchain = Toolchain::discover(None, &config).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let artifact = build(Build {
            manifest: &manifest,
            config: &config,
            toolchain: &toolchain,
            host: &target,
            target: &target,
            host_options: &target_options,
            target_options: &target_options,
            physical_target: None,
            logical_target: None,
            rustflags: &[],
            release: false,
            test: false,
            test_name: None,
            color: false,
            verbosity: Verbosity::Quiet,
            use_cargo_registry: false,
        })
        .unwrap();
        let output = std::process::Command::new(artifact.binary.unwrap())
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"build-script-ok");
    }

    #[test]
    fn builds_and_runs_unit_and_integration_test_harnesses() {
        let fixture = Fixture::new();
        fixture.add_test_targets();
        fixture.add_build_script();
        for relative in [
            "src/lib.rs",
            "src/main.rs",
            "tests/first.rs",
            "tests/second.rs",
        ] {
            let path = fixture.0.join(relative);
            let source = fs::read_to_string(&path).unwrap();
            fs::write(path, source.replace("dependency-ok", "build-script-ok")).unwrap();
        }
        let manifest = Manifest::load(&fixture.0).unwrap();
        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_98);
        config.policy.rules.insert(
            "local-build-script".to_owned(),
            PolicyRule {
                action: PolicyAction::Allow,
                name: Some("local-dependency".to_owned()),
                version: None,
                source: Some("path".to_owned()),
                checksum: None,
                source_tree_sha256: None,
                license: Some("MIT".to_owned()),
                allow_build_script: true,
                native_tools: BTreeSet::new(),
                provenance: fixture.0.join("lorry.toml"),
            },
        );
        let toolchain = Toolchain::discover(None, &config).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let artifacts = build(Build {
            manifest: &manifest,
            config: &config,
            toolchain: &toolchain,
            host: &target,
            target: &target,
            host_options: &target_options,
            target_options: &target_options,
            physical_target: None,
            logical_target: None,
            rustflags: &[],
            release: false,
            test: true,
            test_name: None,
            color: false,
            verbosity: Verbosity::Quiet,
            use_cargo_registry: false,
        })
        .unwrap();
        assert_eq!(artifacts.harnesses.len(), 4);
        assert!(artifacts.binary.as_ref().unwrap().is_file());
        for harness in &artifacts.harnesses {
            let status = std::process::Command::new(harness).status().unwrap();
            assert!(status.success(), "harness `{}` failed", harness.display());
        }
    }

    #[test]
    fn named_test_builds_only_the_selected_integration_harness() {
        let fixture = Fixture::new();
        fixture.add_test_targets();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_98);
        let toolchain = Toolchain::discover(None, &config).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let artifacts = build(Build {
            manifest: &manifest,
            config: &config,
            toolchain: &toolchain,
            host: &target,
            target: &target,
            host_options: &target_options,
            target_options: &target_options,
            physical_target: None,
            logical_target: None,
            rustflags: &[],
            release: false,
            test: true,
            test_name: Some("second"),
            color: false,
            verbosity: Verbosity::Quiet,
            use_cargo_registry: false,
        })
        .unwrap();
        assert_eq!(artifacts.harnesses.len(), 1);
        assert!(
            artifacts.harnesses[0]
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("second-")
        );
        assert!(
            std::process::Command::new(&artifacts.harnesses[0])
                .status()
                .unwrap()
                .success()
        );
    }

    #[test]
    fn unknown_named_test_lists_discovered_integration_targets() {
        let fixture = Fixture::new();
        fixture.add_test_targets();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_98);
        let toolchain = Toolchain::discover(None, &config).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let error = build(Build {
            manifest: &manifest,
            config: &config,
            toolchain: &toolchain,
            host: &target,
            target: &target,
            host_options: &target_options,
            target_options: &target_options,
            physical_target: None,
            logical_target: None,
            rustflags: &[],
            release: false,
            test: true,
            test_name: Some("missing"),
            color: false,
            verbosity: Verbosity::Quiet,
            use_cargo_registry: false,
        })
        .unwrap_err();
        let rendered = format!("{error:?}");
        assert!(rendered.contains("no integration-test target named `missing`"));
        assert!(rendered.contains("first, second"));
    }
}
