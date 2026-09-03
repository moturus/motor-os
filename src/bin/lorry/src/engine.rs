use crate::admission_state::CompactState;
use crate::atomic::AtomicDirectory;
use crate::bundle;
use crate::cache;
use crate::cargo_registry::CargoRegistry;
use crate::cli::{Cli, Color, Command, Verbosity};
use crate::config::{Config, PolicyLimits, TargetOptions, TargetSelector, effective_rustflags};
use crate::dependency;
use crate::diagnostic::{Error, Result};
use crate::executor;
use crate::hash::{Sha256, decode_hex, hex, sha256_file};
use crate::identity::{
    CargoUnitLto, Identity, IdentityInput, RootTargetKind, cargo_identity, root_lto,
};
use crate::manifest::{
    BinaryTarget, Edition, IntegrationTestTarget, LibraryTarget, Manifest, Strip,
};
use crate::process::{self, RustcCommand};
use crate::progress::Progress;
use crate::repository::RepositorySet;
use crate::resolver::{CompileKind, Resolution, TargetSelection, selected_root_features};
use crate::source_tree::{DEFAULT_LIMITS, Limits as TreeLimits};
use crate::toolchain::{TargetInfo, Toolchain};
use crate::unit::{CompilationPlan, PlanOptions, UnitEdgeKind, UnitKey, UnitKind};
use crate::validation::ValidationMode;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::IsTerminal;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

const MOTOR_TARGET: &str = "x86_64-unknown-motor";

pub fn execute(cli: &Cli) -> Result<i32> {
    let current = env::current_dir()
        .map_err(|error| Error::failure(format!("failed to read current directory: {error}")))?;
    let manifest = Manifest::load_selected(&current, cli.package.as_deref())?;
    let compact_state = CompactState::load(&manifest.root)?;
    let mut config = Config::load(&manifest.root)?;
    crate::trace::event("loaded manifest, admission state, and configuration");
    let toolchain = Toolchain::discover(cli.toolchain.as_deref(), &config)?;
    check_rust_version(&manifest, &toolchain)?;
    crate::trace::event("discovered rustc toolchain");
    if cli.verbosity == Verbosity::Verbose {
        eprintln!(
            "Using {} (rustc {}, Cargo {:?} compatibility)",
            toolchain.rustc.display(),
            toolchain.release,
            toolchain.compatibility
        );
    }

    let (release, command_target, validation) = match &cli.command {
        Command::Build(options) => (
            options.release,
            options.target.as_deref(),
            options.validation,
        ),
        Command::Run(options) => (
            options.build.release,
            options.build.target.as_deref(),
            options.build.validation,
        ),
        Command::Test(options) => (
            options.build.release,
            options.build.target.as_deref(),
            options.build.validation,
        ),
        _ => unreachable!("non-build command passed to engine"),
    };
    let binary_selection = match &cli.command {
        Command::Build(options) => validate_binary_selection(&manifest, options.bin.as_deref())?,
        Command::Run(_) | Command::Test(_) => None,
        _ => unreachable!(),
    };
    let run_binary = match &cli.command {
        Command::Run(options) => Some(select_run_binary(&manifest, options.build.bin.as_deref())?),
        _ => None,
    };
    let physical_target = config.selected_target(command_target)?;
    let target_info = toolchain.target_info(physical_target.as_deref())?;
    manifest.require_supported_target(&target_info)?;
    let host_info = if physical_target.is_some() {
        toolchain.target_info(None)?
    } else {
        target_info.clone()
    };
    crate::trace::event("queried rustc target configuration");
    if let Some(compact) = &compact_state {
        compact.require_context(&host_info.triple, &target_info.triple)?;
    }
    let target_matching_cfgs = matching_cfgs(&config, &target_info)?;
    let target_options = config.target_options(&target_info.triple, &target_matching_cfgs)?;
    let host_matching_cfgs = matching_cfgs(&config, &host_info)?;
    let host_options = config.target_options(&host_info.triple, &host_matching_cfgs)?;
    let rustflags = effective_rustflags(&config, &target_options)?;
    let logical_target = if physical_target.is_some() {
        physical_target.as_deref()
    } else if cfg!(target_os = "motor") {
        Some(MOTOR_TARGET)
    } else {
        None
    };
    let color = use_color(cli.color);
    crate::trace::event("resolved effective build configuration");

    let cargo = env::current_exe()
        .map_err(|error| Error::failure(format!("failed to locate Lorry executable: {error}")))?;
    let ordinary_freshness_base = (!validation.is_strict()
        && !matches!(&cli.command, Command::Test(_)))
    .then(|| {
        trusted_freshness_base(&TrustedFreshness {
            manifest: &manifest,
            compact_state: compact_state.as_ref(),
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
            use_cargo_registry: cli.use_cargo_registry,
            binary_selection,
            cargo: &cargo,
        })
    })
    .transpose()?;
    if let Some(base) = ordinary_freshness_base
        && let Some(artifacts) = restore_fresh_profile(
            &profile_destination(&manifest, physical_target.as_deref(), release),
            &manifest.root,
            base,
            validation,
        )
    {
        crate::trace::event("accepted fresh root profile before dependency admission");
        report_finished(release, cli.verbosity, validation, &artifacts)?;
        return match &cli.command {
            Command::Build(_) => Ok(0),
            Command::Run(options) => {
                let artifact = artifacts.binaries.get(run_binary.unwrap()).ok_or_else(|| {
                    Error::failure("selected binary is absent from the fresh build profile")
                })?;
                crate::trace::event("starting program");
                let status = run_artifact(
                    artifact,
                    &options.arguments,
                    &manifest.root,
                    physical_target.as_deref(),
                    &target_options,
                    cli.verbosity,
                )?;
                crate::trace::event("program exited");
                Ok(status)
            }
            _ => unreachable!("only build and run use the ordinary freshness fast path"),
        };
    }

    let progress = Progress::new(cli.verbosity != Verbosity::Quiet);
    progress.report("Verifying dependency state")?;
    // One registry source serves both admission verification and prepare, so
    // repository objects verified during admission are not re-hashed when the
    // build prepares its dependency graph.
    let admission_staging = AtomicDirectory::new(&env::temp_dir(), "lorry-admission")?;
    let repositories = if cli.use_cargo_registry {
        None
    } else {
        Some(RepositorySet::open_with_validation(
            &config.repositories,
            repository_tree_limits(&config.policy.limits)?,
            config.policy.limits.max_package_bytes,
            validation,
        )?)
    };
    let cargo_registry = if cli.use_cargo_registry {
        Some(CargoRegistry::discover_with_validation(
            admission_staging.path(),
            &config.policy.limits,
            validation,
            Some(&artifact_root(&manifest).join(".cargo-evidence")),
        )?)
    } else {
        None
    };
    let source = match (&repositories, &cargo_registry) {
        (Some(repositories), None) => dependency::RegistrySource::Lorry(repositories),
        (None, Some(registry)) => dependency::RegistrySource::Cargo(registry),
        _ => unreachable!("exactly one registry source is constructed"),
    };
    let direct = crate::git::load_locked_dependencies(&manifest, &config.policy.limits)?;
    crate::trace::event("opened dependency source");
    let verified_resolution = if let Some(compact) = &compact_state {
        let options = dependency::resolver_options(&manifest, &config, &toolchain)?;
        let verified = dependency::verify_compact_admission(
            &dependency::ReviewInputs {
                manifest: &manifest,
                config: &config,
                source,
                toolchain: &toolchain,
                options: &options,
                staging_parent: admission_staging.path(),
                direct: Some(&direct),
                prepare_context: Some(crate::admission_state::Context {
                    host: host_info.triple.clone(),
                    target: target_info.triple.clone(),
                }),
            },
            compact,
        )?;
        let (review, resolution) = verified.into_parts();
        review.apply_to_policy(&mut config.policy, &manifest.root)?;
        resolution
    } else {
        None
    };
    crate::trace::event("verified dependency admission");
    let global_cache_root = config.cache_directory()?;

    match &cli.command {
        Command::Build(_) => {
            build(Build {
                manifest: &manifest,
                global_cache_root: &global_cache_root,
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
                source: Some((source, &direct, verified_resolution)),
                bundle: false,
                validation,
                ordinary_freshness_base,
                binary_selection,
            })?;
            Ok(0)
        }
        Command::Run(options) => {
            let artifacts = build(Build {
                manifest: &manifest,
                global_cache_root: &global_cache_root,
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
                source: Some((source, &direct, verified_resolution)),
                bundle: false,
                validation,
                ordinary_freshness_base,
                binary_selection: None,
            })?;
            let artifact = artifacts.binaries.get(run_binary.unwrap()).ok_or_else(|| {
                Error::failure("selected binary is absent from the completed build")
            })?;
            crate::trace::event("starting program");
            let status = run_artifact(
                artifact,
                &options.arguments,
                &manifest.root,
                physical_target.as_deref(),
                &target_options,
                cli.verbosity,
            )?;
            crate::trace::event("program exited");
            Ok(status)
        }
        Command::Test(options) => {
            if cli.verbosity != Verbosity::Quiet {
                eprintln!("note: documentation tests are not supported");
            }
            let artifacts = build(Build {
                manifest: &manifest,
                global_cache_root: &global_cache_root,
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
                source: Some((source, &direct, verified_resolution)),
                bundle: options.bundle,
                validation,
                ordinary_freshness_base,
                binary_selection: None,
            })?;
            if options.no_run {
                if let Some(bundle) = &artifacts.bundle {
                    println!("{}", bundle.display());
                } else {
                    for harness in &artifacts.harnesses {
                        println!("{}", harness.display());
                    }
                }
                return Ok(0);
            }
            if let Some(bundle) = &artifacts.bundle {
                return run_artifact(
                    bundle,
                    &options.arguments,
                    &manifest.root,
                    physical_target.as_deref(),
                    &target_options,
                    cli.verbosity,
                );
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
    global_cache_root: &'a Path,
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
    /// Dependency sources shared with admission verification so verified
    /// repository and direct-Git objects are not re-hashed during prepare.
    source: Option<(
        dependency::RegistrySource<'a>,
        &'a crate::git::DirectCatalog,
        Option<crate::resolver::Resolution>,
    )>,
    bundle: bool,
    validation: ValidationMode,
    ordinary_freshness_base: Option<[u8; 32]>,
    /// `None` builds every binary; `Some` builds exactly that target.
    binary_selection: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BuildArtifacts {
    primary: PathBuf,
    binaries: BTreeMap<String, PathBuf>,
    harnesses: Vec<PathBuf>,
    bundle: Option<PathBuf>,
}

struct IncrementalRoots {
    host: PathBuf,
    target: PathBuf,
}

fn incremental_roots(build: &Build<'_>) -> IncrementalRoots {
    let root = artifact_root(build.manifest).join(".incremental");
    IncrementalRoots {
        host: root.join(&build.host.triple),
        target: root.join(&build.target.triple),
    }
}

pub(crate) fn artifact_root(manifest: &Manifest) -> PathBuf {
    artifact_root_in(manifest, &manifest.workspace_root.join("target"))
}

pub(crate) fn artifact_root_in(manifest: &Manifest, target_directory: &Path) -> PathBuf {
    let root = target_directory.join("lorry");
    if manifest.workspace_root == manifest.root {
        root
    } else {
        root.join("packages").join(&manifest.name)
    }
}

fn profile_destination(
    manifest: &Manifest,
    physical_target: Option<&str>,
    release: bool,
) -> PathBuf {
    let mut profile = artifact_root(manifest);
    if let Some(target) = physical_target {
        profile.push(target);
    }
    profile.push(if release { "release" } else { "debug" });
    profile
}

fn validate_binary_selection<'a>(
    manifest: &'a Manifest,
    requested: Option<&'a str>,
) -> Result<Option<&'a str>> {
    let Some(name) = requested else {
        return Ok(None);
    };
    if manifest.binaries.iter().any(|target| target.name == name) {
        Ok(Some(name))
    } else {
        Err(unknown_binary(manifest, name))
    }
}

fn select_run_binary<'a>(manifest: &'a Manifest, requested: Option<&'a str>) -> Result<&'a str> {
    if let Some(name) = validate_binary_selection(manifest, requested)? {
        return Ok(name);
    }
    if let Some(name) = manifest.default_run.as_deref() {
        return Ok(name);
    }
    match manifest.binaries.as_slice() {
        [target] => Ok(&target.name),
        [] => Err(Error::failure(format!(
            "package `{}` has no binary target to run",
            manifest.name
        ))),
        _ => Err(Error::failure(format!(
            "package `{}` has more than one binary target",
            manifest.name
        ))
        .with_help("use `--bin NAME` or set `package.default-run`")),
    }
}

fn unknown_binary(manifest: &Manifest, name: &str) -> Error {
    let available = manifest
        .binaries
        .iter()
        .map(|target| target.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    Error::failure(format!("no binary target named `{name}`")).with_help(if available.is_empty() {
        "this package has no binary targets".to_owned()
    } else {
        format!("available binary targets: {available}")
    })
}

fn build(mut build: Build<'_>) -> Result<BuildArtifacts> {
    if let Some(name) = build.test_name
        && !build
            .manifest
            .integration_tests
            .iter()
            .any(|target| target.name == name)
    {
        return Err(unknown_integration_test(build.manifest, name));
    }
    let target_root = artifact_root(build.manifest);
    let incremental = incremental_roots(&build);
    if !build.release {
        fs::create_dir_all(&incremental.host).map_err(|error| {
            Error::failure(format!(
                "failed to create incremental directory `{}`: {error}",
                incremental.host.display()
            ))
        })?;
        fs::create_dir_all(&incremental.target).map_err(|error| {
            Error::failure(format!(
                "failed to create incremental directory `{}`: {error}",
                incremental.target.display()
            ))
        })?;
    }
    let profile_parent = match build.physical_target {
        Some(target) => target_root.join(target),
        None => target_root.clone(),
    };
    let destination = profile_destination(build.manifest, build.physical_target, build.release);
    let staging = AtomicDirectory::new_compact(&profile_parent)?;
    crate::trace::event("created build staging directory");

    Progress::new(build.verbosity != Verbosity::Quiet).report("Preparing dependency graph")?;
    let resolver_options =
        dependency::resolver_options(build.manifest, build.config, build.toolchain)?;
    let selection = TargetSelection {
        target_triple: &build.target.triple,
        target_cfg: &build.target.cfg,
        host_triple: &build.host.triple,
        host_cfg: &build.host.cfg,
    };
    let prepared = if let Some((source, direct, verified_resolution)) = build.source.take() {
        dependency::prepare_locked_source(
            build.manifest,
            build.config,
            dependency::LockedSource {
                registry: source,
                direct,
                verified_resolution,
            },
            &resolver_options,
            selection,
            staging.path(),
        )?
    } else if build.use_cargo_registry {
        let registry = CargoRegistry::discover_with_validation(
            staging.path(),
            &build.config.policy.limits,
            build.validation,
            Some(&target_root.join(".cargo-evidence")),
        )?;
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
    crate::trace::event(format_args!(
        "prepared and verified {} dependency packages",
        prepared.packages.len()
    ));
    let manifests = prepared
        .packages
        .iter()
        .map(|(key, package)| (key.clone(), package.manifest.clone()))
        .collect::<BTreeMap<_, _>>();
    let cargo = env::current_exe()
        .map_err(|error| Error::failure(format!("failed to locate Lorry executable: {error}")))?;
    let freshness_base = (!build.test)
        .then(|| freshness_base(&build, &prepared, &cargo))
        .transpose()?;
    if let Some(base) = freshness_base {
        crate::trace::event("fingerprinted build inputs");
        if let Some(artifacts) =
            restore_fresh_profile(&destination, &build.manifest.root, base, build.validation)
        {
            crate::trace::event("validated fresh root profile");
            finish_build(&build, &artifacts)?;
            crate::trace::event("reported build result");
            return Ok(artifacts);
        }
        crate::trace::event("root profile requires rebuilding");
    }
    let dependency_plan = |test_profile| {
        prepared.dependency_plan(&PlanOptions {
            workspace_root: &build.manifest.workspace_root,
            release: build.release,
            test_profile,
            panic_abort: build.manifest.panic_abort(build.release),
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
    let source_limits = repository_tree_limits(&build.config.policy.limits)?;
    let cache = cache::BuildCaches::new(
        build.global_cache_root,
        &target_root.join(".cache"),
        &cache::Options {
            cargo: &cargo,
            toolchain: build.toolchain,
            host: build.host,
            target: build.target,
            host_linker: build.host_options.linker.as_deref(),
            target_linker: build.target_options.linker.as_deref(),
            root_manifest: build.manifest,
            source_limits,
            validation: build.validation,
        },
    )?;
    crate::trace::event("initialized dependency build cache");
    let bundle_layout = if build.test && build.bundle {
        Some(bundle::Layout::new(&bundle::LayoutOptions {
            extraction_root: build.config.test.extraction_root(&build.target.triple),
            package_name: &build.manifest.name,
            package_root: &build.manifest.root,
            lorry: &cargo,
            toolchain: build.toolchain,
            target: build.target,
            release: build.release,
            test_name: build.test_name,
            source_limits,
        })?)
    } else {
        None
    };
    let executor_options = executor::Options {
        cargo: &cargo,
        workspace_root: &build.manifest.workspace_root,
        toolchain: build.toolchain,
        host: build.host,
        target: build.target,
        host_profile: &host_profile,
        target_profile: staging.path(),
        host_incremental: &incremental.host,
        target_incremental: &incremental.target,
        physical_target: build.physical_target,
        host_linker: build.host_options.linker.as_deref(),
        target_linker: build.target_options.linker.as_deref(),
        release: build.release,
        quiet: build.verbosity == Verbosity::Quiet,
        verbose: build.verbosity == Verbosity::Verbose,
        color: build.color,
        build_script_timeout: Duration::from_secs(build.config.policy.limits.build_script_seconds),
        build_script_output_bytes: build.config.policy.limits.build_script_output_bytes,
        out_dir_limits: source_limits,
        cache: Some(&cache),
        admission: &prepared.admission,
        native_tools: &build.config.native_tools,
        jobs: compile_jobs(),
    };
    let selected_integration =
        build.test && (build.test_name.is_some() || !build.manifest.integration_tests.is_empty());
    let needs_normal_plan =
        !build.test || (selected_integration && !build.manifest.binaries.is_empty());
    let normal = if needs_normal_plan {
        let plan = dependency_plan(false)?;
        let outputs = executor::execute(&plan, &manifests, &executor_options)?;
        let dependencies = root_dependencies(&prepared.resolution, &plan, &outputs)?;
        crate::trace::event(format_args!(
            "executed {} normal dependency units",
            plan.units.len()
        ));
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
        crate::trace::event(format_args!(
            "executed {} test dependency units",
            test_plan.units.len()
        ));
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
    if build.validation.is_strict() {
        prepared.revalidate_cargo_registry_sources(repository_tree_limits(
            &build.config.policy.limits,
        )?)?;
        crate::trace::event("revalidated dependency sources");
    }
    let compiled = if build.test {
        compile_test_targets(
            &build,
            staging.path(),
            &host_profile,
            normal_dependencies,
            test_dependencies.as_ref().unwrap(),
            &TestOutput {
                destination: &destination,
                target_root: &target_root,
                bundle_layout: bundle_layout.as_ref(),
            },
        )?
    } else {
        compile_root_targets(&build, staging.path(), &host_profile, normal_dependencies)?
    };
    crate::trace::event("compiled root targets");

    if let Some(base) = freshness_base {
        write_fresh_profile(
            staging.path(),
            &build.manifest.root,
            base,
            &compiled,
            &local_source_roots(&prepared.resolution),
            build.validation,
        )?;
        crate::trace::event("wrote root freshness record");
    }

    drop(prepared);
    if build.physical_target.is_some() {
        match fs::remove_dir_all(&host_profile) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(Error::failure(format!(
                    "failed to remove temporary host dependency output `{}`: {error}",
                    host_profile.display()
                )));
            }
        }
    }

    let relative_primary = compiled
        .primary
        .strip_prefix(staging.path())
        .unwrap()
        .to_path_buf();
    let relative_binaries = compiled
        .binaries
        .iter()
        .map(|(name, artifact)| {
            (
                name.clone(),
                artifact.strip_prefix(staging.path()).unwrap().to_path_buf(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let relative_harnesses = compiled
        .harnesses
        .iter()
        .map(|artifact| artifact.strip_prefix(staging.path()).unwrap().to_path_buf())
        .collect::<Vec<_>>();
    let relative_bundle = compiled
        .bundle
        .as_ref()
        .map(|artifact| artifact.strip_prefix(staging.path()).unwrap().to_path_buf());
    staging.commit(&destination)?;
    let artifacts = BuildArtifacts {
        primary: destination.join(relative_primary),
        binaries: relative_binaries
            .into_iter()
            .map(|(name, artifact)| (name, destination.join(artifact)))
            .collect(),
        harnesses: relative_harnesses
            .into_iter()
            .map(|artifact| destination.join(artifact))
            .collect(),
        bundle: relative_bundle.map(|artifact| destination.join(artifact)),
    };

    crate::trace::event("published build profile");
    finish_build(&build, &artifacts)?;
    crate::trace::event("reported build result");
    Ok(artifacts)
}

fn finish_build(build: &Build<'_>, artifacts: &BuildArtifacts) -> Result<()> {
    report_finished(build.release, build.verbosity, build.validation, artifacts)
}

fn report_finished(
    release: bool,
    verbosity: Verbosity,
    validation: ValidationMode,
    artifacts: &BuildArtifacts,
) -> Result<()> {
    if verbosity != Verbosity::Quiet {
        eprintln!(
            "Finished `{}` profile",
            if release { "release" } else { "dev" }
        );
    }
    if verbosity == Verbosity::Verbose && validation.is_strict() {
        eprintln!(
            "Artifact {} sha256={}",
            artifacts.primary.display(),
            hex(&sha256_file(&artifacts.primary)?)
        );
    }
    Ok(())
}

const FRESH_PROFILE_FILE: &str = ".lorry-fresh-v3";
const MAX_FRESH_PROFILE_BYTES: u64 = 64 * 1024;
const MAX_DEP_INFO_BYTES: u64 = 16 * 1024 * 1024;

// The unit cache handles dependency compilation. This record additionally
// proves that the installed root artifact can be reused as one complete unit.
struct FreshArtifact {
    path: PathBuf,
    sha256: [u8; 32],
}

struct FreshProfile {
    base: [u8; 32],
    inputs: [u8; 32],
    primary: FreshArtifact,
    binaries: BTreeMap<String, FreshArtifact>,
    local_roots: Vec<PathBuf>,
    dep_info: Vec<PathBuf>,
}

struct TrustedFreshness<'a> {
    manifest: &'a Manifest,
    compact_state: Option<&'a CompactState>,
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
    use_cargo_registry: bool,
    binary_selection: Option<&'a str>,
    cargo: &'a Path,
}

fn trusted_freshness_base(inputs: &TrustedFreshness<'_>) -> Result<[u8; 32]> {
    let mut digest = FreshDigest::new();
    digest.bytes("schema", b"lorry-trusted-root-profile-v1");
    digest.debug("manifest", inputs.manifest);
    digest.debug("compact-state", &inputs.compact_state);
    digest.debug("config", inputs.config);
    digest.debug("toolchain", inputs.toolchain);
    digest.debug("host", inputs.host);
    digest.debug("target", inputs.target);
    digest.debug("host-options", inputs.host_options);
    digest.debug("target-options", inputs.target_options);
    digest.debug("physical-target", &inputs.physical_target);
    digest.debug("logical-target", &inputs.logical_target);
    digest.debug("rustflags", &inputs.rustflags);
    digest.debug("release", &inputs.release);
    digest.debug("cargo-registry", &inputs.use_cargo_registry);
    digest.debug("binary-selection", &inputs.binary_selection);
    digest.metadata("lorry", inputs.cargo)?;
    digest.metadata("rustc", &inputs.toolchain.rustc)?;
    for (name, value) in env::vars_os().collect::<BTreeMap<_, _>>() {
        digest.os("environment-name", &name);
        digest.os("environment-value", &value);
    }
    for path in [
        inputs.host_options.linker.as_deref(),
        inputs.target_options.linker.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        digest.metadata("linker", path)?;
    }
    for tool in inputs.config.native_tools.values() {
        if let Some(path) = tool.program.as_deref() {
            digest.metadata("native-tool", path)?;
        }
    }
    Ok(digest.finish())
}

fn freshness_base(
    build: &Build<'_>,
    prepared: &dependency::PreparedGraph,
    cargo: &Path,
) -> Result<[u8; 32]> {
    if !build.validation.is_strict()
        && let Some(base) = build.ordinary_freshness_base
    {
        return Ok(base);
    }
    let mut digest = FreshDigest::new();
    digest.bytes("schema", b"lorry-root-profile-v1");
    digest.debug("manifest", build.manifest);
    digest.debug("config", build.config);
    digest.debug("toolchain", build.toolchain);
    digest.debug("host", build.host);
    digest.debug("target", build.target);
    digest.debug("host-options", build.host_options);
    digest.debug("target-options", build.target_options);
    digest.debug("resolution", &prepared.resolution);
    digest.debug("admission", &prepared.admission);
    digest.debug("physical-target", &build.physical_target);
    digest.debug("logical-target", &build.logical_target);
    digest.debug("rustflags", &build.rustflags);
    digest.debug("release", &build.release);
    digest.debug("cargo-registry", &build.use_cargo_registry);
    digest.debug("bundle", &build.bundle);
    digest.debug("binary-selection", &build.binary_selection);
    if build.validation.is_strict() {
        digest.file("lorry", cargo)?;
        digest.file("rustc", &build.toolchain.rustc)?;
        digest.file("manifest-file", &build.manifest.path)?;
        let lock = build.manifest.workspace_root.join("Cargo.lock");
        if lock.is_file() {
            digest.file("lock-file", &lock)?;
        } else {
            digest.bytes("lock-file", b"missing");
        }
    } else {
        digest.os("lorry-path", cargo.as_os_str());
        digest.os("rustc-path", build.toolchain.rustc.as_os_str());
    }
    for (key, package) in &prepared.packages {
        digest.debug("dependency-key", key);
        digest.bytes("dependency-source", &package.evidence.source_tree_sha256);
        digest.debug("dependency-license", &package.evidence.license);
        digest.debug("dependency-build-script", &package.evidence.build_script);
        digest.debug("dependency-archive-bytes", &package.evidence.archive_bytes);
        digest.debug(
            "dependency-extracted-bytes",
            &package.evidence.extracted_bytes,
        );
        digest.debug("dependency-file-count", &package.evidence.file_count);
    }
    for (name, value) in env::vars_os().collect::<BTreeMap<_, _>>() {
        digest.os("environment-name", &name);
        digest.os("environment-value", &value);
    }
    for path in [
        build.host_options.linker.as_deref(),
        build.target_options.linker.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if build.validation.is_strict() && path.is_file() {
            digest.file("linker", path)?;
        } else {
            digest.os("linker-path", path.as_os_str());
        }
    }
    for tool in build.config.native_tools.values() {
        if let Some(path) = tool.program.as_deref() {
            if build.validation.is_strict() && path.is_file() {
                digest.file("native-tool", path)?;
            } else {
                digest.os("native-tool-path", path.as_os_str());
            }
        }
    }
    Ok(digest.finish())
}

fn restore_fresh_profile(
    profile: &Path,
    package_root: &Path,
    base: [u8; 32],
    validation: ValidationMode,
) -> Option<BuildArtifacts> {
    let record = read_fresh_profile(profile)?;
    if record.base != base {
        return None;
    }
    let primary = profile.join(record.primary.path);
    let binaries = record
        .binaries
        .iter()
        .map(|(name, artifact)| (name.clone(), profile.join(&artifact.path)))
        .collect::<BTreeMap<_, _>>();
    let valid = if validation.is_strict() {
        fresh_input_digest(profile, package_root, base, &record.dep_info).ok()
            == Some(record.inputs)
            && sha256_regular(&primary).ok() == Some(record.primary.sha256)
            && binaries.iter().all(|(name, path)| {
                sha256_regular(path).ok()
                    == record.binaries.get(name).map(|artifact| artifact.sha256)
            })
    } else {
        trusted_input_digest(profile, package_root, &record.dep_info, &record.local_roots).ok()
            == Some(record.inputs)
            && primary.is_file()
            && binaries.values().all(|path| path.is_file())
    };
    if !valid {
        return None;
    }
    Some(BuildArtifacts {
        primary,
        binaries,
        harnesses: Vec::new(),
        bundle: None,
    })
}

fn write_fresh_profile(
    profile: &Path,
    package_root: &Path,
    base: [u8; 32],
    artifacts: &StagedArtifacts,
    local_roots: &[PathBuf],
    validation: ValidationMode,
) -> Result<()> {
    let primary = relative_profile_path(profile, &artifacts.primary)?;
    let mut dep_info = artifacts
        .dep_info
        .iter()
        .map(|path| relative_profile_path(profile, path))
        .collect::<Result<Vec<_>>>()?;
    dep_info.sort();
    let inputs = if validation.is_strict() {
        fresh_input_digest(profile, package_root, base, &dep_info)?
    } else {
        trusted_input_digest(profile, package_root, &dep_info, local_roots)?
    };
    let artifact_sha256 = |path: &Path| {
        if validation.is_strict() {
            sha256_regular(path)
        } else {
            Ok([0; 32])
        }
    };
    let primary_sha256 = artifact_sha256(&artifacts.primary)?;
    let mut document = format!(
        "lorry-fresh-v3\nbase={}\ninputs={}\nprimary={}\t{}\n",
        hex(&base),
        hex(&inputs),
        hex(&primary_sha256),
        primary.display(),
    );
    for (name, path) in &artifacts.binaries {
        let relative = relative_profile_path(profile, path)?;
        document.push_str(&format!(
            "binary={name}\t{}\t{}\n",
            hex(&artifact_sha256(path)?),
            relative.display()
        ));
    }
    for root in local_roots {
        let Some(root) = root.to_str() else {
            return Ok(());
        };
        document.push_str(&format!("local-root={}\n", hex(root.as_bytes())));
    }
    for path in dep_info {
        document.push_str(&format!("dep-info={}\n", path.display()));
    }
    fs::write(profile.join(FRESH_PROFILE_FILE), document).map_err(|error| {
        Error::failure(format!(
            "failed to write build freshness record `{}`: {error}",
            profile.join(FRESH_PROFILE_FILE).display()
        ))
    })
}

fn read_fresh_profile(profile: &Path) -> Option<FreshProfile> {
    let path = profile.join(FRESH_PROFILE_FILE);
    let metadata = fs::symlink_metadata(&path).ok()?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_FRESH_PROFILE_BYTES {
        return None;
    }
    let document = String::from_utf8(fs::read(path).ok()?).ok()?;
    let mut lines = document.lines();
    (lines.next()? == "lorry-fresh-v3").then_some(())?;
    let base = decode_hex(lines.next()?.strip_prefix("base=")?).ok()?;
    let inputs = decode_hex(lines.next()?.strip_prefix("inputs=")?).ok()?;
    let primary = parse_fresh_artifact(lines.next()?.strip_prefix("primary=")?)?;
    let mut binaries = BTreeMap::new();
    let mut local_roots = Vec::new();
    let mut dep_info = Vec::new();
    for line in lines {
        if let Some(value) = line.strip_prefix("binary=") {
            let (name, artifact) = value.split_once('\t')?;
            if binaries
                .insert(name.to_owned(), parse_fresh_artifact(artifact)?)
                .is_some()
            {
                return None;
            }
        } else if let Some(value) = line.strip_prefix("local-root=") {
            local_roots.push(PathBuf::from(String::from_utf8(decode_bytes(value)?).ok()?));
        } else {
            dep_info.push(safe_profile_path(line.strip_prefix("dep-info=")?)?);
        }
    }
    (!dep_info.is_empty()).then_some(FreshProfile {
        base,
        inputs,
        primary,
        binaries,
        local_roots,
        dep_info,
    })
}

fn decode_bytes(value: &str) -> Option<Vec<u8>> {
    value.len().is_multiple_of(2).then_some(())?;
    (0..value.len())
        .step_by(2)
        .map(|index| {
            let high = (value.as_bytes()[index] as char).to_digit(16)?;
            let low = (value.as_bytes()[index + 1] as char).to_digit(16)?;
            Some(((high << 4) | low) as u8)
        })
        .collect()
}

fn parse_fresh_artifact(value: &str) -> Option<FreshArtifact> {
    let (sha256, path) = value.split_once('\t')?;
    Some(FreshArtifact {
        path: safe_profile_path(path)?,
        sha256: decode_hex(sha256).ok()?,
    })
}

fn safe_profile_path(value: &str) -> Option<PathBuf> {
    let path = PathBuf::from(value);
    (!value.is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_))))
    .then_some(path)
}

fn relative_profile_path(profile: &Path, path: &Path) -> Result<PathBuf> {
    let relative = path.strip_prefix(profile).map_err(|_| {
        Error::failure(format!(
            "build artifact `{}` is outside profile `{}`",
            path.display(),
            profile.display()
        ))
    })?;
    safe_profile_path(&relative.to_string_lossy()).ok_or_else(|| {
        Error::failure(format!(
            "build artifact has unsafe relative path `{}`",
            relative.display()
        ))
    })
}

fn fresh_input_digest(
    profile: &Path,
    package_root: &Path,
    base: [u8; 32],
    dep_info: &[PathBuf],
) -> Result<[u8; 32]> {
    let mut digest = FreshDigest::new();
    digest.bytes("base", &base);
    let root = fs::canonicalize(package_root).map_err(|error| {
        Error::failure(format!(
            "failed to resolve package root `{}`: {error}",
            package_root.display()
        ))
    })?;
    let mut sources = BTreeMap::new();
    for relative in dep_info {
        let path = profile.join(relative);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            Error::failure(format!(
                "failed to inspect rustc dep-info `{}`: {error}",
                path.display()
            ))
        })?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_DEP_INFO_BYTES {
            return Err(Error::failure(format!(
                "invalid rustc dep-info `{}`",
                path.display()
            )));
        }
        let bytes = fs::read(&path).map_err(|error| {
            Error::failure(format!(
                "failed to read rustc dep-info `{}`: {error}",
                path.display()
            ))
        })?;
        digest.bytes("dep-info", &bytes);
        // rustc's dep-info is the authoritative list for include!, modules,
        // and other root source inputs that are not named in Cargo.toml.
        for source in executor::parse_dep_info_paths(&bytes)? {
            let source = if source.is_absolute() {
                source
            } else {
                root.join(source)
            };
            let source = fs::canonicalize(&source).map_err(|error| {
                Error::failure(format!(
                    "failed to resolve root source input `{}`: {error}",
                    source.display()
                ))
            })?;
            sources.insert(source.clone(), sha256_regular(&source)?);
        }
    }
    for (path, sha256) in sources {
        digest.os("source-path", path.as_os_str());
        digest.bytes("source", &sha256);
    }
    Ok(digest.finish())
}

fn trusted_input_digest(
    profile: &Path,
    package_root: &Path,
    dep_info: &[PathBuf],
    local_roots: &[PathBuf],
) -> Result<[u8; 32]> {
    let root = fs::canonicalize(package_root).map_err(|error| {
        Error::failure(format!(
            "failed to resolve package root `{}`: {error}",
            package_root.display()
        ))
    })?;
    let mut sources = BTreeMap::new();
    for relative in dep_info {
        let path = profile.join(relative);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            Error::failure(format!(
                "failed to inspect rustc dep-info `{}`: {error}",
                path.display()
            ))
        })?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_DEP_INFO_BYTES {
            return Err(Error::failure(format!(
                "invalid rustc dep-info `{}`",
                path.display()
            )));
        }
        let bytes = fs::read(&path).map_err(|error| {
            Error::failure(format!(
                "failed to read rustc dep-info `{}`: {error}",
                path.display()
            ))
        })?;
        for source in executor::parse_dep_info_paths(&bytes)? {
            let source = if source.is_absolute() {
                source
            } else {
                root.join(source)
            };
            let source = fs::canonicalize(&source).map_err(|error| {
                Error::failure(format!(
                    "failed to resolve root source input `{}`: {error}",
                    source.display()
                ))
            })?;
            let metadata = fs::symlink_metadata(&source).map_err(|error| {
                Error::failure(format!(
                    "failed to inspect root source input `{}`: {error}",
                    source.display()
                ))
            })?;
            if !metadata.file_type().is_file() {
                return Err(Error::failure(format!(
                    "expected a regular file at `{}`",
                    source.display()
                )));
            }
            let modified = metadata.modified().map_err(|error| {
                Error::failure(format!(
                    "failed to read modification time for `{}`: {error}",
                    source.display()
                ))
            })?;
            let modified = modified.duration_since(UNIX_EPOCH).map_err(|_| {
                Error::failure(format!(
                    "modification time for `{}` predates the Unix epoch",
                    source.display()
                ))
            })?;
            sources.insert(source, (metadata.len(), modified));
        }
    }
    let mut digest = FreshDigest::new();
    for (path, (length, modified)) in sources {
        digest.os("source-path", path.as_os_str());
        digest.bytes("source-length", &length.to_le_bytes());
        digest.bytes("source-mtime-secs", &modified.as_secs().to_le_bytes());
        digest.bytes("source-mtime-nanos", &modified.subsec_nanos().to_le_bytes());
    }
    for root in local_roots {
        metadata_tree_digest(root, &mut digest)?;
    }
    Ok(digest.finish())
}

fn local_source_roots(resolution: &Resolution) -> Vec<PathBuf> {
    let mut roots = resolution
        .packages
        .iter()
        .filter_map(|package| match &package.source {
            crate::resolver::ResolvedSource::Path { physical_root, .. } => {
                Some(physical_root.clone())
            }
            crate::resolver::ResolvedSource::Git { physical_root, .. } => {
                Some(physical_root.clone())
            }
            crate::resolver::ResolvedSource::CratesIo { .. } => None,
        })
        .collect::<Vec<_>>();
    roots.sort();
    roots.dedup();
    roots
}

fn metadata_tree_digest(root: &Path, digest: &mut FreshDigest) -> Result<()> {
    let metadata = fs::symlink_metadata(root).map_err(|error| {
        Error::failure(format!(
            "failed to inspect local source root `{}`: {error}",
            root.display()
        ))
    })?;
    if !metadata.file_type().is_dir() {
        return Err(Error::failure(format!(
            "local source root `{}` is not a directory",
            root.display()
        )));
    }
    digest.os("local-root", root.as_os_str());
    let mut pending = vec![root.to_owned()];
    let mut entries = 0_usize;
    while let Some(directory) = pending.pop() {
        let mut children = fs::read_dir(&directory)
            .map_err(|error| {
                Error::failure(format!(
                    "failed to read local source directory `{}`: {error}",
                    directory.display()
                ))
            })?
            .map(|entry| {
                entry.map(|entry| entry.path()).map_err(|error| {
                    Error::failure(format!(
                        "failed to read an entry in local source directory `{}`: {error}",
                        directory.display()
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        children.sort();
        for path in children.into_iter().rev() {
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                Error::failure(format!(
                    "failed to inspect local source input `{}`: {error}",
                    path.display()
                ))
            })?;
            let name = path.file_name().and_then(OsStr::to_str).ok_or_else(|| {
                Error::failure(format!(
                    "local source path is not valid UTF-8: `{}`",
                    path.display()
                ))
            })?;
            if name == ".git" || (name == "target" && metadata.file_type().is_dir()) {
                continue;
            }
            entries += 1;
            if entries > DEFAULT_LIMITS.max_entries {
                return Err(Error::failure(format!(
                    "local source tree `{}` exceeds the entry-count limit of {}",
                    root.display(),
                    DEFAULT_LIMITS.max_entries
                )));
            }
            if metadata.file_type().is_symlink() {
                return Err(Error::failure(format!(
                    "local source input `{}` is a symbolic link",
                    path.display()
                )));
            }
            let relative = path.strip_prefix(root).expect("walk remains below root");
            digest.os("local-path", relative.as_os_str());
            if metadata.file_type().is_dir() {
                digest.bytes("local-kind", b"directory");
                pending.push(path);
            } else if metadata.file_type().is_file() {
                digest.bytes("local-kind", b"file");
                digest.bytes("local-length", &metadata.len().to_le_bytes());
                metadata_time(&path, &metadata, digest)?;
            } else {
                return Err(Error::failure(format!(
                    "local source input `{}` is not a regular file or directory",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

fn metadata_time(path: &Path, metadata: &fs::Metadata, digest: &mut FreshDigest) -> Result<()> {
    let modified = metadata.modified().map_err(|error| {
        Error::failure(format!(
            "failed to read modification time for `{}`: {error}",
            path.display()
        ))
    })?;
    let modified = modified.duration_since(UNIX_EPOCH).map_err(|_| {
        Error::failure(format!(
            "modification time for `{}` predates the Unix epoch",
            path.display()
        ))
    })?;
    digest.bytes("mtime-secs", &modified.as_secs().to_le_bytes());
    digest.bytes("mtime-nanos", &modified.subsec_nanos().to_le_bytes());
    Ok(())
}

fn sha256_regular(path: &Path) -> Result<[u8; 32]> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Error::failure(format!("failed to inspect `{}`: {error}", path.display()))
    })?;
    if !metadata.file_type().is_file() {
        return Err(Error::failure(format!(
            "expected a regular file at `{}`",
            path.display()
        )));
    }
    sha256_file(path)
}

struct FreshDigest(Sha256);

impl FreshDigest {
    fn new() -> Self {
        Self(Sha256::new())
    }

    fn bytes(&mut self, name: &str, value: &[u8]) {
        for field in [name.as_bytes(), value] {
            self.0.update(&(field.len() as u64).to_le_bytes());
            self.0.update(field);
        }
    }

    fn os(&mut self, name: &str, value: &OsStr) {
        self.bytes(name, value.as_encoded_bytes());
    }

    fn debug(&mut self, name: &str, value: &impl std::fmt::Debug) {
        self.bytes(name, format!("{value:?}").as_bytes());
    }

    fn file(&mut self, name: &str, path: &Path) -> Result<()> {
        self.os(&format!("{name}-path"), path.as_os_str());
        self.bytes(name, &sha256_regular(path)?);
        Ok(())
    }

    fn metadata(&mut self, name: &str, path: &Path) -> Result<()> {
        let metadata = fs::metadata(path).map_err(|error| {
            Error::failure(format!("failed to inspect `{}`: {error}", path.display()))
        })?;
        let modified = metadata.modified().map_err(|error| {
            Error::failure(format!(
                "failed to read modification time for `{}`: {error}",
                path.display()
            ))
        })?;
        let modified = modified.duration_since(UNIX_EPOCH).map_err(|_| {
            Error::failure(format!(
                "modification time for `{}` predates the Unix epoch",
                path.display()
            ))
        })?;
        self.os(&format!("{name}-path"), path.as_os_str());
        self.bytes(&format!("{name}-length"), &metadata.len().to_le_bytes());
        self.bytes(
            &format!("{name}-mtime-secs"),
            &modified.as_secs().to_le_bytes(),
        );
        self.bytes(
            &format!("{name}-mtime-nanos"),
            &modified.subsec_nanos().to_le_bytes(),
        );
        Ok(())
    }

    fn finish(self) -> [u8; 32] {
        self.0.finish()
    }
}

/// Number of dependency units compiled concurrently: `LORRY_JOBS` when set to
/// a positive integer, otherwise the available hardware parallelism.
fn compile_jobs() -> usize {
    env::var("LORRY_JOBS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|jobs| *jobs >= 1)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(std::num::NonZeroUsize::get)
                .unwrap_or(1)
        })
}

struct RootDependency {
    alias: String,
    identity: Identity,
    rlib: PathBuf,
    rmeta: PathBuf,
    proc_macro: Option<PathBuf>,
    search_paths: Vec<RootSearchPath>,
}

#[derive(Clone)]
struct RootSearchPath {
    compile_kind: CompileKind,
    path: PathBuf,
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
                && matches!(key.kind, UnitKind::Library | UnitKind::ProcMacro)
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
        let (rlib, rmeta, proc_macro) = match outputs.artifacts.get(key) {
            Some(crate::compile::RustcOutput::Library { rlib, rmeta, .. }) => {
                (rlib.clone(), rmeta.clone(), None)
            }
            Some(crate::compile::RustcOutput::ProcMacro {
                dynamic_library, ..
            }) => (
                dynamic_library.clone(),
                dynamic_library.clone(),
                Some(dynamic_library.clone()),
            ),
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
            proc_macro,
            search_paths: root_dependency_search_paths(plan, outputs, key)?,
        });
    }
    Ok(result)
}

fn root_dependency_search_paths(
    plan: &CompilationPlan,
    outputs: &executor::Outputs,
    root: &UnitKey,
) -> Result<Vec<RootSearchPath>> {
    let mut selected = BTreeSet::new();
    let mut pending = vec![root.clone()];
    while let Some(key) = pending.pop() {
        if !selected.insert(key.clone()) {
            continue;
        }
        let planned = plan.units.get(&key).ok_or_else(|| {
            Error::failure(format!(
                "root dependency search path references absent unit `{} {}`",
                key.package.name, key.package.version
            ))
        })?;
        pending.extend(
            planned
                .unit
                .dependencies
                .iter()
                .filter(|edge| edge.kind == UnitEdgeKind::RustDependency)
                .map(|edge| edge.unit.clone()),
        );
    }
    plan.order
        .iter()
        .filter(|key| selected.contains(*key))
        .map(|key| {
            let artifact = outputs.artifacts.get(key).ok_or_else(|| {
                Error::failure(format!(
                    "root dependency search unit `{} {}` has no artifact",
                    key.package.name, key.package.version
                ))
            })?;
            let path = match artifact {
                crate::compile::RustcOutput::Library { rlib, .. } => rlib,
                crate::compile::RustcOutput::ProcMacro {
                    dynamic_library, ..
                } => dynamic_library,
                crate::compile::RustcOutput::BuildScript { .. } => {
                    return Err(Error::failure(
                        "root Rust dependency resolved to a build-script artifact",
                    ));
                }
            }
            .parent()
            .ok_or_else(|| Error::failure("root dependency artifact has no parent directory"))?;
            Ok(RootSearchPath {
                compile_kind: key.compile_kind,
                path: path.to_owned(),
            })
        })
        .collect()
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
    dep_info: PathBuf,
}

struct StagedArtifacts {
    primary: PathBuf,
    binaries: BTreeMap<String, PathBuf>,
    harnesses: Vec<PathBuf>,
    bundle: Option<PathBuf>,
    dep_info: Vec<PathBuf>,
}

struct TestOutput<'a> {
    destination: &'a Path,
    target_root: &'a Path,
    bundle_layout: Option<&'a bundle::Layout>,
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
    let targets = build.manifest.binaries.iter().filter(|target| {
        build
            .binary_selection
            .is_none_or(|selected| target.name == selected)
    });
    let mut binaries = BTreeMap::new();
    let mut binary_dep_info = Vec::new();
    for target in targets {
        let binary = compile_root_binary(
            build,
            target,
            false,
            staging,
            host_profile,
            dependencies,
            library.as_ref(),
            &features,
            false,
        )?;
        install_primary(&binary.hashed, &binary.primary)?;
        binary_dep_info.push(binary.dep_info);
        binaries.insert(target.name.clone(), binary.primary);
    }
    if let Some(primary) = binaries.values().next().cloned() {
        let mut dep_info = library
            .as_ref()
            .map(|library| library.dep_info.clone())
            .into_iter()
            .collect::<Vec<_>>();
        dep_info.extend(binary_dep_info);
        return Ok(StagedArtifacts {
            primary,
            binaries,
            harnesses: Vec::new(),
            bundle: None,
            dep_info,
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
        binaries,
        harnesses: Vec::new(),
        bundle: None,
        dep_info: vec![library.dep_info],
    })
}

fn compile_test_targets(
    build: &Build<'_>,
    staging: &Path,
    host_profile: &Path,
    normal_dependencies: &[RootDependency],
    test_dependencies: &[RootDependency],
    output: &TestOutput<'_>,
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
    let mut programs = BTreeMap::new();
    if !integration_tests.is_empty() {
        for target in &build.manifest.binaries {
            let binary = compile_root_binary(
                build,
                target,
                false,
                staging,
                host_profile,
                normal_dependencies,
                normal_library.as_ref(),
                &features,
                false,
            )?;
            install_primary(&binary.hashed, &binary.primary)?;
            programs.insert(target.name.clone(), binary);
        }
    }

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
                &[],
            )?);
        }
        for binary in build.manifest.binaries.iter().filter(|target| target.test) {
            harnesses.push(compile_root_harness(
                build,
                RootTarget::Binary(binary),
                staging,
                host_profile,
                test_dependencies,
                test_library.as_ref(),
                &features,
                None,
                &[],
            )?);
        }
    }

    if !integration_tests.is_empty() {
        let temporary_directory = output.bundle_layout.map_or_else(
            || output.target_root.join("tmp"),
            bundle::Layout::temporary_directory,
        );
        if output.bundle_layout.is_none() {
            fs::create_dir_all(&temporary_directory).map_err(|error| {
                Error::failure(format!(
                    "failed to create test temporary directory `{}`: {error}",
                    temporary_directory.display()
                ))
            })?;
        }
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
                    binaries: build
                        .manifest
                        .binaries
                        .iter()
                        .map(|binary| {
                            (
                                binary.name.as_str(),
                                output.bundle_layout.map_or_else(
                                    || output.destination.join(&binary.name),
                                    |layout| layout.program(&binary.name),
                                ),
                            )
                        })
                        .collect(),
                    temporary_directory: &temporary_directory,
                }),
                &programs
                    .values()
                    .map(|binary| binary.identity.clone())
                    .collect::<Vec<_>>(),
            )?);
        }
    }

    let first_harness = harnesses.first().cloned().ok_or_else(|| {
        Error::failure(format!(
            "package `{}` has no enabled test targets",
            build.manifest.name
        ))
    })?;
    let binaries = programs
        .iter()
        .map(|(name, binary)| (name.clone(), binary.primary.clone()))
        .collect::<BTreeMap<_, _>>();
    let bundle_programs = programs
        .iter()
        .map(|(name, binary)| (name.as_str(), binary.primary.as_path()))
        .collect::<Vec<_>>();
    let bundled = output
        .bundle_layout
        .map(|layout| {
            if build.verbosity != Verbosity::Quiet {
                eprintln!("Bundling {} test targets", harnesses.len());
            }
            bundle::build(&bundle::BuildOptions {
                layout,
                package_name: &build.manifest.name,
                package_root: &build.manifest.root,
                staging,
                rustc: &build.toolchain.rustc,
                physical_target: build.physical_target,
                linker: build.target_options.linker.as_deref(),
                rustflags: build.rustflags,
                release: build.release,
                verbose: build.verbosity == Verbosity::Verbose,
                color: build.color,
                harnesses: &harnesses,
                programs: &bundle_programs,
            })
        })
        .transpose()?;
    Ok(StagedArtifacts {
        primary: bundled.clone().unwrap_or(first_harness),
        binaries,
        harnesses,
        bundle: bundled,
        dep_info: Vec::new(),
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
    _host_profile: &Path,
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
    let output_dir = root_output_directory(staging, &build.manifest.name, &identity);
    create_directory(&output_dir, "root rustc output directory")?;
    let arguments = rustc_arguments(
        build,
        target,
        false,
        &identity,
        staging,
        dependencies,
        None,
        features,
        test_profile,
    );
    run_root_rustc(build, target, false, dependencies, &arguments, None)?;
    let stem = format!("{}{}", target.crate_name(), identity.extra_filename);
    let rlib = output_dir.join(format!("lib{stem}.rlib"));
    let rmeta = output_dir.join(format!("lib{stem}.rmeta"));
    let dep_info = output_dir.join(format!("{stem}.d"));
    verify_artifacts([&rlib, &rmeta, &dep_info])?;
    Ok(RootLibraryArtifact {
        identity,
        rlib,
        dep_info,
    })
}

#[allow(clippy::too_many_arguments)]
fn compile_root_binary(
    build: &Build<'_>,
    target: &BinaryTarget,
    test: bool,
    staging: &Path,
    _host_profile: &Path,
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
    let output_dir = root_output_directory(staging, &build.manifest.name, &identity);
    create_directory(&output_dir, "root rustc output directory")?;
    let arguments = rustc_arguments(
        build,
        target,
        test,
        &identity,
        staging,
        dependencies,
        library,
        features,
        test_profile,
    );
    run_root_rustc(build, target, test, dependencies, &arguments, None)?;
    let hashed = output_dir.join(format!(
        "{}{}",
        target.crate_name(),
        identity.extra_filename
    ));
    let dep_info = hashed.with_extension("d");
    verify_artifacts([&hashed, &dep_info])?;
    Ok(RootBinaryArtifact {
        identity,
        hashed,
        primary: staging.join(target.name()),
        dep_info,
    })
}

struct RootBinaryArtifact {
    identity: Identity,
    hashed: PathBuf,
    primary: PathBuf,
    dep_info: PathBuf,
}

#[derive(Clone)]
struct IntegrationEnvironment<'a> {
    binaries: Vec<(&'a str, PathBuf)>,
    temporary_directory: &'a Path,
}

#[allow(clippy::too_many_arguments)]
fn compile_root_harness(
    build: &Build<'_>,
    target: RootTarget<'_>,
    staging: &Path,
    _host_profile: &Path,
    dependencies: &[RootDependency],
    library: Option<&RootLibraryArtifact>,
    features: &[String],
    integration_environment: Option<IntegrationEnvironment<'_>>,
    artifact_dependencies: &[Identity],
) -> Result<PathBuf> {
    let mut identities = dependencies
        .iter()
        .map(|dependency| dependency.identity.clone())
        .collect::<Vec<_>>();
    if let Some(library) = library {
        identities.push(library.identity.clone());
    }
    identities.extend_from_slice(artifact_dependencies);
    let identity = root_identity(build, target, true, true, features, &identities);
    let output_dir = root_output_directory(staging, &build.manifest.name, &identity);
    create_directory(&output_dir, "root rustc output directory")?;
    let arguments = rustc_arguments(
        build,
        target,
        true,
        &identity,
        staging,
        dependencies,
        library,
        features,
        true,
    );
    run_root_rustc(
        build,
        target,
        true,
        dependencies,
        &arguments,
        integration_environment,
    )?;
    let artifact = output_dir.join(format!(
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
        panic_abort: build.manifest.panic_abort(build.release),
        logical_target: build.logical_target,
        release_profile: &build.manifest.release,
        rustc: build.toolchain,
        rustflags: build.rustflags,
        dependencies,
    })
}

fn root_output_directory(staging: &Path, package_name: &str, identity: &Identity) -> PathBuf {
    staging
        .join("build")
        .join(package_name)
        .join(identity.extra_filename.trim_start_matches('-'))
        .join("deps")
}

fn run_root_rustc(
    build: &Build<'_>,
    target: RootTarget<'_>,
    test: bool,
    dependencies: &[RootDependency],
    arguments: &[OsString],
    integration_environment: Option<IntegrationEnvironment<'_>>,
) -> Result<()> {
    if build.verbosity != Verbosity::Quiet {
        let target_kind = if test {
            "test"
        } else {
            match target.kind() {
                RootTargetKind::Library => "library",
                RootTargetKind::Binary => "binary",
                RootTargetKind::IntegrationTest => "integration test",
            }
        };
        eprintln!(
            "Compiling {} v{} ({}) [{target_kind} `{}`]",
            build.manifest.name,
            build.manifest.version.original,
            build.manifest.root.display(),
            target.name()
        );
    }
    let environment = rustc_environment(
        build,
        dependencies,
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

fn create_directory(path: &Path, description: &str) -> Result<()> {
    fs::create_dir_all(path).map_err(|error| {
        Error::failure(format!(
            "failed to create {description} `{}`: {error}",
            path.display()
        ))
    })
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

#[allow(clippy::too_many_arguments)]
fn rustc_arguments(
    build: &Build<'_>,
    target: RootTarget<'_>,
    test: bool,
    identity: &Identity,
    staging: &Path,
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

    let panic_abort = build.manifest.panic_abort(build.release);
    if build.release {
        codegen(&mut args, "opt-level=3");
        if panic_abort && !test_profile {
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
        if panic_abort && !test_profile {
            codegen(&mut args, "panic=abort");
        }
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
    args.push(root_output_directory(staging, &build.manifest.name, identity).into_os_string());
    if let Some(target) = build.physical_target {
        push(&mut args, "--target");
        push(&mut args, target);
    }
    if !build.release {
        let incremental = incremental_roots(build);
        codegen(
            &mut args,
            &format!("incremental={}", incremental.target.display()),
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
    let mut seen = BTreeSet::new();
    for directory in root_dependencies
        .iter()
        .flat_map(|dependency| &dependency.search_paths)
    {
        if seen.insert(&directory.path) {
            push(&mut args, "-L");
            args.push(format!("dependency={}", directory.path.display()).into());
        }
    }
    for dependency in root_dependencies {
        push(&mut args, "--extern");
        let artifact = if let Some(proc_macro) = &dependency.proc_macro {
            proc_macro
        } else if target.kind() == RootTargetKind::Library && !test {
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
    dependencies: &[RootDependency],
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
        for (name, path) in &integration.binaries {
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
        manifest.metadata.authors.join(":"),
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
        version.major.to_string(),
    );
    value(
        &mut values,
        "CARGO_PKG_VERSION_MINOR",
        version.minor.to_string(),
    );
    value(
        &mut values,
        "CARGO_PKG_VERSION_PATCH",
        version.patch.to_string(),
    );
    value(&mut values, "CARGO_PKG_VERSION_PRE", &version.pre);
    value(&mut values, "CARGO_PRIMARY_PACKAGE", "1");
    let mut seen = BTreeSet::new();
    let dynamic_library_paths = dependencies
        .iter()
        .flat_map(|dependency| &dependency.search_paths)
        .filter(|directory| directory.compile_kind == CompileKind::Host)
        .filter_map(|directory| {
            seen.insert(directory.path.clone())
                .then_some(&directory.path)
        });
    let dynamic = env::join_paths(dynamic_library_paths).map_err(|error| {
        Error::failure(format!(
            "failed to construct root rustc dynamic-library search path: {error}"
        ))
    })?;
    value(&mut values, dynamic_library_path_variable(), dynamic);
    Ok(values)
}

pub(crate) fn repository_tree_limits(policy: &PolicyLimits) -> Result<TreeLimits> {
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

pub(crate) fn check_rust_version(manifest: &Manifest, toolchain: &Toolchain) -> Result<()> {
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

        fn add_multiple_binaries(&self) {
            let manifest = fs::read_to_string(self.0.join("Cargo.toml"))
                .unwrap()
                .replace(
                    "edition = \"2024\"",
                    "edition = \"2024\"\ndefault-run = \"worker\"",
                );
            fs::write(self.0.join("Cargo.toml"), manifest).unwrap();
            fs::create_dir_all(self.0.join("src/bin/worker")).unwrap();
            fs::write(
                self.0.join("src/bin/tool.rs"),
                "fn main() { print!(\"tool\"); }\n",
            )
            .unwrap();
            fs::write(
                self.0.join("src/bin/worker/main.rs"),
                "fn main() { print!(\"worker\"); }\n",
            )
            .unwrap();
            if self.0.join("tests").is_dir() {
                for name in ["first", "second"] {
                    let path = self.0.join("tests").join(format!("{name}.rs"));
                    let mut source = fs::read_to_string(&path).unwrap();
                    source.push_str(
                        "#[test]\nfn every_binary_is_available() {\n\
                         for (program, expected) in [(env!(\"CARGO_BIN_EXE_tool\"), b\"tool\".as_slice()), (env!(\"CARGO_BIN_EXE_worker\"), b\"worker\".as_slice())] {\n\
                             let output = std::process::Command::new(program).output().unwrap();\n\
                             assert_eq!(output.stdout, expected);\n\
                         }\n}\n",
                    );
                    fs::write(path, source).unwrap();
                }
            }
        }

        fn make_workspace(&self) -> PathBuf {
            let app = self.0.join("app");
            fs::create_dir(&app).unwrap();
            for entry in ["Cargo.toml", "src", "local"] {
                fs::rename(self.0.join(entry), app.join(entry)).unwrap();
            }
            fs::write(
                self.0.join("Cargo.toml"),
                "[workspace]\nmembers = [\"app\", \"app/local\"]\nresolver = \"3\"\n",
            )
            .unwrap();
            app
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

    fn only_binary(artifacts: &BuildArtifacts) -> &Path {
        assert_eq!(artifacts.binaries.len(), 1);
        artifacts.binaries.values().next().unwrap()
    }

    #[test]
    fn ordinary_freshness_trusts_artifact_contents_but_strict_mode_does_not() {
        let fixture = Fixture::new();
        let profile = fixture.0.join("target/lorry/debug");
        fs::create_dir_all(&profile).unwrap();
        let source = fixture.0.join("src/main.rs");
        let artifact = profile.join("root-bin");
        let dep_info = profile.join("root-bin.d");
        fs::write(&artifact, b"original-artifact").unwrap();
        fs::write(
            &dep_info,
            format!("{}: {}\n", artifact.display(), source.display()),
        )
        .unwrap();
        let staged = StagedArtifacts {
            primary: artifact.clone(),
            binaries: BTreeMap::from([("root-bin".to_owned(), artifact.clone())]),
            harnesses: Vec::new(),
            bundle: None,
            dep_info: vec![dep_info],
        };
        let base = [7; 32];

        write_fresh_profile(
            &profile,
            &fixture.0,
            base,
            &staged,
            &[],
            ValidationMode::Trusted,
        )
        .unwrap();
        fs::write(&artifact, b"tampered-artifact").unwrap();
        assert!(
            restore_fresh_profile(&profile, &fixture.0, base, ValidationMode::Trusted).is_some()
        );
        assert!(
            restore_fresh_profile(&profile, &fixture.0, base, ValidationMode::Strict).is_none()
        );

        write_fresh_profile(
            &profile,
            &fixture.0,
            base,
            &staged,
            &[],
            ValidationMode::Strict,
        )
        .unwrap();
        assert!(
            restore_fresh_profile(&profile, &fixture.0, base, ValidationMode::Strict).is_some()
        );
        fs::write(&artifact, b"changed--artifact").unwrap();
        assert!(
            restore_fresh_profile(&profile, &fixture.0, base, ValidationMode::Strict).is_none()
        );
    }

    #[test]
    fn ordinary_freshness_trusts_same_metadata_source_contents() {
        let fixture = Fixture::new();
        let profile = fixture.0.join("target/lorry/debug");
        fs::create_dir_all(&profile).unwrap();
        let source = fixture.0.join("src/main.rs");
        let artifact = profile.join("root-bin");
        let dep_info = profile.join("root-bin.d");
        fs::write(&artifact, b"artifact").unwrap();
        fs::write(
            &dep_info,
            format!("{}: {}\n", artifact.display(), source.display()),
        )
        .unwrap();
        let staged = StagedArtifacts {
            primary: artifact,
            binaries: BTreeMap::new(),
            harnesses: Vec::new(),
            bundle: None,
            dep_info: vec![dep_info],
        };
        let base = [5; 32];
        let modified = fs::metadata(&source).unwrap().modified().unwrap();
        let overwrite_preserving_metadata = |byte| {
            let mut contents = fs::read(&source).unwrap();
            contents[0] = byte;
            fs::write(&source, contents).unwrap();
            fs::File::options()
                .write(true)
                .open(&source)
                .unwrap()
                .set_times(fs::FileTimes::new().set_modified(modified))
                .unwrap();
        };

        write_fresh_profile(
            &profile,
            &fixture.0,
            base,
            &staged,
            &[],
            ValidationMode::Trusted,
        )
        .unwrap();
        overwrite_preserving_metadata(b'/');
        assert!(
            restore_fresh_profile(&profile, &fixture.0, base, ValidationMode::Trusted).is_some()
        );

        write_fresh_profile(
            &profile,
            &fixture.0,
            base,
            &staged,
            &[],
            ValidationMode::Strict,
        )
        .unwrap();
        overwrite_preserving_metadata(b'f');
        assert!(
            restore_fresh_profile(&profile, &fixture.0, base, ValidationMode::Strict).is_none()
        );
    }

    #[test]
    fn reuses_a_fresh_profile_and_invalidates_root_and_dependency_sources() {
        use std::os::unix::fs::MetadataExt;
        use std::time::Instant;

        let fixture = Fixture::new();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_99);
        let toolchain = Toolchain::discover(None, &config).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let build_once = || {
            build(Build {
                manifest: &manifest,
                global_cache_root: &manifest.root.join("global-cache"),
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
                source: None,
                bundle: false,
                validation: ValidationMode::Trusted,
                ordinary_freshness_base: None,
                binary_selection: None,
            })
            .unwrap()
        };

        let cold = build_once();
        let cold_binary = only_binary(&cold);
        let cold_inode = fs::metadata(cold_binary).unwrap().ino();
        let cold_hash = sha256_file(cold_binary).unwrap();
        assert_eq!(cache_entry_count(&fixture.0), 1);
        let incremental = fixture
            .0
            .join("target/lorry/.incremental")
            .join(&target.triple);
        let incremental_entries = fs::read_dir(&incremental)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        for crate_name in ["root_bin-", "local_dependency-"] {
            assert!(
                incremental_entries
                    .iter()
                    .any(|entry| entry.starts_with(crate_name)),
                "{crate_name} did not persist incremental state in {incremental_entries:?}"
            );
        }

        let started = Instant::now();
        let warm = build_once();
        let warm_elapsed = started.elapsed();
        let warm_binary = only_binary(&warm);
        assert_eq!(fs::metadata(warm_binary).unwrap().ino(), cold_inode);
        assert_eq!(sha256_file(warm_binary).unwrap(), cold_hash);
        assert_eq!(cache_entry_count(&fixture.0), 1);
        assert!(
            warm_elapsed < Duration::from_secs(5),
            "warm build took {warm_elapsed:?}"
        );

        fs::write(
            fixture.0.join("src/main.rs"),
            "fn main() { print!(\"root-{}\", local_dependency::VALUE); }\n",
        )
        .unwrap();
        let root_changed = build_once();
        let root_changed_binary = only_binary(&root_changed);
        assert_ne!(fs::metadata(root_changed_binary).unwrap().ino(), cold_inode);
        let output = std::process::Command::new(root_changed_binary)
            .output()
            .unwrap();
        assert_eq!(output.stdout, b"root-dependency-ok");
        assert_eq!(cache_entry_count(&fixture.0), 1);

        fs::write(
            fixture.0.join("local/src/lib.rs"),
            "pub const VALUE: &str = \"source-changed\";\n",
        )
        .unwrap();
        let invalidated = build_once();
        assert!(incremental.is_dir());
        assert_eq!(cache_entry_count(&fixture.0), 2);
        let output = std::process::Command::new(only_binary(&invalidated))
            .output()
            .unwrap();
        assert_eq!(output.stdout, b"root-source-changed");
    }

    #[test]
    fn builds_a_root_binary_with_an_unversioned_path_dependency() {
        let fixture = Fixture::new();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_99);
        let toolchain = Toolchain::discover(None, &config).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let artifact = build(Build {
            manifest: &manifest,
            global_cache_root: &manifest.root.join("global-cache"),
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
            source: None,
            bundle: false,
            validation: ValidationMode::Trusted,
            ordinary_freshness_base: None,
            binary_selection: None,
        })
        .unwrap();
        let output = std::process::Command::new(only_binary(&artifact))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"dependency-ok");
    }

    #[test]
    fn builds_all_or_one_binary_and_selects_default_run() {
        let fixture = Fixture::new();
        fixture.add_multiple_binaries();
        let manifest = Manifest::load(&fixture.0).unwrap();
        assert_eq!(select_run_binary(&manifest, None).unwrap(), "worker");
        assert_eq!(select_run_binary(&manifest, Some("tool")).unwrap(), "tool");
        assert!(select_run_binary(&manifest, Some("missing")).is_err());

        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_99);
        let toolchain = Toolchain::discover(None, &config).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let build_with = |binary_selection| {
            build(Build {
                manifest: &manifest,
                global_cache_root: &manifest.root.join("global-cache"),
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
                source: None,
                bundle: false,
                validation: ValidationMode::Trusted,
                ordinary_freshness_base: None,
                binary_selection,
            })
            .unwrap()
        };

        let all = build_with(None);
        assert_eq!(
            all.binaries.keys().map(String::as_str).collect::<Vec<_>>(),
            ["root-bin", "tool", "worker"]
        );
        for (name, expected) in [
            ("root-bin", "dependency-ok"),
            ("tool", "tool"),
            ("worker", "worker"),
        ] {
            let output = std::process::Command::new(&all.binaries[name])
                .output()
                .unwrap();
            assert!(output.status.success());
            assert_eq!(output.stdout, expected.as_bytes());
        }
        let selected = build_with(Some("tool"));
        assert_eq!(selected.binaries.keys().collect::<Vec<_>>(), ["tool"]);
    }

    #[test]
    fn builds_a_selected_workspace_member_into_shared_artifacts() {
        let fixture = Fixture::new();
        let member = fixture.make_workspace();
        let manifest = Manifest::load_selected(&fixture.0, Some("root-bin")).unwrap();
        assert_eq!(manifest, Manifest::load(&member).unwrap());
        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_99);
        let toolchain = Toolchain::discover(None, &config).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let artifacts = build(Build {
            manifest: &manifest,
            global_cache_root: &manifest.workspace_root.join("global-cache"),
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
            source: None,
            bundle: false,
            validation: ValidationMode::Trusted,
            ordinary_freshness_base: None,
            binary_selection: None,
        })
        .unwrap();
        let binary = only_binary(&artifacts);
        assert!(
            binary.starts_with(
                manifest
                    .workspace_root
                    .join("target/lorry/packages/root-bin/debug")
            )
        );
        let output = std::process::Command::new(binary).output().unwrap();
        assert_eq!(output.stdout, b"dependency-ok");
    }

    #[test]
    fn builds_the_root_library_before_the_binary() {
        let fixture = Fixture::new();
        fixture.add_root_library();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_99);
        let toolchain = Toolchain::discover(None, &config).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let artifacts = build(Build {
            manifest: &manifest,
            global_cache_root: &manifest.root.join("global-cache"),
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
            source: None,
            bundle: false,
            validation: ValidationMode::Trusted,
            ordinary_freshness_base: None,
            binary_selection: None,
        })
        .unwrap();
        let output = std::process::Command::new(only_binary(&artifacts))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"dependency-ok");
        assert!(
            fs::read_dir(fixture.0.join("target/lorry/debug/build/root-bin"))
                .unwrap()
                .any(|unit| {
                    fs::read_dir(unit.unwrap().path().join("deps"))
                        .unwrap()
                        .any(|entry| {
                            entry
                                .unwrap()
                                .file_name()
                                .to_string_lossy()
                                .starts_with("libroot_bin-")
                        })
                })
        );
    }

    #[test]
    fn builds_a_library_only_root_package() {
        use std::os::unix::fs::MetadataExt;

        let fixture = Fixture::new();
        fs::remove_file(fixture.0.join("src/main.rs")).unwrap();
        fs::write(
            fixture.0.join("src/lib.rs"),
            "pub fn value() -> &'static str { local_dependency::VALUE }\n",
        )
        .unwrap();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_99);
        let toolchain = Toolchain::discover(None, &config).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let build_once = || {
            build(Build {
                manifest: &manifest,
                global_cache_root: &manifest.root.join("global-cache"),
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
                source: None,
                bundle: false,
                validation: ValidationMode::Trusted,
                ordinary_freshness_base: None,
                binary_selection: None,
            })
            .unwrap()
        };
        let artifacts = build_once();
        assert!(artifacts.binaries.is_empty());
        assert!(artifacts.primary.is_file());
        assert!(
            artifacts
                .primary
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("libroot_bin-")
        );
        let inode = fs::metadata(&artifacts.primary).unwrap().ino();
        let warm = build_once();
        assert!(warm.binaries.is_empty());
        assert_eq!(fs::metadata(warm.primary).unwrap().ino(), inode);
    }

    #[test]
    fn executes_an_admitted_dependency_build_script_from_the_engine() {
        let fixture = Fixture::new();
        fixture.add_build_script();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_99);
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
                allow_proc_macro: false,
                native_tools: BTreeSet::new(),
                provenance: fixture.0.join("lorry.toml"),
            },
        );
        let toolchain = Toolchain::discover(None, &config).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let artifact = build(Build {
            manifest: &manifest,
            global_cache_root: &manifest.root.join("global-cache"),
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
            source: None,
            bundle: false,
            validation: ValidationMode::Trusted,
            ordinary_freshness_base: None,
            binary_selection: None,
        })
        .unwrap();
        let output = std::process::Command::new(only_binary(&artifact))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"build-script-ok");
    }

    #[test]
    fn builds_and_runs_unit_and_integration_test_harnesses() {
        let fixture = Fixture::new();
        fixture.add_test_targets();
        fixture.add_multiple_binaries();
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
        config.cargo_compat = Some(CargoCompat::V1_99);
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
                allow_proc_macro: false,
                native_tools: BTreeSet::new(),
                provenance: fixture.0.join("lorry.toml"),
            },
        );
        let toolchain = Toolchain::discover(None, &config).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let artifacts = build(Build {
            manifest: &manifest,
            global_cache_root: &manifest.root.join("global-cache"),
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
            source: None,
            bundle: false,
            validation: ValidationMode::Trusted,
            ordinary_freshness_base: None,
            binary_selection: None,
        })
        .unwrap();
        assert_eq!(artifacts.harnesses.len(), 6);
        assert_eq!(artifacts.binaries.len(), 3);
        for harness in &artifacts.harnesses {
            let status = std::process::Command::new(harness).status().unwrap();
            assert!(status.success(), "harness `{}` failed", harness.display());
        }
    }

    #[test]
    fn builds_a_copyable_verified_aggregating_test_bundle() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = Fixture::new();
        fixture.add_test_targets();
        let first = fixture.0.join("tests/first.rs");
        let second = fixture.0.join("tests/second.rs");
        fs::write(
            &first,
            format!(
                "{}\n#[test]\nfn conditional_bundle_failure() {{\n    if std::env::var_os(\"LORRY_BUNDLE_FAIL\").is_some() {{ panic!(\"requested bundle failure\"); }}\n}}\n",
                fs::read_to_string(&first).unwrap()
            ),
        )
        .unwrap();
        fs::write(
            &second,
            format!(
                "{}\n#[test]\nfn bundle_marker() {{ println!(\"BUNDLE-SECOND-RAN\"); }}\n",
                fs::read_to_string(&second).unwrap()
            ),
        )
        .unwrap();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_99);
        config.test.extraction_root = Some(fixture.0.join("target/bundle-extraction"));
        let toolchain = Toolchain::discover(None, &config).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let build_bundle = || {
            build(Build {
                manifest: &manifest,
                global_cache_root: &manifest.root.join("global-cache"),
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
                source: None,
                bundle: true,
                validation: ValidationMode::Trusted,
                ordinary_freshness_base: None,
                binary_selection: None,
            })
        };
        let artifacts = build_bundle().unwrap();
        let rebuilt = build_bundle().unwrap();
        assert_eq!(artifacts.bundle, rebuilt.bundle);
        let bundle = artifacts.bundle.unwrap();
        assert_eq!(artifacts.primary, bundle);
        assert_eq!(bundle.file_name().unwrap(), "root-bin-test-bundle");
        let copied = fixture.0.join("copied-test-bundle");
        fs::copy(&bundle, &copied).unwrap();
        fs::remove_dir_all(fixture.0.join("target/lorry")).unwrap();

        let success = std::process::Command::new(&copied)
            .arg("--nocapture")
            .output()
            .unwrap();
        assert!(
            success.status.success(),
            "{}",
            String::from_utf8_lossy(&success.stderr)
        );
        assert!(
            success
                .stdout
                .windows(17)
                .any(|bytes| bytes == b"BUNDLE-SECOND-RAN")
        );

        let forwarded = std::process::Command::new(&copied)
            .args(["bundle_marker", "--exact", "--nocapture"])
            .output()
            .unwrap();
        assert!(forwarded.status.success());
        assert!(
            forwarded
                .stdout
                .windows(17)
                .any(|bytes| bytes == b"BUNDLE-SECOND-RAN")
        );

        let aggregated = std::process::Command::new(&copied)
            .arg("--nocapture")
            .env("LORRY_BUNDLE_FAIL", "1")
            .output()
            .unwrap();
        assert_eq!(aggregated.status.code(), Some(1));
        assert!(
            aggregated
                .stdout
                .windows(17)
                .any(|bytes| bytes == b"BUNDLE-SECOND-RAN")
        );

        let extraction_root = config.test.extraction_root.as_ref().unwrap();
        let extraction = fs::read_dir(extraction_root)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(
            fs::metadata(&extraction).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(fs::read_dir(extraction_root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("staging")
        }));
        fs::set_permissions(&extraction, fs::Permissions::from_mode(0o755)).unwrap();
        let public = std::process::Command::new(&copied).output().unwrap();
        assert_eq!(public.status.code(), Some(101));
        assert!(String::from_utf8_lossy(&public.stderr).contains("permissions 755"));
        fs::set_permissions(&extraction, fs::Permissions::from_mode(0o700)).unwrap();

        let unexpected = extraction.join("unexpected");
        fs::write(&unexpected, b"unexpected").unwrap();
        let noncanonical = std::process::Command::new(&copied).output().unwrap();
        assert_eq!(noncanonical.status.code(), Some(101));
        assert!(String::from_utf8_lossy(&noncanonical.stderr).contains("file set"));
        fs::remove_file(unexpected).unwrap();

        let tampered = fs::read_dir(extraction.join("tests"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::write(tampered, b"tampered").unwrap();
        let rejected = std::process::Command::new(&copied).output().unwrap();
        assert_eq!(rejected.status.code(), Some(101));
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("was modified"));
    }

    #[test]
    fn named_test_builds_only_the_selected_integration_harness() {
        let fixture = Fixture::new();
        fixture.add_test_targets();
        let selected = fixture.0.join("tests/second.rs");
        fs::write(
            &selected,
            format!(
                "{}\n#[test]\nfn selected_second() {{}}\n",
                fs::read_to_string(&selected).unwrap()
            ),
        )
        .unwrap();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_99);
        config.test.extraction_root = Some(fixture.0.join("target/bundle-extraction"));
        let toolchain = Toolchain::discover(None, &config).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let artifacts = build(Build {
            manifest: &manifest,
            global_cache_root: &manifest.root.join("global-cache"),
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
            source: None,
            bundle: false,
            validation: ValidationMode::Trusted,
            ordinary_freshness_base: None,
            binary_selection: None,
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

        let bundled = build(Build {
            manifest: &manifest,
            global_cache_root: &manifest.root.join("global-cache"),
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
            source: None,
            bundle: true,
            validation: ValidationMode::Trusted,
            ordinary_freshness_base: None,
            binary_selection: None,
        })
        .unwrap();
        assert_eq!(bundled.harnesses.len(), 1);
        let bundle = bundled.bundle.unwrap();
        let output = std::process::Command::new(&bundle)
            .arg("--list")
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("selected_second: test"));
        assert!(!stdout.contains("library_unit"));

        let runner_marker = fixture.0.join("runner-invocations");
        let runner_options = TargetOptions {
            runner: Some(vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                format!(
                    "printf 'invoked\\n' >> '{}'; exec \"$0\" \"$@\"",
                    runner_marker.display()
                ),
            ]),
            ..TargetOptions::default()
        };
        assert_eq!(
            run_artifact(
                &bundle,
                &["--list".to_owned()],
                &fixture.0,
                Some("cross-target"),
                &runner_options,
                Verbosity::Quiet,
            )
            .unwrap(),
            0
        );
        assert_eq!(fs::read_to_string(runner_marker).unwrap(), "invoked\n");
    }

    #[test]
    fn unknown_named_test_lists_discovered_integration_targets() {
        let fixture = Fixture::new();
        fixture.add_test_targets();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_99);
        let toolchain = Toolchain::discover(None, &config).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let error = build(Build {
            manifest: &manifest,
            global_cache_root: &manifest.root.join("global-cache"),
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
            source: None,
            bundle: false,
            validation: ValidationMode::Trusted,
            ordinary_freshness_base: None,
            binary_selection: None,
        })
        .unwrap_err();
        let rendered = format!("{error:?}");
        assert!(rendered.contains("no integration-test target named `missing`"));
        assert!(rendered.contains("first, second"));
    }
}
