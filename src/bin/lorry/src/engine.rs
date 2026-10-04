use crate::admission_state::CompactState;
use crate::atomic::{AtomicDirectory, AtomicFile};
use crate::bundle;
use crate::cache;
use crate::cargo_registry::CargoRegistry;
use crate::cli::{CheckOptions, Cli, Color, Command, MessageFormat, Verbosity};
use crate::config::{Config, PolicyLimits, TargetOptions, TargetSelector, effective_rustflags};
use crate::dependency;
use crate::diagnostic::{Error, Result};
use crate::executor;
use crate::hash::{Sha256, decode_hex, hex, sha256_file};
use crate::manifest::Manifest;
use crate::process;
use crate::progress::Progress;
use crate::repository::RepositorySet;
use crate::resolver::{PackageKey, Resolution, TargetSelection};
use crate::source_tree::{DEFAULT_LIMITS, Limits as TreeLimits};
use crate::toolchain::{TargetInfo, Toolchain};
use crate::unit::{
    CheckTargetSelection, CompilationPlan, PlanOptions, UnitKey, UnitKind, selected_library_key,
};
use crate::validation::ValidationMode;
use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::IsTerminal;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

const MOTOR_TARGET: &str = "x86_64-unknown-motor";

pub fn execute(cli: &Cli) -> Result<i32> {
    let mut reported = false;
    let result = execute_inner(cli, &mut reported);
    if cli.message_format() != MessageFormat::Human && !reported {
        let finished = crate::check_message::build_finished(matches!(&result, Ok(0)));
        return match (result, finished) {
            (Ok(code), Ok(())) => Ok(code),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        };
    }
    result
}

fn report_build_completion(cli: &Cli, reported: &mut bool) -> Result<()> {
    if cli.message_format() != MessageFormat::Human {
        *reported = true;
        crate::check_message::build_finished(true)?;
    }
    Ok(())
}

fn execute_inner(cli: &Cli, reported: &mut bool) -> Result<i32> {
    let current = env::current_dir()
        .map_err(|error| Error::failure(format!("failed to read current directory: {error}")))?;
    let (workspace, selected) = crate::manifest::SourceWorkspace::load_compilation(
        &current,
        cli.manifest_path.as_deref().map(Path::new),
        &cli.selection,
    )?;
    let ordinary = matches!(&cli.command, Command::Build(_) | Command::Check(_));
    let shared =
        ordinary && (selected.len() > 1 || cli.features != crate::cli::FeatureSelection::default());
    if !ordinary {
        cli.features.require_default()?;
    }
    if selected.len() != 1 && !shared {
        return Err(Error::failure(format!(
            "package selection selects {} packages; multi-package execution is not yet supported",
            selected.len()
        ))
        .with_help("select one workspace package with `-p NAME`"));
    }
    let manifest = selected[0].clone();
    Manifest::report_warnings(&selected, cli.verbosity);
    if shared
        && matches!(&cli.command, Command::Check(options) if options.all_targets || options.test.is_some() || options.examples)
    {
        return Err(Error::failure(
            "workspace test, example, and bench target selection is not yet supported",
        ));
    }
    if matches!(&cli.command, Command::Check(options) if options.all_targets)
        && !manifest.described_targets.is_empty()
        && cli.verbosity != Verbosity::Quiet
    {
        eprintln!(
            "note: --all-targets leaves out examples and benches until their compilation is implemented"
        );
    }
    for manifest in &selected {
        // Compiling the selected package without its build script would quietly
        // produce a different crate, so reject it before any other work.
        if let Some(script) = &manifest.build_script {
            return Err(Error::failure(format!(
                "package `{}` has a build script (`{}`), and Lorry does not run build \
             scripts of the selected package",
                manifest.name,
                script.display()
            ))
            .with_help(
                "Lorry runs build scripts only for dependencies; build scripts of the \
             selected package are a deferred capability",
            ));
        }
    }
    if let Command::Check(options) = &cli.command
        && options.lib
        && selected.iter().all(|member| member.library.is_none())
    {
        return Err(Error::failure(format!(
            "no library targets found in package `{}`",
            manifest.name
        )));
    }
    if let Command::Check(options) = &cli.command {
        validate_member_binary_selection(&selected, options.bin.as_deref())?;
        if let Some(name) = &options.test
            && !manifest
                .integration_tests
                .iter()
                .any(|target| target.name == *name)
        {
            return Err(unknown_integration_test(&manifest, name));
        }
    }
    for manifest in &selected {
        if manifest.root != manifest.workspace_root && CompactState::path(&manifest.root).exists() {
            return Err(Error::failure(
                "per-member admission must be migrated to the workspace root",
            )
            .with_help("run workspace-root `lorry vendor --locked` to review the workspace"));
        }
    }
    let compact_state = CompactState::load(&manifest.workspace_root)?;
    if compact_state
        .as_ref()
        .is_some_and(|state| state.scope.is_none())
        && (shared
            || manifest.root != manifest.workspace_root
            || manifest.workspace_members.len() > 1)
    {
        return Err(
            Error::failure("legacy admission does not cover a workspace").with_help(
                "run workspace-root `lorry vendor --locked` to review and migrate admission",
            ),
        );
    }
    let mut config = Config::load(&current, &manifest)?;
    config.apply_max_packages(cli.max_packages)?;
    let requested_target_directory = match &cli.command {
        Command::Build(options) => options.target_dir.as_deref(),
        Command::Check(options) => options.target_dir.as_deref(),
        Command::Run(options) => options.build.target_dir.as_deref(),
        Command::Test(options) => options.build.target_dir.as_deref(),
        _ => unreachable!("non-build command passed to engine"),
    };
    let target_directory = config.target_directory(
        &current,
        &manifest.workspace_root,
        requested_target_directory,
    );
    let target_root = artifact_root_in(&manifest, &target_directory);
    let artifact_lock = crate::artifact_lock::ArtifactLock::acquire(&target_directory)?;
    migrate_artifact_layout(&target_root)?;
    crate::trace::event("loaded manifest, admission state, and configuration");
    let mut toolchain = Toolchain::discover(cli.toolchain.as_deref(), &config, cli.is_clippy())?;
    if let Command::Check(options) = &cli.command
        && let Some(arguments) = &options.clippy
        && let Some(driver) = &mut toolchain.clippy
    {
        driver.arguments = arguments.join(crate::clippy::ARG_SEPARATOR);
    }
    for manifest in &selected {
        check_rust_version(manifest, &toolchain)?;
    }
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
        Command::Check(options) => (false, options.target.as_deref(), ValidationMode::Trusted),
        Command::Test(options) => (
            options.build.release,
            options.build.target.as_deref(),
            options.build.validation,
        ),
        _ => unreachable!("non-build command passed to engine"),
    };
    for manifest in &selected {
        manifest.require_profile(release, matches!(cli.command, Command::Test(_)))?;
    }
    let binary_selection = match &cli.command {
        Command::Build(options) => {
            validate_member_binary_selection(&selected, options.bin.as_deref())?
        }
        Command::Check(_) | Command::Run(_) | Command::Test(_) => None,
        _ => unreachable!(),
    };
    let run_binary = match &cli.command {
        Command::Run(options) => Some(select_run_binary(&manifest, options.build.bin.as_deref())?),
        _ => None,
    };
    let physical_target = config.selected_target(command_target)?;
    let target_info = toolchain.target_info(physical_target.as_deref())?;
    for manifest in &selected {
        manifest.require_supported_target(&target_info)?;
    }
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
    let jobs = compile_jobs(cli.jobs());
    let color = use_color(cli.color);
    crate::trace::event("resolved effective build configuration");

    let cargo = env::current_exe()
        .map_err(|error| Error::failure(format!("failed to locate Lorry executable: {error}")))?;
    let ordinary_freshness_base = (!shared
        && !validation.is_strict()
        && !(compact_state.is_none()
            && manifest
                .lock
                .iter()
                .flat_map(|lock| &lock.packages)
                .any(|package| package.source.is_some()))
        && matches!(&cli.command, Command::Build(_) | Command::Run(_)))
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
            jobs,
            cargo: &cargo,
        })
    })
    .transpose()?;

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
            Some(&target_root.join(".cargo-evidence")),
        )?)
    } else {
        None
    };
    let source = match (&repositories, &cargo_registry) {
        (Some(repositories), None) => dependency::RegistrySource::Lorry(repositories),
        (None, Some(registry)) => dependency::RegistrySource::Cargo(registry),
        _ => unreachable!("exactly one registry source is constructed"),
    };
    let direct = if shared {
        crate::git::load_locked_sources(&manifest, &config.policy.limits)?
    } else {
        crate::git::load_locked_dependencies(&manifest, &config.policy.limits)?
    };
    let members = shared
        .then(|| {
            crate::resolver::workspace::features::member_requests(
                &workspace,
                &selected.iter().map(|member| member.root.clone()).collect(),
                &cli.features,
                false,
            )
        })
        .transpose()?;
    crate::trace::event("opened dependency source");
    let options = dependency::resolver_options(&manifest, &config, &toolchain)?;
    let inputs = dependency::ReviewInputs {
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
    };
    let verified_resolution = if let Some(compact) = &compact_state {
        let verified = if let Some(members) = &members {
            dependency::workspace::admission::verify_requested(&inputs, compact, members)?
        } else {
            dependency::verify_compact_admission(&inputs, compact)?
        };
        let (review, resolution) = verified.into_parts();
        review.apply_to_policy(&mut config.policy, &manifest.root)?;
        resolution
    } else if let Some(members) = &members {
        Some(dependency::workspace::resolve_compilation(
            &inputs,
            &workspace,
            members,
            TargetSelection {
                host_triple: &host_info.triple,
                host_cfg: &host_info.cfg,
                target_triple: &target_info.triple,
                target_cfg: &target_info.cfg,
            },
        )?)
    } else {
        None
    };
    crate::trace::event("verified dependency admission");
    if let Some(base) = ordinary_freshness_base
        && let Some(artifacts) = restore_fresh_profile(
            &profile_destination(&target_root, physical_target.as_deref(), release),
            &manifest.workspace_root,
            &manifest.root,
            base,
            validation,
        )
    {
        crate::trace::event("accepted fresh root profile after dependency admission");
        crate::check_message::replay(&artifacts.messages, cli.message_format(), color)?;
        report_finished(release, cli.verbosity, validation, &artifacts)?;
        report_build_completion(cli, reported)?;
        return match &cli.command {
            Command::Build(_) => Ok(0),
            Command::Run(options) => {
                let artifact = artifacts.binaries.get(run_binary.unwrap()).ok_or_else(|| {
                    Error::failure("selected binary is absent from the fresh build profile")
                })?;
                drop(artifact_lock);
                crate::trace::event("starting program");
                let status = run_artifact(
                    artifact,
                    &options.arguments,
                    &current,
                    &crate::compile::runtime_environment(
                        &cargo,
                        &manifest,
                        &artifacts.library_paths,
                    )?,
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

    let global_cache_root = config.cache_directory()?;

    match &cli.command {
        Command::Build(options) => {
            build_reported(
                Build {
                    target_root: Some(&target_root),
                    child_lease_fd: artifact_lock.child_lease_fd(),
                    manifest: &manifest,
                    members: shared.then_some(selected.as_slice()),
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
                    jobs,
                    keep_going: options.keep_going,
                    use_cargo_registry: cli.use_cargo_registry,
                    source: Some((source, &direct, verified_resolution)),
                    bundle: false,
                    validation,
                    ordinary_freshness_base,
                    binary_selection,
                },
                options.message_format,
            )?;
            Ok(0)
        }
        Command::Check(options) => check(
            Build {
                target_root: Some(&target_root),
                child_lease_fd: artifact_lock.child_lease_fd(),
                manifest: &manifest,
                members: shared.then_some(selected.as_slice()),
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
                release: false,
                test: false,
                test_name: None,
                color,
                verbosity: cli.verbosity,
                jobs,
                keep_going: false,
                use_cargo_registry: cli.use_cargo_registry,
                source: Some((source, &direct, verified_resolution)),
                bundle: false,
                validation,
                ordinary_freshness_base: None,
                binary_selection: None,
            },
            &target_root,
            options,
        ),
        Command::Run(options) => {
            let artifacts = build_reported(
                Build {
                    target_root: Some(&target_root),
                    child_lease_fd: artifact_lock.child_lease_fd(),
                    manifest: &manifest,
                    members: None,
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
                    jobs,
                    keep_going: false,
                    use_cargo_registry: cli.use_cargo_registry,
                    source: Some((source, &direct, verified_resolution)),
                    bundle: false,
                    validation,
                    ordinary_freshness_base,
                    binary_selection: None,
                },
                options.build.message_format,
            )?;
            let artifact = artifacts.binaries.get(run_binary.unwrap()).ok_or_else(|| {
                Error::failure("selected binary is absent from the completed build")
            })?;
            report_build_completion(cli, reported)?;
            drop(artifact_lock);
            crate::trace::event("starting program");
            let status = run_artifact(
                artifact,
                &options.arguments,
                &current,
                &crate::compile::runtime_environment(&cargo, &manifest, &artifacts.library_paths)?,
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
            let artifacts = build_reported(
                Build {
                    target_root: Some(&target_root),
                    child_lease_fd: artifact_lock.child_lease_fd(),
                    manifest: &manifest,
                    members: None,
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
                    jobs,
                    keep_going: false,
                    use_cargo_registry: cli.use_cargo_registry,
                    source: Some((source, &direct, verified_resolution)),
                    bundle: options.bundle,
                    validation,
                    ordinary_freshness_base,
                    binary_selection: None,
                },
                options.build.message_format,
            )?;
            report_build_completion(cli, reported)?;
            if options.no_run {
                if options.build.message_format != MessageFormat::Human {
                    return Ok(0);
                } else if let Some(bundle) = &artifacts.bundle {
                    println!("{}", bundle.display());
                } else {
                    for harness in &artifacts.harnesses {
                        println!("{}", harness.display());
                    }
                }
                return Ok(0);
            }
            drop(artifact_lock);
            if let Some(bundle) = &artifacts.bundle {
                return run_artifact(
                    bundle,
                    &options.arguments,
                    &manifest.root,
                    &BTreeMap::new(),
                    physical_target.as_deref(),
                    &target_options,
                    cli.verbosity,
                );
            }
            let mut environment =
                crate::compile::runtime_environment(&cargo, &manifest, &artifacts.library_paths)?;
            for (name, path) in &artifacts.binaries {
                environment.insert(format!("CARGO_BIN_EXE_{name}"), path.as_os_str().to_owned());
            }
            for harness in &artifacts.harnesses {
                let status = run_artifact(
                    harness,
                    &options.arguments,
                    &manifest.root,
                    &environment,
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
    /// Selected workspace roots; legacy single-package callers use `None`.
    members: Option<&'a [Manifest]>,
    target_root: Option<&'a Path>,
    child_lease_fd: Option<i32>,
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
    jobs: usize,
    keep_going: bool,
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
    messages: Vec<serde_json::Value>,
    library_paths: Vec<PathBuf>,
}

struct IncrementalRoots {
    host: PathBuf,
    target: PathBuf,
}

fn incremental_roots_in(build: &Build<'_>, target_root: &Path) -> IncrementalRoots {
    let mut root = target_root.join(".incremental");
    if build.toolchain.clippy.is_some() {
        root.push("clippy");
    }
    IncrementalRoots {
        host: root.join(&build.host.triple),
        target: root.join(&build.target.triple),
    }
}

pub(crate) fn artifact_root(manifest: &Manifest) -> PathBuf {
    artifact_root_in(manifest, &manifest.workspace_root.join("target"))
}

pub(crate) fn artifact_root_in(_manifest: &Manifest, target_directory: &Path) -> PathBuf {
    target_directory.join("lorry")
}

const SHARED_LAYOUT_RECORD: &str = ".lorry-shared-layout-v1";

pub(crate) fn migrate_artifact_layout(root: &Path) -> Result<()> {
    let existed = match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => true,
        Ok(_) => {
            return Err(Error::failure(format!(
                "Lorry artifact root `{}` is not a real directory",
                root.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(Error::failure(format!(
                "failed to inspect Lorry artifact root `{}`: {error}",
                root.display()
            )));
        }
    };
    let marker = root.join(SHARED_LAYOUT_RECORD);
    if existed {
        match fs::symlink_metadata(&marker) {
            Ok(metadata)
                if metadata.file_type().is_file()
                    && fs::read(&marker).ok().as_deref() == Some(b"lorry-shared-layout-v1\n") =>
            {
                return Ok(());
            }
            Ok(_) => {
                return Err(Error::failure(format!(
                    "Lorry artifact layout record `{}` is invalid",
                    marker.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(Error::failure(format!(
                    "failed to inspect artifact layout record `{}`: {error}",
                    marker.display()
                )));
            }
        }
    }
    if existed {
        fs::remove_dir_all(root).map_err(|error| {
            Error::failure(format!(
                "failed to reset legacy Lorry artifacts `{}`: {error}",
                root.display()
            ))
        })?;
        eprintln!(
            "Reset legacy Lorry artifacts in `{}` for the shared workspace layout",
            root.display()
        );
    }
    fs::create_dir_all(root).map_err(|error| {
        Error::failure(format!(
            "failed to create Lorry artifact root `{}`: {error}",
            root.display()
        ))
    })?;
    let mut record = AtomicFile::new(&marker)?;
    record.write_all(b"lorry-shared-layout-v1\n")?;
    record.commit()
}

fn profile_destination(
    target_root: &Path,
    physical_target: Option<&str>,
    release: bool,
) -> PathBuf {
    let mut profile = target_root.to_owned();
    if let Some(target) = physical_target {
        profile.push(target);
    }
    profile.push(if release { "release" } else { "debug" });
    profile
}

fn create_published_profile(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|error| {
        Error::failure(format!(
            "failed to create build profile `{}`: {error}",
            path.display()
        ))
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Error::failure(format!(
            "failed to inspect build profile `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::failure(format!(
            "build profile `{}` is not a real directory",
            path.display()
        )));
    }
    Ok(())
}

pub(crate) fn fresh_record_path(profile: &Path, package_root: &Path) -> PathBuf {
    let mut hash = Sha256::new();
    hash.update(b"lorry-fresh-owner-v1");
    hash.update(package_root.as_os_str().as_encoded_bytes());
    profile.join(format!("{FRESH_PROFILE_FILE}-{}", hex(&hash.finish())))
}

fn invalidate_fresh_profile(profile: &Path, package_root: &Path) -> Result<()> {
    let path = fresh_record_path(profile, package_root);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(Error::failure(format!(
                "build freshness record `{}` is not a regular file",
                path.display()
            )))
        }
        Ok(_) => fs::remove_file(&path).map_err(|error| {
            Error::failure(format!(
                "failed to invalidate build freshness record `{}`: {error}",
                path.display()
            ))
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::failure(format!(
            "failed to inspect build freshness record `{}`: {error}",
            path.display()
        ))),
    }
}

fn validate_member_binary_selection<'a>(
    members: &[Manifest],
    requested: Option<&'a str>,
) -> Result<Option<&'a str>> {
    if let [member] = members {
        return validate_binary_selection(member, requested);
    }
    if let Some(name) = requested
        && !members
            .iter()
            .any(|member| member.binaries.iter().any(|target| target.name == name))
    {
        return Err(Error::failure(format!(
            "no binary target named `{name}` in selected packages"
        )));
    }
    Ok(requested)
}

fn validate_binary_selection<'a>(
    manifest: &Manifest,
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

enum BuildOutcome {
    Artifacts(BuildArtifacts),
    Check(i32),
}

#[cfg(test)]
fn build(build: Build<'_>) -> Result<BuildArtifacts> {
    build_reported(build, MessageFormat::Human)
}

fn build_reported(build: Build<'_>, format: MessageFormat) -> Result<BuildArtifacts> {
    match build_inner(build, None, format)? {
        BuildOutcome::Artifacts(artifacts) => Ok(artifacts),
        BuildOutcome::Check(_) => unreachable!("ordinary build returned a check result"),
    }
}

fn check(build: Build<'_>, target_root: &Path, options: &CheckOptions) -> Result<i32> {
    if options.examples {
        return Err(Error::failure(
            "`check --examples` is not supported until example targets are implemented",
        ));
    }
    match build_inner(build, Some((target_root, options)), options.message_format)? {
        BuildOutcome::Check(code) => Ok(code),
        BuildOutcome::Artifacts(_) => unreachable!("check returned ordinary build artifacts"),
    }
}

fn build_inner(
    mut build: Build<'_>,
    check: Option<(&Path, &CheckOptions)>,
    format: MessageFormat,
) -> Result<BuildOutcome> {
    if let Some(name) = build.test_name
        && !build
            .manifest
            .integration_tests
            .iter()
            .any(|target| target.name == name)
    {
        return Err(unknown_integration_test(build.manifest, name));
    }
    let default_target_root = artifact_root(build.manifest);
    let target_root = check.map_or(
        build.target_root.unwrap_or(default_target_root.as_path()),
        |(root, _)| root,
    );
    let incremental = incremental_roots_in(&build, target_root);
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
        None => target_root.to_owned(),
    };
    let destination = if check.is_some() {
        let mut destination = target_root.to_owned();
        if let Some(target) = build.physical_target {
            destination.push(target);
        }
        destination.join(if build.toolchain.clippy.is_some() {
            "clippy"
        } else {
            "check"
        })
    } else {
        profile_destination(target_root, build.physical_target, build.release)
    };
    let staging = AtomicDirectory::new_compact(&profile_parent)?;
    crate::trace::event("created dependency preparation directory");

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
        if build.members.is_some() {
            dependency::workspace::prepare_compilation(
                verified_resolution.ok_or_else(|| {
                    Error::failure("shared compilation requires a selected workspace resolution")
                })?,
                build.config,
                source,
                staging.path(),
                direct,
            )?
        } else {
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
        }
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
    let mut manifests = prepared
        .packages
        .iter()
        .map(|(key, package)| (key.clone(), package.manifest.clone()))
        .collect::<BTreeMap<_, _>>();
    let selected_root = selected_library_key(build.manifest)?;
    let selected_packages = build
        .members
        .unwrap_or_else(|| std::slice::from_ref(build.manifest))
        .iter()
        .map(|manifest| selected_library_key(manifest).map(|key| key.package))
        .collect::<Result<Vec<_>>>()?;
    let selected_library = build
        .manifest
        .library
        .as_ref()
        .map(|_| selected_root.clone());
    manifests.insert(selected_root.package.clone(), build.manifest.clone());
    let cargo = env::current_exe()
        .map_err(|error| Error::failure(format!("failed to locate Lorry executable: {error}")))?;
    let freshness_base = (check.is_none() && !build.test && build.members.is_none())
        .then(|| freshness_base(&build, &prepared, &cargo))
        .transpose()?;
    if let Some(base) = freshness_base {
        crate::trace::event("fingerprinted build inputs");
        if let Some(artifacts) = restore_fresh_profile(
            &destination,
            &build.manifest.workspace_root,
            &build.manifest.root,
            base,
            build.validation,
        ) {
            crate::trace::event("validated fresh root profile");
            crate::check_message::replay(&artifacts.messages, format, build.color)?;
            finish_build(&build, &artifacts)?;
            crate::trace::event("reported build result");
            return Ok(BuildOutcome::Artifacts(artifacts));
        }
        crate::trace::event("root profile requires rebuilding");
    }
    let dependency_plan = |test_profile: bool,
                           include_selected: bool,
                           include_binaries: bool,
                           include_harnesses: bool| {
        let options = PlanOptions {
            workspace_root: &build.manifest.workspace_root,
            release: build.release,
            test_profile,
            panic_abort: build.manifest.panic_abort(build.release),
            release_profile: &build.manifest.release,
            rustc: build.toolchain,
            logical_target: build.logical_target,
            rustflags: build.rustflags,
        };
        if build.members.is_some() {
            if test_profile || include_harnesses || !include_selected {
                return Err(Error::failure(
                    "workspace test targets are not yet supported",
                ));
            }
            prepared.workspace_plan(
                &options,
                &selected_packages,
                false,
                include_binaries,
                build.binary_selection,
            )
        } else if include_selected {
            prepared.selected_targets_plan(
                &options,
                build.manifest,
                build.binary_selection,
                include_binaries,
                include_harnesses,
            )
        } else {
            prepared.dependency_plan(&options)
        }
    };
    let selected_check_plan = |selection: &CheckTargetSelection<'_>| {
        let options = PlanOptions {
            workspace_root: &build.manifest.workspace_root,
            release: build.release,
            test_profile: false,
            panic_abort: build.manifest.panic_abort(build.release),
            release_profile: &build.manifest.release,
            rustc: build.toolchain,
            logical_target: build.logical_target,
            rustflags: build.rustflags,
        };
        if build.members.is_some() {
            if selection.harnesses || selection.integrations || !selection.normal {
                return Err(Error::failure(
                    "workspace test targets are not yet supported",
                ));
            }
            prepared.workspace_plan(
                &options,
                &selected_packages,
                true,
                selection.binaries,
                selection.binary_name,
            )
        } else {
            prepared.selected_check_plan(&options, build.manifest, selection)
        }
    };
    let roots = crate::metadata::publish_sources(build.global_cache_root, build.config, &prepared)?;
    let message_reporter = crate::check_message::Reporter::new(
        build.manifest,
        &prepared,
        &roots,
        format,
        build.color,
    )?;
    let host_profile = if build.physical_target.is_some() {
        target_root.join(if check.is_some() {
            "check"
        } else if build.release {
            "release"
        } else {
            "debug"
        })
    } else {
        destination.clone()
    };
    create_published_profile(&destination)?;
    if host_profile != destination {
        create_published_profile(&host_profile)?;
    }
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
    let selected_integration =
        build.test && (build.test_name.is_some() || !build.manifest.integration_tests.is_empty());
    let check_integration = check.is_some_and(|(_, options)| {
        options.selects_tests() && !build.manifest.integration_tests.is_empty()
    });
    let integration_binaries = (selected_integration || check_integration).then(|| {
        build
            .manifest
            .binaries
            .iter()
            .map(|binary| {
                (
                    binary.name.clone(),
                    if check_integration {
                        destination.join(&binary.name)
                    } else {
                        bundle_layout.as_ref().map_or_else(
                            || destination.join(&binary.name),
                            |layout| layout.program(&binary.name),
                        )
                    },
                )
            })
            .collect::<BTreeMap<_, _>>()
    });
    let integration_temp_dir = (selected_integration || check_integration).then(|| {
        if check_integration {
            destination.clone()
        } else {
            bundle_layout.as_ref().map_or_else(
                || target_root.join("tmp"),
                bundle::Layout::temporary_directory,
            )
        }
    });
    if let Some(directory) = &integration_temp_dir
        && !check_integration
        && bundle_layout.is_none()
    {
        fs::create_dir_all(directory).map_err(|error| {
            Error::failure(format!(
                "failed to create test temporary directory `{}`: {error}",
                directory.display()
            ))
        })?;
    }
    let executor_options = executor::Options {
        cargo: &cargo,
        child_lease_fd: build.child_lease_fd,
        workspace_root: &build.manifest.workspace_root,
        workspace_members: &build.manifest.workspace_members,
        selected_packages: &selected_packages,
        toolchain: build.toolchain,
        host: build.host,
        target: build.target,
        host_profile: &host_profile,
        target_profile: &destination,
        host_incremental: &incremental.host,
        target_incremental: &incremental.target,
        physical_target: build.physical_target,
        host_linker: build.host_options.linker.as_deref(),
        target_linker: build.target_options.linker.as_deref(),
        integration_binaries: integration_binaries.as_ref(),
        integration_temp_dir: integration_temp_dir.as_deref(),
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
        jobs: build.jobs,
        keep_going: build.keep_going || check.is_some_and(|(_, options)| options.keep_going),
        reporter: Some(&message_reporter),
    };
    if let Some((_, options)) = check {
        let members = build
            .members
            .unwrap_or_else(|| std::slice::from_ref(build.manifest));
        if options.lib && members.iter().all(|member| member.library.is_none()) {
            return Err(Error::failure("selected package has no library target"));
        }
        validate_member_binary_selection(members, options.bin.as_deref())?;
        if let Some(name) = options.test.as_deref()
            && !build
                .manifest
                .integration_tests
                .iter()
                .any(|target| target.name == name)
        {
            return Err(unknown_integration_test(build.manifest, name));
        }
        let plan = selected_check_plan(&CheckTargetSelection {
            normal: options.selects_library() || options.selects_binaries(),
            binaries: options.selects_binaries(),
            binary_name: if options.all_targets || options.bins {
                None
            } else {
                options.bin.as_deref()
            },
            harnesses: options.all_targets,
            integrations: options.selects_tests(),
            integration_name: if options.all_targets {
                None
            } else {
                options.test.as_deref()
            },
        })?;
        executor::execute(&plan, &manifests, &executor_options)?;
        if build.validation.is_strict() {
            prepared.revalidate_cargo_registry_sources(repository_tree_limits(
                &build.config.policy.limits,
            )?)?;
        }
        drop(prepared);
        if build.verbosity != Verbosity::Quiet {
            eprintln!("Finished `check` profile");
        }
        return Ok(BuildOutcome::Check(0));
    }
    invalidate_fresh_profile(&destination, &build.manifest.root)?;
    let needs_normal_plan =
        !build.test || (selected_integration && !build.manifest.binaries.is_empty());
    let normal = if needs_normal_plan || selected_integration {
        let plan = if selected_integration {
            if let Some(name) = build.test_name
                && !build
                    .manifest
                    .integration_tests
                    .iter()
                    .any(|target| target.name == name)
            {
                return Err(unknown_integration_test(build.manifest, name));
            }
            prepared.selected_mixed_test_plan(
                &PlanOptions {
                    workspace_root: &build.manifest.workspace_root,
                    release: build.release,
                    test_profile: false,
                    panic_abort: build.manifest.panic_abort(build.release),
                    release_profile: &build.manifest.release,
                    rustc: build.toolchain,
                    logical_target: build.logical_target,
                    rustflags: build.rustflags,
                },
                build.manifest,
                build.test_name.is_none(),
                build.test_name,
            )?
        } else {
            dependency_plan(false, !build.test, !build.test, false)?
        };
        if build.verbosity != Verbosity::Quiet {
            for warning in binary_collision_warnings(&plan, &selected_packages, &destination) {
                eprintln!("{warning}");
            }
        }
        let outputs = executor::execute(&plan, &manifests, &executor_options)?;
        crate::trace::event(format_args!(
            "executed {} normal dependency units",
            plan.units.len()
        ));
        Some((plan, outputs))
    } else {
        None
    };
    let needs_test_plan = !selected_integration && build.test;
    let test_result = if needs_test_plan {
        let test_plan = dependency_plan(
            true,
            build.test,
            false,
            build.test && build.test_name.is_none(),
        )?;
        let outputs = match normal.as_ref() {
            Some((normal_plan, normal_outputs)) => executor::execute_reusing(
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
        let harnesses = test_plan
            .order
            .iter()
            .filter(|key| matches!(key.kind, UnitKind::LibraryHarness | UnitKind::BinaryHarness))
            .map(|key| match outputs.artifacts.get(key) {
                Some(crate::compile::RustcOutput::Binary { executable, .. }) => {
                    Ok(executable.clone())
                }
                _ => Err(Error::failure(
                    "selected test harness produced no executable",
                )),
            })
            .collect::<Result<Vec<_>>>()?;
        Some(harnesses)
    } else {
        None
    };
    let test_harnesses = test_result.as_deref().unwrap_or(&[]);
    let workspace_library = build.members.and_then(|_| {
        normal.as_ref()?.0.order.iter().find(|key| {
            selected_packages.contains(&key.package)
                && key.kind == UnitKind::Library
                && key.compile_kind == crate::resolver::CompileKind::Target
        })
    });
    let normal_library = match (
        normal.as_ref(),
        workspace_library.or(selected_library.as_ref()),
    ) {
        (Some((plan, outputs)), Some(key)) if plan.units.contains_key(key) => {
            Some(planned_root_library(outputs, key)?)
        }
        _ => None,
    };
    if build.validation.is_strict() {
        prepared.revalidate_cargo_registry_sources(repository_tree_limits(
            &build.config.policy.limits,
        )?)?;
        crate::trace::event("revalidated dependency sources");
    }
    let mut compiled = if selected_integration {
        let (plan, outputs) = normal
            .as_ref()
            .ok_or_else(|| Error::failure("integration test has no compilation plan"))?;
        compile_planned_test_targets(
            &build,
            &destination,
            plan,
            outputs,
            &TestOutput {
                bundle_layout: bundle_layout.as_ref(),
            },
        )?
    } else if build.test {
        compile_test_targets(
            &build,
            &destination,
            test_harnesses,
            &TestOutput {
                bundle_layout: bundle_layout.as_ref(),
            },
        )?
    } else {
        let (normal_plan, normal_outputs) = normal
            .as_ref()
            .ok_or_else(|| Error::failure("build has no normal compilation plan"))?;
        compile_root_targets(
            build.manifest,
            &destination,
            &selected_packages,
            normal_plan,
            normal_outputs,
            normal_library.as_ref(),
        )?
    };
    crate::trace::event("compiled root targets");
    compiled.messages = message_reporter.messages();
    compiled.library_paths = runtime_library_paths(&build, &destination, &compiled.messages)?;
    if let Some((_, outputs)) = &normal {
        // Member inputs outside their directories must also invalidate the
        // completed-profile shortcut before any compiler units are visited.
        compiled.dep_info.extend(
            outputs
                .artifacts
                .iter()
                .filter(|(key, _)| manifests[&key.package].editable)
                .map(|(_, output)| output.dep_info().to_owned()),
        );
        compiled.dep_info.sort();
        compiled.dep_info.dedup();
        compiled.script_inputs = outputs
            .build_scripts
            .values()
            .flat_map(|script| {
                script.output.directives.iter().filter_map(|directive| {
                    if let crate::build_script::Directive::RerunIfChanged(path) = directive {
                        Some(path.clone())
                    } else {
                        None
                    }
                })
            })
            .collect();
        compiled.script_inputs.sort();
        compiled.script_inputs.dedup();
    }

    if let Some(base) = freshness_base {
        write_fresh_profile(
            &destination,
            &build.manifest.workspace_root,
            &build.manifest.root,
            base,
            &compiled,
            &local_source_roots(&prepared.resolution),
            build.validation,
        )?;
        crate::trace::event("wrote root freshness record");
    }

    drop(prepared);
    let artifacts = BuildArtifacts {
        primary: compiled.primary,
        binaries: compiled.binaries,
        harnesses: compiled.harnesses,
        bundle: compiled.bundle,
        messages: compiled.messages,
        library_paths: compiled.library_paths,
    };

    crate::trace::event("published build profile");
    finish_build(&build, &artifacts)?;
    crate::trace::event("reported build result");
    Ok(BuildOutcome::Artifacts(artifacts))
}

fn finish_build(build: &Build<'_>, artifacts: &BuildArtifacts) -> Result<()> {
    report_finished(build.release, build.verbosity, build.validation, artifacts)
}

fn runtime_library_paths(
    build: &Build<'_>,
    profile: &Path,
    messages: &[serde_json::Value],
) -> Result<Vec<PathBuf>> {
    let mut native = std::collections::BTreeSet::new();
    let mut dependencies = std::collections::BTreeSet::new();
    for message in messages {
        match message.get("reason").and_then(serde_json::Value::as_str) {
            Some("build-script-executed") => {
                for value in message["linked_paths"].as_array().into_iter().flatten() {
                    let value = value
                        .as_str()
                        .ok_or_else(|| Error::failure("invalid linked path"))?;
                    let path = ["native=", "dependency=", "crate=", "all=", "framework="]
                        .iter()
                        .find_map(|kind| value.strip_prefix(kind))
                        .unwrap_or(value);
                    let path = PathBuf::from(path);
                    if path.starts_with(profile) {
                        native.insert(path);
                    }
                }
            }
            Some("compiler-artifact") => {
                for value in message["filenames"].as_array().into_iter().flatten() {
                    if let Some(path) = value.as_str().and_then(|path| Path::new(path).parent())
                        && path.starts_with(profile)
                    {
                        dependencies.insert(path.to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    let mut arguments = vec![OsString::from("--print"), OsString::from("target-libdir")];
    if let Some(target) = build.physical_target {
        arguments.extend([OsString::from("--target"), target.into()]);
    }
    arguments.extend(build.rustflags.iter().map(OsString::from));
    let output = process::RustcCommand {
        child_lease_fd: build.child_lease_fd,
        program: &build.toolchain.rustc,
        arguments: &arguments,
        environment: &BTreeMap::new(),
        current_dir: &build.manifest.workspace_root,
        verbose: build.verbosity == Verbosity::Verbose,
        color: false,
    }
    .execute()?;
    process::RustcCommand::require_success(&output)?;
    let library = std::str::from_utf8(&output.stdout)
        .map_err(|_| Error::failure("rustc target library directory is not Unicode"))?
        .trim();
    let library = PathBuf::from(library);
    if !library.is_absolute() {
        return Err(Error::failure(
            "rustc target library directory is not absolute",
        ));
    }
    Ok(native
        .into_iter()
        .chain(std::iter::once(profile.to_owned()))
        .chain(dependencies)
        .chain(std::iter::once(library))
        .collect())
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

const FRESH_PROFILE_FILE: &str = ".lorry-fresh-v6";
const MAX_FRESH_PROFILE_BYTES: u64 = 4 * 1024 * 1024;
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
    local_roots: Vec<LocalSource>,
    dep_info: Vec<PathBuf>,
    script_inputs: Vec<PathBuf>,
    script_inputs_sha256: [u8; 32],
    messages: Vec<serde_json::Value>,
    library_paths: Vec<PathBuf>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LocalSource {
    root: PathBuf,
    editable: bool,
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
    jobs: usize,
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
    digest.debug("jobs", &inputs.jobs);
    digest.metadata("lorry", inputs.cargo)?;
    digest.metadata("rustc", &inputs.toolchain.rustc)?;
    digest.metadata(
        "workspace-manifest",
        &inputs.manifest.workspace_root.join("Cargo.toml"),
    )?;
    for (name, value) in env::vars_os().collect::<BTreeMap<_, _>>() {
        if process::is_removed_cargo_client_environment(&name) {
            continue;
        }
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
    digest.debug("jobs", &build.jobs);
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
        if process::is_removed_cargo_client_environment(&name) {
            continue;
        }
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
    owner_root: &Path,
    base: [u8; 32],
    validation: ValidationMode,
) -> Option<BuildArtifacts> {
    let record = read_fresh_profile(profile, owner_root)?;
    if record.base != base {
        return None;
    }
    if script_input_digest(&record.script_inputs).ok() != Some(record.script_inputs_sha256) {
        return None;
    }
    for message in &record.messages {
        match message.get("reason")?.as_str()? {
            "compiler-artifact" => {
                let filenames = message.get("filenames")?.as_array()?;
                if filenames.is_empty()
                    || !filenames
                        .iter()
                        .all(|path| path.as_str().is_some_and(|path| Path::new(path).is_file()))
                {
                    return None;
                }
            }
            "build-script-executed" if !Path::new(message.get("out_dir")?.as_str()?).is_dir() => {
                return None;
            }
            _ => {}
        }
        if let Some(target) = message.get("target")
            && !Path::new(target.get("src_path")?.as_str()?).is_file()
        {
            return None;
        }
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
        messages: record.messages,
        library_paths: record.library_paths,
    })
}

fn write_fresh_profile(
    profile: &Path,
    package_root: &Path,
    owner_root: &Path,
    base: [u8; 32],
    artifacts: &StagedArtifacts,
    local_roots: &[LocalSource],
    validation: ValidationMode,
) -> Result<()> {
    let primary = relative_profile_path(profile, &artifacts.primary)?;
    let mut dep_info = artifacts
        .dep_info
        .iter()
        .map(|path| {
            if path.starts_with(profile) {
                relative_profile_path(profile, path)
            } else {
                Ok(path.clone())
            }
        })
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
        "lorry-fresh-v6\nbase={}\ninputs={}\nscript-inputs={}\nprimary={}\t{}\nmessages={}\n",
        hex(&base),
        hex(&inputs),
        hex(&script_input_digest(&artifacts.script_inputs)?),
        hex(&primary_sha256),
        primary.display(),
        serde_json::to_string(&artifacts.messages).map_err(|error| {
            Error::failure(format!("failed to serialize profile messages: {error}"))
        })?,
    );
    for (name, path) in &artifacts.binaries {
        let relative = relative_profile_path(profile, path)?;
        document.push_str(&format!(
            "binary={name}\t{}\t{}\n",
            hex(&artifact_sha256(path)?),
            relative.display()
        ));
    }
    for source in local_roots {
        let Some(root) = source.root.to_str() else {
            return Ok(());
        };
        let kind = if source.editable {
            "editable-root"
        } else {
            "local-root"
        };
        document.push_str(&format!("{kind}={}\n", hex(root.as_bytes())));
    }
    for path in &artifacts.script_inputs {
        let Some(path) = path.to_str() else {
            return Ok(());
        };
        document.push_str(&format!("script-input={}\n", hex(path.as_bytes())));
    }
    for path in &artifacts.library_paths {
        let path = path
            .to_str()
            .ok_or_else(|| Error::failure("runtime library path is not Unicode"))?;
        document.push_str(&format!("library-path={}\n", hex(path.as_bytes())));
    }
    for path in dep_info {
        if path.is_absolute() {
            let path = path
                .to_str()
                .ok_or_else(|| Error::failure("dep-info path is not Unicode"))?;
            document.push_str(&format!("dep-info-absolute={}\n", hex(path.as_bytes())));
        } else {
            document.push_str(&format!("dep-info={}\n", path.display()));
        }
    }
    let mut record = AtomicFile::new(&fresh_record_path(profile, owner_root))?;
    record.write_all(document.as_bytes())?;
    record.commit()
}

fn read_fresh_profile(profile: &Path, package_root: &Path) -> Option<FreshProfile> {
    let path = fresh_record_path(profile, package_root);
    let metadata = fs::symlink_metadata(&path).ok()?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_FRESH_PROFILE_BYTES {
        return None;
    }
    let document = String::from_utf8(fs::read(path).ok()?).ok()?;
    let mut lines = document.lines();
    (lines.next()? == "lorry-fresh-v6").then_some(())?;
    let base = decode_hex(lines.next()?.strip_prefix("base=")?).ok()?;
    let inputs = decode_hex(lines.next()?.strip_prefix("inputs=")?).ok()?;
    let script_inputs_sha256 = decode_hex(lines.next()?.strip_prefix("script-inputs=")?).ok()?;
    let primary = parse_fresh_artifact(lines.next()?.strip_prefix("primary=")?)?;
    let messages: Vec<serde_json::Value> =
        serde_json::from_str(lines.next()?.strip_prefix("messages=")?).ok()?;
    messages
        .iter()
        .all(|message| {
            matches!(
                message.get("reason").and_then(serde_json::Value::as_str),
                Some(
                    "compiler-artifact"
                        | "compiler-message"
                        | "build-script-executed"
                        | "rustc-stderr"
                )
            )
        })
        .then_some(())?;
    let mut binaries = BTreeMap::new();
    let mut local_roots = Vec::new();
    let mut dep_info = Vec::new();
    let mut script_inputs = Vec::new();
    let mut library_paths = Vec::new();
    for line in lines {
        if let Some(value) = line.strip_prefix("binary=") {
            let (name, artifact) = value.split_once('\t')?;
            if binaries
                .insert(name.to_owned(), parse_fresh_artifact(artifact)?)
                .is_some()
            {
                return None;
            }
        } else if let Some(value) = line
            .strip_prefix("local-root=")
            .or_else(|| line.strip_prefix("editable-root="))
        {
            local_roots.push(LocalSource {
                root: PathBuf::from(String::from_utf8(decode_bytes(value)?).ok()?),
                editable: line.starts_with("editable-root="),
            });
        } else if let Some(value) = line.strip_prefix("script-input=") {
            let path = PathBuf::from(String::from_utf8(decode_bytes(value)?).ok()?);
            path.is_absolute().then_some(())?;
            script_inputs.push(path);
        } else if let Some(value) = line.strip_prefix("dep-info-absolute=") {
            let path = PathBuf::from(String::from_utf8(decode_bytes(value)?).ok()?);
            path.is_absolute().then_some(())?;
            dep_info.push(path);
        } else if let Some(value) = line.strip_prefix("library-path=") {
            let path = PathBuf::from(String::from_utf8(decode_bytes(value)?).ok()?);
            path.is_absolute().then_some(())?;
            library_paths.push(path);
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
        script_inputs,
        script_inputs_sha256,
        messages,
        library_paths,
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

fn script_input_digest(inputs: &[PathBuf]) -> Result<[u8; 32]> {
    let mut digest = FreshDigest::new();
    let mut pending = inputs.to_vec();
    let mut directories = std::collections::BTreeSet::new();
    while let Some(path) = pending.pop() {
        let canonical = fs::canonicalize(&path).map_err(|error| {
            Error::failure(format!(
                "failed to resolve build-script input `{}`: {error}",
                path.display()
            ))
        })?;
        digest.os("script-input-path", path.as_os_str());
        digest.os("script-input-resolved", canonical.as_os_str());
        let metadata = fs::metadata(&canonical).map_err(|error| {
            Error::failure(format!(
                "failed to inspect build-script input `{}`: {error}",
                path.display()
            ))
        })?;
        if metadata.is_file() {
            digest.file("script-input-file", &canonical)?;
        } else if metadata.is_dir() {
            digest.bytes("script-input-kind", b"directory");
            // Canonical identities prevent loops without hiding link retargets.
            if directories.insert(canonical) {
                let mut children = fs::read_dir(&path)
                    .map_err(|error| Error::failure(error.to_string()))?
                    .map(|entry| {
                        entry
                            .map(|entry| entry.path())
                            .map_err(|error| Error::failure(error.to_string()))
                    })
                    .collect::<Result<Vec<_>>>()?;
                children.sort();
                pending.extend(children);
            }
        } else {
            return Err(Error::failure(format!(
                "build-script input `{}` is not a regular file or directory",
                path.display()
            )));
        }
    }
    Ok(digest.finish())
}

fn trusted_input_digest(
    profile: &Path,
    package_root: &Path,
    dep_info: &[PathBuf],
    local_roots: &[LocalSource],
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
    for source in local_roots {
        if source.editable {
            let mut manifest = Manifest::load_path_dependency(&source.root)?;
            manifest.workspace_root.clone_from(&root);
            digest.bytes(
                "editable-source",
                &crate::member_source::snapshot(&manifest, false)?.sha256,
            );
        } else {
            metadata_tree_digest(&source.root, &mut digest)?;
        }
    }
    Ok(digest.finish())
}

fn local_source_roots(resolution: &Resolution) -> Vec<LocalSource> {
    let mut roots = resolution
        .packages
        .iter()
        .filter_map(|package| match &package.source {
            crate::resolver::ResolvedSource::Path { physical_root, .. } => Some(LocalSource {
                root: physical_root.clone(),
                editable: package
                    .local_manifest
                    .as_ref()
                    .is_some_and(|manifest| manifest.editable),
            }),
            crate::resolver::ResolvedSource::Git { physical_root, .. } => Some(LocalSource {
                root: physical_root.clone(),
                editable: false,
            }),
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

/// A CLI job count overrides `LORRY_JOBS`; an omitted setting retains the
/// positive environment count or available hardware parallelism.
fn compile_jobs(requested: Option<crate::cli::Jobs>) -> usize {
    let cpus = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    if let Some(requested) = requested {
        return requested.resolve(cpus);
    }
    env::var("LORRY_JOBS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|jobs| *jobs >= 1)
        .unwrap_or(cpus)
}

struct RootLibraryArtifact {
    extern_path: PathBuf,
    dep_info: PathBuf,
}

fn planned_root_library(outputs: &executor::Outputs, key: &UnitKey) -> Result<RootLibraryArtifact> {
    let Some(crate::compile::RustcOutput::Library { rlib, dep_info, .. }) =
        outputs.artifacts.get(key)
    else {
        return Err(Error::failure(
            "selected library produced no library artifact",
        ));
    };
    Ok(RootLibraryArtifact {
        extern_path: rlib.clone(),
        dep_info: dep_info.clone(),
    })
}

struct StagedArtifacts {
    primary: PathBuf,
    binaries: BTreeMap<String, PathBuf>,
    harnesses: Vec<PathBuf>,
    bundle: Option<PathBuf>,
    dep_info: Vec<PathBuf>,
    script_inputs: Vec<PathBuf>,
    messages: Vec<serde_json::Value>,
    library_paths: Vec<PathBuf>,
}

struct TestOutput<'a> {
    bundle_layout: Option<&'a bundle::Layout>,
}

impl CheckOptions {
    fn has_target_selector(&self) -> bool {
        self.all_targets
            || self.lib
            || self.bins
            || self.bin.is_some()
            || self.test.is_some()
            || self.examples
    }

    fn selects_library(&self) -> bool {
        self.all_targets || self.lib || !self.has_target_selector()
    }

    fn selects_binaries(&self) -> bool {
        self.all_targets || self.bins || self.bin.is_some() || !self.has_target_selector()
    }

    fn selects_tests(&self) -> bool {
        self.all_targets || self.test.is_some()
    }
}

fn binary_collision_warnings(
    plan: &CompilationPlan,
    selected: &[PackageKey],
    profile: &Path,
) -> Vec<String> {
    let mut names = BTreeMap::new();
    let mut warnings = Vec::new();
    let describe = |package: &PackageKey| match &package.source {
        crate::resolver::PackageSourceKey::Path(root) => {
            format!("{} v{} ({})", package.name, package.version, root.display())
        }
        _ => format!("{} v{}", package.name, package.version),
    };
    for key in plan.order.iter().filter(|key| {
        key.kind == UnitKind::Binary
            && key.mode == crate::unit::UnitMode::Build
            && selected.contains(&key.package)
    }) {
        let Some(name) = key.target.as_deref() else {
            continue;
        };
        if let Some(previous) = names.insert(name, &key.package) {
            warnings.push(format!(
                "warning: output filename collision at {}\n\
                 note: the bin target `{name}` in package `{}` has the same output filename as the bin target `{name}` in package `{}`\n\
                 note: this may become a hard error in the future; see <https://github.com/rust-lang/cargo/issues/6313>\n\
                 help: consider changing their names to be unique or compiling them separately",
                profile.join(name).display(), describe(&key.package), describe(previous),
            ));
        }
    }
    warnings
}

fn compile_root_targets(
    manifest: &Manifest,
    staging: &Path,
    selected: &[PackageKey],
    plan: &CompilationPlan,
    outputs: &executor::Outputs,
    library: Option<&RootLibraryArtifact>,
) -> Result<StagedArtifacts> {
    let mut binaries = BTreeMap::new();
    let mut binary_dep_info = Vec::new();
    for key in plan
        .order
        .iter()
        .filter(|key| selected.contains(&key.package) && key.kind == UnitKind::Binary)
    {
        let name = key
            .target
            .as_ref()
            .ok_or_else(|| Error::failure("planned binary has no target name"))?;
        let Some(crate::compile::RustcOutput::Binary {
            executable,
            dep_info,
        }) = outputs.artifacts.get(key)
        else {
            return Err(Error::failure(format!(
                "selected binary `{name}` produced no executable artifact"
            )));
        };
        let primary = staging.join(name);
        install_primary(executable, &primary, &key.package)?;
        binary_dep_info.push(dep_info.clone());
        binaries.insert(name.clone(), primary);
    }
    if let Some(primary) = binaries.values().next().cloned() {
        let mut dep_info = library
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
            script_inputs: Vec::new(),
            messages: Vec::new(),
            library_paths: Vec::new(),
        });
    }
    let library = library.ok_or_else(|| {
        Error::failure(format!(
            "package `{}` has no supported root target",
            manifest.name
        ))
    })?;
    Ok(StagedArtifacts {
        primary: library.extern_path.clone(),
        binaries,
        harnesses: Vec::new(),
        bundle: None,
        dep_info: vec![library.dep_info.clone()],
        script_inputs: Vec::new(),
        messages: Vec::new(),
        library_paths: Vec::new(),
    })
}

fn compile_test_targets(
    build: &Build<'_>,
    staging: &Path,
    planned_harnesses: &[PathBuf],
    output: &TestOutput<'_>,
) -> Result<StagedArtifacts> {
    let harnesses = planned_harnesses.to_vec();
    let first_harness = harnesses.first().cloned().ok_or_else(|| {
        Error::failure(format!(
            "package `{}` has no enabled test targets",
            build.manifest.name
        ))
    })?;
    let bundled = output
        .bundle_layout
        .map(|layout| {
            if build.verbosity != Verbosity::Quiet {
                eprintln!("Bundling {} test targets", harnesses.len());
            }
            bundle::build(&bundle::BuildOptions {
                child_lease_fd: build.child_lease_fd,
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
                programs: &[],
            })
        })
        .transpose()?;
    Ok(StagedArtifacts {
        primary: bundled.clone().unwrap_or(first_harness),
        binaries: BTreeMap::new(),
        harnesses,
        bundle: bundled,
        dep_info: Vec::new(),
        script_inputs: Vec::new(),
        messages: Vec::new(),
        library_paths: Vec::new(),
    })
}

fn compile_planned_test_targets(
    build: &Build<'_>,
    staging: &Path,
    plan: &CompilationPlan,
    outputs: &executor::Outputs,
    output: &TestOutput<'_>,
) -> Result<StagedArtifacts> {
    let selected = selected_library_key(build.manifest)?.package;
    let mut programs = BTreeMap::new();
    let mut harnesses = Vec::new();
    for key in &plan.order {
        if key.package != selected {
            continue;
        }
        match key.kind {
            UnitKind::Binary => {
                let name = key
                    .target
                    .as_ref()
                    .ok_or_else(|| Error::failure("selected program unit has no target name"))?;
                let Some(crate::compile::RustcOutput::Binary { executable, .. }) =
                    outputs.artifacts.get(key)
                else {
                    return Err(Error::failure(format!(
                        "selected program `{name}` produced no executable"
                    )));
                };
                let primary = staging.join(name);
                install_primary(executable, &primary, &selected)?;
                programs.insert(name.clone(), primary);
            }
            UnitKind::LibraryHarness | UnitKind::BinaryHarness | UnitKind::IntegrationHarness => {
                let Some(crate::compile::RustcOutput::Binary { executable, .. }) =
                    outputs.artifacts.get(key)
                else {
                    return Err(Error::failure(
                        "selected test harness produced no executable",
                    ));
                };
                harnesses.push(executable.clone());
            }
            _ => {}
        }
    }
    let first_harness = harnesses.first().cloned().ok_or_else(|| {
        Error::failure(format!(
            "package `{}` has no enabled test targets",
            build.manifest.name
        ))
    })?;
    let bundle_programs = programs
        .iter()
        .map(|(name, path)| (name.as_str(), path.as_path()))
        .collect::<Vec<_>>();
    let bundled = output
        .bundle_layout
        .map(|layout| {
            if build.verbosity != Verbosity::Quiet {
                eprintln!("Bundling {} test targets", harnesses.len());
            }
            bundle::build(&bundle::BuildOptions {
                child_lease_fd: build.child_lease_fd,
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
        binaries: programs,
        harnesses,
        bundle: bundled,
        dep_info: Vec::new(),
        script_inputs: Vec::new(),
        messages: Vec::new(),
        library_paths: Vec::new(),
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

fn install_primary(source: &Path, destination: &Path, package: &PackageKey) -> Result<()> {
    crate::artifact_owner::invalidate_primary(destination)?;
    AtomicFile::from_executable(source, destination)?.commit()?;
    crate::artifact_owner::write_primary(destination, package)
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
    current_dir: &Path,
    environment: &BTreeMap<String, OsString>,
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
        current_dir,
        environment,
        verbosity == Verbosity::Verbose,
    )
}

pub(crate) fn matching_cfgs(config: &Config, target: &TargetInfo) -> Result<Vec<String>> {
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

fn use_color(color: Color) -> bool {
    match color {
        Color::Always => true,
        Color::Never => false,
        Color::Auto => env::var_os("NO_COLOR").is_none() && std::io::stderr().is_terminal(),
    }
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
    fn executes_shared_selected_members_and_reuses_their_units() {
        use std::os::unix::fs::MetadataExt;

        let fixture = Fixture::new();
        let path = fixture.0.join("Cargo.toml");
        fs::write(
            &path,
            format!(
                "{}\n[workspace]\nmembers = [\"local\"]\nresolver = \"2\"\n",
                fs::read_to_string(&path).unwrap()
            ),
        )
        .unwrap();
        let (_, members) = crate::manifest::SourceWorkspace::load_compilation(
            &fixture.0,
            None,
            &crate::manifest::PackageSelection {
                workspace: true,
                ..Default::default()
            },
        )
        .unwrap();
        let manifest = members
            .iter()
            .find(|member| member.name == "root-bin")
            .unwrap();
        let mut workspace = crate::manifest::SourceWorkspace::load(&fixture.0, None).unwrap();
        workspace.load_locked_context().unwrap();
        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_99);
        let toolchain = Toolchain::discover(None, &config, false).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let options = dependency::resolver_options(manifest, &config, &toolchain).unwrap();
        let repositories = RepositorySet::open(
            &config.repositories,
            repository_tree_limits(&config.policy.limits).unwrap(),
            config.policy.limits.max_package_bytes,
        )
        .unwrap();
        let source = dependency::RegistrySource::Lorry(&repositories);
        let direct = crate::git::DirectCatalog::default();
        let (complete, catalog) =
            dependency::workspace::resolve_locked(&workspace, &config, source, &direct, &options)
                .unwrap();
        let requests = crate::resolver::workspace::features::member_requests(
            &workspace,
            &members.iter().map(|member| member.root.clone()).collect(),
            &crate::cli::FeatureSelection::default(),
            false,
        )
        .unwrap();
        let resolution = crate::resolver::workspace::resolve_selected_workspace(
            &complete,
            &catalog,
            &options,
            &requests,
            TargetSelection {
                host_triple: &target.triple,
                host_cfg: &target.cfg,
                target_triple: &target.triple,
                target_cfg: &target.cfg,
            },
        )
        .unwrap();
        let selected_without_admission = dependency::workspace::resolve_compilation(
            &dependency::ReviewInputs {
                manifest,
                config: &config,
                source,
                toolchain: &toolchain,
                options: &options,
                staging_parent: &fixture.0,
                direct: Some(&direct),
                prepare_context: None,
            },
            &workspace,
            &requests,
            TargetSelection {
                host_triple: &target.triple,
                host_cfg: &target.cfg,
                target_triple: &target.triple,
                target_cfg: &target.cfg,
            },
        )
        .unwrap();
        assert_eq!(selected_without_admission, resolution);
        assert!(!CompactState::path(&fixture.0).exists());
        assert!(!fixture.0.join("target").exists());
        let target_options = TargetOptions::default();
        let global_cache = fixture.0.join("global-cache");
        let target_root = artifact_root(manifest);
        let build_once = |check_options| {
            build_inner(
                Build {
                    manifest,
                    members: Some(&members),
                    target_root: Some(&target_root),
                    child_lease_fd: None,
                    global_cache_root: &global_cache,
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
                    jobs: 2,
                    keep_going: false,
                    use_cargo_registry: false,
                    source: Some((source, &direct, Some(resolution.clone()))),
                    bundle: false,
                    validation: ValidationMode::Trusted,
                    ordinary_freshness_base: None,
                    binary_selection: None,
                },
                check_options,
                MessageFormat::Human,
            )
            .unwrap()
        };
        let BuildOutcome::Artifacts(cold) = build_once(None) else {
            panic!("expected artifacts")
        };
        let output = std::process::Command::new(&cold.primary).output().unwrap();
        assert_eq!(output.stdout, b"dependency-ok");
        let libraries = cold
            .messages
            .iter()
            .filter(|message| {
                message["reason"] == "compiler-artifact" && message["target"]["kind"][0] == "lib"
            })
            .collect::<Vec<_>>();
        assert_eq!(libraries.len(), 1, "selected dependency must compile once");
        let inode = fs::metadata(&cold.primary).unwrap().ino();
        let BuildOutcome::Artifacts(warm) = build_once(None) else {
            panic!("expected artifacts")
        };
        assert_eq!(fs::metadata(&warm.primary).unwrap().ino(), inode);
        assert!(
            warm.messages
                .iter()
                .filter(|message| message["reason"] == "compiler-artifact")
                .all(|message| message["fresh"] == true)
        );
        let cli = Cli::parse(["check"].map(str::to_owned)).unwrap();
        let Command::Check(options) = cli.command else {
            panic!("expected check")
        };
        assert!(matches!(
            build_once(Some((&target_root, &options))),
            BuildOutcome::Check(0)
        ));
        assert!(!target_root.join("check/root-bin").exists());
    }

    #[test]
    fn selected_workspace_binaries_publish_with_their_own_package_owners() {
        let fixture = Fixture::new();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let first = selected_library_key(&manifest).unwrap().package;
        let second = PackageKey {
            name: "second".to_owned(),
            source: crate::resolver::PackageSourceKey::Path(fixture.0.join("second")),
            ..first.clone()
        };
        let unselected = PackageKey {
            name: "unselected".to_owned(),
            source: crate::resolver::PackageSourceKey::Path(fixture.0.join("unselected")),
            ..first.clone()
        };
        let destination = fixture.0.join("published");
        fs::create_dir(&destination).unwrap();
        let mut plan = CompilationPlan {
            units: BTreeMap::new(),
            order: Vec::new(),
        };
        let mut outputs = executor::Outputs::default();
        for package in [&first, &second, &unselected] {
            let executable = fixture.0.join(format!("{}-executable", package.name));
            fs::write(&executable, &package.name).unwrap();
            let key = UnitKey {
                package: package.clone(),
                kind: UnitKind::Binary,
                target: Some(package.name.clone()),
                ..selected_library_key(&manifest).unwrap()
            };
            outputs.artifacts.insert(
                key.clone(),
                crate::compile::RustcOutput::Binary {
                    executable,
                    dep_info: fixture.0.join(format!("{}.d", package.name)),
                },
            );
            plan.order.push(key);
        }
        let published = compile_root_targets(
            &manifest,
            &destination,
            &[first.clone(), second.clone()],
            &plan,
            &outputs,
            None,
        )
        .unwrap();
        assert_eq!(published.binaries.len(), 2);
        assert_eq!(published.dep_info.len(), 2);
        for package in [&first, &second] {
            let binary = &published.binaries[&package.name];
            assert_eq!(fs::read_to_string(binary).unwrap(), package.name);
            assert!(crate::artifact_owner::matches_primary(binary, package));
            assert!(!crate::artifact_owner::matches_primary(binary, &unselected));
        }
        assert!(!destination.join(&unselected.name).exists());
        let selection = [first.clone(), second.clone()];
        assert!(binary_collision_warnings(&plan, &selection, &destination).is_empty());
        plan.order[1].target = Some(first.name.clone());
        let warnings = binary_collision_warnings(&plan, &selection, &destination);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("output filename collision"));
        assert!(warnings[0].contains(&format!("package `{} v", first.name)));
        assert!(warnings[0].contains(&format!("package `{} v", second.name)));
        plan.order[1].mode = crate::unit::UnitMode::Check;
        assert!(binary_collision_warnings(&plan, &selection, &destination).is_empty());
    }

    #[test]
    fn legacy_layout_reset_is_scoped_and_runs_once() {
        let fixture = Fixture::new();
        let root = fixture.0.join("target/lorry");
        fs::create_dir_all(root.join("packages/app/debug")).unwrap();
        fs::write(root.join("packages/app/debug/app"), b"old").unwrap();
        let cargo_artifact = fixture.0.join("target/debug/app");
        fs::create_dir_all(cargo_artifact.parent().unwrap()).unwrap();
        fs::write(&cargo_artifact, b"cargo").unwrap();

        migrate_artifact_layout(&root).unwrap();
        assert!(!root.join("packages").exists());
        assert_eq!(fs::read(&cargo_artifact).unwrap(), b"cargo");
        fs::write(root.join("new-artifact"), b"new").unwrap();
        migrate_artifact_layout(&root).unwrap();
        assert_eq!(fs::read(root.join("new-artifact")).unwrap(), b"new");
    }

    #[test]
    fn invalidating_one_package_keeps_another_freshness_record() {
        let fixture = Fixture::new();
        let profile = fixture.0.join("target/lorry/debug");
        fs::create_dir_all(&profile).unwrap();
        let first = fresh_record_path(&profile, &fixture.0.join("first"));
        let second = fresh_record_path(&profile, &fixture.0.join("second"));
        assert_ne!(first, second);
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        invalidate_fresh_profile(&profile, &fixture.0.join("first")).unwrap();
        assert!(!first.exists());
        assert_eq!(fs::read(second).unwrap(), b"second");
    }

    #[test]
    fn completed_profiles_track_script_files_directories_and_symlink_retargets() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new();
        let profile = fixture.0.join("target/lorry/debug");
        let directory = fixture.0.join("workspace-inputs");
        fs::create_dir_all(&profile).unwrap();
        fs::create_dir(&directory).unwrap();
        let first = fixture.0.join("first-input");
        let second = fixture.0.join("second-input");
        let link = fixture.0.join("script-input");
        fs::write(&first, b"same").unwrap();
        fs::write(&second, b"same").unwrap();
        symlink(&first, &link).unwrap();
        let artifact = profile.join("root-bin");
        let dep_info = profile.join("root-bin.d");
        fs::write(&artifact, b"artifact").unwrap();
        fs::write(
            &dep_info,
            format!(
                "{}: {}\n",
                artifact.display(),
                fixture.0.join("src/main.rs").display()
            ),
        )
        .unwrap();
        let staged = StagedArtifacts {
            primary: artifact.clone(),
            binaries: BTreeMap::from([("root-bin".to_owned(), artifact)]),
            harnesses: Vec::new(),
            bundle: None,
            dep_info: vec![dep_info],
            script_inputs: vec![link.clone(), directory.clone()],
            messages: Vec::new(),
            library_paths: Vec::new(),
        };
        for validation in [ValidationMode::Trusted, ValidationMode::Strict] {
            let base = [7; 32];
            write_fresh_profile(
                &profile,
                &fixture.0,
                &fixture.0,
                base,
                &staged,
                &[],
                validation,
            )
            .unwrap();
            assert_eq!(
                read_fresh_profile(&profile, &fixture.0)
                    .unwrap()
                    .script_inputs,
                staged.script_inputs
            );
            let fresh = || {
                restore_fresh_profile(&profile, &fixture.0, &fixture.0, base, validation).is_some()
            };
            assert!(fresh());
            fs::write(&first, b"different").unwrap();
            assert!(!fresh());
            fs::write(&first, b"same").unwrap();
            assert!(fresh());
            let added = directory.join("new-input");
            fs::write(&added, b"new").unwrap();
            assert!(!fresh());
            fs::remove_file(&added).unwrap();
            assert!(fresh());
            fs::remove_file(&link).unwrap();
            symlink(&second, &link).unwrap();
            assert!(!fresh(), "an identical-content retarget must invalidate");
            fs::remove_file(&link).unwrap();
            symlink(&first, &link).unwrap();
            assert!(fresh());
        }
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
            script_inputs: Vec::new(),
            messages: Vec::new(),
            library_paths: Vec::new(),
        };
        let base = [7; 32];

        write_fresh_profile(
            &profile,
            &fixture.0,
            &fixture.0,
            base,
            &staged,
            &[],
            ValidationMode::Trusted,
        )
        .unwrap();
        fs::write(&artifact, b"tampered-artifact").unwrap();
        assert!(
            restore_fresh_profile(
                &profile,
                &fixture.0,
                &fixture.0,
                base,
                ValidationMode::Trusted
            )
            .is_some()
        );
        assert!(
            restore_fresh_profile(
                &profile,
                &fixture.0,
                &fixture.0,
                base,
                ValidationMode::Strict
            )
            .is_none()
        );

        write_fresh_profile(
            &profile,
            &fixture.0,
            &fixture.0,
            base,
            &staged,
            &[],
            ValidationMode::Strict,
        )
        .unwrap();
        assert!(
            restore_fresh_profile(
                &profile,
                &fixture.0,
                &fixture.0,
                base,
                ValidationMode::Strict
            )
            .is_some()
        );
        fs::write(&artifact, b"changed--artifact").unwrap();
        assert!(
            restore_fresh_profile(
                &profile,
                &fixture.0,
                &fixture.0,
                base,
                ValidationMode::Strict
            )
            .is_none()
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
            script_inputs: Vec::new(),
            messages: Vec::new(),
            library_paths: Vec::new(),
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
            &fixture.0,
            base,
            &staged,
            &[],
            ValidationMode::Trusted,
        )
        .unwrap();
        overwrite_preserving_metadata(b'/');
        assert!(
            restore_fresh_profile(
                &profile,
                &fixture.0,
                &fixture.0,
                base,
                ValidationMode::Trusted
            )
            .is_some()
        );

        write_fresh_profile(
            &profile,
            &fixture.0,
            &fixture.0,
            base,
            &staged,
            &[],
            ValidationMode::Strict,
        )
        .unwrap();
        overwrite_preserving_metadata(b'f');
        assert!(
            restore_fresh_profile(
                &profile,
                &fixture.0,
                &fixture.0,
                base,
                ValidationMode::Strict
            )
            .is_none()
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
        let toolchain = Toolchain::discover(None, &config, false).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let build_once = || {
            build(Build {
                target_root: None,
                child_lease_fd: None,
                manifest: &manifest,
                members: None,
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
                jobs: 1,
                keep_going: false,
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
        let dependency_rlib = || {
            fs::read_dir(fixture.0.join("target/lorry/debug/build/local-dependency"))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .flat_map(|unit| {
                    fs::read_dir(unit.join("deps"))
                        .into_iter()
                        .flatten()
                        .map(|entry| entry.unwrap().path())
                })
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("liblocal_dependency-")
                        && path.extension().is_some_and(|ext| ext == "rlib")
                })
                .unwrap()
        };
        let dependency_inode = fs::metadata(dependency_rlib()).unwrap().ino();
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
        assert_eq!(
            fs::metadata(dependency_rlib()).unwrap().ino(),
            dependency_inode
        );
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
        let toolchain = Toolchain::discover(None, &config, false).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let artifact = build(Build {
            target_root: None,
            child_lease_fd: None,
            manifest: &manifest,
            members: None,
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
            jobs: 1,
            keep_going: false,
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
        let toolchain = Toolchain::discover(None, &config, false).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let build_with = |binary_selection| {
            build(Build {
                target_root: None,
                child_lease_fd: None,
                manifest: &manifest,
                members: None,
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
                jobs: 1,
                keep_going: false,
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
        let toolchain = Toolchain::discover(None, &config, false).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let artifacts = build(Build {
            target_root: None,
            child_lease_fd: None,
            manifest: &manifest,
            members: None,
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
            jobs: 1,
            keep_going: false,
            use_cargo_registry: false,
            source: None,
            bundle: false,
            validation: ValidationMode::Trusted,
            ordinary_freshness_base: None,
            binary_selection: None,
        })
        .unwrap();
        let binary = only_binary(&artifacts);
        assert!(binary.starts_with(manifest.workspace_root.join("target/lorry/debug")));
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
        let toolchain = Toolchain::discover(None, &config, false).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let artifacts = build(Build {
            target_root: None,
            child_lease_fd: None,
            manifest: &manifest,
            members: None,
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
            jobs: 1,
            keep_going: false,
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
        let toolchain = Toolchain::discover(None, &config, false).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let build_once = || {
            build(Build {
                target_root: None,
                child_lease_fd: None,
                manifest: &manifest,
                members: None,
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
                jobs: 1,
                keep_going: false,
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
        let manifest_path = fixture.0.join("Cargo.toml");
        let source = fs::read_to_string(&manifest_path).unwrap();
        fs::write(
            &manifest_path,
            format!("{source}\n[workspace]\nmembers = [\"local\"]\n"),
        )
        .unwrap();
        let workspace_input = fixture.0.join("workspace-input");
        fs::write(&workspace_input, b"first").unwrap();
        let script_path = fixture.0.join("local/build.rs");
        let script = fs::read_to_string(&script_path).unwrap().replace(
            "fn main() {",
            r#"fn main() {
                println!("cargo:rustc-link-search=native={}", std::env::var("OUT_DIR").unwrap());
                let input = std::path::Path::new(&std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("../workspace-input");
                println!("cargo:rerun-if-changed={}", input.display());
                std::fs::write(
                    std::path::Path::new(&std::env::var_os("OUT_DIR").unwrap()).join("workspace-input"),
                    std::fs::read(input).unwrap(),
                ).unwrap();
                std::fs::write(
                    std::path::Path::new(&std::env::var_os("OUT_DIR").unwrap()).join("num-jobs"),
                    std::env::var("NUM_JOBS").unwrap(),
                ).unwrap();"#,
        );
        fs::write(script_path, script).unwrap();
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
        let toolchain = Toolchain::discover(None, &config, false).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let build_once = |jobs, format| {
            build_reported(
                Build {
                    target_root: None,
                    child_lease_fd: None,
                    manifest: &manifest,
                    members: None,
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
                    jobs,
                    keep_going: false,
                    use_cargo_registry: false,
                    source: None,
                    bundle: false,
                    validation: ValidationMode::Trusted,
                    ordinary_freshness_base: None,
                    binary_selection: None,
                },
                format,
            )
        };
        let artifact = build_once(2, MessageFormat::Human).unwrap();
        let output = std::process::Command::new(only_binary(&artifact))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"build-script-ok");
        let script = fs::read_to_string(fixture.0.join("local/build.rs")).unwrap();
        let output_directory = || {
            fs::read_dir(fixture.0.join("target/lorry/debug/build/local-dependency"))
                .unwrap()
                .map(|entry| entry.unwrap().path().join("build-script-execution/out"))
                .find(|path| path.is_dir())
                .unwrap()
        };
        let out_dir = output_directory();
        assert_eq!(fs::read(out_dir.join("workspace-input")).unwrap(), b"first");
        assert!(artifact.library_paths.contains(&out_dir));
        assert_eq!(fs::read_to_string(out_dir.join("num-jobs")).unwrap(), "2");
        let modified = fs::metadata(out_dir.join("num-jobs"))
            .unwrap()
            .modified()
            .unwrap();
        build_once(2, MessageFormat::Json).unwrap();
        assert_eq!(
            fs::metadata(out_dir.join("num-jobs"))
                .unwrap()
                .modified()
                .unwrap(),
            modified,
            "unchanged JSON build reran the build script",
        );
        fs::write(&workspace_input, b"second").unwrap();
        build_once(2, MessageFormat::Human).unwrap();
        assert_eq!(
            fs::read(out_dir.join("workspace-input")).unwrap(),
            b"second"
        );
        build_once(1, MessageFormat::Human).unwrap();
        assert_eq!(fs::read_to_string(out_dir.join("num-jobs")).unwrap(), "1");
        let updated = script.replace("build-script-ok", "build-script-new");
        fs::write(fixture.0.join("local/build.rs"), &updated).unwrap();
        let rebuilt = build_once(1, MessageFormat::Human).unwrap();
        assert_eq!(output_directory(), out_dir);
        assert_eq!(
            std::process::Command::new(only_binary(&rebuilt))
                .output()
                .unwrap()
                .stdout,
            b"build-script-new"
        );

        let failed = updated
            .replace("build-script-new", "build-script-failed")
            .replace(
                "println!(\"cargo:rerun-if-changed=build.rs\");",
                "panic!(\"intentional failure\");",
            );
        fs::write(fixture.0.join("local/build.rs"), failed).unwrap();
        assert!(build_once(1, MessageFormat::Human).is_err());
        assert_eq!(output_directory(), out_dir);
        assert!(
            fs::read_to_string(out_dir.join("generated.rs"))
                .unwrap()
                .contains("build-script-failed")
        );
        assert_eq!(
            std::process::Command::new(only_binary(&rebuilt))
                .output()
                .unwrap()
                .stdout,
            b"build-script-new"
        );
        fs::write(
            fixture.0.join("local/build.rs"),
            updated.replace("build-script-new", "build-script-final"),
        )
        .unwrap();
        let final_artifact = build_once(1, MessageFormat::Human).unwrap();
        assert_eq!(output_directory(), out_dir);
        assert_eq!(
            std::process::Command::new(only_binary(&final_artifact))
                .output()
                .unwrap()
                .stdout,
            b"build-script-final"
        );
    }

    #[test]
    fn builds_and_runs_unit_and_integration_test_harnesses() {
        use std::os::unix::fs::MetadataExt;

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
        let toolchain = Toolchain::discover(None, &config, false).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let build_once = || {
            build(Build {
                target_root: None,
                child_lease_fd: None,
                manifest: &manifest,
                members: None,
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
                jobs: 1,
                keep_going: false,
                use_cargo_registry: false,
                source: None,
                bundle: false,
                validation: ValidationMode::Trusted,
                ordinary_freshness_base: None,
                binary_selection: None,
            })
        };
        let artifacts = build_once().unwrap();
        assert_eq!(artifacts.harnesses.len(), 6);
        assert_eq!(artifacts.binaries.len(), 3);
        let first_inodes = artifacts
            .harnesses
            .iter()
            .map(|path| fs::metadata(path).unwrap().ino())
            .collect::<Vec<_>>();
        for harness in &artifacts.harnesses {
            let status = std::process::Command::new(harness).status().unwrap();
            assert!(status.success(), "harness `{}` failed", harness.display());
        }
        let repeated = build_once().unwrap();
        assert_eq!(repeated.harnesses, artifacts.harnesses);
        assert_eq!(
            repeated
                .harnesses
                .iter()
                .map(|path| fs::metadata(path).unwrap().ino())
                .collect::<Vec<_>>(),
            first_inodes,
            "unchanged test harnesses should be reused in place"
        );
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
        let toolchain = Toolchain::discover(None, &config, false).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let build_bundle = || {
            build(Build {
                target_root: None,
                child_lease_fd: None,
                manifest: &manifest,
                members: None,
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
                jobs: 1,
                keep_going: false,
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
        let toolchain = Toolchain::discover(None, &config, false).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let artifacts = build(Build {
            target_root: None,
            child_lease_fd: None,
            manifest: &manifest,
            members: None,
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
            jobs: 1,
            keep_going: false,
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
            target_root: None,
            child_lease_fd: None,
            manifest: &manifest,
            members: None,
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
            jobs: 1,
            keep_going: false,
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
                &BTreeMap::new(),
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
        let toolchain = Toolchain::discover(None, &config, false).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let target_options = TargetOptions::default();
        let error = build(Build {
            target_root: None,
            child_lease_fd: None,
            manifest: &manifest,
            members: None,
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
            jobs: 1,
            keep_going: false,
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
