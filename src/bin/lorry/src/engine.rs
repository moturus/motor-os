use crate::atomic::AtomicDirectory;
use crate::cli::{Cli, Color, Command, Verbosity};
use crate::config::{Config, TargetOptions, TargetSelector, environment_rustflags};
use crate::diagnostic::{Error, Result};
use crate::hash::{hex, sha256_file};
use crate::identity::{Identity, IdentityInput, cargo_identity};
use crate::manifest::{Edition, Lto, Manifest, Strip};
use crate::process::{self, RustcCommand};
use crate::toolchain::{TargetInfo, Toolchain};
use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

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
    let matching_cfgs = matching_cfgs(&config, &target_info)?;
    let target_options = config.target_options(&target_info.triple, &matching_cfgs)?;
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
                toolchain: &toolchain,
                target_options: &target_options,
                physical_target: physical_target.as_deref(),
                logical_target,
                rustflags: &rustflags,
                release,
                test: false,
                color,
                verbosity: cli.verbosity,
            })?;
            Ok(0)
        }
        Command::Run(options) => {
            let artifact = build(Build {
                manifest: &manifest,
                toolchain: &toolchain,
                target_options: &target_options,
                physical_target: physical_target.as_deref(),
                logical_target,
                rustflags: &rustflags,
                release,
                test: false,
                color,
                verbosity: cli.verbosity,
            })?;
            run_artifact(
                &artifact,
                &options.arguments,
                &manifest.root,
                physical_target.as_deref(),
                &target_options,
                cli.verbosity,
            )
        }
        Command::Test(options) => {
            if cli.verbosity != Verbosity::Quiet {
                eprintln!(
                    "note: Stage 1 runs binary unit tests; documentation tests are not supported"
                );
            }
            let artifact = build(Build {
                manifest: &manifest,
                toolchain: &toolchain,
                target_options: &target_options,
                physical_target: physical_target.as_deref(),
                logical_target,
                rustflags: &rustflags,
                release,
                test: true,
                color,
                verbosity: cli.verbosity,
            })?;
            run_artifact(
                &artifact,
                &options.arguments,
                &manifest.root,
                physical_target.as_deref(),
                &target_options,
                cli.verbosity,
            )
        }
        _ => unreachable!(),
    }
}

struct Build<'a> {
    manifest: &'a Manifest,
    toolchain: &'a Toolchain,
    target_options: &'a TargetOptions,
    physical_target: Option<&'a str>,
    logical_target: Option<&'a str>,
    rustflags: &'a [String],
    release: bool,
    test: bool,
    color: bool,
    verbosity: Verbosity,
}

fn build(build: Build<'_>) -> Result<PathBuf> {
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

    let identity = cargo_identity(&IdentityInput {
        package_name: &build.manifest.name,
        version: &build.manifest.version,
        target_name: &build.manifest.crate_name,
        release: build.release,
        test: build.test,
        logical_target: build.logical_target,
        release_profile: &build.manifest.release,
        rustc: build.toolchain,
        rustflags: build.rustflags,
    });
    let arguments = rustc_arguments(&build, &identity, staging.path());
    let environment = rustc_environment(&build, &target_root, profile_name)?;
    RustcCommand {
        program: &build.toolchain.rustc,
        arguments: &arguments,
        environment: &environment,
        current_dir: &build.manifest.root,
        verbose: build.verbosity == Verbosity::Verbose,
        color: build.color,
    }
    .run()?;

    let dependency_artifact = dependencies.join(format!(
        "{}{}",
        build.manifest.crate_name, identity.extra_filename
    ));
    if !dependency_artifact.is_file() {
        return Err(Error::failure(format!(
            "rustc succeeded but expected artifact `{}` is missing",
            dependency_artifact.display()
        )));
    }
    let staged_artifact = if build.test {
        dependency_artifact
    } else {
        let primary = staging.path().join(&build.manifest.crate_name);
        match fs::hard_link(&dependency_artifact, &primary) {
            Ok(()) => {}
            Err(_) => {
                fs::copy(&dependency_artifact, &primary).map_err(|error| {
                    Error::failure(format!(
                        "failed to install primary artifact `{}`: {error}",
                        primary.display()
                    ))
                })?;
            }
        }
        primary
    };
    let relative_artifact = staged_artifact
        .strip_prefix(staging.path())
        .unwrap()
        .to_path_buf();
    staging.commit(&destination)?;
    let artifact = destination.join(relative_artifact);

    if build.verbosity != Verbosity::Quiet {
        eprintln!(
            "Finished `{}` profile",
            if build.release { "release" } else { "dev" }
        );
    }
    if build.verbosity == Verbosity::Verbose {
        eprintln!(
            "Artifact {} sha256={}",
            artifact.display(),
            hex(&sha256_file(&artifact)?)
        );
    }
    Ok(artifact)
}

fn rustc_arguments(build: &Build<'_>, identity: &Identity, staging: &Path) -> Vec<OsString> {
    let mut args = Vec::new();
    push(&mut args, "--crate-name");
    push(&mut args, &build.manifest.crate_name);
    push(
        &mut args,
        &format!("--edition={}", edition_name(build.manifest.edition)),
    );
    push(&mut args, "src/main.rs");
    push(&mut args, "--error-format=json");
    push(
        &mut args,
        "--json=diagnostic-rendered-ansi,artifacts,future-incompat",
    );
    if !build.test {
        push(&mut args, "--crate-type");
        push(&mut args, "bin");
    }
    push(&mut args, "--emit=dep-info,link");

    if build.release {
        codegen(&mut args, "opt-level=3");
        if build.manifest.release.panic_abort && !build.test {
            codegen(&mut args, "panic=abort");
        }
        match build.manifest.release.lto {
            Lto::Default => codegen(&mut args, "embed-bitcode=no"),
            Lto::True => codegen(&mut args, "lto"),
            Lto::Fat => codegen(&mut args, "lto=fat"),
            Lto::Thin => codegen(&mut args, "lto=thin"),
            Lto::Off => codegen(&mut args, "lto=off"),
        }
        if let Some(units) = build.manifest.release.codegen_units {
            codegen(&mut args, &format!("codegen-units={units}"));
        }
    } else {
        codegen(&mut args, "embed-bitcode=no");
        codegen(&mut args, "debuginfo=2");
    }
    if build.test {
        push(&mut args, "--test");
    }
    push(&mut args, "--check-cfg");
    push(&mut args, "cfg(docsrs,test)");
    push(&mut args, "--check-cfg");
    push(&mut args, "cfg(feature, values())");
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
        let host_dependencies = build
            .manifest
            .root
            .join("target/lorry")
            .join(if build.release { "release" } else { "debug" })
            .join("deps");
        push(&mut args, "-L");
        args.push(format!("dependency={}", host_dependencies.display()).into());
    }
    args.extend(build.rustflags.iter().map(OsString::from));
    push(&mut args, "--verbose");
    args
}

fn rustc_environment(
    build: &Build<'_>,
    target_root: &Path,
    profile_name: &str,
) -> Result<BTreeMap<String, OsString>> {
    let manifest = build.manifest;
    let version = &manifest.version;
    let mut values = BTreeMap::new();
    let current_exe = env::current_exe()
        .map_err(|error| Error::failure(format!("failed to locate Lorry executable: {error}")))?;
    value(&mut values, "CARGO", current_exe.as_os_str());
    value(&mut values, "CARGO_BIN_NAME", &manifest.crate_name);
    value(&mut values, "CARGO_CRATE_NAME", &manifest.crate_name);
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
        target_root.join(profile_name).join("deps").as_os_str(),
    );
    Ok(values)
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
