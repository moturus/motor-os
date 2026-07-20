#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::build_script::{self, EnvironmentOptions, RunOptions};
use crate::compile::{
    BuildOutput, CommandOptions, RustcOutput, dependency_rustc_invocation,
    dependency_rustc_invocation_with_build_output,
};
use crate::diagnostic::{Error, Result};
use crate::manifest::Manifest;
use crate::process::RustcCommand;
use crate::resolver::{CompileKind, PackageKey};
use crate::sandbox::Executable;
use crate::source_tree::Limits as TreeLimits;
use crate::toolchain::{TargetInfo, Toolchain};
use crate::unit::{CompilationPlan, UnitEdgeKind, UnitKey, UnitKind};

pub struct Options<'a> {
    pub cargo: &'a Path,
    pub toolchain: &'a Toolchain,
    pub host: &'a TargetInfo,
    pub target: &'a TargetInfo,
    pub host_profile: &'a Path,
    pub target_profile: &'a Path,
    pub physical_target: Option<&'a str>,
    pub host_linker: Option<&'a Path>,
    pub target_linker: Option<&'a Path>,
    pub release: bool,
    pub verbose: bool,
    pub color: bool,
    pub build_script_timeout: Duration,
    pub build_script_output_bytes: u64,
    pub out_dir_limits: TreeLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutedBuildScript {
    pub output: build_script::Output,
    pub out_dir: PathBuf,
    pub temp_dir: PathBuf,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Outputs {
    pub artifacts: BTreeMap<UnitKey, RustcOutput>,
    pub build_scripts: BTreeMap<UnitKey, ExecutedBuildScript>,
}

pub fn execute(
    plan: &CompilationPlan,
    manifests: &BTreeMap<PackageKey, Manifest>,
    options: &Options<'_>,
) -> Result<Outputs> {
    create_directory(
        &options.host_profile.join("deps"),
        "host dependency directory",
    )?;
    create_directory(
        &options.target_profile.join("deps"),
        "target dependency directory",
    )?;
    let commands = CommandOptions {
        cargo: options.cargo,
        host_profile: options.host_profile,
        target_profile: options.target_profile,
        physical_target: options.physical_target,
        host_linker: options.host_linker,
        target_linker: options.target_linker,
        verbose: options.verbose,
    };
    let mut outputs = Outputs::default();
    for key in &plan.order {
        let planned = plan.units.get(key).ok_or_else(|| {
            Error::failure(format!(
                "dependency execution plan is missing {:?} unit `{} {}`",
                key.kind, key.package.name, key.package.version
            ))
        })?;
        match key.kind {
            UnitKind::BuildScriptRun => {
                let manifest = manifests.get(&key.package).ok_or_else(|| {
                    Error::failure(format!(
                        "dependency execution has no manifest for `{} {}`",
                        key.package.name, key.package.version
                    ))
                })?;
                let compile_key = planned
                    .unit
                    .dependencies
                    .iter()
                    .find(|edge| edge.kind == UnitEdgeKind::BuildScriptExecutable)
                    .map(|edge| &edge.unit)
                    .ok_or_else(|| {
                        Error::failure(format!(
                            "build-script run unit `{} {}` has no executable dependency",
                            key.package.name, key.package.version
                        ))
                    })?;
                let executable = match outputs.artifacts.get(compile_key) {
                    Some(RustcOutput::BuildScript { executable, .. }) => executable,
                    _ => {
                        return Err(Error::failure(format!(
                            "build-script executable for `{} {}` was not compiled first",
                            key.package.name, key.package.version
                        )));
                    }
                };
                let root = options.host_profile.join("build").join(format!(
                    "{}-{}",
                    manifest.name,
                    planned.identity.extra_filename.trim_start_matches('-')
                ));
                let out_dir = root.join("out");
                let temp_dir = root.join("tmp");
                create_directory(&out_dir, "build-script OUT_DIR")?;
                create_directory(&temp_dir, "build-script temporary directory")?;
                let target = match key.compile_kind {
                    CompileKind::Host => options.host,
                    CompileKind::Target => options.target,
                };
                let environment = build_script::environment(
                    manifest,
                    &planned.unit,
                    &planned.settings,
                    &EnvironmentOptions {
                        cargo: options.cargo,
                        rustc: &options.toolchain.rustc,
                        host: &options.host.triple,
                        target,
                        host_profile: options.host_profile,
                        out_dir: &out_dir,
                        temp_dir: &temp_dir,
                        release: options.release,
                        num_jobs: 1,
                        primary_package: false,
                    },
                )?;
                let read_only = sandbox_inputs(manifests, options);
                let build_output = build_script::run(&RunOptions {
                    executable,
                    arguments: &[],
                    environment: &environment,
                    package_root: &manifest.root,
                    out_dir: &out_dir,
                    temp_dir: &temp_dir,
                    read_only: &read_only,
                    executables: &[Executable {
                        path: options.toolchain.rustc.clone(),
                        argument_prefix: Vec::new(),
                    }],
                    timeout: options.build_script_timeout,
                    max_output_bytes: options.build_script_output_bytes,
                    out_dir_limits: options.out_dir_limits,
                    verbose: options.verbose,
                })?;
                render_build_script_output(key, &build_output);
                outputs.build_scripts.insert(
                    key.clone(),
                    ExecutedBuildScript {
                        output: build_output,
                        out_dir,
                        temp_dir,
                    },
                );
            }
            UnitKind::Library | UnitKind::BuildScriptCompile => {
                let build_output = if key.kind == UnitKind::Library {
                    let run = planned
                        .unit
                        .dependencies
                        .iter()
                        .find(|edge| edge.kind == UnitEdgeKind::BuildScriptOutput)
                        .map(|edge| &edge.unit);
                    match run {
                        Some(run) => {
                            let output = outputs.build_scripts.get(run).ok_or_else(|| {
                                Error::failure(format!(
                                    "build-script output for `{} {}` was not produced first",
                                    key.package.name, key.package.version
                                ))
                            })?;
                            Some(BuildOutput {
                                output: &output.output,
                                out_dir: &output.out_dir,
                            })
                        }
                        None => None,
                    }
                } else {
                    None
                };
                let invocation = match build_output {
                    Some(output) => dependency_rustc_invocation_with_build_output(
                        plan,
                        manifests,
                        key,
                        &commands,
                        Some(output),
                    )?,
                    None => dependency_rustc_invocation(plan, manifests, key, &commands)?,
                }
                .ok_or_else(|| Error::failure("rustc invocation unexpectedly missing"))?;
                create_output_directories(&invocation.output)?;
                if options.verbose {
                    eprintln!(
                        "Compiling {} v{} ({})",
                        key.package.name,
                        key.package.version,
                        invocation.current_dir.display()
                    );
                }
                RustcCommand {
                    program: &options.toolchain.rustc,
                    arguments: &invocation.arguments,
                    environment: &invocation.environment,
                    current_dir: &invocation.current_dir,
                    verbose: options.verbose,
                    color: options.color,
                }
                .run()?;
                verify_outputs(&invocation.output)?;
                if let RustcOutput::BuildScript {
                    executable,
                    unhashed_executable,
                    ..
                } = &invocation.output
                {
                    install_unhashed(executable, unhashed_executable)?;
                }
                outputs.artifacts.insert(key.clone(), invocation.output);
            }
        }
    }
    Ok(outputs)
}

fn create_output_directories(output: &RustcOutput) -> Result<()> {
    let path = match output {
        RustcOutput::Library { rlib, .. } => rlib,
        RustcOutput::BuildScript { executable, .. } => executable,
    };
    create_directory(
        path.parent()
            .ok_or_else(|| Error::failure("rustc output has no parent directory"))?,
        "rustc output directory",
    )
}

fn create_directory(path: &Path, description: &str) -> Result<()> {
    fs::create_dir_all(path).map_err(|error| {
        Error::failure(format!(
            "failed to create {description} `{}`: {error}",
            path.display()
        ))
    })
}

fn verify_outputs(output: &RustcOutput) -> Result<()> {
    let expected = match output {
        RustcOutput::Library {
            rlib,
            rmeta,
            dep_info,
        } => vec![rlib, rmeta, dep_info],
        RustcOutput::BuildScript {
            executable,
            dep_info,
            ..
        } => vec![executable, dep_info],
    };
    for path in expected {
        if !path.is_file() {
            return Err(Error::failure(format!(
                "rustc succeeded but expected output `{}` is missing",
                path.display()
            )));
        }
    }
    Ok(())
}

fn install_unhashed(source: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        return Err(Error::failure(format!(
            "build-script output `{}` already exists",
            destination.display()
        )));
    }
    if fs::hard_link(source, destination).is_ok() {
        return Ok(());
    }
    fs::copy(source, destination).map_err(|error| {
        Error::failure(format!(
            "failed to install build-script executable `{}`: {error}",
            destination.display()
        ))
    })?;
    Ok(())
}

fn sandbox_inputs(
    manifests: &BTreeMap<PackageKey, Manifest>,
    options: &Options<'_>,
) -> Vec<PathBuf> {
    let mut paths = manifests
        .values()
        .map(|manifest| manifest.root.clone())
        .collect::<Vec<_>>();
    paths.push(options.host_profile.join("deps"));
    paths.push(options.target_profile.join("deps"));
    if let Some(toolchain_root) = options
        .toolchain
        .rustc
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("lib"))
        .filter(|path| path.is_dir())
    {
        paths.push(toolchain_root);
    }
    for path in [
        "/dev/null",
        "/lib",
        "/lib64",
        "/usr/lib",
        "/etc/ld.so.cache",
    ] {
        let path = PathBuf::from(path);
        if path.exists() {
            paths.push(path);
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

fn render_build_script_output(key: &UnitKey, output: &build_script::Output) {
    for diagnostic in &output.diagnostics {
        eprintln!(
            "[{} {}] {diagnostic}",
            key.package.name, key.package.version
        );
    }
    if !output.stderr.is_empty() {
        eprint!("{}", output.stderr);
        if !output.stderr.ends_with('\n') {
            eprintln!();
        }
    }
    for directive in &output.directives {
        if let build_script::Directive::Warning(warning) = directive {
            eprintln!(
                "warning: {} {}: {warning}",
                key.package.name, key.package.version
            );
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::config::{CargoCompat, Config};
    use crate::manifest::ReleaseProfile;
    use crate::resolver::{PackageSourceKey, Resolution, ResolvedPackage, ResolvedSource};
    use crate::source_tree::DEFAULT_LIMITS;
    use crate::unit::{PlanOptions, dependency_units, plan_dependency_units};
    use semver::Version;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "lorry-dependency-executor-{}-{id}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("package/src")).unwrap();
            fs::write(
                root.join("package/Cargo.toml"),
                "[package]\nname = \"generated-dependency\"\nversion = \"1.0.0\"\n\
                 edition = \"2024\"\nbuild = \"build.rs\"\nlicense = \"MIT\"\n",
            )
            .unwrap();
            fs::write(
                root.join("package/src/lib.rs"),
                "#[cfg(not(generated_cfg))]\ncompile_error!(\"build cfg missing\");\n\
                 include!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));\n\
                 pub const BUILD_VALUE: &str = env!(\"BUILD_VALUE\");\n",
            )
            .unwrap();
            fs::write(
                root.join("package/build.rs"),
                "use std::{env, fs, net::TcpStream, process::Command};\n\
                 fn main() {\n\
                     let root = env::current_dir().unwrap();\n\
                     assert!(env::var_os(\"HOME\").is_none());\n\
                     assert!(fs::write(root.join(\"src/lib.rs\"), \"bad\").is_err());\n\
                     assert!(TcpStream::connect(\"127.0.0.1:9\").is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied));\n\
                     assert!(Command::new(\"/bin/true\").status().is_err());\n\
                     let rustc = env::var_os(\"RUSTC\").unwrap();\n\
                     assert!(Command::new(rustc).arg(\"--version\").output().unwrap().status.success());\n\
                     let out = env::var_os(\"OUT_DIR\").unwrap();\n\
                     fs::write(std::path::Path::new(&out).join(\"generated.rs\"), \"pub const GENERATED: &str = \\\"yes\\\";\\n\").unwrap();\n\
                     println!(\"cargo:rerun-if-changed=build.rs\");\n\
                     println!(\"cargo:rustc-check-cfg=cfg(generated_cfg)\");\n\
                     println!(\"cargo:rustc-cfg=generated_cfg\");\n\
                     println!(\"cargo:rustc-env=BUILD_VALUE=generated\");\n\
                 }\n",
            )
            .unwrap();
            Self(root)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn actual_toolchain() -> (Toolchain, TargetInfo) {
        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_98);
        let toolchain = Toolchain::discover(None, &config).unwrap();
        let target = toolchain.target_info(None).unwrap();
        (toolchain, target)
    }

    #[test]
    fn compiles_runs_and_consumes_a_sandboxed_build_script() {
        let fixture = Fixture::new();
        let manifest = Manifest::load_path_dependency(&fixture.0.join("package")).unwrap();
        let key = PackageKey {
            name: manifest.name.clone(),
            version: Version::parse(&manifest.version.original).unwrap(),
            source: PackageSourceKey::CratesIo,
        };
        let resolution = Resolution {
            root_edges: Vec::new(),
            packages: vec![ResolvedPackage {
                key: key.clone(),
                source: ResolvedSource::CratesIo { checksum: [7; 32] },
                local_manifest: None,
                feature_sets: BTreeMap::new(),
                compile_kinds: BTreeSet::from([CompileKind::Target]),
                target_features: BTreeSet::new(),
                host_features: BTreeSet::new(),
                edges: Vec::new(),
                lock_edges: Vec::new(),
            }],
        };
        let manifests = BTreeMap::from([(key, manifest)]);
        let graph = dependency_units(&resolution, &manifests).unwrap();
        let (toolchain, target) = actual_toolchain();
        let plan = plan_dependency_units(
            &graph,
            &manifests,
            &PlanOptions {
                workspace_root: &fixture.0,
                release: false,
                release_profile: &ReleaseProfile::default(),
                rustc: &toolchain,
                logical_target: None,
                rustflags: &[],
            },
        )
        .unwrap();
        let profile = fixture.0.join("output/debug");
        let cargo = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let outputs = execute(
            &plan,
            &manifests,
            &Options {
                cargo: &cargo,
                toolchain: &toolchain,
                host: &target,
                target: &target,
                host_profile: &profile,
                target_profile: &profile,
                physical_target: None,
                host_linker: None,
                target_linker: None,
                release: false,
                verbose: false,
                color: false,
                build_script_timeout: Duration::from_secs(10),
                build_script_output_bytes: 64 * 1024,
                out_dir_limits: DEFAULT_LIMITS,
            },
        )
        .unwrap();

        assert_eq!(outputs.artifacts.len(), 2);
        assert_eq!(outputs.build_scripts.len(), 1);
        let build = outputs.build_scripts.values().next().unwrap();
        assert_eq!(
            fs::read(build.out_dir.join("generated.rs")).unwrap(),
            b"pub const GENERATED: &str = \"yes\";\n"
        );
        assert_eq!(build.output.out_dir.file_count, 1);
        assert!(outputs.artifacts.iter().any(|(unit, output)| {
            unit.kind == UnitKind::Library
                && matches!(output, RustcOutput::Library { rlib, .. } if rlib.is_file())
        }));
        assert!(
            fs::read_to_string(fixture.0.join("package/src/lib.rs"))
                .unwrap()
                .contains("generated_cfg")
        );
    }
}
