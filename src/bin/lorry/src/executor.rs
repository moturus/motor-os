#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::build_script::{self, EnvironmentOptions, RunOptions};
use crate::cache::{BuildCaches, BuildScriptInput, CacheKey, DependencyInput, UnitInput};
use crate::compile::{
    BuildOutput, CommandOptions, RustcOutput, dependency_rustc_invocation,
    dependency_rustc_invocation_with_build_output,
};
use crate::diagnostic::{Error, Result};
use crate::hash::sha256_file;
use crate::manifest::Manifest;
use crate::native_tool;
use crate::policy::Admission;
use crate::process::RustcCommand;
use crate::resolver::{CompileKind, PackageKey};
use crate::sandbox::Executable;
use crate::source_tree::Limits as TreeLimits;
use crate::toolchain::{TargetInfo, Toolchain};
use crate::unit::{CompilationPlan, UnitEdgeKind, UnitKey, UnitKind};

pub struct Options<'a> {
    pub cargo: &'a Path,
    pub workspace_root: &'a Path,
    pub toolchain: &'a Toolchain,
    pub host: &'a TargetInfo,
    pub target: &'a TargetInfo,
    pub host_profile: &'a Path,
    pub target_profile: &'a Path,
    pub host_incremental: &'a Path,
    pub target_incremental: &'a Path,
    pub physical_target: Option<&'a str>,
    pub host_linker: Option<&'a Path>,
    pub target_linker: Option<&'a Path>,
    pub release: bool,
    pub quiet: bool,
    pub verbose: bool,
    pub color: bool,
    pub build_script_timeout: Duration,
    pub build_script_output_bytes: u64,
    pub out_dir_limits: TreeLimits,
    pub cache: Option<&'a BuildCaches>,
    pub admission: &'a Admission,
    pub native_tools:
        &'a BTreeMap<(String, crate::config::NativeToolRole), crate::config::NativeTool>,
    /// Maximum number of units executed concurrently; 1 preserves strict
    /// plan-order execution.
    pub jobs: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutedBuildScript {
    pub output: build_script::Output,
    pub environment: BTreeMap<String, std::ffi::OsString>,
    pub executable_sha256: [u8; 32],
    pub out_dir: PathBuf,
    pub temp_dir: PathBuf,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Outputs {
    pub artifacts: BTreeMap<UnitKey, RustcOutput>,
    pub build_scripts: BTreeMap<UnitKey, ExecutedBuildScript>,
    pub cache_keys: BTreeMap<UnitKey, CacheKey>,
}

pub fn execute(
    plan: &CompilationPlan,
    manifests: &BTreeMap<PackageKey, Manifest>,
    options: &Options<'_>,
) -> Result<Outputs> {
    execute_inner(plan, manifests, options, None)
}

pub fn execute_reusing(
    plan: &CompilationPlan,
    manifests: &BTreeMap<PackageKey, Manifest>,
    options: &Options<'_>,
    previous_plan: &CompilationPlan,
    previous_outputs: &Outputs,
) -> Result<Outputs> {
    execute_inner(
        plan,
        manifests,
        options,
        Some((previous_plan, previous_outputs)),
    )
}

/// One executed unit's result, recorded into `Outputs` by the scheduler.
enum Executed {
    BuildScript(ExecutedBuildScript),
    Artifact {
        output: RustcOutput,
        cache_key: Option<CacheKey>,
    },
}

/// Shared scheduling state: units become ready when their last dependency
/// completes and are dispatched in plan order.
struct Scheduler {
    ready: std::collections::BTreeSet<(usize, UnitKey)>,
    remaining: BTreeMap<UnitKey, usize>,
    outputs: Outputs,
    failures: Vec<(usize, Error)>,
    dispatched: usize,
    completed: usize,
}

impl Scheduler {
    fn record(
        &mut self,
        dependents: &BTreeMap<UnitKey, Vec<UnitKey>>,
        index_of: &BTreeMap<UnitKey, usize>,
        key: &UnitKey,
        executed: Executed,
    ) -> Result<()> {
        match executed {
            Executed::BuildScript(output) => {
                self.outputs.build_scripts.insert(key.clone(), output);
            }
            Executed::Artifact { output, cache_key } => {
                self.outputs.artifacts.insert(key.clone(), output);
                if let Some(cache_key) = cache_key {
                    self.outputs.cache_keys.insert(key.clone(), cache_key);
                }
            }
        }
        for child in dependents.get(key).map(Vec::as_slice).unwrap_or(&[]) {
            let counter = self.remaining.get_mut(child).ok_or_else(|| {
                Error::failure("dependency execution lost track of a scheduled unit")
            })?;
            *counter -= 1;
            if *counter == 0 {
                self.remaining.remove(child);
                let index = *index_of.get(child).ok_or_else(|| {
                    Error::failure("dependency execution order is missing a ready unit")
                })?;
                self.ready.insert((index, child.clone()));
            }
        }
        self.completed += 1;
        Ok(())
    }
}

/// Clones the direct-dependency outputs one unit needs, so it can execute
/// outside the scheduler lock.
fn snapshot_inputs(planned: &crate::unit::PlannedUnit, outputs: &Outputs) -> Outputs {
    let mut snapshot = Outputs::default();
    for edge in &planned.unit.dependencies {
        if let Some(artifact) = outputs.artifacts.get(&edge.unit) {
            snapshot
                .artifacts
                .insert(edge.unit.clone(), artifact.clone());
        }
        if let Some(script) = outputs.build_scripts.get(&edge.unit) {
            snapshot
                .build_scripts
                .insert(edge.unit.clone(), script.clone());
        }
        if let Some(cache_key) = outputs.cache_keys.get(&edge.unit) {
            snapshot.cache_keys.insert(edge.unit.clone(), *cache_key);
        }
    }
    snapshot
}

fn execute_inner(
    plan: &CompilationPlan,
    manifests: &BTreeMap<PackageKey, Manifest>,
    options: &Options<'_>,
    previous: Option<(&CompilationPlan, &Outputs)>,
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
        workspace_root: options.workspace_root,
        host_profile: options.host_profile,
        target_profile: options.target_profile,
        host_incremental: options.host_incremental,
        target_incremental: options.target_incremental,
        physical_target: options.physical_target,
        host_linker: options.host_linker,
        target_linker: options.target_linker,
        verbose: options.verbose,
    };

    let total = plan.order.len();
    let mut index_of = BTreeMap::new();
    for (index, key) in plan.order.iter().enumerate() {
        index_of.insert(key.clone(), index);
    }
    let mut dependents: BTreeMap<UnitKey, Vec<UnitKey>> = BTreeMap::new();
    let mut state = Scheduler {
        ready: std::collections::BTreeSet::new(),
        remaining: BTreeMap::new(),
        outputs: Outputs::default(),
        failures: Vec::new(),
        dispatched: 0,
        completed: 0,
    };
    for (index, key) in plan.order.iter().enumerate() {
        let planned = plan.units.get(key).ok_or_else(|| {
            Error::failure(format!(
                "dependency execution plan is missing {:?} unit `{} {}`",
                key.kind, key.package.name, key.package.version
            ))
        })?;
        let dependencies = planned
            .unit
            .dependencies
            .iter()
            .map(|edge| &edge.unit)
            .collect::<std::collections::BTreeSet<_>>();
        for dependency in &dependencies {
            if !index_of.contains_key(*dependency) {
                return Err(Error::failure(
                    "dependency execution received an incomplete unit graph",
                ));
            }
            dependents
                .entry((*dependency).clone())
                .or_default()
                .push(key.clone());
        }
        if dependencies.is_empty() {
            state.ready.insert((index, key.clone()));
        } else {
            state.remaining.insert(key.clone(), dependencies.len());
        }
    }

    let workers = options.jobs.clamp(1, total.max(1));
    let state = std::sync::Mutex::new(state);
    let wakeup = std::sync::Condvar::new();
    let print = std::sync::Mutex::new(());
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let mut guard = state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let (index, key) = loop {
                        if !guard.failures.is_empty() || guard.completed == total {
                            return;
                        }
                        if let Some(entry) = guard.ready.iter().next().cloned() {
                            guard.ready.remove(&entry);
                            guard.dispatched += 1;
                            break entry;
                        }
                        if guard.dispatched == guard.completed {
                            guard.failures.push((
                                usize::MAX,
                                Error::failure(
                                    "dependency execution stalled with unresolved units",
                                ),
                            ));
                            wakeup.notify_all();
                            return;
                        }
                        guard = wakeup
                            .wait(guard)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    };
                    let Some(planned) = plan.units.get(&key) else {
                        guard.failures.push((
                            index,
                            Error::failure("dependency execution plan lost a dispatched unit"),
                        ));
                        wakeup.notify_all();
                        return;
                    };
                    if let Some((previous_plan, previous_outputs)) = previous
                        && previous_plan.units.get(&key) == Some(planned)
                    {
                        let reused = match key.kind {
                            UnitKind::BuildScriptRun => previous_outputs
                                .build_scripts
                                .get(&key)
                                .cloned()
                                .map(Executed::BuildScript),
                            UnitKind::Library | UnitKind::BuildScriptCompile => {
                                previous_outputs.artifacts.get(&key).cloned().map(|output| {
                                    Executed::Artifact {
                                        output,
                                        cache_key: previous_outputs.cache_keys.get(&key).copied(),
                                    }
                                })
                            }
                        };
                        if let Some(executed) = reused {
                            let recorded = guard.record(&dependents, &index_of, &key, executed);
                            if let Err(error) = recorded {
                                guard.failures.push((index, error));
                            }
                            wakeup.notify_all();
                            continue;
                        }
                    }
                    let inputs = snapshot_inputs(planned, &guard.outputs);
                    drop(guard);
                    let outcome = execute_unit(
                        plan, manifests, options, &commands, &key, planned, &inputs, &print,
                    );
                    let mut guard = state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    match outcome {
                        Ok(executed) => {
                            let recorded = guard.record(&dependents, &index_of, &key, executed);
                            if let Err(error) = recorded {
                                guard.failures.push((index, error));
                            }
                        }
                        Err(error) => {
                            guard.failures.push((index, error));
                            guard.completed += 1;
                        }
                    }
                    wakeup.notify_all();
                }
            });
        }
    });

    let state = state
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((_, error)) = state.failures.into_iter().min_by_key(|(index, _)| *index) {
        return Err(error);
    }
    Ok(state.outputs)
}

/// Executes one plan unit against a snapshot of its direct-dependency
/// outputs. Diagnostics are rendered as one uninterrupted block under the
/// shared print lock.
#[allow(clippy::too_many_arguments)]
fn execute_unit(
    plan: &CompilationPlan,
    manifests: &BTreeMap<PackageKey, Manifest>,
    options: &Options<'_>,
    commands: &CommandOptions<'_>,
    key: &UnitKey,
    planned: &crate::unit::PlannedUnit,
    outputs: &Outputs,
    print: &std::sync::Mutex<()>,
) -> Result<Executed> {
    {
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
                let mut environment = build_script::environment(
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
                let admission = options
                    .admission
                    .packages
                    .get(&key.package)
                    .ok_or_else(|| {
                        Error::failure(format!(
                            "dependency execution has no policy admission for `{} {}`",
                            key.package.name, key.package.version
                        ))
                    })?;
                let native = native_tool::project(
                    options.native_tools,
                    &admission.native_tools,
                    &target.triple,
                    planned.source_remap.as_ref(),
                )?;
                environment.extend(native.environment);
                let mut read_only = sandbox_inputs(manifests, options);
                read_only.extend(native.read_only);
                read_only.sort();
                read_only.dedup();
                let mut executables = vec![Executable {
                    path: options.toolchain.rustc.clone(),
                    argument_prefix: Vec::new(),
                }];
                executables.extend(native.executables);
                let build_output = build_script::run(&RunOptions {
                    executable,
                    arguments: &[],
                    environment: &environment,
                    package_root: &manifest.root,
                    out_dir: &out_dir,
                    temp_dir: &temp_dir,
                    read_only: &read_only,
                    executables: &executables,
                    timeout: options.build_script_timeout,
                    max_output_bytes: options.build_script_output_bytes,
                    out_dir_limits: options.out_dir_limits,
                    verbose: options.verbose,
                })?;
                {
                    let _guard = print
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    render_build_script_output(key, &build_output);
                }
                Ok(Executed::BuildScript(ExecutedBuildScript {
                    output: build_output,
                    environment,
                    executable_sha256: sha256_file(executable)?,
                    out_dir,
                    temp_dir,
                }))
            }
            UnitKind::Library | UnitKind::BuildScriptCompile => {
                let executed_build_script = if key.kind == UnitKind::Library {
                    let run = planned
                        .unit
                        .dependencies
                        .iter()
                        .find(|edge| edge.kind == UnitEdgeKind::BuildScriptOutput)
                        .map(|edge| &edge.unit);
                    match run {
                        Some(run) => Some(outputs.build_scripts.get(run).ok_or_else(|| {
                            Error::failure(format!(
                                "build-script output for `{} {}` was not produced first",
                                key.package.name, key.package.version
                            ))
                        })?),
                        None => None,
                    }
                } else {
                    None
                };
                let build_output = executed_build_script.map(|output| BuildOutput {
                    output: &output.output,
                    out_dir: &output.out_dir,
                });
                let invocation = match build_output {
                    Some(output) => dependency_rustc_invocation_with_build_output(
                        plan,
                        manifests,
                        key,
                        commands,
                        Some(output),
                    )?,
                    None => dependency_rustc_invocation(plan, manifests, key, commands)?,
                }
                .ok_or_else(|| Error::failure("rustc invocation unexpectedly missing"))?;
                create_output_directories(&invocation.output)?;
                let dependencies = if key.kind == UnitKind::Library {
                    cache_dependencies(planned, outputs)?
                } else {
                    Vec::new()
                };
                let cache_build_script = executed_build_script.map(cache_build_script_input);
                let cache_key =
                    if let Some(caches) = options.cache.filter(|_| key.kind == UnitKind::Library) {
                        let cache = caches.for_unit(planned);
                        let manifest = manifests.get(&key.package).ok_or_else(|| {
                            Error::failure(format!(
                                "dependency execution has no manifest for `{} {}`",
                                key.package.name, key.package.version
                            ))
                        })?;
                        let cache_key = cache.key(&UnitInput {
                            key,
                            planned,
                            manifest,
                            invocation: &invocation,
                            host_profile: options.host_profile,
                            target_profile: options.target_profile,
                            dependencies: &dependencies,
                            build_script: cache_build_script,
                        })?;
                        if cache.restore(cache_key, &invocation.output)? {
                            if options.verbose {
                                eprintln!(
                                    "Fresh {} v{} (verified Lorry cache)",
                                    key.package.name, key.package.version
                                );
                            }
                            return Ok(Executed::Artifact {
                                output: invocation.output,
                                cache_key: Some(cache_key),
                            });
                        }
                        if !options.quiet && caches.report_shared_rebuild(planned) {
                            let _guard = print
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            eprintln!("Rebuilding global dependency cache");
                        }
                        if options.verbose {
                            eprintln!("Cache miss {} v{}", key.package.name, key.package.version);
                        }
                        Some(cache_key)
                    } else {
                        None
                    };
                if options.verbose {
                    eprintln!(
                        "Compiling {} v{} ({})",
                        key.package.name,
                        key.package.version,
                        invocation.current_dir.display()
                    );
                }
                let rustc_output = RustcCommand {
                    program: &options.toolchain.rustc,
                    arguments: &invocation.arguments,
                    environment: &invocation.environment,
                    current_dir: &invocation.current_dir,
                    verbose: options.verbose,
                    color: options.color,
                }
                .execute()?;
                {
                    let _guard = print
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    RustcCommand::finish(&rustc_output, options.color)?;
                }
                verify_outputs(&invocation.output)?;
                validate_dep_info(
                    &invocation.output,
                    &manifests[&key.package].root,
                    executed_build_script.map(|build| build.out_dir.as_path()),
                    planned.source_remap.as_ref(),
                )?;
                if let (Some(caches), Some(cache_key)) = (options.cache, cache_key) {
                    caches.for_unit(planned).store(
                        cache_key,
                        &invocation.output,
                        cache_build_script.as_ref(),
                    )?;
                }
                if let RustcOutput::BuildScript {
                    executable,
                    unhashed_executable,
                    ..
                } = &invocation.output
                {
                    install_unhashed(executable, unhashed_executable)?;
                }
                Ok(Executed::Artifact {
                    output: invocation.output,
                    cache_key,
                })
            }
        }
    }
}

fn cache_build_script_input(output: &ExecutedBuildScript) -> BuildScriptInput<'_> {
    BuildScriptInput {
        output: &output.output,
        environment: &output.environment,
        executable_sha256: output.executable_sha256,
        out_dir: &output.out_dir,
        temp_dir: &output.temp_dir,
    }
}

fn cache_dependencies<'a>(
    planned: &'a crate::unit::PlannedUnit,
    outputs: &'a Outputs,
) -> Result<Vec<DependencyInput<'a>>> {
    planned
        .unit
        .dependencies
        .iter()
        .filter(|edge| edge.kind == UnitEdgeKind::RustDependency)
        .map(|edge| match outputs.artifacts.get(&edge.unit) {
            Some(RustcOutput::Library { rlib, rmeta, .. }) => Ok(DependencyInput {
                key: &edge.unit,
                alias: edge.alias.as_deref(),
                rlib,
                rmeta,
                cache_key: outputs.cache_keys.get(&edge.unit).copied(),
            }),
            _ => Err(Error::failure(format!(
                "cache input dependency `{} {}` has no compiled library",
                edge.unit.package.name, edge.unit.package.version
            ))),
        })
        .collect()
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

fn validate_dep_info(
    output: &RustcOutput,
    package_root: &Path,
    build_out_dir: Option<&Path>,
    source_remap: Option<&crate::unit::SourceRemap>,
) -> Result<()> {
    const MAX_DEP_INFO_BYTES: u64 = 16 * 1024 * 1024;
    let dep_info = match output {
        RustcOutput::Library { dep_info, .. } | RustcOutput::BuildScript { dep_info, .. } => {
            dep_info
        }
    };
    let metadata = fs::metadata(dep_info).map_err(|error| {
        Error::failure(format!(
            "failed to inspect rustc dep-info `{}`: {error}",
            dep_info.display()
        ))
    })?;
    if metadata.len() > MAX_DEP_INFO_BYTES {
        return Err(Error::failure(format!(
            "rustc dep-info `{}` exceeds the {} byte limit",
            dep_info.display(),
            MAX_DEP_INFO_BYTES
        )));
    }
    let bytes = fs::read(dep_info).map_err(|error| {
        Error::failure(format!(
            "failed to read rustc dep-info `{}`: {error}",
            dep_info.display()
        ))
    })?;
    let root = fs::canonicalize(package_root).map_err(|error| {
        Error::failure(format!(
            "failed to resolve package root `{}`: {error}",
            package_root.display()
        ))
    })?;
    let out_dir = build_out_dir
        .map(|path| {
            fs::canonicalize(path).map_err(|error| {
                Error::failure(format!(
                    "failed to resolve build-script OUT_DIR `{}`: {error}",
                    path.display()
                ))
            })
        })
        .transpose()?;
    for path in parse_dep_info_paths(&bytes)? {
        let path = source_remap
            .and_then(|remap| remap.restore_physical_path(&path))
            .unwrap_or_else(|| {
                if path.is_absolute() {
                    path
                } else {
                    root.join(path)
                }
            });
        let canonical = fs::canonicalize(&path).map_err(|error| {
            Error::failure(format!(
                "failed to resolve rustc dep-info input `{}`: {error}",
                path.display()
            ))
        })?;
        if !canonical.starts_with(&root)
            && !out_dir
                .as_ref()
                .is_some_and(|out_dir| canonical.starts_with(out_dir))
        {
            return Err(Error::failure(format!(
                "rustc dep-info input `{}` is outside package root `{}`{}",
                canonical.display(),
                root.display(),
                out_dir.as_ref().map_or_else(String::new, |out_dir| format!(
                    " and build-script OUT_DIR `{}`",
                    out_dir.display()
                ))
            ))
            .with_help(
                "keep dependency source inputs inside the package or its assigned OUT_DIR",
            ));
        }
    }
    Ok(())
}

pub(crate) fn parse_dep_info_paths(bytes: &[u8]) -> Result<Vec<PathBuf>> {
    let mut unfolded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && bytes.get(index + 1) == Some(&b'\n') {
            unfolded.push(b' ');
            index += 2;
        } else if bytes[index] == b'\\'
            && bytes.get(index + 1) == Some(&b'\r')
            && bytes.get(index + 2) == Some(&b'\n')
        {
            unfolded.push(b' ');
            index += 3;
        } else {
            unfolded.push(bytes[index]);
            index += 1;
        }
    }

    let mut paths = Vec::new();
    for line in unfolded.split(|byte| *byte == b'\n' || *byte == b'\r') {
        if line
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace())
            == Some(b'#')
        {
            continue;
        }
        let Some(delimiter) = line.iter().enumerate().position(|(index, byte)| {
            *byte == b':'
                && line
                    .get(index + 1)
                    .is_none_or(|next| next.is_ascii_whitespace())
        }) else {
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            return Err(Error::failure("rustc emitted malformed dep-info rule"));
        };
        let mut token = Vec::new();
        let mut escaped = false;
        for byte in &line[delimiter + 1..] {
            if escaped {
                token.push(*byte);
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if byte.is_ascii_whitespace() {
                push_dep_info_path(&mut paths, &mut token)?;
            } else if *byte == b'#' {
                break;
            } else {
                token.push(*byte);
            }
        }
        if escaped {
            return Err(Error::failure(
                "rustc emitted dep-info with a trailing escape",
            ));
        }
        push_dep_info_path(&mut paths, &mut token)?;
    }
    Ok(paths)
}

fn push_dep_info_path(paths: &mut Vec<PathBuf>, token: &mut Vec<u8>) -> Result<()> {
    if token.is_empty() {
        return Ok(());
    }
    let value = String::from_utf8(std::mem::take(token))
        .map_err(|_| Error::failure("rustc emitted a non-UTF-8 dep-info path"))?;
    paths.push(PathBuf::from(value));
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
        "/lib",
        "/lib64",
        "/usr/include",
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
    use crate::config::{CargoCompat, Config, NativeTool, NativeToolRole};
    use crate::manifest::ReleaseProfile;
    use crate::policy::PackageAdmission;
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
    fn parses_makefile_escaped_dep_info_paths() {
        let document = concat!(
            "/output/lib.rlib: /package/src/lib.rs /package/a\\ b.rs \\\n",
            "  /out/generated.rs\n",
            "/package/src/lib.rs:\n",
            "# env-dep:OUT_DIR=/out\n",
        );
        assert_eq!(
            parse_dep_info_paths(document.as_bytes()).unwrap(),
            [
                PathBuf::from("/package/src/lib.rs"),
                PathBuf::from("/package/a b.rs"),
                PathBuf::from("/out/generated.rs"),
            ]
        );
        assert!(parse_dep_info_paths(b"not-a-rule\n").is_err());
        assert!(parse_dep_info_paths(b"out: trailing\\").is_err());
    }

    #[test]
    fn runs_a_sandboxed_build_script_without_undeclared_native_tools() {
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
        let manifests = BTreeMap::from([(key.clone(), manifest)]);
        let admission = Admission {
            packages: BTreeMap::from([(
                key,
                PackageAdmission {
                    matching_allow_rules: Vec::new(),
                    native_tools: BTreeSet::new(),
                },
            )]),
        };
        let graph = dependency_units(&resolution, &manifests).unwrap();
        let (toolchain, target) = actual_toolchain();
        let native_tools = BTreeMap::from([(
            (target.triple.clone(), NativeToolRole::CCompiler),
            NativeTool {
                program: Some(PathBuf::from("/bin/true")),
                prefix_args: Vec::new(),
                flags: Vec::new(),
            },
        )]);
        let plan = plan_dependency_units(
            &graph,
            &manifests,
            &PlanOptions {
                workspace_root: &fixture.0,
                release: false,
                test_profile: false,
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
                workspace_root: &fixture.0,
                toolchain: &toolchain,
                host: &target,
                target: &target,
                host_profile: &profile,
                target_profile: &profile,
                host_incremental: &fixture.0.join("incremental/host"),
                target_incremental: &fixture.0.join("incremental/target"),
                physical_target: None,
                host_linker: None,
                target_linker: None,
                release: false,
                quiet: false,
                verbose: false,
                color: false,
                build_script_timeout: Duration::from_secs(10),
                build_script_output_bytes: 64 * 1024,
                out_dir_limits: DEFAULT_LIMITS,
                cache: None,
                admission: &admission,
                native_tools: &native_tools,
                jobs: 2,
            },
        )
        .unwrap();

        assert_eq!(outputs.artifacts.len(), 2);
        assert_eq!(outputs.build_scripts.len(), 1);
        let build = outputs.build_scripts.values().next().unwrap();
        assert!(
            !build.environment.keys().any(|name| name.starts_with("CC_")),
            "configured but ungranted C compiler leaked into the build-script environment"
        );
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
