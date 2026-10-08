use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::atomic::AtomicDirectory;
use crate::build_script::{self, EnvironmentOptions, RunOptions};
use crate::cache::{
    BuildCache, BuildCaches, BuildScriptInput, CacheKey, DependencyInput, SelectedInputs, UnitInput,
};
use crate::compile::{
    BuildOutput, CommandOptions, RustcInvocation, RustcOutput, dependency_directories,
    dependency_rustc_invocation, dependency_rustc_invocation_with_build_output,
    unit_output_directory,
};
use crate::diagnostic::{Error, Result};
use crate::hash::sha256_file;
use crate::manifest::Manifest;
use crate::native_tool;
use crate::policy::Admission;
use crate::process::RustcCommand;
use crate::resolver::{CompileKind, PackageKey, PackageSourceKey};
use crate::run_record;
use crate::sandbox::Executable;
use crate::source_tree::Limits as TreeLimits;
use crate::toolchain::{TargetInfo, Toolchain};
use crate::tracked_env::{self, Tracked};
use crate::unit::{CompilationPlan, PlannedUnit, UnitEdgeKind, UnitKey, UnitKind, UnitMode};

pub trait EventReporter: Sync {
    fn compiler_messages(
        &self,
        key: &UnitKey,
        planned: &PlannedUnit,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Result<()>;

    fn compiler_artifact(
        &self,
        key: &UnitKey,
        planned: &PlannedUnit,
        output: &RustcOutput,
        fresh: bool,
    ) -> Result<()>;

    fn build_script_executed(&self, key: &UnitKey, output: &ExecutedBuildScript) -> Result<()>;
}

pub struct Options<'a> {
    pub child_lease_fd: Option<i32>,
    pub cargo: &'a Path,
    pub workspace_root: &'a Path,
    pub workspace_members: &'a BTreeMap<String, PathBuf>,
    pub selected_packages: &'a [PackageKey],
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
    pub integration_binaries: Option<&'a BTreeMap<PackageKey, BTreeMap<String, PathBuf>>>,
    pub integration_temp_dirs: Option<&'a BTreeMap<PackageKey, PathBuf>>,
    pub release: bool,
    pub quiet: bool,
    pub verbose: bool,
    pub color: bool,
    pub build_script_timeout: Duration,
    pub build_script_output_bytes: u64,
    pub out_dir_limits: TreeLimits,
    pub cache: &'a BuildCaches,
    pub admission: &'a Admission,
    pub native_tools:
        &'a BTreeMap<(String, crate::config::NativeToolRole), crate::config::NativeTool>,
    /// Maximum number of units executed concurrently.
    pub jobs: usize,
    pub keep_going: bool,
    pub reporter: &'a dyn EventReporter,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutedBuildScript {
    pub output: build_script::Output,
    pub environment: BTreeMap<String, std::ffi::OsString>,
    pub executable_sha256: [u8; 32],
    pub out_dir: PathBuf,
    pub temp_dir: PathBuf,
    /// Caller variables that policy passes into the script's environment.
    pub caller_variables: BTreeSet<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Outputs {
    pub artifacts: BTreeMap<UnitKey, RustcOutput>,
    pub build_scripts: BTreeMap<UnitKey, ExecutedBuildScript>,
    pub cache_keys: BTreeMap<UnitKey, CacheKey>,
    /// Process variables that some unit's output depends on.
    pub tracked_variables: BTreeSet<String>,
}

/// One executed unit's result, recorded into `Outputs` by the scheduler.
enum Executed {
    BuildScript(ExecutedBuildScript),
    Artifact {
        output: RustcOutput,
        cache_key: CacheKey,
        tracked: Tracked,
    },
}

impl Executed {
    fn artifact(
        cache: &BuildCache,
        cache_key: CacheKey,
        output: RustcOutput,
        sources: Option<[u8; 32]>,
        tracked: Tracked,
    ) -> Self {
        Self::Artifact {
            cache_key: cache.dependency_key(cache_key, sources, &tracked),
            output,
            tracked,
        }
    }
}

/// Each dependent of a unit, and whether that dependent reads only the unit's
/// metadata.
type Dependents = BTreeMap<UnitKey, Vec<(UnitKey, bool)>>;

/// Shared scheduling state: units become ready when their last dependency
/// completes, or writes its metadata if that is all they read, and are
/// dispatched by rank.
struct Scheduler {
    ready: std::collections::BTreeSet<(usize, UnitKey)>,
    remaining: BTreeMap<UnitKey, usize>,
    metadata_ready: BTreeSet<UnitKey>,
    outputs: Outputs,
    failures: Vec<(usize, Error)>,
    dispatched: usize,
    completed: usize,
}

impl Scheduler {
    fn record(
        &mut self,
        dependents: &Dependents,
        rank_of: &BTreeMap<UnitKey, usize>,
        key: &UnitKey,
        executed: Executed,
    ) -> Result<()> {
        let released = self.metadata_ready.contains(key);
        self.record_output(key, executed);
        for (child, metadata) in dependents.get(key).map(Vec::as_slice).unwrap_or(&[]) {
            if !(*metadata && released) {
                self.release(child, rank_of)?;
            }
        }
        self.completed += 1;
        Ok(())
    }

    /// A library's metadata is written; dependents that read only that can
    /// start while its code generation continues.
    fn record_metadata(
        &mut self,
        dependents: &Dependents,
        rank_of: &BTreeMap<UnitKey, usize>,
        key: &UnitKey,
        executed: Executed,
    ) -> Result<()> {
        self.record_output(key, executed);
        self.metadata_ready.insert(key.clone());
        for (child, metadata) in dependents.get(key).map(Vec::as_slice).unwrap_or(&[]) {
            if *metadata {
                self.release(child, rank_of)?;
            }
        }
        Ok(())
    }

    fn record_output(&mut self, key: &UnitKey, executed: Executed) {
        match executed {
            Executed::BuildScript(output) => {
                self.outputs
                    .tracked_variables
                    .extend(output.caller_variables.iter().cloned());
                self.outputs.build_scripts.insert(key.clone(), output);
            }
            Executed::Artifact {
                output,
                cache_key,
                tracked,
            } => {
                self.outputs.tracked_variables.extend(tracked.into_keys());
                self.outputs.artifacts.insert(key.clone(), output);
                self.outputs.cache_keys.insert(key.clone(), cache_key);
            }
        }
    }

    fn release(&mut self, child: &UnitKey, rank_of: &BTreeMap<UnitKey, usize>) -> Result<()> {
        let counter = self
            .remaining
            .get_mut(child)
            .ok_or_else(|| Error::failure("dependency execution lost track of a scheduled unit"))?;
        *counter -= 1;
        if *counter == 0 {
            self.remaining.remove(child);
            let rank = *rank_of.get(child).ok_or_else(|| {
                Error::failure("dependency execution order is missing a ready unit")
            })?;
            self.ready.insert((rank, child.clone()));
        }
        Ok(())
    }
}

/// Whether a dependent can start once a library dependency's metadata is
/// written, as under Cargo's pipelining.
fn reads_metadata(
    manifests: &BTreeMap<PackageKey, Manifest>,
    planned: &PlannedUnit,
    edge: &crate::unit::UnitEdge,
) -> bool {
    edge.kind == UnitEdgeKind::RustDependency
        && edge.unit.kind == UnitKind::Library
        && edge.unit.mode == UnitMode::Build
        && manifests
            .get(&edge.unit.package)
            .and_then(|manifest| manifest.library.as_ref())
            .is_some_and(|library| {
                crate::compile::uses_dependency_metadata(manifests, planned, &edge.unit, library)
            })
}

/// Whether a unit links its library dependencies rather than reading their
/// metadata alone.
fn links_libraries(manifests: &BTreeMap<PackageKey, Manifest>, planned: &PlannedUnit) -> bool {
    planned.unit.dependencies.iter().any(|edge| {
        edge.kind == UnitEdgeKind::RustDependency
            && edge.unit.kind == UnitKind::Library
            && !reads_metadata(manifests, planned, edge)
    })
}

/// The libraries reachable from a unit through library dependencies. A
/// procedural macro's dependencies belong to the macro, not to its user.
fn linked_libraries<'a>(plan: &'a CompilationPlan, planned: &'a PlannedUnit) -> Vec<&'a UnitKey> {
    let mut found = BTreeSet::new();
    let mut pending = vec![planned];
    while let Some(unit) = pending.pop() {
        for edge in &unit.unit.dependencies {
            if edge.kind == UnitEdgeKind::RustDependency
                && edge.unit.kind == UnitKind::Library
                && found.insert(&edge.unit)
                && let Some(child) = plan.units.get(&edge.unit)
            {
                pending.push(child);
            }
        }
    }
    found.into_iter().collect()
}

/// Like Cargo, ranks first the units that the most other units wait on, so
/// long dependency chains start early. Ties keep plan order.
fn dispatch_ranks(
    plan: &CompilationPlan,
    index_of: &BTreeMap<UnitKey, usize>,
    dependents: &Dependents,
) -> BTreeMap<UnitKey, usize> {
    let mut waiting = vec![BTreeSet::new(); plan.order.len()];
    // Plan order lists dependencies first, so dependents are counted first.
    for (index, key) in plan.order.iter().enumerate().rev() {
        let mut units = BTreeSet::new();
        for (child, _) in dependents.get(key).into_iter().flatten() {
            let child = index_of[child];
            units.insert(child);
            units.extend(waiting[child].iter().copied());
        }
        waiting[index] = units;
    }
    let mut order = (0..plan.order.len()).collect::<Vec<_>>();
    order.sort_by_key(|index| (std::cmp::Reverse(waiting[*index].len()), *index));
    order
        .into_iter()
        .enumerate()
        .map(|(rank, index)| (plan.order[index].clone(), rank))
        .collect()
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

pub fn execute(
    plan: &CompilationPlan,
    manifests: &BTreeMap<PackageKey, Manifest>,
    options: &Options<'_>,
) -> Result<Outputs> {
    let commands = CommandOptions {
        cargo: options.cargo,
        workspace_root: options.workspace_root,
        selected_packages: options.selected_packages,
        host_profile: options.host_profile,
        target_profile: options.target_profile,
        host_incremental: options.host_incremental,
        target_incremental: options.target_incremental,
        physical_target: options.physical_target,
        host_linker: options.host_linker,
        target_linker: options.target_linker,
        integration_binaries: options.integration_binaries,
        integration_temp_dirs: options.integration_temp_dirs,
        verbose: options.verbose,
    };

    let total = plan.order.len();
    let mut index_of = BTreeMap::new();
    for (index, key) in plan.order.iter().enumerate() {
        index_of.insert(key.clone(), index);
    }
    let mut dependents = Dependents::new();
    // Strict keys hash dependency libraries, so dependents wait for them.
    let pipelining = PIPELINING && !options.cache.is_strict();
    let mut state = Scheduler {
        ready: std::collections::BTreeSet::new(),
        remaining: BTreeMap::new(),
        metadata_ready: BTreeSet::new(),
        outputs: Outputs::default(),
        failures: Vec::new(),
        dispatched: 0,
        completed: 0,
    };
    let mut initially_ready = Vec::new();
    for key in &plan.order {
        let planned = plan.units.get(key).ok_or_else(|| {
            Error::failure(format!(
                "dependency execution plan is missing {:?} unit `{} {}`",
                key.kind, key.package.name, key.package.version
            ))
        })?;
        let mut dependencies = planned
            .unit
            .dependencies
            .iter()
            .map(|edge| &edge.unit)
            .collect::<std::collections::BTreeSet<_>>();
        // A unit that links needs every library below it whole, not just its
        // direct dependencies, as Cargo arranges when it pipelines.
        if pipelining && links_libraries(manifests, planned) {
            dependencies.extend(linked_libraries(plan, planned));
        }
        for dependency in &dependencies {
            if !index_of.contains_key(*dependency) {
                return Err(Error::failure(
                    "dependency execution received an incomplete unit graph",
                ));
            }
            let mut edges = planned
                .unit
                .dependencies
                .iter()
                .filter(|edge| &edge.unit == *dependency)
                .peekable();
            let metadata = pipelining
                && edges.peek().is_some()
                && edges.all(|edge| reads_metadata(manifests, planned, edge));
            dependents
                .entry((*dependency).clone())
                .or_default()
                .push((key.clone(), metadata));
        }
        if dependencies.is_empty() {
            initially_ready.push(key.clone());
        } else {
            state.remaining.insert(key.clone(), dependencies.len());
        }
    }
    let rank_of = dispatch_ranks(plan, &index_of, &dependents);
    state
        .ready
        .extend(initially_ready.into_iter().map(|key| (rank_of[&key], key)));

    // Recovery enumerates shared unit parents. Finish it before workers can
    // rename or remove sibling entries; Motor's iterator needs stable entries.
    for key in &plan.order {
        if key.kind == UnitKind::BuildScriptRun {
            continue;
        }
        let planned = &plan.units[key];
        let output_dir = unit_output_directory(planned, &commands);
        let unit_dir = output_dir
            .parent()
            .ok_or_else(|| Error::failure("rustc unit has no output directory"))?;
        AtomicDirectory::recover_previous(unit_dir)?;
        AtomicDirectory::discard_abandoned_staging(unit_dir)?;
    }

    let workers = options.jobs.clamp(1, total.max(1));
    let state = std::sync::Mutex::new(state);
    let wakeup = std::sync::Condvar::new();
    let print = std::sync::Mutex::new(());
    let (stores, store_queue) = std::sync::mpsc::channel::<CacheStore<'_>>();
    let store_queue = std::sync::Mutex::new(store_queue);
    let store_failures = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..CACHE_STORE_THREADS {
            scope.spawn(|| store_in_caches(&store_queue, &store_failures));
        }
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    loop {
                        let mut guard = state
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        let (_, key) = loop {
                            if (!options.keep_going && !guard.failures.is_empty())
                                || guard.completed == total
                            {
                                return;
                            }
                            if let Some(entry) = guard.ready.iter().next().cloned() {
                                guard.ready.remove(&entry);
                                guard.dispatched += 1;
                                break entry;
                            }
                            if guard.dispatched == guard.completed {
                                if !guard.failures.is_empty() {
                                    return;
                                }
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
                        let index = index_of[&key];
                        let Some(planned) = plan.units.get(&key) else {
                            guard.failures.push((
                                index,
                                Error::failure("dependency execution plan lost a dispatched unit"),
                            ));
                            wakeup.notify_all();
                            return;
                        };
                        let inputs = snapshot_inputs(planned, &guard.outputs);
                        drop(guard);
                        let on_metadata = |executed| {
                            let mut guard = state
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            let recorded =
                                guard.record_metadata(&dependents, &rank_of, &key, executed);
                            if let Err(error) = recorded {
                                guard.failures.push((index, error));
                            }
                            wakeup.notify_all();
                        };
                        let outcome = execute_unit(
                            plan,
                            manifests,
                            options,
                            &commands,
                            &key,
                            planned,
                            &inputs,
                            &print,
                            &stores,
                            &on_metadata,
                        );
                        let mut guard = state
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        match outcome {
                            Ok(executed) => {
                                let recorded = guard.record(&dependents, &rank_of, &key, executed);
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
        // Store threads finish the queued copies and exit.
        drop(stores);
    });

    let state = state
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((_, error)) = state.failures.into_iter().min_by_key(|(index, _)| *index) {
        return Err(error);
    }
    if let Some(error) = store_failures
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .into_iter()
        .next()
    {
        return Err(error);
    }
    Ok(state.outputs)
}

/// Motor's directory listing ends early when an entry it has not returned yet
/// is removed. A pipelined library's compiler removes temporary files while
/// dependents' rustc lists its directory, so Motor builds do not pipeline.
const PIPELINING: bool = cfg!(not(target_os = "motor"));

/// Copying a library into its cache is I/O bound, so a few threads keep up
/// with the compiler workers.
const CACHE_STORE_THREADS: usize = 4;

/// A published library's copy into its cache. It runs off the compiler
/// workers, so dependents need not wait for the copy.
struct CacheStore<'a> {
    cache: &'a BuildCache,
    key: CacheKey,
    package: PackageKey,
    output: RustcOutput,
    build_script: Option<ExecutedBuildScript>,
    sources: Option<[u8; 32]>,
    diagnostics: Vec<u8>,
    tracked: Tracked,
}

impl CacheStore<'_> {
    fn run(&self) -> Result<()> {
        self.cache.store(
            self.key,
            &self.output,
            self.build_script
                .as_ref()
                .map(cache_build_script_input)
                .as_ref(),
            self.sources,
            (&[], &self.diagnostics),
            &self.tracked,
        )?;
        self.cache.record_cache_owner(self.key, &self.package)
    }
}

fn store_in_caches(
    queue: &std::sync::Mutex<std::sync::mpsc::Receiver<CacheStore<'_>>>,
    failures: &std::sync::Mutex<Vec<Error>>,
) {
    loop {
        let job = queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .recv();
        let Ok(job) = job else { return };
        if let Err(error) = job.run() {
            failures
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(error);
        }
    }
}

/// Executes one plan unit against a snapshot of its direct-dependency
/// outputs. Diagnostics are rendered as one uninterrupted block under the
/// shared print lock.
#[allow(clippy::too_many_arguments)]
fn execute_unit<'a>(
    plan: &'a CompilationPlan,
    manifests: &BTreeMap<PackageKey, Manifest>,
    options: &Options<'a>,
    commands: &CommandOptions<'_>,
    key: &UnitKey,
    planned: &'a crate::unit::PlannedUnit,
    outputs: &Outputs,
    print: &std::sync::Mutex<()>,
    stores: &std::sync::mpsc::Sender<CacheStore<'a>>,
    on_metadata: &dyn Fn(Executed),
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
                let compile = plan.units.get(compile_key).ok_or_else(|| {
                    Error::failure(format!(
                        "build-script executable unit for `{} {}` is absent",
                        key.package.name, key.package.version
                    ))
                })?;
                let directories = dependency_directories(plan, compile, commands)?;
                let dynamic_library_paths = directories
                    .iter()
                    .filter(|directory| directory.compile_kind == CompileKind::Host)
                    .map(|directory| directory.path.clone())
                    .collect::<Vec<_>>();
                let out_dir = unit_output_directory(planned, commands);
                let root = out_dir
                    .parent()
                    .ok_or_else(|| Error::failure("build-script output has no unit directory"))?;
                let temp_dir = root.join("tmp");
                create_directory(&out_dir, "build-script OUT_DIR")?;
                create_directory(&temp_dir, "build-script temporary directory")?;
                crate::artifact_owner::write(
                    root.parent()
                        .ok_or_else(|| Error::failure("build-script run has no unit directory"))?,
                    &key.package,
                )?;
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
                        dynamic_library_paths: &dynamic_library_paths,
                        out_dir: &out_dir,
                        temp_dir: &temp_dir,
                        release: options.release,
                        num_jobs: options.jobs,
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
                let caller = admission
                    .caller_env
                    .iter()
                    .filter_map(|name| std::env::var_os(name).map(|value| (name.clone(), value)))
                    .collect();
                build_script::add_caller_environment(
                    &mut environment,
                    &admission.caller_env,
                    &caller,
                )?;
                let mut read_only = sandbox_inputs(
                    manifests,
                    options,
                    directories.iter().map(|directory| directory.path.clone()),
                );
                read_only.extend(native.read_only);
                read_only.sort();
                read_only.dedup();
                let mut executables = vec![Executable {
                    path: options.toolchain.rustc.clone(),
                    argument_prefix: Vec::new(),
                }];
                executables.extend(native.executables);
                let workspace_lock = options.workspace_root.join("Cargo.lock");
                let run_options = RunOptions {
                    child_lease_fd: options.child_lease_fd,
                    executable,
                    arguments: &[],
                    environment: &environment,
                    package_root: &manifest.root,
                    workspace_root: manifest
                        .editable
                        .then_some(manifest.workspace_root.as_path()),
                    workspace_lock: workspace_lock.exists().then_some(workspace_lock.as_path()),
                    out_dir: &out_dir,
                    temp_dir: &temp_dir,
                    read_only: &read_only,
                    executables: &executables,
                    timeout: options.build_script_timeout,
                    max_output_bytes: options.build_script_output_bytes,
                    out_dir_limits: options.out_dir_limits,
                    verbose: options.verbose,
                };
                let executable_sha256 = sha256_file(executable)?;
                let run_key = run_record::key(
                    &options.toolchain.verbose_version,
                    &executable_sha256,
                    &environment,
                    &executables,
                );
                let package_sources = || match key.package.source {
                    PackageSourceKey::Path(_) => {
                        crate::member_source::snapshot(manifest, false).map(|s| Some(s.sha256))
                    }
                    PackageSourceKey::CratesIo | PackageSourceKey::Git(_) => Ok(None),
                };
                let build_output =
                    match run_record::fresh(root, &run_key, &run_options, package_sources) {
                        Some(output) => {
                            let _guard = print
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            if options.verbose {
                                eprintln!(
                                    "Fresh {} v{} (build script)",
                                    key.package.name, key.package.version
                                );
                            }
                            render_build_script_warnings(key, &output);
                            output
                        }
                        None => run_build_script(
                            key,
                            manifest,
                            options,
                            &run_options,
                            root,
                            &run_key,
                            package_sources()?,
                            print,
                        )?,
                    };
                let executed = ExecutedBuildScript {
                    output: build_output,
                    environment,
                    executable_sha256,
                    out_dir,
                    temp_dir,
                    caller_variables: admission.caller_env.clone(),
                };
                options.reporter.build_script_executed(key, &executed)?;
                Ok(Executed::BuildScript(executed))
            }
            UnitKind::Library
            | UnitKind::Binary
            | UnitKind::LibraryHarness
            | UnitKind::BinaryHarness
            | UnitKind::IntegrationHarness
            | UnitKind::Example
            | UnitKind::Bench
            | UnitKind::ProcMacro
            | UnitKind::BuildScriptCompile => {
                let manifest = manifests.get(&key.package).ok_or_else(|| {
                    Error::failure(format!(
                        "dependency execution has no manifest for `{} {}`",
                        key.package.name, key.package.version
                    ))
                })?;
                let executed_build_script = if key.kind != UnitKind::BuildScriptCompile {
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
                let mut planned_invocation = match build_output {
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
                let driver = options.toolchain.clippy.as_ref().filter(|_| {
                    options
                        .workspace_members
                        .values()
                        .any(|root| root == &manifest.root)
                });
                if let Some(driver) = driver {
                    planned_invocation
                        .environment
                        .insert("CLIPPY_ARGS".to_owned(), driver.arguments.clone().into());
                }
                let mut clippy_inputs = Vec::new();
                if let Some(driver) = driver {
                    clippy_inputs.extend([
                        planned_invocation.current_dir.join("Cargo.toml"),
                        driver.path.clone(),
                    ]);
                    clippy_inputs.extend(
                        crate::clippy::configuration_candidates(
                            &manifest.root,
                            &planned_invocation.current_dir,
                            &driver.arguments,
                            options.selected_packages.contains(&key.package),
                        )
                        .into_iter()
                        .filter(|path| path.is_file()),
                    );
                }
                let output_dir = unit_output_directory(planned, commands);
                let unit_dir = output_dir
                    .parent()
                    .ok_or_else(|| Error::failure("rustc unit has no output directory"))?;
                let parent = unit_dir
                    .parent()
                    .ok_or_else(|| Error::failure("rustc unit has no parent directory"))?;
                let label = unit_dir
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| Error::failure("rustc unit has no UTF-8 name"))?;
                let dependencies = cache_dependencies(planned, outputs)?;
                let selected = options.selected_packages.contains(&key.package);
                let selected_inputs =
                    (manifest.editable || driver.is_some()).then_some(SelectedInputs {
                        working_dir: &planned_invocation.current_dir,
                        source_remap: planned.source_remap.as_ref(),
                    });
                let cache_build_script = executed_build_script.map(cache_build_script_input);
                let caches = options.cache;
                let cache = caches.for_unit(planned);
                let restorable = matches!(key.kind, UnitKind::Library | UnitKind::ProcMacro)
                    && matches!(
                        &planned_invocation.output,
                        RustcOutput::Library { .. }
                            | RustcOutput::StaticLibrary { .. }
                            | RustcOutput::ProcMacro { .. }
                    );
                let cache_key = cache.key(&UnitInput {
                    key,
                    selected,
                    planned,
                    manifest,
                    invocation: &planned_invocation,
                    host_profile: options.host_profile,
                    target_profile: options.target_profile,
                    dependencies: &dependencies,
                    build_script: cache_build_script,
                })?;
                if let Some((tracked, sources)) = cache.published_fresh(
                    cache_key,
                    &planned_invocation.output,
                    selected_inputs,
                    &key.package,
                )? {
                    if options.verbose {
                        eprintln!(
                            "Fresh {} v{} (published Lorry unit)",
                            key.package.name, key.package.version
                        );
                    }
                    if replays_messages(key, options) {
                        let (stdout, stderr) =
                            cache.published_messages(&planned_invocation.output)?;
                        options
                            .reporter
                            .compiler_messages(key, planned, &stdout, &stderr)?;
                    }
                    options.reporter.compiler_artifact(
                        key,
                        planned,
                        &planned_invocation.output,
                        true,
                    )?;
                    return Ok(Executed::artifact(
                        cache,
                        cache_key,
                        planned_invocation.output,
                        sources,
                        tracked,
                    ));
                }
                let staging = AtomicDirectory::new_stable(parent, label)?;
                let invocation = planned_invocation.with_output_directory(
                    &staging.path().join(
                        output_dir
                            .file_name()
                            .ok_or_else(|| Error::failure("rustc output has no directory name"))?,
                    ),
                )?;
                create_output_directories(&invocation.output)?;
                if restorable
                    && let Some(restored) =
                        cache.restore(cache_key, &invocation.output, selected_inputs)?
                {
                    let (stdout, stderr) = (&restored.stdout, &restored.stderr);
                    cache.record_cache_owner(cache_key, &key.package)?;
                    cache.record_published(
                        cache_key,
                        &invocation.output,
                        restored.sources,
                        &key.package,
                        (stdout, stderr),
                        &restored.tracked,
                    )?;
                    staging.commit(unit_dir)?;
                    if options.verbose {
                        eprintln!(
                            "Fresh {} v{} (verified Lorry cache)",
                            key.package.name, key.package.version
                        );
                    }
                    if replays_messages(key, options) {
                        options
                            .reporter
                            .compiler_messages(key, planned, stdout, stderr)?;
                    }
                    options.reporter.compiler_artifact(
                        key,
                        planned,
                        &planned_invocation.output,
                        true,
                    )?;
                    return Ok(Executed::artifact(
                        cache,
                        cache_key,
                        planned_invocation.output,
                        restored.sources,
                        restored.tracked,
                    ));
                }
                // Like Cargo, a library compiles in place, so a dependent that
                // reads only its metadata can start during code generation.
                // Removing its record first keeps an interrupted compile stale.
                let pipelined = PIPELINING
                    && key.kind == UnitKind::Library
                    && key.mode == UnitMode::Build
                    && matches!(planned_invocation.output, RustcOutput::Library { .. })
                    && !cache.is_strict();
                let (invocation, staging) = if pipelined {
                    drop(staging);
                    create_output_directories(&planned_invocation.output)?;
                    cache.unpublish(&planned_invocation.output)?;
                    (planned_invocation.clone(), None)
                } else {
                    (invocation, Some(staging))
                };
                if restorable && !options.quiet && caches.report_shared_rebuild(planned) {
                    let _guard = print
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    eprintln!("Rebuilding global dependency cache");
                }
                if restorable && options.verbose {
                    eprintln!("Cache miss {} v{}", key.package.name, key.package.version);
                }
                if !options.quiet {
                    let _guard = print
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let unit = match key.kind {
                        UnitKind::Library => "library".to_owned(),
                        UnitKind::Binary => format!(
                            "binary `{}`",
                            key.target.as_deref().ok_or_else(|| Error::failure(
                                "selected binary has no target name"
                            ))?
                        ),
                        UnitKind::LibraryHarness
                        | UnitKind::BinaryHarness
                        | UnitKind::IntegrationHarness => format!(
                            "test `{}`",
                            key.target.as_deref().ok_or_else(|| Error::failure(
                                "selected harness has no target name"
                            ))?
                        ),
                        UnitKind::ProcMacro => "proc macro".to_owned(),
                        UnitKind::Example | UnitKind::Bench => format!(
                            "{} `{}`",
                            if key.kind == UnitKind::Example {
                                "example"
                            } else {
                                "bench"
                            },
                            key.target.as_deref().unwrap()
                        ),
                        UnitKind::BuildScriptCompile => "build script".to_owned(),
                        UnitKind::BuildScriptRun => unreachable!(),
                    };
                    eprintln!(
                        "Compiling {} v{} ({}) [{unit}]",
                        key.package.name,
                        key.package.version,
                        manifest.root.display()
                    );
                }
                let command = RustcCommand {
                    child_lease_fd: options.child_lease_fd,
                    program: driver.map_or(&options.toolchain.rustc, |driver| &driver.path),
                    arguments: &invocation.arguments,
                    environment: &invocation.environment,
                    current_dir: &invocation.current_dir,
                    verbose: options.verbose,
                    color: options.color,
                };
                let started = run_record::now();
                let metadata_written = || -> Result<Executed> {
                    validate_dep_info(
                        &invocation.output,
                        &manifest.root,
                        &invocation.current_dir,
                        manifest.editable,
                        executed_build_script.map(|build| build.out_dir.as_path()),
                        planned.source_remap.as_ref(),
                        &clippy_inputs,
                    )?;
                    let (sources, racing) =
                        compiled_sources(&invocation.output, selected_inputs, started)?;
                    if racing {
                        return Err(Error::failure("a member source changed during compilation"));
                    }
                    Ok(Executed::artifact(
                        cache,
                        cache_key,
                        planned_invocation.output.clone(),
                        sources,
                        tracked_environment(&invocation)?,
                    ))
                };
                let rustc_output = if pipelined {
                    let mut signaled = false;
                    command.execute_observed(&mut |line| {
                        // A failed early check leaves dependents to the end,
                        // where the same check reports the error.
                        if !signaled
                            && is_metadata_artifact(line)
                            && let Ok(executed) = metadata_written()
                        {
                            signaled = true;
                            on_metadata(executed);
                        }
                    })?
                } else {
                    command.execute()?
                };
                options.reporter.compiler_messages(
                    key,
                    planned,
                    &rustc_output.stdout,
                    &rustc_output.stderr,
                )?;
                RustcCommand::require_success(&rustc_output)?;
                verify_outputs(&invocation.output)?;
                let diagnostics = (
                    Vec::new(),
                    RustcCommand::diagnostic_messages(&rustc_output.stderr),
                );
                validate_dep_info(
                    &invocation.output,
                    &manifest.root,
                    &invocation.current_dir,
                    manifest.editable,
                    executed_build_script.map(|build| build.out_dir.as_path()),
                    planned.source_remap.as_ref(),
                    &clippy_inputs,
                )?;
                let tracked = tracked_environment(&invocation)?;
                if let RustcOutput::BuildScript {
                    executable,
                    unhashed_executable,
                    ..
                } = &invocation.output
                {
                    install_unhashed(executable, unhashed_executable)?;
                }
                // A unit whose sources changed while rustc ran is used by this
                // build only: it is neither recorded nor stored, and its
                // dependents get a key that no later build matches.
                let (sources, racing) =
                    compiled_sources(&invocation.output, selected_inputs, started)?;
                if !racing {
                    cache.record_published(
                        cache_key,
                        &invocation.output,
                        sources,
                        &key.package,
                        (&diagnostics.0, &diagnostics.1),
                        &tracked,
                    )?;
                }
                if let Some(staging) = staging {
                    staging.commit(unit_dir)?;
                }
                if restorable && !racing {
                    stores
                        .send(CacheStore {
                            cache,
                            key: cache_key,
                            package: key.package.clone(),
                            output: planned_invocation.output.clone(),
                            build_script: executed_build_script.cloned(),
                            sources,
                            diagnostics: diagnostics.1.clone(),
                            tracked: tracked.clone(),
                        })
                        .map_err(|_| Error::failure("cache store threads stopped unexpectedly"))?;
                }
                options.reporter.compiler_artifact(
                    key,
                    planned,
                    &planned_invocation.output,
                    false,
                )?;
                Ok(Executed::artifact(
                    cache,
                    cache_key,
                    planned_invocation.output,
                    if racing {
                        Some(racing_sources())
                    } else {
                        sources
                    },
                    tracked,
                ))
            }
        }
    }
}

/// Digests a member unit's sources after rustc, and reports whether one of
/// them changed after rustc started, so its outputs may not reflect it.
fn compiled_sources(
    output: &RustcOutput,
    selected: Option<SelectedInputs<'_>>,
    started: Duration,
) -> Result<(Option<[u8; 32]>, bool)> {
    let Some(inputs) = selected else {
        return Ok((None, false));
    };
    let (digest, newest) = crate::cache::source_inputs(output, inputs)?;
    Ok((Some(digest), newest >= started))
}

/// A source digest that no real sources produce.
fn racing_sources() -> [u8; 32] {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut digest = crate::hash::FieldDigest::tagged(b"lorry-racing-sources\0");
    digest.bytes("time", &run_record::now().as_nanos().to_le_bytes());
    digest.bytes("process", &std::process::id().to_le_bytes());
    let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    digest.bytes("sequence", &next.to_le_bytes());
    digest.finish()
}

/// Whether a rustc stderr line reports that the metadata file is written.
fn is_metadata_artifact(line: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(line).is_ok_and(|message| {
        message
            .get("$message_type")
            .and_then(serde_json::Value::as_str)
            == Some("artifact")
            && message.get("emit").and_then(serde_json::Value::as_str) == Some("metadata")
    })
}

/// Registry and Git dependencies compile with `--cap-lints allow` outside
/// verbose builds. Like Cargo, a reused unit of theirs then replays nothing,
/// even warnings that an earlier verbose build recorded.
fn replays_messages(key: &UnitKey, options: &Options<'_>) -> bool {
    options.verbose || matches!(key.package.source, PackageSourceKey::Path(_))
}

/// The process variables rustc reported reading. Variables Lorry set for this
/// invocation are already part of the unit key.
fn tracked_environment(invocation: &RustcInvocation) -> Result<Tracked> {
    let dep_info = invocation.output.dep_info();
    let bytes = fs::read(dep_info).map_err(|error| {
        Error::failure(format!(
            "failed to read rustc dep-info `{}`: {error}",
            dep_info.display()
        ))
    })?;
    let mut tracked = tracked_env::parse(&bytes)?;
    tracked.retain(|name, _| !invocation.environment.contains_key(name));
    Ok(tracked)
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
            Some(RustcOutput::ProcMacro {
                dynamic_library, ..
            }) => Ok(DependencyInput {
                key: &edge.unit,
                alias: edge.alias.as_deref(),
                rlib: dynamic_library,
                rmeta: dynamic_library,
                cache_key: outputs.cache_keys.get(&edge.unit).copied(),
            }),
            Some(RustcOutput::Metadata { metadata, .. }) => Ok(DependencyInput {
                key: &edge.unit,
                alias: edge.alias.as_deref(),
                rlib: metadata,
                rmeta: metadata,
                cache_key: outputs.cache_keys.get(&edge.unit).copied(),
            }),
            Some(RustcOutput::StaticLibrary { archive, .. }) => Ok(DependencyInput {
                key: &edge.unit,
                alias: edge.alias.as_deref(),
                rlib: archive,
                rmeta: archive,
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
        RustcOutput::StaticLibrary { archive, .. } => archive,
        RustcOutput::Binary { executable, .. } => executable,
        RustcOutput::Metadata { metadata, .. } => metadata,
        RustcOutput::ProcMacro {
            dynamic_library, ..
        } => dynamic_library,
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
            archive,
        } => {
            let mut paths = vec![rlib, rmeta, dep_info];
            paths.extend(archive.iter());
            paths
        }
        RustcOutput::Binary {
            executable,
            dep_info,
        } => vec![executable, dep_info],
        RustcOutput::Metadata { metadata, dep_info } => vec![metadata, dep_info],
        RustcOutput::BuildScript {
            executable,
            dep_info,
            ..
        } => vec![executable, dep_info],
        RustcOutput::ProcMacro {
            dynamic_library,
            dep_info,
        } => vec![dynamic_library, dep_info],
        RustcOutput::StaticLibrary { archive, dep_info } => vec![archive, dep_info],
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
    working_dir: &Path,
    selected: bool,
    build_out_dir: Option<&Path>,
    source_remap: Option<&crate::unit::SourceRemap>,
    allowed_inputs: &[PathBuf],
) -> Result<()> {
    let dep_info = match output {
        RustcOutput::Library { dep_info, .. }
        | RustcOutput::StaticLibrary { dep_info, .. }
        | RustcOutput::Binary { dep_info, .. }
        | RustcOutput::Metadata { dep_info, .. }
        | RustcOutput::ProcMacro { dep_info, .. }
        | RustcOutput::BuildScript { dep_info, .. } => dep_info,
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
    let allowed_inputs = allowed_inputs
        .iter()
        .map(|path| {
            fs::canonicalize(path).map_err(|error| {
                Error::failure(format!(
                    "failed to resolve Clippy input `{}`: {error}",
                    path.display()
                ))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    for path in parse_dep_info_paths(&bytes)? {
        let path = source_remap
            .and_then(|remap| remap.restore_physical_path(&path))
            .unwrap_or_else(|| {
                if path.is_absolute() {
                    path
                } else {
                    working_dir.join(path)
                }
            });
        let canonical = fs::canonicalize(&path).map_err(|error| {
            Error::failure(format!(
                "failed to resolve rustc dep-info input `{}`: {error}",
                path.display()
            ))
        })?;
        if !selected
            && !canonical.starts_with(&root)
            && !allowed_inputs.contains(&canonical)
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

const MAX_DEP_INFO_BYTES: u64 = 16 * 1024 * 1024;

pub(crate) struct DepInfo {
    pub bytes: Vec<u8>,
    /// Each input as placed by the caller, with its canonical path.
    pub inputs: Vec<(PathBuf, PathBuf)>,
}

/// Reads a bounded rustc dep-info file. Each listed input is placed by
/// `resolve` and then canonicalized; `kind` names the inputs in errors.
pub(crate) fn read_dep_info(
    path: &Path,
    kind: &str,
    resolve: impl Fn(PathBuf) -> PathBuf,
) -> Result<DepInfo> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
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
    let bytes = fs::read(path).map_err(|error| {
        Error::failure(format!(
            "failed to read rustc dep-info `{}`: {error}",
            path.display()
        ))
    })?;
    let mut inputs = Vec::new();
    for input in parse_dep_info_paths(&bytes)? {
        let input = resolve(input);
        let canonical = fs::canonicalize(&input).map_err(|error| {
            Error::failure(format!(
                "failed to resolve {kind} `{}`: {error}",
                input.display()
            ))
        })?;
        inputs.push((input, canonical));
    }
    Ok(DepInfo { bytes, inputs })
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
    dependency_directories: impl IntoIterator<Item = PathBuf>,
) -> Vec<PathBuf> {
    let mut paths = manifests
        .values()
        .map(|manifest| manifest.root.clone())
        .collect::<Vec<_>>();
    paths.extend(dependency_directories);
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

/// Runs a build script that has no fresh record and records the run.
#[allow(clippy::too_many_arguments)]
fn run_build_script(
    key: &UnitKey,
    manifest: &Manifest,
    options: &Options<'_>,
    run_options: &RunOptions<'_>,
    directory: &Path,
    run_key: &[u8; 32],
    package_sources: Option<[u8; 32]>,
    print: &std::sync::Mutex<()>,
) -> Result<build_script::Output> {
    run_record::remove(directory)?;
    if !options.quiet {
        let _guard = print
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        eprintln!(
            "Running build script {} v{} ({})",
            key.package.name,
            key.package.version,
            manifest.root.display()
        );
    }
    let started = run_record::now();
    let output = build_script::run(run_options)?;
    for directive in &output.directives {
        if let build_script::Directive::RerunIfEnvChanged { name, value: None } = directive
            && std::env::var_os(name).is_some()
        {
            let advice = if build_script::validate_caller_environment_name(name).is_ok() {
                format!("add caller-env = [\"{name}\"] to the named path build-script rule")
            } else {
                "use the documented compiler/native-tool configuration; this variable is controlled"
                    .into()
            };
            eprintln!(
                "warning: {} build script tracks hidden caller variable `{name}`; {advice}",
                key.package.name
            );
        }
    }
    {
        let _guard = print
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        render_build_script_output(key, &output);
    }
    run_record::write(
        directory,
        run_key,
        run_options,
        &output,
        package_sources,
        started,
    )?;
    Ok(output)
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
    render_build_script_warnings(key, output);
}

/// A fresh run replays only the script's warnings, as Cargo does.
fn render_build_script_warnings(key: &UnitKey, output: &build_script::Output) {
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

    struct SilentReporter;

    impl EventReporter for SilentReporter {
        fn compiler_messages(
            &self,
            _: &UnitKey,
            _: &PlannedUnit,
            _: &[u8],
            _: &[u8],
        ) -> Result<()> {
            Ok(())
        }

        fn compiler_artifact(
            &self,
            _: &UnitKey,
            _: &PlannedUnit,
            _: &RustcOutput,
            _: bool,
        ) -> Result<()> {
            Ok(())
        }

        fn build_script_executed(&self, _: &UnitKey, _: &ExecutedBuildScript) -> Result<()> {
            Ok(())
        }
    }

    fn actual_toolchain() -> (Toolchain, TargetInfo) {
        let mut config = Config::default();
        config.cargo_compat = Some(CargoCompat::V1_99);
        let toolchain = Toolchain::discover(None, &config, false).unwrap();
        let target = toolchain.target_info(None).unwrap();
        (toolchain, target)
    }

    /// Records whether any reported compiler message mentions `needle`.
    struct MessageReporter(&'static str, std::sync::atomic::AtomicBool);

    impl EventReporter for MessageReporter {
        fn compiler_messages(
            &self,
            _: &UnitKey,
            _: &PlannedUnit,
            stdout: &[u8],
            stderr: &[u8],
        ) -> Result<()> {
            let text = [stdout, stderr].concat();
            if String::from_utf8_lossy(&text).contains(self.0) {
                self.1.store(true, Ordering::Relaxed);
            }
            Ok(())
        }

        fn compiler_artifact(
            &self,
            _: &UnitKey,
            _: &PlannedUnit,
            _: &RustcOutput,
            _: bool,
        ) -> Result<()> {
            Ok(())
        }

        fn build_script_executed(&self, _: &UnitKey, _: &ExecutedBuildScript) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn reused_registry_units_replay_capped_warnings_only_when_verbose() {
        let fixture = Fixture::new();
        let package = fixture.0.join("package");
        fs::write(
            package.join("Cargo.toml"),
            "[package]\nname = \"warns\"\nversion = \"1.0.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::remove_file(package.join("build.rs")).unwrap();
        fs::write(package.join("src/lib.rs"), "fn never_called() {}\n").unwrap();
        let manifest = Manifest::load_path_dependency(&package).unwrap();
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
                    native_tools: BTreeSet::new(),
                    caller_env: Default::default(),
                },
            )]),
        };
        let graph = dependency_units(&resolution, &manifests).unwrap();
        let (toolchain, target) = actual_toolchain();
        let plan = plan_dependency_units(
            &graph,
            &manifests,
            &PlanOptions {
                workspace_root: &fixture.0,
                release: false,
                panic_abort: false,
                profile: &crate::manifest::Profile::default(),
                rustc: &toolchain,
                logical_target: None,
                rustflags: &[],
            },
        )
        .unwrap();
        let profile = fixture.0.join("output/debug");
        let cargo = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let cache = BuildCaches::new(
            &fixture.0.join("global-cache"),
            &fixture.0.join("local-cache"),
            &crate::cache::Options {
                cargo: &cargo,
                toolchain: &toolchain,
                host: &target,
                target: &target,
                host_linker: None,
                target_linker: None,
                root_manifest: manifests.values().next().unwrap(),
                source_limits: DEFAULT_LIMITS,
                validation: crate::validation::ValidationMode::Trusted,
            },
        )
        .unwrap();
        let build = |verbose| {
            let reporter = MessageReporter("never_called", Default::default());
            execute(
                &plan,
                &manifests,
                &Options {
                    cargo: &cargo,
                    child_lease_fd: None,
                    workspace_root: &fixture.0,
                    workspace_members: &BTreeMap::new(),
                    selected_packages: &[],
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
                    integration_binaries: None,
                    integration_temp_dirs: None,
                    release: false,
                    quiet: true,
                    verbose,
                    color: false,
                    build_script_timeout: Duration::from_secs(10),
                    build_script_output_bytes: 64 * 1024,
                    out_dir_limits: DEFAULT_LIMITS,
                    cache: &cache,
                    admission: &admission,
                    native_tools: &BTreeMap::new(),
                    jobs: 1,
                    keep_going: false,
                    reporter: &reporter,
                },
            )
            .unwrap();
            reporter.1.into_inner()
        };
        // A verbose build caps dependency lints at `warn` and records them.
        assert!(build(true));
        // An ordinary build caps them at `allow`, so its reuse shows none.
        assert!(!build(false));
        assert!(build(true));
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
                    native_tools: BTreeSet::new(),
                    caller_env: Default::default(),
                },
            )]),
        };
        let graph = dependency_units(&resolution, &manifests).unwrap();
        let (toolchain, target) = actual_toolchain();
        let native_tools = BTreeMap::from([(
            (target.triple.clone(), NativeToolRole::CCompiler),
            NativeTool {
                cpp_stdlib: None,
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
                panic_abort: false,
                profile: &crate::manifest::Profile::default(),
                rustc: &toolchain,
                logical_target: None,
                rustflags: &[],
            },
        )
        .unwrap();
        let profile = fixture.0.join("output/debug");
        let cargo = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let cache = BuildCaches::new(
            &fixture.0.join("global-cache"),
            &fixture.0.join("local-cache"),
            &crate::cache::Options {
                cargo: &cargo,
                toolchain: &toolchain,
                host: &target,
                target: &target,
                host_linker: None,
                target_linker: None,
                root_manifest: manifests.values().next().unwrap(),
                source_limits: DEFAULT_LIMITS,
                validation: crate::validation::ValidationMode::Trusted,
            },
        )
        .unwrap();
        let outputs = execute(
            &plan,
            &manifests,
            &Options {
                cargo: &cargo,
                child_lease_fd: None,
                workspace_root: &fixture.0,
                workspace_members: &BTreeMap::new(),
                selected_packages: &[],
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
                integration_binaries: None,
                integration_temp_dirs: None,
                release: false,
                quiet: false,
                verbose: false,
                color: false,
                build_script_timeout: Duration::from_secs(10),
                build_script_output_bytes: 64 * 1024,
                out_dir_limits: DEFAULT_LIMITS,
                cache: &cache,
                admission: &admission,
                native_tools: &native_tools,
                jobs: 2,
                keep_going: false,
                reporter: &SilentReporter,
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
