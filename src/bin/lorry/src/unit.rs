#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::diagnostic::{Error, Result};
use crate::hash::{Sha256, hex};
use crate::identity::{
    CargoCompileMode, CargoCrateType, CargoDebugInfo, CargoPanicStrategy, CargoProfile,
    CargoProfileLto, CargoSource, CargoStrip, CargoTargetKind, CargoUnitIdentityInput,
    CargoUnitLto, Identity, RootTargetKind, cargo_unit_identity, root_lto,
};
use crate::manifest::{DevProfile, Lto as ManifestLto, Manifest, ReleaseProfile};
use crate::resolver::{
    CompileKind, FeatureContext, PackageKey, PackageSourceKey, Resolution, ResolvedEdge,
    ResolvedPackage, selected_root_features,
};
use crate::source_tree::Exclusions;
use crate::sparse::DependencyKind;
use crate::toolchain::Toolchain;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum UnitKind {
    Library,
    Binary,
    LibraryHarness,
    BinaryHarness,
    IntegrationHarness,
    Example,
    Bench,
    ProcMacro,
    BuildScriptCompile,
    BuildScriptRun,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProfileContext {
    Normal,
    Test,
    Selected,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum UnitMode {
    Build,
    Test,
    Check,
    CheckTest,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnitKey {
    pub package: PackageKey,
    pub kind: UnitKind,
    pub mode: UnitMode,
    pub target: Option<String>,
    pub compile_kind: CompileKind,
    pub profile: ProfileContext,
    pub features: BTreeSet<String>,
}

impl UnitKey {
    pub(crate) fn auxiliary_target<'a>(
        &self,
        manifest: &'a Manifest,
    ) -> Option<&'a crate::manifest::DescribedTarget> {
        let kind = match self.kind {
            UnitKind::Example => "example",
            UnitKind::Bench => "bench",
            _ => return None,
        };
        manifest.described_targets.iter().find(|target| {
            target.kind == kind && Some(target.name.as_str()) == self.target.as_deref()
        })
    }

    pub(crate) fn is_harness(&self) -> bool {
        matches!(self.mode, UnitMode::Test | UnitMode::CheckTest)
    }

    pub(crate) fn library_types<'a>(&self, manifest: &'a Manifest) -> Option<&'a [String]> {
        if self.is_harness() {
            return None;
        }
        if self.kind == UnitKind::Library {
            Some(&manifest.library.as_ref().unwrap().crate_types)
        } else {
            self.auxiliary_target(manifest)
                .filter(|target| target.crate_types != ["bin"])
                .map(|target| target.crate_types.as_slice())
        }
    }

    pub fn with_profile(mut self, profile: ProfileContext, panic_abort: bool) -> Self {
        self.profile =
            if panic_abort && !self.uses_host_profile() && self.kind != UnitKind::BuildScriptRun {
                profile
            } else {
                ProfileContext::Normal
            };
        self
    }

    fn uses_host_profile(&self) -> bool {
        matches!(
            self.kind,
            UnitKind::BuildScriptCompile | UnitKind::ProcMacro
        ) || self.compile_kind == CompileKind::Host
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum UnitEdgeKind {
    RustDependency,
    ArtifactDependency,
    BuildScriptExecutable,
    BuildScriptOutput,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnitEdge {
    pub unit: UnitKey,
    pub kind: UnitEdgeKind,
    pub alias: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Unit {
    pub key: UnitKey,
    pub dependencies: BTreeSet<UnitEdge>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnitGraph {
    pub units: BTreeMap<UnitKey, Unit>,
    pub order: Vec<UnitKey>,
    pub selected_packages: BTreeSet<PackageKey>,
    // Selecting an example still treats its owning macro library as a host dependency.
    pub primary_macros: BTreeSet<PackageKey>,
}

impl UnitGraph {
    pub fn with_profile(mut self, profile: ProfileContext, panic_abort: bool) -> Self {
        let mut units = BTreeMap::new();
        for (_, mut unit) in std::mem::take(&mut self.units) {
            unit.key = unit.key.with_profile(profile, panic_abort);
            unit.dependencies = unit
                .dependencies
                .into_iter()
                .map(|mut edge| {
                    edge.unit = edge.unit.with_profile(profile, panic_abort);
                    edge
                })
                .collect();
            units.insert(unit.key.clone(), unit);
        }
        for key in &mut self.order {
            *key = key.clone().with_profile(profile, panic_abort);
        }
        self.units = units;
        self
    }

    pub fn merge(&mut self, other: Self) -> Result<()> {
        self.selected_packages.extend(other.selected_packages);
        self.primary_macros.extend(other.primary_macros);
        for (key, unit) in other.units {
            if let Some(existing) = self.units.get(&key) {
                if existing != &unit {
                    return Err(Error::failure(format!(
                        "unit graph has conflicting dependencies for `{} {}` {:?}",
                        key.package.name, key.package.version, key.kind
                    )));
                }
            } else {
                self.units.insert(key, unit);
            }
        }
        self.order = topological_order(&self.units)?;
        Ok(())
    }

    fn with_selected_check_mode(self, selected: &PackageKey) -> Result<Self> {
        self.rekey(|mut key| {
            if &key.package == selected {
                key.mode = if key.mode == UnitMode::Test {
                    UnitMode::CheckTest
                } else {
                    UnitMode::Check
                };
            }
            key
        })
    }

    fn rekey(mut self, rekey: impl Fn(UnitKey) -> UnitKey) -> Result<Self> {
        let mut units = BTreeMap::new();
        for (_, mut unit) in std::mem::take(&mut self.units) {
            unit.key = rekey(unit.key);
            unit.dependencies = unit
                .dependencies
                .into_iter()
                .map(|mut edge| {
                    edge.unit = rekey(edge.unit);
                    edge
                })
                .collect();
            units.insert(unit.key.clone(), unit);
        }
        self.units = units;
        self.order = topological_order(&self.units)?;
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnitProfile {
    pub opt_level: &'static str,
    pub lto: CargoProfileLto<'static>,
    pub codegen_units: Option<u32>,
    pub debuginfo: CargoDebugInfo,
    pub debug_assertions: bool,
    pub overflow_checks: bool,
    pub incremental: bool,
    pub panic: CargoPanicStrategy,
    pub strip: CargoStrip<'static>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnitSettings {
    pub profile: UnitProfile,
    pub mode: CargoCompileMode,
    pub lto: CargoUnitLto<'static>,
    pub logical_target: Option<String>,
    pub rustflags: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedUnit {
    pub unit: Unit,
    pub identity: Identity,
    pub settings: UnitSettings,
    pub source_remap: Option<SourceRemap>,
    pub source_exclusions: Exclusions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRemap {
    pub physical_root: PathBuf,
    pub logical_root: PathBuf,
    pub presented_root: PathBuf,
}

impl SourceRemap {
    pub fn registry(
        workspace_root: &Path,
        checksum: &[u8; 32],
        physical_root: &Path,
    ) -> Result<Self> {
        Self::content_addressed(workspace_root, "registry", checksum, physical_root)
    }

    pub fn path(
        workspace_root: &Path,
        source_tree_sha256: &[u8; 32],
        physical_root: &Path,
    ) -> Result<Self> {
        Self::content_addressed(workspace_root, "path", source_tree_sha256, physical_root)
    }

    pub fn git(
        workspace_root: &Path,
        cargo_source: &str,
        package_path: &str,
        physical_root: &Path,
    ) -> Result<Self> {
        let mut digest = Sha256::new();
        digest.update(cargo_source.as_bytes());
        let mut logical_root = workspace_root
            .join(".lorry/git/sha256")
            .join(hex(&digest.finish()))
            .join("source");
        if !package_path.is_empty() {
            logical_root.push(package_path);
        }
        Self::new(workspace_root, &logical_root, physical_root)
    }

    fn content_addressed(
        workspace_root: &Path,
        source_kind: &str,
        digest: &[u8; 32],
        physical_root: &Path,
    ) -> Result<Self> {
        let logical_root = workspace_root
            .join(".lorry")
            .join(source_kind)
            .join("sha256")
            .join(hex(digest))
            .join("source");
        Self::new(workspace_root, &logical_root, physical_root)
    }

    fn new(workspace_root: &Path, logical_root: &Path, physical_root: &Path) -> Result<Self> {
        if !workspace_root.is_absolute()
            || !logical_root.is_absolute()
            || !physical_root.is_absolute()
        {
            return Err(Error::failure(
                "source remapping requires absolute workspace, logical, and physical roots",
            ));
        }
        let presented_root = logical_root
            .strip_prefix(workspace_root)
            .map_err(|_| {
                Error::failure(format!(
                    "logical source root `{}` is outside workspace `{}`",
                    logical_root.display(),
                    workspace_root.display()
                ))
            })?
            .to_owned();
        if presented_root.as_os_str().is_empty() || physical_root == logical_root {
            return Err(Error::failure(
                "source remapping requires distinct non-root paths",
            ));
        }
        if [&physical_root.as_os_str(), &presented_root.as_os_str()]
            .into_iter()
            .any(|root| root.as_encoded_bytes().contains(&b'='))
        {
            return Err(Error::failure(format!(
                "source mapping `{}` to `{}` contains `=`, which rustc cannot represent unambiguously",
                physical_root.display(),
                presented_root.display()
            )));
        }
        Ok(Self {
            physical_root: physical_root.to_owned(),
            logical_root: logical_root.to_owned(),
            presented_root,
        })
    }

    pub fn rustc_argument(&self) -> OsString {
        let mut argument = self.physical_root.as_os_str().to_owned();
        argument.push("=");
        argument.push(&self.presented_root);
        argument
    }

    pub fn restore_physical_path(&self, presented: &Path) -> Option<PathBuf> {
        let relative = if presented.is_absolute() {
            presented.strip_prefix(&self.logical_root).ok()?
        } else {
            presented.strip_prefix(&self.presented_root).ok()?
        };
        Some(self.physical_root.join(relative))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompilationPlan {
    pub units: BTreeMap<UnitKey, PlannedUnit>,
    pub order: Vec<UnitKey>,
}

pub struct PlanOptions<'a> {
    pub workspace_root: &'a Path,
    pub release: bool,
    pub test_profile: bool,
    pub panic_abort: bool,
    pub dev_profile: &'a DevProfile,
    pub release_profile: &'a ReleaseProfile,
    pub rustc: &'a Toolchain,
    /// `None` is a native Linux build. Native Motor passes its normalized
    /// explicit Motor target identity here.
    pub logical_target: Option<&'a str>,
    pub rustflags: &'a [String],
}

pub struct CheckTargetSelection<'a> {
    pub normal: bool,
    pub binaries: bool,
    pub binary_name: Option<&'a str>,
    pub harnesses: bool,
    pub integrations: bool,
    pub integration_name: Option<&'a str>,
    pub examples: bool,
    pub benches: bool,
}

pub(crate) struct AuxiliarySelection<'a> {
    pub kind: &'static str,
    pub name: Option<&'a str>,
    pub mode: UnitMode,
}

pub(crate) fn workspace_auxiliary_units(
    resolution: &Resolution,
    manifests: &BTreeMap<PackageKey, Manifest>,
    selected: &[PackageKey],
    options: &PlanOptions<'_>,
    selection: &AuxiliarySelection<'_>,
) -> Result<UnitGraph> {
    if let Some(name) = selection.name
        && !selected.iter().any(|package| {
            manifests[package]
                .described_targets
                .iter()
                .any(|target| target.kind == selection.kind && target.name == name)
        })
    {
        return Err(Error::failure(format!(
            "no {} target named `{name}`",
            selection.kind
        )));
    }
    let mut graph = dependency_units_with_selected(resolution, manifests, selected)?;
    graph.selected_packages.extend(selected.iter().cloned());
    let mut roots = Vec::new();
    for package in resolution
        .packages
        .iter()
        .filter(|package| selected.contains(&package.key))
    {
        let manifest = &manifests[&package.key];
        let features = features_for(package, CompileKind::Target);
        for target in manifest.described_targets.iter().filter(|target| {
            target.kind == selection.kind && selection.name.is_none_or(|name| name == target.name)
        }) {
            if !target_enabled(
                resolution,
                manifest,
                &features,
                &target.name,
                target.required_features.as_deref(),
                selection.name.is_some(),
            )? {
                continue;
            }
            if target
                .crate_types
                .iter()
                .any(|kind| !matches!(kind.as_str(), "bin" | "lib" | "rlib" | "staticlib"))
                || target.crate_types.len() > 1
                    && target.crate_types.iter().any(|kind| kind == "bin")
            {
                return Err(Error::failure(format!(
                    "example `{}` uses unsupported crate types; use bin, lib, rlib, or staticlib",
                    target.name
                )));
            }
            let kind = if selection.kind == "example" {
                UnitKind::Example
            } else {
                UnitKind::Bench
            };
            let mut key = unit_key(package, kind, CompileKind::Target, &features);
            key.target = Some(target.name.clone());
            key.mode = selection.mode;
            insert_unit(&mut graph.units, key.clone());
            add_member_target_edges(&mut graph, resolution, manifests, &key, true, true)?;
            roots.push(key);
        }
    }
    if matches!(selection.mode, UnitMode::Test | UnitMode::CheckTest) {
        graph = graph.with_profile(ProfileContext::Test, options.panic_abort);
        roots = roots
            .into_iter()
            .map(|key| key.with_profile(ProfileContext::Test, options.panic_abort))
            .collect();
    }
    if selection.kind == "bench" && selection.mode == UnitMode::Test {
        let mut programs = workspace_units(
            resolution,
            manifests,
            selected,
            false,
            true,
            None,
            options.release || options.dev_profile.opt_level != "0",
        )?;
        let keys = programs
            .units
            .keys()
            .filter(|key| key.kind == UnitKind::Binary)
            .cloned()
            .collect::<Vec<_>>();
        retain_unit_roots(&mut programs, keys.clone())?;
        graph.merge(programs)?;
        for root in &roots {
            for program in keys.iter().filter(|key| key.package == root.package) {
                add_edge(
                    &mut graph.units,
                    root,
                    program.clone(),
                    UnitEdgeKind::ArtifactDependency,
                    None,
                )?;
            }
        }
    }
    if matches!(selection.mode, UnitMode::Check | UnitMode::CheckTest) {
        graph = graph.rekey(|mut key| {
            if key.kind == UnitKind::Library
                && manifests[&key.package].editable
                && key.compile_kind == CompileKind::Target
            {
                key.mode = UnitMode::Check;
            }
            key
        })?;
    }
    retain_unit_roots(&mut graph, roots)?;
    Ok(graph)
}

pub(crate) fn workspace_check_units(
    resolution: &Resolution,
    manifests: &BTreeMap<PackageKey, Manifest>,
    selected: &[PackageKey],
    selection: &CheckTargetSelection<'_>,
    options: &PlanOptions<'_>,
) -> Result<UnitGraph> {
    let mut graph = if selection.normal {
        workspace_units(
            resolution,
            manifests,
            selected,
            true,
            selection.binaries,
            selection.binary_name,
            options.release || options.dev_profile.opt_level != "0",
        )?
    } else {
        UnitGraph {
            units: BTreeMap::new(),
            order: Vec::new(),
            selected_packages: selected.iter().cloned().collect(),
            primary_macros: BTreeSet::new(),
        }
    };
    if selection.harnesses || selection.integrations {
        let mut tests = workspace_harness_units(
            resolution,
            manifests,
            selected,
            options,
            selection.integration_name,
            selection.harnesses,
        )?;
        for unit in tests.units.values_mut() {
            unit.dependencies
                .retain(|edge| edge.kind != UnitEdgeKind::ArtifactDependency);
        }
        let mut pending = tests
            .units
            .keys()
            .filter(|key| {
                key.mode == UnitMode::Test
                    && if key.kind == UnitKind::IntegrationHarness {
                        selection.integrations
                    } else {
                        selection.harnesses
                    }
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut checked = BTreeMap::new();
        let roots = pending
            .iter()
            .map(|key| UnitKey {
                mode: UnitMode::CheckTest,
                ..key.clone()
            })
            .collect::<Vec<_>>();
        while let Some(key) = pending.pop() {
            let mode = if key.mode == UnitMode::Test {
                UnitMode::CheckTest
            } else {
                UnitMode::Check
            };
            let checked_key = UnitKey {
                mode,
                ..key.clone()
            };
            if checked.contains_key(&checked_key) {
                continue;
            }
            let mut unit = tests.units[&key].clone();
            unit.key = checked_key.clone();
            unit.dependencies = unit
                .dependencies
                .into_iter()
                .map(|mut edge| {
                    if edge.kind == UnitEdgeKind::RustDependency
                        && edge.unit.kind == UnitKind::Library
                        && manifests[&edge.unit.package].editable
                    {
                        pending.push(edge.unit.clone());
                        edge.unit.mode = UnitMode::Check;
                    }
                    edge
                })
                .collect();
            checked.insert(checked_key, unit);
        }
        tests.units.extend(checked);
        retain_unit_roots(&mut tests, roots)?;
        graph.merge(tests)?;
    }
    for (enabled, kind, mode) in [
        (selection.examples, "example", UnitMode::Check),
        (selection.benches, "bench", UnitMode::CheckTest),
    ] {
        if enabled {
            graph.merge(workspace_auxiliary_units(
                resolution,
                manifests,
                selected,
                options,
                &AuxiliarySelection {
                    kind,
                    name: None,
                    mode,
                },
            )?)?;
        }
    }
    Ok(graph)
}

pub fn selected_check_units(
    resolution: &Resolution,
    manifests: &BTreeMap<PackageKey, Manifest>,
    selected: &Manifest,
    selection: &CheckTargetSelection<'_>,
    panic_abort: bool,
) -> Result<UnitGraph> {
    let package = selected_library_key(selected)?.package;
    let mut normal = if selection.normal {
        let mut graph = dependency_units(resolution, manifests)?;
        if selected.library.is_some() {
            add_selected_library(&mut graph, resolution, manifests, selected)?;
        }
        if selection.binaries {
            add_selected_binaries(
                &mut graph,
                resolution,
                manifests,
                selected,
                selection.binary_name,
            )?;
        }
        graph.with_selected_check_mode(&package)?
    } else {
        UnitGraph {
            units: BTreeMap::new(),
            order: Vec::new(),
            selected_packages: BTreeSet::new(),
            primary_macros: BTreeSet::new(),
        }
    };
    if selection.harnesses || selection.integrations {
        let mut test = dependency_units(resolution, manifests)?;
        if selected.library.is_some() {
            add_selected_library(&mut test, resolution, manifests, selected)?;
        }
        if selection.harnesses {
            add_selected_harnesses(&mut test, resolution, manifests, selected)?;
        }
        test = test.with_profile(ProfileContext::Test, panic_abort);
        if selection.integrations {
            add_selected_integration_harnesses(
                &mut test,
                resolution,
                manifests,
                selected,
                selection.integration_name,
                panic_abort,
                false,
            )?;
        }
        normal.merge(test.with_selected_check_mode(&package)?)?;
    }
    Ok(normal)
}

pub fn dependency_units(
    resolution: &Resolution,
    manifests: &BTreeMap<PackageKey, Manifest>,
) -> Result<UnitGraph> {
    dependency_units_with_selected(resolution, manifests, &[])
}

fn dependency_units_with_selected(
    resolution: &Resolution,
    manifests: &BTreeMap<PackageKey, Manifest>,
    selected: &[PackageKey],
) -> Result<UnitGraph> {
    let packages = resolution
        .packages
        .iter()
        .map(|package| (package.key.clone(), package))
        .collect::<BTreeMap<_, _>>();
    if packages.len() != resolution.packages.len()
        || manifests.keys().collect::<BTreeSet<_>>() != packages.keys().collect()
    {
        return Err(Error::failure(
            "dependency unit graph requires exactly one manifest for every resolved package",
        ));
    }

    let mut units = BTreeMap::new();
    for package in &resolution.packages {
        let manifest = &manifests[&package.key];
        if manifest.library.is_none() && !selected.contains(&package.key) {
            return Err(Error::failure(format!(
                "dependency package `{} {}` has no supported library target",
                package.key.name, package.key.version
            )));
        }
        for compile_kind in &package.compile_kinds {
            let features = features_for(package, *compile_kind);
            let kind = library_unit_kind(manifest);
            let library = manifest
                .library
                .as_ref()
                .filter(|library| !library.proc_macro || *compile_kind == CompileKind::Host)
                .map(|_| unit_key(package, kind, *compile_kind, &features));
            if let Some(library) = &library {
                insert_unit(&mut units, library.clone());
            }
            if manifest.build_script.is_some() {
                let compile = unit_key(
                    package,
                    UnitKind::BuildScriptCompile,
                    CompileKind::Host,
                    &features,
                );
                let run = unit_key(package, UnitKind::BuildScriptRun, *compile_kind, &features);
                insert_unit(&mut units, compile.clone());
                insert_unit(&mut units, run.clone());
                add_edge(
                    &mut units,
                    &run,
                    compile,
                    UnitEdgeKind::BuildScriptExecutable,
                    None,
                )?;
                if let Some(library) = &library {
                    add_edge(
                        &mut units,
                        library,
                        run,
                        UnitEdgeKind::BuildScriptOutput,
                        None,
                    )?;
                }
            }
        }
    }

    for package in &resolution.packages {
        let manifest = &manifests[&package.key];
        for edge in &package.edges {
            match edge.kind {
                DependencyKind::Normal => {
                    if manifest.library.is_none() {
                        continue;
                    }
                    let parent_compile_kind = edge.parent_compile_kind.ok_or_else(|| {
                        Error::failure(format!(
                            "resolved edge from `{} {}` omitted its parent compilation context",
                            package.key.name, package.key.version
                        ))
                    })?;
                    if manifest.library.as_ref().unwrap().proc_macro
                        && parent_compile_kind == CompileKind::Target
                    {
                        continue;
                    }
                    let parent = unit_key(
                        package,
                        library_unit_kind(manifest),
                        parent_compile_kind,
                        &features_for(package, parent_compile_kind),
                    );
                    let dependency = packages.get(&edge.package).ok_or_else(|| {
                        Error::failure(format!(
                            "resolved edge from `{} {}` references missing package `{} {}`",
                            package.key.name,
                            package.key.version,
                            edge.package.name,
                            edge.package.version
                        ))
                    })?;
                    let child = unit_key(
                        dependency,
                        library_unit_kind(&manifests[&dependency.key]),
                        edge.compile_kind,
                        &features_for(dependency, edge.compile_kind),
                    );
                    add_edge(
                        &mut units,
                        &parent,
                        child,
                        UnitEdgeKind::RustDependency,
                        Some(dependency_alias(
                            edge,
                            manifest,
                            &manifests[&dependency.key],
                        )),
                    )?;
                }
                DependencyKind::Build => {
                    if manifest.build_script.is_none() {
                        continue;
                    }
                    let dependency = packages.get(&edge.package).ok_or_else(|| {
                        Error::failure(format!(
                            "resolved build edge from `{} {}` references missing package `{} {}`",
                            package.key.name,
                            package.key.version,
                            edge.package.name,
                            edge.package.version
                        ))
                    })?;
                    let child = unit_key(
                        dependency,
                        library_unit_kind(&manifests[&dependency.key]),
                        CompileKind::Host,
                        &features_for(dependency, CompileKind::Host),
                    );
                    let compiles = units
                        .keys()
                        .filter(|key| {
                            key.package == package.key && key.kind == UnitKind::BuildScriptCompile
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    for compile in compiles {
                        add_edge(
                            &mut units,
                            &compile,
                            child.clone(),
                            UnitEdgeKind::RustDependency,
                            Some(dependency_alias(
                                edge,
                                manifest,
                                &manifests[&dependency.key],
                            )),
                        )?;
                    }
                }
                // Development edges belong to harness/example units, never ordinary libraries.
                DependencyKind::Dev => {}
            }
        }
    }

    let order = topological_order(&units)?;
    Ok(UnitGraph {
        units,
        order,
        selected_packages: BTreeSet::new(),
        primary_macros: BTreeSet::new(),
    })
}

/// Member roots retain the resolver's feature unions even when a selected
/// member is also another selected member's dependency.
pub(crate) fn workspace_units(
    resolution: &Resolution,
    manifests: &BTreeMap<PackageKey, Manifest>,
    selected: &[PackageKey],
    check: bool,
    binaries: bool,
    binary_name: Option<&str>,
    separate_macros: bool,
) -> Result<UnitGraph> {
    let mut graph = dependency_units_with_selected(resolution, manifests, selected)?;
    graph.selected_packages.extend(selected.iter().cloned());
    graph.primary_macros.extend(
        selected
            .iter()
            .filter(|key| {
                manifests[*key]
                    .library
                    .as_ref()
                    .is_some_and(|library| library.proc_macro)
            })
            .cloned(),
    );
    for key in selected {
        let package = resolution
            .packages
            .iter()
            .find(|package| &package.key == key)
            .ok_or_else(|| Error::failure("selected member is absent from the unit resolution"))?;
        let manifest = &manifests[key];
        if !binaries {
            continue;
        }
        for target in manifest
            .binaries
            .iter()
            .filter(|target| binary_name.is_none_or(|name| name == target.name))
        {
            if !target_enabled(
                resolution,
                manifest,
                &features_for(package, CompileKind::Target),
                &target.name,
                target.required_features.as_deref(),
                binary_name.is_some(),
            )? {
                continue;
            }
            let mut binary = unit_key(
                package,
                UnitKind::Binary,
                CompileKind::Target,
                &features_for(package, CompileKind::Target),
            );
            binary.target = Some(target.name.clone());
            insert_unit(&mut graph.units, binary.clone());
            add_member_target_edges(&mut graph, resolution, manifests, &binary, false, true)?;
        }
    }
    if separate_macros {
        let macros = graph
            .units
            .keys()
            .filter(|key| selected.contains(&key.package) && key.kind == UnitKind::ProcMacro)
            .cloned()
            .collect::<Vec<_>>();
        for key in macros {
            let mut root = graph.units[&key].clone();
            root.key.profile = ProfileContext::Selected;
            graph.units.insert(root.key.clone(), root);
            if !graph
                .units
                .values()
                .any(|unit| unit.dependencies.iter().any(|edge| edge.unit == key))
            {
                graph.units.remove(&key);
            }
        }
        graph.order = topological_order(&graph.units)?;
    }
    if check {
        graph = graph.rekey(|mut key| {
            if manifests[&key.package].editable
                && key.compile_kind == CompileKind::Target
                && matches!(key.kind, UnitKind::Library | UnitKind::Binary)
            {
                key.mode = UnitMode::Check;
            }
            key
        })?;
        let mut checks = BTreeSet::new();
        let mut pending = graph
            .units
            .keys()
            .filter(|key| {
                selected.contains(&key.package)
                    && key.kind == UnitKind::ProcMacro
                    && (!separate_macros || key.profile == ProfileContext::Selected)
            })
            .cloned()
            .collect::<Vec<_>>();
        while let Some(key) = pending.pop() {
            if !checks.insert(key.clone()) {
                continue;
            }
            pending.extend(
                graph.units[&key]
                    .dependencies
                    .iter()
                    .filter(|edge| {
                        edge.kind == UnitEdgeKind::RustDependency
                            && edge.unit.kind == UnitKind::Library
                    })
                    .map(|edge| edge.unit.clone()),
            );
        }
        for key in graph
            .order
            .clone()
            .iter()
            .filter(|key| checks.contains(*key))
        {
            let mut unit = graph.units[key].clone();
            unit.key.mode = UnitMode::Check;
            unit.dependencies = unit
                .dependencies
                .into_iter()
                .map(|mut edge| {
                    if checks.contains(&edge.unit) {
                        edge.unit.mode = UnitMode::Check;
                    }
                    edge
                })
                .collect();
            graph.units.insert(unit.key.clone(), unit);
        }
    }
    let roots = graph
        .units
        .keys()
        .filter(|key| {
            selected.contains(&key.package)
                && match key.kind {
                    UnitKind::Library | UnitKind::Binary => key.compile_kind == CompileKind::Target,
                    UnitKind::ProcMacro => {
                        key.mode
                            == if check {
                                UnitMode::Check
                            } else {
                                UnitMode::Build
                            }
                            && (!separate_macros || key.profile == ProfileContext::Selected)
                    }
                    _ => false,
                }
        })
        .cloned()
        .collect::<Vec<_>>();
    retain_unit_roots(&mut graph, roots)?;
    Ok(graph)
}

fn retain_unit_roots(graph: &mut UnitGraph, mut pending: Vec<UnitKey>) -> Result<()> {
    let mut reachable = BTreeSet::new();
    while let Some(key) = pending.pop() {
        if reachable.insert(key.clone()) {
            pending.extend(
                graph.units[&key]
                    .dependencies
                    .iter()
                    .map(|edge| edge.unit.clone()),
            );
        }
    }
    graph.units.retain(|key, _| reachable.contains(key));
    graph.order = topological_order(&graph.units)?;
    Ok(())
}

pub(crate) fn workspace_test_units(
    resolution: &Resolution,
    manifests: &BTreeMap<PackageKey, Manifest>,
    selected: &[PackageKey],
    options: &PlanOptions<'_>,
    integration_name: Option<&str>,
) -> Result<UnitGraph> {
    workspace_harness_units(
        resolution,
        manifests,
        selected,
        options,
        integration_name,
        false,
    )
}

fn workspace_harness_units(
    resolution: &Resolution,
    manifests: &BTreeMap<PackageKey, Manifest>,
    selected: &[PackageKey],
    options: &PlanOptions<'_>,
    integration_name: Option<&str>,
    bench_harnesses: bool,
) -> Result<UnitGraph> {
    let panic_abort = options.panic_abort;
    if let Some(name) = integration_name
        && !selected.iter().any(|package| {
            manifests[package]
                .integration_tests
                .iter()
                .any(|target| target.name == name)
        })
    {
        return Err(Error::failure(format!(
            "no integration-test target named `{name}`"
        )));
    }
    let base = dependency_units_with_selected(resolution, manifests, selected)?;
    let mut normal = base.clone();
    let mut tests = base;
    tests.selected_packages.extend(selected.iter().cloned());
    let mut roots = Vec::new();
    let mut programs = Vec::new();
    for package in resolution
        .packages
        .iter()
        .filter(|package| selected.contains(&package.key))
    {
        let manifest = &manifests[&package.key];
        let features = features_for(package, CompileKind::Target);
        let library = manifest
            .library
            .iter()
            .filter(|target| {
                integration_name.is_none() && (target.test || (bench_harnesses && target.bench))
            })
            .map(|target| (UnitKind::LibraryHarness, &target.name, None));
        let binaries = manifest
            .binaries
            .iter()
            .filter(|target| {
                integration_name.is_none() && (target.test || (bench_harnesses && target.bench))
            })
            .map(|target| {
                (
                    UnitKind::BinaryHarness,
                    &target.name,
                    target.required_features.as_deref(),
                )
            });
        let integrations = manifest
            .integration_tests
            .iter()
            .filter(|target| integration_name.map_or(target.test, |name| name == target.name))
            .map(|target| {
                (
                    UnitKind::IntegrationHarness,
                    &target.name,
                    target.required_features.as_deref(),
                )
            });
        let mut integration = false;
        for (kind, name, required) in library.chain(binaries).chain(integrations) {
            if !target_enabled(
                resolution,
                manifest,
                &features,
                name,
                required,
                integration_name.is_some(),
            )? {
                continue;
            }
            let compile_kind = if kind == UnitKind::LibraryHarness
                && manifest
                    .library
                    .as_ref()
                    .is_some_and(|library| library.proc_macro)
            {
                CompileKind::Host
            } else {
                CompileKind::Target
            };
            let mut key = unit_key(
                package,
                kind,
                compile_kind,
                &features_for(package, compile_kind),
            );
            key.mode = UnitMode::Test;
            key.target = Some(name.clone());
            insert_unit(&mut tests.units, key.clone());
            add_member_target_edges(
                &mut tests,
                resolution,
                manifests,
                &key,
                true,
                kind != UnitKind::LibraryHarness,
            )?;
            integration |= kind == UnitKind::IntegrationHarness;
            roots.push(key.with_profile(ProfileContext::Test, panic_abort));
        }
        if integration {
            for target in &manifest.binaries {
                if !target_enabled(
                    resolution,
                    manifest,
                    &features,
                    &target.name,
                    target.required_features.as_deref(),
                    false,
                )? {
                    continue;
                }
                let mut key = unit_key(package, UnitKind::Binary, CompileKind::Target, &features);
                key.target = Some(target.name.clone());
                insert_unit(&mut normal.units, key.clone());
                add_member_target_edges(&mut normal, resolution, manifests, &key, false, true)?;
                programs.push(key);
            }
        }
    }
    tests = tests.with_profile(ProfileContext::Test, panic_abort);
    // Normal programs keep their panic strategy; harnesses and their libraries unwind.
    // Keeping those graphs separate also permits legal dev cycles back to ordinary libraries.
    if programs.is_empty() {
        retain_unit_roots(&mut tests, roots)?;
        Ok(tests)
    } else {
        retain_unit_roots(&mut normal, programs.clone())?;
        normal.merge(tests)?;
        for harness in roots
            .iter()
            .filter(|key| key.kind == UnitKind::IntegrationHarness)
        {
            for program in programs.iter().filter(|key| key.package == harness.package) {
                add_edge(
                    &mut normal.units,
                    harness,
                    program.clone(),
                    UnitEdgeKind::ArtifactDependency,
                    None,
                )?;
            }
        }
        roots.extend(programs);
        retain_unit_roots(&mut normal, roots)?;
        Ok(normal)
    }
}

fn add_member_target_edges(
    graph: &mut UnitGraph,
    resolution: &Resolution,
    manifests: &BTreeMap<PackageKey, Manifest>,
    parent: &UnitKey,
    dev: bool,
    own_library: bool,
) -> Result<()> {
    let package = resolution
        .packages
        .iter()
        .find(|package| package.key == parent.package)
        .ok_or_else(|| Error::failure("selected member is absent from the unit resolution"))?;
    let manifest = &manifests[&package.key];
    if manifest.build_script.is_some() {
        add_edge(
            &mut graph.units,
            parent,
            unit_key(
                package,
                UnitKind::BuildScriptRun,
                parent.compile_kind,
                &features_for(package, parent.compile_kind),
            ),
            UnitEdgeKind::BuildScriptOutput,
            None,
        )?;
    }
    for edge in package.edges.iter().filter(|edge| {
        (edge.kind == DependencyKind::Normal || (dev && edge.kind == DependencyKind::Dev))
            && edge.parent_compile_kind == Some(parent.compile_kind)
    }) {
        let dependency = resolution
            .packages
            .iter()
            .find(|package| package.key == edge.package)
            .ok_or_else(|| Error::failure("member dependency is absent from the resolution"))?;
        let child = &manifests[&edge.package];
        add_edge(
            &mut graph.units,
            parent,
            unit_key(
                dependency,
                library_unit_kind(child),
                edge.compile_kind,
                &features_for(dependency, edge.compile_kind),
            ),
            UnitEdgeKind::RustDependency,
            Some(dependency_alias(edge, manifest, child)),
        )?;
    }
    if own_library && let Some(library) = &manifest.library {
        let compile_kind = if library.proc_macro {
            CompileKind::Host
        } else {
            parent.compile_kind
        };
        add_edge(
            &mut graph.units,
            parent,
            unit_key(
                package,
                library_unit_kind(manifest),
                compile_kind,
                &features_for(package, compile_kind),
            ),
            UnitEdgeKind::RustDependency,
            Some(library.name.clone()),
        )?;
    }
    Ok(())
}

fn target_enabled(
    resolution: &Resolution,
    manifest: &Manifest,
    features: &BTreeSet<String>,
    name: &str,
    required: Option<&[String]>,
    explicit: bool,
) -> Result<bool> {
    let Some(required) = required else {
        return Ok(true);
    };
    let package = selected_library_key(manifest)?.package;
    let edges = resolution
        .packages
        .iter()
        .find(|candidate| candidate.key == package)
        .map_or(resolution.root_edges.as_slice(), |package| {
            package.edges.as_slice()
        });
    let mut enabled = features.clone();
    for edge in edges {
        if let Some(child) = resolution
            .packages
            .iter()
            .find(|child| child.key == edge.package)
        {
            enabled.extend(
                features_for(child, edge.compile_kind)
                    .iter()
                    .map(|feature| format!("{}/{feature}", edge.alias)),
            );
        }
    }
    if required.iter().all(|feature| enabled.contains(feature)) {
        return Ok(true);
    }
    if explicit {
        return Err(Error::failure(format!(
            "target `{name}` in package `{}` requires the features: {}",
            manifest.name,
            required
                .iter()
                .map(|feature| format!("`{feature}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ))
        .with_help(format!(
            "enable the required features: {}",
            required.join(",")
        )));
    }
    Ok(false)
}

pub fn add_selected_library(
    graph: &mut UnitGraph,
    resolution: &Resolution,
    manifests: &BTreeMap<PackageKey, Manifest>,
    manifest: &Manifest,
) -> Result<UnitKey> {
    if manifest.library.is_none() {
        return Err(Error::failure("selected package has no library target"));
    }
    let key = selected_library_key(manifest)?;
    if graph.units.contains_key(&key) {
        return Err(Error::failure(
            "selected library is already in the unit graph",
        ));
    }
    insert_unit(&mut graph.units, key.clone());
    add_selected_normal_edges(graph, resolution, manifests, manifest, &key, false)?;
    graph.order = topological_order(&graph.units)?;
    Ok(key)
}

pub fn selected_library_key(manifest: &Manifest) -> Result<UnitKey> {
    Ok(UnitKey {
        package: PackageKey {
            name: manifest.name.clone(),
            version: semver::Version::parse(&manifest.version.original).map_err(|error| {
                Error::failure(format!(
                    "invalid selected package version `{}`: {error}",
                    manifest.version.original
                ))
            })?,
            source: PackageSourceKey::Path(manifest.root.clone()),
        },
        kind: UnitKind::Library,
        mode: UnitMode::Build,
        target: None,
        compile_kind: CompileKind::Target,
        profile: ProfileContext::Normal,
        features: selected_root_features(manifest)?,
    })
}

pub fn add_selected_binaries(
    graph: &mut UnitGraph,
    resolution: &Resolution,
    manifests: &BTreeMap<PackageKey, Manifest>,
    manifest: &Manifest,
    selected_name: Option<&str>,
) -> Result<Vec<UnitKey>> {
    let library = manifest
        .library
        .as_ref()
        .map(|_| selected_library_key(manifest))
        .transpose()?;
    let mut binaries = Vec::new();
    for target in manifest
        .binaries
        .iter()
        .filter(|target| selected_name.is_none_or(|name| name == target.name))
    {
        let mut key = selected_library_key(manifest)?;
        if !target_enabled(
            resolution,
            manifest,
            &key.features,
            &target.name,
            target.required_features.as_deref(),
            selected_name.is_some(),
        )? {
            continue;
        }
        key.kind = UnitKind::Binary;
        key.target = Some(target.name.clone());
        insert_unit(&mut graph.units, key.clone());
        add_selected_normal_edges(graph, resolution, manifests, manifest, &key, false)?;
        if let Some(library) = &library {
            add_edge(
                &mut graph.units,
                &key,
                library.clone(),
                UnitEdgeKind::RustDependency,
                manifest.library.as_ref().map(|target| target.name.clone()),
            )?;
        }
        binaries.push(key);
    }
    graph.order = topological_order(&graph.units)?;
    Ok(binaries)
}

pub fn add_selected_harnesses(
    graph: &mut UnitGraph,
    resolution: &Resolution,
    manifests: &BTreeMap<PackageKey, Manifest>,
    manifest: &Manifest,
) -> Result<Vec<UnitKey>> {
    let library = manifest
        .library
        .as_ref()
        .map(|_| selected_library_key(manifest))
        .transpose()?;
    let mut harnesses = Vec::new();
    if let Some(target) = manifest.library.as_ref().filter(|target| target.test) {
        let mut key = selected_library_key(manifest)?;
        key.kind = UnitKind::LibraryHarness;
        key.mode = UnitMode::Test;
        key.target = Some(target.name.clone());
        insert_unit(&mut graph.units, key.clone());
        add_selected_normal_edges(graph, resolution, manifests, manifest, &key, false)?;
        harnesses.push(key);
    }
    for target in manifest.binaries.iter().filter(|target| target.test) {
        let mut key = selected_library_key(manifest)?;
        if !target_enabled(
            resolution,
            manifest,
            &key.features,
            &target.name,
            target.required_features.as_deref(),
            false,
        )? {
            continue;
        }
        key.kind = UnitKind::BinaryHarness;
        key.mode = UnitMode::Test;
        key.target = Some(target.name.clone());
        insert_unit(&mut graph.units, key.clone());
        add_selected_normal_edges(graph, resolution, manifests, manifest, &key, false)?;
        if let Some(library) = &library {
            add_edge(
                &mut graph.units,
                &key,
                library.clone(),
                UnitEdgeKind::RustDependency,
                manifest.library.as_ref().map(|target| target.name.clone()),
            )?;
        }
        harnesses.push(key);
    }
    graph.order = topological_order(&graph.units)?;
    Ok(harnesses)
}

pub fn add_selected_integration_harnesses(
    graph: &mut UnitGraph,
    resolution: &Resolution,
    manifests: &BTreeMap<PackageKey, Manifest>,
    manifest: &Manifest,
    selected_name: Option<&str>,
    panic_abort: bool,
    program_artifacts: bool,
) -> Result<Vec<UnitKey>> {
    let library = manifest
        .library
        .as_ref()
        .map(|_| selected_library_key(manifest))
        .transpose()?
        .map(|key| key.with_profile(ProfileContext::Test, panic_abort));
    let mut harnesses = Vec::new();
    let features = selected_root_features(manifest)?;
    for target in manifest
        .integration_tests
        .iter()
        .filter(|target| selected_name.is_none_or(|name| name == target.name))
        .filter(|target| !program_artifacts || selected_name.is_some() || target.test)
    {
        if !target_enabled(
            resolution,
            manifest,
            &features,
            &target.name,
            target.required_features.as_deref(),
            selected_name.is_some(),
        )? {
            continue;
        }
        let mut key =
            selected_library_key(manifest)?.with_profile(ProfileContext::Test, panic_abort);
        key.kind = UnitKind::IntegrationHarness;
        key.mode = UnitMode::Test;
        key.target = Some(target.name.clone());
        insert_unit(&mut graph.units, key.clone());
        add_selected_normal_edges(graph, resolution, manifests, manifest, &key, panic_abort)?;
        if let Some(library) = &library {
            add_edge(
                &mut graph.units,
                &key,
                library.clone(),
                UnitEdgeKind::RustDependency,
                manifest.library.as_ref().map(|target| target.name.clone()),
            )?;
        }
        if program_artifacts {
            for binary in &manifest.binaries {
                let mut program = selected_library_key(manifest)?;
                program.kind = UnitKind::Binary;
                program.target = Some(binary.name.clone());
                add_edge(
                    &mut graph.units,
                    &key,
                    program,
                    UnitEdgeKind::ArtifactDependency,
                    Some(binary.name.clone()),
                )?;
            }
        }
        harnesses.push(key);
    }
    graph.order = topological_order(&graph.units)?;
    Ok(harnesses)
}

fn add_selected_normal_edges(
    graph: &mut UnitGraph,
    resolution: &Resolution,
    manifests: &BTreeMap<PackageKey, Manifest>,
    manifest: &Manifest,
    parent: &UnitKey,
    panic_abort: bool,
) -> Result<()> {
    let packages = resolution
        .packages
        .iter()
        .map(|package| (&package.key, package))
        .collect::<BTreeMap<_, _>>();
    for edge in resolution
        .root_edges
        .iter()
        .filter(|edge| edge.kind == DependencyKind::Normal)
    {
        let package = packages.get(&edge.package).ok_or_else(|| {
            Error::failure(format!(
                "selected target dependency `{} {}` has no resolved package",
                edge.package.name, edge.package.version
            ))
        })?;
        let child_manifest = manifests.get(&edge.package).ok_or_else(|| {
            Error::failure(format!(
                "selected target dependency `{} {}` has no manifest",
                edge.package.name, edge.package.version
            ))
        })?;
        let child = unit_key(
            package,
            library_unit_kind(child_manifest),
            edge.compile_kind,
            &features_for(package, edge.compile_kind),
        )
        .with_profile(parent.profile, panic_abort);
        add_edge(
            &mut graph.units,
            parent,
            child,
            UnitEdgeKind::RustDependency,
            Some(dependency_alias(edge, manifest, child_manifest)),
        )?;
    }
    Ok(())
}

fn dependency_alias(edge: &ResolvedEdge, parent: &Manifest, child: &Manifest) -> String {
    let renamed = edge.alias != edge.package.name
        || parent.dependencies.iter().any(|dependency| {
            dependency.alias == edge.alias
                && dependency.package == edge.package.name
                && dependency.kind == edge.kind
                && dependency.target == edge.target
                && dependency.renamed
        });
    if renamed {
        edge.alias.clone()
    } else {
        child
            .library
            .as_ref()
            .map_or_else(|| edge.alias.clone(), |library| library.name.clone())
    }
}

fn library_unit_kind(manifest: &Manifest) -> UnitKind {
    if manifest
        .library
        .as_ref()
        .is_some_and(|library| library.proc_macro)
    {
        UnitKind::ProcMacro
    } else {
        UnitKind::Library
    }
}

pub fn plan_dependency_units(
    graph: &UnitGraph,
    manifests: &BTreeMap<PackageKey, Manifest>,
    options: &PlanOptions<'_>,
) -> Result<CompilationPlan> {
    plan_dependency_units_with_remaps(
        graph,
        manifests,
        options,
        &BTreeMap::new(),
        &BTreeMap::new(),
    )
}

pub fn plan_dependency_units_with_remaps(
    graph: &UnitGraph,
    manifests: &BTreeMap<PackageKey, Manifest>,
    options: &PlanOptions<'_>,
    source_remaps: &BTreeMap<PackageKey, SourceRemap>,
    source_exclusions: &BTreeMap<PackageKey, Exclusions>,
) -> Result<CompilationPlan> {
    let normalized = selected_macro_script_units(graph, manifests, options)?;
    let graph = normalized.as_ref().unwrap_or(graph);
    if graph.units.values().any(|unit| {
        !unit
            .dependencies
            .iter()
            .all(|dependency| graph.units.contains_key(&dependency.unit))
    }) {
        return Err(Error::failure(
            "dependency compilation plan received an incomplete unit graph",
        ));
    }

    let mut settings_by_unit = BTreeMap::new();
    for key in &graph.order {
        if !graph.units.contains_key(key) {
            return Err(Error::failure(
                "dependency compilation order references an absent unit",
            ));
        }
        let manifest = manifests.get(&key.package).ok_or_else(|| {
            Error::failure(format!(
                "dependency compilation plan has no manifest for `{} {}`",
                key.package.name, key.package.version
            ))
        })?;
        validate_manifest_identity(&key.package, manifest)?;
        settings_by_unit.insert(key.clone(), unit_settings(graph, key, manifest, options));
    }
    // Mixed libraries need objects for their archive and bitcode for LTO consumers.
    // Propagate that requirement before calculating identities, including shared inputs.
    for key in graph.order.iter().rev() {
        if settings_by_unit[key].lto != CargoUnitLto::ObjectAndBitcode {
            continue;
        }
        for edge in &graph.units[key].dependencies {
            if edge.kind == UnitEdgeKind::RustDependency {
                let settings = settings_by_unit.get_mut(&edge.unit).ok_or_else(|| {
                    Error::failure("dependency compilation order omits a dependency unit")
                })?;
                if settings.lto == CargoUnitLto::OnlyBitcode {
                    settings.lto = CargoUnitLto::ObjectAndBitcode;
                }
            }
        }
    }

    let mut planned: BTreeMap<UnitKey, PlannedUnit> = BTreeMap::new();
    for key in &graph.order {
        let unit = &graph.units[key];
        let manifest = &manifests[&key.package];
        let settings = settings_by_unit
            .remove(key)
            .ok_or_else(|| Error::failure("dependency compilation order repeats a unit"))?;
        let profile = settings.profile.cargo_profile();
        let source_value;
        let source = match &key.package.source {
            PackageSourceKey::CratesIo => CargoSource::CratesIo,
            PackageSourceKey::Git(source) => CargoSource::Git(source),
            PackageSourceKey::Path(root) => {
                source_value = match source_remaps.get(&key.package) {
                    Some(remap) => remap
                        .presented_root
                        .to_str()
                        .ok_or_else(|| {
                            Error::failure("presented path package identity is not valid UTF-8")
                        })?
                        .to_owned(),
                    None => cargo_path_source(options.workspace_root, root)?,
                };
                CargoSource::Path(&source_value)
            }
        };
        let features = key.features.iter().cloned().collect::<Vec<_>>();
        let mut edges = unit.dependencies.iter().collect::<Vec<_>>();
        if matches!(
            key.kind,
            UnitKind::Binary
                | UnitKind::BinaryHarness
                | UnitKind::IntegrationHarness
                | UnitKind::Example
                | UnitKind::Bench
        ) {
            edges.sort_by_key(|edge| edge.unit.package == key.package);
        }
        let dependencies = edges
            .into_iter()
            .map(|dependency| {
                planned
                    .get(&dependency.unit)
                    .map(|unit| unit.identity.clone())
                    .ok_or_else(|| {
                        Error::failure(format!(
                            "dependency unit {:?} for `{} {}` was not planned before its dependent",
                            dependency.unit.kind,
                            dependency.unit.package.name,
                            dependency.unit.package.version
                        ))
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let (target_name, target_kind) = match key.kind {
            UnitKind::Library | UnitKind::ProcMacro => {
                let library = manifest.library.as_ref().ok_or_else(|| {
                    Error::failure(format!(
                        "dependency compilation unit for `{} {}` has no library target",
                        key.package.name, key.package.version
                    ))
                })?;
                (
                    library.name.as_str(),
                    CargoTargetKind::Lib(library_crate_types(manifest)),
                )
            }
            UnitKind::Binary => (
                key.target
                    .as_deref()
                    .ok_or_else(|| Error::failure("selected binary unit has no target name"))?,
                CargoTargetKind::Bin,
            ),
            UnitKind::LibraryHarness | UnitKind::BinaryHarness => (
                key.target
                    .as_deref()
                    .ok_or_else(|| Error::failure("selected harness unit has no target name"))?,
                if key.kind == UnitKind::LibraryHarness {
                    CargoTargetKind::Lib(library_crate_types(manifest))
                } else {
                    CargoTargetKind::Bin
                },
            ),
            UnitKind::IntegrationHarness => (
                key.target.as_deref().ok_or_else(|| {
                    Error::failure("selected integration harness unit has no target name")
                })?,
                CargoTargetKind::Test,
            ),
            UnitKind::Example | UnitKind::Bench => (
                key.auxiliary_target(manifest)
                    .ok_or_else(|| Error::failure("auxiliary unit has no target"))?
                    .name
                    .as_str(),
                if key.kind == UnitKind::Example {
                    let types = &key.auxiliary_target(manifest).unwrap().crate_types;
                    if types == &["bin"] {
                        CargoTargetKind::ExampleBin
                    } else {
                        CargoTargetKind::ExampleLib(cargo_crate_types(types))
                    }
                } else {
                    CargoTargetKind::Bench
                },
            ),
            UnitKind::BuildScriptCompile | UnitKind::BuildScriptRun => {
                ("build-script-build", CargoTargetKind::CustomBuild)
            }
        };
        let identity = cargo_unit_identity(&CargoUnitIdentityInput {
            package_name: &manifest.name,
            version: &manifest.version,
            source,
            features: &features,
            profile: &profile,
            mode: settings.mode,
            lto: settings.lto,
            logical_target: settings.logical_target.as_deref(),
            target_name,
            target_kind,
            rustc: options.rustc,
            rustflags: &settings.rustflags,
            extra_arguments: &[],
            dependencies: &dependencies,
            host_configuration_differs: None,
        });
        planned.insert(
            key.clone(),
            PlannedUnit {
                unit: unit.clone(),
                identity,
                settings,
                source_remap: source_remaps.get(&key.package).cloned(),
                source_exclusions: source_exclusions.get(&key.package).copied().unwrap_or(
                    match key.package.source {
                        PackageSourceKey::CratesIo => Exclusions::CargoRegistryMarker,
                        PackageSourceKey::Git(_) => Exclusions::None,
                        PackageSourceKey::Path(_) => Exclusions::GitAndTarget,
                    },
                ),
            },
        );
    }
    if planned.len() != graph.units.len() {
        return Err(Error::failure(
            "dependency compilation order does not cover every unit",
        ));
    }
    Ok(CompilationPlan {
        units: planned,
        order: graph.order.clone(),
    })
}

fn selected_macro_script_units(
    graph: &UnitGraph,
    manifests: &BTreeMap<PackageKey, Manifest>,
    options: &PlanOptions<'_>,
) -> Result<Option<UnitGraph>> {
    let root_opt = if options.release {
        options.release_profile.opt_level
    } else {
        options.dev_profile.opt_level
    };
    // Equal pre-reduction script profiles share Cargo's host debug adjustment.
    if root_opt == "0" {
        return Ok(None);
    }
    let mut normalized = None;
    for parent in graph.units.values().filter(|unit| {
        graph.selected_packages.contains(&unit.key.package)
            && (unit.key.kind == UnitKind::ProcMacro
                && unit.key.profile == ProfileContext::Selected
                || unit.key.kind == UnitKind::LibraryHarness
                    && unit.key.compile_kind == CompileKind::Host)
    }) {
        let Some(edge) = parent
            .dependencies
            .iter()
            .find(|edge| edge.kind == UnitEdgeKind::BuildScriptOutput)
        else {
            continue;
        };
        let mut run = graph.units[&edge.unit].clone();
        run.key.profile = ProfileContext::Selected;
        let manifest = &manifests[&parent.key.package];
        if unit_settings(graph, &edge.unit, manifest, options)
            == unit_settings(graph, &run.key, manifest, options)
        {
            continue;
        }
        let graph = normalized.get_or_insert_with(|| graph.clone());
        let selected = run.key.clone();
        graph.units.insert(selected.clone(), run);
        let parent = graph.units.get_mut(&parent.key).unwrap();
        parent.dependencies = parent
            .dependencies
            .iter()
            .cloned()
            .map(|mut dependency| {
                if dependency.kind == UnitEdgeKind::BuildScriptOutput {
                    dependency.unit = selected.clone();
                }
                dependency
            })
            .collect();
    }
    if let Some(graph) = &mut normalized {
        let roots = graph
            .units
            .keys()
            .filter(|key| key.kind != UnitKind::BuildScriptRun)
            .cloned()
            .collect();
        retain_unit_roots(graph, roots)?;
    }
    Ok(normalized)
}

impl UnitProfile {
    fn cargo_profile(&self) -> CargoProfile<'_> {
        CargoProfile {
            opt_level: self.opt_level,
            lto: self.lto,
            codegen_backend: None,
            codegen_units: self.codegen_units,
            debuginfo: self.debuginfo,
            split_debuginfo: None,
            debug_assertions: self.debug_assertions,
            overflow_checks: self.overflow_checks,
            rpath: false,
            incremental: self.incremental,
            panic: self.panic,
            strip: self.strip,
            rustflags: &[],
        }
    }
}

fn library_crate_types(manifest: &Manifest) -> Vec<CargoCrateType<'_>> {
    cargo_crate_types(&manifest.library.as_ref().unwrap().crate_types)
}

fn cargo_crate_types(types: &[String]) -> Vec<CargoCrateType<'_>> {
    types
        .iter()
        .map(|kind| match kind.as_str() {
            "lib" => CargoCrateType::Lib,
            "rlib" => CargoCrateType::Rlib,
            "staticlib" => CargoCrateType::Staticlib,
            "dylib" => CargoCrateType::Dylib,
            "cdylib" => CargoCrateType::Cdylib,
            "proc-macro" => CargoCrateType::ProcMacro,
            other => CargoCrateType::Other(other),
        })
        .collect()
}

fn validate_manifest_identity(key: &PackageKey, manifest: &Manifest) -> Result<()> {
    let version = &manifest.version;
    if manifest.name != key.name
        || (version.major, version.minor, version.patch)
            != (key.version.major, key.version.minor, key.version.patch)
        || version.pre != key.version.pre.as_str()
        || version.build != key.version.build.as_str()
    {
        return Err(Error::failure(format!(
            "dependency manifest identity `{} {}` does not match resolved package `{} {}`",
            manifest.name, manifest.version.original, key.name, key.version
        )));
    }
    Ok(())
}

fn unit_settings(
    graph: &UnitGraph,
    key: &UnitKey,
    manifest: &Manifest,
    options: &PlanOptions<'_>,
) -> UnitSettings {
    let local = matches!(key.package.source, PackageSourceKey::Path(_));
    let mut profile = base_profile(
        options.release,
        options.release_profile,
        options.dev_profile,
        options.panic_abort,
        local,
        key.profile == ProfileContext::Test,
    );
    let test_graph = graph
        .units
        .keys()
        .any(|key| matches!(key.mode, UnitMode::Test | UnitMode::CheckTest));
    let selected_macro_profile = |key: &UnitKey| {
        let selected_macro = (key.kind == UnitKind::ProcMacro
            && graph.primary_macros.contains(&key.package)
            && (!test_graph || key.mode == UnitMode::Check)
            && (key.profile == ProfileContext::Selected
                || (!options.release
                    && !graph.units.keys().any(|other| {
                        other.package == key.package
                            && other.kind == UnitKind::ProcMacro
                            && other.profile == ProfileContext::Selected
                    })
                    && (key.mode == UnitMode::Check
                        || !graph.units.contains_key(&UnitKey {
                            mode: UnitMode::Check,
                            ..key.clone()
                        })))))
            || (key.kind == UnitKind::LibraryHarness
                && manifest
                    .library
                    .as_ref()
                    .is_some_and(|library| library.proc_macro));
        selected_macro && graph.selected_packages.contains(&key.package)
    };
    let macro_dependency = graph.units.keys().any(|parent| {
        parent.package == key.package
            && parent.kind == UnitKind::ProcMacro
            && !selected_macro_profile(parent)
    });
    let selected_macro = selected_macro_profile(key)
        || (key.kind == UnitKind::BuildScriptRun
            && (key.profile == ProfileContext::Selected
                || (!macro_dependency
                    && graph.units.values().any(|parent| {
                        parent.key.package == key.package
                            && selected_macro_profile(&parent.key)
                            && parent.dependencies.iter().any(|edge| {
                                edge.kind == UnitEdgeKind::BuildScriptOutput && edge.unit == *key
                            })
                    }))));
    let for_host = key.uses_host_profile() && !selected_macro;
    let run_strip = run_build_profile(&profile).strip;
    if selected_macro {
        profile.panic = CargoPanicStrategy::Unwind;
    }
    if for_host {
        profile.opt_level = "0";
        profile.codegen_units = None;
        profile.panic = CargoPanicStrategy::Unwind;
        let sharing_key = if key.kind == UnitKind::BuildScriptRun {
            UnitKey {
                kind: UnitKind::Library,
                ..key.clone()
            }
        } else {
            key.clone()
        };
        if profile.debuginfo != CargoDebugInfo::None
            && options.logical_target.is_none()
            && !shared_native_library(graph, &sharing_key, options, &profile)
        {
            profile.debuginfo = CargoDebugInfo::None;
        }
    }
    if key.kind == UnitKind::BuildScriptRun {
        profile = run_build_profile(&profile);
        // Cargo chooses automatic stripping before it reduces host debug information.
        profile.strip = run_strip;
    }

    let logical_target = match key.compile_kind {
        CompileKind::Target => options.logical_target.map(str::to_owned),
        CompileKind::Host => None,
    };
    let rustflags = if key.compile_kind == CompileKind::Target || options.logical_target.is_none() {
        options.rustflags.to_vec()
    } else {
        Vec::new()
    };
    UnitSettings {
        profile,
        mode: match key.mode {
            UnitMode::Build if key.kind == UnitKind::BuildScriptRun => {
                CargoCompileMode::RunCustomBuild
            }
            UnitMode::Build => CargoCompileMode::Build,
            UnitMode::Test => CargoCompileMode::Test,
            UnitMode::Check => CargoCompileMode::Check { test: false },
            UnitMode::CheckTest => CargoCompileMode::Check { test: true },
        },
        lto: if let Some(types) = key.library_types(manifest)
            && types.iter().any(|kind| {
                matches!(
                    kind.as_str(),
                    "staticlib" | "dylib" | "cdylib" | "proc-macro"
                )
            }) {
            library_lto(key, types, options)
        } else {
            unit_lto(
                key,
                key.library_types(manifest).is_some(),
                options.release,
                options.release_profile.lto,
            )
        },
        logical_target,
        rustflags,
    }
}

fn library_lto(
    key: &UnitKey,
    types: &[String],
    options: &PlanOptions<'_>,
) -> CargoUnitLto<'static> {
    let configured = options.release_profile.lto;
    let ordinary = unit_lto(key, true, options.release, configured);
    if !options.release
        || key.compile_kind == CompileKind::Host
        || matches!(configured, ManifestLto::Default | ManifestLto::Off)
    {
        return ordinary;
    }
    if types
        .iter()
        .all(|kind| matches!(kind.as_str(), "staticlib" | "cdylib"))
    {
        root_lto(true, configured, RootTargetKind::Binary, false)
    } else if types.iter().all(|kind| kind == "dylib") {
        CargoUnitLto::OnlyObject
    } else {
        CargoUnitLto::ObjectAndBitcode
    }
}

fn base_profile(
    release: bool,
    configured: &ReleaseProfile,
    dev: &DevProfile,
    panic_abort: bool,
    local: bool,
    test_profile: bool,
) -> UnitProfile {
    if release {
        UnitProfile {
            opt_level: configured.opt_level,
            lto: profile_lto(configured.lto),
            codegen_units: configured.codegen_units,
            debuginfo: configured.debug.unwrap_or(CargoDebugInfo::None),
            debug_assertions: false,
            overflow_checks: false,
            incremental: false,
            panic: if panic_abort && !test_profile {
                CargoPanicStrategy::Abort
            } else {
                CargoPanicStrategy::Unwind
            },
            strip: crate::identity::manifest_strip(
                configured.strip,
                configured.debug.unwrap_or(CargoDebugInfo::None),
            ),
        }
    } else {
        UnitProfile {
            opt_level: dev.opt_level,
            lto: CargoProfileLto::Bool(false),
            codegen_units: None,
            debuginfo: dev.debug.unwrap_or(CargoDebugInfo::Full),
            debug_assertions: true,
            overflow_checks: true,
            incremental: local,
            panic: if panic_abort && !test_profile {
                CargoPanicStrategy::Abort
            } else {
                CargoPanicStrategy::Unwind
            },
            strip: crate::identity::manifest_strip(
                crate::manifest::Strip::Default,
                dev.debug.unwrap_or(CargoDebugInfo::Full),
            ),
        }
    }
}

fn run_build_profile(for_unit: &UnitProfile) -> UnitProfile {
    UnitProfile {
        opt_level: for_unit.opt_level,
        lto: CargoProfileLto::Bool(false),
        codegen_units: None,
        debuginfo: for_unit.debuginfo,
        debug_assertions: for_unit.debug_assertions,
        overflow_checks: false,
        incremental: false,
        panic: CargoPanicStrategy::Unwind,
        strip: if for_unit.debuginfo == CargoDebugInfo::None {
            CargoStrip::Named("debuginfo")
        } else {
            CargoStrip::None
        },
    }
}

fn shared_native_library(
    graph: &UnitGraph,
    key: &UnitKey,
    options: &PlanOptions<'_>,
    host_profile: &UnitProfile,
) -> bool {
    let target = UnitKey {
        compile_kind: CompileKind::Target,
        ..key.clone()
    };
    key.kind == UnitKind::Library
        && key.compile_kind == CompileKind::Host
        && options.logical_target.is_none()
        && graph.units.contains_key(&target)
        && *host_profile
            == base_profile(
                options.release,
                options.release_profile,
                options.dev_profile,
                options.panic_abort,
                matches!(key.package.source, PackageSourceKey::Path(_)),
                key.profile == ProfileContext::Test,
            )
        && unit_lto(key, true, options.release, options.release_profile.lto)
            == unit_lto(&target, true, options.release, options.release_profile.lto)
}

fn profile_lto(lto: ManifestLto) -> CargoProfileLto<'static> {
    match lto {
        ManifestLto::Default => CargoProfileLto::Bool(false),
        ManifestLto::True => CargoProfileLto::Bool(true),
        ManifestLto::Fat => CargoProfileLto::Named("fat"),
        ManifestLto::Thin => CargoProfileLto::Named("thin"),
        ManifestLto::Off => CargoProfileLto::Off,
    }
}

fn unit_lto(
    key: &UnitKey,
    library: bool,
    release: bool,
    configured: ManifestLto,
) -> CargoUnitLto<'static> {
    if key.is_harness() {
        return root_lto(release, configured, RootTargetKind::Binary, true);
    }
    if !library
        && matches!(
            key.kind,
            UnitKind::Binary | UnitKind::Example | UnitKind::Bench
        )
    {
        return root_lto(release, configured, RootTargetKind::Binary, false);
    }
    if !release || key.compile_kind == CompileKind::Host || !library {
        return CargoUnitLto::OnlyObject;
    }
    match configured {
        ManifestLto::Default => CargoUnitLto::OnlyObject,
        ManifestLto::Off => CargoUnitLto::Off,
        ManifestLto::True | ManifestLto::Fat | ManifestLto::Thin => CargoUnitLto::OnlyBitcode,
    }
}

fn cargo_path_source(workspace_root: &Path, package_root: &Path) -> Result<String> {
    if let Ok(relative) = package_root.strip_prefix(workspace_root) {
        return relative
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| Error::failure("path package identity is not valid UTF-8"));
    }
    let path = package_root
        .to_str()
        .ok_or_else(|| Error::failure("path package identity is not valid UTF-8"))?;
    if !package_root.is_absolute() {
        return Err(Error::failure(format!(
            "path package identity `{}` is neither workspace-relative nor absolute",
            package_root.display()
        )));
    }
    let mut encoded = String::from("file://");
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'/' | b'-'
                    | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
            )
        {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").unwrap();
        }
    }
    Ok(encoded)
}

fn features_for(package: &ResolvedPackage, compile_kind: CompileKind) -> BTreeSet<String> {
    if let Some(features) = package.feature_sets.get(&FeatureContext::Unified) {
        return features.clone();
    }
    match compile_kind {
        CompileKind::Target => package.target_features.clone(),
        CompileKind::Host => package.host_features.clone(),
    }
}

fn unit_key(
    package: &ResolvedPackage,
    kind: UnitKind,
    compile_kind: CompileKind,
    features: &BTreeSet<String>,
) -> UnitKey {
    UnitKey {
        package: package.key.clone(),
        kind,
        mode: UnitMode::Build,
        target: None,
        compile_kind,
        profile: ProfileContext::Normal,
        features: features.clone(),
    }
}

fn insert_unit(units: &mut BTreeMap<UnitKey, Unit>, key: UnitKey) {
    units.entry(key.clone()).or_insert_with(|| Unit {
        key,
        dependencies: BTreeSet::new(),
    });
}

fn add_edge(
    units: &mut BTreeMap<UnitKey, Unit>,
    parent: &UnitKey,
    dependency: UnitKey,
    kind: UnitEdgeKind,
    alias: Option<String>,
) -> Result<()> {
    if !units.contains_key(&dependency) {
        return Err(Error::failure(format!(
            "unit {:?} for `{} {}` depends on absent unit {:?} for `{} {}`",
            parent.kind,
            parent.package.name,
            parent.package.version,
            dependency.kind,
            dependency.package.name,
            dependency.package.version
        )));
    }
    let unit = units.get_mut(parent).ok_or_else(|| {
        Error::failure(format!(
            "dependency graph omitted {:?} unit for `{} {}`",
            parent.kind, parent.package.name, parent.package.version
        ))
    })?;
    unit.dependencies.insert(UnitEdge {
        unit: dependency,
        kind,
        alias,
    });
    Ok(())
}

fn topological_order(units: &BTreeMap<UnitKey, Unit>) -> Result<Vec<UnitKey>> {
    let mut remaining = units
        .iter()
        .map(|(key, unit)| {
            (
                key.clone(),
                unit.dependencies
                    .iter()
                    .map(|edge| edge.unit.clone())
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut ready = remaining
        .iter()
        .filter(|(_, dependencies)| dependencies.is_empty())
        .map(|(key, _)| key.clone())
        .collect::<BTreeSet<_>>();
    let mut order = Vec::with_capacity(units.len());

    while let Some(key) = ready.pop_first() {
        if !remaining.contains_key(&key) {
            continue;
        }
        remaining.remove(&key);
        order.push(key.clone());
        let dependents = remaining
            .iter_mut()
            .filter_map(|(dependent, dependencies)| {
                dependencies.remove(&key).then(|| dependent.clone())
            })
            .collect::<Vec<_>>();
        for dependent in dependents {
            if remaining[&dependent].is_empty() {
                ready.insert(dependent);
            }
        }
    }
    if !remaining.is_empty() {
        let units = remaining
            .keys()
            .map(|key| {
                format!(
                    "{} {} {:?}",
                    key.package.name, key.package.version, key.kind
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        return Err(Error::failure(format!(
            "dependency unit graph contains a cycle among: {units}"
        )));
    }
    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::{CommandOptions, RustcOutput, dependency_rustc_invocation};
    use crate::config::CargoCompat;
    use crate::manifest::Manifest;
    use crate::manifest::Strip as ManifestStrip;
    use crate::resolver::{
        Catalog, Options, ResolvedEdge, ResolvedSource, TargetSelection, resolve_selected,
    };
    use crate::toolchain::CfgSet;
    use semver::Version;
    use serde_json::Value;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("lorry-unit-graph-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(path.join("src")).unwrap();
            fs::write(path.join("src/lib.rs"), "pub fn root() {}\n").unwrap();
            Self(path)
        }

        fn package(&self, name: &str, manifest: &str, build_script: bool) {
            let root = self.0.join(name);
            fs::create_dir_all(root.join("src")).unwrap();
            fs::write(root.join("Cargo.toml"), manifest).unwrap();
            fs::write(root.join("src/lib.rs"), "pub fn library() {}\n").unwrap();
            if build_script {
                fs::write(root.join("build.rs"), "fn main() {}\n").unwrap();
            }
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
            clippy: None,
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
            compatibility: CargoCompat::V1_99,
        }
    }

    #[test]
    fn custom_library_dependency_names_match_cargo() {
        let fixture = Fixture::new();
        fixture.package(
            "shared",
            "[package]\nname = \"shared\"\nversion = \"1.0.0\"\nedition = \"2024\"\n\
             [lib]\nname = \"shared_crate\"\n",
            false,
        );
        let cfg = CfgSet::parse("unix\n").unwrap();
        for (declaration, expected) in [
            ("shared = { path = \"shared\" }", "shared_crate"),
            (
                "renamed = { package = \"shared\", path = \"shared\" }",
                "renamed",
            ),
            (
                "shared = { package = \"shared\", path = \"shared\" }",
                "shared",
            ),
        ] {
            fs::write(
                fixture.0.join("Cargo.toml"),
                format!(
                    "[package]\nname = \"root\"\nversion = \"1.0.0\"\nedition = \"2024\"\n\
                         [dependencies]\n{declaration}\n"
                ),
            )
            .unwrap();
            let cargo = Command::new(env!("CARGO"))
                .current_dir(&fixture.0)
                .env(
                    "RUSTC",
                    Path::new(env!("CARGO")).parent().unwrap().join("rustc"),
                )
                .args([
                    "-Z",
                    "unstable-options",
                    "build",
                    "--unit-graph",
                    "--offline",
                ])
                .output()
                .unwrap();
            assert!(
                cargo.status.success(),
                "{}",
                String::from_utf8_lossy(&cargo.stderr)
            );
            let cargo: Value = serde_json::from_slice(&cargo.stdout).unwrap();
            let root_index = cargo["roots"][0].as_u64().unwrap() as usize;
            let cargo_alias = cargo["units"][root_index]["dependencies"][0]["extern_crate_name"]
                .as_str()
                .unwrap();
            assert_eq!(cargo_alias, expected);
            let root = Manifest::load(&fixture.0).unwrap();
            let resolution = resolve_selected(
                &root,
                &Catalog::default(),
                &Options {
                    resolver: root.resolver,
                    incompatible_rust_versions: None,
                    rust_versions: vec![Version::parse("1.99.0").unwrap()],
                    package_limit: crate::policy::PackageLimit::with_max(16),
                    max_depth: Some(8),
                },
                &[],
                TargetSelection {
                    target_triple: "x86_64-unknown-linux-gnu",
                    target_cfg: &cfg,
                    host_triple: "x86_64-unknown-linux-gnu",
                    host_cfg: &cfg,
                },
            )
            .unwrap();
            let manifests = resolution
                .packages
                .iter()
                .map(|package| (package.key.clone(), package.local_manifest.clone().unwrap()))
                .collect::<BTreeMap<_, _>>();
            let mut graph = dependency_units(&resolution, &manifests).unwrap();
            let library = add_selected_library(&mut graph, &resolution, &manifests, &root).unwrap();
            let edge = graph.units[&library].dependencies.iter().next().unwrap();
            assert_eq!(edge.alias.as_deref(), Some(cargo_alias), "{declaration}");
            // The same crate name is needed when this root is a dependency.
            let mut resolved_root = resolution.packages[0].clone();
            resolved_root.key = library.package.clone();
            resolved_root.local_manifest = Some(root.clone());
            resolved_root.edges = resolution.root_edges.clone();
            for edge in &mut resolved_root.edges {
                edge.parent_compile_kind = Some(CompileKind::Target);
            }
            let mut complete = resolution.clone();
            complete.packages.push(resolved_root);
            let mut manifests = manifests.clone();
            manifests.insert(library.package.clone(), root);
            let graph = dependency_units(&complete, &manifests).unwrap();
            let edge = graph.units[&library].dependencies.iter().next().unwrap();
            assert_eq!(
                edge.alias.as_deref(),
                Some(cargo_alias),
                "dependency {declaration}"
            );
        }
    }

    #[test]
    fn selected_targets_use_dependency_units_and_aliases() {
        let fixture = Fixture::new();
        fs::write(fixture.0.join("src/one.rs"), "fn main() {}\n").unwrap();
        fs::write(fixture.0.join("src/two.rs"), "fn main() {}\n").unwrap();
        fixture.package(
            "shared",
            "[package]\nname = \"shared\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
            false,
        );
        let root = Manifest::parse(
            &fixture.0,
            &fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\nrenamed = { package = \"shared\", path = \"shared\" }\n\
             [[bin]]\nname = \"one\"\npath = \"src/one.rs\"\n\
             [[bin]]\nname = \"two\"\npath = \"src/two.rs\"\n",
        )
        .unwrap();
        let cfg = CfgSet::parse("unix\n").unwrap();
        let resolution = resolve_selected(
            &root,
            &Catalog::default(),
            &Options {
                resolver: root.resolver,
                incompatible_rust_versions: None,
                rust_versions: vec![Version::parse("1.98.0").unwrap()],
                package_limit: crate::policy::PackageLimit::with_max(16),
                max_depth: Some(8),
            },
            &[],
            TargetSelection {
                target_triple: "x86_64-unknown-linux-gnu",
                target_cfg: &cfg,
                host_triple: "x86_64-unknown-linux-gnu",
                host_cfg: &cfg,
            },
        )
        .unwrap();
        let mut manifests = resolution
            .packages
            .iter()
            .map(|package| (package.key.clone(), package.local_manifest.clone().unwrap()))
            .collect::<BTreeMap<_, _>>();
        let mut graph = dependency_units(&resolution, &manifests).unwrap();
        let selected = add_selected_library(&mut graph, &resolution, &manifests, &root).unwrap();
        let binaries =
            add_selected_binaries(&mut graph, &resolution, &manifests, &root, None).unwrap();
        assert_eq!(binaries.len(), 2);
        let harnesses = add_selected_harnesses(&mut graph, &resolution, &manifests, &root).unwrap();
        assert_eq!(harnesses.len(), 3);
        assert!(
            harnesses
                .iter()
                .any(|key| key.kind == UnitKind::LibraryHarness)
        );
        assert!(
            harnesses
                .iter()
                .filter(|key| key.kind == UnitKind::BinaryHarness)
                .all(|key| {
                    graph.units[key]
                        .dependencies
                        .iter()
                        .any(|edge| edge.unit == selected)
                })
        );
        assert_eq!(binaries[0].target.as_deref(), Some("one"));
        assert_eq!(binaries[1].target.as_deref(), Some("two"));
        for binary in &binaries {
            assert!(
                graph.units[binary]
                    .dependencies
                    .iter()
                    .any(|edge| edge.unit == selected)
            );
            assert!(
                graph.units[binary]
                    .dependencies
                    .iter()
                    .any(|edge| edge.alias.as_deref() == Some("renamed"))
            );
        }
        manifests.insert(selected.package.clone(), root.clone());
        let edge = graph.units[&selected].dependencies.iter().next().unwrap();
        assert_eq!(edge.alias.as_deref(), Some("renamed"));
        assert_eq!(edge.unit.package.name, "shared");
        assert!(
            graph
                .order
                .iter()
                .position(|key| key == &edge.unit)
                .unwrap()
                < graph.order.iter().position(|key| key == &selected).unwrap()
        );
        let plan = plan_dependency_units(
            &graph,
            &manifests,
            &PlanOptions {
                workspace_root: &fixture.0,
                release: true,
                test_profile: false,
                panic_abort: false,
                dev_profile: &root.dev,
                release_profile: &root.release,
                rustc: &toolchain(),
                logical_target: None,
                rustflags: &[],
            },
        )
        .unwrap();
        assert!(plan.units.contains_key(&selected));
        assert_ne!(
            plan.units[&binaries[0]].identity,
            plan.units[&binaries[1]].identity
        );
        let test_graph = graph.clone().with_profile(ProfileContext::Test, true);
        let test_key = UnitKey {
            profile: ProfileContext::Test,
            ..selected.clone()
        };
        assert_eq!(test_graph.units.len(), graph.units.len());
        assert!(
            test_graph.units[&test_key]
                .dependencies
                .iter()
                .all(|edge| edge.unit.profile == ProfileContext::Test)
        );
        let options = PlanOptions {
            workspace_root: &fixture.0,
            release: true,
            test_profile: false,
            panic_abort: true,
            dev_profile: &root.dev,
            release_profile: &root.release,
            rustc: &toolchain(),
            logical_target: None,
            rustflags: &[],
        };
        let normal_plan = plan_dependency_units(&graph, &manifests, &options).unwrap();
        let test_plan = plan_dependency_units(&test_graph, &manifests, &options).unwrap();
        assert_eq!(
            normal_plan.units[&selected].settings.profile.panic,
            CargoPanicStrategy::Abort
        );
        assert_eq!(
            test_plan.units[&test_key].settings.profile.panic,
            CargoPanicStrategy::Unwind
        );
        assert_ne!(
            normal_plan.units[&selected].identity,
            test_plan.units[&test_key].identity
        );
        let mut merged = graph.clone();
        merged.merge(test_graph).unwrap();
        assert_eq!(merged.units.len(), graph.units.len() * 2);
        assert!(merged.units.contains_key(&selected));
        assert!(merged.units.contains_key(&test_key));
        let test_dependency = &merged.units[&test_key]
            .dependencies
            .iter()
            .next()
            .unwrap()
            .unit;
        assert_eq!(test_dependency.profile, ProfileContext::Test);
        assert!(
            merged.order.iter().position(|key| key == test_dependency)
                < merged.order.iter().position(|key| key == &test_key)
        );
        let mut equivalent = graph.clone();
        equivalent
            .merge(graph.clone().with_profile(ProfileContext::Test, false))
            .unwrap();
        assert_eq!(equivalent, graph);
        let invocation = dependency_rustc_invocation(
            &plan,
            &manifests,
            &binaries[0],
            &CommandOptions {
                cargo: Path::new("/cargo"),
                workspace_root: &fixture.0,
                selected_packages: std::slice::from_ref(&selected.package),
                host_profile: Path::new("/target/debug"),
                target_profile: Path::new("/target/debug"),
                host_incremental: Path::new("/incremental/host"),
                target_incremental: Path::new("/incremental/target"),
                physical_target: None,
                host_linker: None,
                target_linker: None,
                integration_binaries: None,
                integration_temp_dirs: None,
                verbose: false,
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(invocation.arguments[3], "src/one.rs");
        assert_eq!(invocation.environment["CARGO_BIN_NAME"], "one");
        assert_eq!(invocation.environment["CARGO_PRIMARY_PACKAGE"], "1");
        assert!(matches!(invocation.output, RustcOutput::Binary { .. }));
        let harness = dependency_rustc_invocation(
            &plan,
            &manifests,
            &harnesses[0],
            &CommandOptions {
                cargo: Path::new("/cargo"),
                workspace_root: &fixture.0,
                selected_packages: std::slice::from_ref(&selected.package),
                host_profile: Path::new("/target/debug"),
                target_profile: Path::new("/target/debug"),
                host_incremental: Path::new("/incremental/host"),
                target_incremental: Path::new("/incremental/target"),
                physical_target: None,
                host_linker: None,
                target_linker: None,
                integration_binaries: None,
                integration_temp_dirs: None,
                verbose: false,
            },
        )
        .unwrap()
        .unwrap();
        assert!(
            harness
                .arguments
                .iter()
                .any(|argument| argument == "--test")
        );
        assert!(
            !harness
                .arguments
                .iter()
                .any(|argument| argument == "--crate-type")
        );
    }

    #[test]
    fn selected_build_graph_matches_cargo_unit_graph() {
        let fixture = Fixture::new();
        let workspace = fixture.0.join("workspace");
        fs::create_dir_all(workspace.join("app/src")).unwrap();
        fs::create_dir_all(workspace.join("shared/src")).unwrap();
        fs::write(
            workspace.join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\", \"shared\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        fs::write(
            workspace.join("Cargo.lock"),
            "version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
             dependencies = [\"shared\"]\n[[package]]\nname = \"shared\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(
            workspace.join("app/Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\
             [dependencies]\nrenamed = { package = \"shared\", path = \"../shared\" }\n",
        )
        .unwrap();
        fs::write(
            workspace.join("shared/Cargo.toml"),
            "[package]\nname = \"shared\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(workspace.join("app/src/lib.rs"), "pub fn value() {}\n").unwrap();
        fs::write(workspace.join("app/src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(workspace.join("shared/src/lib.rs"), "pub fn value() {}\n").unwrap();

        let root = Manifest::load_selected(&workspace, Some("app")).unwrap();
        let cfg = CfgSet::parse("unix\n").unwrap();
        let resolution = resolve_selected(
            &root,
            &Catalog::default(),
            &Options {
                resolver: root.resolver,
                incompatible_rust_versions: None,
                rust_versions: vec![Version::parse("1.99.0").unwrap()],
                package_limit: crate::policy::PackageLimit::with_max(16),
                max_depth: Some(8),
            },
            &[],
            TargetSelection {
                target_triple: "x86_64-unknown-linux-gnu",
                target_cfg: &cfg,
                host_triple: "x86_64-unknown-linux-gnu",
                host_cfg: &cfg,
            },
        )
        .unwrap();
        let mut manifests = resolution
            .packages
            .iter()
            .map(|package| (package.key.clone(), package.local_manifest.clone().unwrap()))
            .collect::<BTreeMap<_, _>>();
        let mut graph = dependency_units(&resolution, &manifests).unwrap();
        let library = add_selected_library(&mut graph, &resolution, &manifests, &root).unwrap();
        let binaries =
            add_selected_binaries(&mut graph, &resolution, &manifests, &root, None).unwrap();
        manifests.insert(library.package.clone(), root.clone());
        let plan = plan_dependency_units(
            &graph,
            &manifests,
            &PlanOptions {
                workspace_root: &workspace,
                release: false,
                test_profile: false,
                panic_abort: false,
                dev_profile: &root.dev,
                release_profile: &root.release,
                rustc: &toolchain(),
                logical_target: None,
                rustflags: &[],
            },
        )
        .unwrap();

        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let result = Command::new(cargo)
            .args([
                "-Z",
                "unstable-options",
                "build",
                "--unit-graph",
                "--offline",
            ])
            .arg("--manifest-path")
            .arg(workspace.join("Cargo.toml"))
            .args(["-p", "app"])
            .env("CARGO_NET_OFFLINE", "true")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let cargo: Value = serde_json::from_slice(&result.stdout).unwrap();
        let roots = std::iter::once(library).chain(binaries).collect::<Vec<_>>();
        assert_ordinary_cargo_plan(&cargo, &plan, &manifests, &roots, "dev");
    }

    fn assert_ordinary_cargo_plan(
        cargo: &Value,
        plan: &CompilationPlan,
        manifests: &BTreeMap<PackageKey, Manifest>,
        roots: &[UnitKey],
        profile_name: &str,
    ) {
        let units = cargo["units"].as_array().unwrap();
        let cargo_nodes = units
            .iter()
            .map(|unit| {
                let package = unit["pkg_id"]
                    .as_str()
                    .unwrap()
                    .rsplit('/')
                    .next()
                    .unwrap()
                    .split('#')
                    .next()
                    .unwrap();
                let kind = unit["target"]["kind"][0].as_str().unwrap();
                let name = unit["target"]["name"].as_str().unwrap();
                (package.to_owned(), kind.to_owned(), name.to_owned())
            })
            .collect::<Vec<_>>();
        let lorry_node = |key: &UnitKey| {
            let kind = match key.kind {
                UnitKind::Library => "lib",
                UnitKind::Binary => "bin",
                UnitKind::Example => "example",
                UnitKind::Bench => "bench",
                _ => panic!("unexpected unit in build oracle: {:?}", key.kind),
            };
            let name = key.target.as_deref().unwrap_or_else(|| {
                manifests[&key.package]
                    .library
                    .as_ref()
                    .unwrap()
                    .name
                    .as_str()
            });
            (key.package.name.clone(), kind.to_owned(), name.to_owned())
        };
        let lorry_nodes = plan.units.keys().map(lorry_node).collect::<Vec<_>>();
        assert_eq!(
            cargo_nodes.iter().cloned().collect::<BTreeSet<_>>(),
            lorry_nodes.iter().cloned().collect::<BTreeSet<_>>()
        );
        let mut cargo_edges = BTreeSet::new();
        for (parent, unit) in units.iter().enumerate() {
            for edge in unit["dependencies"].as_array().unwrap() {
                cargo_edges.insert((
                    cargo_nodes[parent].clone(),
                    cargo_nodes[edge["index"].as_u64().unwrap() as usize].clone(),
                    edge["extern_crate_name"].as_str().unwrap().to_owned(),
                ));
            }
        }
        let lorry_edges = plan
            .units
            .values()
            .flat_map(|planned| {
                planned.unit.dependencies.iter().map(|edge| {
                    (
                        lorry_node(&planned.unit.key),
                        lorry_node(&edge.unit),
                        edge.alias.clone().unwrap(),
                    )
                })
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(cargo_edges, lorry_edges);
        let cargo_roots = cargo["roots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|index| cargo_nodes[index.as_u64().unwrap() as usize].clone())
            .collect::<BTreeSet<_>>();
        let lorry_roots = roots.iter().map(lorry_node).collect::<BTreeSet<_>>();
        assert_eq!(cargo_roots, lorry_roots);
        for (key, planned) in &plan.units {
            let node = lorry_node(key);
            let unit = &units[cargo_nodes
                .iter()
                .position(|candidate| *candidate == node)
                .unwrap()];
            let profile = &unit["profile"];
            if let Some(target) = key.auxiliary_target(&manifests[&key.package]) {
                assert_eq!(
                    unit["target"]["crate_types"],
                    serde_json::json!(target.crate_types)
                );
            }
            let (mode, compile_mode) = match key.mode {
                UnitMode::Check => ("check", CargoCompileMode::Check { test: false }),
                UnitMode::CheckTest => ("check", CargoCompileMode::Check { test: true }),
                UnitMode::Test => ("test", CargoCompileMode::Test),
                UnitMode::Build => ("build", CargoCompileMode::Build),
            };
            assert_eq!(planned.settings.mode, compile_mode);
            assert_eq!(unit["mode"], mode);
            assert!(unit["platform"].is_null());
            assert_eq!(unit["features"], serde_json::json!(key.features));
            assert_eq!(profile["name"], profile_name);
            assert_eq!(profile["opt_level"], planned.settings.profile.opt_level);
            assert_eq!(planned.settings.profile.lto, CargoProfileLto::Bool(false));
            assert_eq!(profile["lto"], "false");
            assert!(profile["codegen_backend"].is_null());
            assert!(profile["codegen_units"].is_null());
            assert_eq!(profile["debuginfo"], 2);
            assert_eq!(planned.settings.profile.debuginfo, CargoDebugInfo::Full);
            assert!(profile["split_debuginfo"].is_null());
            assert_eq!(
                profile["debug_assertions"],
                planned.settings.profile.debug_assertions
            );
            assert_eq!(
                profile["overflow_checks"],
                planned.settings.profile.overflow_checks
            );
            assert_eq!(profile["incremental"], planned.settings.profile.incremental);
            assert_eq!(profile["panic"], "unwind");
            assert_eq!(planned.settings.profile.panic, CargoPanicStrategy::Unwind);
            assert_eq!(planned.settings.profile.strip, CargoStrip::None);
            assert_eq!(profile["strip"], serde_json::json!({ "deferred": "None" }));
            assert_eq!(profile["rpath"], false);
            assert!(planned.settings.rustflags.is_empty());
        }
    }

    #[test]
    fn workspace_auxiliary_graphs_match_cargo_with_dev_dependencies() {
        let fixture = Fixture::new();
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[workspace]\nmembers = [\"a\", \"b\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        fixture.package("a", "[package]\nname = \"a\"\nversion = \"1.0.0\"\nedition = \"2024\"\n[dev-dependencies]\nb = { path = \"../b\", features = [\"dev\"] }\n", false);
        fixture.package("b", "[package]\nname = \"b\"\nversion = \"1.0.0\"\nedition = \"2024\"\n[features]\ndev = []\n[dependencies]\na = { path = \"../a\" }\n", false);
        for directory in ["examples", "benches"] {
            fs::create_dir(fixture.0.join("a").join(directory)).unwrap();
            fs::write(
                fixture.0.join("a").join(directory).join("selected.rs"),
                "fn main() {}\n",
            )
            .unwrap();
        }
        let path = fixture.0.join("a/Cargo.toml");
        let source = fs::read_to_string(&path).unwrap();
        fs::write(&path, format!("{source}\n[[example]]\nname = \"library\"\ncrate-type = [\"rlib\", \"staticlib\"]\n")).unwrap();
        fs::write(
            fixture.0.join("a/examples/library.rs"),
            "pub fn value() {}\n",
        )
        .unwrap();
        let workspace = crate::manifest::SourceWorkspace::load(&fixture.0, None).unwrap();
        let limits = Options {
            resolver: crate::manifest::Resolver::V2,
            incompatible_rust_versions: None,
            rust_versions: vec![Version::parse("1.99.0").unwrap()],
            package_limit: crate::policy::PackageLimit::with_max(16),
            max_depth: None,
        };
        let mut catalog = Catalog::default();
        let complete = crate::resolver::workspace::resolve_complete_workspace(
            &workspace,
            &mut catalog,
            &limits,
            &[],
            &mut |_, _, _| Ok(()),
        )
        .unwrap();
        let cfg = CfgSet::parse("unix\n").unwrap();
        let resolution = crate::resolver::workspace::resolve_selected_workspace(
            &complete,
            &catalog,
            &limits,
            &[crate::resolver::workspace::MemberRequest {
                root: fixture.0.join("a"),
                features: BTreeSet::new(),
                default_features: true,
                dev: true,
                selected: true,
                target_units: true,
            }],
            TargetSelection {
                host_triple: "x86_64-unknown-linux-gnu",
                host_cfg: &cfg,
                target_triple: "x86_64-unknown-linux-gnu",
                target_cfg: &cfg,
            },
        )
        .unwrap();
        let manifests = resolution
            .packages
            .iter()
            .map(|package| (package.key.clone(), package.local_manifest.clone().unwrap()))
            .collect::<BTreeMap<_, _>>();
        let selected = manifests
            .keys()
            .filter(|key| key.name == "a")
            .cloned()
            .collect::<Vec<_>>();
        let options = PlanOptions {
            workspace_root: &fixture.0,
            release: false,
            test_profile: false,
            panic_abort: false,
            dev_profile: &DevProfile::default(),
            release_profile: &ReleaseProfile::default(),
            rustc: &toolchain(),
            logical_target: None,
            rustflags: &[],
        };
        for (kind, name, command, mode) in [
            ("example", "selected", "build", UnitMode::Build),
            ("example", "selected", "check", UnitMode::Check),
            ("example", "selected", "test", UnitMode::Test),
            ("example", "library", "build", UnitMode::Build),
            ("example", "library", "check", UnitMode::Check),
            ("example", "library", "test", UnitMode::Test),
            ("bench", "selected", "build", UnitMode::Test),
            ("bench", "selected", "check", UnitMode::CheckTest),
            ("bench", "selected", "test", UnitMode::Test),
        ] {
            let graph = workspace_auxiliary_units(
                &resolution,
                &manifests,
                &selected,
                &options,
                &AuxiliarySelection {
                    kind,
                    name: Some(name),
                    mode,
                },
            )
            .unwrap();
            let roots = graph
                .units
                .keys()
                .filter(|key| matches!(key.kind, UnitKind::Example | UnitKind::Bench))
                .cloned()
                .collect::<Vec<_>>();
            let plan = plan_dependency_units(&graph, &manifests, &options).unwrap();
            let output = Command::new(env!("CARGO"))
                .current_dir(&fixture.0)
                .args([
                    "-Z",
                    "unstable-options",
                    command,
                    "--unit-graph",
                    "--offline",
                    "-p",
                    "a",
                ])
                .args([&format!("--{kind}"), name])
                .env("CARGO_NET_OFFLINE", "true")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let cargo: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_ordinary_cargo_plan(
                &cargo,
                &plan,
                &manifests,
                &roots,
                if command == "test" { "test" } else { "dev" },
            );
            if kind == "example" {
                let invocation = crate::compile::dependency_rustc_invocation(
                    &plan,
                    &manifests,
                    &roots[0],
                    &crate::compile::CommandOptions {
                        cargo: Path::new("/lorry"),
                        workspace_root: &fixture.0,
                        selected_packages: &selected,
                        host_profile: Path::new("/outputs"),
                        target_profile: Path::new("/outputs"),
                        host_incremental: Path::new("/incremental"),
                        target_incremental: Path::new("/incremental"),
                        physical_target: None,
                        host_linker: None,
                        target_linker: None,
                        integration_binaries: None,
                        integration_temp_dirs: None,
                        verbose: false,
                    },
                )
                .unwrap()
                .unwrap();
                assert_eq!(
                    invocation.environment.contains_key("CARGO_BIN_NAME"),
                    name == "selected"
                );
                assert_eq!(
                    invocation
                        .arguments
                        .iter()
                        .any(|argument| argument == "--test"),
                    mode == UnitMode::Test
                );
                if name == "library" && mode == UnitMode::Build {
                    assert!(matches!(
                        invocation.output,
                        crate::compile::RustcOutput::Library {
                            archive: Some(_),
                            ..
                        }
                    ));
                    for kind in ["rlib", "staticlib"] {
                        assert!(
                            invocation
                                .arguments
                                .windows(2)
                                .any(|args| args[0] == "--crate-type" && args[1] == kind)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn workspace_build_and_check_plans_match_cargo() {
        let fixture = Fixture::new();
        fs::write(fixture.0.join("Cargo.toml"), "[workspace]\nmembers = [\"a\", \"b\", \"shared\"]\ndefault-members = [\"a\", \"b\"]\nresolver = \"2\"\n").unwrap();
        fixture.package("shared", "[package]\nname = \"shared\"\nversion = \"1.0.0\"\nedition = \"2024\"\n[lib]\nname = \"shared_crate\"\n[features]\nred = []\nblue = []\n", false);
        for (member, feature) in [("a", "red"), ("b", "blue")] {
            fixture.package(member, &format!("[package]\nname = \"{member}\"\nversion = \"1.0.0\"\nedition = \"2024\"\n[dependencies]\nshared = {{ path = \"../shared\", features = [\"{feature}\"] }}\n"), false);
            fs::write(fixture.0.join(member).join("src/main.rs"), "fn main() {}\n").unwrap();
        }
        fs::remove_file(fixture.0.join("b/src/lib.rs")).unwrap();
        let cfg = CfgSet::parse("unix\n").unwrap();
        let workspace = crate::manifest::SourceWorkspace::load(&fixture.0, None).unwrap();
        let limits = Options {
            resolver: workspace.packages[0].resolver,
            incompatible_rust_versions: None,
            rust_versions: vec![Version::parse("1.99.0").unwrap()],
            package_limit: crate::policy::PackageLimit::with_max(16),
            max_depth: None,
        };
        let mut catalog = Catalog::default();
        let complete = crate::resolver::workspace::resolve_complete_workspace(
            &workspace,
            &mut catalog,
            &limits,
            &[],
            &mut |_, _, _| Ok(()),
        )
        .unwrap();
        for (arguments, names) in [
            (vec![], vec!["a", "b"]),
            (vec!["--workspace"], vec!["a", "b", "shared"]),
            (vec!["-p", "a", "-p", "b"], vec!["a", "b"]),
            (vec!["--workspace", "--exclude", "b"], vec!["a", "shared"]),
        ] {
            let requests = names
                .iter()
                .map(|name| crate::resolver::workspace::MemberRequest {
                    root: fixture.0.join(name),
                    features: BTreeSet::new(),
                    default_features: true,
                    dev: false,
                    selected: true,
                    target_units: false,
                })
                .collect::<Vec<_>>();
            let resolution = crate::resolver::workspace::resolve_selected_workspace(
                &complete,
                &catalog,
                &limits,
                &requests,
                TargetSelection {
                    host_triple: "x86_64-unknown-linux-gnu",
                    host_cfg: &cfg,
                    target_triple: "x86_64-unknown-linux-gnu",
                    target_cfg: &cfg,
                },
            )
            .unwrap();
            let manifests = resolution
                .packages
                .iter()
                .map(|package| (package.key.clone(), package.local_manifest.clone().unwrap()))
                .collect::<BTreeMap<_, _>>();
            let selected = resolution
                .packages
                .iter()
                .filter(|package| names.contains(&package.key.name.as_str()))
                .map(|package| package.key.clone())
                .collect::<Vec<_>>();
            for command in ["build", "check"] {
                let result = Command::new(env!("CARGO"))
                    .args([
                        "-Z",
                        "unstable-options",
                        command,
                        "--unit-graph",
                        "--offline",
                    ])
                    .args(&arguments)
                    .env("CARGO_HOME", fixture.0.join("cargo-home"))
                    .env("RUSTC", Path::new(env!("CARGO")).with_file_name("rustc"))
                    .current_dir(&fixture.0)
                    .output()
                    .unwrap();
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
                let cargo = serde_json::from_slice(&result.stdout).unwrap();
                let graph = workspace_units(
                    &resolution,
                    &manifests,
                    &selected,
                    command == "check",
                    true,
                    None,
                    false,
                )
                .unwrap();
                let plan = plan_dependency_units(
                    &graph,
                    &manifests,
                    &PlanOptions {
                        workspace_root: &fixture.0,
                        release: false,
                        test_profile: false,
                        panic_abort: false,
                        dev_profile: &workspace.packages[0].dev,
                        release_profile: &workspace.packages[0].release,
                        rustc: &toolchain(),
                        logical_target: None,
                        rustflags: &[],
                    },
                )
                .unwrap();
                let roots = plan
                    .units
                    .keys()
                    .filter(|key| selected.contains(&key.package))
                    .cloned()
                    .collect::<Vec<_>>();
                assert_ordinary_cargo_plan(&cargo, &plan, &manifests, &roots, "dev");
            }
        }
    }

    #[test]
    fn selected_member_build_script_graphs_match_cargo() {
        let fixture = Fixture::new();
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[workspace]\nmembers = [\"a\", \"b\", \"builder\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        fixture.package("builder", "[package]\nname = \"builder\"\nversion = \"1.0.0\"\nedition = \"2024\"\n[features]\nnormal = []\nbuild = []\n", false);
        fixture.package("a", "[package]\nname = \"a\"\nversion = \"1.0.0\"\nedition = \"2024\"\n[dependencies]\nbuilder = { path = \"../builder\", features = [\"normal\"] }\n[build-dependencies]\nbuilder = { path = \"../builder\", features = [\"build\"] }\n", true);
        fixture.package("b", "[package]\nname = \"b\"\nversion = \"1.0.0\"\nedition = \"2024\"\n[target.'cfg(unix)'.build-dependencies]\nbuilder = { path = \"../builder\", features = [\"build\"] }\n", true);
        fs::remove_file(fixture.0.join("b/src/lib.rs")).unwrap();
        fs::write(fixture.0.join("b/src/main.rs"), "fn main() {}\n").unwrap();
        let lock = Command::new(env!("CARGO"))
            .args(["generate-lockfile", "--offline"])
            .env("CARGO_HOME", fixture.0.join("cargo-home"))
            .env("RUSTC", Path::new(env!("CARGO")).with_file_name("rustc"))
            .current_dir(&fixture.0)
            .output()
            .unwrap();
        assert!(
            lock.status.success(),
            "{}",
            String::from_utf8_lossy(&lock.stderr)
        );
        let (workspace, members) = crate::manifest::SourceWorkspace::load_compilation(
            &fixture.0,
            None,
            &crate::manifest::PackageSelection {
                workspace: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            members
                .iter()
                .filter(|member| member.build_script.is_some())
                .all(|member| member
                    .dependencies
                    .iter()
                    .any(|dependency| dependency.kind == DependencyKind::Build))
        );
        let cfg = CfgSet::parse("unix\n").unwrap();
        let options = Options {
            resolver: members[0].resolver,
            incompatible_rust_versions: None,
            rust_versions: vec![Version::parse("1.99.0").unwrap()],
            package_limit: crate::policy::PackageLimit::with_max(16),
            max_depth: None,
        };
        let mut catalog = Catalog::default();
        let complete = crate::resolver::workspace::resolve_complete_workspace(
            &workspace,
            &mut catalog,
            &options,
            &[],
            &mut |_, _, _| Ok(()),
        )
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
                host_triple: "x86_64-unknown-linux-gnu",
                host_cfg: &cfg,
                target_triple: "x86_64-unknown-linux-gnu",
                target_cfg: &cfg,
            },
        )
        .unwrap();
        let manifests = resolution
            .packages
            .iter()
            .map(|package| (package.key.clone(), package.local_manifest.clone().unwrap()))
            .collect::<BTreeMap<_, _>>();
        let selected = resolution
            .packages
            .iter()
            .map(|package| package.key.clone())
            .collect::<Vec<_>>();
        for command in ["build", "check"] {
            let output = Command::new(env!("CARGO"))
                .args([
                    "-Z",
                    "unstable-options",
                    command,
                    "--unit-graph",
                    "--offline",
                    "--workspace",
                    "--target",
                    "x86_64-unknown-linux-gnu",
                ])
                .env("CARGO_HOME", fixture.0.join("cargo-home"))
                .env("RUSTC", Path::new(env!("CARGO")).with_file_name("rustc"))
                .current_dir(&fixture.0)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let cargo: Value = serde_json::from_slice(&output.stdout).unwrap();
            let units = cargo["units"].as_array().unwrap();
            let cargo_nodes = units
                .iter()
                .map(|unit| {
                    (
                        unit["pkg_id"]
                            .as_str()
                            .unwrap()
                            .split('#')
                            .next()
                            .unwrap()
                            .rsplit('/')
                            .next()
                            .unwrap()
                            .to_owned(),
                        unit["target"]["kind"][0].as_str().unwrap().to_owned(),
                        unit["mode"].as_str().unwrap().to_owned(),
                        unit["platform"].as_str().is_some(),
                    )
                })
                .collect::<Vec<_>>();
            let graph = workspace_units(
                &resolution,
                &manifests,
                &selected,
                command == "check",
                true,
                None,
                false,
            )
            .unwrap();
            let node = |key: &UnitKey| {
                (
                    key.package.name.clone(),
                    match key.kind {
                        UnitKind::Library => "lib",
                        UnitKind::Binary => "bin",
                        UnitKind::BuildScriptCompile | UnitKind::BuildScriptRun => "custom-build",
                        _ => panic!("unexpected scripted member unit"),
                    }
                    .to_owned(),
                    if key.kind == UnitKind::BuildScriptRun {
                        "run-custom-build"
                    } else if key.mode == UnitMode::Check {
                        "check"
                    } else {
                        "build"
                    }
                    .to_owned(),
                    key.compile_kind == CompileKind::Target,
                )
            };
            assert_eq!(
                cargo_nodes.iter().cloned().collect::<BTreeSet<_>>(),
                graph.units.keys().map(node).collect()
            );
            let cargo_edges = units
                .iter()
                .enumerate()
                .flat_map(|(parent, unit)| {
                    let nodes = &cargo_nodes;
                    unit["dependencies"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(move |edge| {
                            (
                                nodes[parent].clone(),
                                nodes[edge["index"].as_u64().unwrap() as usize].clone(),
                            )
                        })
                })
                .collect::<BTreeSet<_>>();
            let edges = graph
                .units
                .values()
                .flat_map(|unit| {
                    unit.dependencies
                        .iter()
                        .map(|edge| (node(&unit.key), node(&edge.unit)))
                })
                .collect::<BTreeSet<_>>();
            assert_eq!(cargo_edges, edges);
            for unit in graph.units.values() {
                let index = cargo_nodes
                    .iter()
                    .position(|candidate| *candidate == node(&unit.key))
                    .unwrap();
                assert_eq!(
                    units[index]["features"],
                    serde_json::json!(unit.key.features)
                );
            }
        }
    }

    #[test]
    fn workspace_harness_graph_matches_cargo_with_legal_dev_cycle() {
        let fixture = Fixture::new();
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[workspace]\nmembers = [\"a\", \"b\", \"helper\", \"derive\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        fixture.package("helper", "[package]\nname = \"helper\"\nversion = \"1.0.0\"\nedition = \"2024\"\n[lib]\ntest = false\nbench = false\ndoctest = false\n[features]\nbuild = []\nnormal = []\n", false);
        fixture.package("a", "[package]\nname = \"a\"\nversion = \"1.0.0\"\nedition = \"2024\"\n[lib]\ndoctest = false\n[features]\nnormal = []\n[dependencies]\nderive = { path = \"../derive\" }\nhelper = { path = \"../helper\", features = [\"normal\"] }\n[dev-dependencies]\nb = { path = \"../b\", features = [\"dev\"] }\n[build-dependencies]\nhelper = { path = \"../helper\", features = [\"build\"] }\n", true);
        fixture.package("b", "[package]\nname = \"b\"\nversion = \"1.0.0\"\nedition = \"2024\"\n[lib]\ndoctest = false\n[features]\ndev = []\n[dependencies]\na = { path = \"../a\", features = [\"normal\"] }\n", false);
        fixture.package("derive", "[package]\nname = \"derive\"\nversion = \"1.0.0\"\nedition = \"2024\"\n[lib]\nproc-macro = true\ndoctest = false\n[features]\ndefault = [\"harness\"]\nharness = []\n[dependencies]\nhelper = { path = \"../helper\", features = [\"normal\"] }\n[build-dependencies]\nhelper = { path = \"../helper\", features = [\"build\"] }\n", true);
        fs::write(fixture.0.join("a/src/main.rs"), "fn main() {}\n").unwrap();
        fs::create_dir(fixture.0.join("a/tests")).unwrap();
        fs::write(
            fixture.0.join("a/tests/integration.rs"),
            "#[test]\nfn integration() {}\n",
        )
        .unwrap();
        fs::write(
            fixture.0.join("a/tests/disabled.rs"),
            "#[test] fn disabled() {}\n",
        )
        .unwrap();
        let manifest_path = fixture.0.join("a/Cargo.toml");
        let manifest_text = fs::read_to_string(&manifest_path).unwrap();
        fs::write(&manifest_path, format!("{manifest_text}\n[[test]]\nname = \"disabled\"\ntest = false\nrequired-features = [\"normal\"]\n")).unwrap();
        let workspace = crate::manifest::SourceWorkspace::load(&fixture.0, None).unwrap();
        let options = Options {
            resolver: crate::manifest::Resolver::V2,
            incompatible_rust_versions: None,
            rust_versions: vec![Version::parse("1.99.0").unwrap()],
            package_limit: crate::policy::PackageLimit::with_max(16),
            max_depth: None,
        };
        let mut catalog = Catalog::default();
        let complete = crate::resolver::workspace::resolve_complete_workspace(
            &workspace,
            &mut catalog,
            &options,
            &[],
            &mut |_, _, _| Ok(()),
        )
        .unwrap();
        let requests = crate::resolver::workspace::features::member_requests(
            &workspace,
            &workspace
                .packages
                .iter()
                .map(|member| member.root.clone())
                .collect(),
            &crate::cli::FeatureSelection::default(),
            true,
        )
        .unwrap();
        let cfg = CfgSet::parse("unix\n").unwrap();
        let resolution = crate::resolver::workspace::resolve_selected_workspace(
            &complete,
            &catalog,
            &options,
            &requests,
            TargetSelection {
                host_triple: "x86_64-unknown-linux-gnu",
                host_cfg: &cfg,
                target_triple: "x86_64-unknown-linux-gnu",
                target_cfg: &cfg,
            },
        )
        .unwrap();
        let manifests = resolution
            .packages
            .iter()
            .map(|package| (package.key.clone(), package.local_manifest.clone().unwrap()))
            .collect();
        let selected = resolution
            .packages
            .iter()
            .map(|package| package.key.clone())
            .collect::<Vec<_>>();
        let options = PlanOptions {
            workspace_root: &fixture.0,
            release: false,
            test_profile: false,
            panic_abort: false,
            dev_profile: &crate::manifest::DevProfile::default(),
            release_profile: &ReleaseProfile::default(),
            rustc: &toolchain(),
            logical_target: None,
            rustflags: &[],
        };
        assert!(
            workspace_test_units(
                &resolution,
                &manifests,
                &selected,
                &options,
                Some("missing")
            )
            .is_err()
        );
        for (integration_name, logical_target, checking, opt_level) in [
            (None, None, false, "0"),
            (None, Some("x86_64-unknown-linux-gnu"), false, "0"),
            (
                Some("integration"),
                Some("x86_64-unknown-linux-gnu"),
                false,
                "0",
            ),
            (
                Some("disabled"),
                Some("x86_64-unknown-linux-gnu"),
                false,
                "0",
            ),
            (None, None, true, "0"),
            (None, Some("x86_64-unknown-linux-gnu"), true, "0"),
            (
                Some("integration"),
                Some("x86_64-unknown-linux-gnu"),
                true,
                "0",
            ),
            (None, None, false, "2"),
            (None, Some("x86_64-unknown-linux-gnu"), false, "2"),
            (None, None, true, "2"),
            (None, Some("x86_64-unknown-linux-gnu"), true, "2"),
        ] {
            let original = fs::read_to_string(fixture.0.join("Cargo.toml")).unwrap();
            let workspace_text = original.split("[profile.dev]").next().unwrap();
            fs::write(
                fixture.0.join("Cargo.toml"),
                format!("{workspace_text}\n[profile.dev]\nopt-level = {opt_level}\n"),
            )
            .unwrap();
            let dev_profile = crate::manifest::DevProfile {
                opt_level,
                ..crate::manifest::DevProfile::default()
            };
            let options = PlanOptions {
                dev_profile: &dev_profile,
                logical_target,
                ..options
            };
            let graph = if checking {
                workspace_check_units(
                    &resolution,
                    &manifests,
                    &selected,
                    &CheckTargetSelection {
                        normal: integration_name.is_none(),
                        binaries: true,
                        binary_name: None,
                        harnesses: integration_name.is_none(),
                        integrations: true,
                        integration_name,
                        examples: false,
                        benches: false,
                    },
                    &options,
                )
            } else {
                workspace_test_units(
                    &resolution,
                    &manifests,
                    &selected,
                    &options,
                    integration_name,
                )
            }
            .unwrap();
            let plan = plan_dependency_units(&graph, &manifests, &options).unwrap();
            let mut command = Command::new(env!("CARGO"));
            command
                .args([
                    "-Z",
                    "unstable-options",
                    if checking { "check" } else { "test" },
                    "--unit-graph",
                    "--workspace",
                    "--offline",
                ])
                .env("CARGO_HOME", fixture.0.join("cargo-home"))
                .env("RUSTC", Path::new(env!("CARGO")).with_file_name("rustc"))
                .current_dir(&fixture.0);
            if checking && integration_name.is_none() {
                command.arg("--all-targets");
            }
            if let Some(target) = logical_target {
                command.args(["--target", target]);
            }
            if let Some(name) = integration_name {
                command.args(["--test", name]);
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let cargo: Value = serde_json::from_slice(&output.stdout).unwrap();
            let units = cargo["units"].as_array().unwrap();
            let cargo_nodes = units
                .iter()
                .map(|unit| {
                    (
                        unit["pkg_id"]
                            .as_str()
                            .unwrap()
                            .split('#')
                            .next()
                            .unwrap()
                            .rsplit('/')
                            .next()
                            .unwrap()
                            .to_owned(),
                        unit["target"]["kind"][0].as_str().unwrap().to_owned(),
                        unit["target"]["name"].as_str().unwrap().to_owned(),
                        unit["mode"].as_str().unwrap().to_owned(),
                        unit["platform"].is_string(),
                        unit["profile"]["opt_level"].as_str().unwrap().to_owned(),
                        unit["features"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|feature| feature.as_str().unwrap().to_owned())
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>();
            let node = |key: &UnitKey| {
                (
                    key.package.name.clone(),
                    match key.kind {
                        UnitKind::Library | UnitKind::LibraryHarness => {
                            if manifests[&key.package].library.as_ref().unwrap().proc_macro {
                                "proc-macro"
                            } else {
                                "lib"
                            }
                        }
                        UnitKind::Binary | UnitKind::BinaryHarness => "bin",
                        UnitKind::IntegrationHarness => "test",
                        UnitKind::Example => "example",
                        UnitKind::Bench => "bench",
                        UnitKind::ProcMacro => "proc-macro",
                        UnitKind::BuildScriptCompile | UnitKind::BuildScriptRun => "custom-build",
                    }
                    .to_owned(),
                    key.target.clone().unwrap_or_else(|| {
                        if matches!(
                            key.kind,
                            UnitKind::BuildScriptCompile | UnitKind::BuildScriptRun
                        ) {
                            "build-script-build".to_owned()
                        } else {
                            key.package.name.clone()
                        }
                    }),
                    match key.kind {
                        UnitKind::BuildScriptRun => "run-custom-build",
                        _ if matches!(key.mode, UnitMode::Check | UnitMode::CheckTest) => "check",
                        _ if key.mode == UnitMode::Test => "test",
                        _ => "build",
                    }
                    .to_owned(),
                    key.compile_kind == CompileKind::Target && logical_target.is_some(),
                    plan.units[key].settings.profile.opt_level.to_owned(),
                    key.features.iter().cloned().collect::<Vec<_>>(),
                )
            };
            assert_eq!(
                cargo_nodes.iter().cloned().collect::<BTreeSet<_>>(),
                plan.units.keys().map(node).collect()
            );
            let cargo_edges = units
                .iter()
                .enumerate()
                .flat_map(|(parent, unit)| {
                    let nodes = &cargo_nodes;
                    unit["dependencies"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(move |edge| {
                            (
                                nodes[parent].clone(),
                                nodes[edge["index"].as_u64().unwrap() as usize].clone(),
                                edge["extern_crate_name"].as_str().unwrap().to_owned(),
                            )
                        })
                })
                .collect::<BTreeSet<_>>();
            let edges = plan
                .units
                .values()
                .flat_map(|unit| {
                    unit.unit.dependencies.iter().map(|edge| {
                        (
                            node(&unit.unit.key),
                            node(&edge.unit),
                            edge.alias.clone().unwrap_or_else(|| {
                                edge.unit
                                    .target
                                    .as_deref()
                                    .unwrap_or("build-script-build")
                                    .replace('-', "_")
                            }),
                        )
                    })
                })
                .collect::<BTreeSet<_>>();
            assert_eq!(cargo_edges, edges);
            for (key, unit) in &plan.units {
                let reference = &units[cargo_nodes
                    .iter()
                    .position(|candidate| *candidate == node(key))
                    .unwrap()];
                assert_eq!(reference["features"], serde_json::json!(key.features));
                assert_eq!(
                    reference["profile"]["opt_level"],
                    unit.settings.profile.opt_level
                );
                let debug = match unit.settings.profile.debuginfo {
                    CargoDebugInfo::None => 0,
                    CargoDebugInfo::Full => 2,
                    other => panic!("unexpected debug setting {other:?}"),
                };
                assert_eq!(reference["profile"]["debuginfo"], debug);
                assert_eq!(reference["profile"]["panic"], "unwind");
                assert_eq!(unit.settings.profile.panic, CargoPanicStrategy::Unwind);
            }
        }
    }

    #[test]
    fn creates_distinct_host_target_and_build_script_units_in_dependency_order() {
        let fixture = Fixture::new();
        fixture.package(
            "shared",
            "[package]\nname = \"shared\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\
             [features]\ntarget = []\nhost = []\n",
            false,
        );
        fixture.package(
            "a",
            "[package]\nname = \"a\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\
             build = \"build.rs\"\n\
             [dependencies]\n\
             shared = { path = \"../shared\", features = [\"target\"] }\n\
             [build-dependencies]\n\
             shared-build = { package = \"shared\", path = \"../shared\", features = [\"host\"] }\n",
            true,
        );
        let root = Manifest::parse(
            &fixture.0,
            &fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             resolver = \"1\"\n[dependencies]\na = { path = \"a\" }\n",
        )
        .unwrap();
        let cfg = CfgSet::parse("unix\n").unwrap();
        let resolution = resolve_selected(
            &root,
            &Catalog::default(),
            &Options {
                resolver: root.resolver,
                incompatible_rust_versions: None,
                rust_versions: vec![Version::parse("1.98.0").unwrap()],
                package_limit: crate::policy::PackageLimit::with_max(16),
                max_depth: Some(8),
            },
            &[],
            TargetSelection {
                target_triple: "x86_64-unknown-motor",
                target_cfg: &cfg,
                host_triple: "x86_64-unknown-linux-gnu",
                host_cfg: &cfg,
            },
        )
        .unwrap();
        let manifests = resolution
            .packages
            .iter()
            .map(|package| (package.key.clone(), package.local_manifest.clone().unwrap()))
            .collect();
        let graph = dependency_units(&resolution, &manifests).unwrap();
        assert_eq!(graph.units.len(), 5);

        let shared = graph
            .units
            .keys()
            .filter(|key| key.package.name == "shared")
            .collect::<Vec<_>>();
        assert_eq!(shared.len(), 2);
        assert_eq!(
            shared
                .iter()
                .map(|key| key.compile_kind)
                .collect::<BTreeSet<_>>(),
            [CompileKind::Target, CompileKind::Host].into()
        );
        assert!(
            shared
                .iter()
                .all(|key| key.features == BTreeSet::from(["host".to_owned(), "target".to_owned()]))
        );

        let a_library = graph
            .units
            .values()
            .find(|unit| unit.key.package.name == "a" && unit.key.kind == UnitKind::Library)
            .unwrap();
        assert!(a_library.dependencies.iter().any(|edge| {
            edge.kind == UnitEdgeKind::RustDependency
                && edge.alias.as_deref() == Some("shared")
                && edge.unit.compile_kind == CompileKind::Target
        }));
        assert!(a_library.dependencies.iter().any(|edge| {
            edge.kind == UnitEdgeKind::BuildScriptOutput
                && edge.unit.kind == UnitKind::BuildScriptRun
        }));
        let compile = graph
            .units
            .values()
            .find(|unit| {
                unit.key.package.name == "a" && unit.key.kind == UnitKind::BuildScriptCompile
            })
            .unwrap();
        assert!(compile.dependencies.iter().any(|edge| {
            edge.kind == UnitEdgeKind::RustDependency
                && edge.alias.as_deref() == Some("shared-build")
                && edge.unit.compile_kind == CompileKind::Host
        }));

        let positions = graph
            .order
            .iter()
            .enumerate()
            .map(|(index, key)| (key.clone(), index))
            .collect::<BTreeMap<_, _>>();
        for unit in graph.units.values() {
            for dependency in &unit.dependencies {
                assert!(positions[&dependency.unit] < positions[&unit.key]);
            }
        }

        let release_profile = ReleaseProfile {
            panic_abort: true,
            lto: ManifestLto::Fat,
            strip: ManifestStrip::Symbols,
            codegen_units: Some(1),
            ..ReleaseProfile::default()
        };
        let rustflags = vec!["-Ctarget-cpu=x86-64-v3".to_owned()];
        let plan = plan_dependency_units(
            &graph,
            &manifests,
            &PlanOptions {
                workspace_root: &fixture.0,
                release: true,
                test_profile: false,
                panic_abort: true,
                dev_profile: &crate::manifest::DevProfile::default(),
                release_profile: &release_profile,
                rustc: &toolchain(),
                logical_target: Some("x86_64-unknown-motor"),
                rustflags: &rustflags,
            },
        )
        .unwrap();
        assert_eq!(plan.order, graph.order);
        assert_eq!(plan.units.len(), graph.units.len());
        let shared_target = plan
            .units
            .values()
            .find(|unit| {
                unit.unit.key.package.name == "shared"
                    && unit.unit.key.compile_kind == CompileKind::Target
            })
            .unwrap();
        assert_eq!(shared_target.settings.profile.opt_level, "3");
        assert_eq!(
            shared_target.settings.profile.panic,
            CargoPanicStrategy::Abort
        );
        assert_eq!(shared_target.settings.lto, CargoUnitLto::OnlyBitcode);
        assert_eq!(
            shared_target.settings.logical_target.as_deref(),
            Some("x86_64-unknown-motor")
        );
        assert_eq!(shared_target.settings.rustflags, rustflags);

        let shared_host = plan
            .units
            .values()
            .find(|unit| {
                unit.unit.key.package.name == "shared"
                    && unit.unit.key.compile_kind == CompileKind::Host
            })
            .unwrap();
        assert_eq!(shared_host.settings.profile.opt_level, "0");
        assert_eq!(
            shared_host.settings.profile.panic,
            CargoPanicStrategy::Unwind
        );
        assert_eq!(shared_host.settings.lto, CargoUnitLto::OnlyObject);
        assert_eq!(shared_host.settings.logical_target, None);
        assert!(shared_host.settings.rustflags.is_empty());

        let run = plan
            .units
            .values()
            .find(|unit| unit.unit.key.kind == UnitKind::BuildScriptRun)
            .unwrap();
        assert_eq!(run.settings.mode, CargoCompileMode::RunCustomBuild);
        assert_eq!(run.settings.profile.lto, CargoProfileLto::Bool(false));
        assert_eq!(run.settings.profile.strip, CargoStrip::Named("debuginfo"));
        for unit in plan.units.values() {
            assert!(!unit.identity.metadata.is_empty());
            assert!(unit.identity.extra_filename.starts_with('-'));
        }

        let dev = plan_dependency_units(
            &graph,
            &manifests,
            &PlanOptions {
                workspace_root: &fixture.0,
                release: false,
                test_profile: false,
                panic_abort: true,
                dev_profile: &crate::manifest::DevProfile::default(),
                release_profile: &ReleaseProfile::default(),
                rustc: &toolchain(),
                logical_target: None,
                rustflags: &rustflags,
            },
        )
        .unwrap();
        let shared_host = dev
            .units
            .values()
            .find(|unit| {
                unit.unit.key.package.name == "shared"
                    && unit.unit.key.compile_kind == CompileKind::Host
            })
            .unwrap();
        assert_eq!(shared_host.settings.profile.debuginfo, CargoDebugInfo::None);
        assert_eq!(
            shared_host.settings.profile.panic,
            CargoPanicStrategy::Unwind
        );
        assert_eq!(shared_host.settings.rustflags, rustflags);
        let shared_target = dev
            .units
            .values()
            .find(|unit| {
                unit.unit.key.package.name == "shared"
                    && unit.unit.key.compile_kind == CompileKind::Target
            })
            .unwrap();
        assert_eq!(
            shared_target.settings.profile.panic,
            CargoPanicStrategy::Abort
        );
        let compile = dev
            .units
            .values()
            .find(|unit| unit.unit.key.kind == UnitKind::BuildScriptCompile)
            .unwrap();
        assert_eq!(compile.settings.profile.debuginfo, CargoDebugInfo::None);
    }

    #[test]
    fn target_library_depends_on_host_proc_macro_unit() {
        let fixture = Fixture::new();
        fixture.package(
            "derive-example",
            "[package]\nname = \"derive-example\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\
             [lib]\nproc-macro = true\n",
            false,
        );
        fixture.package(
            "parent",
            "[package]\nname = \"parent\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\
             [dependencies]\nderive-example = { path = \"../derive-example\" }\n",
            false,
        );
        let root = Manifest::parse(
            &fixture.0,
            &fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             resolver = \"2\"\n[dependencies]\nparent = { path = \"parent\" }\n",
        )
        .unwrap();
        let cfg = CfgSet::parse("unix\n").unwrap();
        let resolution = resolve_selected(
            &root,
            &Catalog::default(),
            &Options {
                resolver: root.resolver,
                incompatible_rust_versions: None,
                rust_versions: vec![Version::parse("1.98.0").unwrap()],
                package_limit: crate::policy::PackageLimit::with_max(16),
                max_depth: Some(8),
            },
            &[],
            TargetSelection {
                target_triple: "x86_64-unknown-motor",
                target_cfg: &cfg,
                host_triple: "x86_64-unknown-linux-gnu",
                host_cfg: &cfg,
            },
        )
        .unwrap();
        let manifests = resolution
            .packages
            .iter()
            .map(|package| (package.key.clone(), package.local_manifest.clone().unwrap()))
            .collect();
        let graph = dependency_units(&resolution, &manifests).unwrap();
        let parent = graph
            .units
            .values()
            .find(|unit| {
                unit.key.package.name == "parent"
                    && unit.key.kind == UnitKind::Library
                    && unit.key.compile_kind == CompileKind::Target
            })
            .unwrap();
        assert!(parent.dependencies.iter().any(|edge| {
            edge.kind == UnitEdgeKind::RustDependency
                && edge.unit.package.name == "derive-example"
                && edge.unit.kind == UnitKind::ProcMacro
                && edge.unit.compile_kind == CompileKind::Host
        }));
    }

    #[test]
    fn renders_cargo_stable_path_source_identities() {
        assert_eq!(
            cargo_path_source(Path::new("/workspace"), Path::new("/workspace/dep")).unwrap(),
            "dep"
        );
        assert_eq!(
            cargo_path_source(Path::new("/workspace"), Path::new("/outside/a b#c%")).unwrap(),
            "file:///outside/a%20b%23c%25"
        );
    }

    #[test]
    fn registry_remap_uses_locked_content_identity() {
        let remap = SourceRemap::registry(
            Path::new("/workspace"),
            &[0xab; 32],
            Path::new("/repository/object/source"),
        )
        .unwrap();
        let logical = format!(".lorry/registry/sha256/{}/source", "ab".repeat(32));
        assert_eq!(remap.presented_root, PathBuf::from(&logical));
        assert_eq!(remap.logical_root, Path::new("/workspace").join(&logical));
        assert_eq!(
            remap.rustc_argument(),
            OsString::from(format!("/repository/object/source={logical}"))
        );
    }

    #[test]
    fn planned_build_script_graph_matches_the_cargo_release_oracle() {
        fn key(name: &str, version: &str) -> PackageKey {
            PackageKey {
                name: name.to_owned(),
                version: semver::Version::parse(version).unwrap(),
                source: PackageSourceKey::CratesIo,
            }
        }

        fn package(
            key: PackageKey,
            compile_kind: CompileKind,
            edges: Vec<ResolvedEdge>,
        ) -> ResolvedPackage {
            ResolvedPackage {
                key,
                source: ResolvedSource::CratesIo { checksum: [0; 32] },
                local_manifest: None,
                feature_sets: BTreeMap::new(),
                compile_kinds: [compile_kind].into(),
                target_features: BTreeSet::new(),
                host_features: BTreeSet::new(),
                lock_edges: edges.clone(),
                edges,
            }
        }

        let fixture = Fixture::new();
        fixture.package(
            "version_check",
            "[package]\nname = \"version_check\"\nversion = \"0.9.5\"\nedition = \"2015\"\n",
            false,
        );
        fixture.package(
            "typenum",
            "[package]\nname = \"typenum\"\nversion = \"1.20.0\"\nedition = \"2018\"\n",
            false,
        );
        fixture.package(
            "generic-array",
            "[package]\nname = \"generic-array\"\nversion = \"0.14.7\"\nedition = \"2015\"\n\
             build = \"build.rs\"\n\
             [dependencies]\ntypenum = \"=1.20.0\"\n\
             [build-dependencies]\nversion_check = \"=0.9.5\"\n",
            true,
        );
        let version_check = key("version_check", "0.9.5");
        let typenum = key("typenum", "1.20.0");
        let generic_array = key("generic-array", "0.14.7");
        let normal_edge = ResolvedEdge {
            dependency_index: 0,
            alias: "typenum".to_owned(),
            target: None,
            kind: DependencyKind::Normal,
            parent_compile_kind: Some(CompileKind::Target),
            compile_kind: CompileKind::Target,
            context: FeatureContext::Target("x86_64-unknown-linux-gnu".to_owned()),
            package: typenum.clone(),
        };
        let build_edge = ResolvedEdge {
            dependency_index: 1,
            alias: "version_check".to_owned(),
            target: None,
            kind: DependencyKind::Build,
            parent_compile_kind: Some(CompileKind::Target),
            compile_kind: CompileKind::Host,
            context: FeatureContext::Host,
            package: version_check.clone(),
        };
        let resolution = Resolution {
            root_edges: Vec::new(),
            packages: vec![
                package(version_check.clone(), CompileKind::Host, Vec::new()),
                package(typenum.clone(), CompileKind::Target, Vec::new()),
                package(
                    generic_array.clone(),
                    CompileKind::Target,
                    vec![normal_edge, build_edge],
                ),
            ],
        };
        let manifests = [
            version_check.clone(),
            typenum.clone(),
            generic_array.clone(),
        ]
        .into_iter()
        .map(|key| {
            let manifest = Manifest::load_path_dependency(&fixture.0.join(&key.name)).unwrap();
            (key, manifest)
        })
        .collect::<BTreeMap<_, _>>();
        let graph = dependency_units(&resolution, &manifests).unwrap();
        let plan = plan_dependency_units(
            &graph,
            &manifests,
            &PlanOptions {
                workspace_root: &fixture.0,
                release: true,
                test_profile: false,
                panic_abort: true,
                dev_profile: &crate::manifest::DevProfile::default(),
                release_profile: &ReleaseProfile {
                    panic_abort: true,
                    lto: ManifestLto::Fat,
                    strip: ManifestStrip::Symbols,
                    codegen_units: Some(1),
                    ..ReleaseProfile::default()
                },
                rustc: &toolchain(),
                logical_target: None,
                rustflags: &[],
            },
        )
        .unwrap();
        let identity = |package: &PackageKey, kind| {
            &plan
                .units
                .iter()
                .find(|(key, _)| key.package == *package && key.kind == kind)
                .unwrap()
                .1
                .identity
        };
        assert_eq!(
            identity(&version_check, UnitKind::Library).extra_filename,
            "-a52364eda26712a9"
        );
        assert_eq!(
            identity(&typenum, UnitKind::Library).extra_filename,
            "-3bece92618a1f233"
        );
        assert_eq!(
            identity(&generic_array, UnitKind::BuildScriptCompile).extra_filename,
            "-54bde9ff4b0e1354"
        );
        assert_eq!(
            identity(&generic_array, UnitKind::BuildScriptRun).extra_filename,
            "-6dae74b52cdc9822"
        );
        let generic = identity(&generic_array, UnitKind::Library);
        assert_eq!(generic.metadata, "b4888d1c786ef3d6");
        assert_eq!(generic.extra_filename, "-ff844e945f4f0d9d");
    }

    #[test]
    fn rejects_incomplete_manifest_sets_and_cycles() {
        let resolution = Resolution {
            root_edges: Vec::new(),
            packages: Vec::new(),
        };
        dependency_units(&resolution, &BTreeMap::new()).unwrap();

        let key = UnitKey {
            package: PackageKey {
                name: "cycle".to_owned(),
                version: Version::parse("1.0.0").unwrap(),
                source: crate::resolver::PackageSourceKey::Path(Path::new("/cycle").to_owned()),
            },
            kind: UnitKind::Library,
            mode: UnitMode::Build,
            target: None,
            compile_kind: CompileKind::Target,
            profile: ProfileContext::Normal,
            features: BTreeSet::new(),
        };
        let incomplete = Resolution {
            root_edges: Vec::new(),
            packages: vec![ResolvedPackage {
                key: key.package.clone(),
                source: crate::resolver::ResolvedSource::Path {
                    logical_root: Path::new("/cycle").to_owned(),
                    physical_root: Path::new("/cycle").to_owned(),
                    source_tree_sha256: [0; 32],
                    patched_crates_io: false,
                },
                local_manifest: None,
                feature_sets: BTreeMap::new(),
                compile_kinds: [CompileKind::Target].into(),
                target_features: BTreeSet::new(),
                host_features: BTreeSet::new(),
                edges: Vec::new(),
                lock_edges: Vec::new(),
            }],
        };
        assert!(
            dependency_units(&incomplete, &BTreeMap::new())
                .unwrap_err()
                .to_string()
                .contains("exactly one manifest")
        );

        let mut units = BTreeMap::from([(
            key.clone(),
            Unit {
                key: key.clone(),
                dependencies: BTreeSet::new(),
            },
        )]);
        add_edge(
            &mut units,
            &key,
            key.clone(),
            UnitEdgeKind::RustDependency,
            Some("cycle".to_owned()),
        )
        .unwrap();
        assert!(
            topological_order(&units)
                .unwrap_err()
                .to_string()
                .contains("cycle")
        );
    }
}
