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
use crate::manifest::{Lto as ManifestLto, Manifest, ReleaseProfile, Strip as ManifestStrip};
use crate::resolver::{
    CompileKind, FeatureContext, PackageKey, PackageSourceKey, Resolution, ResolvedPackage,
    selected_root_features,
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
    ProcMacro,
    BuildScriptCompile,
    BuildScriptRun,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProfileContext {
    Normal,
    Test,
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

    fn with_selected_check_mode(mut self, selected: &PackageKey) -> Result<Self> {
        let rekey = |mut key: UnitKey| {
            if &key.package == selected {
                key.mode = if key.mode == UnitMode::Test {
                    UnitMode::CheckTest
                } else {
                    UnitMode::Check
                };
            }
            key
        };
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
        if manifest.library.is_none() {
            return Err(Error::failure(format!(
                "dependency package `{} {}` has no supported library target",
                package.key.name, package.key.version
            )));
        }
        for compile_kind in &package.compile_kinds {
            let features = features_for(package, *compile_kind);
            let kind = library_unit_kind(manifest);
            let library = unit_key(package, kind, *compile_kind, &features);
            insert_unit(&mut units, library.clone());
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
                add_edge(
                    &mut units,
                    &library,
                    run,
                    UnitEdgeKind::BuildScriptOutput,
                    None,
                )?;
            }
        }
    }

    for package in &resolution.packages {
        let manifest = &manifests[&package.key];
        for edge in &package.edges {
            match edge.kind {
                DependencyKind::Normal => {
                    let parent_compile_kind = edge.parent_compile_kind.ok_or_else(|| {
                        Error::failure(format!(
                            "resolved edge from `{} {}` omitted its parent compilation context",
                            package.key.name, package.key.version
                        ))
                    })?;
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
                        Some(edge.alias.clone()),
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
                            Some(edge.alias.clone()),
                        )?;
                    }
                }
                DependencyKind::Dev => {
                    return Err(Error::failure(
                        "selected dependency unit graph contains a dev-dependency edge",
                    ));
                }
            }
        }
    }

    let order = topological_order(&units)?;
    Ok(UnitGraph { units, order })
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
    add_selected_normal_edges(graph, resolution, manifests, &key, false)?;
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
        key.kind = UnitKind::Binary;
        key.target = Some(target.name.clone());
        insert_unit(&mut graph.units, key.clone());
        add_selected_normal_edges(graph, resolution, manifests, &key, false)?;
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
        add_selected_normal_edges(graph, resolution, manifests, &key, false)?;
        harnesses.push(key);
    }
    for target in manifest.binaries.iter().filter(|target| target.test) {
        let mut key = selected_library_key(manifest)?;
        key.kind = UnitKind::BinaryHarness;
        key.mode = UnitMode::Test;
        key.target = Some(target.name.clone());
        insert_unit(&mut graph.units, key.clone());
        add_selected_normal_edges(graph, resolution, manifests, &key, false)?;
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
    for target in manifest
        .integration_tests
        .iter()
        .filter(|target| selected_name.is_none_or(|name| name == target.name))
    {
        let mut key =
            selected_library_key(manifest)?.with_profile(ProfileContext::Test, panic_abort);
        key.kind = UnitKind::IntegrationHarness;
        key.mode = UnitMode::Test;
        key.target = Some(target.name.clone());
        insert_unit(&mut graph.units, key.clone());
        add_selected_normal_edges(graph, resolution, manifests, &key, panic_abort)?;
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
            Some(edge.alias.clone()),
        )?;
    }
    Ok(())
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

    let mut planned: BTreeMap<UnitKey, PlannedUnit> = BTreeMap::new();
    for key in &graph.order {
        let unit = graph.units.get(key).ok_or_else(|| {
            Error::failure("dependency compilation order references an absent unit")
        })?;
        let manifest = manifests.get(&key.package).ok_or_else(|| {
            Error::failure(format!(
                "dependency compilation plan has no manifest for `{} {}`",
                key.package.name, key.package.version
            ))
        })?;
        validate_manifest_identity(&key.package, manifest)?;

        let settings = unit_settings(graph, key, options);
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
            UnitKind::Binary | UnitKind::BinaryHarness | UnitKind::IntegrationHarness
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
                    CargoTargetKind::Lib(vec![if key.kind == UnitKind::ProcMacro {
                        CargoCrateType::ProcMacro
                    } else {
                        CargoCrateType::Lib
                    }]),
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
                    CargoTargetKind::Lib(vec![CargoCrateType::Lib])
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

fn unit_settings(graph: &UnitGraph, key: &UnitKey, options: &PlanOptions<'_>) -> UnitSettings {
    let local = matches!(key.package.source, PackageSourceKey::Path(_));
    let mut profile = base_profile(
        options.release,
        options.release_profile,
        options.panic_abort,
        local,
        key.profile == ProfileContext::Test,
    );
    let for_host = key.uses_host_profile();
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
            && !shared_native_library(graph, &sharing_key, options.logical_target)
        {
            profile.debuginfo = CargoDebugInfo::None;
        }
    }
    if key.kind == UnitKind::BuildScriptRun {
        profile = run_build_profile(&profile);
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
        lto: unit_lto(key, options.release, options.release_profile.lto),
        logical_target,
        rustflags,
    }
}

fn base_profile(
    release: bool,
    configured: &ReleaseProfile,
    panic_abort: bool,
    local: bool,
    test_profile: bool,
) -> UnitProfile {
    if release {
        UnitProfile {
            opt_level: "3",
            lto: profile_lto(configured.lto),
            codegen_units: configured.codegen_units,
            debuginfo: CargoDebugInfo::None,
            debug_assertions: false,
            overflow_checks: false,
            incremental: false,
            panic: if panic_abort && !test_profile {
                CargoPanicStrategy::Abort
            } else {
                CargoPanicStrategy::Unwind
            },
            strip: profile_strip(configured.strip),
        }
    } else {
        UnitProfile {
            opt_level: "0",
            lto: CargoProfileLto::Bool(false),
            codegen_units: None,
            debuginfo: CargoDebugInfo::Full,
            debug_assertions: true,
            overflow_checks: true,
            incremental: local,
            panic: if panic_abort && !test_profile {
                CargoPanicStrategy::Abort
            } else {
                CargoPanicStrategy::Unwind
            },
            strip: CargoStrip::None,
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

fn shared_native_library(graph: &UnitGraph, key: &UnitKey, logical_target: Option<&str>) -> bool {
    key.kind == UnitKind::Library
        && key.compile_kind == CompileKind::Host
        && logical_target.is_none()
        && graph.units.contains_key(&UnitKey {
            compile_kind: CompileKind::Target,
            ..key.clone()
        })
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

fn profile_strip(strip: ManifestStrip) -> CargoStrip<'static> {
    match strip {
        ManifestStrip::None => CargoStrip::None,
        ManifestStrip::Debuginfo => CargoStrip::Named("debuginfo"),
        ManifestStrip::Symbols => CargoStrip::Named("symbols"),
    }
}

fn unit_lto(key: &UnitKey, release: bool, configured: ManifestLto) -> CargoUnitLto<'static> {
    if matches!(
        key.kind,
        UnitKind::LibraryHarness | UnitKind::BinaryHarness | UnitKind::IntegrationHarness
    ) {
        return root_lto(release, configured, RootTargetKind::Binary, true);
    }
    if key.kind == UnitKind::Binary {
        return root_lto(release, configured, RootTargetKind::Binary, false);
    }
    if !release || key.compile_kind == CompileKind::Host || key.kind != UnitKind::Library {
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
                rust_version: Version::parse("1.98.0").unwrap(),
                package_limit: crate::policy::PackageLimit::with_max(16),
                max_depth: 8,
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
                selected_package: Some(&selected.package),
                host_profile: Path::new("/target/debug"),
                target_profile: Path::new("/target/debug"),
                host_incremental: Path::new("/incremental/host"),
                target_incremental: Path::new("/incremental/target"),
                physical_target: None,
                host_linker: None,
                target_linker: None,
                integration_binaries: None,
                integration_temp_dir: None,
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
                selected_package: Some(&selected.package),
                host_profile: Path::new("/target/debug"),
                target_profile: Path::new("/target/debug"),
                host_incremental: Path::new("/incremental/host"),
                target_incremental: Path::new("/incremental/target"),
                physical_target: None,
                host_linker: None,
                target_linker: None,
                integration_binaries: None,
                integration_temp_dir: None,
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
                rust_version: Version::parse("1.99.0").unwrap(),
                package_limit: crate::policy::PackageLimit::with_max(16),
                max_depth: 8,
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
        let lorry_roots = std::iter::once(library)
            .chain(binaries)
            .map(|key| lorry_node(&key))
            .collect::<BTreeSet<_>>();
        assert_eq!(cargo_roots, lorry_roots);
        for (key, planned) in &plan.units {
            let node = lorry_node(key);
            let unit = &units[cargo_nodes
                .iter()
                .position(|candidate| *candidate == node)
                .unwrap()];
            let profile = &unit["profile"];
            assert_eq!(unit["mode"], "build");
            assert!(unit["platform"].is_null());
            assert_eq!(unit["features"], serde_json::json!([]));
            assert_eq!(profile["name"], "dev");
            assert_eq!(profile["opt_level"], planned.settings.profile.opt_level);
            assert_eq!(planned.settings.mode, CargoCompileMode::Build);
            assert_eq!(planned.settings.profile.lto, CargoProfileLto::Bool(false));
            assert_eq!(profile["lto"], "false");
            assert!(profile["codegen_backend"].is_null());
            assert!(profile["codegen_units"].is_null());
            assert_eq!(profile["debuginfo"], 2);
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
            assert_eq!(planned.settings.profile.strip, CargoStrip::None);
            assert_eq!(profile["strip"], serde_json::json!({ "deferred": "None" }));
            assert_eq!(profile["rpath"], false);
            assert!(planned.settings.rustflags.is_empty());
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
                rust_version: Version::parse("1.98.0").unwrap(),
                package_limit: crate::policy::PackageLimit::with_max(16),
                max_depth: 8,
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
        assert_eq!(shared_host.settings.profile.debuginfo, CargoDebugInfo::Full);
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
                rust_version: Version::parse("1.98.0").unwrap(),
                package_limit: crate::policy::PackageLimit::with_max(16),
                max_depth: 8,
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
                release_profile: &ReleaseProfile {
                    panic_abort: true,
                    lto: ManifestLto::Fat,
                    strip: ManifestStrip::Symbols,
                    codegen_units: Some(1),
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
