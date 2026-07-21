#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::diagnostic::{Error, Result};
use crate::identity::{
    CargoCompileMode, CargoCrateType, CargoDebugInfo, CargoPanicStrategy, CargoProfile,
    CargoProfileLto, CargoSource, CargoStrip, CargoTargetKind, CargoUnitIdentityInput,
    CargoUnitLto, Identity, cargo_unit_identity,
};
use crate::manifest::{Lto as ManifestLto, Manifest, ReleaseProfile, Strip as ManifestStrip};
use crate::resolver::{
    CompileKind, FeatureContext, PackageKey, PackageSourceKey, Resolution, ResolvedPackage,
};
use crate::sparse::DependencyKind;
use crate::toolchain::Toolchain;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum UnitKind {
    Library,
    BuildScriptCompile,
    BuildScriptRun,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnitKey {
    pub package: PackageKey,
    pub kind: UnitKind,
    pub compile_kind: CompileKind,
    pub features: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum UnitEdgeKind {
    RustDependency,
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
    pub release_profile: &'a ReleaseProfile,
    pub rustc: &'a Toolchain,
    /// `None` is a native Linux build. Native Motor passes its normalized
    /// explicit Motor target identity here.
    pub logical_target: Option<&'a str>,
    pub rustflags: &'a [String],
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
            let library = unit_key(package, UnitKind::Library, *compile_kind, &features);
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
                    let parent = unit_key(
                        package,
                        UnitKind::Library,
                        edge.compile_kind,
                        &features_for(package, edge.compile_kind),
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
                        UnitKind::Library,
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
                        UnitKind::Library,
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

pub fn plan_dependency_units(
    graph: &UnitGraph,
    manifests: &BTreeMap<PackageKey, Manifest>,
    options: &PlanOptions<'_>,
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
            PackageSourceKey::Path(root) => {
                source_value = cargo_path_source(options.workspace_root, root)?;
                CargoSource::Path(&source_value)
            }
        };
        let features = key.features.iter().cloned().collect::<Vec<_>>();
        let dependencies = unit
            .dependencies
            .iter()
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
            UnitKind::Library => {
                let library = manifest.library.as_ref().ok_or_else(|| {
                    Error::failure(format!(
                        "dependency compilation unit for `{} {}` has no library target",
                        key.package.name, key.package.version
                    ))
                })?;
                (
                    library.name.as_str(),
                    CargoTargetKind::Lib(vec![CargoCrateType::Lib]),
                )
            }
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
        local,
        options.test_profile,
    );
    let for_host =
        key.kind == UnitKind::BuildScriptCompile || key.compile_kind == CompileKind::Host;
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
        mode: if key.kind == UnitKind::BuildScriptRun {
            CargoCompileMode::RunCustomBuild
        } else {
            CargoCompileMode::Build
        },
        lto: unit_lto(key, options.release, options.release_profile.lto),
        logical_target,
        rustflags,
    }
}

fn base_profile(
    release: bool,
    configured: &ReleaseProfile,
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
            panic: if configured.panic_abort && !test_profile {
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
            panic: CargoPanicStrategy::Unwind,
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
        compile_kind,
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
    use crate::config::CargoCompat;
    use crate::manifest::Manifest;
    use crate::resolver::{
        Catalog, Options, ResolvedEdge, ResolvedSource, TargetSelection, resolve_selected,
    };
    use crate::toolchain::CfgSet;
    use semver::Version;
    use std::fs;
    use std::path::{Path, PathBuf};
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
                max_packages: 16,
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
        assert_eq!(shared_host.settings.rustflags, rustflags);
        let compile = dev
            .units
            .values()
            .find(|unit| unit.unit.key.kind == UnitKind::BuildScriptCompile)
            .unwrap();
        assert_eq!(compile.settings.profile.debuginfo, CargoDebugInfo::None);
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
            kind: DependencyKind::Normal,
            compile_kind: CompileKind::Target,
            context: FeatureContext::Target("x86_64-unknown-linux-gnu".to_owned()),
            package: typenum.clone(),
        };
        let build_edge = ResolvedEdge {
            dependency_index: 1,
            alias: "version_check".to_owned(),
            kind: DependencyKind::Build,
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
            compile_kind: CompileKind::Target,
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
                    required_patch: None,
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
