#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use crate::diagnostic::{Error, Result};
use crate::manifest::Manifest;
use crate::resolver::{CompileKind, FeatureContext, PackageKey, Resolution, ResolvedPackage};
use crate::sparse::DependencyKind;

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
    use crate::manifest::Manifest;
    use crate::resolver::{Catalog, Options, TargetSelection, resolve_selected};
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
