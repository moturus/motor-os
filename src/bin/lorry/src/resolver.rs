#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use semver::Version;

use crate::config::IncompatibleRustVersions;
use crate::diagnostic::{Error, Result};
use crate::hash::decode_hex;
use crate::manifest::{DependencySource, Lockfile, Manifest, Resolver as ResolverVersion};
use crate::sparse::{Dependency, DependencyKind, Record};

#[derive(Clone, Debug, Default)]
pub struct Catalog {
    records: BTreeMap<String, Vec<Record>>,
}

impl Catalog {
    pub fn insert(&mut self, record: Record) -> Result<()> {
        let records = self.records.entry(record.name.clone()).or_default();
        if records
            .iter()
            .any(|existing| same_semver_identity(&existing.version, &record.version))
        {
            return Err(Error::failure(format!(
                "sparse catalog contains duplicate package version `{} {}`",
                record.name, record.version
            )));
        }
        records.push(record);
        records.sort_unstable_by(|left, right| right.version.cmp(&left.version));
        Ok(())
    }

    pub fn records(&self, name: &str) -> &[Record] {
        self.records.get(name).map(Vec::as_slice).unwrap_or(&[])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedPreference {
    pub name: String,
    pub version: Version,
    pub checksum: [u8; 32],
}

impl LockedPreference {
    pub fn from_lockfile(lock: Option<&Lockfile>) -> Result<Vec<Self>> {
        let mut preferences = Vec::new();
        for package in lock.into_iter().flat_map(|lock| &lock.packages) {
            let (Some(source), Some(checksum)) = (&package.source, &package.checksum) else {
                continue;
            };
            if source != "registry+https://github.com/rust-lang/crates.io-index" {
                continue;
            }
            let version = Version::parse(&package.version.original).map_err(|error| {
                Error::failure(format!(
                    "invalid locked version `{} {}`: {error}",
                    package.name, package.version.original
                ))
            })?;
            let checksum = decode_hex(checksum).map_err(|error| {
                Error::failure(format!(
                    "invalid locked checksum for `{} {version}`: {error}",
                    package.name
                ))
            })?;
            preferences.push(Self {
                name: package.name.clone(),
                version,
                checksum,
            });
        }
        Ok(preferences)
    }
}

#[derive(Clone, Debug)]
pub struct Options {
    pub resolver: ResolverVersion,
    pub incompatible_rust_versions: Option<IncompatibleRustVersions>,
    pub rust_version: Version,
    pub max_packages: u64,
    pub max_depth: u64,
}

impl Options {
    fn rust_policy(&self) -> IncompatibleRustVersions {
        self.incompatible_rust_versions
            .unwrap_or(match self.resolver {
                ResolverVersion::V3 => IncompatibleRustVersions::Fallback,
                ResolverVersion::V1 | ResolverVersion::V2 => IncompatibleRustVersions::Allow,
            })
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FeatureContext {
    Unified,
    Target(String),
    Host,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PackageKey {
    pub name: String,
    pub version: Version,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedEdge {
    pub dependency_index: usize,
    pub context: FeatureContext,
    pub package: PackageKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedPackage {
    pub key: PackageKey,
    pub checksum: [u8; 32],
    pub feature_sets: BTreeMap<FeatureContext, BTreeSet<String>>,
    pub target_features: BTreeSet<String>,
    pub host_features: BTreeSet<String>,
    pub edges: Vec<ResolvedEdge>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Resolution {
    pub packages: Vec<ResolvedPackage>,
}

pub fn resolve(
    manifest: &Manifest,
    catalog: &Catalog,
    options: &Options,
    locked: &[LockedPreference],
) -> Result<Resolution> {
    validate_locked_checksums(catalog, locked)?;
    let requirements = root_requirements(manifest)?;
    let mut queue = VecDeque::new();
    for requirement in requirements {
        queue.push_back(Event {
            parent: None,
            dependency_index: requirement.index,
            context: normalize_context(
                options.resolver,
                FeatureContext::Target(requirement.dependency.target.clone().unwrap_or_default()),
            ),
            dependency: requirement.dependency,
            depth: 1,
            ancestors: BTreeSet::new(),
        });
    }
    let state = solve(State::default(), queue, catalog, options, locked).map_err(|failure| {
        Error::failure(format!("dependency resolution failed: {}", failure.message))
    })?;
    Ok(state.into_resolution())
}

#[derive(Clone)]
struct RootRequirement {
    index: usize,
    dependency: Dependency,
}

fn root_requirements(manifest: &Manifest) -> Result<Vec<RootRequirement>> {
    let mut enabled = BTreeSet::new();
    for (index, dependency) in manifest.dependencies.iter().enumerate() {
        if !dependency.optional {
            enabled.insert(index);
        }
    }

    let namespaced = manifest
        .features
        .values()
        .flatten()
        .filter_map(|reference| reference.strip_prefix("dep:"))
        .collect::<BTreeSet<_>>();
    let mut active = manifest.features.keys().cloned().collect::<BTreeSet<_>>();
    for dependency in &manifest.dependencies {
        if dependency.optional && !namespaced.contains(dependency.alias.as_str()) {
            active.insert(dependency.alias.clone());
        }
    }

    let mut expanded = BTreeSet::new();
    let mut dependency_features: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    while let Some(feature) = active
        .iter()
        .find(|feature| !expanded.contains(*feature))
        .cloned()
    {
        expanded.insert(feature.clone());
        if let Some(references) = manifest.features.get(&feature) {
            for reference in references {
                expand_root_reference(
                    manifest,
                    reference,
                    &mut active,
                    &mut enabled,
                    &mut dependency_features,
                )?;
            }
        } else {
            enable_root_alias(manifest, &feature, &mut enabled)?;
        }
    }

    let weak = manifest
        .features
        .iter()
        .filter(|(feature, _)| active.contains(*feature))
        .flat_map(|(_, references)| references)
        .filter_map(|reference| {
            let (dependency, feature) = reference.split_once('/')?;
            dependency
                .strip_suffix('?')
                .map(|dependency| (dependency, feature))
        })
        .collect::<Vec<_>>();
    for (dependency, feature) in weak {
        if manifest
            .dependencies
            .iter()
            .enumerate()
            .any(|(index, value)| value.alias == dependency && enabled.contains(&index))
        {
            dependency_features
                .entry(dependency.to_owned())
                .or_default()
                .insert(feature.to_owned());
        }
    }

    let mut output = Vec::new();
    for (index, dependency) in manifest.dependencies.iter().enumerate() {
        if !enabled.contains(&index) || !matches!(dependency.source, DependencySource::CratesIo) {
            continue;
        }
        let mut features = dependency.features.clone();
        if let Some(additional) = dependency_features.get(&dependency.alias) {
            for feature in additional {
                if !features.contains(feature) {
                    features.push(feature.clone());
                }
            }
        }
        output.push(RootRequirement {
            index,
            dependency: Dependency {
                alias: dependency.alias.clone(),
                package: dependency.package.clone(),
                requirement: dependency.requirement.clone(),
                features,
                optional: false,
                default_features: dependency.default_features,
                target: dependency.target.clone(),
                kind: DependencyKind::Normal,
            },
        });
    }
    Ok(output)
}

fn expand_root_reference(
    manifest: &Manifest,
    reference: &str,
    active: &mut BTreeSet<String>,
    enabled: &mut BTreeSet<usize>,
    dependency_features: &mut BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    if let Some(dependency) = reference.strip_prefix("dep:") {
        return enable_root_alias(manifest, dependency, enabled);
    }
    if let Some((dependency, feature)) = reference.split_once('/') {
        if let Some(dependency) = dependency.strip_suffix('?') {
            return require_root_dependency_alias(manifest, dependency);
        }
        enable_root_dependency(manifest, dependency, enabled)?;
        dependency_features
            .entry(dependency.to_owned())
            .or_default()
            .insert(feature.to_owned());
        return Ok(());
    }
    if manifest.features.contains_key(reference) {
        active.insert(reference.to_owned());
        Ok(())
    } else {
        enable_root_alias(manifest, reference, enabled)
    }
}

fn require_root_dependency_alias(manifest: &Manifest, alias: &str) -> Result<()> {
    if manifest
        .dependencies
        .iter()
        .any(|dependency| dependency.alias == alias)
    {
        Ok(())
    } else {
        Err(Error::failure(format!(
            "root feature references unknown dependency `{alias}`"
        )))
    }
}

fn enable_root_dependency(
    manifest: &Manifest,
    alias: &str,
    enabled: &mut BTreeSet<usize>,
) -> Result<()> {
    require_root_dependency_alias(manifest, alias)?;
    for (index, dependency) in manifest.dependencies.iter().enumerate() {
        if dependency.alias == alias && dependency.optional {
            enabled.insert(index);
        }
    }
    Ok(())
}

fn enable_root_alias(
    manifest: &Manifest,
    alias: &str,
    enabled: &mut BTreeSet<usize>,
) -> Result<()> {
    let mut found = false;
    for (index, dependency) in manifest.dependencies.iter().enumerate() {
        if dependency.alias == alias && dependency.optional {
            enabled.insert(index);
            found = true;
        }
    }
    if found {
        Ok(())
    } else {
        Err(Error::failure(format!(
            "root feature references unknown optional dependency or feature `{alias}`"
        )))
    }
}

#[derive(Clone)]
struct Event {
    parent: Option<PackageKey>,
    dependency_index: usize,
    dependency: Dependency,
    context: FeatureContext,
    depth: u64,
    ancestors: BTreeSet<PackageKey>,
}

#[derive(Clone, Debug, Default)]
struct Activation {
    active: BTreeSet<String>,
    enabled_optional: BTreeSet<String>,
    dependency_features: BTreeMap<String, BTreeSet<String>>,
    sent: BTreeMap<usize, Sent>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Sent {
    features: BTreeSet<String>,
    default_features: bool,
}

#[derive(Clone)]
struct Node {
    record: Record,
    activations: BTreeMap<FeatureContext, Activation>,
    edges: BTreeMap<(FeatureContext, usize), PackageKey>,
}

#[derive(Clone, Default)]
struct State {
    nodes: BTreeMap<PackageKey, Node>,
    links: BTreeMap<String, PackageKey>,
}

impl State {
    fn into_resolution(self) -> Resolution {
        let mut packages = Vec::with_capacity(self.nodes.len());
        for (key, node) in self.nodes {
            let feature_sets = node
                .activations
                .iter()
                .map(|(context, activation)| (context.clone(), activation.active.clone()))
                .collect::<BTreeMap<_, _>>();
            let unified = feature_sets.get(&FeatureContext::Unified);
            let target_features = unified.cloned().unwrap_or_default();
            let target_features = feature_sets
                .iter()
                .filter(|(context, _)| matches!(context, FeatureContext::Target(_)))
                .fold(target_features, |mut features, (_, active)| {
                    features.extend(active.iter().cloned());
                    features
                });
            let host_features = unified
                .or_else(|| feature_sets.get(&FeatureContext::Host))
                .cloned()
                .unwrap_or_default();
            let edges = node
                .edges
                .into_iter()
                .map(|((context, dependency_index), package)| ResolvedEdge {
                    dependency_index,
                    context,
                    package,
                })
                .collect();
            packages.push(ResolvedPackage {
                key,
                checksum: node.record.checksum,
                feature_sets,
                target_features,
                host_features,
                edges,
            });
        }
        Resolution { packages }
    }
}

#[derive(Clone, Debug)]
struct Failure {
    message: String,
}

impl Failure {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

fn solve(
    state: State,
    mut queue: VecDeque<Event>,
    catalog: &Catalog,
    options: &Options,
    locked: &[LockedPreference],
) -> std::result::Result<State, Failure> {
    let Some(event) = queue.pop_front() else {
        return Ok(state);
    };
    if event.depth > options.max_depth {
        return Err(Failure::new(format!(
            "`{}` exceeds dependency depth {}",
            event.dependency.package, options.max_depth
        )));
    }
    let matching_selected = state
        .nodes
        .keys()
        .filter(|key| {
            key.name == event.dependency.package
                && event.dependency.requirement.matches(&key.version)
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut last_failure = None;
    for key in matching_selected {
        let mut candidate_state = state.clone();
        let mut candidate_queue = queue.clone();
        match fulfill(
            &mut candidate_state,
            &mut candidate_queue,
            &event,
            &key,
            options,
        )
        .and_then(|()| solve(candidate_state, candidate_queue, catalog, options, locked))
        {
            Ok(state) => return Ok(state),
            Err(failure) => last_failure = Some(failure),
        }
    }

    let candidates = candidates(catalog, &event, options, locked);
    for record in candidates {
        if state
            .nodes
            .keys()
            .any(|key| key.name == record.name && semver_compatible(&key.version, &record.version))
        {
            if last_failure.is_none() {
                last_failure = Some(Failure::new(format!(
                    "compatible requirements for `{}` cannot be unified",
                    record.name
                )));
            }
            continue;
        }
        if state.nodes.len() as u64 >= options.max_packages {
            last_failure = Some(Failure::new(format!(
                "selected package count exceeds {}",
                options.max_packages
            )));
            continue;
        }

        let key = PackageKey {
            name: record.name.clone(),
            version: record.version.clone(),
        };
        let mut candidate_state = state.clone();
        if let Some(links) = &record.links {
            if let Some(existing) = candidate_state.links.get(links) {
                last_failure = Some(Failure::new(format!(
                    "packages `{}` and `{}` both link native library `{links}`",
                    existing.name, key.name
                )));
                continue;
            }
            candidate_state.links.insert(links.clone(), key.clone());
        }
        candidate_state.nodes.insert(
            key.clone(),
            Node {
                record,
                activations: BTreeMap::new(),
                edges: BTreeMap::new(),
            },
        );
        let mut candidate_queue = queue.clone();
        match fulfill(
            &mut candidate_state,
            &mut candidate_queue,
            &event,
            &key,
            options,
        )
        .and_then(|()| solve(candidate_state, candidate_queue, catalog, options, locked))
        {
            Ok(state) => return Ok(state),
            Err(failure) => last_failure = Some(failure),
        }
    }

    Err(last_failure.unwrap_or_else(|| {
        Failure::new(format!(
            "no version of `{}` matches `{}`",
            event.dependency.package, event.dependency.requirement
        ))
    }))
}

fn fulfill(
    state: &mut State,
    queue: &mut VecDeque<Event>,
    event: &Event,
    key: &PackageKey,
    options: &Options,
) -> std::result::Result<(), Failure> {
    if event.ancestors.contains(key) {
        return Err(Failure::new(format!(
            "dependency cycle reaches `{} {}` again",
            key.name, key.version
        )));
    }
    if let Some(parent) = &event.parent {
        let node = state
            .nodes
            .get_mut(parent)
            .ok_or_else(|| Failure::new("dependency parent disappeared during resolution"))?;
        let edge = (event.context.clone(), event.dependency_index);
        if node
            .edges
            .insert(edge, key.clone())
            .is_some_and(|existing| existing != *key)
        {
            return Err(Failure::new(format!(
                "dependency edge from `{}` changed selected package",
                parent.name
            )));
        }
    }
    activate(state, queue, key, event, options)
}

fn activate(
    state: &mut State,
    queue: &mut VecDeque<Event>,
    key: &PackageKey,
    event: &Event,
    options: &Options,
) -> std::result::Result<(), Failure> {
    let record = state
        .nodes
        .get(key)
        .ok_or_else(|| Failure::new("selected package disappeared during activation"))?
        .record
        .clone();
    let activation = state
        .nodes
        .get_mut(key)
        .unwrap()
        .activations
        .entry(event.context.clone())
        .or_default();

    if event.dependency.default_features && record.features.contains_key("default") {
        activation.active.insert("default".to_owned());
    }
    for feature in &event.dependency.features {
        if record.features.contains_key(feature)
            || record
                .dependencies
                .iter()
                .any(|dependency| dependency.optional && dependency.alias == *feature)
        {
            activation.active.insert(feature.clone());
        } else {
            return Err(Failure::new(format!(
                "`{}` {} does not define requested feature `{feature}`",
                record.name, record.version
            )));
        }
    }

    let mut expanded = BTreeSet::new();
    let mut weak = Vec::new();
    while let Some(feature) = activation
        .active
        .iter()
        .find(|feature| !expanded.contains(*feature))
        .cloned()
    {
        expanded.insert(feature.clone());
        let Some(references) = record.features.get(&feature) else {
            activation.enabled_optional.insert(feature);
            continue;
        };
        for reference in references {
            if let Some(dependency) = reference.strip_prefix("dep:") {
                if !record
                    .dependencies
                    .iter()
                    .any(|candidate| candidate.optional && candidate.alias == dependency)
                {
                    return Err(Failure::new(format!(
                        "`{}` {} feature `{feature}` references unknown optional dependency `{dependency}`",
                        record.name, record.version
                    )));
                }
                activation.enabled_optional.insert(dependency.to_owned());
            } else if let Some((dependency, dependency_feature)) = reference.split_once('/') {
                if let Some(dependency) = dependency.strip_suffix('?') {
                    if !record
                        .dependencies
                        .iter()
                        .any(|candidate| candidate.alias == dependency)
                    {
                        return Err(Failure::new(format!(
                            "`{}` {} feature `{feature}` references unknown dependency `{dependency}`",
                            record.name, record.version
                        )));
                    }
                    weak.push((dependency.to_owned(), dependency_feature.to_owned()));
                } else {
                    if !record
                        .dependencies
                        .iter()
                        .any(|candidate| candidate.alias == dependency)
                    {
                        return Err(Failure::new(format!(
                            "`{}` {} feature `{feature}` references unknown dependency `{dependency}`",
                            record.name, record.version
                        )));
                    }
                    activation.enabled_optional.insert(dependency.to_owned());
                    activation
                        .dependency_features
                        .entry(dependency.to_owned())
                        .or_default()
                        .insert(dependency_feature.to_owned());
                }
            } else if record.features.contains_key(reference) {
                activation.active.insert(reference.to_owned());
            } else if record
                .dependencies
                .iter()
                .any(|dependency| dependency.optional && dependency.alias == *reference)
            {
                activation.enabled_optional.insert(reference.to_owned());
            } else {
                return Err(Failure::new(format!(
                    "`{}` {} feature `{feature}` references unknown `{reference}`",
                    record.name, record.version
                )));
            }
        }
    }
    for (dependency, dependency_feature) in weak {
        if activation.enabled_optional.contains(&dependency) {
            activation
                .dependency_features
                .entry(dependency)
                .or_default()
                .insert(dependency_feature);
        }
    }

    for (index, dependency) in record.dependencies.iter().enumerate() {
        if dependency.kind == DependencyKind::Dev
            || (dependency.optional && !activation.enabled_optional.contains(&dependency.alias))
        {
            continue;
        }
        let child_context = match options.resolver {
            ResolverVersion::V1 => FeatureContext::Unified,
            ResolverVersion::V2 | ResolverVersion::V3 => match dependency.kind {
                DependencyKind::Build => FeatureContext::Host,
                DependencyKind::Normal => {
                    target_dependency_context(event.context.clone(), dependency.target.as_deref())
                }
                DependencyKind::Dev => unreachable!(),
            },
        };
        let mut features = dependency.features.iter().cloned().collect::<BTreeSet<_>>();
        if let Some(additional) = activation.dependency_features.get(&dependency.alias) {
            features.extend(additional.iter().cloned());
        }
        let sent = Sent {
            features,
            default_features: dependency.default_features,
        };
        if activation.sent.get(&index) == Some(&sent) {
            continue;
        }
        activation.sent.insert(index, sent.clone());
        let mut dependency = dependency.clone();
        dependency.features = sent.features.into_iter().collect();
        let mut ancestors = event.ancestors.clone();
        ancestors.insert(key.clone());
        queue.push_back(Event {
            parent: Some(key.clone()),
            dependency_index: index,
            dependency,
            context: normalize_context(options.resolver, child_context),
            depth: event.depth.saturating_add(1),
            ancestors,
        });
    }
    Ok(())
}

fn candidates(
    catalog: &Catalog,
    event: &Event,
    options: &Options,
    locked: &[LockedPreference],
) -> Vec<Record> {
    let mut candidates = catalog
        .records(&event.dependency.package)
        .iter()
        .filter(|record| event.dependency.requirement.matches(&record.version))
        .filter(|record| {
            !record.yanked
                || locked.iter().any(|locked| {
                    locked.name == record.name
                        && same_semver_identity(&locked.version, &record.version)
                        && locked.checksum == record.checksum
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    let rust_policy = options.rust_policy();
    candidates.sort_unstable_by(|left, right| {
        let left_locked = lock_rank(left, locked);
        let right_locked = lock_rank(right, locked);
        right_locked.cmp(&left_locked).then_with(|| {
            if rust_policy == IncompatibleRustVersions::Fallback
                && left_locked == 0
                && right_locked == 0
            {
                let left_compatible = rust_compatible(left, &options.rust_version);
                let right_compatible = rust_compatible(right, &options.rust_version);
                right_compatible
                    .cmp(&left_compatible)
                    .then_with(|| right.version.cmp(&left.version))
            } else {
                right.version.cmp(&left.version)
            }
        })
    });
    candidates
}

fn lock_rank(record: &Record, locked: &[LockedPreference]) -> u8 {
    locked
        .iter()
        .any(|locked| {
            locked.name == record.name
                && same_semver_identity(&locked.version, &record.version)
                && locked.checksum == record.checksum
        })
        .into()
}

fn rust_compatible(record: &Record, rust_version: &Version) -> bool {
    record
        .rust_version
        .as_ref()
        .is_none_or(|required| required.version <= *rust_version)
}

fn validate_locked_checksums(catalog: &Catalog, locked: &[LockedPreference]) -> Result<()> {
    for locked in locked {
        if let Some(record) = catalog
            .records(&locked.name)
            .iter()
            .find(|record| same_semver_identity(&record.version, &locked.version))
            && record.checksum != locked.checksum
        {
            return Err(Error::failure(format!(
                "Cargo.lock checksum for `{} {}` conflicts with the sparse index",
                locked.name, locked.version
            )));
        }
    }
    Ok(())
}

fn normalize_context(resolver: ResolverVersion, context: FeatureContext) -> FeatureContext {
    match resolver {
        ResolverVersion::V1 => FeatureContext::Unified,
        ResolverVersion::V2 | ResolverVersion::V3 => context,
    }
}

fn target_dependency_context(parent: FeatureContext, selector: Option<&str>) -> FeatureContext {
    match parent {
        FeatureContext::Unified => FeatureContext::Unified,
        FeatureContext::Host => FeatureContext::Host,
        FeatureContext::Target(parent) => match (parent.is_empty(), selector) {
            (_, None) => FeatureContext::Target(parent),
            (true, Some(selector)) => FeatureContext::Target(selector.to_owned()),
            (false, Some(selector)) => FeatureContext::Target(format!("all({parent};{selector})")),
        },
    }
}

fn semver_compatible(left: &Version, right: &Version) -> bool {
    if left.major != right.major {
        return false;
    }
    if left.major != 0 {
        return true;
    }
    if left.minor != right.minor {
        return false;
    }
    left.minor != 0 || left.patch == right.patch
}

fn same_semver_identity(left: &Version, right: &Version) -> bool {
    left.major == right.major
        && left.minor == right.minor
        && left.patch == right.patch
        && left.pre == right.pre
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;
    use semver::VersionReq;
    use std::fs;
    use std::path::{Path, PathBuf};

    const SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

    fn checksum(version: &str) -> String {
        let digit = version
            .bytes()
            .filter(u8::is_ascii_digit)
            .fold(0_u8, |sum, byte| sum.wrapping_add(byte - b'0'));
        format!("{digit:02x}").repeat(32)
    }

    fn record(
        name: &str,
        version: &str,
        dependencies: &str,
        features: &str,
        extra: &str,
    ) -> Record {
        let source = format!(
            "{{\"name\":\"{name}\",\"vers\":\"{version}\",\
             \"deps\":{dependencies},\"cksum\":\"{}\",\
             \"features\":{features},\"yanked\":false{extra}}}\n",
            checksum(version)
        );
        Record::parse(Path::new("/fixture/index-record.json"), source.as_bytes()).unwrap()
    }

    fn dependency(name: &str, requirement: &str) -> String {
        format!(
            "{{\"name\":\"{name}\",\"req\":\"{requirement}\",\
             \"features\":[],\"optional\":false,\"default_features\":true,\
             \"target\":null,\"kind\":\"normal\"}}"
        )
    }

    fn dependency_with(
        alias: &str,
        package: &str,
        requirement: &str,
        features: &[&str],
        optional: bool,
        kind: &str,
    ) -> String {
        let features = features
            .iter()
            .map(|feature| format!("\"{feature}\""))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"name\":\"{alias}\",\"package\":\"{package}\",\
             \"req\":\"{requirement}\",\"features\":[{features}],\
             \"optional\":{optional},\"default_features\":true,\
             \"target\":null,\"kind\":\"{kind}\"}}"
        )
    }

    fn manifest(dependencies: &str, features: &str, resolver: &str) -> Manifest {
        Manifest::parse(
            Path::new("/fixture"),
            Path::new("/fixture/Cargo.toml"),
            &format!(
                "[package]\nname = \"root\"\nversion = \"0.1.0\"\n\
                 edition = \"2021\"\nresolver = \"{resolver}\"\n\
                 [dependencies]\n{dependencies}\n\
                 [features]\n{features}\n"
            ),
        )
        .unwrap()
    }

    fn target_manifest(resolver: &str) -> Manifest {
        Manifest::parse(
            Path::new("/fixture"),
            Path::new("/fixture/Cargo.toml"),
            &format!(
                "[package]\nname = \"root\"\nversion = \"0.1.0\"\n\
                 edition = \"2021\"\nresolver = \"{resolver}\"\n\
                 [target.'cfg(unix)'.dependencies]\n\
                 unix-shared = {{ package = \"shared\", version = \"1\", features = [\"unix\"] }}\n\
                 [target.'cfg(windows)'.dependencies]\n\
                 windows-shared = {{ package = \"shared\", version = \"1\", features = [\"windows\"] }}\n"
            ),
        )
        .unwrap()
    }

    fn options(resolver: ResolverVersion) -> Options {
        Options {
            resolver,
            incompatible_rust_versions: None,
            rust_version: Version::parse("1.70.0").unwrap(),
            max_packages: 64,
            max_depth: 16,
        }
    }

    fn selected<'a>(resolution: &'a Resolution, name: &str) -> Vec<&'a Version> {
        resolution
            .packages
            .iter()
            .filter(|package| package.key.name == name)
            .map(|package| &package.key.version)
            .collect()
    }

    #[test]
    fn backtracks_to_unify_semver_compatible_requirements() {
        let mut catalog = Catalog::default();
        catalog
            .insert(record(
                "a",
                "1.1.0",
                &format!("[{}]", dependency("shared", "^1.1")),
                "{}",
                "",
            ))
            .unwrap();
        catalog
            .insert(record(
                "a",
                "1.0.0",
                &format!("[{}]", dependency("shared", "=1.0.0")),
                "{}",
                "",
            ))
            .unwrap();
        catalog
            .insert(record(
                "b",
                "1.0.0",
                &format!("[{}]", dependency("shared", "=1.0.0")),
                "{}",
                "",
            ))
            .unwrap();
        catalog
            .insert(record("shared", "1.1.0", "[]", "{}", ""))
            .unwrap();
        catalog
            .insert(record("shared", "1.0.0", "[]", "{}", ""))
            .unwrap();
        let root = manifest("a = \"1\"\nb = \"1\"", "", "2");
        let resolution = resolve(&root, &catalog, &options(ResolverVersion::V2), &[]).unwrap();
        assert_eq!(
            selected(&resolution, "a"),
            [&Version::parse("1.0.0").unwrap()]
        );
        assert_eq!(
            selected(&resolution, "shared"),
            [&Version::parse("1.0.0").unwrap()]
        );
    }

    #[test]
    fn permits_distinct_semver_incompatible_versions() {
        let mut catalog = Catalog::default();
        catalog
            .insert(record("demo", "0.2.1", "[]", "{}", ""))
            .unwrap();
        catalog
            .insert(record("demo", "0.1.9", "[]", "{}", ""))
            .unwrap();
        let root = manifest(
            "old = { package = \"demo\", version = \"0.1\" }\n\
             new = { package = \"demo\", version = \"0.2\" }",
            "",
            "2",
        );
        let resolution = resolve(&root, &catalog, &options(ResolverVersion::V2), &[]).unwrap();
        assert_eq!(selected(&resolution, "demo").len(), 2);
    }

    #[test]
    fn retains_locked_and_yanked_versions_but_checks_their_checksum() {
        let mut catalog = Catalog::default();
        let mut yanked = record("demo", "1.2.0", "[]", "{}", "");
        yanked.yanked = true;
        let yanked_checksum = yanked.checksum;
        catalog.insert(yanked).unwrap();
        catalog
            .insert(record("demo", "1.1.0", "[]", "{}", ""))
            .unwrap();
        let root = manifest("demo = \"1\"", "", "2");

        let unlocked = resolve(&root, &catalog, &options(ResolverVersion::V2), &[]).unwrap();
        assert_eq!(
            selected(&unlocked, "demo"),
            [&Version::parse("1.1.0").unwrap()]
        );
        let locked = [LockedPreference {
            name: "demo".to_owned(),
            version: Version::parse("1.2.0").unwrap(),
            checksum: yanked_checksum,
        }];
        let resolution = resolve(&root, &catalog, &options(ResolverVersion::V2), &locked).unwrap();
        assert_eq!(
            selected(&resolution, "demo"),
            [&Version::parse("1.2.0").unwrap()]
        );

        let corrupt = [LockedPreference {
            checksum: [0_u8; 32],
            ..locked[0].clone()
        }];
        assert!(
            resolve(&root, &catalog, &options(ResolverVersion::V2), &corrupt)
                .unwrap_err()
                .to_string()
                .contains("checksum")
        );
    }

    #[test]
    fn resolver_three_falls_back_to_rust_compatible_versions() {
        let mut catalog = Catalog::default();
        catalog
            .insert(record(
                "demo",
                "1.2.0",
                "[]",
                "{}",
                ",\"rust_version\":\"1.80\"",
            ))
            .unwrap();
        catalog
            .insert(record(
                "demo",
                "1.1.0",
                "[]",
                "{}",
                ",\"rust_version\":\"1.60\"",
            ))
            .unwrap();
        let root = manifest("demo = \"1\"", "", "3");
        let fallback = resolve(&root, &catalog, &options(ResolverVersion::V3), &[]).unwrap();
        assert_eq!(
            selected(&fallback, "demo"),
            [&Version::parse("1.1.0").unwrap()]
        );

        let mut allow = options(ResolverVersion::V3);
        allow.incompatible_rust_versions = Some(IncompatibleRustVersions::Allow);
        let allow = resolve(&root, &catalog, &allow, &[]).unwrap();
        assert_eq!(
            selected(&allow, "demo"),
            [&Version::parse("1.2.0").unwrap()]
        );
    }

    #[test]
    fn backtracks_when_a_candidate_lacks_a_requested_feature() {
        let mut catalog = Catalog::default();
        catalog
            .insert(record("demo", "1.2.0", "[]", "{}", ""))
            .unwrap();
        catalog
            .insert(record("demo", "1.1.0", "[]", "{\"needed\":[]}", ""))
            .unwrap();
        let root = manifest(
            "demo = { version = \"1\", features = [\"needed\"] }",
            "",
            "2",
        );
        let resolution = resolve(&root, &catalog, &options(ResolverVersion::V2), &[]).unwrap();
        assert_eq!(
            selected(&resolution, "demo"),
            [&Version::parse("1.1.0").unwrap()]
        );
    }

    #[test]
    fn resolves_optional_default_and_separate_host_features() {
        let dependencies = [
            dependency_with("shared", "shared", "1", &["target"], false, "normal"),
            dependency_with("shared-build", "shared", "1", &["host"], false, "build"),
            dependency_with("optional", "optional", "1", &[], true, "normal"),
            dependency_with("weak", "weak", "1", &[], true, "normal"),
            dependency_with("defaultdep", "defaultdep", "1", &[], true, "normal"),
        ]
        .join(",");
        let mut catalog = Catalog::default();
        catalog
            .insert(record(
                "a",
                "1.0.0",
                &format!("[{dependencies}]"),
                "{\"default\":[\"dep:defaultdep\"],\
                 \"full\":[\"dep:optional\",\"weak?/feature\"]}",
                "",
            ))
            .unwrap();
        catalog
            .insert(record(
                "shared",
                "1.0.0",
                "[]",
                "{\"target\":[],\"host\":[]}",
                "",
            ))
            .unwrap();
        for name in ["optional", "weak", "defaultdep"] {
            catalog
                .insert(record(name, "1.0.0", "[]", "{\"feature\":[]}", ""))
                .unwrap();
        }
        let root = manifest("a = { version = \"1\", features = [\"full\"] }", "", "2");
        let resolution = resolve(&root, &catalog, &options(ResolverVersion::V2), &[]).unwrap();
        assert_eq!(selected(&resolution, "optional").len(), 1);
        assert_eq!(selected(&resolution, "defaultdep").len(), 1);
        assert!(selected(&resolution, "weak").is_empty());
        let shared = resolution
            .packages
            .iter()
            .find(|package| package.key.name == "shared")
            .unwrap();
        assert_eq!(shared.target_features, ["target".to_owned()].into());
        assert_eq!(shared.host_features, ["host".to_owned()].into());
    }

    #[test]
    fn resolver_two_separates_target_feature_sets_while_one_unifies_them() {
        let mut catalog = Catalog::default();
        catalog
            .insert(record(
                "shared",
                "1.0.0",
                "[]",
                "{\"unix\":[],\"windows\":[]}",
                "",
            ))
            .unwrap();

        let root = target_manifest("2");
        let resolution = resolve(&root, &catalog, &options(ResolverVersion::V2), &[]).unwrap();
        let shared = resolution
            .packages
            .iter()
            .find(|package| package.key.name == "shared")
            .unwrap();
        assert_eq!(
            shared
                .feature_sets
                .get(&FeatureContext::Target("cfg(unix)".to_owned())),
            Some(&["unix".to_owned()].into())
        );
        assert_eq!(
            shared
                .feature_sets
                .get(&FeatureContext::Target("cfg(windows)".to_owned())),
            Some(&["windows".to_owned()].into())
        );

        let root = target_manifest("1");
        let resolution = resolve(&root, &catalog, &options(ResolverVersion::V1), &[]).unwrap();
        let shared = resolution
            .packages
            .iter()
            .find(|package| package.key.name == "shared")
            .unwrap();
        assert_eq!(
            shared.feature_sets.get(&FeatureContext::Unified),
            Some(&["unix".to_owned(), "windows".to_owned()].into())
        );
        assert_eq!(shared.feature_sets.len(), 1);
    }

    #[test]
    fn rejects_links_conflicts_and_graph_limits() {
        let mut catalog = Catalog::default();
        catalog
            .insert(record("a", "1.0.0", "[]", "{}", ",\"links\":\"native\""))
            .unwrap();
        catalog
            .insert(record("b", "1.0.0", "[]", "{}", ",\"links\":\"native\""))
            .unwrap();
        let root = manifest("a = \"1\"\nb = \"1\"", "", "2");
        assert!(
            resolve(&root, &catalog, &options(ResolverVersion::V2), &[])
                .unwrap_err()
                .to_string()
                .contains("link")
        );

        let mut limits = options(ResolverVersion::V2);
        limits.max_packages = 1;
        assert!(
            resolve(&root, &catalog, &limits, &[])
                .unwrap_err()
                .to_string()
                .contains("package count")
        );
    }

    #[test]
    fn rejects_dependency_cycles_and_deep_paths_to_selected_packages() {
        let mut catalog = Catalog::default();
        catalog
            .insert(record(
                "a",
                "1.0.0",
                &format!("[{}]", dependency("b", "1")),
                "{}",
                "",
            ))
            .unwrap();
        catalog
            .insert(record(
                "b",
                "1.0.0",
                &format!("[{}]", dependency("a", "1")),
                "{}",
                "",
            ))
            .unwrap();
        let root = manifest("a = \"1\"", "", "2");
        assert!(
            resolve(&root, &catalog, &options(ResolverVersion::V2), &[])
                .unwrap_err()
                .to_string()
                .contains("cycle")
        );

        let mut catalog = Catalog::default();
        catalog
            .insert(record(
                "a",
                "1.0.0",
                &format!("[{}]", dependency("b", "1")),
                "{}",
                "",
            ))
            .unwrap();
        catalog
            .insert(record(
                "b",
                "1.0.0",
                &format!("[{}]", dependency("shared", "1")),
                "{}",
                "",
            ))
            .unwrap();
        catalog
            .insert(record("shared", "1.0.0", "[]", "{}", ""))
            .unwrap();
        let root = manifest("shared = \"1\"\na = \"1\"", "", "2");
        let mut limits = options(ResolverVersion::V2);
        limits.max_depth = 2;
        assert!(
            resolve(&root, &catalog, &limits, &[])
                .unwrap_err()
                .to_string()
                .contains("dependency depth")
        );
    }

    #[test]
    fn resolves_the_seeded_lorry_lock_graph_when_requested() {
        let Some(repository) = std::env::var_os("LORRY_TEST_SEEDED_REPOSITORY") else {
            return;
        };
        let mut catalog = Catalog::default();
        let objects = PathBuf::from(repository).join("objects/crates-io/sha256");
        for prefix in fs::read_dir(objects).unwrap() {
            for object in fs::read_dir(prefix.unwrap().path()).unwrap() {
                let path = object.unwrap().path().join("index-record.json");
                catalog
                    .insert(Record::parse(&path, &fs::read(&path).unwrap()).unwrap())
                    .unwrap();
            }
        }

        let manifest = Manifest::load(Path::new(".")).unwrap();
        let locked = LockedPreference::from_lockfile(manifest.lock.as_ref()).unwrap();
        let lock = manifest.lock.as_ref().unwrap();
        for package in &lock.packages {
            if package.source.as_deref() != Some(SOURCE)
                || catalog.records(&package.name).iter().any(|record| {
                    record.version == Version::parse(&package.version.original).unwrap()
                })
            {
                continue;
            }
            let dependencies = package
                .dependencies
                .iter()
                .map(|dependency| {
                    let name = dependency.split_whitespace().next().unwrap();
                    let matches = lock
                        .packages
                        .iter()
                        .filter(|package| package.name == name)
                        .collect::<Vec<_>>();
                    assert_eq!(
                        matches.len(),
                        1,
                        "test supplement needs an unambiguous lock dependency"
                    );
                    Dependency {
                        alias: name.to_owned(),
                        package: name.to_owned(),
                        requirement: VersionReq::parse(&format!(
                            "={}",
                            matches[0].version.original
                        ))
                        .unwrap(),
                        features: Vec::new(),
                        optional: false,
                        default_features: true,
                        target: None,
                        kind: DependencyKind::Normal,
                    }
                })
                .collect();
            catalog
                .insert(Record {
                    name: package.name.clone(),
                    version: Version::parse(&package.version.original).unwrap(),
                    dependencies,
                    checksum: decode_hex(package.checksum.as_deref().unwrap()).unwrap(),
                    features: BTreeMap::new(),
                    features2: BTreeMap::new(),
                    yanked: false,
                    links: None,
                    schema: 1,
                    rust_version: None,
                    published: None,
                    exact_bytes: Vec::new(),
                })
                .unwrap();
        }
        let resolution = resolve(
            &manifest,
            &catalog,
            &Options {
                resolver: manifest.resolver,
                incompatible_rust_versions: None,
                rust_version: Version::parse("1.98.0").unwrap(),
                max_packages: 64,
                max_depth: 16,
            },
            &locked,
        )
        .unwrap();
        let expected = lock
            .packages
            .iter()
            .filter(|package| package.source.as_deref() == Some(SOURCE))
            .map(|package| {
                (
                    package.name.clone(),
                    Version::parse(&package.version.original).unwrap(),
                )
            })
            .collect::<BTreeSet<_>>();
        let actual = resolution
            .packages
            .iter()
            .map(|package| (package.key.name.clone(), package.key.version.clone()))
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
    }
}
