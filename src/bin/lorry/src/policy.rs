#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use semver::Version;

use crate::config::{
    LimitSource, NativeToolRole, Policy, PolicyAction, PolicyDefault, PolicyLimits, PolicyRule,
};
use crate::diagnostic::{Error, Result};
use crate::hash::hex;
use crate::manifest::Manifest;
use crate::repository::RegistryObject;
use crate::resolver::{PackageKey, PackageSourceKey, Resolution, ResolvedPackage, ResolvedSource};
use crate::source_tree::{DEFAULT_LIMITS, Exclusions, Tree};

/// Lorry's limit on the number of packages in one dependency graph. Workspace
/// members are the user's own code, so only other packages count. Members are
/// matched by canonical directory: another package may share a member's name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageLimit {
    pub max: u64,
    source: LimitSource,
    members: BTreeSet<PathBuf>,
}

impl PackageLimit {
    pub fn new(limits: &PolicyLimits, manifest: &Manifest) -> Self {
        Self {
            max: limits.max_packages,
            source: limits.max_packages_source.clone(),
            members: manifest.workspace_members.values().cloned().collect(),
        }
    }

    #[cfg(test)]
    pub fn with_max(max: u64) -> Self {
        Self {
            max,
            source: LimitSource::Default,
            members: BTreeSet::new(),
        }
    }

    pub fn counts(&self, key: &PackageKey) -> bool {
        !matches!(&key.source, PackageSourceKey::Path(path) if self.members.contains(path))
    }

    pub(crate) fn with_members(mut self, members: impl IntoIterator<Item = PathBuf>) -> Self {
        self.members = members.into_iter().collect();
        self
    }

    pub fn check(&self, resolution: &Resolution) -> Result<()> {
        let counted = resolution
            .packages
            .iter()
            .filter(|package| self.counts(&package.key))
            .count();
        if counted as u64 > self.max {
            return Err(self.error());
        }
        Ok(())
    }

    pub fn error(&self) -> Error {
        let origin = match &self.source {
            LimitSource::File(path) => format!("set in `{}`", path.display()),
            LimitSource::CommandLine => "set by --max-packages".to_owned(),
            LimitSource::Default => "Lorry's default".to_owned(),
        };
        let user = if cfg!(target_os = "motor") {
            "/user/cfg/lorry.toml"
        } else {
            "~/.config/lorry/lorry.toml"
        };
        Error::failure(format!(
            "the dependency graph has more packages from outside the workspace than \
             the limit of {} ({origin})",
            self.max
        ))
        .with_help(format!(
            "raise `max-packages` in the `[policy.limits]` table of `{user}` \
             or of the project's `lorry.toml`, or pass `--max-packages N` for this run"
        ))
    }
}

#[derive(Clone, Debug)]
pub struct Preflight {
    policy: Policy,
    packages: BTreeMap<PackageKey, PreliminaryPackage>,
}

#[derive(Clone, Debug)]
struct PreliminaryPackage {
    potential_rules: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageEvidence {
    pub license: String,
    pub build_script: bool,
    pub proc_macro: bool,
    pub newly_acquired: bool,
    pub archive_bytes: Option<u64>,
    pub extracted_bytes: u64,
    pub file_count: u64,
    pub source_tree_sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Admission {
    pub packages: BTreeMap<PackageKey, PackageAdmission>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageAdmission {
    pub matching_allow_rules: Vec<String>,
    pub native_tools: BTreeSet<NativeToolRole>,
    pub caller_env: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SourceKind {
    CratesIo,
    Git,
    Path,
}

impl SourceKind {
    fn policy_name(self) -> &'static str {
        match self {
            Self::CratesIo => "crates.io",
            Self::Git => "git",
            Self::Path => "path",
        }
    }
}

#[derive(Clone)]
enum Fact {
    Unknown,
    Absent,
    Value(String),
}

struct Facts<'a> {
    package: &'a PackageKey,
    source: SourceKind,
    checksum: Fact,
    source_tree_sha256: Fact,
    license: Fact,
}

pub fn preflight(policy: &Policy, resolution: &Resolution) -> Result<Preflight> {
    let depth = selected_depth(resolution)?;
    preflight_depth(policy, resolution, depth)
}

pub(crate) fn preflight_workspace(policy: &Policy, resolution: &Resolution) -> Result<Preflight> {
    preflight_depth(policy, resolution, graph_depth(resolution, true)?)
}

fn preflight_depth(policy: &Policy, resolution: &Resolution, depth: u64) -> Result<Preflight> {
    if let Some(limit) = policy.limits.max_depth
        && depth > limit
    {
        return Err(Error::failure(format!(
            "selected dependency depth {depth} exceeds policy limit {limit}"
        )));
    }

    let mut packages = BTreeMap::new();
    for package in &resolution.packages {
        if packages.contains_key(&package.key) {
            return Err(Error::failure(format!(
                "policy input contains duplicate package `{} {}`",
                package.key.name, package.key.version
            )));
        }
        check_path_root(policy, package)?;
        let facts = preliminary_facts(package);
        let mut potential_rules = Vec::new();
        for (id, rule) in &policy.rules {
            if rule_could_match(rule, &facts) {
                potential_rules.push(id.clone());
            }
            if rule.action == PolicyAction::Deny && rule_definitely_matches(rule, &facts) {
                return Err(denied_by_rule(&package.key, id, rule));
            }
        }

        let known_build_script = package
            .local_manifest
            .as_ref()
            .is_some_and(|manifest| manifest.build_script.is_some());
        let needs_allow = base_requires_allow(policy, facts.source);
        if needs_allow
            && !potential_rules
                .iter()
                .any(|id| policy.rules[id].action == PolicyAction::Allow)
        {
            return Err(not_admitted(package, &facts, None));
        }
        if known_build_script
            && !potential_rules
                .iter()
                .any(|id| script_rule_authorizes(&policy.rules[id], package))
        {
            return Err(build_script_not_admitted(package, &facts, None));
        }
        let known_proc_macro = package.local_manifest.as_ref().is_some_and(|manifest| {
            manifest
                .library
                .as_ref()
                .is_some_and(|library| library.proc_macro)
        });
        if known_proc_macro
            && !potential_rules
                .iter()
                .any(|id| proc_macro_rule_authorizes(&policy.rules[id], package))
        {
            return Err(proc_macro_not_admitted(package, &facts, None));
        }

        packages.insert(package.key.clone(), PreliminaryPackage { potential_rules });
    }
    Ok(Preflight {
        policy: policy.clone(),
        packages,
    })
}

pub fn inspect(
    preflight: &Preflight,
    resolution: &Resolution,
    evidence: &BTreeMap<PackageKey, PackageEvidence>,
) -> Result<Admission> {
    let selected = resolution
        .packages
        .iter()
        .map(|package| package.key.clone())
        .collect::<BTreeSet<_>>();
    if selected.len() != resolution.packages.len()
        || selected != preflight.packages.keys().cloned().collect()
    {
        return Err(Error::failure(
            "resolved package graph changed between policy passes",
        ));
    }
    inspect_evidence(&preflight.policy, resolution, evidence)?;
    let mut admitted = BTreeMap::new();
    for package in &resolution.packages {
        let evidence = &evidence[&package.key];
        let source = source_kind(package);
        let facts = complete_facts(package, evidence);
        let preliminary = &preflight.packages[&package.key];
        let matching = preliminary
            .potential_rules
            .iter()
            .filter(|id| rule_matches(&preflight.policy.rules[id.as_str()], &facts))
            .collect::<Vec<_>>();
        if let Some(id) = matching
            .iter()
            .find(|id| preflight.policy.rules[id.as_str()].action == PolicyAction::Deny)
        {
            return Err(denied_by_rule(
                &package.key,
                id,
                &preflight.policy.rules[id.as_str()],
            ));
        }
        let allows = matching
            .iter()
            .filter(|id| preflight.policy.rules[id.as_str()].action == PolicyAction::Allow)
            .copied()
            .collect::<Vec<_>>();
        if base_requires_allow(&preflight.policy, source) && allows.is_empty() {
            return Err(not_admitted(package, &facts, Some(evidence)));
        }

        let script_allows = allows
            .iter()
            .filter(|id| script_rule_authorizes(&preflight.policy.rules[id.as_str()], package))
            .copied()
            .collect::<Vec<_>>();
        if evidence.build_script && script_allows.is_empty() {
            return Err(build_script_not_admitted(package, &facts, Some(evidence)));
        }
        let proc_macro_allows = allows
            .iter()
            .filter(|id| proc_macro_rule_authorizes(&preflight.policy.rules[id.as_str()], package))
            .copied()
            .collect::<Vec<_>>();
        if evidence.proc_macro && proc_macro_allows.is_empty() {
            return Err(proc_macro_not_admitted(package, &facts, Some(evidence)));
        }
        let native_tools = script_allows
            .iter()
            .flat_map(|id| {
                preflight.policy.rules[id.as_str()]
                    .native_tools
                    .iter()
                    .copied()
            })
            .collect();
        let caller_env = script_allows
            .iter()
            .flat_map(|id| {
                preflight.policy.rules[id.as_str()]
                    .caller_env
                    .iter()
                    .cloned()
            })
            .collect();
        admitted.insert(
            package.key.clone(),
            PackageAdmission {
                matching_allow_rules: allows.into_iter().cloned().collect(),
                native_tools,
                caller_env,
            },
        );
    }

    Ok(Admission { packages: admitted })
}

/// Veto known locked identities before any index or Git acquisition. Tree and
/// license constraints remain unknown until verified sources can supply them.
pub(crate) fn preflight_locked_sources(
    policy: &Policy,
    lock: &crate::manifest::Lockfile,
) -> Result<()> {
    for package in &lock.packages {
        let Some(source) = &package.source else {
            continue;
        };
        let (source_kind, source_key, checksum) =
            if source == "registry+https://github.com/rust-lang/crates.io-index" {
                (
                    SourceKind::CratesIo,
                    PackageSourceKey::CratesIo,
                    package.checksum.clone().map_or(Fact::Absent, Fact::Value),
                )
            } else if source.starts_with("git+") {
                crate::git::parse_locked_source(source)?;
                (
                    SourceKind::Git,
                    PackageSourceKey::Git(source.clone()),
                    Fact::Absent,
                )
            } else {
                return Err(Error::failure(format!(
                    "unsupported locked source `{source}`"
                )));
            };
        let key = PackageKey {
            name: package.name.clone(),
            version: Version::parse(&package.version.original)
                .map_err(|error| Error::failure(format!("invalid locked version: {error}")))?,
            source: source_key,
        };
        let facts = Facts {
            package: &key,
            source: source_kind,
            checksum,
            source_tree_sha256: Fact::Unknown,
            license: Fact::Unknown,
        };
        for (id, rule) in &policy.rules {
            if rule.action == PolicyAction::Deny && rule_definitely_matches(rule, &facts) {
                return Err(denied_by_rule(&key, id, rule));
            }
        }
    }
    Ok(())
}

/// Source preparation checks vetoes and resource limits without granting any
/// capability to compile or execute a build script or procedural macro.
pub(crate) fn preflight_sources(policy: &Policy, resolution: &Resolution) -> Result<()> {
    PackageLimit {
        max: policy.limits.max_packages,
        source: policy.limits.max_packages_source.clone(),
        members: resolution
            .packages
            .iter()
            .filter_map(|package| {
                let PackageSourceKey::Path(root) = &package.key.source else {
                    return None;
                };
                package
                    .local_manifest
                    .as_ref()
                    .is_some_and(|manifest| manifest.editable)
                    .then(|| root.clone())
            })
            .collect(),
    }
    .check(resolution)?;
    let depth = graph_depth(resolution, true)?;
    if let Some(limit) = policy.limits.max_depth
        && depth > limit
    {
        return Err(Error::failure(format!(
            "complete dependency depth {depth} exceeds policy limit {limit}"
        )));
    }
    let mut keys = BTreeSet::new();
    for package in &resolution.packages {
        if !keys.insert(&package.key) {
            return Err(Error::failure(
                "source graph contains a duplicate package identity",
            ));
        }
        check_path_root(policy, package)?;
        let facts = preliminary_facts(package);
        check_denies(policy, package, &facts)?;
    }
    Ok(())
}

pub(crate) fn inspect_sources(
    policy: &Policy,
    resolution: &Resolution,
    evidence: &BTreeMap<PackageKey, PackageEvidence>,
) -> Result<()> {
    preflight_sources(policy, resolution)?;
    inspect_evidence(policy, resolution, evidence)?;
    for package in &resolution.packages {
        check_denies(
            policy,
            package,
            &complete_facts(package, &evidence[&package.key]),
        )?;
    }
    Ok(())
}

fn check_denies(policy: &Policy, package: &ResolvedPackage, facts: &Facts<'_>) -> Result<()> {
    for (id, rule) in &policy.rules {
        if rule.action == PolicyAction::Deny && rule_definitely_matches(rule, facts) {
            return Err(denied_by_rule(&package.key, id, rule));
        }
    }
    Ok(())
}

fn inspect_evidence(
    policy: &Policy,
    resolution: &Resolution,
    evidence: &BTreeMap<PackageKey, PackageEvidence>,
) -> Result<()> {
    let selected = resolution
        .packages
        .iter()
        .map(|package| package.key.clone())
        .collect::<BTreeSet<_>>();
    if selected.len() != resolution.packages.len()
        || evidence.keys().cloned().collect::<BTreeSet<_>>() != selected
    {
        return Err(Error::failure(
            "second policy pass does not have exact evidence for every selected package",
        ));
    }
    let mut compressed_total = 0_u64;
    let mut extracted_total = 0_u64;
    for package in &resolution.packages {
        let evidence = &evidence[&package.key];
        check_evidence_identity(package, evidence)?;
        if !package
            .local_manifest
            .as_ref()
            .is_some_and(|manifest| manifest.editable)
        {
            check_package_limits(policy, package, evidence)?;
        }
        let source = source_kind(package);
        if source == SourceKind::CratesIo && evidence.newly_acquired {
            let archive_bytes = evidence.archive_bytes.ok_or_else(|| {
                Error::failure(format!(
                    "crates.io package `{} {}` has no inspected archive size",
                    package.key.name, package.key.version
                ))
            })?;
            compressed_total = compressed_total
                .checked_add(archive_bytes)
                .ok_or_else(|| Error::failure("vendor transaction byte count overflowed"))?;
            extracted_total = extracted_total
                .checked_add(evidence.extracted_bytes)
                .ok_or_else(|| {
                    Error::failure("vendor transaction extracted byte count overflowed")
                })?;
        }
    }
    if compressed_total > policy.limits.max_transaction_bytes {
        return Err(Error::failure(format!(
            "selected crates.io archives total {compressed_total} bytes, exceeding policy transaction limit {}",
            policy.limits.max_transaction_bytes
        )));
    }
    if extracted_total > policy.limits.max_extracted_transaction_bytes {
        return Err(Error::failure(format!(
            "selected crates.io sources total {extracted_total} extracted bytes, exceeding policy transaction limit {}",
            policy.limits.max_extracted_transaction_bytes
        )));
    }
    Ok(())
}

impl PackageEvidence {
    pub(crate) fn from_verified_git(manifest: &Manifest, tree: &Tree) -> Self {
        Self {
            license: manifest.metadata.license.clone(),
            build_script: manifest.build_script.is_some(),
            proc_macro: manifest
                .library
                .as_ref()
                .is_some_and(|library| library.proc_macro),
            newly_acquired: false,
            archive_bytes: None,
            extracted_bytes: tree.total_bytes,
            file_count: tree.file_count as u64,
            source_tree_sha256: tree.sha256,
        }
    }

    pub fn from_registry(
        package: &ResolvedPackage,
        object: &RegistryObject,
        manifest: &Manifest,
        tree: &Tree,
        newly_acquired: bool,
    ) -> Result<Self> {
        let evidence = Self::from_trusted_registry(package, object, manifest, newly_acquired)?;
        if tree.sha256 != object.source_tree_sha256
            || tree.total_bytes != object.extracted_bytes
            || tree.file_count as u64 != object.file_count
            || tree.directory_count as u64 != object.directory_count
        {
            return Err(Error::failure(format!(
                "inspected source tree does not match repository metadata for `{} {}`",
                package.key.name, package.key.version
            )));
        }
        Ok(evidence)
    }

    pub fn from_trusted_registry(
        package: &ResolvedPackage,
        object: &RegistryObject,
        manifest: &Manifest,
        newly_acquired: bool,
    ) -> Result<Self> {
        let ResolvedSource::CratesIo { checksum } = package.source else {
            return Err(Error::failure(format!(
                "`{} {}` is not a crates.io package",
                package.key.name, package.key.version
            )));
        };
        let manifest_version = Version::parse(&manifest.version.original).map_err(|error| {
            Error::failure(format!(
                "inspected manifest has invalid version `{} {}`: {error}",
                manifest.name, manifest.version.original
            ))
        })?;
        if package.key.source != PackageSourceKey::CratesIo
            || object.name != package.key.name
            || object.version != package.key.version
            || object.checksum != checksum
            || manifest.name != package.key.name
            || manifest_version != package.key.version
            || object.license != manifest.metadata.license
        {
            return Err(Error::failure(format!(
                "inspected crates.io evidence does not match resolved package `{} {}`",
                package.key.name, package.key.version
            )));
        }
        Ok(Self {
            license: manifest.metadata.license.clone(),
            build_script: manifest.build_script.is_some(),
            proc_macro: manifest
                .library
                .as_ref()
                .is_some_and(|library| library.proc_macro),
            newly_acquired,
            archive_bytes: Some(object.archive_bytes),
            extracted_bytes: object.extracted_bytes,
            file_count: object.file_count,
            source_tree_sha256: object.source_tree_sha256,
        })
    }

    pub fn from_path(package: &ResolvedPackage) -> Result<Self> {
        let ResolvedSource::Path {
            physical_root,
            source_tree_sha256,
            ..
        } = &package.source
        else {
            return Err(Error::failure(format!(
                "`{} {}` is not a path package",
                package.key.name, package.key.version
            )));
        };
        let manifest = package.local_manifest.as_ref().ok_or_else(|| {
            Error::failure(format!(
                "resolved path package `{} {}` has no inspected manifest",
                package.key.name, package.key.version
            ))
        })?;
        let manifest_version = Version::parse(&manifest.version.original).map_err(|error| {
            Error::failure(format!(
                "path manifest has invalid version `{} {}`: {error}",
                manifest.name, manifest.version.original
            ))
        })?;
        if manifest.name != package.key.name
            || manifest_version != package.key.version
            || manifest.root != *physical_root
        {
            return Err(Error::failure(format!(
                "path manifest does not match resolved package `{} {}`",
                package.key.name, package.key.version
            )));
        }
        let (sha256, extracted_bytes, file_count) = if manifest.editable {
            let snapshot = crate::member_source::snapshot(manifest, true)?;
            (snapshot.sha256, snapshot.bytes, snapshot.files)
        } else {
            let tree = Tree::scan(physical_root, DEFAULT_LIMITS, Exclusions::GitAndTarget)?;
            (tree.sha256, tree.total_bytes, tree.file_count as u64)
        };
        if sha256 != *source_tree_sha256 {
            return Err(Error::failure(format!(
                "path source for `{} {}` changed after resolution",
                package.key.name, package.key.version
            )));
        }
        Ok(Self {
            license: manifest.metadata.license.clone(),
            build_script: manifest.build_script.is_some(),
            proc_macro: manifest
                .library
                .as_ref()
                .is_some_and(|library| library.proc_macro),
            newly_acquired: false,
            archive_bytes: None,
            extracted_bytes,
            file_count,
            source_tree_sha256: sha256,
        })
    }

    pub fn from_git(package: &ResolvedPackage) -> Result<Self> {
        let ResolvedSource::Git {
            physical_root,
            source_tree_sha256,
            ..
        } = &package.source
        else {
            return Err(Error::failure(format!(
                "`{} {}` is not a Git package",
                package.key.name, package.key.version
            )));
        };
        let manifest = package.local_manifest.as_ref().ok_or_else(|| {
            Error::failure(format!(
                "resolved Git package `{} {}` has no inspected manifest",
                package.key.name, package.key.version
            ))
        })?;
        let manifest_version = Version::parse(&manifest.version.original).map_err(|error| {
            Error::failure(format!(
                "Git manifest has invalid version `{} {}`: {error}",
                manifest.name, manifest.version.original
            ))
        })?;
        if manifest.name != package.key.name
            || manifest_version != package.key.version
            || manifest.root != *physical_root
        {
            return Err(Error::failure(format!(
                "Git manifest does not match resolved package `{} {}`",
                package.key.name, package.key.version
            )));
        }
        let tree = Tree::scan(physical_root, DEFAULT_LIMITS, Exclusions::None)?;
        if tree.sha256 != *source_tree_sha256 {
            return Err(Error::failure(format!(
                "Git source for `{} {}` changed after resolution",
                package.key.name, package.key.version
            )));
        }
        Ok(Self::from_verified_git(manifest, &tree))
    }
}

fn preliminary_facts(package: &ResolvedPackage) -> Facts<'_> {
    match &package.source {
        ResolvedSource::CratesIo { checksum } => Facts {
            package: &package.key,
            source: SourceKind::CratesIo,
            checksum: Fact::Value(hex(checksum)),
            source_tree_sha256: Fact::Unknown,
            license: Fact::Unknown,
        },
        ResolvedSource::Path {
            source_tree_sha256, ..
        } => Facts {
            package: &package.key,
            source: SourceKind::Path,
            checksum: Fact::Absent,
            source_tree_sha256: Fact::Value(hex(source_tree_sha256)),
            license: package
                .local_manifest
                .as_ref()
                .map_or(Fact::Unknown, |manifest| {
                    Fact::Value(manifest.metadata.license.clone())
                }),
        },
        ResolvedSource::Git {
            source_tree_sha256, ..
        } => Facts {
            package: &package.key,
            source: SourceKind::Git,
            checksum: Fact::Absent,
            source_tree_sha256: Fact::Value(hex(source_tree_sha256)),
            license: package
                .local_manifest
                .as_ref()
                .map_or(Fact::Unknown, |manifest| {
                    Fact::Value(manifest.metadata.license.clone())
                }),
        },
    }
}

fn complete_facts<'a>(package: &'a ResolvedPackage, evidence: &'a PackageEvidence) -> Facts<'a> {
    let source = source_kind(package);
    let checksum = match &package.source {
        ResolvedSource::CratesIo { checksum } => Fact::Value(hex(checksum)),
        ResolvedSource::Path { .. } | ResolvedSource::Git { .. } => Fact::Absent,
    };
    Facts {
        package: &package.key,
        source,
        checksum,
        source_tree_sha256: Fact::Value(hex(&evidence.source_tree_sha256)),
        license: Fact::Value(evidence.license.clone()),
    }
}

fn source_kind(package: &ResolvedPackage) -> SourceKind {
    match &package.source {
        ResolvedSource::CratesIo { .. } => SourceKind::CratesIo,
        ResolvedSource::Git { .. } => SourceKind::Git,
        ResolvedSource::Path { .. } => SourceKind::Path,
    }
}

fn base_requires_allow(policy: &Policy, source: SourceKind) -> bool {
    matches!(source, SourceKind::CratesIo | SourceKind::Git)
        && policy.default == PolicyDefault::Deny
}

fn check_path_root(policy: &Policy, package: &ResolvedPackage) -> Result<()> {
    let ResolvedSource::Path { physical_root, .. } = &package.source else {
        return Ok(());
    };
    if package
        .local_manifest
        .as_ref()
        .is_some_and(|manifest| manifest.editable)
        || policy.path_roots.is_empty()
        || policy
            .path_roots
            .iter()
            .any(|root| physical_root.starts_with(root))
    {
        return Ok(());
    }
    Err(Error::failure(format!(
        "local path package `{} {}` resolves outside every configured `policy.path-roots`: `{}`",
        package.key.name,
        package.key.version,
        physical_root.display()
    )))
}

fn rule_could_match(rule: &PolicyRule, facts: &Facts<'_>) -> bool {
    basic_rule_matches(rule, facts)
        && fact_could_match(rule.checksum.as_deref(), &facts.checksum)
        && fact_could_match(
            rule.source_tree_sha256.as_deref(),
            &facts.source_tree_sha256,
        )
        && fact_could_match(rule.license.as_deref(), &facts.license)
}

fn rule_definitely_matches(rule: &PolicyRule, facts: &Facts<'_>) -> bool {
    basic_rule_matches(rule, facts)
        && fact_definitely_matches(rule.checksum.as_deref(), &facts.checksum)
        && fact_definitely_matches(
            rule.source_tree_sha256.as_deref(),
            &facts.source_tree_sha256,
        )
        && fact_definitely_matches(rule.license.as_deref(), &facts.license)
}

fn rule_matches(rule: &PolicyRule, facts: &Facts<'_>) -> bool {
    rule_definitely_matches(rule, facts)
}

fn basic_rule_matches(rule: &PolicyRule, facts: &Facts<'_>) -> bool {
    rule.name
        .as_ref()
        .is_none_or(|name| name == &facts.package.name)
        && rule
            .version
            .as_ref()
            .is_none_or(|version| version.matches(&facts.package.version))
        && rule
            .source
            .as_deref()
            .is_none_or(|source| source == facts.source.policy_name())
}

fn fact_could_match(expected: Option<&str>, actual: &Fact) -> bool {
    match (expected, actual) {
        (None, _) | (Some(_), Fact::Unknown) => true,
        (Some(_), Fact::Absent) => false,
        (Some(expected), Fact::Value(actual)) => expected == actual,
    }
}

fn fact_definitely_matches(expected: Option<&str>, actual: &Fact) -> bool {
    match (expected, actual) {
        (None, _) => true,
        (Some(_), Fact::Unknown | Fact::Absent) => false,
        (Some(expected), Fact::Value(actual)) => expected == actual,
    }
}

fn script_rule_authorizes(rule: &PolicyRule, package: &ResolvedPackage) -> bool {
    if rule.action != PolicyAction::Allow
        || !rule.allow_build_script
        || !member_grant_is_named(rule, package)
    {
        return false;
    }
    let source = source_kind(package);
    if source == SourceKind::Path
        && !rule.native_tools.is_empty()
        && rule.source_tree_sha256.is_none()
        && !is_editable_member(package)
    {
        return false;
    }
    match source {
        SourceKind::CratesIo => true,
        SourceKind::Git | SourceKind::Path => rule.source.as_deref() == Some(source.policy_name()),
    }
}

fn proc_macro_rule_authorizes(rule: &PolicyRule, package: &ResolvedPackage) -> bool {
    if rule.action != PolicyAction::Allow
        || !rule.allow_proc_macro
        || !member_grant_is_named(rule, package)
    {
        return false;
    }
    let source = source_kind(package);
    match source {
        SourceKind::CratesIo => true,
        SourceKind::Git | SourceKind::Path => rule.source.as_deref() == Some(source.policy_name()),
    }
}

fn is_editable_member(package: &ResolvedPackage) -> bool {
    source_kind(package) == SourceKind::Path
        && package
            .local_manifest
            .as_ref()
            .is_some_and(|manifest| manifest.editable)
}

fn member_grant_is_named(rule: &PolicyRule, package: &ResolvedPackage) -> bool {
    !is_editable_member(package) || rule.name.as_deref() == Some(&package.key.name)
}

pub(crate) fn check_evidence_identity(
    package: &ResolvedPackage,
    evidence: &PackageEvidence,
) -> Result<()> {
    match &package.source {
        ResolvedSource::CratesIo { .. } if evidence.archive_bytes.is_none() => {
            Err(Error::failure(format!(
                "crates.io evidence for `{} {}` has no archive",
                package.key.name, package.key.version
            )))
        }
        ResolvedSource::Path {
            source_tree_sha256, ..
        } if evidence.newly_acquired
            || evidence.archive_bytes.is_some()
            || evidence.source_tree_sha256 != *source_tree_sha256 =>
        {
            Err(Error::failure(format!(
                "path evidence does not match `{} {}`",
                package.key.name, package.key.version
            )))
        }
        ResolvedSource::Git {
            source_tree_sha256, ..
        } if evidence.newly_acquired
            || evidence.archive_bytes.is_some()
            || evidence.source_tree_sha256 != *source_tree_sha256 =>
        {
            Err(Error::failure(format!(
                "Git evidence does not match `{} {}`",
                package.key.name, package.key.version
            )))
        }
        _ => Ok(()),
    }
}

fn check_package_limits(
    policy: &Policy,
    package: &ResolvedPackage,
    evidence: &PackageEvidence,
) -> Result<()> {
    if evidence
        .archive_bytes
        .is_some_and(|bytes| bytes > policy.limits.max_package_bytes)
    {
        return Err(Error::failure(format!(
            "archive for `{} {}` exceeds policy package-byte limit {}",
            package.key.name, package.key.version, policy.limits.max_package_bytes
        )));
    }
    if evidence.extracted_bytes > policy.limits.max_extracted_package_bytes {
        return Err(Error::failure(format!(
            "source for `{} {}` exceeds policy extracted-byte limit {}",
            package.key.name, package.key.version, policy.limits.max_extracted_package_bytes
        )));
    }
    if evidence.file_count > policy.limits.max_package_files {
        return Err(Error::failure(format!(
            "source for `{} {}` exceeds policy file-count limit {}",
            package.key.name, package.key.version, policy.limits.max_package_files
        )));
    }
    Ok(())
}

fn selected_depth(resolution: &Resolution) -> Result<u64> {
    graph_depth(resolution, false)
}

fn graph_depth(resolution: &Resolution, member_roots: bool) -> Result<u64> {
    let packages = resolution
        .packages
        .iter()
        .map(|package| (package.key.clone(), package))
        .collect::<BTreeMap<_, _>>();
    let mut memo = BTreeMap::new();
    let mut visiting = BTreeSet::new();
    let mut depth = 0;
    for edge in &resolution.root_edges {
        let tail = tail_depth(&edge.package, &packages, &mut memo, &mut visiting, None)?;
        depth = depth.max(tail.saturating_sub(u64::from(member_roots)));
    }
    let mut reachable = memo.keys().cloned().collect::<BTreeSet<_>>();
    if member_roots {
        for edge in &resolution.root_edges {
            for dev in packages[&edge.package]
                .edges
                .iter()
                .filter(|edge| edge.kind == crate::sparse::DependencyKind::Dev)
            {
                // A development dependency may depend back on this member.
                // Its ordinary dependencies were already traversed above.
                let mut dev_memo = BTreeMap::new();
                depth = depth.max(tail_depth(
                    &dev.package,
                    &packages,
                    &mut dev_memo,
                    &mut visiting,
                    Some(&edge.package),
                )?);
                reachable.extend(dev_memo.into_keys());
            }
        }
    }
    if reachable.len() != packages.len() {
        return Err(Error::failure(
            "policy graph contains a selected package unreachable from the root",
        ));
    }
    Ok(depth)
}

fn tail_depth(
    key: &PackageKey,
    packages: &BTreeMap<PackageKey, &ResolvedPackage>,
    memo: &mut BTreeMap<PackageKey, u64>,
    visiting: &mut BTreeSet<PackageKey>,
    development_root: Option<&PackageKey>,
) -> Result<u64> {
    if development_root == Some(key) {
        return Ok(0);
    }
    if let Some(depth) = memo.get(key) {
        return Ok(*depth);
    }
    let package = packages.get(key).ok_or_else(|| {
        Error::failure(format!(
            "policy graph edge names missing package `{} {}`",
            key.name, key.version
        ))
    })?;
    if !visiting.insert(key.clone()) {
        return Err(Error::failure(format!(
            "policy graph contains a dependency cycle at `{} {}`",
            key.name, key.version
        )));
    }
    let mut depth = 1;
    for edge in &package.edges {
        if edge.kind == crate::sparse::DependencyKind::Dev {
            continue;
        }
        depth = depth.max(
            1_u64
                .checked_add(tail_depth(
                    &edge.package,
                    packages,
                    memo,
                    visiting,
                    development_root,
                )?)
                .ok_or_else(|| Error::failure("policy dependency depth overflowed"))?,
        );
    }
    visiting.remove(key);
    memo.insert(key.clone(), depth);
    Ok(depth)
}

fn denied_by_rule(package: &PackageKey, id: &str, rule: &PolicyRule) -> Error {
    Error::failure(format!(
        "package `{} {}` is denied by policy rule `{id}` from `{}`",
        package.name,
        package.version,
        rule.provenance.display()
    ))
}

fn not_admitted(
    package: &ResolvedPackage,
    facts: &Facts<'_>,
    evidence: Option<&PackageEvidence>,
) -> Error {
    Error::failure(format!(
        "package `{} {}` is not admitted by the effective dependency policy",
        package.key.name, package.key.version
    ))
    .with_help(exact_allow_example(package, facts, evidence, false, false))
}

fn build_script_not_admitted(
    package: &ResolvedPackage,
    facts: &Facts<'_>,
    evidence: Option<&PackageEvidence>,
) -> Error {
    Error::failure(format!(
        "package `{} {}` contains a build script without an explicit matching policy grant",
        package.key.name, package.key.version
    ))
    .with_help(exact_allow_example(package, facts, evidence, true, false))
}

fn proc_macro_not_admitted(
    package: &ResolvedPackage,
    facts: &Facts<'_>,
    evidence: Option<&PackageEvidence>,
) -> Error {
    Error::failure(format!(
        "package `{} {}` contains a procedural macro without an explicit matching policy grant",
        package.key.name, package.key.version
    ))
    .with_help(exact_allow_example(package, facts, evidence, false, true))
}

fn exact_allow_example(
    package: &ResolvedPackage,
    facts: &Facts<'_>,
    evidence: Option<&PackageEvidence>,
    allow_build_script: bool,
    allow_proc_macro: bool,
) -> String {
    let id_name = rule_id_component(&package.key.name);
    let id_version = rule_id_component(&package.key.version.to_string());
    let mut example = format!(
        "review the package, then add an exact rule such as:\n\
         [policy.rules.allow-{id_name}-{id_version}]\n\
         action = \"allow\"\n\
         name = \"{}\"\n\
         version = \"={}\"\n\
         source = \"{}\"\n",
        package.key.name,
        package.key.version,
        facts.source.policy_name()
    );
    if let Fact::Value(checksum) = &facts.checksum {
        example.push_str(&format!("checksum = \"{checksum}\"\n"));
    }
    if facts.source != SourceKind::CratesIo
        && !is_editable_member(package)
        && let Fact::Value(digest) = &facts.source_tree_sha256
    {
        example.push_str(&format!("source-tree-sha256 = \"{digest}\"\n"));
    }
    if let Some(evidence) = evidence
        && safe_toml_string(&evidence.license)
    {
        example.push_str(&format!("license = \"{}\"\n", evidence.license));
    }
    if allow_build_script {
        example.push_str("allow-build-script = true\n");
    }
    if allow_proc_macro {
        example.push_str("allow-proc-macro = true\n");
    }
    example.push_str("`--accept-all` cannot bypass this policy");
    example
}

fn rule_id_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn safe_toml_string(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\\'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PolicyLimits, PolicyRule};
    use crate::resolver::{FeatureContext, PackageSourceKey, ResolvedEdge};
    use semver::VersionReq;
    use std::path::Path;

    fn checksum(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn registry_package(name: &str, version: &str, byte: u8) -> ResolvedPackage {
        let version = Version::parse(version).unwrap();
        ResolvedPackage {
            key: PackageKey {
                name: name.to_owned(),
                version,
                source: PackageSourceKey::CratesIo,
            },
            source: ResolvedSource::CratesIo {
                checksum: checksum(byte),
            },
            local_manifest: None,
            feature_sets: BTreeMap::new(),
            compile_kinds: [crate::resolver::CompileKind::Target].into(),
            target_features: BTreeSet::new(),
            host_features: BTreeSet::new(),
            edges: Vec::new(),
            lock_edges: Vec::new(),
        }
    }

    fn path_package(root: &Path, build_script: bool, proc_macro: bool) -> ResolvedPackage {
        let build = if build_script {
            "build = \"build.rs\""
        } else {
            "build = false"
        };
        let library = if proc_macro {
            "[lib]\nproc-macro = true"
        } else {
            ""
        };
        let manifest = Manifest::parse_dependency(
            root,
            &root.join("Cargo.toml"),
            &format!(
                "[package]\nname = \"local-demo\"\nversion = \"1.2.3\"\n\
                 edition = \"2021\"\nlicense = \"MIT\"\n{build}\n{library}\n"
            ),
        )
        .unwrap();
        let version = Version::parse("1.2.3").unwrap();
        ResolvedPackage {
            key: PackageKey {
                name: "local-demo".to_owned(),
                version,
                source: PackageSourceKey::Path(root.to_owned()),
            },
            source: ResolvedSource::Path {
                logical_root: root.to_owned(),
                physical_root: root.to_owned(),
                source_tree_sha256: checksum(7),
                patched_crates_io: false,
            },
            local_manifest: Some(manifest),
            feature_sets: BTreeMap::new(),
            compile_kinds: [crate::resolver::CompileKind::Target].into(),
            target_features: BTreeSet::new(),
            host_features: BTreeSet::new(),
            edges: Vec::new(),
            lock_edges: Vec::new(),
        }
    }

    #[test]
    fn path_root_allowlists_cover_outside_paths_while_member_vetoes_still_apply() {
        let mut member = path_package(Path::new("/ws/member"), false, false);
        member.local_manifest.as_mut().unwrap().editable = true;
        let outside = path_package(Path::new("/allowed/outside"), false, false);
        let unowned = path_package(Path::new("/ws/unowned"), false, false);
        let mut policy = Policy {
            default: PolicyDefault::Deny,
            path_roots: vec![Path::new("/allowed").to_owned()],
            limits: PolicyLimits::default(),
            rules: BTreeMap::new(),
        };
        let resolution = make_resolution(vec![member.clone(), outside]);
        preflight_sources(&policy, &resolution).unwrap();
        preflight_workspace(&policy, &resolution).unwrap();
        assert!(
            preflight_sources(&policy, &make_resolution(vec![unowned]))
                .unwrap_err()
                .render()
                .contains("path-roots")
        );
        let mut deny = rule(PolicyAction::Deny, None, None);
        deny.name = Some(member.key.name.clone());
        deny.source = Some("path".into());
        policy.rules.insert("member-veto".into(), deny);
        assert!(
            preflight_sources(&policy, &make_resolution(vec![member]))
                .unwrap_err()
                .render()
                .contains("member-veto")
        );
    }

    #[test]
    fn package_limit_counts_only_packages_outside_the_workspace() {
        let mut manifest = Manifest::parse(
            Path::new("/ws/app"),
            Path::new("/ws/app/Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        manifest.workspace_root = Path::new("/ws").to_owned();
        manifest.workspace_members = [("app", "/ws/app"), ("local-demo", "/ws/local-demo")]
            .map(|(name, root)| (name.to_owned(), Path::new(root).to_owned()))
            .into();
        let limits = PolicyLimits {
            max_packages: 1,
            max_packages_source: LimitSource::File(Path::new("/user/cfg/lorry.toml").to_owned()),
            ..PolicyLimits::default()
        };
        let limit = PackageLimit::new(&limits, &manifest);
        let member = path_package(Path::new("/ws/local-demo"), false, false);
        let outside = path_package(Path::new("/elsewhere/local-demo"), false, false);
        // Below the root and named like a member, but not a member directory.
        let namesake = path_package(Path::new("/ws/vendored/local-demo"), false, false);
        let registry = registry_package("demo", "1.2.3", 4);

        limit
            .check(&make_resolution(vec![member.clone(), registry.clone()]))
            .unwrap();
        limit
            .check(&make_resolution(vec![
                member.clone(),
                namesake,
                registry.clone(),
            ]))
            .unwrap_err();
        let error = limit
            .check(&make_resolution(vec![member, outside, registry]))
            .unwrap_err()
            .render();
        assert!(
            error.contains("limit of 1 (set in `/user/cfg/lorry.toml`)"),
            "{error}"
        );
        assert!(error.contains("raise `max-packages`"), "{error}");
    }

    fn make_resolution(packages: Vec<ResolvedPackage>) -> Resolution {
        let root_edges = packages
            .iter()
            .enumerate()
            .map(|(dependency_index, package)| ResolvedEdge {
                dependency_index,
                alias: package.key.name.clone(),
                target: None,
                kind: crate::sparse::DependencyKind::Normal,
                parent_compile_kind: None,
                compile_kind: crate::resolver::CompileKind::Target,
                context: FeatureContext::Target(String::new()),
                package: package.key.clone(),
            })
            .collect();
        Resolution {
            root_edges,
            packages,
        }
    }

    fn rule(action: PolicyAction, checksum: Option<String>, license: Option<&str>) -> PolicyRule {
        PolicyRule {
            action,
            name: Some("demo".to_owned()),
            version: Some(VersionReq::parse("=1.2.3").unwrap()),
            source: Some("crates.io".to_owned()),
            checksum,
            source_tree_sha256: None,
            license: license.map(str::to_owned),
            allow_build_script: false,
            allow_proc_macro: false,
            native_tools: BTreeSet::new(),
            caller_env: Default::default(),
            provenance: Path::new("/system/lorry.toml").to_owned(),
        }
    }

    fn evidence(package: &ResolvedPackage, build_script: bool) -> PackageEvidence {
        let ResolvedSource::CratesIo {
            checksum: resolved_checksum,
        } = package.source
        else {
            unreachable!()
        };
        assert_ne!(resolved_checksum, [0; 32]);
        PackageEvidence {
            license: "MIT".to_owned(),
            build_script,
            proc_macro: false,
            newly_acquired: true,
            archive_bytes: Some(100),
            extracted_bytes: 200,
            file_count: 2,
            source_tree_sha256: checksum(9),
        }
    }

    #[test]
    fn locked_git_veto_uses_known_identity_without_inventing_source_evidence() {
        let lock = crate::manifest::Lockfile {
            format: crate::lockfile::Format::V4,
            packages: vec![crate::manifest::LockedPackage {
                name: "demo".into(),
                version: crate::manifest::Version {
                    original: "1.2.3".into(),
                    major: 1,
                    minor: 2,
                    patch: 3,
                    pre: String::new(),
                    build: String::new(),
                },
                source: Some(format!("git+https://example.test/demo#{}", "1".repeat(40))),
                checksum: None,
                dependencies: vec![],
            }],
        };
        let mut veto = rule(PolicyAction::Deny, None, None);
        veto.source = Some("git".into());
        let mut policy = Policy {
            default: PolicyDefault::Deny,
            path_roots: vec![],
            limits: PolicyLimits::default(),
            rules: BTreeMap::from([("veto".into(), veto)]),
        };
        assert!(
            preflight_locked_sources(&policy, &lock)
                .unwrap_err()
                .render()
                .contains("veto")
        );
        policy.rules.get_mut("veto").unwrap().source_tree_sha256 = Some("0".repeat(64));
        preflight_locked_sources(&policy, &lock).unwrap();
        policy.rules.get_mut("veto").unwrap().source_tree_sha256 = None;
        policy.rules.get_mut("veto").unwrap().license = Some("MIT".into());
        preflight_locked_sources(&policy, &lock).unwrap();
    }

    #[test]
    fn source_inspection_needs_no_execution_grants_but_keeps_vetoes_and_limits() {
        let package = registry_package("demo", "1.2.3", 4);
        let resolution = make_resolution(vec![package.clone()]);
        let mut policy = Policy {
            default: PolicyDefault::Deny,
            path_roots: Vec::new(),
            limits: PolicyLimits::default(),
            rules: BTreeMap::new(),
        };
        let mut inspected = evidence(&package, true);
        inspected.proc_macro = true;
        let evidence = BTreeMap::from([(package.key.clone(), inspected)]);
        assert!(preflight(&policy, &resolution).is_err());
        inspect_sources(&policy, &resolution, &evidence).unwrap();
        policy.limits.max_package_bytes = 99;
        assert!(
            inspect_sources(&policy, &resolution, &evidence)
                .unwrap_err()
                .to_string()
                .contains("package-byte")
        );
        policy.limits.max_package_bytes = 100;
        policy.rules.insert(
            "veto".to_owned(),
            rule(PolicyAction::Deny, None, Some("MIT")),
        );
        preflight_sources(&policy, &resolution).unwrap();
        assert!(
            inspect_sources(&policy, &resolution, &evidence)
                .unwrap_err()
                .to_string()
                .contains("veto")
        );
        policy.rules.get_mut("veto").unwrap().license = None;
        assert!(
            preflight_sources(&policy, &resolution)
                .unwrap_err()
                .to_string()
                .contains("veto")
        );
        policy.rules.clear();
        assert!(inspect_sources(&policy, &resolution, &BTreeMap::new()).is_err());
        policy.limits.max_packages = 0;
        assert!(
            preflight_sources(&policy, &resolution)
                .unwrap_err()
                .to_string()
                .contains("limit of 0")
        );
    }

    #[test]
    fn workspace_source_depth_excludes_member_roots_and_allows_development_cycles() {
        let mut member = path_package(Path::new("/workspace/member"), false, false);
        member.local_manifest.as_mut().unwrap().editable = true;
        let child = registry_package("child", "1.0.0", 1);
        let edge = |package, kind| ResolvedEdge {
            dependency_index: 0,
            alias: "dependency".to_owned(),
            target: None,
            kind,
            parent_compile_kind: Some(crate::resolver::CompileKind::Target),
            compile_kind: crate::resolver::CompileKind::Target,
            context: FeatureContext::Unified,
            package,
        };
        member
            .edges
            .push(edge(member.key.clone(), crate::sparse::DependencyKind::Dev));
        member.edges.push(edge(
            child.key.clone(),
            crate::sparse::DependencyKind::Normal,
        ));
        let mut resolution = make_resolution(vec![member.clone()]);
        resolution.packages.push(child);
        let mut policy = Policy {
            default: PolicyDefault::Deny,
            path_roots: Vec::new(),
            limits: PolicyLimits::default(),
            rules: BTreeMap::new(),
        };
        policy.limits.max_depth = Some(1);
        policy.limits.max_packages = 1;
        preflight_sources(&policy, &resolution).unwrap();
        policy.limits.max_depth = Some(0);
        assert!(
            preflight_sources(&policy, &resolution)
                .unwrap_err()
                .to_string()
                .contains("depth 1")
        );
        policy.limits.max_depth = Some(1);
        policy.limits.max_packages = 0;
        assert!(preflight_sources(&policy, &resolution).is_err());
        resolution.packages.truncate(1);
        resolution.packages[0].edges.truncate(1);
        preflight_sources(&policy, &resolution).unwrap();
        resolution.packages[0].edges[0].kind = crate::sparse::DependencyKind::Normal;
        assert!(
            preflight_sources(&policy, &resolution)
                .unwrap_err()
                .to_string()
                .contains("cycle")
        );
    }

    #[test]
    fn two_pass_default_deny_waits_for_license_and_honors_vetoes() {
        let package = registry_package("demo", "1.2.3", 4);
        let resolution = make_resolution(vec![package.clone()]);
        let mut policy = Policy::default();
        policy.rules.insert(
            "allow-demo".to_owned(),
            rule(PolicyAction::Allow, Some(hex(&checksum(4))), Some("MIT")),
        );
        let pass = preflight(&policy, &resolution).unwrap();
        let evidence = BTreeMap::from([(package.key.clone(), evidence(&package, false))]);
        let admission = inspect(&pass, &resolution, &evidence).unwrap();
        assert_eq!(
            admission.packages[&package.key].matching_allow_rules,
            ["allow-demo"]
        );

        policy.rules.insert(
            "deny-demo".to_owned(),
            rule(PolicyAction::Deny, Some(hex(&checksum(4))), Some("MIT")),
        );
        let pass = preflight(&policy, &resolution).unwrap();
        let error = inspect(&pass, &resolution, &evidence).unwrap_err();
        assert!(error.to_string().contains("deny-demo"));
        assert!(error.to_string().contains("/system/lorry.toml"));
    }

    #[test]
    fn preflight_rejects_default_deny_without_a_possible_allow() {
        let package = registry_package("demo", "1.2.3", 4);
        let resolution = make_resolution(vec![package]);
        let error = preflight(&Policy::default(), &resolution).unwrap_err();
        assert!(error.to_string().contains("not admitted"));
        assert!(error.render().contains("[policy.rules.allow-demo-1_2_3]"));
        assert!(error.render().contains(&hex(&checksum(4))));
    }

    #[test]
    fn build_scripts_need_an_explicit_grant_even_under_default_allow() {
        let package = registry_package("demo", "1.2.3", 4);
        let resolution = make_resolution(vec![package.clone()]);
        let mut policy = Policy {
            default: PolicyDefault::Allow,
            path_roots: Vec::new(),
            limits: PolicyLimits::default(),
            rules: BTreeMap::new(),
        };
        let pass = preflight(&policy, &resolution).unwrap();
        let evidence = BTreeMap::from([(package.key.clone(), evidence(&package, true))]);
        let error = inspect(&pass, &resolution, &evidence).unwrap_err();
        assert!(error.to_string().contains("build script"));

        let mut allow = rule(PolicyAction::Allow, None, None);
        allow.allow_build_script = true;
        policy.rules.insert("allow-script".to_owned(), allow);
        let pass = preflight(&policy, &resolution).unwrap();
        inspect(&pass, &resolution, &evidence).unwrap();
    }

    #[test]
    fn procedural_macros_need_an_explicit_grant() {
        let package = path_package(Path::new("/allowed/local-demo"), false, true);
        let resolution = make_resolution(vec![package.clone()]);
        let mut policy = Policy::default();
        policy.path_roots.push(Path::new("/allowed").to_owned());
        assert!(
            preflight(&policy, &resolution)
                .unwrap_err()
                .to_string()
                .contains("procedural macro")
        );

        policy.rules.insert(
            "allow-local-proc-macro".to_owned(),
            PolicyRule {
                action: PolicyAction::Allow,
                name: Some("local-demo".to_owned()),
                version: Some(VersionReq::parse("=1.2.3").unwrap()),
                source: Some("path".to_owned()),
                checksum: None,
                source_tree_sha256: Some(hex(&checksum(7))),
                license: Some("MIT".to_owned()),
                allow_build_script: false,
                allow_proc_macro: true,
                native_tools: BTreeSet::new(),
                caller_env: Default::default(),
                provenance: Path::new("/system/lorry.toml").to_owned(),
            },
        );
        let pass = preflight(&policy, &resolution).unwrap();
        let evidence = BTreeMap::from([(
            package.key.clone(),
            PackageEvidence {
                license: "MIT".to_owned(),
                build_script: false,
                proc_macro: true,
                newly_acquired: false,
                archive_bytes: None,
                extracted_bytes: 10,
                file_count: 1,
                source_tree_sha256: checksum(7),
            },
        )]);
        inspect(&pass, &resolution, &evidence).unwrap();
    }

    #[test]
    fn local_paths_only_need_rules_for_roots_denies_or_build_scripts() {
        let package = path_package(Path::new("/allowed/local-demo"), false, false);
        let resolution = make_resolution(vec![package.clone()]);
        let mut policy = Policy::default();
        policy.path_roots.push(Path::new("/allowed").to_owned());
        let pass = preflight(&policy, &resolution).unwrap();
        let evidence = BTreeMap::from([(
            package.key.clone(),
            PackageEvidence {
                license: "MIT".to_owned(),
                build_script: false,
                proc_macro: false,
                newly_acquired: false,
                archive_bytes: None,
                extracted_bytes: 10,
                file_count: 1,
                source_tree_sha256: checksum(7),
            },
        )]);
        inspect(&pass, &resolution, &evidence).unwrap();

        policy.path_roots = vec![Path::new("/different-root").to_owned()];
        assert!(
            preflight(&policy, &resolution)
                .unwrap_err()
                .to_string()
                .contains("path-roots")
        );

        let package = path_package(Path::new("/allowed/local-demo"), true, false);
        let resolution = make_resolution(vec![package.clone()]);
        policy.path_roots = vec![Path::new("/allowed").to_owned()];
        assert!(
            preflight(&policy, &resolution)
                .unwrap_err()
                .to_string()
                .contains("build script")
        );

        policy.rules.insert(
            "allow-local-script".to_owned(),
            PolicyRule {
                action: PolicyAction::Allow,
                name: Some("local-demo".to_owned()),
                version: Some(VersionReq::parse("=1.2.3").unwrap()),
                source: Some("path".to_owned()),
                checksum: None,
                source_tree_sha256: Some(hex(&checksum(7))),
                license: Some("MIT".to_owned()),
                allow_build_script: true,
                allow_proc_macro: false,
                native_tools: BTreeSet::from([NativeToolRole::CCompiler]),
                caller_env: Default::default(),
                provenance: Path::new("/system/lorry.toml").to_owned(),
            },
        );
        let pass = preflight(&policy, &resolution).unwrap();
        let evidence = BTreeMap::from([(
            package.key.clone(),
            PackageEvidence {
                license: "MIT".to_owned(),
                build_script: true,
                proc_macro: false,
                newly_acquired: false,
                archive_bytes: None,
                extracted_bytes: 10,
                file_count: 1,
                source_tree_sha256: checksum(7),
            },
        )]);
        let admission = inspect(&pass, &resolution, &evidence).unwrap();
        assert_eq!(
            admission.packages[&package.key].native_tools,
            BTreeSet::from([NativeToolRole::CCompiler])
        );
    }

    #[test]
    fn member_build_time_grants_are_named_and_unpinned_tools_stay_with_members() {
        let mut package = path_package(Path::new("/ws/local-demo"), true, true);
        package.local_manifest.as_mut().unwrap().editable = true;
        let evidence = BTreeMap::from([(
            package.key.clone(),
            PackageEvidence {
                license: "MIT".to_owned(),
                build_script: true,
                proc_macro: true,
                newly_acquired: false,
                archive_bytes: None,
                extracted_bytes: 10,
                file_count: 1,
                source_tree_sha256: checksum(7),
            },
        )]);
        let mut grant = rule(PolicyAction::Allow, None, None);
        grant.source = Some("path".into());
        grant.name = Some(package.key.name.clone());
        grant.allow_build_script = true;
        grant.allow_proc_macro = true;
        grant.native_tools.insert(NativeToolRole::CCompiler);
        grant.caller_env.insert("PUBLIC".into());
        let mut policy = Policy::default();
        for name in [None, Some("other".to_owned()), grant.name.clone()] {
            let mut candidate = grant.clone();
            candidate.name = name.clone();
            policy.rules.insert("member".into(), candidate);
            let resolution = make_resolution(vec![package.clone()]);
            let result = preflight(&policy, &resolution);
            assert_eq!(result.is_ok(), name == grant.name);
            if let Ok(pass) = result {
                let admission = inspect(&pass, &resolution, &evidence).unwrap();
                assert_eq!(
                    admission.packages[&package.key].native_tools,
                    grant.native_tools
                );
                assert_eq!(
                    admission.packages[&package.key].caller_env,
                    grant.caller_env
                );
            }
            // Inspection must enforce the grants even when source-only
            // preparation had not yet discovered build-time code.
            let mut unknown = package.clone();
            let manifest = unknown.local_manifest.as_mut().unwrap();
            manifest.build_script = None;
            manifest.library = None;
            let unknown_resolution = make_resolution(vec![unknown]);
            let pass = preflight(&policy, &unknown_resolution).unwrap();
            assert_eq!(
                inspect(&pass, &unknown_resolution, &evidence).is_ok(),
                name == grant.name
            );
        }
        let resolution = make_resolution(vec![package.clone()]);
        policy.rules.get_mut("member").unwrap().allow_proc_macro = false;
        assert!(
            preflight(&policy, &resolution)
                .unwrap_err()
                .render()
                .contains("procedural macro")
        );
        policy.rules.insert("member".into(), grant.clone());
        package.local_manifest.as_mut().unwrap().editable = false;
        let outside = make_resolution(vec![package]);
        assert!(
            preflight(&policy, &outside)
                .unwrap_err()
                .render()
                .contains("build script")
        );
        policy.rules.get_mut("member").unwrap().source_tree_sha256 = Some(hex(&checksum(7)));
        let pass = preflight(&policy, &outside).unwrap();
        inspect(&pass, &outside, &evidence).unwrap();
    }

    #[test]
    fn graph_and_artifact_limits_are_enforced_in_their_earliest_pass() {
        let mut first = registry_package("demo", "1.2.3", 4);
        let second = registry_package("child", "2.0.0", 5);
        first.edges.push(ResolvedEdge {
            dependency_index: 0,
            alias: "child".to_owned(),
            target: None,
            kind: crate::sparse::DependencyKind::Normal,
            parent_compile_kind: Some(crate::resolver::CompileKind::Target),
            compile_kind: crate::resolver::CompileKind::Target,
            context: FeatureContext::Target(String::new()),
            package: second.key.clone(),
        });
        let resolution = Resolution {
            root_edges: vec![ResolvedEdge {
                dependency_index: 0,
                alias: "demo".to_owned(),
                target: None,
                kind: crate::sparse::DependencyKind::Normal,
                parent_compile_kind: None,
                compile_kind: crate::resolver::CompileKind::Target,
                context: FeatureContext::Target(String::new()),
                package: first.key.clone(),
            }],
            packages: vec![first.clone(), second.clone()],
        };
        let mut policy = Policy {
            default: PolicyDefault::Allow,
            path_roots: Vec::new(),
            limits: PolicyLimits::default(),
            rules: BTreeMap::new(),
        };
        policy.limits.max_depth = Some(1);
        assert!(
            preflight(&policy, &resolution)
                .unwrap_err()
                .to_string()
                .contains("depth")
        );

        policy.limits.max_depth = Some(2);
        policy.limits.max_package_bytes = 99;
        let pass = preflight(&policy, &resolution).unwrap();
        let evidence = BTreeMap::from([
            (first.key.clone(), evidence(&first, false)),
            (second.key.clone(), evidence(&second, false)),
        ]);
        assert!(
            inspect(&pass, &resolution, &evidence)
                .unwrap_err()
                .to_string()
                .contains("package-byte")
        );

        policy.limits.max_package_bytes = 100;
        policy.limits.max_transaction_bytes = 150;
        let pass = preflight(&policy, &resolution).unwrap();
        assert!(
            inspect(&pass, &resolution, &evidence)
                .unwrap_err()
                .to_string()
                .contains("transaction limit")
        );

        let existing = evidence
            .into_iter()
            .map(|(key, mut evidence)| {
                evidence.newly_acquired = false;
                (key, evidence)
            })
            .collect();
        inspect(&pass, &resolution, &existing).unwrap();
    }
}
