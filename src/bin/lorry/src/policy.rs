#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use semver::Version;

use crate::config::{NativeToolRole, Policy, PolicyAction, PolicyDefault, PolicyRule};
use crate::diagnostic::{Error, Result};
use crate::hash::hex;
use crate::manifest::Manifest;
use crate::repository::RegistryObject;
use crate::resolver::{PackageKey, PackageSourceKey, Resolution, ResolvedPackage, ResolvedSource};
use crate::source_tree::{DEFAULT_LIMITS, Exclusions, Tree};

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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SourceKind {
    CratesIo,
    Path,
    SystemVendoredPath,
}

impl SourceKind {
    fn policy_name(self) -> &'static str {
        match self {
            Self::CratesIo => "crates.io",
            Self::Path => "path",
            Self::SystemVendoredPath => "system-vendored-path",
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
    package: &'a ResolvedPackage,
    source: SourceKind,
    checksum: Fact,
    source_tree_sha256: Fact,
    license: Fact,
}

pub fn preflight(policy: &Policy, resolution: &Resolution) -> Result<Preflight> {
    if resolution.packages.len() as u64 > policy.limits.max_packages {
        return Err(Error::failure(format!(
            "selected package count {} exceeds policy limit {}",
            resolution.packages.len(),
            policy.limits.max_packages
        )));
    }
    let depth = selected_depth(resolution)?;
    if depth > policy.limits.max_depth {
        return Err(Error::failure(format!(
            "selected dependency depth {depth} exceeds policy limit {}",
            policy.limits.max_depth
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
                return Err(denied_by_rule(package, id, rule));
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
                .any(|id| script_rule_authorizes(&policy.rules[id], facts.source))
        {
            return Err(build_script_not_admitted(package, &facts, None));
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
    if evidence.keys().cloned().collect::<BTreeSet<_>>() != selected {
        return Err(Error::failure(
            "second policy pass does not have exact evidence for every selected package",
        ));
    }

    let mut compressed_total = 0_u64;
    let mut extracted_total = 0_u64;
    let mut admitted = BTreeMap::new();
    for package in &resolution.packages {
        let evidence = &evidence[&package.key];
        check_evidence_identity(package, evidence)?;
        check_package_limits(&preflight.policy, package, evidence)?;
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
                package,
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
            .filter(|id| script_rule_authorizes(&preflight.policy.rules[id.as_str()], source))
            .copied()
            .collect::<Vec<_>>();
        if evidence.build_script && script_allows.is_empty() {
            return Err(build_script_not_admitted(package, &facts, Some(evidence)));
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
        admitted.insert(
            package.key.clone(),
            PackageAdmission {
                matching_allow_rules: allows.into_iter().cloned().collect(),
                native_tools,
            },
        );
    }

    if compressed_total > preflight.policy.limits.max_transaction_bytes {
        return Err(Error::failure(format!(
            "selected crates.io archives total {compressed_total} bytes, exceeding policy transaction limit {}",
            preflight.policy.limits.max_transaction_bytes
        )));
    }
    if extracted_total > preflight.policy.limits.max_extracted_transaction_bytes {
        return Err(Error::failure(format!(
            "selected crates.io sources total {extracted_total} extracted bytes, exceeding policy transaction limit {}",
            preflight.policy.limits.max_extracted_transaction_bytes
        )));
    }
    Ok(Admission { packages: admitted })
}

impl PackageEvidence {
    pub fn from_registry(
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
        let tree = Tree::scan(&manifest.root, DEFAULT_LIMITS, Exclusions::None)?;
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
        Ok(Self {
            license: manifest.metadata.license.clone(),
            build_script: manifest.build_script.is_some(),
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
        let tree = Tree::scan(physical_root, DEFAULT_LIMITS, Exclusions::GitAndTarget)?;
        if tree.sha256 != *source_tree_sha256 {
            return Err(Error::failure(format!(
                "path source for `{} {}` changed after resolution",
                package.key.name, package.key.version
            )));
        }
        Ok(Self {
            license: manifest.metadata.license.clone(),
            build_script: manifest.build_script.is_some(),
            newly_acquired: false,
            archive_bytes: None,
            extracted_bytes: tree.total_bytes,
            file_count: tree.file_count as u64,
            source_tree_sha256: tree.sha256,
        })
    }
}

fn preliminary_facts(package: &ResolvedPackage) -> Facts<'_> {
    match &package.source {
        ResolvedSource::CratesIo { checksum } => Facts {
            package,
            source: SourceKind::CratesIo,
            checksum: Fact::Value(hex(checksum)),
            source_tree_sha256: Fact::Unknown,
            license: Fact::Unknown,
        },
        ResolvedSource::Path {
            source_tree_sha256,
            required_patch,
            ..
        } => Facts {
            package,
            source: if required_patch.is_some() {
                SourceKind::SystemVendoredPath
            } else {
                SourceKind::Path
            },
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
        ResolvedSource::Path { .. } => Fact::Absent,
    };
    Facts {
        package,
        source,
        checksum,
        source_tree_sha256: Fact::Value(hex(&evidence.source_tree_sha256)),
        license: Fact::Value(evidence.license.clone()),
    }
}

fn source_kind(package: &ResolvedPackage) -> SourceKind {
    match &package.source {
        ResolvedSource::CratesIo { .. } => SourceKind::CratesIo,
        ResolvedSource::Path {
            required_patch: Some(_),
            ..
        } => SourceKind::SystemVendoredPath,
        ResolvedSource::Path { .. } => SourceKind::Path,
    }
}

fn base_requires_allow(policy: &Policy, source: SourceKind) -> bool {
    source == SourceKind::SystemVendoredPath
        || (source == SourceKind::CratesIo && policy.default == PolicyDefault::Deny)
}

fn check_path_root(policy: &Policy, package: &ResolvedPackage) -> Result<()> {
    let ResolvedSource::Path {
        physical_root,
        required_patch: None,
        ..
    } = &package.source
    else {
        return Ok(());
    };
    if policy.path_roots.is_empty()
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
        .is_none_or(|name| name == &facts.package.key.name)
        && rule
            .version
            .as_ref()
            .is_none_or(|version| version.matches(&facts.package.key.version))
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

fn script_rule_authorizes(rule: &PolicyRule, source: SourceKind) -> bool {
    if rule.action != PolicyAction::Allow || !rule.allow_build_script {
        return false;
    }
    match source {
        SourceKind::CratesIo => true,
        SourceKind::Path | SourceKind::SystemVendoredPath => {
            rule.source.as_deref() == Some(source.policy_name())
        }
    }
}

fn check_evidence_identity(package: &ResolvedPackage, evidence: &PackageEvidence) -> Result<()> {
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
    let packages = resolution
        .packages
        .iter()
        .map(|package| (package.key.clone(), package))
        .collect::<BTreeMap<_, _>>();
    let mut memo = BTreeMap::new();
    let mut visiting = BTreeSet::new();
    let mut depth = 0;
    for edge in &resolution.root_edges {
        depth = depth.max(tail_depth(
            &edge.package,
            &packages,
            &mut memo,
            &mut visiting,
        )?);
    }
    if memo.len() != packages.len() {
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
) -> Result<u64> {
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
        depth = depth.max(
            1_u64
                .checked_add(tail_depth(&edge.package, packages, memo, visiting)?)
                .ok_or_else(|| Error::failure("policy dependency depth overflowed"))?,
        );
    }
    visiting.remove(key);
    memo.insert(key.clone(), depth);
    Ok(depth)
}

fn denied_by_rule(package: &ResolvedPackage, id: &str, rule: &PolicyRule) -> Error {
    Error::failure(format!(
        "package `{} {}` is denied by policy rule `{id}` from `{}`",
        package.key.name,
        package.key.version,
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
    .with_help(exact_allow_example(package, facts, evidence, false))
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
    .with_help(exact_allow_example(package, facts, evidence, true))
}

fn exact_allow_example(
    package: &ResolvedPackage,
    facts: &Facts<'_>,
    evidence: Option<&PackageEvidence>,
    allow_build_script: bool,
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
    use crate::config::{Config, PolicyLimits, PolicyRule};
    use crate::repository::RepositorySet;
    use crate::resolver::{FeatureContext, PackageSourceKey, ResolvedEdge};
    use semver::VersionReq;
    use std::fs;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("lorry-policy-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

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
            target_features: BTreeSet::new(),
            host_features: BTreeSet::new(),
            edges: Vec::new(),
            lock_edges: Vec::new(),
        }
    }

    fn path_package(root: &Path, build_script: bool) -> ResolvedPackage {
        let build = if build_script {
            "build = \"build.rs\""
        } else {
            "build = false"
        };
        let manifest = Manifest::parse(
            root,
            &root.join("Cargo.toml"),
            &format!(
                "[package]\nname = \"local-demo\"\nversion = \"1.2.3\"\n\
                 edition = \"2021\"\nlicense = \"MIT\"\n{build}\n"
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
                required_patch: None,
            },
            local_manifest: Some(manifest),
            feature_sets: BTreeMap::new(),
            target_features: BTreeSet::new(),
            host_features: BTreeSet::new(),
            edges: Vec::new(),
            lock_edges: Vec::new(),
        }
    }

    fn make_resolution(packages: Vec<ResolvedPackage>) -> Resolution {
        let root_edges = packages
            .iter()
            .enumerate()
            .map(|(dependency_index, package)| ResolvedEdge {
                dependency_index,
                alias: package.key.name.clone(),
                kind: crate::sparse::DependencyKind::Normal,
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
            native_tools: BTreeSet::new(),
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
            newly_acquired: true,
            archive_bytes: Some(100),
            extracted_bytes: 200,
            file_count: 2,
            source_tree_sha256: checksum(9),
        }
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
    fn local_paths_only_need_rules_for_roots_denies_or_build_scripts() {
        let package = path_package(Path::new("/allowed/local-demo"), false);
        let resolution = make_resolution(vec![package.clone()]);
        let mut policy = Policy::default();
        policy.path_roots.push(Path::new("/allowed").to_owned());
        let pass = preflight(&policy, &resolution).unwrap();
        let evidence = BTreeMap::from([(
            package.key.clone(),
            PackageEvidence {
                license: "MIT".to_owned(),
                build_script: false,
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

        let package = path_package(Path::new("/allowed/local-demo"), true);
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
                native_tools: BTreeSet::from([NativeToolRole::CCompiler]),
                provenance: Path::new("/system/lorry.toml").to_owned(),
            },
        );
        let pass = preflight(&policy, &resolution).unwrap();
        let evidence = BTreeMap::from([(
            package.key.clone(),
            PackageEvidence {
                license: "MIT".to_owned(),
                build_script: true,
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
    fn graph_and_artifact_limits_are_enforced_in_their_earliest_pass() {
        let mut first = registry_package("demo", "1.2.3", 4);
        let second = registry_package("child", "2.0.0", 5);
        first.edges.push(ResolvedEdge {
            dependency_index: 0,
            alias: "child".to_owned(),
            kind: crate::sparse::DependencyKind::Normal,
            context: FeatureContext::Target(String::new()),
            package: second.key.clone(),
        });
        let resolution = Resolution {
            root_edges: vec![ResolvedEdge {
                dependency_index: 0,
                alias: "demo".to_owned(),
                kind: crate::sparse::DependencyKind::Normal,
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
        policy.limits.max_depth = 1;
        assert!(
            preflight(&policy, &resolution)
                .unwrap_err()
                .to_string()
                .contains("depth")
        );

        policy.limits.max_depth = 2;
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

    #[test]
    fn admits_every_object_with_the_external_generated_policy_when_requested() {
        let Some(repository) = std::env::var_os("LORRY_TEST_SEEDED_REPOSITORY") else {
            return;
        };
        let repository = PathBuf::from(repository);
        let generated = repository.parent().unwrap().join("lorry.toml");
        assert!(generated.is_file());

        let fixture = Fixture::new();
        let home_config = fixture.0.join("home/.config/lorry");
        fs::create_dir_all(&home_config).unwrap();
        fs::copy(&generated, home_config.join("lorry.toml")).unwrap();
        let config = Config::load_for_test(
            Path::new("."),
            &BTreeMap::from([(
                "HOME".to_owned(),
                fixture.0.join("home").display().to_string(),
            )]),
        )
        .unwrap();
        let repositories = RepositorySet::open(
            &config.repositories,
            DEFAULT_LIMITS,
            config.policy.limits.max_package_bytes,
        )
        .unwrap();

        let mut packages = Vec::new();
        let mut evidence = BTreeMap::new();
        let namespace = repository.join("objects/crates-io/sha256");
        for prefix in fs::read_dir(namespace).unwrap() {
            for entry in fs::read_dir(prefix.unwrap().path()).unwrap() {
                let checksum = entry
                    .unwrap()
                    .file_name()
                    .into_string()
                    .expect("object address is UTF-8");
                let object = repositories.lookup_registry(&checksum).unwrap().unwrap();
                let manifest = Manifest::load_path_dependency(&object.root.join("source")).unwrap();
                let package = ResolvedPackage {
                    key: PackageKey {
                        name: object.name.clone(),
                        version: object.version.clone(),
                        source: PackageSourceKey::CratesIo,
                    },
                    source: ResolvedSource::CratesIo {
                        checksum: object.checksum,
                    },
                    local_manifest: None,
                    feature_sets: BTreeMap::new(),
                    target_features: BTreeSet::new(),
                    host_features: BTreeSet::new(),
                    edges: Vec::new(),
                    lock_edges: Vec::new(),
                };
                let inspected =
                    PackageEvidence::from_registry(&package, &object, &manifest, false).unwrap();
                evidence.insert(package.key.clone(), inspected);
                packages.push(package);
            }
        }

        let rule = &config.required_patches["ring-0_17_14"];
        let object = repositories
            .lookup_seeded_git(&rule.source_tree_sha256)
            .unwrap()
            .unwrap();
        let manifest = Manifest::load_path_dependency(&object.root.join("source")).unwrap();
        let logical_root = PathBuf::from("/fixture/.lorry/vendor/ring-0_17_14/source");
        let ring = ResolvedPackage {
            key: PackageKey {
                name: object.name.clone(),
                version: object.version.clone(),
                source: PackageSourceKey::Path(logical_root.clone()),
            },
            source: ResolvedSource::Path {
                logical_root,
                physical_root: manifest.root.clone(),
                source_tree_sha256: object.source_tree_sha256,
                patched_crates_io: true,
                required_patch: Some("ring-0_17_14".to_owned()),
            },
            local_manifest: Some(manifest),
            feature_sets: BTreeMap::new(),
            target_features: BTreeSet::new(),
            host_features: BTreeSet::new(),
            edges: Vec::new(),
            lock_edges: Vec::new(),
        };
        evidence.insert(ring.key.clone(), PackageEvidence::from_path(&ring).unwrap());
        packages.push(ring);

        packages.sort_by(|left, right| left.key.cmp(&right.key));
        let resolution = make_resolution(packages);
        let pass = preflight(&config.policy, &resolution).unwrap();
        let admission = inspect(&pass, &resolution, &evidence).unwrap();
        assert_eq!(admission.packages.len(), 46);
    }
}
