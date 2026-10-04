#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use semver::Version;

use crate::diagnostic::{Error, Result};
use crate::hash::hex;
use crate::manifest::{LockedPackage, Lockfile, Manifest};
use crate::resolver::{PackageKey, PackageSourceKey, Resolution, ResolvedSource};

const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

pub fn validate_resolution(manifest: &Manifest, resolution: &Resolution) -> Result<()> {
    validate(manifest, resolution, EdgeMode::Exact)
}

pub fn validate_selected_resolution(manifest: &Manifest, resolution: &Resolution) -> Result<()> {
    validate(manifest, resolution, EdgeMode::SelectedSubset)
}

fn validate(manifest: &Manifest, resolution: &Resolution, edge_mode: EdgeMode) -> Result<()> {
    let lock = manifest
        .lock
        .as_ref()
        .ok_or_else(|| stale("Cargo.lock is missing"))?;
    let root = lock
        .packages
        .iter()
        .find(|package| {
            package.name == manifest.name
                && package.version.original == manifest.version.original
                && package.source.is_none()
        })
        .ok_or_else(|| {
            stale(format!(
                "Cargo.lock has no root path package `{} {}`",
                manifest.name, manifest.version.original
            ))
        })?;
    let source_kinds = source_kinds(resolution);
    validate_edges(
        "root package",
        &resolution.root_edges,
        &root.dependencies,
        &lock.packages,
        &source_kinds,
        edge_mode,
        lock.format,
    )?;

    validate_packages(lock, resolution, &source_kinds, edge_mode)
}

/// Workspace roots are ordinary packages; no synthetic root edges are locked.
pub(crate) fn validate_workspace_resolution(
    lock: &Lockfile,
    resolution: &Resolution,
) -> Result<()> {
    validate_packages(lock, resolution, &source_kinds(resolution), EdgeMode::Exact)
}

fn source_kinds(resolution: &Resolution) -> BTreeMap<PackageKey, Option<String>> {
    resolution
        .packages
        .iter()
        .map(|package| {
            (
                package.key.clone(),
                match &package.source {
                    ResolvedSource::CratesIo { .. } => Some(CRATES_IO_SOURCE.to_owned()),
                    ResolvedSource::Git { cargo_source, .. } => Some(cargo_source.clone()),
                    ResolvedSource::Path { .. } => None,
                },
            )
        })
        .collect()
}

fn validate_packages(
    lock: &Lockfile,
    resolution: &Resolution,
    source_kinds: &BTreeMap<PackageKey, Option<String>>,
    edge_mode: EdgeMode,
) -> Result<()> {
    let mut selected = BTreeSet::new();
    for package in &resolution.packages {
        if !selected.insert(package.key.clone()) {
            return Err(Error::failure(format!(
                "resolver returned duplicate package `{} {}`",
                package.key.name, package.key.version
            )));
        }
        let locked = match &package.source {
            ResolvedSource::CratesIo { checksum } => {
                let locked = find_registry_package(&lock.packages, &package.key)?;
                let expected_checksum = hex(checksum);
                if locked.checksum.as_deref() != Some(expected_checksum.as_str()) {
                    return Err(stale(format!(
                        "Cargo.lock checksum for `{} {}` does not match the resolved sparse-index checksum",
                        package.key.name, package.key.version
                    )));
                }
                locked
            }
            ResolvedSource::Git { cargo_source, .. } => {
                find_git_package(&lock.packages, &package.key, cargo_source)?
            }
            ResolvedSource::Path { .. } => find_path_package(&lock.packages, &package.key)?,
        };
        validate_edges(
            &format!("package `{} {}`", package.key.name, package.key.version),
            &package.lock_edges,
            &locked.dependencies,
            &lock.packages,
            source_kinds,
            edge_mode,
            lock.format,
        )?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum EdgeMode {
    Exact,
    SelectedSubset,
}

fn find_registry_package<'a>(
    packages: &'a [LockedPackage],
    key: &PackageKey,
) -> Result<&'a LockedPackage> {
    if key.source != PackageSourceKey::CratesIo {
        return Err(stale(format!(
            "resolved package `{} {}` has inconsistent crates.io source identity",
            key.name, key.version
        )));
    }
    packages
        .iter()
        .find(|package| {
            package.name == key.name
                && package.source.as_deref() == Some(CRATES_IO_SOURCE)
                && Version::parse(&package.version.original)
                    .is_ok_and(|version| version == key.version)
        })
        .ok_or_else(|| {
            stale(format!(
                "Cargo.lock has no crates.io package `{} {}`",
                key.name, key.version
            ))
        })
}

fn find_path_package<'a>(
    packages: &'a [LockedPackage],
    key: &PackageKey,
) -> Result<&'a LockedPackage> {
    if !matches!(key.source, PackageSourceKey::Path(_)) {
        return Err(stale(format!(
            "resolved package `{} {}` has inconsistent path source identity",
            key.name, key.version
        )));
    }
    packages
        .iter()
        .find(|package| {
            package.name == key.name
                && package.source.is_none()
                && Version::parse(&package.version.original)
                    .is_ok_and(|version| version == key.version)
        })
        .ok_or_else(|| {
            stale(format!(
                "Cargo.lock has no local path package `{} {}`",
                key.name, key.version
            ))
        })
}

fn find_git_package<'a>(
    packages: &'a [LockedPackage],
    key: &PackageKey,
    cargo_source: &str,
) -> Result<&'a LockedPackage> {
    if key.source != PackageSourceKey::Git(cargo_source.to_owned()) {
        return Err(stale(format!(
            "resolved package `{} {}` has inconsistent Git source identity",
            key.name, key.version
        )));
    }
    packages
        .iter()
        .find(|package| {
            package.name == key.name
                && package.source.as_deref() == Some(cargo_source)
                && Version::parse(&package.version.original)
                    .is_ok_and(|version| version == key.version)
        })
        .ok_or_else(|| {
            stale(format!(
                "Cargo.lock has no Git package `{} {}` from `{cargo_source}`",
                key.name, key.version
            ))
        })
}

fn validate_edges(
    owner: &str,
    resolved: &[crate::resolver::ResolvedEdge],
    locked: &[String],
    packages: &[LockedPackage],
    source_kinds: &BTreeMap<PackageKey, Option<String>>,
    mode: EdgeMode,
    format: crate::lockfile::Format,
) -> Result<()> {
    let expected = resolved
        .iter()
        .map(|edge| {
            let source = source_kinds.get(&edge.package).ok_or_else(|| {
                Error::failure(format!(
                    "resolver edge references absent package `{} {}`",
                    edge.package.name, edge.package.version
                ))
            })?;
            Ok(LockKey {
                name: edge.package.name.clone(),
                version: edge.package.version.clone(),
                source: source.clone(),
            })
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let mut actual = BTreeSet::new();
    let mut exact_references = BTreeSet::new();
    for reference in locked {
        if !exact_references.insert(reference) {
            return Err(stale(format!(
                "{owner} repeats Cargo.lock dependency reference `{reference}`"
            )));
        }
        let package = resolve_lock_reference(reference, packages, format)?;
        actual.insert(LockKey {
            name: package.name.clone(),
            version: Version::parse(&package.version.original).map_err(|error| {
                stale(format!(
                    "Cargo.lock dependency `{reference}` has an invalid version: {error}"
                ))
            })?,
            source: package.source.clone(),
        });
    }
    let agrees = match mode {
        EdgeMode::Exact => actual == expected,
        EdgeMode::SelectedSubset => expected.is_subset(&actual),
    };
    if !agrees {
        return Err(stale(format!(
            "{owner} dependency edges disagree with Cargo.lock: resolved [{}], locked [{}]",
            display_keys(&expected),
            display_keys(&actual)
        )));
    }
    Ok(())
}

pub(crate) fn resolve_lock_reference<'a>(
    reference: &str,
    packages: &'a [LockedPackage],
    format: crate::lockfile::Format,
) -> Result<&'a LockedPackage> {
    let (identity, source) = match reference.strip_suffix(')') {
        Some(without_close) => {
            let (identity, source) = without_close.rsplit_once(" (").ok_or_else(|| {
                stale(format!(
                    "malformed Cargo.lock dependency reference `{reference}`"
                ))
            })?;
            (identity, Some(source))
        }
        None => (reference, None),
    };
    let mut parts = identity.split_whitespace();
    let name = parts.next().ok_or_else(|| {
        stale(format!(
            "malformed empty Cargo.lock dependency reference `{reference}`"
        ))
    })?;
    let version = parts.next();
    if parts.next().is_some() || (source.is_some() && version.is_none()) {
        return Err(stale(format!(
            "malformed Cargo.lock dependency reference `{reference}`"
        )));
    }
    let version = version
        .map(|value| {
            Version::parse(value).map_err(|error| {
                stale(format!(
                    "malformed version in Cargo.lock dependency reference `{reference}`: {error}"
                ))
            })
        })
        .transpose()?;

    let matches = packages
        .iter()
        .filter(|package| package.name == name)
        .filter(|package| {
            version.as_ref().is_none_or(|version| {
                Version::parse(&package.version.original)
                    .is_ok_and(|candidate| candidate == *version)
            })
        })
        .filter(|package| {
            source.is_none_or(|source| {
                package
                    .source
                    .as_deref()
                    .is_some_and(|locked| lock_source_matches(source, locked, format))
            })
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [package] => Ok(package),
        [] => Err(stale(format!(
            "Cargo.lock dependency reference `{reference}` selects no package node"
        ))),
        packages if source.is_none() => {
            let path_packages = packages
                .iter()
                .filter(|package| package.source.is_none())
                .collect::<Vec<_>>();
            match path_packages.as_slice() {
                [package] => Ok(package),
                _ => Err(stale(format!(
                    "Cargo.lock dependency reference `{reference}` is ambiguous"
                ))),
            }
        }
        _ => Err(stale(format!(
            "Cargo.lock dependency reference `{reference}` is ambiguous"
        ))),
    }
}

pub(crate) fn lock_source_matches(
    reference: &str,
    locked: &str,
    format: crate::lockfile::Format,
) -> bool {
    if reference == locked {
        return true;
    }
    if !reference.starts_with("git+") || reference.contains('#') {
        return false;
    }
    let Some((remote, _)) = locked.rsplit_once('#') else {
        return false;
    };
    // Cargo's legacy dependency encoding omits master; package source IDs
    // remain distinct. Never apply this equivalence to modern references.
    remote == reference
        || (matches!(
            format,
            crate::lockfile::Format::V1 | crate::lockfile::Format::V2
        ) && remote.strip_suffix("?branch=master") == Some(reference))
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LockKey {
    name: String,
    version: Version,
    source: Option<String>,
}

fn display_keys(keys: &BTreeSet<LockKey>) -> String {
    keys.iter()
        .map(|key| {
            format!(
                "{} {} ({})",
                key.name,
                key.version,
                key.source.as_deref().unwrap_or("path")
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn stale(message: impl Into<String>) -> Error {
    Error::failure(format!("Cargo.lock is stale: {}", message.into())).with_help(
        "run `lorry vendor [--accept-all]` to validate and transactionally update Cargo.lock",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::config::IncompatibleRustVersions;
    use crate::manifest::Resolver;
    use crate::resolver::{Catalog, Options, resolve};
    use crate::sparse::Record;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("lorry-offline-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(path.join("src")).unwrap();
            fs::write(path.join("src/main.rs"), "fn main() {}\n").unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn checksum(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn record(name: &str, version: &str, dependencies: &str, byte: u8) -> Record {
        Record::parse(
            Path::new("/fixture/index-record.json"),
            format!(
                "{{\"name\":\"{name}\",\"vers\":\"{version}\",\"deps\":{dependencies},\
                 \"cksum\":\"{}\",\"features\":{{}},\"yanked\":false}}\n",
                checksum(byte)
            )
            .as_bytes(),
        )
        .unwrap()
    }

    fn dependency(name: &str, requirement: &str) -> String {
        format!(
            "{{\"name\":\"{name}\",\"req\":\"{requirement}\",\"features\":[],\
             \"optional\":false,\"default_features\":true,\"target\":null,\"kind\":\"normal\"}}"
        )
    }

    fn fixture() -> (TempDir, Manifest, Resolution) {
        let temp = TempDir::new();
        fs::write(
            temp.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\na = \"1\"\n",
        )
        .unwrap();
        fs::write(
            temp.0.join("Cargo.lock"),
            format!(
                "version = 4\n\
                 [[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"{CRATES_IO_SOURCE}\"\n\
                 checksum = \"{}\"\ndependencies = [\"b\"]\n\
                 [[package]]\nname = \"b\"\nversion = \"2.0.0\"\nsource = \"{CRATES_IO_SOURCE}\"\n\
                 checksum = \"{}\"\n\
                 [[package]]\nname = \"root\"\nversion = \"0.1.0\"\ndependencies = [\"a\"]\n\
                 [[package]]\nname = \"unused\"\nversion = \"9.0.0\"\nsource = \"{CRATES_IO_SOURCE}\"\n\
                 checksum = \"{}\"\n",
                checksum(0x11),
                checksum(0x22),
                checksum(0x99),
            ),
        )
        .unwrap();
        let manifest = Manifest::load(&temp.0).unwrap();
        let mut catalog = Catalog::default();
        catalog
            .insert(record(
                "a",
                "1.0.0",
                &format!("[{}]", dependency("b", "2")),
                0x11,
            ))
            .unwrap();
        catalog.insert(record("b", "2.0.0", "[]", 0x22)).unwrap();
        let locked =
            crate::resolver::LockedPreference::from_lockfile(manifest.lock.as_ref()).unwrap();
        let resolution = resolve(
            &manifest,
            &catalog,
            &Options {
                resolver: Resolver::V2,
                incompatible_rust_versions: Some(IncompatibleRustVersions::Allow),
                rust_versions: vec![Version::parse("1.98.0").unwrap()],
                package_limit: crate::policy::PackageLimit::with_max(16),
                max_depth: 8,
            },
            &locked,
        )
        .unwrap();
        (temp, manifest, resolution)
    }

    #[test]
    fn accepts_the_selected_subgraph_and_unused_lock_nodes() {
        let (_temp, manifest, resolution) = fixture();
        validate_resolution(&manifest, &resolution).unwrap();
    }

    #[test]
    fn selected_validation_allows_inactive_locked_edges_but_exact_validation_does_not() {
        let (_temp, mut manifest, resolution) = fixture();
        let root = manifest
            .lock
            .as_mut()
            .unwrap()
            .packages
            .iter_mut()
            .find(|package| package.name == "root")
            .unwrap();
        root.dependencies.push("unused".to_owned());

        validate_selected_resolution(&manifest, &resolution).unwrap();
        assert!(
            validate_resolution(&manifest, &resolution)
                .unwrap_err()
                .to_string()
                .contains("dependency edges")
        );
    }

    #[test]
    fn rejects_checksum_node_and_edge_drift() {
        let (_temp, mut manifest, resolution) = fixture();
        let lock = manifest.lock.as_mut().unwrap();
        lock.packages
            .iter_mut()
            .find(|package| package.name == "a")
            .unwrap()
            .checksum = Some(checksum(0xff));
        assert!(
            validate_resolution(&manifest, &resolution)
                .unwrap_err()
                .to_string()
                .contains("checksum")
        );

        let (_temp, mut manifest, resolution) = fixture();
        let lock = manifest.lock.as_mut().unwrap();
        lock.packages
            .iter_mut()
            .find(|package| package.name == "a")
            .unwrap()
            .dependencies
            .clear();
        assert!(
            validate_resolution(&manifest, &resolution)
                .unwrap_err()
                .to_string()
                .contains("dependency edges")
        );

        let (_temp, mut manifest, resolution) = fixture();
        manifest
            .lock
            .as_mut()
            .unwrap()
            .packages
            .retain(|package| package.name != "b");
        assert!(
            validate_resolution(&manifest, &resolution)
                .unwrap_err()
                .to_string()
                .contains("selects no package")
        );
    }

    #[test]
    fn parses_only_unambiguous_cargo_lock_dependency_references() {
        let packages = vec![
            locked("demo", "1.0.0", Some(CRATES_IO_SOURCE)),
            locked("demo", "2.0.0", Some(CRATES_IO_SOURCE)),
            locked("local", "1.0.0", None),
        ];
        assert_eq!(
            resolve_lock_reference("demo 1.0.0", &packages, crate::lockfile::Format::V4)
                .unwrap()
                .version
                .original,
            "1.0.0"
        );
        assert_eq!(
            resolve_lock_reference(
                &format!("demo 2.0.0 ({CRATES_IO_SOURCE})"),
                &packages,
                crate::lockfile::Format::V4
            )
            .unwrap()
            .version
            .original,
            "2.0.0"
        );
        assert!(resolve_lock_reference("demo", &packages, crate::lockfile::Format::V4).is_err());
        assert!(resolve_lock_reference("missing", &packages, crate::lockfile::Format::V4).is_err());
        assert!(
            resolve_lock_reference("demo bad version", &packages, crate::lockfile::Format::V4)
                .is_err()
        );
        assert_eq!(
            resolve_lock_reference("local", &packages, crate::lockfile::Format::V4)
                .unwrap()
                .name,
            "local"
        );
    }

    #[test]
    fn git_dependency_references_omit_the_locked_commit() {
        let source = format!(
            "git+https://example.com/demo?branch=motor#{}",
            "0".repeat(40)
        );
        let packages = [locked("demo", "1.0.0", Some(&source))];
        assert_eq!(
            resolve_lock_reference(
                "demo 1.0.0 (git+https://example.com/demo?branch=motor)",
                &packages,
                crate::lockfile::Format::V4,
            )
            .unwrap()
            .source
            .as_deref(),
            Some(source.as_str())
        );
        assert!(
            resolve_lock_reference(
                "demo 1.0.0 (git+https://example.com/demo?branch=other)",
                &packages,
                crate::lockfile::Format::V4,
            )
            .is_err()
        );
        assert!(
            resolve_lock_reference(
                &format!(
                    "demo 1.0.0 (git+https://example.com/demo?branch=motor#{})",
                    "1".repeat(40)
                ),
                &packages,
                crate::lockfile::Format::V4,
            )
            .is_err()
        );
        let mut ambiguous = packages.to_vec();
        ambiguous.push(LockedPackage {
            source: Some(source.replace(&"0".repeat(40), &"1".repeat(40))),
            ..packages[0].clone()
        });
        assert!(
            resolve_lock_reference(
                "demo 1.0.0 (git+https://example.com/demo?branch=motor)",
                &ambiguous,
                crate::lockfile::Format::V4,
            )
            .is_err()
        );
    }

    #[test]
    fn legacy_git_master_dependency_reference_omits_the_branch() {
        // Cargo V1/V2 keep the branch on package sources, but omit it on
        // dependency references even when a path package needs disambiguation.
        let source = format!(
            "git+https://example.com/demo?branch=master#{}",
            "0".repeat(40)
        );
        let packages = [
            locked("demo", "1.0.0", Some(&source)),
            locked("demo", "1.0.0", None),
        ];
        for format in [crate::lockfile::Format::V1, crate::lockfile::Format::V2] {
            assert_eq!(
                resolve_lock_reference(
                    "demo 1.0.0 (git+https://example.com/demo)",
                    &packages,
                    format
                )
                .unwrap()
                .source
                .as_deref(),
                Some(source.as_str())
            );
        }
        for format in [crate::lockfile::Format::V3, crate::lockfile::Format::V4] {
            assert!(
                resolve_lock_reference(
                    "demo 1.0.0 (git+https://example.com/demo)",
                    &packages,
                    format
                )
                .is_err()
            );
            assert!(
                resolve_lock_reference(
                    "demo 1.0.0 (git+https://example.com/demo?branch=master)",
                    &packages,
                    format
                )
                .is_ok()
            );
        }
    }

    fn locked(name: &str, version: &str, source: Option<&str>) -> LockedPackage {
        LockedPackage {
            name: name.to_owned(),
            version: crate::manifest::Version {
                original: version.to_owned(),
                major: Version::parse(version).unwrap().major,
                minor: Version::parse(version).unwrap().minor,
                patch: Version::parse(version).unwrap().patch,
                pre: String::new(),
                build: String::new(),
            },
            source: source.map(str::to_owned),
            checksum: source.map(|_| checksum(0x11)),
            dependencies: Vec::new(),
        }
    }
}
