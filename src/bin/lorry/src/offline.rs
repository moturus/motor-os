#![allow(dead_code)]

use std::collections::BTreeSet;

use semver::Version;

use crate::diagnostic::{Error, Result};
use crate::hash::hex;
use crate::manifest::{LockedPackage, Manifest};
use crate::resolver::{PackageKey, Resolution};

const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

pub fn validate_registry_resolution(manifest: &Manifest, resolution: &Resolution) -> Result<()> {
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

    validate_edges(
        "root package",
        &resolution.root_edges,
        &root.dependencies,
        &lock.packages,
    )?;

    let mut selected = BTreeSet::new();
    for package in &resolution.packages {
        if !selected.insert(package.key.clone()) {
            return Err(Error::failure(format!(
                "resolver returned duplicate package `{} {}`",
                package.key.name, package.key.version
            )));
        }
        let locked = find_registry_package(&lock.packages, &package.key)?;
        let expected_checksum = hex(&package.checksum);
        if locked.checksum.as_deref() != Some(expected_checksum.as_str()) {
            return Err(stale(format!(
                "Cargo.lock checksum for `{} {}` does not match the resolved sparse-index checksum",
                package.key.name, package.key.version
            )));
        }
        validate_edges(
            &format!("package `{} {}`", package.key.name, package.key.version),
            &package.lock_edges,
            &locked.dependencies,
            &lock.packages,
        )?;
    }
    Ok(())
}

fn find_registry_package<'a>(
    packages: &'a [LockedPackage],
    key: &PackageKey,
) -> Result<&'a LockedPackage> {
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

fn validate_edges(
    owner: &str,
    resolved: &[crate::resolver::ResolvedEdge],
    locked: &[String],
    packages: &[LockedPackage],
) -> Result<()> {
    let expected = resolved
        .iter()
        .map(|edge| edge.package.clone())
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    let mut exact_references = BTreeSet::new();
    for reference in locked {
        if !exact_references.insert(reference) {
            return Err(stale(format!(
                "{owner} repeats Cargo.lock dependency reference `{reference}`"
            )));
        }
        let package = resolve_lock_reference(reference, packages)?;
        if package.source.as_deref() == Some(CRATES_IO_SOURCE) {
            actual.insert(PackageKey {
                name: package.name.clone(),
                version: Version::parse(&package.version.original).map_err(|error| {
                    stale(format!(
                        "Cargo.lock dependency `{reference}` has an invalid version: {error}"
                    ))
                })?,
            });
        }
    }
    if actual != expected {
        return Err(stale(format!(
            "{owner} dependency edges disagree with Cargo.lock: resolved [{}], locked [{}]",
            display_keys(&expected),
            display_keys(&actual)
        )));
    }
    Ok(())
}

fn resolve_lock_reference<'a>(
    reference: &str,
    packages: &'a [LockedPackage],
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
        .filter(|package| source.is_none_or(|source| package.source.as_deref() == Some(source)))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [package] => Ok(package),
        [] => Err(stale(format!(
            "Cargo.lock dependency reference `{reference}` selects no package node"
        ))),
        _ => Err(stale(format!(
            "Cargo.lock dependency reference `{reference}` is ambiguous"
        ))),
    }
}

fn display_keys(keys: &BTreeSet<PackageKey>) -> String {
    keys.iter()
        .map(|key| format!("{} {}", key.name, key.version))
        .collect::<Vec<_>>()
        .join(", ")
}

fn stale(message: impl Into<String>) -> Error {
    Error::failure(format!("Cargo.lock is stale: {}", message.into()))
        .with_help("run `lorry vendor` to validate and transactionally update Cargo.lock")
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
                rust_version: Version::parse("1.98.0").unwrap(),
                max_packages: 16,
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
        validate_registry_resolution(&manifest, &resolution).unwrap();
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
            validate_registry_resolution(&manifest, &resolution)
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
            validate_registry_resolution(&manifest, &resolution)
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
            validate_registry_resolution(&manifest, &resolution)
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
            resolve_lock_reference("demo 1.0.0", &packages)
                .unwrap()
                .version
                .original,
            "1.0.0"
        );
        assert_eq!(
            resolve_lock_reference(&format!("demo 2.0.0 ({CRATES_IO_SOURCE})"), &packages,)
                .unwrap()
                .version
                .original,
            "2.0.0"
        );
        assert!(resolve_lock_reference("demo", &packages).is_err());
        assert!(resolve_lock_reference("missing", &packages).is_err());
        assert!(resolve_lock_reference("demo bad version", &packages).is_err());
        assert_eq!(
            resolve_lock_reference("local", &packages).unwrap().name,
            "local"
        );
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
