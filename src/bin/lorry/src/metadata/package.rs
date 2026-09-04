use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::diagnostic::{Error, Result};
use crate::manifest::{
    Dependency, DependencySource, Edition, GitDependency, GitSelector, Manifest,
};
use crate::resolver::{PackageSourceKey, ResolvedPackage, ResolvedSource};
use crate::sparse::DependencyKind;

use super::wire;

const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

#[derive(Clone, Copy)]
pub(crate) enum Identity<'a> {
    Root,
    Resolved(&'a ResolvedPackage),
}

pub(crate) fn package_id(manifest: &Manifest, identity: Identity<'_>) -> Result<String> {
    match identity {
        Identity::Root => {
            path_package_id(&manifest.root, &manifest.name, &manifest.version.original)
        }
        Identity::Resolved(package) => {
            validate_identity(manifest, package)?;
            let version = package.key.version.to_string();
            match &package.source {
                ResolvedSource::CratesIo { .. } => {
                    Ok(format!("{CRATES_IO}#{}@{version}", package.key.name))
                }
                ResolvedSource::Path { logical_root, .. } => {
                    path_package_id(logical_root, &package.key.name, &version)
                }
                ResolvedSource::Git { cargo_source, .. } => {
                    let locked = crate::git::parse_locked_source(cargo_source)?;
                    let source = cargo_source.rsplit_once('#').unwrap().0;
                    Ok(url_package_id(
                        source,
                        &locked.url,
                        &package.key.name,
                        &version,
                    ))
                }
            }
        }
    }
}

pub(super) fn map(
    manifest: &Manifest,
    identity: Identity<'_>,
    presented_root: &Path,
    dependency_roots: &BTreeMap<PathBuf, PathBuf>,
) -> Result<wire::Package> {
    validate_aliases(manifest)?;
    let id = package_id(manifest, identity)?;
    let source = match identity {
        Identity::Root => None,
        Identity::Resolved(package) => match &package.source {
            ResolvedSource::CratesIo { .. } => Some(CRATES_IO.to_owned()),
            ResolvedSource::Path { .. } => None,
            ResolvedSource::Git { cargo_source, .. } => Some(cargo_source.clone()),
        },
    };
    let root = fs::canonicalize(presented_root).map_err(|error| {
        Error::failure(format!(
            "failed to canonicalize package source root `{}`: {error}",
            presented_root.display()
        ))
    })?;
    let dependencies = manifest
        .dependencies
        .iter()
        .map(|dependency| map_dependency(dependency, dependency_roots))
        .collect::<Result<Vec<_>>>()?;

    Ok(wire::Package {
        name: manifest.name.clone(),
        version: manifest.version.original.clone(),
        authors: manifest.metadata.authors.clone(),
        id,
        source,
        description: nonempty(&manifest.metadata.description),
        dependencies,
        license: nonempty(&manifest.metadata.license),
        license_file: nonempty(&manifest.metadata.license_file),
        targets: map_targets(manifest, &root)?,
        features: manifest.features.clone(),
        manifest_path: canonical_utf8(&root.join("Cargo.toml"), "package manifest")?,
        categories: Vec::new(),
        keywords: Vec::new(),
        readme: nonempty(&manifest.metadata.readme),
        repository: nonempty(&manifest.metadata.repository),
        homepage: nonempty(&manifest.metadata.homepage),
        documentation: nonempty(&manifest.metadata.documentation),
        edition: edition(manifest.edition).to_owned(),
        metadata: serde_json::Value::Null,
        links: manifest.links.clone(),
        publish: None,
        default_run: manifest.default_run.clone(),
        rust_version: nonempty(&manifest.metadata.rust_version),
    })
}

fn validate_aliases(manifest: &Manifest) -> Result<()> {
    let mut aliases = BTreeMap::<String, String>::new();
    for dependency in &manifest.dependencies {
        let normalized = dependency.alias.replace('-', "_");
        if let Some(previous) = aliases.insert(normalized.clone(), dependency.alias.clone())
            && previous != dependency.alias
        {
            return Err(Error::failure(format!(
                "dependency aliases `{previous}` and `{}` collide as `{normalized}`",
                dependency.alias
            )));
        }
    }
    Ok(())
}

fn map_targets(manifest: &Manifest, root: &Path) -> Result<Vec<wire::Target>> {
    let mut targets = Vec::new();
    if let Some(library) = &manifest.library {
        targets.push(wire::Target {
            name: library.name.clone(),
            kind: library.crate_types.clone(),
            crate_types: library.crate_types.clone(),
            required_features: Vec::new(),
            src_path: rebase_path(manifest, root, &library.path, "library source")?,
            edition: edition(manifest.edition).to_owned(),
            doctest: library.doctest,
            test: library.test,
            doc: library.doc,
        });
    }
    for binary in &manifest.binaries {
        targets.push(wire::Target {
            name: binary.name.clone(),
            kind: vec!["bin".to_owned()],
            crate_types: vec!["bin".to_owned()],
            required_features: Vec::new(),
            src_path: rebase_path(manifest, root, &binary.path, "binary source")?,
            edition: edition(manifest.edition).to_owned(),
            doctest: false,
            test: binary.test,
            doc: binary.doc,
        });
    }
    for test in &manifest.integration_tests {
        targets.push(wire::Target {
            name: test.name.clone(),
            kind: vec!["test".to_owned()],
            crate_types: vec!["bin".to_owned()],
            required_features: Vec::new(),
            src_path: rebase_path(manifest, root, &test.path, "integration-test source")?,
            edition: edition(manifest.edition).to_owned(),
            doctest: false,
            test: true,
            doc: false,
        });
    }
    if let Some(build_script) = &manifest.build_script {
        targets.push(wire::Target {
            name: "build-script-build".to_owned(),
            kind: vec!["custom-build".to_owned()],
            crate_types: vec!["bin".to_owned()],
            required_features: Vec::new(),
            src_path: rebase_path(manifest, root, build_script, "build-script source")?,
            edition: edition(manifest.edition).to_owned(),
            doctest: false,
            test: false,
            doc: false,
        });
    }
    Ok(targets)
}

fn map_dependency(
    dependency: &Dependency,
    dependency_roots: &BTreeMap<PathBuf, PathBuf>,
) -> Result<wire::Dependency> {
    let (source, path) = match &dependency.source {
        DependencySource::CratesIo => (Some(CRATES_IO.to_owned()), None),
        DependencySource::Path(path) => {
            let canonical = fs::canonicalize(path).map_err(|error| {
                Error::failure(format!(
                    "failed to canonicalize dependency path `{}`: {error}",
                    path.display()
                ))
            })?;
            let presented = dependency_roots.get(&canonical).unwrap_or(&canonical);
            (None, Some(path_utf8(presented, "dependency path")?))
        }
        DependencySource::Git(git) => (Some(git_source(git)), None),
    };
    Ok(wire::Dependency {
        name: dependency.package.clone(),
        source,
        req: dependency.requirement.to_string(),
        kind: match dependency.kind {
            DependencyKind::Normal => None,
            DependencyKind::Dev => Some(wire::DependencyKind::Dev),
            DependencyKind::Build => Some(wire::DependencyKind::Build),
        },
        optional: dependency.optional,
        uses_default_features: dependency.default_features,
        features: dependency.features.clone(),
        target: dependency.target.clone(),
        rename: (dependency.alias != dependency.package).then(|| dependency.alias.clone()),
        registry: None,
        path,
    })
}

fn validate_identity(manifest: &Manifest, package: &ResolvedPackage) -> Result<()> {
    let version = semver::Version::parse(&manifest.version.original)
        .map_err(|error| Error::failure(format!("invalid prepared package version: {error}")))?;
    let source_matches = match (&package.key.source, &package.source) {
        (PackageSourceKey::CratesIo, ResolvedSource::CratesIo { .. }) => true,
        (PackageSourceKey::Path(key_root), ResolvedSource::Path { logical_root, .. }) => {
            key_root == logical_root
        }
        (PackageSourceKey::Git(key_source), ResolvedSource::Git { cargo_source, .. }) => {
            key_source == cargo_source
        }
        _ => false,
    };
    if manifest.name != package.key.name || version != package.key.version || !source_matches {
        return Err(Error::failure(format!(
            "prepared manifest identity does not match resolved package `{} {}`",
            package.key.name, package.key.version
        )));
    }
    Ok(())
}

fn path_package_id(root: &Path, name: &str, version: &str) -> Result<String> {
    let root = fs::canonicalize(root).map_err(|error| {
        Error::failure(format!(
            "failed to canonicalize package root `{}`: {error}",
            root.display()
        ))
    })?;
    let text = path_utf8(&root, "package root")?;
    let source = format!("path+file://{}", percent_encode(text.as_bytes(), true));
    let final_segment = root.file_name().and_then(|value| value.to_str());
    Ok(url_package_id(
        &source,
        final_segment.unwrap_or(""),
        name,
        version,
    ))
}

fn url_package_id(source: &str, url_or_segment: &str, name: &str, version: &str) -> String {
    let segment = url_or_segment
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("");
    if segment == name {
        format!("{source}#{version}")
    } else {
        format!("{source}#{name}@{version}")
    }
}

fn git_source(git: &GitDependency) -> String {
    let selector = match &git.selector {
        GitSelector::Head => None,
        GitSelector::Branch(value) => Some(("branch", value)),
        GitSelector::Tag(value) => Some(("tag", value)),
        GitSelector::Revision(value) => Some(("rev", value)),
    };
    match selector {
        None => format!("git+{}", git.url),
        Some((kind, value)) => format!(
            "git+{}?{}={}",
            git.url,
            kind,
            percent_encode(value.as_bytes(), false)
        ),
    }
}

fn rebase_path(manifest: &Manifest, root: &Path, path: &Path, what: &str) -> Result<String> {
    let relative = path.strip_prefix(&manifest.root).map_err(|_| {
        Error::failure(format!(
            "{what} `{}` escapes its package root",
            path.display()
        ))
    })?;
    canonical_utf8(&root.join(relative), what)
}

fn canonical_utf8(path: &Path, what: &str) -> Result<String> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        Error::failure(format!(
            "failed to canonicalize {what} `{}`: {error}",
            path.display()
        ))
    })?;
    path_utf8(&canonical, what)
}

pub(super) fn path_utf8(path: &Path, what: &str) -> Result<String> {
    if !path.is_absolute() {
        return Err(Error::failure(format!(
            "{what} `{}` is not absolute",
            path.display()
        )));
    }
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::failure(format!("{what} is not valid UTF-8")))
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

fn edition(value: Edition) -> &'static str {
    match value {
        Edition::E2015 => "2015",
        Edition::E2018 => "2018",
        Edition::E2021 => "2021",
        Edition::E2024 => "2024",
    }
}

fn percent_encode(value: &[u8], keep_slash: bool) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::new();
    for &byte in value {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~')
            || (keep_slash && byte == b'/')
        {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[(byte >> 4) as usize]));
            encoded.push(char::from(HEX[(byte & 0xf) as usize]));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn path_ids_match_cargo_omission_and_encoding_rules() {
        let root = env::temp_dir().join(format!(
            "lorry metadata id {} {}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let name = root.file_name().unwrap().to_str().unwrap();
        let omitted = path_package_id(&root, name, "1.2.3").unwrap();
        assert!(omitted.ends_with("#1.2.3"));
        assert!(omitted.contains("lorry%20metadata%20id%20"));
        let included = path_package_id(&root, "different", "1.2.3").unwrap();
        assert!(included.ends_with("#different@1.2.3"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn git_sources_encode_selectors_and_apply_name_omission() {
        let git = GitDependency {
            url: "https://example.test/demo".to_owned(),
            selector: GitSelector::Branch("feature/motor".to_owned()),
        };
        assert_eq!(
            git_source(&git),
            "git+https://example.test/demo?branch=feature%2Fmotor"
        );
        assert_eq!(
            url_package_id(&git_source(&git), &git.url, "demo", "1.0.0"),
            "git+https://example.test/demo?branch=feature%2Fmotor#1.0.0"
        );
        assert_eq!(
            url_package_id(
                "git+https://example.test/demo.git",
                "https://example.test/demo.git",
                "demo",
                "1.0.0"
            ),
            "git+https://example.test/demo.git#demo@1.0.0"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_utf8_metadata_paths() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path = PathBuf::from(OsString::from_vec(b"/tmp/metadata-\xff".to_vec()));
        assert!(path_utf8(&path, "fixture path").is_err());
    }
}
