use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use semver::{Version as SemVersion, VersionReq};
use toml_edit::{Array, InlineTable, Item, Table, Value};

use crate::diagnostic::{Error, Result};
use crate::toml::Document;

const MANIFEST_NAME: &str = "Cargo.toml";
const LOCK_NAME: &str = "Cargo.lock";
const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest {
    pub root: PathBuf,
    pub path: PathBuf,
    pub name: String,
    pub crate_name: String,
    pub version: Version,
    pub edition: Edition,
    pub metadata: PackageMetadata,
    pub release: ReleaseProfile,
    #[allow(dead_code)]
    pub resolver: Resolver,
    #[allow(dead_code)]
    pub build_script: Option<PathBuf>,
    #[allow(dead_code)]
    pub library: Option<LibraryTarget>,
    #[allow(dead_code)]
    pub binaries: Vec<BinaryTarget>,
    #[allow(dead_code)]
    pub dependencies: Vec<Dependency>,
    #[allow(dead_code)]
    pub features: BTreeMap<String, Vec<String>>,
    #[allow(dead_code)]
    pub patches: Vec<PathPatch>,
    #[allow(dead_code)]
    pub rust_lints: BTreeMap<String, Lint>,
    #[allow(dead_code)]
    pub lock: Option<Lockfile>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Edition {
    E2015,
    E2018,
    E2021,
    E2024,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resolver {
    V1,
    V2,
    V3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Version {
    pub original: String,
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: String,
    pub build: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PackageMetadata {
    pub authors: Vec<String>,
    pub description: String,
    pub homepage: String,
    pub documentation: String,
    pub repository: String,
    pub license: String,
    pub license_file: String,
    pub readme: String,
    pub rust_version: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lto {
    Default,
    True,
    Fat,
    Thin,
    Off,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Strip {
    None,
    Debuginfo,
    Symbols,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseProfile {
    pub panic_abort: bool,
    pub lto: Lto,
    pub strip: Strip,
    pub codegen_units: Option<u32>,
}

impl Default for ReleaseProfile {
    fn default() -> Self {
        Self {
            panic_abort: false,
            lto: Lto::Default,
            strip: Strip::None,
            codegen_units: None,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LibraryTarget {
    pub name: String,
    pub path: PathBuf,
    pub test: bool,
    pub doctest: bool,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryTarget {
    pub name: String,
    pub path: PathBuf,
    pub test: bool,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dependency {
    pub alias: String,
    pub package: String,
    pub requirement: VersionReq,
    pub source: DependencySource,
    pub optional: bool,
    pub default_features: bool,
    pub features: Vec<String>,
    pub target: Option<String>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DependencySource {
    CratesIo,
    Path(PathBuf),
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathPatch {
    pub alias: String,
    pub package: String,
    pub path: PathBuf,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lint {
    pub level: String,
    pub priority: i64,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lockfile {
    pub packages: Vec<LockedPackage>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedPackage {
    pub name: String,
    pub version: Version,
    pub source: Option<String>,
    pub checksum: Option<String>,
    pub dependencies: Vec<String>,
}

impl Manifest {
    pub fn load(root: &Path) -> Result<Self> {
        let path = root.join(MANIFEST_NAME);
        if !path.is_file() {
            return Err(Error::failure(format!(
                "manifest `{}` does not exist; Lorry does not search parent directories",
                path.display()
            )));
        }
        let document = Document::load(&path, "Cargo manifest")?;
        let mut manifest = Self::parse_document(root, &path, &document)?;
        manifest.root = fs::canonicalize(root).map_err(|error| {
            Error::failure(format!(
                "failed to canonicalize package directory `{}`: {error}",
                root.display()
            ))
        })?;
        manifest.path = manifest.root.join(MANIFEST_NAME);
        resolve_target_defaults(&mut manifest)?;

        let lock_path = manifest.root.join(LOCK_NAME);
        if !lock_path.is_file() {
            return Err(Error::failure(format!(
                "required lockfile `{}` is missing",
                lock_path.display()
            ))
            .with_help("create a version-4 Cargo.lock; build commands never resolve or write it"));
        }
        let lock_document = Document::load(&lock_path, "Cargo lockfile")?;
        manifest.lock = Some(parse_lock_document(&manifest, &lock_path, &lock_document)?);
        Ok(manifest)
    }

    #[cfg(test)]
    fn parse(root: &Path, path: &Path, source: &str) -> Result<Self> {
        let document = Document::parse(path, "Cargo manifest", source.to_owned())?;
        Self::parse_document(root, path, &document)
    }

    fn parse_document(root: &Path, path: &Path, document: &Document) -> Result<Self> {
        validate_root_tables(path, document)?;
        let package_item = document.root().get("package").ok_or_else(|| {
            Error::failure(format!(
                "manifest `{}` is missing required table `[package]`",
                path.display()
            ))
        })?;
        let package = require_table(path, document, package_item, "package")?;
        validate_package_keys(path, document, package)?;

        let name = required_string(path, document, package, "package", "name")?;
        validate_package_name(path, document.line_of_item(package_item), &name)?;
        let version_text = required_string(path, document, package, "package", "version")?;
        let version = parse_version(path, item_line(document, package, "version"), &version_text)?;
        let edition = parse_edition(
            path,
            document,
            package.get("edition"),
            document.line_of_table(package),
        )?;
        let resolver = parse_resolver(
            path,
            document,
            package.get("resolver"),
            edition,
            document.line_of_table(package),
        )?;
        let mut metadata = parse_package_metadata(path, document, package)?;
        if metadata.readme.is_empty() {
            for candidate in ["README.md", "README.txt", "README"] {
                if root.join(candidate).is_file() {
                    metadata.readme = candidate.to_owned();
                    break;
                }
            }
        }

        let build_script = parse_build_script(path, document, package, root)?;
        let library = parse_library(path, document, root, &name)?;
        let binaries = parse_binaries(path, document, root, &name)?;
        let mut dependencies = Vec::new();
        if let Some(item) = document.root().get("dependencies") {
            let table = require_table(path, document, item, "dependencies")?;
            parse_dependency_table(path, document, root, table, None, &mut dependencies)?;
        }
        parse_target_dependencies(path, document, root, &mut dependencies)?;
        let features = parse_features(path, document)?;
        let patches = parse_patches(path, document, root)?;
        let rust_lints = parse_rust_lints(path, document)?;
        let release = parse_profiles(path, document)?;

        Ok(Self {
            root: root.to_path_buf(),
            path: path.to_path_buf(),
            crate_name: name.replace('-', "_"),
            name,
            version,
            edition,
            metadata,
            release,
            resolver,
            build_script,
            library,
            binaries,
            dependencies,
            features,
            patches,
            rust_lints,
            lock: None,
        })
    }
}

fn validate_root_tables(path: &Path, document: &Document) -> Result<()> {
    for (key, item) in document.root().iter() {
        if !matches!(
            key,
            "package"
                | "dependencies"
                | "target"
                | "features"
                | "patch"
                | "profile"
                | "lib"
                | "bin"
                | "lints"
        ) {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("unsupported Stage-2 manifest table or key `{key}`"),
                "remove it or use a later Lorry stage that supports its build semantics",
            ));
        }
    }
    Ok(())
}

fn validate_package_keys(path: &Path, document: &Document, package: &Table) -> Result<()> {
    const ALLOWED: &[&str] = &[
        "name",
        "version",
        "edition",
        "resolver",
        "rust-version",
        "build",
        "authors",
        "description",
        "homepage",
        "documentation",
        "repository",
        "license",
        "license-file",
        "readme",
        "keywords",
        "categories",
        "publish",
        "include",
        "exclude",
        "default-run",
        "metadata",
    ];
    for (key, item) in package.iter() {
        if !ALLOWED.contains(&key) {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("unsupported Stage-2 manifest key `package.{key}`"),
                "remove the key or use a later Lorry stage that supports its build semantics",
            ));
        }
    }
    for key in ["authors", "keywords", "categories", "include", "exclude"] {
        if let Some(item) = package.get(key) {
            string_array(path, document, item, &format!("package.{key}"))?;
        }
    }
    if let Some(item) = package.get("publish") {
        if item.as_bool().is_none() && item.as_array().is_none() {
            return Err(type_error(
                path,
                document.line_of_item(item),
                "package.publish",
                "a boolean or string array",
            ));
        }
        if item.as_array().is_some() {
            string_array(path, document, item, "package.publish")?;
        }
    }
    Ok(())
}

fn parse_package_metadata(
    path: &Path,
    document: &Document,
    package: &Table,
) -> Result<PackageMetadata> {
    Ok(PackageMetadata {
        authors: optional_string_array(path, document, package, "package", "authors")?
            .unwrap_or_default(),
        description: optional_string(path, document, package, "package", "description")?
            .unwrap_or_default(),
        homepage: optional_string(path, document, package, "package", "homepage")?
            .unwrap_or_default(),
        documentation: optional_string(path, document, package, "package", "documentation")?
            .unwrap_or_default(),
        repository: optional_string(path, document, package, "package", "repository")?
            .unwrap_or_default(),
        license: optional_string(path, document, package, "package", "license")?
            .unwrap_or_default(),
        license_file: optional_string(path, document, package, "package", "license-file")?
            .unwrap_or_default(),
        readme: optional_string_or_false(path, document, package, "package", "readme")?
            .unwrap_or_default(),
        rust_version: optional_string(path, document, package, "package", "rust-version")?
            .unwrap_or_default(),
    })
}

fn parse_edition(
    path: &Path,
    document: &Document,
    item: Option<&Item>,
    default_line: usize,
) -> Result<Edition> {
    let Some(item) = item else {
        return Ok(Edition::E2015);
    };
    let line = document.line_of_item(item).max(default_line);
    match item.as_str() {
        Some("2015") => Ok(Edition::E2015),
        Some("2018") => Ok(Edition::E2018),
        Some("2021") => Ok(Edition::E2021),
        Some("2024") => Ok(Edition::E2024),
        Some(value) => Err(Error::at(
            path,
            line,
            format!("unsupported package edition `{value}`"),
            "choose edition 2015, 2018, 2021, or 2024",
        )),
        None => Err(type_error(path, line, "package.edition", "a string")),
    }
}

fn parse_resolver(
    path: &Path,
    document: &Document,
    item: Option<&Item>,
    edition: Edition,
    default_line: usize,
) -> Result<Resolver> {
    let Some(item) = item else {
        return Ok(match edition {
            Edition::E2015 | Edition::E2018 => Resolver::V1,
            Edition::E2021 => Resolver::V2,
            Edition::E2024 => Resolver::V3,
        });
    };
    let line = document.line_of_item(item).max(default_line);
    match item.as_str() {
        Some("1") => Ok(Resolver::V1),
        Some("2") => Ok(Resolver::V2),
        Some("3") => Ok(Resolver::V3),
        Some(value) => Err(Error::at(
            path,
            line,
            format!("unsupported Cargo feature resolver `{value}`"),
            "choose resolver `1`, `2`, or `3`",
        )),
        None => Err(type_error(path, line, "package.resolver", "a string")),
    }
}

fn parse_build_script(
    path: &Path,
    document: &Document,
    package: &Table,
    root: &Path,
) -> Result<Option<PathBuf>> {
    match package.get("build") {
        Some(item) if item.as_bool() == Some(false) => Ok(None),
        Some(item) if item.as_str().is_some() => {
            let value = item.as_str().unwrap();
            validate_relative_path(path, document.line_of_item(item), "package.build", value)?;
            Ok(Some(root.join(value)))
        }
        Some(item) => Err(type_error(
            path,
            document.line_of_item(item),
            "package.build",
            "a relative path string or false",
        )),
        None if root.join("build.rs").is_file() => Ok(Some(root.join("build.rs"))),
        None => Ok(None),
    }
}

fn parse_library(
    path: &Path,
    document: &Document,
    root: &Path,
    package_name: &str,
) -> Result<Option<LibraryTarget>> {
    let Some(item) = document.root().get("lib") else {
        return Ok(root.join("src/lib.rs").is_file().then(|| LibraryTarget {
            name: package_name.replace('-', "_"),
            path: root.join("src/lib.rs"),
            test: true,
            doctest: true,
        }));
    };
    let table = require_table(path, document, item, "lib")?;
    for (key, item) in table.iter() {
        if !matches!(key, "name" | "path" | "test" | "doctest" | "crate-type") {
            return Err(unsupported_key(path, document, item, &format!("lib.{key}")));
        }
    }
    if let Some(crate_types) = table.get("crate-type") {
        let values = string_array(path, document, crate_types, "lib.crate-type")?;
        if values
            .iter()
            .any(|value| !matches!(value.as_str(), "lib" | "rlib"))
        {
            return Err(Error::at(
                path,
                document.line_of_item(crate_types),
                "custom library crate types are not supported in Stage 2",
                "use `lib` or `rlib` only",
            ));
        }
    }
    let name = optional_string(path, document, table, "lib", "name")?
        .unwrap_or_else(|| package_name.replace('-', "_"));
    validate_crate_name(path, document.line_of_table(table), &name)?;
    let relative = optional_string(path, document, table, "lib", "path")?
        .unwrap_or_else(|| "src/lib.rs".to_owned());
    validate_relative_path(path, document.line_of_table(table), "lib.path", &relative)?;
    Ok(Some(LibraryTarget {
        name,
        path: root.join(relative),
        test: optional_bool(path, document, table, "lib", "test")?.unwrap_or(true),
        doctest: optional_bool(path, document, table, "lib", "doctest")?.unwrap_or(true),
    }))
}

fn parse_binaries(
    path: &Path,
    document: &Document,
    root: &Path,
    package_name: &str,
) -> Result<Vec<BinaryTarget>> {
    let mut binaries = Vec::new();
    if let Some(item) = document.root().get("bin") {
        let tables = item.as_array_of_tables().ok_or_else(|| {
            type_error(
                path,
                document.line_of_item(item),
                "bin",
                "an array of tables",
            )
        })?;
        if tables.len() > 1 {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                "Stage 2 supports at most one explicit `[[bin]]` target",
                "keep one program binary target",
            ));
        }
        for table in tables.iter() {
            for (key, item) in table.iter() {
                if !matches!(key, "name" | "path" | "test" | "bench" | "doc") {
                    return Err(unsupported_key(path, document, item, &format!("bin.{key}")));
                }
                if matches!(key, "bench" | "doc") && item.as_bool() != Some(false) {
                    return Err(Error::at(
                        path,
                        document.line_of_item(item),
                        format!("`bin.{key}` must be false in Stage 2"),
                        "benches and binary documentation targets are deferred",
                    ));
                }
            }
            let name = optional_string(path, document, table, "bin", "name")?
                .unwrap_or_else(|| package_name.to_owned());
            validate_package_name(path, document.line_of_table(table), &name)?;
            let relative = optional_string(path, document, table, "bin", "path")?
                .unwrap_or_else(|| "src/main.rs".to_owned());
            validate_relative_path(path, document.line_of_table(table), "bin.path", &relative)?;
            binaries.push(BinaryTarget {
                name,
                path: root.join(relative),
                test: optional_bool(path, document, table, "bin", "test")?.unwrap_or(true),
            });
        }
    } else if root.join("src/main.rs").is_file() {
        binaries.push(BinaryTarget {
            name: package_name.to_owned(),
            path: root.join("src/main.rs"),
            test: true,
        });
    }
    Ok(binaries)
}

fn resolve_target_defaults(manifest: &mut Manifest) -> Result<()> {
    if let Some(library) = &manifest.library
        && !library.path.is_file()
    {
        return Err(Error::failure(format!(
            "library target `{}` does not exist",
            library.path.display()
        )));
    }
    for binary in &manifest.binaries {
        if !binary.path.is_file() {
            return Err(Error::failure(format!(
                "binary target `{}` does not exist",
                binary.path.display()
            )));
        }
    }
    if manifest.library.is_none() && manifest.binaries.is_empty() {
        return Err(Error::failure(format!(
            "package `{}` has no supported library or binary target",
            manifest.name
        ))
        .with_help("add `src/lib.rs`, `src/main.rs`, or one supported `[[bin]]`"));
    }
    Ok(())
}

fn parse_dependency_table(
    path: &Path,
    document: &Document,
    root: &Path,
    table: &Table,
    target: Option<&str>,
    output: &mut Vec<Dependency>,
) -> Result<()> {
    for (alias, item) in table.iter() {
        validate_package_name(path, document.line_of_item(item), alias)?;
        output.push(parse_dependency(path, document, root, alias, item, target)?);
    }
    Ok(())
}

fn parse_dependency(
    path: &Path,
    document: &Document,
    root: &Path,
    alias: &str,
    item: &Item,
    target: Option<&str>,
) -> Result<Dependency> {
    if let Some(requirement) = item.as_str() {
        return Ok(Dependency {
            alias: alias.to_owned(),
            package: alias.to_owned(),
            requirement: parse_requirement(path, document.line_of_item(item), alias, requirement)?,
            source: DependencySource::CratesIo,
            optional: false,
            default_features: true,
            features: Vec::new(),
            target: target.map(str::to_owned),
        });
    }
    let (lookup, line) = match item {
        Item::Value(Value::InlineTable(table)) => {
            (DependencyTable::Inline(table), document.line_of_item(item))
        }
        Item::Table(table) => (DependencyTable::Regular(table), document.line_of_item(item)),
        _ => {
            return Err(type_error(
                path,
                document.line_of_item(item),
                &format!("dependencies.{alias}"),
                "a version string or dependency table",
            ));
        }
    };
    const ALLOWED: &[&str] = &[
        "version",
        "path",
        "package",
        "optional",
        "default-features",
        "features",
    ];
    for (key, value) in lookup.entries() {
        if !ALLOWED.contains(&key) {
            let unsupported = if matches!(
                key,
                "git"
                    | "branch"
                    | "tag"
                    | "rev"
                    | "registry"
                    | "registry-index"
                    | "workspace"
                    | "artifact"
                    | "lib"
            ) {
                format!("dependency source or mode `{key}` is not supported in Stage 2")
            } else {
                format!("unknown dependency key `{key}`")
            };
            return Err(Error::at(
                path,
                value.line(document),
                unsupported,
                "use a crates.io version or a local path dependency",
            ));
        }
    }
    let requirement_item = lookup.get("version").ok_or_else(|| {
        Error::at(
            path,
            line,
            format!("dependency `{alias}` is missing a version requirement"),
            "add `version = \"...\"`, including for verified path dependencies",
        )
    })?;
    let requirement_text = requirement_item.as_str().ok_or_else(|| {
        type_error(
            path,
            requirement_item.line(document),
            &format!("dependencies.{alias}.version"),
            "a string",
        )
    })?;
    let package = match lookup.get("package") {
        Some(value) => value
            .as_str()
            .ok_or_else(|| {
                type_error(
                    path,
                    value.line(document),
                    &format!("dependencies.{alias}.package"),
                    "a string",
                )
            })?
            .to_owned(),
        None => alias.to_owned(),
    };
    validate_package_name(path, line, &package)?;
    let source = match lookup.get("path") {
        Some(value) => {
            let relative = value.as_str().ok_or_else(|| {
                type_error(
                    path,
                    value.line(document),
                    &format!("dependencies.{alias}.path"),
                    "a string",
                )
            })?;
            validate_relative_path(
                path,
                value.line(document),
                &format!("dependencies.{alias}.path"),
                relative,
            )?;
            DependencySource::Path(root.join(relative))
        }
        None => DependencySource::CratesIo,
    };
    Ok(Dependency {
        alias: alias.to_owned(),
        package,
        requirement: parse_requirement(
            path,
            requirement_item.line(document),
            alias,
            requirement_text,
        )?,
        source,
        optional: lookup_bool(path, document, &lookup, alias, "optional")?.unwrap_or(false),
        default_features: lookup_bool(path, document, &lookup, alias, "default-features")?
            .unwrap_or(true),
        features: match lookup.get("features") {
            Some(value) => node_string_array(
                path,
                document,
                value,
                &format!("dependencies.{alias}.features"),
            )?,
            None => Vec::new(),
        },
        target: target.map(str::to_owned),
    })
}

fn parse_target_dependencies(
    path: &Path,
    document: &Document,
    root: &Path,
    output: &mut Vec<Dependency>,
) -> Result<()> {
    let Some(item) = document.root().get("target") else {
        return Ok(());
    };
    let targets = require_table(path, document, item, "target")?;
    for (selector, item) in targets.iter() {
        validate_target_selector(path, document.line_of_item(item), selector)?;
        let target = require_table(path, document, item, &format!("target.{selector}"))?;
        for (key, item) in target.iter() {
            if key != "dependencies" {
                return Err(Error::at(
                    path,
                    document.line_of_item(item),
                    format!("root `target.{selector}.{key}` is not supported in Stage 2"),
                    "root build-dependencies and dev-dependencies are deferred",
                ));
            }
            let dependencies = require_table(
                path,
                document,
                item,
                &format!("target.{selector}.dependencies"),
            )?;
            parse_dependency_table(path, document, root, dependencies, Some(selector), output)?;
        }
    }
    Ok(())
}

fn parse_features(path: &Path, document: &Document) -> Result<BTreeMap<String, Vec<String>>> {
    let Some(item) = document.root().get("features") else {
        return Ok(BTreeMap::new());
    };
    let table = require_table(path, document, item, "features")?;
    let mut result = BTreeMap::new();
    for (name, item) in table.iter() {
        validate_feature(path, document.line_of_item(item), name)?;
        let members = string_array(path, document, item, &format!("features.{name}"))?;
        for member in &members {
            validate_feature_reference(path, document.line_of_item(item), member)?;
        }
        result.insert(name.to_owned(), members);
    }
    Ok(result)
}

fn parse_patches(path: &Path, document: &Document, root: &Path) -> Result<Vec<PathPatch>> {
    let Some(item) = document.root().get("patch") else {
        return Ok(Vec::new());
    };
    let patch = require_table(path, document, item, "patch")?;
    for (source, item) in patch.iter() {
        if source != "crates-io" {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("patch source `{source}` is not supported in Stage 2"),
                "use `[patch.crates-io]` with exact local path replacements",
            ));
        }
    }
    let Some(item) = patch.get("crates-io") else {
        return Ok(Vec::new());
    };
    let crates_io = require_table(path, document, item, "patch.crates-io")?;
    let mut result = Vec::new();
    for (alias, item) in crates_io.iter() {
        let table = item.as_inline_table().ok_or_else(|| {
            type_error(
                path,
                document.line_of_item(item),
                &format!("patch.crates-io.{alias}"),
                "an inline path table",
            )
        })?;
        for (key, value) in table.iter() {
            if !matches!(key, "path" | "package") {
                return Err(Error::at(
                    path,
                    document.line_of_value(value),
                    format!("patch key `{key}` is not supported in Stage 2"),
                    "use only `path` and optional `package`",
                ));
            }
        }
        let relative = table.get("path").and_then(Value::as_str).ok_or_else(|| {
            Error::at(
                path,
                document.line_of_item(item),
                format!("patch `{alias}` is missing string key `path`"),
                "use `{ path = \"relative/source\" }`",
            )
        })?;
        validate_relative_path(
            path,
            document.line_of_item(item),
            &format!("patch.crates-io.{alias}.path"),
            relative,
        )?;
        let package = table
            .get("package")
            .and_then(Value::as_str)
            .unwrap_or(alias);
        validate_package_name(path, document.line_of_item(item), package)?;
        result.push(PathPatch {
            alias: alias.to_owned(),
            package: package.to_owned(),
            path: root.join(relative),
        });
    }
    Ok(result)
}

fn parse_rust_lints(path: &Path, document: &Document) -> Result<BTreeMap<String, Lint>> {
    let Some(item) = document.root().get("lints") else {
        return Ok(BTreeMap::new());
    };
    let lints = require_table(path, document, item, "lints")?;
    for (key, item) in lints.iter() {
        if key != "rust" {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("lint namespace `lints.{key}` is not supported in Stage 2"),
                "configure Rust lints under `[lints.rust]`",
            ));
        }
    }
    let Some(item) = lints.get("rust") else {
        return Ok(BTreeMap::new());
    };
    let rust = require_table(path, document, item, "lints.rust")?;
    let mut result = BTreeMap::new();
    for (name, item) in rust.iter() {
        let lint = if let Some(level) = item.as_str() {
            Lint {
                level: validate_lint_level(path, document.line_of_item(item), level)?,
                priority: 0,
            }
        } else if let Some(table) = item.as_inline_table() {
            for (key, value) in table.iter() {
                if !matches!(key, "level" | "priority") {
                    return Err(Error::at(
                        path,
                        document.line_of_value(value),
                        format!("unknown lint configuration key `{key}`"),
                        "use only `level` and optional `priority`",
                    ));
                }
            }
            let level = table.get("level").and_then(Value::as_str).ok_or_else(|| {
                Error::at(
                    path,
                    document.line_of_item(item),
                    format!("lint `{name}` is missing string key `level`"),
                    "set a supported rustc lint level",
                )
            })?;
            Lint {
                level: validate_lint_level(path, document.line_of_item(item), level)?,
                priority: table
                    .get("priority")
                    .map(|value| {
                        value.as_integer().ok_or_else(|| {
                            type_error(
                                path,
                                document.line_of_value(value),
                                &format!("lints.rust.{name}.priority"),
                                "an integer",
                            )
                        })
                    })
                    .transpose()?
                    .unwrap_or(0),
            }
        } else {
            return Err(type_error(
                path,
                document.line_of_item(item),
                &format!("lints.rust.{name}"),
                "a level string or inline table",
            ));
        };
        result.insert(name.to_owned(), lint);
    }
    Ok(result)
}

fn parse_profiles(path: &Path, document: &Document) -> Result<ReleaseProfile> {
    let Some(item) = document.root().get("profile") else {
        return Ok(ReleaseProfile::default());
    };
    let profiles = require_table(path, document, item, "profile")?;
    for (key, item) in profiles.iter() {
        if !matches!(key, "dev" | "release") {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("custom profile `profile.{key}` is not supported in Stage 2"),
                "use only the default dev profile and supported release keys",
            ));
        }
    }
    if let Some(dev) = profiles.get("dev") {
        let table = require_table(path, document, dev, "profile.dev")?;
        if let Some((key, item)) = table.iter().next() {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("custom dev profile key `profile.dev.{key}` is not supported"),
                "remove the key to use Cargo's default dev profile",
            ));
        }
    }
    let Some(release) = profiles.get("release") else {
        return Ok(ReleaseProfile::default());
    };
    parse_release(
        path,
        document,
        require_table(path, document, release, "profile.release")?,
    )
}

fn parse_release(path: &Path, document: &Document, table: &Table) -> Result<ReleaseProfile> {
    for (key, item) in table.iter() {
        if !matches!(key, "panic" | "lto" | "strip" | "codegen-units") {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("unsupported Stage-2 release profile key `profile.release.{key}`"),
                "Stage 2 supports only panic, lto, strip, and codegen-units",
            ));
        }
    }
    let panic_abort = match table.get("panic") {
        None => false,
        Some(item) if item.as_str() == Some("unwind") => false,
        Some(item) if item.as_str() == Some("abort") => true,
        Some(item) => {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                "unsupported `profile.release.panic` value",
                "choose `unwind` or `abort`",
            ));
        }
    };
    let lto = match table.get("lto") {
        None => Lto::Default,
        Some(item) if item.as_bool() == Some(false) => Lto::Default,
        Some(item) if item.as_bool() == Some(true) => Lto::True,
        Some(item) if item.as_str() == Some("fat") => Lto::Fat,
        Some(item) if item.as_str() == Some("thin") => Lto::Thin,
        Some(item) if item.as_str() == Some("off") => Lto::Off,
        Some(item) => {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                "unsupported value for `profile.release.lto`",
                "choose false, true, `fat`, `thin`, or `off`",
            ));
        }
    };
    let strip = match table.get("strip") {
        None => Strip::None,
        Some(item) if item.as_bool() == Some(false) => Strip::None,
        Some(item) if item.as_bool() == Some(true) => Strip::Symbols,
        Some(item) if item.as_str() == Some("none") => Strip::None,
        Some(item) if item.as_str() == Some("debuginfo") => Strip::Debuginfo,
        Some(item) if item.as_str() == Some("symbols") => Strip::Symbols,
        Some(item) => {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                "unsupported value for `profile.release.strip`",
                "choose false, true, `none`, `debuginfo`, or `symbols`",
            ));
        }
    };
    let codegen_units = match table.get("codegen-units") {
        None => None,
        Some(item) => match item.as_integer() {
            Some(value) if value > 0 && value <= u32::MAX as i64 => Some(value as u32),
            _ => {
                return Err(Error::at(
                    path,
                    document.line_of_item(item),
                    "`profile.release.codegen-units` must be an integer from 1 through 4294967295",
                    "use a positive codegen unit count",
                ));
            }
        },
    };
    Ok(ReleaseProfile {
        panic_abort,
        lto,
        strip,
        codegen_units,
    })
}

#[cfg(test)]
fn validate_lock_source(manifest: &Manifest, path: &Path, source: &str) -> Result<Lockfile> {
    let document = Document::parse(path, "Cargo lockfile", source.to_owned())?;
    parse_lock_document(manifest, path, &document)
}

fn parse_lock_document(manifest: &Manifest, path: &Path, document: &Document) -> Result<Lockfile> {
    for (key, item) in document.root().iter() {
        if !matches!(key, "version" | "package") {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("unsupported root Cargo.lock key `{key}`"),
                "use Cargo.lock format version 4",
            ));
        }
    }
    let version = document.root().get("version").ok_or_else(|| {
        Error::failure(format!(
            "lockfile `{}` is missing `version = 4`",
            path.display()
        ))
    })?;
    if version.as_integer() != Some(4) {
        return Err(Error::at(
            path,
            document.line_of_item(version),
            "unsupported Cargo.lock format; expected `version = 4`",
            "regenerate the lockfile with a current Cargo or `lorry vendor`",
        ));
    }
    let package_item = document.root().get("package").ok_or_else(|| {
        Error::failure(format!(
            "lockfile `{}` contains no package records",
            path.display()
        ))
    })?;
    let tables = package_item.as_array_of_tables().ok_or_else(|| {
        type_error(
            path,
            document.line_of_item(package_item),
            "package",
            "an array of tables",
        )
    })?;
    let mut packages = Vec::new();
    let mut identities = BTreeSet::new();
    for table in tables.iter() {
        for (key, item) in table.iter() {
            if !matches!(
                key,
                "name" | "version" | "source" | "checksum" | "dependencies"
            ) {
                return Err(Error::at(
                    path,
                    document.line_of_item(item),
                    format!("unsupported Cargo.lock package key `{key}`"),
                    "use only Cargo.lock v4 package identity and dependency fields",
                ));
            }
        }
        let name = required_string(path, document, table, "package", "name")?;
        validate_package_name(path, document.line_of_table(table), &name)?;
        let version_text = required_string(path, document, table, "package", "version")?;
        let version = parse_version(path, item_line(document, table, "version"), &version_text)?;
        let source = optional_string(path, document, table, "package", "source")?;
        if source
            .as_deref()
            .is_some_and(|value| value != CRATES_IO_SOURCE)
        {
            return Err(Error::at(
                path,
                item_line(document, table, "source"),
                format!(
                    "unsupported Cargo.lock source `{}`",
                    source.as_deref().unwrap()
                ),
                "Stage 2 supports crates.io and local path package nodes only",
            ));
        }
        let checksum = optional_string(path, document, table, "package", "checksum")?;
        match (&source, &checksum) {
            (Some(_), Some(value)) if is_sha256(value) => {}
            (Some(_), _) => {
                return Err(Error::at(
                    path,
                    item_line(document, table, "checksum"),
                    format!(
                        "registry package `{name} {version_text}` needs a lowercase SHA-256 checksum"
                    ),
                    "use Cargo's authoritative crates.io checksum",
                ));
            }
            (None, Some(_)) => {
                return Err(Error::at(
                    path,
                    item_line(document, table, "checksum"),
                    format!("path package `{name} {version_text}` cannot have a checksum"),
                    "remove source/checksum from path package lock nodes",
                ));
            }
            (None, None) => {}
        }
        let dependencies = optional_string_array(path, document, table, "package", "dependencies")?
            .unwrap_or_default();
        let identity = (name.clone(), version.original.clone(), source.clone());
        if !identities.insert(identity) {
            return Err(Error::at(
                path,
                document.line_of_table(table),
                format!("duplicate Cargo.lock package `{name} {version_text}`"),
                "keep one package node for each exact source identity",
            ));
        }
        packages.push(LockedPackage {
            name,
            version,
            source,
            checksum,
            dependencies,
        });
    }
    let roots = packages
        .iter()
        .filter(|package| {
            package.name == manifest.name
                && package.version.original == manifest.version.original
                && package.source.is_none()
        })
        .count();
    if roots != 1 {
        return Err(Error::failure(format!(
            "Cargo.lock is stale: expected one root path package `{} {}`, found {roots}",
            manifest.name, manifest.version.original
        )));
    }
    Ok(Lockfile { packages })
}

#[derive(Clone, Copy)]
enum DependencyTable<'a> {
    Regular(&'a Table),
    Inline(&'a InlineTable),
}

impl<'a> DependencyTable<'a> {
    fn get(self, key: &str) -> Option<TomlNode<'a>> {
        match self {
            Self::Regular(table) => table.get(key).map(TomlNode::Item),
            Self::Inline(table) => table.get(key).map(TomlNode::Value),
        }
    }

    fn entries(self) -> Vec<(&'a str, TomlNode<'a>)> {
        match self {
            Self::Regular(table) => table
                .iter()
                .map(|(key, item)| (key, TomlNode::Item(item)))
                .collect(),
            Self::Inline(table) => table
                .iter()
                .map(|(key, value)| (key, TomlNode::Value(value)))
                .collect(),
        }
    }
}

#[derive(Clone, Copy)]
enum TomlNode<'a> {
    Item(&'a Item),
    Value(&'a Value),
}

impl<'a> TomlNode<'a> {
    fn as_str(self) -> Option<&'a str> {
        match self {
            Self::Item(item) => item.as_str(),
            Self::Value(value) => value.as_str(),
        }
    }

    fn as_bool(self) -> Option<bool> {
        match self {
            Self::Item(item) => item.as_bool(),
            Self::Value(value) => value.as_bool(),
        }
    }

    fn as_array(self) -> Option<&'a Array> {
        match self {
            Self::Item(item) => item.as_array(),
            Self::Value(value) => value.as_array(),
        }
    }

    fn line(self, document: &Document) -> usize {
        match self {
            Self::Item(item) => document.line_of_item(item),
            Self::Value(value) => document.line_of_value(value),
        }
    }
}

fn lookup_bool(
    path: &Path,
    document: &Document,
    table: &DependencyTable<'_>,
    dependency: &str,
    key: &str,
) -> Result<Option<bool>> {
    match table.get(key) {
        None => Ok(None),
        Some(item) => item.as_bool().map(Some).ok_or_else(|| {
            type_error(
                path,
                item.line(document),
                &format!("dependencies.{dependency}.{key}"),
                "a boolean",
            )
        }),
    }
}

fn required_string(
    path: &Path,
    document: &Document,
    table: &Table,
    table_name: &str,
    key: &str,
) -> Result<String> {
    optional_string(path, document, table, table_name, key)?.ok_or_else(|| {
        Error::at(
            path,
            document.line_of_table(table),
            format!("table `[{table_name}]` is missing required string `{key}`"),
            format!("add `{key} = \"...\"` to `[{table_name}]`"),
        )
    })
}

fn optional_string(
    path: &Path,
    document: &Document,
    table: &Table,
    table_name: &str,
    key: &str,
) -> Result<Option<String>> {
    match table.get(key) {
        None => Ok(None),
        Some(item) => item.as_str().map(str::to_owned).map(Some).ok_or_else(|| {
            type_error(
                path,
                document.line_of_item(item),
                &format!("{table_name}.{key}"),
                "a string",
            )
        }),
    }
}

fn optional_bool(
    path: &Path,
    document: &Document,
    table: &Table,
    table_name: &str,
    key: &str,
) -> Result<Option<bool>> {
    match table.get(key) {
        None => Ok(None),
        Some(item) => item.as_bool().map(Some).ok_or_else(|| {
            type_error(
                path,
                document.line_of_item(item),
                &format!("{table_name}.{key}"),
                "a boolean",
            )
        }),
    }
}

fn optional_string_or_false(
    path: &Path,
    document: &Document,
    table: &Table,
    table_name: &str,
    key: &str,
) -> Result<Option<String>> {
    match table.get(key) {
        None => Ok(None),
        Some(item) if item.as_bool() == Some(false) => Ok(None),
        Some(item) => item.as_str().map(str::to_owned).map(Some).ok_or_else(|| {
            type_error(
                path,
                document.line_of_item(item),
                &format!("{table_name}.{key}"),
                "a string or false",
            )
        }),
    }
}

fn optional_string_array(
    path: &Path,
    document: &Document,
    table: &Table,
    table_name: &str,
    key: &str,
) -> Result<Option<Vec<String>>> {
    table
        .get(key)
        .map(|item| string_array(path, document, item, &format!("{table_name}.{key}")))
        .transpose()
}

fn string_array(path: &Path, document: &Document, item: &Item, name: &str) -> Result<Vec<String>> {
    let array = item.as_array().ok_or_else(|| {
        type_error(
            path,
            document.line_of_item(item),
            name,
            "an array of strings",
        )
    })?;
    string_values(path, document, array, name)
}

fn node_string_array(
    path: &Path,
    document: &Document,
    node: TomlNode<'_>,
    name: &str,
) -> Result<Vec<String>> {
    let array = node
        .as_array()
        .ok_or_else(|| type_error(path, node.line(document), name, "an array of strings"))?;
    string_values(path, document, array, name)
}

fn string_values(
    path: &Path,
    document: &Document,
    array: &Array,
    name: &str,
) -> Result<Vec<String>> {
    array
        .iter()
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                type_error(
                    path,
                    document.line_of_value(value),
                    name,
                    "an array containing only strings",
                )
            })
        })
        .collect()
}

fn require_table<'a>(
    path: &Path,
    document: &Document,
    item: &'a Item,
    name: &str,
) -> Result<&'a Table> {
    item.as_table()
        .ok_or_else(|| type_error(path, document.line_of_item(item), name, "a TOML table"))
}

fn item_line(document: &Document, table: &Table, key: &str) -> usize {
    table.get(key).map_or_else(
        || document.line_of_table(table),
        |item| document.line_of_item(item),
    )
}

fn parse_version(path: &Path, line: usize, version: &str) -> Result<Version> {
    let parsed = SemVersion::parse(version).map_err(|error| {
        Error::at(
            path,
            line,
            format!("invalid semantic package version `{version}`: {error}"),
            "use a semantic version with major.minor.patch components",
        )
    })?;
    Ok(Version {
        original: version.to_owned(),
        major: parsed.major,
        minor: parsed.minor,
        patch: parsed.patch,
        pre: parsed.pre.to_string(),
        build: parsed.build.to_string(),
    })
}

fn parse_requirement(path: &Path, line: usize, name: &str, value: &str) -> Result<VersionReq> {
    VersionReq::parse(value).map_err(|error| {
        Error::at(
            path,
            line,
            format!("invalid version requirement `{value}` for dependency `{name}`: {error}"),
            "use a Cargo-compatible semantic version requirement",
        )
    })
}

fn validate_package_name(path: &Path, line: usize, name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && name.bytes().any(|byte| byte.is_ascii_alphabetic());
    if !valid {
        return Err(Error::at(
            path,
            line,
            format!("unsupported Stage-2 package name `{name}`"),
            "use 1–64 ASCII letters, digits, `-`, or `_`, including at least one letter",
        ));
    }
    Ok(())
}

fn validate_crate_name(path: &Path, line: usize, name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(Error::at(
            path,
            line,
            format!("unsupported Rust crate name `{name}`"),
            "use ASCII letters, digits, and underscores",
        ));
    }
    Ok(())
}

fn validate_feature(path: &Path, line: usize, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'+'))
    {
        return Err(Error::at(
            path,
            line,
            format!("unsupported feature name `{value}`"),
            "use a non-empty ASCII feature name",
        ));
    }
    Ok(())
}

fn validate_feature_reference(path: &Path, line: usize, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 512
        || value.bytes().any(|byte| {
            !byte.is_ascii_graphic() || matches!(byte, b'\\' | b'[' | b']' | b'{' | b'}')
        })
    {
        return Err(Error::at(
            path,
            line,
            format!("unsupported feature reference `{value}`"),
            "use a feature, `dep:name`, `name/feature`, or `name?/feature` reference",
        ));
    }
    Ok(())
}

fn validate_target_selector(path: &Path, line: usize, value: &str) -> Result<()> {
    let valid_cfg = value.starts_with("cfg(") && value.ends_with(')') && value.len() > 5;
    let valid_triple = !value.is_empty()
        && !value.ends_with(".json")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !valid_cfg && !valid_triple {
        return Err(Error::at(
            path,
            line,
            format!("unsupported target dependency selector `{value}`"),
            "use a target triple or non-empty `cfg(...)` expression",
        ));
    }
    Ok(())
}

fn validate_relative_path(path: &Path, line: usize, name: &str, value: &str) -> Result<()> {
    let candidate = Path::new(value);
    if value.is_empty() || candidate.is_absolute() || value.as_bytes().contains(&0) {
        return Err(Error::at(
            path,
            line,
            format!("`{name}` must be a non-empty relative path"),
            "use a path relative to the package manifest",
        ));
    }
    Ok(())
}

fn validate_lint_level(path: &Path, line: usize, value: &str) -> Result<String> {
    if matches!(value, "allow" | "warn" | "force-warn" | "deny" | "forbid") {
        Ok(value.to_owned())
    } else {
        Err(Error::at(
            path,
            line,
            format!("unsupported rustc lint level `{value}`"),
            "choose allow, warn, force-warn, deny, or forbid",
        ))
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn unsupported_key(path: &Path, document: &Document, item: &Item, name: &str) -> Error {
    Error::at(
        path,
        document.line_of_item(item),
        format!("unsupported Stage-2 manifest key `{name}`"),
        "remove the key or use a later Lorry stage",
    )
}

fn type_error(path: &Path, line: usize, name: &str, expected: &str) -> Error {
    Error::at(
        path,
        line,
        format!("`{name}` must be {expected}"),
        "use the supported TOML value type",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const RED: &str = r#"
[package]
name = "red"
version = "0.1.0"
edition = "2024"
license = "MIT OR Apache-2.0"
authors = ["A", "B"]

[package.metadata.anything]
opaque = { stage = 2 }

[dependencies]

[profile.release]
panic = "abort"
lto = "fat"
strip = true
codegen-units = 1
"#;

    fn parsed(source: &str) -> Result<Manifest> {
        Manifest::parse(
            Path::new("/tmp/pkg"),
            Path::new("/tmp/pkg/Cargo.toml"),
            source,
        )
    }

    #[test]
    fn parses_dependency_free_manifest_compatibly() {
        let manifest = parsed(RED).unwrap();
        assert_eq!(manifest.name, "red");
        assert_eq!(manifest.crate_name, "red");
        assert_eq!(manifest.edition, Edition::E2024);
        assert_eq!(manifest.resolver, Resolver::V3);
        assert_eq!(manifest.metadata.authors, ["A", "B"]);
        assert!(manifest.release.panic_abort);
        assert_eq!(manifest.release.lto, Lto::Fat);
        assert_eq!(manifest.release.strip, Strip::Symbols);
        assert_eq!(manifest.release.codegen_units, Some(1));
    }

    #[test]
    fn parses_stage_two_manifest_models() {
        let source = r#"
[package]
name = "demo"
version = "1.2.3-alpha.1+build"
edition = "2021"
resolver = "2"
build = false

[lib]
name = "demo_lib"
path = "src/library.rs"

[[bin]]
name = "demo"
path = "src/program.rs"
bench = false
doc = false

[dependencies]
serde = { version = "=1.0.228", default-features = false, features = [
    "std",
] }
local-name = { package = "real-name", version = "^2.0", path = "../real" }

[target.'cfg(target_os = "motor")'.dependencies]
motor = "0.16"

[features]
default = ["serde/std", "dep:local-name"]
"fast+mode" = []

[patch.crates-io]
ring = { path = ".lorry/vendor/ring/source" }

[lints.rust]
unsafe_code = { level = "forbid", priority = 1 }
"#;
        let manifest = parsed(source).unwrap();
        assert_eq!(manifest.dependencies.len(), 3);
        assert_eq!(manifest.dependencies[0].package, "serde");
        assert!(!manifest.dependencies[0].default_features);
        assert!(matches!(
            manifest.dependencies[1].source,
            DependencySource::Path(_)
        ));
        assert_eq!(
            manifest.dependencies[2].target.as_deref(),
            Some("cfg(target_os = \"motor\")")
        );
        assert_eq!(manifest.features["default"].len(), 2);
        assert!(manifest.features.contains_key("fast+mode"));
        assert_eq!(manifest.patches[0].package, "ring");
        assert_eq!(manifest.rust_lints["unsafe_code"].priority, 1);
    }

    #[test]
    fn loads_lorrys_frozen_stage_two_manifest_and_lock() {
        let root = Path::new(".");
        assert!(root.join("Cargo.toml").is_file());
        let manifest = Manifest::load(root).unwrap();
        assert_eq!(manifest.name, "lorry");
        assert_eq!(manifest.dependencies.len(), 8);
        assert!(manifest.dependencies.iter().any(|dependency| {
            dependency.package == "moto-rt"
                && dependency.target.as_deref() == Some("cfg(target_os = \"motor\")")
                && matches!(dependency.source, DependencySource::Path(_))
        }));
        assert_eq!(manifest.lock.as_ref().unwrap().packages.len(), 40);
    }

    #[test]
    fn rejects_unknown_and_unsupported_build_semantics() {
        for source in [
            format!("{RED}\n[dev-dependencies]\nhelper = \"1\"\n"),
            RED.replace(
                "[dependencies]",
                "[dependencies]\nthing = { version = \"1\", git = \"https://example.test/x\" }",
            ),
            format!("{RED}\n[workspace]\nmembers = []\n"),
            format!("{RED}\n[lib]\nproc-macro = true\n"),
        ] {
            let error = parsed(&source).unwrap_err();
            assert!(
                error.to_string().contains("supported") || error.to_string().contains("unknown"),
                "{error}"
            );
        }
    }

    #[test]
    fn rejects_malformed_values_duplicates_and_semver() {
        for input in [
            RED.replace("name = \"red\"", "name = \"unterminated"),
            RED.replace("version = \"0.1.0\"", "version = \"1\""),
            RED.replace("edition = \"2024\"", "edition = \"2050\""),
            RED.replace("name = \"red\"", "name = \"red\"\nname = \"again\""),
            RED.replace("codegen-units = 1", "codegen-units = 0"),
        ] {
            assert!(parsed(&input).is_err());
        }
    }

    #[test]
    fn validates_full_version_four_lockfile() {
        let mut manifest =
            parsed(&RED.replace("[dependencies]", "[dependencies]\nserde = \"=1.0.228\"")).unwrap();
        manifest.name = "red".to_owned();
        let valid = r#"
version = 4

[[package]]
name = "red"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "9a8e94ea7f378bd32cbbd37198a4a91436180c5bb472411e48b5ec2e2124ae9e"
"#;
        let lock = validate_lock_source(&manifest, Path::new("Cargo.lock"), valid).unwrap();
        assert_eq!(lock.packages.len(), 2);

        for invalid in [
            valid.replace("version = 4", "version = 3"),
            valid.replace("name = \"red\"", "name = \"other\""),
            valid.replace(
                "registry+https://github.com/rust-lang/crates.io-index",
                "git+https://example.test/repo",
            ),
            format!(
                "{valid}\n[[package]]\nname = \"serde\"\nversion = \"1.0.228\"\nsource = \"{CRATES_IO_SOURCE}\"\nchecksum = \"9a8e94ea7f378bd32cbbd37198a4a91436180c5bb472411e48b5ec2e2124ae9e\"\n"
            ),
        ] {
            assert!(validate_lock_source(&manifest, Path::new("Cargo.lock"), &invalid).is_err());
        }
    }
}
