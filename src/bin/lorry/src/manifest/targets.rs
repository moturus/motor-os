use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use toml_edit::{Item, Table};

use super::{
    Edition, optional_bool, optional_string, optional_string_array, parse_edition, required_string,
    type_error, unsupported_key, validate_relative_path,
};
use crate::diagnostic::{Error, Result};
use crate::toml::Document;

const MAX_TARGETS: usize = 1_024;

/// Cargo's non-library target kinds, in its metadata order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum TargetKind {
    Bin,
    Example,
    Test,
    Bench,
}

impl TargetKind {
    pub(crate) const ALL: [Self; 4] = [Self::Bin, Self::Example, Self::Test, Self::Bench];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Bin => "bin",
            Self::Example => "example",
            Self::Test => "test",
            Self::Bench => "bench",
        }
    }

    pub(super) fn description(self) -> &'static str {
        match self {
            Self::Bin => "binary",
            Self::Example => "example",
            Self::Test => "integration-test",
            Self::Bench => "bench",
        }
    }

    fn directory(self) -> &'static str {
        match self {
            Self::Bin => "src/bin",
            Self::Example => "examples",
            Self::Test => "tests",
            Self::Bench => "benches",
        }
    }

    fn auto_key(self) -> &'static str {
        match self {
            Self::Bin => "autobins",
            Self::Example => "autoexamples",
            Self::Test => "autotests",
            Self::Bench => "autobenches",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Target {
    pub kind: TargetKind,
    pub name: String,
    pub path: PathBuf,
    pub crate_types: Vec<String>,
    pub required_features: Option<Vec<String>>,
    pub edition: Edition,
    pub test: bool,
    pub bench: bool,
    pub doc: bool,
    pub harness: bool,
}

impl Target {
    fn new(kind: TargetKind, name: String, path: PathBuf, edition: Edition) -> Self {
        Self {
            kind,
            name,
            path,
            crate_types: vec!["bin".to_owned()],
            required_features: None,
            edition,
            test: matches!(kind, TargetKind::Bin | TargetKind::Test),
            bench: matches!(kind, TargetKind::Bin | TargetKind::Bench),
            doc: kind == TargetKind::Bin,
            harness: true,
        }
    }
}

pub(super) struct Package<'a> {
    pub root: &'a Path,
    pub path: &'a Path,
    pub document: &'a Document,
    pub table: &'a Table,
    pub name: &'a str,
    pub edition: Edition,
    pub has_library: bool,
}

/// Merges explicit `[[kind]]` tables with inferred targets as Cargo does.
/// Cargo drops an explicit test, example, or bench whose source cannot be
/// inferred; its error is kept in `unresolved` for member loaders.
pub(super) fn parse(
    package: &Package<'_>,
    kind: TargetKind,
    warnings: &mut Vec<String>,
    unresolved: &mut Option<Error>,
) -> Result<Vec<Target>> {
    let (path, document) = (package.path, package.document);
    let inferred = infer(package, kind)?;
    let explicit = document.root().get(kind.as_str());
    let mut targets = Vec::new();
    let mut names = BTreeSet::new();
    let mut paths = BTreeSet::new();
    if let Some(item) = explicit {
        let tables = item.as_array_of_tables().ok_or_else(|| {
            type_error(
                path,
                document.line_of_item(item),
                kind.as_str(),
                "an array of tables",
            )
        })?;
        for table in tables {
            let mut target = parse_table(package, kind, table, warnings)?;
            if !names.insert(target.name.clone()) {
                return Err(Error::at(
                    path,
                    document.line_of_table(table),
                    format!("duplicate {} target `{}`", kind.description(), target.name),
                    format!("give every `[[{}]]` target a distinct name", kind.as_str()),
                ));
            }
            if table.contains_key("path") {
                paths.insert(target.path.clone());
            } else if let Some(source) =
                inferred_path(package, kind, &target.name, &inferred, warnings)?
            {
                target.path = source;
            } else {
                unresolved.get_or_insert_with(|| unresolved_path(kind, &target.name));
                continue;
            }
            targets.push(target);
        }
    }
    let remaining = inferred
        .into_iter()
        .filter(|(name, source)| !names.contains(name) && !paths.contains(source))
        .collect::<Vec<_>>();
    let auto = package.table.get(kind.auto_key()).and_then(Item::as_bool);
    if auto.unwrap_or(explicit.is_none() || package.edition != Edition::E2015) {
        for (name, source) in remaining {
            validate_target_name(path, 1, &name)?;
            targets.push(Target::new(kind, name, source, package.edition));
        }
    } else if auto.is_none() && !remaining.is_empty() {
        warnings.push(format!(
            "{}: an explicit [[{}]] section disables automatic {} target inference in edition 2015; set `{}` explicitly",
            path.display(),
            kind.as_str(),
            kind.description(),
            kind.auto_key()
        ));
    }
    if targets.len() > MAX_TARGETS {
        return Err(Error::failure(format!(
            "package describes more than {MAX_TARGETS} {} targets",
            kind.description()
        )));
    }
    targets.sort_by(|left, right| left.name.cmp(&right.name));
    if let Some(pair) = targets.windows(2).find(|pair| pair[0].name == pair[1].name) {
        return Err(Error::failure(format!(
            "found duplicate {} name `{}`",
            kind.description(),
            pair[0].name
        ))
        .with_help(format!(
            "all {} targets must have a unique name",
            kind.as_str()
        )));
    }
    // Integration-test crates must also be distinct after `-` becomes `_`.
    let mut crate_names = BTreeSet::new();
    if kind == TargetKind::Test
        && let Some(target) = targets
            .iter()
            .find(|target| !crate_names.insert(target.name.replace('-', "_")))
    {
        return Err(Error::failure(format!(
            "integration-test target `{}` has duplicate crate name `{}`",
            target.name,
            target.name.replace('-', "_")
        )));
    }
    Ok(targets)
}

fn parse_table(
    package: &Package<'_>,
    kind: TargetKind,
    table: &Table,
    warnings: &mut Vec<String>,
) -> Result<Target> {
    let (path, document, section) = (package.path, package.document, kind.as_str());
    for (key, item) in table.iter() {
        if !matches!(
            key,
            "name"
                | "path"
                | "test"
                | "doc"
                | "doc-scrape-examples"
                | "bench"
                | "doctest"
                | "harness"
                | "required-features"
                | "crate-type"
                | "edition"
        ) {
            return Err(unsupported_key(
                path,
                document,
                item,
                &format!("{section}.{key}"),
            ));
        }
    }
    let name = required_string(path, document, table, section, "name")?;
    let line = document.line_of_table(table);
    validate_target_name(path, line, &name)?;
    let mut source = PathBuf::new();
    if let Some(relative) = optional_string(path, document, table, section, "path")? {
        validate_relative_path(path, line, &format!("{section}.path"), &relative)?;
        source = package.root.join(relative);
    }
    for flag in ["doctest", "doc-scrape-examples"] {
        optional_bool(path, document, table, section, flag)?;
    }
    let crate_types = optional_string_array(path, document, table, section, "crate-type")?;
    // Cargo rejects binary crate types and ignores them on tests and benches.
    if let Some(types) = &crate_types
        && (kind == TargetKind::Bin
            || types.is_empty()
            || types.iter().any(|value| {
                !matches!(
                    value.as_str(),
                    "bin" | "lib" | "rlib" | "dylib" | "cdylib" | "staticlib" | "proc-macro"
                )
            }))
    {
        return Err(Error::failure(format!("unsupported {section} crate-type")));
    }
    let mut target = Target::new(kind, name, source, package.edition);
    if kind == TargetKind::Example
        && let Some(types) = crate_types
    {
        target.crate_types = types;
    }
    target.required_features =
        optional_string_array(path, document, table, section, "required-features")?;
    if let Some(item) = table.get("edition") {
        warnings.push(format!(
            "{}: `edition` is set on {section} `{}` which is deprecated",
            path.display(),
            target.name
        ));
        target.edition = parse_edition(path, document, Some(item), line, None)?;
    }
    let flags = [
        ("test", &mut target.test),
        ("bench", &mut target.bench),
        ("doc", &mut target.doc),
        ("harness", &mut target.harness),
    ];
    for (key, value) in flags {
        if let Some(flag) = optional_bool(path, document, table, section, key)? {
            *value = flag;
        }
    }
    Ok(target)
}

/// Like Cargo, accepts any non-empty name; rustc rejects one that is not a
/// valid crate name when the target is built. Lorry also uses the name as a
/// file name, so it must be one.
fn validate_target_name(path: &Path, line: usize, name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 255
        || matches!(name, "." | "..")
        || name
            .chars()
            .any(|character| matches!(character, '/' | '\\') || character.is_control())
    {
        return Err(Error::at(
            path,
            line,
            format!("unsupported target name `{name}`"),
            "use a name that is also a file name",
        ));
    }
    Ok(())
}

/// Returns the single inferred source for `name`. Only a binary fails here.
fn inferred_path(
    package: &Package<'_>,
    kind: TargetKind,
    name: &str,
    inferred: &[(String, PathBuf)],
    warnings: &mut Vec<String>,
) -> Result<Option<PathBuf>> {
    let mut matches = inferred
        .iter()
        .filter(|(candidate, _)| candidate == name)
        .map(|(_, source)| source);
    if let (Some(source), None) = (matches.next(), matches.next()) {
        return Ok(Some(source.clone()));
    }
    if kind != TargetKind::Bin {
        return Ok(None);
    }
    if package.edition == Edition::E2015
        && let Some(legacy) = legacy_binary_path(package.root, name, package.has_library)
    {
        warnings.push(format!(
            "path `{}` was erroneously implicitly accepted for binary `{name}`,\nplease set bin.path in Cargo.toml",
            legacy.strip_prefix(package.root).unwrap().display()
        ));
        return Ok(Some(legacy));
    }
    Err(unresolved_path(kind, name))
}

fn unresolved_path(kind: TargetKind, name: &str) -> Error {
    Error::failure(format!(
        "cannot infer source path for {} `{name}`; specify `{}.path`",
        kind.description(),
        kind.as_str()
    ))
}

fn legacy_binary_path(root: &Path, name: &str, has_library: bool) -> Option<PathBuf> {
    let named = root.join("src").join(format!("{name}.rs"));
    if !has_library && named.is_file() {
        return Some(named);
    }
    [root.join("src/main.rs"), root.join("src/bin/main.rs")]
        .into_iter()
        .find(|path| path.is_file())
}

/// Infers `name.rs` files and `name/main.rs` directories like Cargo: hidden
/// and non-UTF-8 entries are skipped, and a symbolic link is never a directory.
fn infer(package: &Package<'_>, kind: TargetKind) -> Result<Vec<(String, PathBuf)>> {
    let mut inferred = Vec::new();
    let main = package.root.join("src/main.rs");
    if kind == TargetKind::Bin && main.is_file() {
        inferred.push((package.name.to_owned(), main));
    }
    let directory = package.root.join(kind.directory());
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            return Ok(inferred);
        }
        Err(error) => {
            return Err(Error::failure(format!(
                "failed to discover {} targets in `{}`: {error}",
                kind.description(),
                directory.display()
            )));
        }
    };
    for entry in entries {
        let entry = entry.map_err(|error| {
            Error::failure(format!("failed to read `{}`: {error}", directory.display()))
        })?;
        let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let source = entry.path();
        let file_type = entry.file_type().map_err(|error| {
            Error::failure(format!("failed to inspect `{}`: {error}", source.display()))
        })?;
        let (name, source) = if file_name.starts_with('.') {
            continue;
        } else if file_type.is_dir() && source.join("main.rs").exists() {
            (file_name, source.join("main.rs"))
        } else if let Some(stem) = file_name.strip_suffix(".rs")
            && !file_type.is_dir()
        {
            (stem.to_owned(), source)
        } else {
            continue;
        };
        inferred.push((name, source));
    }
    inferred.sort();
    Ok(inferred)
}
