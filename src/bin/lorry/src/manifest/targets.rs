use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use toml_edit::{Item, Table};

use super::{
    Edition, MAX_DESCRIBED_TARGETS, optional_bool, optional_string, optional_string_array,
    parse_edition, required_string, type_error, unsupported_key, validate_package_name,
    validate_relative_path,
};
use crate::diagnostic::{Error, Result};
use crate::toml::Document;

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DescribedTarget {
    pub kind: &'static str,
    pub name: String,
    pub path: PathBuf,
    pub crate_types: Vec<String>,
    pub required_features: Vec<String>,
    pub edition: Edition,
    pub test: bool,
    pub doc: bool,
    pub harness: bool,
}

pub(super) fn parse(
    root: &Path,
    path: &Path,
    document: &Document,
    package: &Table,
    edition: Edition,
    kind: &'static str,
    warnings: &mut Vec<String>,
) -> Result<Vec<DescribedTarget>> {
    let directory = if kind == "example" {
        "examples"
    } else {
        "benches"
    };
    let mut targets = BTreeMap::new();
    {
        let entries = match fs::read_dir(root.join(directory)) {
            Ok(entries) => Some(entries),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(Error::failure(format!(
                    "failed to discover {directory}: {error}"
                )));
            }
        };
        for entry in entries.into_iter().flatten() {
            let entry = entry
                .map_err(|error| Error::failure(format!("failed to read {directory}: {error}")))?;
            let source = entry.path();
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with('.'))
            {
                continue;
            }
            let (name, source) =
                if source.is_file() && source.extension().is_some_and(|value| value == "rs") {
                    (source.file_stem().unwrap().to_owned(), source)
                } else if source.is_dir() && source.join("main.rs").is_file() {
                    (entry.file_name(), source.join("main.rs"))
                } else {
                    continue;
                };
            let name = name
                .into_string()
                .map_err(|_| Error::failure("target name is not UTF-8"))?;
            validate_package_name(path, 1, &name)?;
            let target = DescribedTarget {
                kind,
                name: name.clone(),
                path: source,
                crate_types: vec!["bin".to_owned()],
                required_features: Vec::new(),
                edition,
                test: false,
                doc: false,
                harness: true,
            };
            if targets.insert(name.clone(), target).is_some() {
                return Err(Error::failure(format!("duplicate {kind} target `{name}`")));
            }
            if targets.len() > MAX_DESCRIBED_TARGETS {
                return Err(Error::failure(format!("too many {kind} targets")));
            }
        }
    }
    let discovered = targets.clone();
    let explicit = document.root().get(kind);
    let automatic = package
        .get(&format!("auto{directory}"))
        .and_then(Item::as_bool)
        .unwrap_or(edition != Edition::E2015 || explicit.is_none());
    if !automatic {
        targets.clear();
    }
    if let Some(item) = explicit {
        let tables = item.as_array_of_tables().ok_or_else(|| {
            type_error(
                path,
                document.line_of_item(item),
                kind,
                "an array of tables",
            )
        })?;
        let mut names = BTreeSet::new();
        for table in tables {
            for (key, item) in table.iter() {
                if !matches!(
                    key,
                    "name"
                        | "path"
                        | "test"
                        | "doc"
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
                        &format!("{kind}.{key}"),
                    ));
                }
            }
            let name = required_string(path, document, table, kind, "name")?;
            validate_package_name(path, document.line_of_table(table), &name)?;
            if !names.insert(name.clone()) {
                return Err(Error::failure(format!("duplicate {kind} target `{name}`")));
            }
            let inferred = discovered.get(&name).map(|target| target.path.clone());
            let source = match optional_string(path, document, table, kind, "path")? {
                Some(relative) => {
                    validate_relative_path(
                        path,
                        document.line_of_table(table),
                        &format!("{kind}.path"),
                        &relative,
                    )?;
                    root.join(relative)
                }
                None => inferred.unwrap_or_else(|| root.join(directory).join(format!("{name}.rs"))),
            };
            if !source.is_file() {
                return Err(Error::failure(format!(
                    "{kind} source `{}` does not exist",
                    source.display()
                )));
            }
            for flag in ["bench", "doctest"] {
                optional_bool(path, document, table, kind, flag)?;
            }
            let crate_types = optional_string_array(path, document, table, kind, "crate-type")?
                .unwrap_or_else(|| vec!["bin".to_owned()]);
            if crate_types.is_empty()
                || crate_types.iter().any(|value| {
                    !matches!(
                        value.as_str(),
                        "bin" | "lib" | "rlib" | "dylib" | "cdylib" | "staticlib" | "proc-macro"
                    )
                })
            {
                return Err(Error::failure(format!("unsupported {kind} crate-type")));
            }
            let target = DescribedTarget {
                kind,
                name: name.clone(),
                path: source,
                crate_types: if kind == "bench" {
                    vec!["bin".to_owned()]
                } else {
                    crate_types
                },
                required_features: optional_string_array(
                    path,
                    document,
                    table,
                    kind,
                    "required-features",
                )?
                .unwrap_or_default(),
                edition: if let Some(item) = table.get("edition") {
                    warnings.push(format!(
                        "{}: `edition` is set on {kind} `{name}` which is deprecated",
                        path.display()
                    ));
                    parse_edition(path, document, Some(item), 1, None)?
                } else {
                    edition
                },
                test: optional_bool(path, document, table, kind, "test")?.unwrap_or(false),
                doc: optional_bool(path, document, table, kind, "doc")?.unwrap_or(false),
                harness: optional_bool(path, document, table, kind, "harness")?.unwrap_or(true),
            };
            targets.retain(|inferred_name, inferred| {
                names.contains(inferred_name) || inferred.path != target.path
            });
            targets.insert(name, target);
            if targets.len() > MAX_DESCRIBED_TARGETS {
                return Err(Error::failure(format!("too many {kind} targets")));
            }
        }
    }
    if !automatic
        && edition == Edition::E2015
        && explicit.is_some()
        && !package.contains_key(&format!("auto{directory}"))
        && discovered.values().any(|target| {
            !targets.contains_key(&target.name)
                && !targets
                    .values()
                    .any(|explicit| explicit.path == target.path)
        })
    {
        warnings.push(format!("{}: explicit [[{kind}]] sections disable automatic {directory} discovery in edition 2015; set auto{directory} to select the intended behavior", path.display()));
    }
    Ok(targets.into_values().collect())
}
