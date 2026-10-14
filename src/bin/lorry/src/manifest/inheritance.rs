use std::path::{Component, Path, PathBuf};

use toml_edit::{Item, Table, Value};

use super::{
    Dependency, DependencyFields, DependencyTable, Edition, InheritedPackage, lookup_bool,
    node_string_array, parse_dependency, require_table, string_array, type_error,
};
use crate::diagnostic::{Error, Result};
use crate::sparse::DependencyKind;
use crate::toml::Document;

pub(super) fn validate_dependencies(
    path: &Path,
    document: &Document,
    workspace: &Table,
) -> Result<()> {
    let Some(item) = workspace.get("dependencies") else {
        return Ok(());
    };
    let dependencies = require_table(path, document, item, "workspace.dependencies")?;
    for (alias, item) in dependencies.iter() {
        let lookup = match item {
            Item::Table(table) => Some(DependencyTable::Regular(table)),
            Item::Value(Value::InlineTable(table)) => Some(DependencyTable::Inline(table)),
            _ => None,
        };
        if let Some(lookup) = lookup
            && lookup_bool(path, document, &lookup, alias, "optional")? == Some(true)
        {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("workspace dependency `{alias}` cannot be optional"),
                "set optional = true on the member's inherited dependency instead",
            ));
        }
    }
    Ok(())
}

pub(super) fn dependency(
    fields: &mut DependencyFields<'_>,
    alias: &str,
    member: &DependencyTable<'_>,
    line: usize,
    target: Option<&str>,
    kind: DependencyKind,
) -> Result<Dependency> {
    let path = fields.path;
    let document = fields.document;
    if lookup_bool(path, document, member, alias, "workspace")? != Some(true) {
        return Err(Error::at(
            path,
            line,
            "dependency.workspace must be true",
            "remove workspace = false or inherit with workspace = true",
        ));
    }
    for (key, value) in member.entries() {
        if !matches!(
            key,
            "workspace" | "features" | "optional" | "default-features" | "default_features"
        ) {
            return Err(Error::at(
                path,
                value.line(document),
                format!("unsupported inherited dependency key `{key}`"),
                "define dependency sources at the workspace root",
            ));
        }
    }
    let inherited = fields.inherited.ok_or_else(|| {
        Error::failure(format!(
            "dependency `{alias}` inherits from a missing workspace"
        ))
    })?;
    let item = inherited
        .document
        .root()
        .get("workspace")
        .and_then(Item::as_table)
        .and_then(|table| table.get("dependencies"))
        .and_then(Item::as_table)
        .and_then(|table| table.get(alias))
        .ok_or_else(|| {
            Error::at(
                path,
                line,
                format!("inherited workspace.dependencies.{alias} is not defined"),
                "define the dependency at the workspace root",
            )
        })?;
    let mut dependency = parse_dependency(
        &mut DependencyFields {
            path: &inherited.path,
            document: &inherited.document,
            root: inherited.path.parent().unwrap(),
            inherited: None,
            edition: fields.edition,
            warnings: fields.warnings,
        },
        alias,
        item,
        target,
        kind,
    )?;
    // Edition 2024 permits disabling inherited defaults. Older editions keep
    // the workspace defaults and report Cargo's compatibility warning.
    // Cargo folds member aliases into the canonical field before validating
    // the merged dependency; the root declaration keeps its edition checks.
    let modern = lookup_bool(path, document, member, alias, "default-features")?;
    let legacy = lookup_bool(path, document, member, alias, "default_features")?;
    if let Some(defaults) = modern.or(legacy) {
        if fields.edition != Edition::E2024 && !defaults && dependency.default_features {
            let specified = match item {
                Item::Table(table) => {
                    table.contains_key("default-features") || table.contains_key("default_features")
                }
                Item::Value(Value::InlineTable(table)) => {
                    table.contains_key("default-features") || table.contains_key("default_features")
                }
                _ => false,
            };
            fields.warnings.push(format!(
                "{}: `default-features` is ignored for {alias}, since `default-features` was {} \
                 for `workspace.dependencies.{alias}`; overriding workspace `default-features` \
                 to false requires Rust 1.99+ and the 2024 edition",
                path.display(),
                if specified { "true" } else { "not specified" },
            ));
        } else {
            dependency.default_features = defaults;
        }
    }
    dependency.optional = lookup_bool(path, document, member, alias, "optional")?.unwrap_or(false);
    if let Some(value) = member.get("features") {
        dependency.features.extend(node_string_array(
            path,
            document,
            value,
            &format!("dependencies.{alias}.features"),
        )?);
    }
    Ok(dependency)
}

pub(super) struct PackageFields<'a> {
    path: &'a Path,
    document: &'a Document,
    package: &'a Table,
    inherited: Option<&'a InheritedPackage>,
}

pub(super) struct Field<'a> {
    pub path: &'a Path,
    pub document: &'a Document,
    pub item: &'a Item,
}

pub(super) fn lint_table<'a>(
    path: &'a Path,
    document: &'a Document,
    inherited: Option<&'a InheritedPackage>,
) -> Result<Option<Field<'a>>> {
    let Some(item) = document.root().get("lints") else {
        return Ok(None);
    };
    let table = require_table(path, document, item, "lints")?;
    let Some(workspace) = table.get("workspace") else {
        return Ok(Some(Field {
            path,
            document,
            item,
        }));
    };
    let value = workspace.as_bool().ok_or_else(|| {
        type_error(
            path,
            document.line_of_item(workspace),
            "lints.workspace",
            "a boolean",
        )
    })?;
    if !value {
        return Ok(Some(Field {
            path,
            document,
            item,
        }));
    }
    if table.len() != 1 {
        return Err(Error::at(
            path,
            document.line_of_item(item),
            "inherited workspace lints cannot have member overrides",
            "remove the member lint tables or lints.workspace = true",
        ));
    }
    let inherited =
        inherited.ok_or_else(|| Error::failure("lints inherit from a missing workspace"))?;
    let item = inherited
        .document
        .root()
        .get("workspace")
        .and_then(Item::as_table)
        .and_then(|table| table.get("lints"))
        .ok_or_else(|| Error::failure("inherited workspace.lints is not defined"))?;
    Ok(Some(Field {
        path: &inherited.path,
        document: &inherited.document,
        item,
    }))
}

impl<'a> PackageFields<'a> {
    pub fn new(
        path: &'a Path,
        document: &'a Document,
        package: &'a Table,
        inherited: Option<&'a InheritedPackage>,
    ) -> Self {
        Self {
            path,
            document,
            package,
            inherited,
        }
    }

    // Keep each field attached to its original document, so inherited type
    // errors point to the workspace declaration rather than a member's line.
    pub fn get(&self, key: &str) -> Result<Option<Field<'a>>> {
        let Some(item) = self.package.get(key) else {
            return Ok(None);
        };
        if uses_workspace(item) {
            let inherited = self.inherited.ok_or_else(|| self.missing(key, item))?;
            let item = inherited
                .document
                .root()
                .get("workspace")
                .and_then(Item::as_table)
                .and_then(|table| table.get("package"))
                .and_then(Item::as_table)
                .and_then(|table| table.get(key))
                .ok_or_else(|| self.missing(key, item))?;
            return Ok(Some(Field {
                path: &inherited.path,
                document: &inherited.document,
                item,
            }));
        }
        Ok(Some(Field {
            path: self.path,
            document: self.document,
            item,
        }))
    }

    fn missing(&self, key: &str, item: &Item) -> Error {
        Error::at(
            self.path,
            self.document.line_of_item(item),
            format!("package.{key} inherits a missing workspace.package.{key}"),
            format!("define workspace.package.{key} at the workspace root"),
        )
    }

    pub fn string(&self, key: &str) -> Result<Option<String>> {
        self.get(key)?
            .map(|field| {
                field.item.as_str().map(str::to_owned).ok_or_else(|| {
                    type_error(
                        field.path,
                        field.document.line_of_item(field.item),
                        &format!("package.{key}"),
                        "a string",
                    )
                })
            })
            .transpose()
    }

    pub fn array(&self, key: &str) -> Result<Option<Vec<String>>> {
        self.get(key)?
            .map(|field| {
                string_array(
                    field.path,
                    field.document,
                    field.item,
                    &format!("package.{key}"),
                )
            })
            .transpose()
    }

    pub fn publish(&self) -> Result<Option<Vec<String>>> {
        match self.get("publish")? {
            None => Ok(None),
            Some(field) if field.item.as_bool() == Some(true) => Ok(None),
            Some(field) if field.item.as_bool() == Some(false) => Ok(Some(Vec::new())),
            Some(_) => self.array("publish"),
        }
    }

    pub fn file(&self, key: &str, root: &Path) -> Result<String> {
        let Some(value) = self.string(key)? else {
            return Ok(String::new());
        };
        if self.package.get(key).is_some_and(uses_workspace) {
            rebase(self.inherited.unwrap().path.parent().unwrap(), root, &value)
        } else {
            Ok(value)
        }
    }

    pub fn readme(&self, root: &Path) -> Result<String> {
        let item = self.package.get("readme");
        if let Some(item) = item.filter(|item| uses_workspace(item)) {
            let inherited = self.inherited.ok_or_else(|| self.missing("readme", item))?;
            let base = inherited.path.parent().unwrap();
            let value = inherited
                .document
                .root()
                .get("workspace")
                .and_then(Item::as_table)
                .and_then(|table| table.get("package"))
                .and_then(Item::as_table)
                .and_then(|table| table.get("readme"));
            let readme = normalize_readme(&inherited.path, &inherited.document, value, base)?
                .ok_or_else(|| self.missing("readme", item))?;
            return rebase(base, root, &readme);
        }
        Ok(normalize_readme(self.path, self.document, item, root)?.unwrap_or_default())
    }
}

fn uses_workspace(item: &Item) -> bool {
    match item {
        Item::Table(table) if table.len() == 1 => {
            table.get("workspace").and_then(Item::as_bool) == Some(true)
        }
        Item::Value(Value::InlineTable(table)) if table.len() == 1 => {
            table.get("workspace").and_then(Value::as_bool) == Some(true)
        }
        _ => false,
    }
}

fn normalize_readme(
    path: &Path,
    document: &Document,
    item: Option<&Item>,
    root: &Path,
) -> Result<Option<String>> {
    match item {
        None => Ok(["README.md", "README.txt", "README"]
            .into_iter()
            .find(|candidate| root.join(candidate).is_file())
            .map(str::to_owned)),
        Some(item) if item.as_bool() == Some(false) => Ok(None),
        Some(item) if item.as_bool() == Some(true) => Ok(Some("README.md".to_owned())),
        Some(item) => item.as_str().map(str::to_owned).map(Some).ok_or_else(|| {
            type_error(
                path,
                document.line_of_item(item),
                "package.readme",
                "a string or boolean",
            )
        }),
    }
}

fn rebase(base: &Path, root: &Path, value: &str) -> Result<String> {
    let mut target = PathBuf::new();
    for component in base.join(value).components() {
        match component {
            Component::ParentDir => {
                target.pop();
            }
            Component::CurDir => {}
            other => target.push(other),
        }
    }
    let common = target
        .components()
        .zip(root.components())
        .take_while(|(left, right)| left == right)
        .count();
    let mut relative = PathBuf::new();
    for _ in root.components().skip(common) {
        relative.push("..");
    }
    for component in target.components().skip(common) {
        relative.push(component);
    }
    relative.to_str().map(str::to_owned).ok_or_else(|| {
        Error::failure(format!(
            "inherited package path `{}` is not UTF-8",
            relative.display()
        ))
    })
}
