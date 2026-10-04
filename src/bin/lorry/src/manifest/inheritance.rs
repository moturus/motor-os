use std::path::{Component, Path, PathBuf};

use toml_edit::{Item, Table, Value};

use super::{InheritedPackage, string_array, type_error};
use crate::diagnostic::{Error, Result};
use crate::toml::Document;

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
