use std::path::Path;

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
        let workspace = match item {
            Item::Table(table) if table.len() == 1 => {
                table.get("workspace").and_then(Item::as_bool)
            }
            Item::Value(Value::InlineTable(table)) if table.len() == 1 => {
                table.get("workspace").and_then(Value::as_bool)
            }
            _ => None,
        };
        if workspace == Some(true) {
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
}
