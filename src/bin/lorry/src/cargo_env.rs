//! Cargo configuration environment, merged before consulting the caller.
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::diagnostic::{Error, Result};
use crate::toml::Document;

#[derive(Default)]
pub(crate) struct Definitions(BTreeMap<String, Definition>);

#[derive(Default)]
struct Definition {
    file: PathBuf,
    line: usize,
    table: bool,
    value: Option<(String, PathBuf)>,
    force: Option<bool>,
    relative: Option<bool>,
}

impl Definitions {
    pub(crate) fn merge(
        &mut self,
        path: &Path,
        document: &Document,
        item: &toml_edit::Item,
    ) -> Result<()> {
        let error = |item, message: String| {
            Error::at(
                path,
                document.line_of_item(item),
                message,
                "use an environment string or a table with value, force, and relative",
            )
        };
        let table = item
            .as_table_like()
            .ok_or_else(|| error(item, "Cargo `env` must be a table".to_owned()))?;
        let root = path
            .parent()
            .and_then(Path::parent)
            .unwrap_or(Path::new("/"));
        for (name, item) in table.iter() {
            if matches!(name, "CARGO_HOME" | "RUSTUP_HOME" | "RUSTUP_TOOLCHAIN") {
                return Err(error(
                    item,
                    format!("Cargo does not allow `{name}` in `[env]`"),
                ));
            }
            if name.is_empty() || name.contains(['=', '\0']) {
                return Err(error(
                    item,
                    format!("invalid Cargo environment name `{name}`"),
                ));
            }
            let mut definition = Definition {
                file: path.to_path_buf(),
                line: document.line_of_item(item),
                ..Definition::default()
            };
            if let Some(value) = item.as_str() {
                definition.value = Some((value.to_owned(), root.to_path_buf()));
            } else if let Some(fields) = item.as_table_like() {
                definition.table = true;
                for (field, value) in fields.iter() {
                    match field {
                        "value" => {
                            definition.value = Some((
                                value
                                    .as_str()
                                    .ok_or_else(|| {
                                        error(value, format!("env.{name}.value must be a string"))
                                    })?
                                    .to_owned(),
                                root.to_path_buf(),
                            ))
                        }
                        "force" | "relative" => {
                            let flag = value.as_bool().ok_or_else(|| {
                                error(value, format!("env.{name}.{field} must be a boolean"))
                            })?;
                            if field == "force" {
                                definition.force = Some(flag);
                            } else {
                                definition.relative = Some(flag);
                            }
                        }
                        _ => {
                            return Err(error(
                                value,
                                format!("unsupported Cargo environment key `env.{name}.{field}`"),
                            ));
                        }
                    }
                }
            } else {
                return Err(error(
                    item,
                    format!("invalid Cargo environment value for `{name}`"),
                ));
            }
            if definition
                .value
                .as_ref()
                .is_some_and(|(value, _)| value.contains('\0'))
            {
                return Err(error(
                    item,
                    format!("Cargo environment value for `{name}` contains NUL"),
                ));
            }
            if let Some(previous) = self.0.get_mut(name) {
                if previous.table != definition.table {
                    return Err(error(
                        item,
                        format!("conflicting string and table definitions for `env.{name}`"),
                    ));
                }
                if definition.value.is_some() {
                    previous.value = definition.value;
                }
                if definition.force.is_some() {
                    previous.force = definition.force;
                }
                if definition.relative.is_some() {
                    previous.relative = definition.relative;
                }
                previous.file = definition.file;
                previous.line = definition.line;
            } else {
                self.0.insert(name.to_owned(), definition);
            }
        }
        Ok(())
    }

    pub(crate) fn resolve(
        self,
        mut caller: impl FnMut(&str) -> Option<OsString>,
    ) -> Result<BTreeMap<String, OsString>> {
        self.0
            .into_iter()
            .map(|(name, definition)| {
                let (value, root) = definition.value.ok_or_else(|| {
                    Error::at(
                        &definition.file,
                        definition.line,
                        format!("Cargo `env.{name}` is missing `value`"),
                        "set `value` to an environment string",
                    )
                })?;
                let configured = if definition.relative.unwrap_or(false) {
                    root.join(value).into_os_string()
                } else {
                    value.into()
                };
                let value = if definition.force.unwrap_or(false) {
                    configured
                } else {
                    caller(&name).unwrap_or(configured)
                };
                Ok((name, value))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definitions(text: &str) -> Result<Definitions> {
        let path = Path::new("/workspace/.cargo/config.toml");
        let document = Document::parse(path, "Cargo environment", text.to_owned())?;
        let mut definitions = Definitions::default();
        definitions.merge(path, &document, &document.root()["env"])?;
        Ok(definitions)
    }

    #[test]
    fn rejects_invalid_environment_before_starting_children() {
        for text in [
            "[env]\nA = 3",
            "[env]\nA = {}",
            "[env]\nA = { force = true }",
            "[env]\nA = { value = 1 }",
            "[env]\nA = { value = 'v', force = 'true' }",
            "[env]\nA = { value = 'v', relative = 1 }",
            "[env]\nA = { value = 'v', unknown = true }",
            "[env]\n'' = 'v'",
            "[env]\n'A=B' = 'v'",
            "[env]\nA = \"\\u0000\"",
            "[env]\nCARGO_HOME = 'other'",
            "[env]\nRUSTUP_HOME = 'other'",
            "[env]\nRUSTUP_TOOLCHAIN = 'other'",
        ] {
            assert!(
                definitions(text).and_then(|d| d.resolve(|_| None)).is_err(),
                "accepted {text}"
            );
        }
    }

    #[test]
    fn missing_value_names_its_definition() {
        let error = definitions("[env]\nA = { force = true }")
            .unwrap()
            .resolve(|_| None)
            .unwrap_err();
        let diagnostic = error.render();
        assert!(
            diagnostic.contains("/workspace/.cargo/config.toml:2"),
            "{diagnostic}"
        );
        assert!(diagnostic.contains("missing `value`"));
    }

    #[cfg(unix)]
    #[test]
    fn preserves_non_unicode_caller_values() {
        use std::os::unix::ffi::OsStringExt;
        let non_unicode = OsString::from_vec(vec![0xff]);
        let values = definitions("[env]\nA = 'default'\nB = {value = 'forced', force = true}")
            .unwrap()
            .resolve(|_| Some(non_unicode.clone()))
            .unwrap();
        assert_eq!(values["A"], non_unicode);
        assert_eq!(values["B"], "forced");
    }
}
