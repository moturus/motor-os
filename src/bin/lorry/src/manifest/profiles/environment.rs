use super::KEYS;
use crate::diagnostic::{Error, Result};
use std::collections::BTreeMap;
use std::ffi::OsString;
use toml_edit::{Table, value};

pub(super) fn overrides(
    environment: &BTreeMap<OsString, OsString>,
    profile: &str,
    building: bool,
) -> Result<Table> {
    let prefix = format!(
        "CARGO_PROFILE_{}_",
        profile.replace('-', "_").to_uppercase()
    );
    let mut table = Table::new();
    for (variable, raw) in environment {
        let variable = variable.to_string_lossy();
        let Some(key) = variable.strip_prefix(&prefix) else {
            continue;
        };
        let key = key.to_lowercase().replace('_', "-");
        if key != "inherits" && !KEYS.contains(&key.as_str()) {
            if !building {
                continue;
            }
            return Err(Error::failure(format!(
                "unsupported selected profile environment variable `{variable}`"
            )));
        }
        let raw = raw.to_str().ok_or_else(|| {
            Error::failure(format!("environment variable `{variable}` must be UTF-8"))
        })?;
        let item = match key.as_str() {
            "debug-assertions" | "overflow-checks" | "incremental" => {
                value(raw.parse::<bool>().map_err(|_| {
                    Error::failure(format!(
                        "environment variable `{variable}` must be true or false"
                    ))
                })?)
            }
            "codegen-units" => value(raw.parse::<i64>().map_err(|_| {
                Error::failure(format!(
                    "environment variable `{variable}` must be an integer"
                ))
            })?),
            "opt-level" | "debug" => match raw.parse::<i64>() {
                Ok(number) => value(number),
                Err(_) => match raw.parse::<bool>() {
                    Ok(boolean) => value(boolean),
                    Err(_) => value(raw),
                },
            },
            "lto" | "strip" => match raw.parse::<bool>() {
                Ok(boolean) => value(boolean),
                Err(_) => value(raw),
            },
            _ => value(raw),
        };
        table.insert(&key, item);
    }
    Ok(table)
}
