use super::KEYS;
use crate::diagnostic::{Error, Result};
use std::collections::BTreeMap;
use std::ffi::OsString;
use toml_edit::{Table, value};

/// Cargo profile keys that Lorry does not implement, as environment names
/// spell them. `build-override` and `package` take a nested key.
fn unsupported_cargo_key(key: &str) -> bool {
    const KEYS: [&str; 7] = [
        "split-debuginfo",
        "rpath",
        "trim-paths",
        "codegen-backend",
        "dir-name",
        "rustflags",
        "frame-pointers",
    ];
    KEYS.contains(&key)
        || ["build-override-", "package-"]
            .iter()
            .any(|prefix| key.starts_with(prefix))
}

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
            // Like Cargo, ignore what is not a profile key: it may be another
            // profile's, such as `CARGO_PROFILE_RELEASE_LTO_LTO` for a
            // `release-lto` profile. Fail on a Cargo key Lorry lacks.
            if !building || !unsupported_cargo_key(&key) {
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
