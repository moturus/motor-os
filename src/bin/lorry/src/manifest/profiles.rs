use super::{DevProfile, Manifest, ReleaseProfile, parse_release, require_table};
use crate::diagnostic::{Error, Result};
use crate::identity::CargoDebugInfo;
use crate::toml::Document;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::Path;
use toml_edit::Table;
mod environment;

pub(crate) const KEYS: &[&str] = &[
    "panic",
    "debug",
    "opt-level",
    "lto",
    "strip",
    "codegen-units",
    "debug-assertions",
    "overflow-checks",
    "incremental",
];

pub(crate) struct SelectedProfile {
    name: String,
    pub directory: String,
    pub release: bool,
    settings: ReleaseProfile,
    warnings: Vec<String>,
}

impl SelectedProfile {
    pub fn load(root: &Path, name: &str) -> Result<Self> {
        Self::load_checked(root, name, true)
    }

    pub fn directory_for_clean(root: &Path, name: &str) -> Result<String> {
        Ok(Self::load_checked(root, name, false)?.directory)
    }

    fn load_checked(root: &Path, name: &str, building: bool) -> Result<Self> {
        let path = root.join("Cargo.toml");
        let document = Document::load(&path, "workspace profiles")?;
        Self::parse(
            &path,
            &document,
            name,
            building,
            &std::env::vars_os().collect(),
        )
    }

    fn parse(
        path: &Path,
        document: &Document,
        name: &str,
        building: bool,
        environment: &BTreeMap<OsString, OsString>,
    ) -> Result<Self> {
        validate_name(name)?;
        let profiles = document
            .root()
            .get("profile")
            .map(|item| require_table(path, document, item, "profile"))
            .transpose()?;
        let mut chain = Vec::new();
        let mut seen = BTreeSet::new();
        let mut current = name.to_owned();
        let release = loop {
            if !seen.insert(current.clone()) {
                return Err(Error::failure(format!(
                    "profile inheritance cycle involving `{current}`"
                )));
            }
            let declared = profiles
                .and_then(|profiles| profiles.get(&current))
                .map(|item| require_table(path, document, item, &format!("profile.{current}")))
                .transpose()?;
            let overrides = environment::overrides(environment, &current, building)?;
            let defined = declared.is_some() || !overrides.is_empty();
            let mut table = declared.cloned().unwrap_or_default();
            for (key, item) in overrides.iter() {
                table.insert(key, item.clone());
            }
            chain.push((current.clone(), table));
            let parent = chain.last().unwrap().1.get("inherits");
            if matches!(current.as_str(), "dev" | "release") {
                if let Some(parent) = parent {
                    return Err(Error::at(
                        path,
                        document.line_of_item(parent),
                        format!("`inherits` must not be specified in root profile `{current}`"),
                        "only custom profiles may inherit",
                    ));
                }
                break current == "release";
            }
            current = match parent {
                Some(parent) => parent
                    .as_str()
                    .ok_or_else(|| Error::failure("profile.inherits must be a string"))?
                    .to_owned(),
                None => match current.as_str() {
                    "test" | "debug" | "doc" => "dev".to_owned(),
                    "bench" => "release".to_owned(),
                    _ if !defined => {
                        return Err(Error::failure(format!(
                            "profile `{current}` is not defined"
                        )));
                    }
                    _ => {
                        return Err(Error::failure(format!(
                            "profile `{current}` is missing an `inherits` directive"
                        )));
                    }
                },
            };
        };
        let mut merged = Table::new();
        let mut warnings = Vec::new();
        for (profile, table) in chain.into_iter().rev() {
            for (key, item) in table.iter() {
                if key == "inherits" {
                    continue;
                }
                if key == "panic" && matches!(profile.as_str(), "test" | "bench") {
                    super::parse_panic_abort(
                        path,
                        document,
                        &table,
                        &format!("profile.{profile}"),
                    )?;
                    warnings.push(format!(
                        "`panic` setting is ignored for `{profile}` profile"
                    ));
                    continue;
                }
                if !KEYS.contains(&key) {
                    if !building {
                        continue;
                    }
                    return Err(Error::at(
                        path,
                        document.line_of_item(item),
                        format!("unsupported selected profile key `profile.{profile}.{key}`"),
                        format!("supported keys: {}", KEYS.join(", ")),
                    ));
                }
                merged.insert(key, item.clone());
            }
        }
        let mut settings = parse_release(
            path,
            document,
            &merged,
            &format!("profile.{name}"),
            if release { "3" } else { "0" },
        )?;
        // Resolve the inherited root default before applying settings to either
        // compiler profile; an inherited release profile may publish in debug.
        settings.debug.get_or_insert(if release {
            CargoDebugInfo::None
        } else {
            CargoDebugInfo::Full
        });
        Ok(Self {
            name: name.to_owned(),
            directory: match name {
                "dev" | "test" | "debug" => "debug",
                "bench" => "release",
                _ => name,
            }
            .to_owned(),
            release,
            settings,
            warnings,
        })
    }

    pub fn apply(&self, manifest: &mut Manifest) {
        let profile = &self.settings;
        manifest.dev = DevProfile {
            panic_abort: profile.panic_abort,
            opt_level: profile.opt_level,
            debug: profile.debug,
            lto: profile.lto,
            strip: profile.strip,
            codegen_units: profile.codegen_units,
            debug_assertions: profile.debug_assertions,
            overflow_checks: profile.overflow_checks,
            incremental: profile.incremental,
        };
        manifest.release = profile.clone();
        manifest.profile_directory = Some(self.directory.clone());
        manifest.profile_name = Some(self.name.clone());
        manifest.profile_errors.clear();
        manifest.warnings.extend(self.warnings.iter().cloned());
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name
            .chars()
            .any(|ch| !ch.is_alphanumeric() && ch != '_' && ch != '-')
    {
        return Err(Error::failure(format!("invalid profile name `{name}`")));
    }
    let lower = name.to_lowercase();
    if lower.starts_with("cargo")
        || matches!(
            lower.as_str(),
            "build-override"
                | "build"
                | "check"
                | "clean"
                | "config"
                | "fetch"
                | "fix"
                | "install"
                | "metadata"
                | "package"
                | "publish"
                | "report"
                | "root"
                | "run"
                | "rust"
                | "rustc"
                | "rustdoc"
                | "target"
                | "tmp"
                | "uninstall"
                | "doc"
        )
    {
        return Err(Error::failure(format!(
            "profile `{name}` is reserved and not allowed to be explicitly specified"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str, name: &str) -> Result<SelectedProfile> {
        let path = Path::new("Cargo.toml");
        SelectedProfile::parse(
            path,
            &Document::parse(path, "profiles", text.to_owned())?,
            name,
            true,
            &BTreeMap::new(),
        )
    }

    #[test]
    fn inherits_settings_and_built_in_directories() {
        let text = "[profile.release]\nlto = 'thin'\n[profile.opt]\ninherits = 'release'\nopt-level = 2\n[profile.small]\ninherits = 'opt'\nstrip = true\n[profile.test]\ninherits = 'small'\n";
        let selected = parse(text, "test").unwrap();
        assert!(selected.release);
        assert_eq!(selected.directory, "debug");
        assert_eq!(selected.settings.opt_level, "2");
        assert_eq!(selected.settings.lto, super::super::Lto::Thin);
        assert_eq!(selected.settings.strip, super::super::Strip::Symbols);
        assert_eq!(selected.settings.debug, Some(CargoDebugInfo::None));
        assert_eq!(parse(text, "small").unwrap().directory, "small");
        let ignored = parse("[profile.test]\npanic = 'abort'", "test").unwrap();
        assert!(!ignored.settings.panic_abort);
        assert_eq!(
            ignored.warnings,
            ["`panic` setting is ignored for `test` profile"]
        );
    }

    #[test]
    fn environment_overrides_active_inheritance_layers() {
        let path = Path::new("Cargo.toml");
        let document = Document::parse(path, "profiles", "[profile.release]\nopt-level = 3\n[profile.custom]\ninherits = 'release'\nopt-level = 2\n".to_owned()).unwrap();
        let environment = BTreeMap::from([
            ("CARGO_PROFILE_RELEASE_OPT_LEVEL".into(), "1".into()),
            ("CARGO_PROFILE_CUSTOM_OPT_LEVEL".into(), "z".into()),
            ("CARGO_PROFILE_UNUSED_RPATH".into(), "true".into()),
        ]);
        let selected =
            SelectedProfile::parse(path, &document, "custom", true, &environment).unwrap();
        assert!(selected.release);
        assert_eq!(selected.settings.opt_level, "z");
        let environment = BTreeMap::from([
            ("CARGO_PROFILE_ENV_PROFILE_INHERITS".into(), "dev".into()),
            ("CARGO_PROFILE_ENV_PROFILE_OPT_LEVEL".into(), "1".into()),
        ]);
        let selected =
            SelectedProfile::parse(path, &document, "env-profile", true, &environment).unwrap();
        assert!(!selected.release);
        assert_eq!(selected.settings.opt_level, "1");
        let invalid = BTreeMap::from([("CARGO_PROFILE_CUSTOM_RPATH".into(), "true".into())]);
        assert!(
            SelectedProfile::parse(path, &document, "custom", true, &invalid)
                .err()
                .unwrap()
                .to_string()
                .contains("CARGO_PROFILE_CUSTOM_RPATH")
        );
    }

    #[test]
    fn rejects_invalid_active_inheritance_and_settings() {
        for (text, name, expected) in [
            (
                "[profile.one]\ninherits = 'two'\n[profile.two]\ninherits = 'one'",
                "one",
                "cycle",
            ),
            (
                "[profile.one]\nopt-level = 3",
                "one",
                "missing an `inherits`",
            ),
            ("[profile.one]\ninherits = 'absent'", "one", "not defined"),
            ("[profile.dev]\ninherits = 'release'", "dev", "root profile"),
            (
                "[profile.one]\ninherits = 'release'\nrpath = true",
                "one",
                "profile.one.rpath",
            ),
        ] {
            assert!(
                parse(text, name)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains(expected)
            );
        }
        assert!(parse("[profile.unused]\nrpath = true", "dev").is_ok());
        for name in ["test", "bench"] {
            for value in ["'invalid'", "true", "1"] {
                assert!(
                    parse(&format!("[profile.{name}]\npanic = {value}"), name)
                        .err()
                        .unwrap()
                        .to_string()
                        .contains(&format!("profile.{name}.panic"))
                );
            }
        }
        assert!(parse("", "../escape").is_err());
    }
}
