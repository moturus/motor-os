use crate::config::{CargoCompat, Config};
use crate::diagnostic::{Error, Result};
use crate::process;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Toolchain {
    pub rustc: PathBuf,
    pub verbose_version: String,
    pub release: String,
    pub host: String,
    pub compatibility: CargoCompat,
}

#[derive(Clone, Debug)]
pub struct TargetInfo {
    pub triple: String,
    pub cfg: CfgSet,
}

impl Toolchain {
    pub fn discover(selector: Option<&str>, config: &Config) -> Result<Self> {
        let rustc = if cfg!(target_os = "motor") {
            if selector.is_some() {
                return Err(Error::failure(
                    "leading `+toolchain` selection requires rustup and is unavailable on Motor",
                ));
            }
            env::var_os("RUSTC")
                .map(PathBuf::from)
                .or_else(|| config.rustc.clone())
                .unwrap_or_else(|| PathBuf::from("/sys/tools/rust/bin/rustc"))
        } else if let Some(selector) = selector {
            let rustup = find_program("rustup").ok_or_else(|| {
                Error::failure(format!(
                    "cannot resolve `+{selector}` because `rustup` was not found in PATH"
                ))
                .with_help("install rustup or omit the leading toolchain selector")
            })?;
            let output = process::query(
                &rustup,
                &["which", "rustc", "--toolchain", selector],
                "rustup toolchain lookup",
            )?;
            let value = String::from_utf8(output.stdout)
                .map_err(|_| Error::failure("rustup returned a non-Unicode rustc path"))?;
            let value = value.trim();
            if value.is_empty() {
                return Err(Error::failure(format!(
                    "rustup returned no rustc path for `+{selector}`"
                )));
            }
            PathBuf::from(value)
        } else {
            env::var_os("RUSTC")
                .map(PathBuf::from)
                .or_else(|| config.rustc.clone())
                .or_else(|| find_program("rustc"))
                .ok_or_else(|| {
                    Error::failure("rustc was not found")
                        .with_help("set RUSTC, configure toolchain.rustc, or add rustc to PATH")
                })?
        };

        validate_program(&rustc, "rustc")?;
        let output = process::query(&rustc, &["--version", "--verbose"], "rustc version query")?;
        let verbose_version = String::from_utf8(output.stdout)
            .map_err(|_| Error::failure("rustc version output is not Unicode"))?;
        let fields = parse_verbose_version(&verbose_version)?;
        let release = fields["release"].clone();
        let host = fields["host"].clone();
        let inferred = infer_compatibility(&release);
        let compatibility = config.cargo_compat.or(inferred).ok_or_else(|| {
            Error::failure(format!(
                "rustc release `{release}` does not identify a supported Cargo compatibility family"
            ))
            .with_help("set `cargo-compat-version = \"1.97\"` or `\"1.98\"` in lorry.toml")
        })?;

        Ok(Self {
            rustc,
            verbose_version,
            release,
            host,
            compatibility,
        })
    }

    pub fn target_info(&self, explicit_target: Option<&str>) -> Result<TargetInfo> {
        let mut arguments = vec!["--print", "cfg"];
        if let Some(target) = explicit_target {
            arguments.extend(["--target", target]);
        }
        let output =
            process::query(&self.rustc, &arguments, "rustc target cfg query").map_err(|error| {
                Error::failure(format!(
                    "rustc does not support target `{}`: {error}",
                    explicit_target.unwrap_or(&self.host)
                ))
                .with_help("install the target's standard library or choose another target")
            })?;
        let text = String::from_utf8(output.stdout)
            .map_err(|_| Error::failure("rustc target cfg output is not Unicode"))?;
        Ok(TargetInfo {
            triple: explicit_target.unwrap_or(&self.host).to_owned(),
            cfg: CfgSet::parse(&text)?,
        })
    }
}

fn parse_verbose_version(text: &str) -> Result<BTreeMap<String, String>> {
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':') {
            fields.insert(key.trim().to_owned(), value.trim().to_owned());
        }
    }
    for required in ["release", "host"] {
        if !fields.contains_key(required) {
            return Err(Error::failure(format!(
                "rustc verbose version output is missing `{required}:`"
            )));
        }
    }
    Ok(fields)
}

fn infer_compatibility(release: &str) -> Option<CargoCompat> {
    if release == "1.97.0" || release.starts_with("1.97.0-") {
        Some(CargoCompat::V1_97)
    } else if release == "1.98.0" || release.starts_with("1.98.0-") {
        Some(CargoCompat::V1_98)
    } else {
        None
    }
}

fn find_program(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let path = PathBuf::from(name);
        return path.is_file().then_some(path);
    }
    env::split_paths(&env::var_os("PATH")?)
        .map(|directory| directory.join(name))
        .find(|path| is_executable(path))
}

fn validate_program(path: &Path, description: &str) -> Result<()> {
    if !is_executable(path) {
        return Err(Error::failure(format!(
            "configured {description} `{}` is not a regular executable file",
            path.display()
        )));
    }
    Ok(())
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[derive(Clone, Debug, Default)]
pub struct CfgSet {
    names: BTreeSet<String>,
    values: BTreeMap<String, BTreeSet<String>>,
}

impl CfgSet {
    fn parse(text: &str) -> Result<Self> {
        let mut set = Self::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((key, raw)) = line.split_once('=') {
                let value = raw
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .ok_or_else(|| {
                        Error::failure(format!("malformed rustc cfg output `{line}`"))
                    })?;
                set.values
                    .entry(key.to_owned())
                    .or_default()
                    .insert(value.to_owned());
            } else {
                set.names.insert(line.to_owned());
            }
        }
        Ok(set)
    }

    pub fn matching_selectors<'a>(
        &self,
        selectors: impl IntoIterator<Item = &'a str>,
    ) -> Result<Vec<String>> {
        selectors
            .into_iter()
            .filter_map(|selector| match evaluate_selector(selector, self) {
                Ok(true) => Some(Ok(selector.to_owned())),
                Ok(false) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }
}

fn evaluate_selector(selector: &str, cfg: &CfgSet) -> Result<bool> {
    let expression = selector
        .strip_prefix("cfg(")
        .and_then(|value| value.strip_suffix(')'))
        .ok_or_else(|| Error::failure(format!("invalid cfg selector `{selector}`")))?;
    let mut parser = CfgParser {
        source: expression.as_bytes(),
        position: 0,
        cfg,
    };
    let result = parser.expression()?;
    parser.space();
    if parser.position != parser.source.len() {
        return Err(parser.error("unexpected trailing cfg syntax"));
    }
    Ok(result)
}

struct CfgParser<'a> {
    source: &'a [u8],
    position: usize,
    cfg: &'a CfgSet,
}

impl CfgParser<'_> {
    fn expression(&mut self) -> Result<bool> {
        self.space();
        let name = self.identifier()?;
        self.space();
        if self.take(b'=') {
            self.space();
            let value = self.string()?;
            return Ok(self
                .cfg
                .values
                .get(&name)
                .is_some_and(|values| values.contains(&value)));
        }
        if !self.take(b'(') {
            return Ok(self.cfg.names.contains(&name));
        }
        let mut values = Vec::new();
        loop {
            self.space();
            if self.take(b')') {
                break;
            }
            values.push(self.expression()?);
            self.space();
            if self.take(b')') {
                break;
            }
            if !self.take(b',') {
                return Err(self.error("expected `,` or `)`"));
            }
        }
        match name.as_str() {
            "all" => Ok(values.into_iter().all(|value| value)),
            "any" => Ok(values.into_iter().any(|value| value)),
            "not" if values.len() == 1 => Ok(!values[0]),
            "not" => Err(self.error("`not` requires exactly one argument")),
            _ => Err(self.error(format!("unknown cfg predicate `{name}`"))),
        }
    }

    fn identifier(&mut self) -> Result<String> {
        let start = self.position;
        while self
            .source
            .get(self.position)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            self.position += 1;
        }
        if start == self.position {
            return Err(self.error("expected cfg identifier"));
        }
        Ok(String::from_utf8(self.source[start..self.position].to_vec()).unwrap())
    }

    fn string(&mut self) -> Result<String> {
        if !self.take(b'"') {
            return Err(self.error("expected quoted cfg value"));
        }
        let start = self.position;
        while self
            .source
            .get(self.position)
            .is_some_and(|byte| *byte != b'"')
        {
            if self.source[self.position] == b'\\' {
                return Err(self.error("cfg string escapes are not supported"));
            }
            self.position += 1;
        }
        if !self.take(b'"') {
            return Err(self.error("unterminated cfg value"));
        }
        Ok(String::from_utf8(self.source[start..self.position - 1].to_vec()).unwrap())
    }

    fn space(&mut self) {
        while self
            .source
            .get(self.position)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.position += 1;
        }
    }

    fn take(&mut self, byte: u8) -> bool {
        if self.source.get(self.position) == Some(&byte) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn error(&self, message: impl std::fmt::Display) -> Error {
        Error::failure(format!(
            "invalid Cargo target cfg expression at byte {}: {message}",
            self.position
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rustc_verbose_version_and_family() {
        let fields = parse_verbose_version(
            "rustc 1.98.0-nightly\nhost: x86_64-unknown-linux-gnu\nrelease: 1.98.0-nightly\n",
        )
        .unwrap();
        assert_eq!(fields["host"], "x86_64-unknown-linux-gnu");
        assert_eq!(
            infer_compatibility(&fields["release"]),
            Some(CargoCompat::V1_98)
        );
        assert_eq!(infer_compatibility("1.99.0"), None);
    }

    #[test]
    fn evaluates_nested_cfg_selectors() {
        let cfg = CfgSet::parse(
            "unix\ntarget_arch=\"x86_64\"\ntarget_feature=\"sse2\"\ntarget_feature=\"sse3\"\n",
        )
        .unwrap();
        assert!(evaluate_selector("cfg(unix)", &cfg).unwrap());
        assert!(
            evaluate_selector(
                "cfg(all(unix, target_arch = \"x86_64\", not(windows)))",
                &cfg
            )
            .unwrap()
        );
        assert!(
            evaluate_selector(
                "cfg(any(target_arch=\"aarch64\", target_feature=\"sse3\"))",
                &cfg
            )
            .unwrap()
        );
        assert!(!evaluate_selector("cfg(windows)", &cfg).unwrap());
        assert!(evaluate_selector("cfg(not(unix, windows))", &cfg).is_err());
    }
}
