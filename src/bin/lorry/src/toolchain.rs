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
    pub clippy: Option<ClippyDriver>,
    pub verbose_version: String,
    pub release: String,
    pub host: String,
    pub compatibility: CargoCompat,
}

#[derive(Clone, Debug)]
pub struct ClippyDriver {
    pub path: PathBuf,
    pub sha256: [u8; 32],
    pub arguments: String,
}

#[derive(Clone, Debug)]
pub struct TargetInfo {
    pub triple: String,
    pub cfg: CfgSet,
}

impl Toolchain {
    pub fn discover(selector: Option<&str>, config: &Config, clippy: bool) -> Result<Self> {
        let mut rustc = if cfg!(target_os = "motor") {
            if selector.is_some() {
                return Err(Error::failure(
                    "leading `+toolchain` selection requires rustup and is unavailable on Motor",
                ));
            }
            env::var_os("RUSTC")
                .map(PathBuf::from)
                .map(|rustc| program_path(&rustc).unwrap_or(rustc))
                .or_else(|| config.rustc.clone())
                .unwrap_or_else(|| PathBuf::from("/devtools/bin/rustc"))
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
                .map(|rustc| program_path(&rustc).unwrap_or(rustc))
                .or_else(|| config.rustc.clone())
                .or_else(|| find_program("rustc"))
                .ok_or_else(|| {
                    Error::failure("rustc was not found")
                        .with_help("set RUSTC, configure toolchain.rustc, or add rustc to PATH")
                })?
        };
        if !cfg!(target_os = "motor") {
            rustc = resolve_rustup_proxy(rustc)?;
        }

        validate_program(&rustc, "rustc")?;
        let output =
            process::query_rustc(&rustc, &["--version", "--verbose"], "rustc version query")?;
        let verbose_version = String::from_utf8(output.stdout)
            .map_err(|_| Error::failure("rustc version output is not Unicode"))?;
        let fields = parse_verbose_version(&verbose_version)?;
        let release = fields["release"].clone();
        let host = fields["host"].clone();
        let inferred = infer_compatibility(&release);
        let compatibility = config.cargo_compat.or(inferred).ok_or_else(|| {
            Error::failure(format!(
                "rustc release `{release}` does not identify the current Motor Cargo compatibility family"
            ))
            .with_help(
                "use the current Motor Rust toolchain or set `cargo-compat-version = \"1.99\"` for an equivalent custom toolchain",
            )
        })?;
        let clippy = clippy
            .then(|| discover_clippy_driver(&rustc, &verbose_version))
            .transpose()?;

        Ok(Self {
            rustc,
            clippy,
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
        let output = process::query_rustc(&self.rustc, &arguments, "rustc target cfg query")
            .map_err(|error| {
                if error.exit_code() == 130 {
                    return error;
                }
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

fn discover_clippy_driver(rustc: &Path, rustc_version: &str) -> Result<ClippyDriver> {
    let path = rustc.with_file_name(if cfg!(windows) {
        "clippy-driver.exe"
    } else {
        "clippy-driver"
    });
    validate_program(&path, "Clippy driver").map_err(|error| {
        error.with_help("install clippy-driver beside the selected rustc, from the same toolchain")
    })?;
    let output = process::query_rustc(
        &path,
        &["--rustc", "-vV"],
        "Clippy embedded compiler version query",
    )?;
    let version = String::from_utf8(output.stdout)
        .map_err(|_| Error::failure("Clippy embedded compiler version output is not Unicode"))?;
    if version.trim() != rustc_version.trim() {
        return Err(Error::failure(format!(
            "Clippy driver `{}` does not embed the selected rustc `{}`",
            path.display(),
            rustc.display()
        ))
        .with_help("select rustc and clippy-driver from the same toolchain"));
    }
    let mut sha256 = crate::hash::sha256_file(&path)?;
    if cfg!(target_os = "motor") && path == Path::new("/devtools/bin/clippy-driver") {
        // The shipped sibling is a TMPDIR launcher; bind the compiler payload
        // too, so a driver rebuilt from the same rustc cannot reuse old lints.
        let payload = crate::hash::sha256_file(Path::new("/devtools/rust/bin/clippy-driver"))?;
        let mut digest = crate::hash::Sha256::new();
        digest.update(&sha256);
        digest.update(&payload);
        sha256 = digest.finish();
    }
    Ok(ClippyDriver {
        path,
        sha256,
        arguments: String::new(),
    })
}

fn resolve_rustup_proxy(rustc: PathBuf) -> Result<PathBuf> {
    let canonical = fs::canonicalize(&rustc).map_err(|error| {
        Error::failure(format!(
            "failed to resolve rustc path `{}`: {error}",
            rustc.display()
        ))
    })?;
    if canonical.file_stem().and_then(|name| name.to_str()) != Some("rustup") {
        return Ok(rustc);
    }
    let rustup = find_program("rustup").ok_or_else(|| {
        Error::failure(format!(
            "rustc `{}` is a rustup proxy, but rustup was not found",
            rustc.display()
        ))
    })?;
    let output = process::query(&rustup, &["which", "rustc"], "rustup rustc lookup")?;
    let value = String::from_utf8(output.stdout)
        .map_err(|_| Error::failure("rustup returned a non-Unicode rustc path"))?;
    let path = PathBuf::from(value.trim());
    if path.as_os_str().is_empty() {
        return Err(Error::failure("rustup returned no rustc path"));
    }
    Ok(path)
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
    if release == "1.99.0" || release.starts_with("1.99.0-") {
        Some(CargoCompat::V1_99)
    } else {
        None
    }
}

/// Where a program runs from: like `Command`, a bare name is looked up on
/// PATH, and any other path is used as given.
pub(crate) fn program_path(program: &Path) -> Option<PathBuf> {
    match program.to_str() {
        Some(name) if !name.contains('/') => find_program(name),
        _ => Some(program.to_owned()),
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
    pub(crate) fn parse(text: &str) -> Result<Self> {
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

    pub fn matches_selector(&self, selector: &str) -> Result<bool> {
        evaluate_selector(selector, self)
    }

    pub(crate) fn cargo_environment(&self) -> BTreeMap<String, String> {
        let mut environment = self
            .names
            .iter()
            .map(|name| (name.clone(), String::new()))
            .collect::<BTreeMap<_, _>>();
        for (name, values) in &self.values {
            environment.insert(
                name.clone(),
                values.iter().cloned().collect::<Vec<_>>().join(","),
            );
        }
        environment
    }
}

fn evaluate_selector(selector: &str, cfg: &CfgSet) -> Result<bool> {
    Ok(parse_selector(selector, cfg, false)?.0)
}

pub(crate) fn canonical_selector(selector: &str) -> Result<String> {
    if selector.starts_with("cfg(") {
        Ok(format!(
            "cfg({})",
            parse_selector(selector, &CfgSet::default(), true)?.1
        ))
    } else {
        Ok(selector.to_owned())
    }
}

fn parse_selector(selector: &str, cfg: &CfgSet, render: bool) -> Result<(bool, String)> {
    let expression = selector
        .strip_prefix("cfg(")
        .and_then(|value| value.strip_suffix(')'))
        .ok_or_else(|| Error::failure(format!("invalid cfg selector `{selector}`")))?;
    let mut parser = CfgParser {
        source: expression.as_bytes(),
        position: 0,
        cfg,
        render,
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
    render: bool,
}

impl CfgParser<'_> {
    fn expression(&mut self) -> Result<(bool, String)> {
        self.space();
        let name = self.identifier()?;
        self.space();
        if self.take(b'=') {
            self.space();
            let value = self.string()?;
            let enabled = self
                .cfg
                .values
                .get(&name)
                .is_some_and(|values| values.contains(&value));
            return Ok((
                enabled,
                if self.render {
                    format!("{name} = \"{value}\"")
                } else {
                    String::new()
                },
            ));
        }
        if !self.take(b'(') {
            return Ok((self.cfg.names.contains(&name), name));
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
        let enabled = match name.as_str() {
            "all" => values.iter().all(|value| value.0),
            "any" => values.iter().any(|value| value.0),
            "not" if values.len() == 1 => !values[0].0,
            "not" => return Err(self.error("`not` requires exactly one argument")),
            _ => return Err(self.error(format!("unknown cfg predicate `{name}`"))),
        };
        let rendered = if self.render {
            let arguments = values
                .into_iter()
                .map(|value| value.1)
                .collect::<Vec<_>>()
                .join(", ");
            format!("{name}({arguments})")
        } else {
            String::new()
        };
        Ok((enabled, rendered))
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
    fn bare_program_names_run_from_path() {
        let shell = program_path(Path::new("sh")).unwrap();
        assert!(shell.is_absolute() && shell.is_file());
        assert_eq!(
            program_path(Path::new("relative/tool")),
            Some(PathBuf::from("relative/tool"))
        );
        assert_eq!(program_path(Path::new("lorry-no-such-program")), None);
    }

    #[test]
    fn canonical_target_cfgs_preserve_values_and_remove_trailing_commas() {
        assert_eq!(
            canonical_selector("cfg(all( unix,not( target_os=\"motor\"), any(),))").unwrap(),
            "cfg(all(unix, not(target_os = \"motor\"), any()))"
        );
        assert_eq!(
            canonical_selector("cfg(custom=\"two words\")").unwrap(),
            "cfg(custom = \"two words\")"
        );
        assert_eq!(
            canonical_selector("x86_64-unknown-motor").unwrap(),
            "x86_64-unknown-motor"
        );
        assert!(canonical_selector("cfg(not(unix, windows))").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn clippy_discovery_requires_a_matching_executable_sibling() {
        use std::os::unix::fs::PermissionsExt;

        struct Fixture(PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let root = std::env::temp_dir().join(format!(
            "lorry-clippy-driver-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let fixture = Fixture(root);
        let rustc = fixture.0.join("rustc");
        let driver = fixture.0.join("clippy-driver");
        let version = "rustc 1.99.0-dev\ncommit-hash: selected\nhost: host\nrelease: 1.99.0-dev\n";
        // A process that forks while this one holds the driver open for writing
        // makes executing it fail with ETXTBSY, so a child process writes it.
        let install = |contents: &str, mode: u32| {
            let staged = fixture.0.join("staged-driver");
            fs::write(&staged, contents).unwrap();
            let _ = fs::remove_file(&driver);
            let status = std::process::Command::new("cp")
                .arg(&staged)
                .arg(&driver)
                .status()
                .unwrap();
            assert!(status.success());
            fs::set_permissions(&driver, fs::Permissions::from_mode(mode)).unwrap();
        };
        let missing = discover_clippy_driver(&rustc, version).unwrap_err();
        assert!(missing.render().contains("beside the selected rustc"));
        install("#!/bin/sh\nprintf 'different compiler\\n'\n", 0o644);
        assert!(discover_clippy_driver(&rustc, version).is_err());
        fs::set_permissions(&driver, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            discover_clippy_driver(&rustc, version)
                .unwrap_err()
                .render()
                .contains("does not embed the selected rustc")
        );
        let script = format!(
            "#!/bin/sh\n[ \"$*\" = '--rustc -vV' ] || exit 2\ncat <<'VERSION'\n{version}VERSION\n"
        );
        install(&script, 0o755);
        let first = discover_clippy_driver(&rustc, version).unwrap();
        assert_eq!(first.path, driver);
        assert_eq!(first.sha256, crate::hash::sha256_file(&driver).unwrap());
        install(&format!("{script}# changed lint implementation\n"), 0o755);
        assert_ne!(
            first.sha256,
            discover_clippy_driver(&rustc, version).unwrap().sha256
        );
        assert!(discover_clippy_driver(&rustc, &version.replace("selected", "other")).is_err());
    }

    #[cfg(not(target_os = "motor"))]
    #[test]
    fn selected_toolchains_clippy_embeds_its_rustc() {
        let toolchain = Toolchain::discover(None, &Config::default(), true).unwrap();
        let driver = toolchain.clippy.unwrap();
        assert_eq!(driver.path.parent(), toolchain.rustc.parent());
        assert_eq!(
            driver.sha256,
            crate::hash::sha256_file(&driver.path).unwrap()
        );
    }

    #[test]
    fn parses_rustc_verbose_version_and_family() {
        let fields = parse_verbose_version(
            "rustc 1.99.0-dev\nhost: x86_64-unknown-linux-gnu\nrelease: 1.99.0-dev\n",
        )
        .unwrap();
        assert_eq!(fields["host"], "x86_64-unknown-linux-gnu");
        assert_eq!(
            infer_compatibility(&fields["release"]),
            Some(CargoCompat::V1_99)
        );
        assert_eq!(infer_compatibility("1.99.0-dev"), Some(CargoCompat::V1_99));
        assert_eq!(infer_compatibility("1.98.0"), None);
        assert_eq!(infer_compatibility("2.0.0"), None);
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
