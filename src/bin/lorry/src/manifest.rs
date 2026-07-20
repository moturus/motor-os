use crate::diagnostic::{Error, Result};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const MANIFEST_NAME: &str = "Cargo.toml";
const LOCK_NAME: &str = "Cargo.lock";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest {
    pub root: PathBuf,
    pub path: PathBuf,
    pub name: String,
    pub crate_name: String,
    pub version: Version,
    pub edition: Edition,
    pub metadata: PackageMetadata,
    pub release: ReleaseProfile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Edition {
    E2015,
    E2018,
    E2021,
    E2024,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Version {
    pub original: String,
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: String,
    pub build: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PackageMetadata {
    pub authors: Vec<String>,
    pub description: String,
    pub homepage: String,
    pub documentation: String,
    pub repository: String,
    pub license: String,
    pub license_file: String,
    pub readme: String,
    pub rust_version: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lto {
    Default,
    True,
    Fat,
    Thin,
    Off,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Strip {
    None,
    Debuginfo,
    Symbols,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseProfile {
    pub panic_abort: bool,
    pub lto: Lto,
    pub strip: Strip,
    pub codegen_units: Option<u32>,
}

impl Default for ReleaseProfile {
    fn default() -> Self {
        Self {
            panic_abort: false,
            lto: Lto::Default,
            strip: Strip::None,
            codegen_units: None,
        }
    }
}

impl Manifest {
    pub fn load(root: &Path) -> Result<Self> {
        let path = root.join(MANIFEST_NAME);
        let source = fs::read_to_string(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Error::failure(format!(
                    "manifest `{}` does not exist; Lorry does not search parent directories",
                    path.display()
                ))
            } else {
                Error::failure(format!("failed to read `{}`: {error}", path.display()))
            }
        })?;
        let mut manifest = Self::parse(root, &path, &source)?;
        manifest.root = fs::canonicalize(root).map_err(|error| {
            Error::failure(format!(
                "failed to canonicalize package directory `{}`: {error}",
                root.display()
            ))
        })?;
        manifest.path = manifest.root.join(MANIFEST_NAME);

        let main = manifest.root.join("src/main.rs");
        if !main.is_file() {
            return Err(Error::failure(format!(
                "Stage 1 requires the implicit binary target `{}`",
                main.display()
            )));
        }
        validate_lock(&manifest)?;
        Ok(manifest)
    }

    fn parse(root: &Path, path: &Path, source: &str) -> Result<Self> {
        let document = Document::parse(path, source)?;
        let package = document.table("package").ok_or_else(|| {
            Error::failure(format!(
                "manifest `{}` is missing required table `[package]`",
                path.display()
            ))
        })?;

        let name = required_string(path, package, "name")?;
        validate_package_name(path, package.line, &name)?;
        let version_text = required_string(path, package, "version")?;
        let version = parse_version(path, package.line_of("version"), &version_text)?;
        let edition = match optional_string(path, package, "edition")?.as_deref() {
            None | Some("2015") => Edition::E2015,
            Some("2018") => Edition::E2018,
            Some("2021") => Edition::E2021,
            Some("2024") => Edition::E2024,
            Some(value) => {
                return Err(Error::at(
                    path,
                    package.line_of("edition"),
                    format!("unsupported package edition `{value}`"),
                    "choose edition 2015, 2018, 2021, or 2024",
                ));
            }
        };

        let mut metadata = PackageMetadata {
            authors: optional_array(path, package, "authors")?.unwrap_or_default(),
            description: optional_string(path, package, "description")?.unwrap_or_default(),
            homepage: optional_string(path, package, "homepage")?.unwrap_or_default(),
            documentation: optional_string(path, package, "documentation")?.unwrap_or_default(),
            repository: optional_string(path, package, "repository")?.unwrap_or_default(),
            license: optional_string(path, package, "license")?.unwrap_or_default(),
            license_file: optional_string(path, package, "license-file")?.unwrap_or_default(),
            readme: optional_string_or_false(path, package, "readme")?.unwrap_or_default(),
            rust_version: optional_string(path, package, "rust-version")?.unwrap_or_default(),
        };
        if metadata.readme.is_empty() {
            for candidate in ["README.md", "README.txt", "README"] {
                if root.join(candidate).is_file() {
                    metadata.readme = candidate.to_owned();
                    break;
                }
            }
        }

        let allowed_package_keys = [
            "name",
            "version",
            "edition",
            "authors",
            "description",
            "homepage",
            "documentation",
            "repository",
            "license",
            "license-file",
            "readme",
            "rust-version",
            "keywords",
            "categories",
            "publish",
            "include",
            "exclude",
            "default-run",
        ];
        for (key, value) in &package.values {
            if !allowed_package_keys.contains(&key.as_str()) {
                return Err(Error::at(
                    path,
                    value.line,
                    format!("unsupported Stage-1 manifest key `package.{key}`"),
                    "remove the key or use a later Lorry stage that supports its build semantics",
                ));
            }
        }

        let dependencies = document.table("dependencies");
        if let Some(table) = dependencies {
            if let Some((name, value)) = table.values.first_key_value() {
                return Err(Error::at(
                    path,
                    value.line,
                    format!("dependency `dependencies.{name}` is not supported in Stage 1"),
                    "Stage 1 accepts only an empty `[dependencies]` table",
                ));
            }
        }

        if let Some(dev) = document.table("profile.dev") {
            if let Some((key, value)) = dev.values.first_key_value() {
                return Err(Error::at(
                    path,
                    value.line,
                    format!("custom dev profile key `profile.dev.{key}` is not supported"),
                    "remove the key to use Cargo's default dev profile",
                ));
            }
        }

        let release = parse_release(path, document.table("profile.release"))?;
        for table in document.tables.values() {
            let supported = matches!(
                table.name.as_str(),
                "package" | "dependencies" | "profile.dev" | "profile.release"
            ) || table.name == "package.metadata"
                || table.name.starts_with("package.metadata.");
            if !supported {
                return Err(Error::at(
                    path,
                    table.line,
                    format!("unsupported Stage-1 manifest table `[{}]`", table.name),
                    "remove the table or use a later Lorry stage that supports it",
                ));
            }
        }

        Ok(Self {
            root: root.to_path_buf(),
            path: path.to_path_buf(),
            crate_name: name.replace('-', "_"),
            name,
            version,
            edition,
            metadata,
            release,
        })
    }
}

fn parse_release(path: &Path, table: Option<&Table>) -> Result<ReleaseProfile> {
    let Some(table) = table else {
        return Ok(ReleaseProfile::default());
    };
    for (key, value) in &table.values {
        if !matches!(key.as_str(), "panic" | "lto" | "strip" | "codegen-units") {
            return Err(Error::at(
                path,
                value.line,
                format!("unsupported Stage-1 release profile key `profile.release.{key}`"),
                "Stage 1 supports only panic, lto, strip, and codegen-units",
            ));
        }
    }

    let panic_abort = match optional_string(path, table, "panic")?.as_deref() {
        None | Some("unwind") => false,
        Some("abort") => true,
        Some(value) => {
            return Err(Error::at(
                path,
                table.line_of("panic"),
                format!("unsupported panic strategy `{value}`"),
                "choose `unwind` or `abort`",
            ));
        }
    };
    let lto = match table.value("lto") {
        None
        | Some(ValueAt {
            value: Value::Bool(false),
            ..
        }) => Lto::Default,
        Some(ValueAt {
            value: Value::Bool(true),
            ..
        }) => Lto::True,
        Some(ValueAt {
            value: Value::String(value),
            ..
        }) if value == "fat" => Lto::Fat,
        Some(ValueAt {
            value: Value::String(value),
            ..
        }) if value == "thin" => Lto::Thin,
        Some(ValueAt {
            value: Value::String(value),
            ..
        }) if value == "off" => Lto::Off,
        Some(value) => {
            return Err(Error::at(
                path,
                value.line,
                "unsupported value for `profile.release.lto`",
                "choose false, true, `fat`, `thin`, or `off`",
            ));
        }
    };
    let strip = match table.value("strip") {
        None
        | Some(ValueAt {
            value: Value::Bool(false),
            ..
        }) => Strip::None,
        Some(ValueAt {
            value: Value::Bool(true),
            ..
        }) => Strip::Symbols,
        Some(ValueAt {
            value: Value::String(value),
            ..
        }) if value == "none" => Strip::None,
        Some(ValueAt {
            value: Value::String(value),
            ..
        }) if value == "debuginfo" => Strip::Debuginfo,
        Some(ValueAt {
            value: Value::String(value),
            ..
        }) if value == "symbols" => Strip::Symbols,
        Some(value) => {
            return Err(Error::at(
                path,
                value.line,
                "unsupported value for `profile.release.strip`",
                "choose false, true, `none`, `debuginfo`, or `symbols`",
            ));
        }
    };
    let codegen_units = match table.value("codegen-units") {
        None => None,
        Some(ValueAt {
            value: Value::Integer(value),
            line,
        }) if *value > 0 && *value <= u32::MAX as u64 => Some(*value as u32),
        Some(value) => {
            return Err(Error::at(
                path,
                value.line,
                "`profile.release.codegen-units` must be an integer from 1 through 4294967295",
                "use a positive codegen unit count",
            ));
        }
    };

    Ok(ReleaseProfile {
        panic_abort,
        lto,
        strip,
        codegen_units,
    })
}

fn validate_lock(manifest: &Manifest) -> Result<()> {
    let path = manifest.root.join(LOCK_NAME);
    let source = fs::read_to_string(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            Error::failure(format!(
                "required root-only lockfile `{}` is missing",
                path.display()
            ))
            .with_help(
                "create a version-4 Cargo.lock containing exactly the root package; build commands never write it",
            )
        } else {
            Error::failure(format!("failed to read `{}`: {error}", path.display()))
        }
    })?;
    validate_lock_source(manifest, &path, &source)
}

fn validate_lock_source(manifest: &Manifest, path: &Path, source: &str) -> Result<()> {
    let mut version = None;
    let mut packages: Vec<BTreeMap<String, ValueAt>> = Vec::new();
    let mut current_package = None;
    let mut seen = BTreeMap::<String, usize>::new();

    for (index, raw) in source.lines().enumerate() {
        let line = index + 1;
        let text = strip_comment(raw).trim();
        if text.is_empty() {
            continue;
        }
        if text == "[[package]]" {
            packages.push(BTreeMap::new());
            current_package = Some(packages.len() - 1);
            continue;
        }
        if text.starts_with('[') {
            return Err(Error::at(
                path,
                line,
                format!("unsupported Cargo.lock table `{text}`"),
                "Stage 1 requires a version-4 root-only Cargo.lock",
            ));
        }
        let (key, raw_value) = split_assignment(path, line, text)?;
        let value = parse_value(path, line, raw_value)?;
        if let Some(package) = current_package {
            if packages[package]
                .insert(key.clone(), ValueAt { value, line })
                .is_some()
            {
                return Err(Error::at(
                    path,
                    line,
                    format!("duplicate Cargo.lock key `package.{key}`"),
                    "remove the duplicate key",
                ));
            }
        } else {
            if seen.insert(key.clone(), line).is_some() {
                return Err(Error::at(
                    path,
                    line,
                    format!("duplicate Cargo.lock key `{key}`"),
                    "remove the duplicate key",
                ));
            }
            if key != "version" {
                return Err(Error::at(
                    path,
                    line,
                    format!("unsupported root Cargo.lock key `{key}`"),
                    "Stage 1 requires only `version = 4` before the root package",
                ));
            }
            version = Some((value, line));
        }
    }

    match version {
        Some((Value::Integer(4), _)) => {}
        Some((_, line)) => {
            return Err(Error::at(
                path,
                line,
                "unsupported Cargo.lock format; expected `version = 4`",
                "regenerate the lockfile with a current Cargo or `lorry vendor` in Stage 2",
            ));
        }
        None => {
            return Err(Error::failure(format!(
                "lockfile `{}` is missing `version = 4`",
                path.display()
            )));
        }
    }
    if packages.len() != 1 {
        return Err(Error::failure(format!(
            "Stage 1 requires one root package in `{}`, found {}",
            path.display(),
            packages.len()
        )));
    }
    let package = &packages[0];
    for (key, value) in package {
        if !matches!(key.as_str(), "name" | "version") {
            return Err(Error::at(
                path,
                value.line,
                format!("unsupported root-only Cargo.lock key `package.{key}`"),
                "remove dependencies, sources, and checksums for a Stage-1 package",
            ));
        }
    }
    let locked_name = lock_string(path, package, "name")?;
    let locked_version = lock_string(path, package, "version")?;
    if locked_name != manifest.name || locked_version != manifest.version.original {
        return Err(Error::failure(format!(
            "Cargo.lock is stale: expected root package `{} {}`, found `{} {}`",
            manifest.name, manifest.version.original, locked_name, locked_version
        )));
    }
    Ok(())
}

fn lock_string(path: &Path, package: &BTreeMap<String, ValueAt>, key: &str) -> Result<String> {
    let value = package.get(key).ok_or_else(|| {
        Error::failure(format!(
            "root package in `{}` is missing `{key}`",
            path.display()
        ))
    })?;
    match &value.value {
        Value::String(value) => Ok(value.clone()),
        _ => Err(Error::at(
            path,
            value.line,
            format!("Cargo.lock `package.{key}` must be a string"),
            "use Cargo's version-4 lockfile syntax",
        )),
    }
}

fn required_string(path: &Path, table: &Table, key: &str) -> Result<String> {
    optional_string(path, table, key)?.ok_or_else(|| {
        Error::at(
            path,
            table.line,
            format!(
                "table `[{}]` is missing required string `{key}`",
                table.name
            ),
            format!("add `{key} = \"...\"` to `[{}]`", table.name),
        )
    })
}

fn optional_string(path: &Path, table: &Table, key: &str) -> Result<Option<String>> {
    match table.value(key) {
        None => Ok(None),
        Some(ValueAt {
            value: Value::String(value),
            ..
        }) => Ok(Some(value.clone())),
        Some(value) => Err(Error::at(
            path,
            value.line,
            format!("`{}.{key}` must be a string", table.name),
            "use a quoted TOML string",
        )),
    }
}

fn optional_string_or_false(path: &Path, table: &Table, key: &str) -> Result<Option<String>> {
    match table.value(key) {
        None
        | Some(ValueAt {
            value: Value::Bool(false),
            ..
        }) => Ok(None),
        Some(ValueAt {
            value: Value::String(value),
            ..
        }) => Ok(Some(value.clone())),
        Some(value) => Err(Error::at(
            path,
            value.line,
            format!("`{}.{key}` must be a string or false", table.name),
            "use a quoted README path or `false`",
        )),
    }
}

fn optional_array(path: &Path, table: &Table, key: &str) -> Result<Option<Vec<String>>> {
    match table.value(key) {
        None => Ok(None),
        Some(ValueAt {
            value: Value::Strings(value),
            ..
        }) => Ok(Some(value.clone())),
        Some(value) => Err(Error::at(
            path,
            value.line,
            format!("`{}.{key}` must be an array of strings", table.name),
            "use a TOML array such as `[\"Name <email>\"]`",
        )),
    }
}

fn validate_package_name(path: &Path, line: usize, name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && name.bytes().any(|byte| byte.is_ascii_alphabetic());
    if !valid {
        return Err(Error::at(
            path,
            line,
            format!("unsupported Stage-1 package name `{name}`"),
            "use 1–64 ASCII letters, digits, `-`, or `_`, including at least one letter",
        ));
    }
    Ok(())
}

fn parse_version(path: &Path, line: usize, version: &str) -> Result<Version> {
    let (without_build, build) = version
        .split_once('+')
        .map_or((version, ""), |(left, right)| (left, right));
    let (core, pre) = without_build
        .split_once('-')
        .map_or((without_build, ""), |(left, right)| (left, right));
    let mut parts = core.split('.');
    let (Some(major), Some(minor), Some(patch), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid_version(path, line, version));
    };
    if [major, minor, patch].iter().any(|part| {
        part.is_empty()
            || !part.bytes().all(|byte| byte.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
    }) || (!pre.is_empty()
        && !pre
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')))
        || (!build.is_empty()
            && !build
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')))
    {
        return Err(invalid_version(path, line, version));
    }
    let major = major
        .parse()
        .map_err(|_| invalid_version(path, line, version))?;
    let minor = minor
        .parse()
        .map_err(|_| invalid_version(path, line, version))?;
    let patch = patch
        .parse()
        .map_err(|_| invalid_version(path, line, version))?;
    Ok(Version {
        original: version.to_owned(),
        major,
        minor,
        patch,
        pre: pre.to_owned(),
        build: build.to_owned(),
    })
}

fn invalid_version(path: &Path, line: usize, version: &str) -> Error {
    Error::at(
        path,
        line,
        format!("unsupported Stage-1 package version `{version}`"),
        "use a semantic version with major.minor.patch components",
    )
}

#[derive(Clone, Debug)]
struct Document {
    tables: BTreeMap<String, Table>,
}

#[derive(Clone, Debug)]
struct Table {
    name: String,
    line: usize,
    values: BTreeMap<String, ValueAt>,
}

impl Table {
    fn value(&self, key: &str) -> Option<&ValueAt> {
        self.values.get(key)
    }

    fn line_of(&self, key: &str) -> usize {
        self.value(key).map_or(self.line, |value| value.line)
    }
}

#[derive(Clone, Debug)]
struct ValueAt {
    value: Value,
    line: usize,
}

#[derive(Clone, Debug)]
enum Value {
    String(String),
    Strings(Vec<String>),
    Bool(bool),
    Integer(u64),
}

impl Document {
    fn parse(path: &Path, source: &str) -> Result<Self> {
        let mut tables = BTreeMap::<String, Table>::new();
        let mut current = String::new();
        for (index, raw) in source.lines().enumerate() {
            let line = index + 1;
            let text = strip_comment(raw).trim();
            if text.is_empty() {
                continue;
            }
            if text.starts_with("[[") {
                let name = text
                    .strip_prefix("[[")
                    .and_then(|value| value.strip_suffix("]]"))
                    .map(str::trim)
                    .unwrap_or("");
                return Err(Error::at(
                    path,
                    line,
                    format!("array-of-tables `[[{name}]]` is not supported in Stage 1"),
                    "use only the implicit `src/main.rs` binary target",
                ));
            }
            if text.starts_with('[') {
                let name = text
                    .strip_prefix('[')
                    .and_then(|value| value.strip_suffix(']'))
                    .map(str::trim)
                    .unwrap_or("");
                if name.is_empty()
                    || !name.split('.').all(|part| {
                        !part.is_empty()
                            && part.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
                            })
                    })
                {
                    return Err(Error::at(
                        path,
                        line,
                        "malformed or unsupported TOML table header",
                        "use a simple dotted table name such as `[package]`",
                    ));
                }
                if tables.contains_key(name) {
                    return Err(Error::at(
                        path,
                        line,
                        format!("duplicate TOML table `[{name}]`"),
                        "merge the duplicate table declarations",
                    ));
                }
                current = name.to_owned();
                tables.insert(
                    current.clone(),
                    Table {
                        name: current.clone(),
                        line,
                        values: BTreeMap::new(),
                    },
                );
                continue;
            }
            if current.is_empty() {
                return Err(Error::at(
                    path,
                    line,
                    "root manifest keys are not supported in Stage 1",
                    "place package fields under `[package]`",
                ));
            }
            let (key, raw_value) = split_assignment(path, line, text)?;
            if current == "package.metadata" || current.starts_with("package.metadata.") {
                continue;
            }
            let value = parse_value(path, line, raw_value)?;
            let table = tables.get_mut(&current).unwrap();
            if table
                .values
                .insert(key.clone(), ValueAt { value, line })
                .is_some()
            {
                return Err(Error::at(
                    path,
                    line,
                    format!("duplicate manifest key `{}.{key}`", table.name),
                    "remove the duplicate key",
                ));
            }
        }
        Ok(Self { tables })
    }

    fn table(&self, name: &str) -> Option<&Table> {
        self.tables.get(name)
    }
}

fn split_assignment<'a>(path: &Path, line: usize, text: &'a str) -> Result<(String, &'a str)> {
    let Some((raw_key, raw_value)) = text.split_once('=') else {
        return Err(Error::at(
            path,
            line,
            "expected a TOML `key = value` assignment",
            "put each Stage-1 value on one line",
        ));
    };
    let key = raw_key.trim();
    if key.is_empty()
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Error::at(
            path,
            line,
            format!("unsupported TOML key `{key}`"),
            "use a simple bare key in the Stage-1 subset",
        ));
    }
    Ok((key.to_owned(), raw_value.trim()))
}

fn parse_value(path: &Path, line: usize, text: &str) -> Result<Value> {
    if text.starts_with('"') {
        return parse_string(path, line, text).map(Value::String);
    }
    match text {
        "true" => return Ok(Value::Bool(true)),
        "false" => return Ok(Value::Bool(false)),
        _ => {}
    }
    if text.starts_with('[') {
        return parse_string_array(path, line, text).map(Value::Strings);
    }
    if !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'_')
    {
        let digits = text.replace('_', "");
        return digits.parse::<u64>().map(Value::Integer).map_err(|_| {
            Error::at(
                path,
                line,
                "TOML integer is out of range",
                "use an unsigned 64-bit integer",
            )
        });
    }
    Err(Error::at(
        path,
        line,
        format!("unsupported Stage-1 TOML value `{text}`"),
        "use a one-line quoted string, string array, boolean, or unsigned integer",
    ))
}

fn parse_string(path: &Path, line: usize, text: &str) -> Result<String> {
    if text.len() < 2 || !text.ends_with('"') {
        return Err(Error::at(
            path,
            line,
            "unterminated TOML string",
            "close the string on the same line",
        ));
    }
    let mut result = String::new();
    let mut escaped = false;
    let body = &text[1..text.len() - 1];
    for character in body.chars() {
        if escaped {
            match character {
                '"' => result.push('"'),
                '\\' => result.push('\\'),
                'n' => result.push('\n'),
                'r' => result.push('\r'),
                't' => result.push('\t'),
                _ => {
                    return Err(Error::at(
                        path,
                        line,
                        format!("unsupported TOML escape `\\{character}`"),
                        "Stage 1 supports \\\", \\\\, \\n, \\r, and \\t escapes",
                    ));
                }
            }
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' || character.is_control() {
            return Err(Error::at(
                path,
                line,
                "invalid character in TOML string",
                "escape quotes and control characters",
            ));
        } else {
            result.push(character);
        }
    }
    if escaped {
        return Err(Error::at(
            path,
            line,
            "unterminated TOML escape",
            "complete the escape before the closing quote",
        ));
    }
    Ok(result)
}

fn parse_string_array(path: &Path, line: usize, text: &str) -> Result<Vec<String>> {
    let Some(body) = text
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    else {
        return Err(Error::at(
            path,
            line,
            "unterminated TOML array",
            "close the array on the same line",
        ));
    };
    let mut values = Vec::new();
    let mut start = 0;
    let mut in_string = false;
    let mut escaped = false;
    for (index, byte) in body.bytes().enumerate() {
        if escaped {
            escaped = false;
        } else if in_string && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            in_string = !in_string;
        } else if byte == b',' && !in_string {
            let item = body[start..index].trim();
            if !item.is_empty() {
                values.push(parse_string(path, line, item)?);
            }
            start = index + 1;
        }
    }
    if in_string {
        return Err(Error::at(
            path,
            line,
            "unterminated string in TOML array",
            "close every string on the same line",
        ));
    }
    let final_item = body[start..].trim();
    if !final_item.is_empty() {
        values.push(parse_string(path, line, final_item)?);
    }
    Ok(values)
}

fn strip_comment(text: &str) -> &str {
    let mut escaped = false;
    let mut in_string = false;
    for (index, byte) in text.bytes().enumerate() {
        if escaped {
            escaped = false;
        } else if in_string && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            in_string = !in_string;
        } else if byte == b'#' && !in_string {
            return &text[..index];
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    const RED: &str = r#"
[package]
name = "red"
version = "0.1.0"
edition = "2024"
license = "MIT OR Apache-2.0"
authors = ["A", "B"]

[package.metadata.anything]
opaque = { stage = 2 }

[dependencies]

[profile.release]
panic = "abort"
lto = "fat"
strip = true
codegen-units = 1
"#;

    fn parsed(source: &str) -> Result<Manifest> {
        Manifest::parse(
            Path::new("/tmp/pkg"),
            Path::new("/tmp/pkg/Cargo.toml"),
            source,
        )
    }

    #[test]
    fn parses_stage_one_manifest() {
        let manifest = parsed(RED).unwrap();
        assert_eq!(manifest.name, "red");
        assert_eq!(manifest.crate_name, "red");
        assert_eq!(manifest.edition, Edition::E2024);
        assert_eq!(manifest.metadata.authors, ["A", "B"]);
        assert!(manifest.release.panic_abort);
        assert_eq!(manifest.release.lto, Lto::Fat);
        assert_eq!(manifest.release.strip, Strip::Symbols);
        assert_eq!(manifest.release.codegen_units, Some(1));
    }

    #[test]
    fn rejects_unknown_and_build_semantic_keys() {
        for (needle, replacement) in [
            ("license = ", "links = \"native\"\nlicense = "),
            ("[dependencies]", "[dependencies]\nlibc = \"1\""),
            (
                "[profile.release]",
                "[features]\ndefault = []\n\n[profile.release]",
            ),
            ("codegen-units = 1", "opt-level = 2"),
        ] {
            let input = RED.replacen(needle, replacement, 1);
            let error = parsed(&input).unwrap_err();
            assert!(error.to_string().contains("supported"), "{error}");
        }
    }

    #[test]
    fn rejects_malformed_values_and_duplicates() {
        for input in [
            RED.replace("name = \"red\"", "name = \"unterminated"),
            RED.replace("version = \"0.1.0\"", "version = \"1\""),
            RED.replace("edition = \"2024\"", "edition = \"2050\""),
            RED.replace("name = \"red\"", "name = \"red\"\nname = \"again\""),
            RED.replace("codegen-units = 1", "codegen-units = 0"),
        ] {
            assert!(parsed(&input).is_err());
        }
    }

    #[test]
    fn validates_root_only_lock() {
        let manifest = parsed(RED).unwrap();
        let valid = "version = 4\n\n[[package]]\nname = \"red\"\nversion = \"0.1.0\"\n";
        validate_lock_source(&manifest, Path::new("Cargo.lock"), valid).unwrap();

        for invalid in [
            valid.replace("version = 4", "version = 3"),
            valid.replace("name = \"red\"", "name = \"other\""),
            format!("{valid}\n[[package]]\nname = \"dep\"\nversion = \"1.0.0\"\n"),
            valid.replace(
                "version = \"0.1.0\"",
                "version = \"0.1.0\"\nsource = \"registry+x\"",
            ),
        ] {
            assert!(validate_lock_source(&manifest, Path::new("Cargo.lock"), &invalid).is_err());
        }
    }
}
