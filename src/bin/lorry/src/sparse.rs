use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;

use semver::{Version, VersionReq};

use crate::diagnostic::{Error, Result};
use crate::hash::decode_hex;
use crate::json::{DOCUMENT_LIMITS, Value};

pub const MAX_RESPONSE_BYTES: u64 = DOCUMENT_LIMITS.max_bytes as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DependencyKind {
    Normal,
    Build,
    Dev,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dependency {
    pub alias: String,
    pub package: String,
    pub requirement: VersionReq,
    pub features: Vec<String>,
    pub optional: bool,
    pub default_features: bool,
    pub target: Option<String>,
    pub kind: DependencyKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustVersion {
    pub original: String,
    pub version: Version,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub name: String,
    pub version: Version,
    pub dependencies: Vec<Dependency>,
    pub checksum: [u8; 32],
    pub features: BTreeMap<String, Vec<String>>,
    pub features2: BTreeMap<String, Vec<String>>,
    pub yanked: bool,
    pub links: Option<String>,
    pub schema: u64,
    pub rust_version: Option<RustVersion>,
    pub published: Option<String>,
    pub exact_bytes: Vec<u8>,
}

impl Record {
    /// Parses one retained record. An entry that Cargo skips is an error.
    pub fn parse(path: &Path, bytes: &[u8]) -> Result<Self> {
        Self::parse_entry(path, bytes, &mut Vec::new())?.ok_or_else(|| {
            invalid(
                path,
                "sparse index entry has a schema version above 2 or a `pubtime` that Cargo skips",
            )
        })
    }

    /// Parses one index line as Cargo does. Unknown keys are ignored. `None`
    /// is an entry that Cargo skips: a newer schema version or a publish time
    /// it cannot read. `notes` receives the malformed fields Cargo tolerates.
    fn parse_entry(path: &Path, bytes: &[u8], notes: &mut Vec<String>) -> Result<Option<Self>> {
        if !bytes.ends_with(b"\n") || bytes[..bytes.len().saturating_sub(1)].contains(&b'\n') {
            return Err(Error::failure(format!(
                "sparse index record `{}` is not exactly one newline-terminated record",
                path.display()
            )));
        }
        let value = Value::parse(path, "sparse index record", &bytes[..bytes.len() - 1])?;
        let object = require_object(path, &value, "record")?;
        require_exact_keys(
            path,
            object,
            &["name", "vers", "deps", "cksum", "yanked"],
            "record",
        )?;

        let name = require_string(path, object, "name", "record")?.to_owned();
        validate_package_name(path, &name)?;
        let version_text = require_string(path, object, "vers", "record")?;
        let version = Version::parse(version_text).map_err(|error| {
            invalid(
                path,
                format!("invalid sparse index version `{version_text}`: {error}"),
            )
        })?;
        let checksum_text = require_string(path, object, "cksum", "record")?;
        let checksum = decode_hex(checksum_text).map_err(|error| {
            invalid(
                path,
                format!("invalid sparse index checksum `{checksum_text}`: {error}"),
            )
        })?;
        let yanked = require_bool(path, object, "yanked", "record")?;
        let schema = optional_u64(path, object, "v", "record")?.unwrap_or(1);
        if schema == 0 {
            return Err(invalid(path, "sparse index schema version 0 is invalid"));
        }
        let published = optional_nullable_string(path, object, "pubtime", "record")?;
        if schema > 2 || published.is_some_and(|value| !valid_publish_time(value)) {
            return Ok(None);
        }
        let dependencies =
            parse_dependencies(path, require_array(path, object, "deps", "record")?, notes)?;
        let mut features = match object.get("features") {
            Some(value) => parse_feature_map(
                path,
                require_object(path, value, "record.features")?,
                "features",
                notes,
            )?,
            None => BTreeMap::new(),
        };
        let features2 = match object.get("features2") {
            Some(_) if schema != 2 => {
                return Err(invalid(
                    path,
                    "sparse index `features2` requires schema version 2",
                ));
            }
            Some(value) => parse_feature_map(
                path,
                require_object(path, value, "record.features2")?,
                "features2",
                notes,
            )?,
            None => BTreeMap::new(),
        };
        // Cargo appends `features2` to `features`, keeping any repeats.
        for (name, references) in &features2 {
            let merged = features.entry(name.clone()).or_default();
            let original = merged.len();
            for reference in references {
                if merged[..original].contains(reference) {
                    notes.push(format!(
                        "feature `{name}` lists `{reference}` in both `features` and `features2`"
                    ));
                }
                merged.push(reference.clone());
            }
        }
        let links = optional_nullable_string(path, object, "links", "record")?.map(str::to_owned);
        if links
            .as_deref()
            .is_some_and(|value| !valid_identifier(value, 256))
        {
            return Err(invalid(path, "sparse index `links` value is invalid"));
        }
        let rust_version = optional_nullable_string(path, object, "rust_version", "record")?
            .map(|value| parse_rust_version(path, value))
            .transpose()?;

        Ok(Some(Self {
            name,
            version,
            dependencies,
            checksum,
            features,
            features2,
            yanked,
            links,
            schema,
            rust_version,
            published: published.map(str::to_owned),
            exact_bytes: bytes.to_vec(),
        }))
    }
}

/// The records Cargo reads from one index response, with warnings about the
/// entries it skips or reads despite malformed fields.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Response {
    pub records: Vec<Record>,
    pub warnings: Vec<String>,
}

pub fn parse_response(path: &Path, expected_name: &str, bytes: &[u8]) -> Result<Response> {
    validate_package_name(path, expected_name)?;
    if bytes.is_empty() {
        return Err(invalid(path, "sparse index response is empty"));
    }
    if bytes.len() > DOCUMENT_LIMITS.max_bytes {
        return Err(invalid(
            path,
            format!(
                "sparse index response exceeds the {}-byte limit",
                DOCUMENT_LIMITS.max_bytes
            ),
        ));
    }
    if !bytes.ends_with(b"\n") {
        return Err(invalid(
            path,
            "sparse index response is not newline-terminated",
        ));
    }
    let mut response = Response::default();
    let mut noted = BTreeMap::<String, Vec<Version>>::new();
    for (index, line) in bytes.split_inclusive(|byte| *byte == b'\n').enumerate() {
        let mut notes = Vec::new();
        let record = match Record::parse_entry(path, line, &mut notes) {
            Ok(Some(record)) => record,
            Ok(None) => continue,
            // Like Cargo, an unreadable entry costs only its own version.
            Err(error) => {
                let message = error
                    .message()
                    .chars()
                    .map(|character| {
                        if character.is_control() {
                            '?'
                        } else {
                            character
                        }
                    })
                    .collect::<String>();
                response.warnings.push(format!(
                    "crates.io index for `{expected_name}`: skipped {}: {message}",
                    entry_label(path, line, index + 1)
                ));
                continue;
            }
        };
        if record.name != expected_name {
            return Err(invalid(
                path,
                format!(
                    "sparse index response for `{expected_name}` contains package `{}`",
                    record.name
                ),
            ));
        }
        for note in notes {
            noted.entry(note).or_default().push(record.version.clone());
        }
        response.records.push(record);
    }
    // One warning per distinct note keeps a crate's repeated quirk to a line.
    for (note, mut versions) in noted {
        versions.sort();
        versions.dedup();
        let label = match versions.as_slice() {
            [first, .., last] => format!("{} versions from {first} to {last}", versions.len()),
            _ => format!("version {}", versions[0]),
        };
        response.warnings.push(format!(
            "crates.io index for `{expected_name}`: {note} in {label}"
        ));
    }
    Ok(response)
}

/// Names a skipped entry by its version when that is still readable.
fn entry_label(path: &Path, line: &[u8], number: usize) -> String {
    Value::parse(path, "sparse index record", line.trim_ascii_end())
        .ok()
        .and_then(|value| Version::parse(value.as_object()?.get("vers")?.as_str()?).ok())
        .map_or_else(
            || format!("line {number}"),
            |version| format!("version {version}"),
        )
}

pub fn load_response(path: &Path, expected_name: &str) -> Result<Response> {
    let mut file = File::open(path).map_err(|error| {
        Error::failure(format!(
            "failed to open sparse index response `{}`: {error}",
            path.display()
        ))
    })?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            Error::failure(format!(
                "failed to read sparse index response `{}`: {error}",
                path.display()
            ))
        })?;
    parse_response(path, expected_name, &bytes)
}

fn parse_dependencies(
    path: &Path,
    values: &[Value],
    notes: &mut Vec<String>,
) -> Result<Vec<Dependency>> {
    let mut dependencies = Vec::with_capacity(values.len());
    let mut exact = BTreeSet::new();
    for (index, value) in values.iter().enumerate() {
        let context = format!("record.deps[{index}]");
        let object = require_object(path, value, &context)?;
        require_exact_keys(path, object, &["name", "req"], &context)?;
        reject_artifact_dependency(path, object, &context)?;
        if optional_nullable_string(path, object, "registry", &context)?.is_some() {
            return Err(invalid(
                path,
                format!("{context} selects an unsupported alternative registry"),
            ));
        }

        let alias = require_string(path, object, "name", &context)?.to_owned();
        validate_package_name(path, &alias)?;
        let package = optional_nullable_string(path, object, "package", &context)?
            .unwrap_or(&alias)
            .to_owned();
        validate_package_name(path, &package)?;
        let requirement_text = require_string(path, object, "req", &context)?;
        let requirement = VersionReq::parse(requirement_text).map_err(|error| {
            invalid(
                path,
                format!(
                    "invalid sparse dependency requirement `{requirement_text}` in {context}: {error}"
                ),
            )
        })?;
        let mut features = match object.get("features") {
            Some(value) => parse_string_array(
                path,
                value.as_array().ok_or_else(|| {
                    invalid(
                        path,
                        format!("sparse index {context}.features must be an array"),
                    )
                })?,
                &format!("{context}.features"),
                validate_requested_feature,
            )?,
            None => Vec::new(),
        };
        // Older registries published the empty feature, which Cargo drops.
        if features.iter().any(String::is_empty) {
            notes.push(format!("dependency `{alias}` requests the empty feature"));
            features.retain(|feature| !feature.is_empty());
        }
        for feature in repeated(&features) {
            notes.push(format!("dependency `{alias}` repeats feature `{feature}`"));
        }
        let optional = optional_bool(path, object, "optional", &context)?.unwrap_or(false);
        let default_features =
            optional_bool(path, object, "default_features", &context)?.unwrap_or(true);
        let target = optional_nullable_string(path, object, "target", &context)?.map(str::to_owned);
        if target
            .as_deref()
            .is_some_and(|value| !valid_target_selector(value))
        {
            return Err(invalid(
                path,
                format!("{context}.target is not a supported target selector"),
            ));
        }
        // Cargo reads any other kind as a normal dependency.
        let kind = match optional_nullable_string(path, object, "kind", &context)? {
            Some("build") => DependencyKind::Build,
            Some("dev") => DependencyKind::Dev,
            _ => DependencyKind::Normal,
        };

        let identity = format!(
            "{alias}\0{package}\0{requirement_text}\0{features:?}\0{optional}\0\
             {default_features}\0{target:?}\0{kind:?}"
        );
        if !exact.insert(identity) {
            return Err(invalid(
                path,
                format!("{context} duplicates an earlier dependency edge"),
            ));
        }
        dependencies.push(Dependency {
            alias,
            package,
            requirement,
            features,
            optional,
            default_features,
            target,
            kind,
        });
    }
    Ok(dependencies)
}

fn reject_artifact_dependency(
    path: &Path,
    object: &BTreeMap<String, Value>,
    context: &str,
) -> Result<()> {
    let artifact = object
        .get("artifact")
        .is_some_and(|value| !matches!(value, Value::Null));
    let bindep_target = object
        .get("bindep_target")
        .is_some_and(|value| !matches!(value, Value::Null));
    let lib = object
        .get("lib")
        .is_some_and(|value| value.as_bool() != Some(false) && !matches!(value, Value::Null));
    if artifact || bindep_target || lib {
        return Err(invalid(
            path,
            format!("{context} is an unsupported artifact dependency"),
        ));
    }
    Ok(())
}

fn parse_feature_map(
    path: &Path,
    object: &BTreeMap<String, Value>,
    field: &str,
    notes: &mut Vec<String>,
) -> Result<BTreeMap<String, Vec<String>>> {
    let mut features = BTreeMap::new();
    for (name, value) in object {
        validate_feature_name(path, name)?;
        let values = value.as_array().ok_or_else(|| {
            invalid(
                path,
                format!("record.{field}.{name} must be an array of feature references"),
            )
        })?;
        let references = parse_string_array(
            path,
            values,
            &format!("record.{field}.{name}"),
            validate_feature_reference,
        )?;
        for reference in repeated(&references) {
            notes.push(format!("feature `{name}` repeats `{reference}`"));
        }
        features.insert(name.clone(), references);
    }
    Ok(features)
}

fn parse_string_array(
    path: &Path,
    values: &[Value],
    context: &str,
    validate: fn(&Path, &str) -> Result<()>,
) -> Result<Vec<String>> {
    let mut output = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let value = value
            .as_str()
            .ok_or_else(|| invalid(path, format!("{context}[{index}] must be a string")))?;
        validate(path, value)?;
        output.push(value.to_owned());
    }
    Ok(output)
}

/// Values listed more than once. Cargo keeps repeats; they change nothing.
fn repeated(values: &[String]) -> BTreeSet<&str> {
    let mut seen = BTreeSet::new();
    values
        .iter()
        .map(String::as_str)
        .filter(|value| !seen.insert(*value))
        .collect()
}

fn parse_rust_version(path: &Path, value: &str) -> Result<RustVersion> {
    if value.is_empty() || value.starts_with('v') || value.contains(['-', '+']) {
        return Err(invalid(
            path,
            format!("invalid sparse index Rust version `{value}`"),
        ));
    }
    let components = value.split('.').count();
    let normalized = match components {
        1 => format!("{value}.0.0"),
        2 => format!("{value}.0"),
        3 => value.to_owned(),
        _ => {
            return Err(invalid(
                path,
                format!("invalid sparse index Rust version `{value}`"),
            ));
        }
    };
    let version = Version::parse(&normalized).map_err(|error| {
        invalid(
            path,
            format!("invalid sparse index Rust version `{value}`: {error}"),
        )
    })?;
    Ok(RustVersion {
        original: value.to_owned(),
        version,
    })
}

/// Cargo reads only canonical UTC ISO-8601 without fractions.
fn valid_publish_time(value: &str) -> bool {
    let bytes = value.as_bytes();
    let punctuation = [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'Z'),
    ];
    if bytes.len() != 20
        || punctuation
            .iter()
            .any(|(index, expected)| bytes[*index] != *expected)
        || bytes.iter().enumerate().any(|(index, byte)| {
            !punctuation.iter().any(|(position, _)| *position == index) && !byte.is_ascii_digit()
        })
    {
        return false;
    }
    let number = |range: std::ops::Range<usize>| -> u32 {
        std::str::from_utf8(&bytes[range]).unwrap().parse().unwrap()
    };
    (1..=12).contains(&number(5..7))
        && (1..=31).contains(&number(8..10))
        && number(11..13) <= 23
        && number(14..16) <= 59
        && number(17..19) <= 59
}

fn validate_package_name(path: &Path, name: &str) -> Result<()> {
    if crate::manifest::valid_package_name(name) {
        Ok(())
    } else {
        Err(invalid(
            path,
            format!("unsupported sparse index package name `{name}`"),
        ))
    }
}

fn validate_feature_name(path: &Path, value: &str) -> Result<()> {
    if valid_identifier(value, 256) {
        Ok(())
    } else {
        Err(invalid(
            path,
            format!("unsupported sparse index feature name `{value}`"),
        ))
    }
}

/// A dependency may request the empty feature, which Cargo drops.
fn validate_requested_feature(path: &Path, value: &str) -> Result<()> {
    if value.is_empty() {
        Ok(())
    } else {
        validate_feature_name(path, value)
    }
}

fn validate_feature_reference(path: &Path, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 512
        || value.bytes().any(|byte| {
            !byte.is_ascii_graphic() || matches!(byte, b'\\' | b'[' | b']' | b'{' | b'}')
        })
    {
        return Err(invalid(
            path,
            format!("unsupported sparse index feature reference `{value}`"),
        ));
    }
    if let Some(dependency) = value.strip_prefix("dep:") {
        return validate_package_name(path, dependency);
    }
    if let Some((dependency, feature)) = value.split_once('/') {
        let dependency = dependency.strip_suffix('?').unwrap_or(dependency);
        validate_package_name(path, dependency)?;
        return validate_feature_name(path, feature);
    }
    validate_feature_name(path, value)
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'+' | b'.'))
}

fn valid_target_selector(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 4096
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return false;
    }
    (value.starts_with("cfg(") && value.ends_with(')') && value.len() > 5)
        || (!value.ends_with(".json")
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
}

fn require_object<'a>(
    path: &Path,
    value: &'a Value,
    context: &str,
) -> Result<&'a BTreeMap<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid(path, format!("sparse index {context} must be an object")))
}

fn require_array<'a>(
    path: &Path,
    object: &'a BTreeMap<String, Value>,
    key: &str,
    context: &str,
) -> Result<&'a [Value]> {
    object.get(key).and_then(Value::as_array).ok_or_else(|| {
        invalid(
            path,
            format!("sparse index {context}.{key} must be an array"),
        )
    })
}

fn require_string<'a>(
    path: &Path,
    object: &'a BTreeMap<String, Value>,
    key: &str,
    context: &str,
) -> Result<&'a str> {
    object.get(key).and_then(Value::as_str).ok_or_else(|| {
        invalid(
            path,
            format!("sparse index {context}.{key} must be a string"),
        )
    })
}

fn optional_nullable_string<'a>(
    path: &Path,
    object: &'a BTreeMap<String, Value>,
    key: &str,
    context: &str,
) -> Result<Option<&'a str>> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_str().map(Some).ok_or_else(|| {
            invalid(
                path,
                format!("sparse index {context}.{key} must be a string or null"),
            )
        }),
    }
}

fn optional_bool(
    path: &Path,
    object: &BTreeMap<String, Value>,
    key: &str,
    context: &str,
) -> Result<Option<bool>> {
    object
        .get(key)
        .map(|value| {
            value.as_bool().ok_or_else(|| {
                invalid(
                    path,
                    format!("sparse index {context}.{key} must be a boolean"),
                )
            })
        })
        .transpose()
}

fn require_bool(
    path: &Path,
    object: &BTreeMap<String, Value>,
    key: &str,
    context: &str,
) -> Result<bool> {
    object.get(key).and_then(Value::as_bool).ok_or_else(|| {
        invalid(
            path,
            format!("sparse index {context}.{key} must be a boolean"),
        )
    })
}

fn optional_u64(
    path: &Path,
    object: &BTreeMap<String, Value>,
    key: &str,
    context: &str,
) -> Result<Option<u64>> {
    object
        .get(key)
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                invalid(
                    path,
                    format!("sparse index {context}.{key} must be a nonnegative integer"),
                )
            })
        })
        .transpose()
}

fn require_exact_keys(
    path: &Path,
    object: &BTreeMap<String, Value>,
    required: &[&str],
    context: &str,
) -> Result<()> {
    if let Some(key) = required.iter().find(|key| !object.contains_key(**key)) {
        return Err(invalid(
            path,
            format!("sparse index {context} is missing key `{key}`"),
        ));
    }
    Ok(())
}

fn invalid(path: &Path, message: impl Into<String>) -> Error {
    Error::at(
        path,
        1,
        message.into(),
        "use an unmodified supported crates.io sparse-index record",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const CHECKSUM: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn parse(source: &str) -> Result<Record> {
        Record::parse(Path::new("/fixture/index-record.json"), source.as_bytes())
    }

    fn basic(extra: &str) -> String {
        format!(
            "{{\"name\":\"demo\",\"vers\":\"1.2.3\",\"deps\":[],\
             \"cksum\":\"{CHECKSUM}\",\"features\":{{}},\"yanked\":false{extra}}}\n"
        )
    }

    #[test]
    fn parses_a_complete_sparse_response_for_one_package() {
        let first = basic("");
        let second = first.replace("\"1.2.3\"", "\"2.0.0\"");
        let response = parse_response(
            Path::new("/fixture/de/mo/demo"),
            "demo",
            format!("{first}{second}").as_bytes(),
        )
        .unwrap();
        let records = &response.records;
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].version, Version::parse("1.2.3").unwrap());
        assert_eq!(records[1].version, Version::parse("2.0.0").unwrap());
        assert!(response.warnings.is_empty());
        assert_eq!(MAX_RESPONSE_BYTES, 16 * 1024 * 1024);

        let path =
            std::env::temp_dir().join(format!("lorry-sparse-response-{}.json", std::process::id()));
        fs::write(&path, format!("{first}{second}")).unwrap();
        assert_eq!(load_response(&path, "demo").unwrap(), response);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_empty_truncated_mismatched_and_oversized_sparse_responses() {
        let path = Path::new("/fixture/de/mo/demo");
        assert!(parse_response(path, "demo", b"").is_err());
        assert!(parse_response(path, "demo", basic("").trim_end().as_bytes()).is_err());
        assert!(
            parse_response(path, "other", basic("").as_bytes())
                .unwrap_err()
                .to_string()
                .contains("contains package `demo`")
        );
        let oversized = vec![b' '; DOCUMENT_LIMITS.max_bytes + 1];
        assert!(
            parse_response(path, "demo", &oversized)
                .unwrap_err()
                .to_string()
                .contains("byte limit")
        );
    }

    #[test]
    fn parses_schema_two_dependencies_and_merged_features() {
        let source = format!(
            "{{\
             \"name\":\"demo\",\
             \"vers\":\"1.2.3\",\
             \"deps\":[{{\
               \"name\":\"renamed\",\
               \"req\":\"^2\",\
               \"features\":[\"embedded-io-v0.7\"],\
               \"optional\":true,\
               \"default_features\":false,\
               \"target\":\"cfg(target_os = \\\"motor\\\")\",\
               \"kind\":\"build\",\
               \"registry\":null,\
               \"package\":\"actual-name\"\
             }}],\
             \"cksum\":\"{CHECKSUM}\",\
             \"features\":{{\"legacy\":[\"renamed/feature+\"]}},\
             \"features2\":{{\
               \"legacy\":[\"dep:renamed\"],\
               \"default\":[\"legacy\",\"renamed?/feature+\"],\
               \"embedded-io-v0.7\":[]\
             }},\
             \"yanked\":true,\
             \"links\":\"demo-sys\",\
             \"rust_version\":\"1.85\",\
             \"pubtime\":\"2026-07-20T12:34:56Z\",\
             \"v\":2\
             }}\n"
        );
        let record = parse(&source).unwrap();
        assert_eq!(record.name, "demo");
        assert_eq!(record.version, Version::parse("1.2.3").unwrap());
        assert_eq!(record.checksum, decode_hex(CHECKSUM).unwrap());
        assert!(record.yanked);
        assert_eq!(record.schema, 2);
        assert_eq!(record.links.as_deref(), Some("demo-sys"));
        assert_eq!(
            record.rust_version.as_ref().unwrap().version,
            Version::parse("1.85.0").unwrap()
        );
        assert_eq!(
            parse_rust_version(Path::new("/fixture"), "1")
                .unwrap()
                .version,
            Version::parse("1.0.0").unwrap()
        );
        assert_eq!(
            record.features["legacy"],
            ["renamed/feature+", "dep:renamed"]
        );
        assert_eq!(record.features["default"], ["legacy", "renamed?/feature+"]);
        assert!(record.features.contains_key("embedded-io-v0.7"));
        assert_eq!(record.exact_bytes, source.as_bytes());

        let dependency = &record.dependencies[0];
        assert_eq!(dependency.alias, "renamed");
        assert_eq!(dependency.package, "actual-name");
        assert_eq!(dependency.requirement, VersionReq::parse("^2").unwrap());
        assert_eq!(dependency.features, ["embedded-io-v0.7"]);
        assert_eq!(dependency.kind, DependencyKind::Build);
        assert!(dependency.optional);
        assert!(!dependency.default_features);
    }

    #[test]
    fn applies_current_cargo_defaults_to_omitted_fields() {
        let source = format!(
            "{{\"name\":\"demo\",\"vers\":\"1.2.3\",\
             \"deps\":[{{\"name\":\"dependency\",\"req\":\"1\"}}],\
             \"cksum\":\"{CHECKSUM}\",\"yanked\":false}}\n"
        );
        let record = parse(&source).unwrap();
        assert_eq!(record.schema, 1);
        assert!(record.features.is_empty());
        let dependency = &record.dependencies[0];
        assert_eq!(dependency.package, "dependency");
        assert!(dependency.features.is_empty());
        assert!(!dependency.optional);
        assert!(dependency.default_features);
        assert_eq!(dependency.target, None);
        assert_eq!(dependency.kind, DependencyKind::Normal);
    }

    #[test]
    fn follows_cargo_for_unknown_keys_kinds_and_newer_entries() {
        let record = parse(&format!(
            "{{\"name\":\"demo\",\"vers\":\"1.2.3\",\
             \"deps\":[{{\"name\":\"dependency\",\"req\":\"1\",\
             \"kind\":\"future\",\"public\":true,\"mystery\":false}}],\
             \"cksum\":\"{CHECKSUM}\",\"yanked\":false,\"unknown\":true}}\n"
        ))
        .unwrap();
        assert_eq!(record.dependencies[0].kind, DependencyKind::Normal);

        let newer = basic(",\"v\":3,\"deps2\":[]").replace("\"1.2.3\"", "\"2.0.0\"");
        let unreadable_time =
            basic(",\"pubtime\":\"2026-07-20 12:34:56\"").replace("\"1.2.3\"", "\"3.0.0\"");
        let records = parse_response(
            Path::new("/fixture/de/mo/demo"),
            "demo",
            format!("{}{newer}{unreadable_time}", basic("")).as_bytes(),
        )
        .unwrap()
        .records;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].version, Version::parse("1.2.3").unwrap());
        let error = parse(&newer).unwrap_err().to_string();
        assert!(error.contains("schema version above 2"));
    }

    #[test]
    fn rejects_alternative_sources_artifacts_and_schema_mismatches() {
        let cases = [
            (
                basic(",\"features2\":{\"new\":[\"dep:dependency\"]}"),
                "features2",
            ),
            (
                format!(
                    "{{\"name\":\"demo\",\"vers\":\"1.2.3\",\
                     \"deps\":[{{\"name\":\"dependency\",\"req\":\"1\",\
                     \"registry\":\"https://example.invalid/index\"}}],\
                     \"cksum\":\"{CHECKSUM}\",\"yanked\":false}}\n"
                ),
                "alternative registry",
            ),
            (
                format!(
                    "{{\"name\":\"demo\",\"vers\":\"1.2.3\",\
                     \"deps\":[{{\"name\":\"dependency\",\"req\":\"1\",\
                     \"artifact\":\"bin\"}}],\
                     \"cksum\":\"{CHECKSUM}\",\"yanked\":false}}\n"
                ),
                "artifact dependency",
            ),
        ];
        for (source, expected) in cases {
            let error = parse(&source).unwrap_err().to_string();
            assert!(
                error.contains(expected),
                "{error:?} did not contain {expected:?}"
            );
        }
    }

    #[test]
    fn rejects_invalid_integrity_version_feature_and_time_fields() {
        let cases = [
            (
                "{\"name\":\"demo\",\"vers\":\"1.2.3\",\"deps\":[],\
                 \"cksum\":\"abcd\",\"yanked\":false}\n"
                    .to_owned(),
                "checksum",
            ),
            (basic(",\"rust_version\":\"=1.85\""), "Rust version"),
            (basic(",\"pubtime\":\"2026-07-20T12:34:56.1Z\""), "pubtime"),
            (
                format!(
                    "{{\"name\":\"demo\",\"vers\":\"1.2.3\",\"deps\":[],\
                     \"cksum\":\"{CHECKSUM}\",\
                     \"features\":{{\"bad/name\":[]}},\"yanked\":false}}\n"
                ),
                "feature name",
            ),
            (
                format!(
                    "{{\"name\":\"demo\",\"vers\":\"1.2.3\",\"deps\":[],\
                     \"cksum\":\"{CHECKSUM}\",\
                     \"features\":{{\"feature\":[\"dependency//bad\"]}},\
                     \"yanked\":false}}\n"
                ),
                "feature name",
            ),
        ];
        for (source, expected) in cases {
            let error = parse(&source).unwrap_err().to_string();
            assert!(
                error.contains(expected),
                "{error:?} did not contain {expected:?}"
            );
        }
    }

    #[test]
    fn reads_repeated_dependency_features_as_cargo_does() {
        // Cargo's workspace inheritance publishes `wit-component`'s
        // `wasmparser` features with `simd` twice.
        let record = |version: &str| {
            format!(
                "{{\"name\":\"wit-component\",\"vers\":\"{version}\",\"deps\":[\
                 {{\"name\":\"wasmparser\",\"req\":\"^0.244.0\",\
                 \"features\":[\"simd\",\"std\",\"component-model\",\"simd\"],\
                 \"optional\":false,\"default_features\":false,\"target\":null,\
                 \"kind\":\"normal\"}}],\
                 \"cksum\":\"{CHECKSUM}\",\"features\":{{}},\"yanked\":false,\"v\":2}}\n"
            )
        };
        let source = record("0.244.0") + &record("0.221.0");
        let response = parse_response(
            Path::new("/fixture/wi/t-/wit-component"),
            "wit-component",
            source.as_bytes(),
        )
        .unwrap();
        assert_eq!(response.records.len(), 2);
        assert_eq!(
            response.records[0].dependencies[0].features,
            ["simd", "std", "component-model", "simd"]
        );
        assert_eq!(
            response.warnings,
            [
                "crates.io index for `wit-component`: dependency `wasmparser` repeats \
                 feature `simd` in 2 versions from 0.221.0 to 0.244.0"
            ]
        );
        assert!(parse(&record("0.244.0")).is_ok());
    }

    #[test]
    fn reads_empty_and_repeated_feature_entries_as_cargo_does() {
        let source = format!(
            "{{\"name\":\"demo\",\"vers\":\"1.2.3\",\
             \"deps\":[{{\"name\":\"dependency\",\"req\":\"1\",\
             \"features\":[\"\",\"fast\",\"\"],\"optional\":true}}],\
             \"cksum\":\"{CHECKSUM}\",\
             \"features\":{{\"extra\":[\"dependency\",\"dependency\"]}},\
             \"features2\":{{\"extra\":[\"dep:dependency\",\"dependency\"]}},\
             \"yanked\":false,\"v\":2}}\n"
        );
        let response =
            parse_response(Path::new("/fixture/de/mo/demo"), "demo", source.as_bytes()).unwrap();
        let record = &response.records[0];
        assert_eq!(record.dependencies[0].features, ["fast"]);
        assert_eq!(
            record.features["extra"],
            ["dependency", "dependency", "dep:dependency", "dependency"]
        );
        assert_eq!(
            response.warnings,
            [
                "crates.io index for `demo`: dependency `dependency` requests the empty \
                 feature in version 1.2.3",
                "crates.io index for `demo`: feature `extra` lists `dependency` in both \
                 `features` and `features2` in version 1.2.3",
                "crates.io index for `demo`: feature `extra` repeats `dependency` in \
                 version 1.2.3",
            ]
        );
    }

    #[test]
    fn skips_unreadable_entries_as_cargo_does() {
        let bad_requirement = |version: &str, requirement: &str| {
            format!(
                "{{\"name\":\"demo\",\"vers\":\"{version}\",\
                 \"deps\":[{{\"name\":\"dependency\",\"req\":\"{requirement}\"}}],\
                 \"cksum\":\"{CHECKSUM}\",\"yanked\":false}}\n"
            )
        };
        let source = format!(
            "{}{}{}not json\n",
            basic(""),
            bad_requirement("2.0.0", "not a requirement"),
            bad_requirement("3.0.0", "\\u001b[2J"),
        );
        let response =
            parse_response(Path::new("/fixture/de/mo/demo"), "demo", source.as_bytes()).unwrap();
        assert_eq!(response.records.len(), 1);
        assert_eq!(
            response.records[0].version,
            Version::parse("1.2.3").unwrap()
        );
        let expected = [
            "crates.io index for `demo`: skipped version 2.0.0: \
             invalid sparse dependency requirement `not a requirement`",
            "crates.io index for `demo`: skipped version 3.0.0: \
             invalid sparse dependency requirement `?[2J`",
            "crates.io index for `demo`: skipped line 4: ",
        ];
        assert_eq!(response.warnings.len(), expected.len());
        for (warning, expected) in response.warnings.iter().zip(expected) {
            assert!(warning.starts_with(expected), "{warning:?}");
        }
        // A retained record is still parsed strictly.
        assert!(parse(&bad_requirement("2.0.0", "not a requirement")).is_err());
    }

    #[test]
    fn requires_one_complete_newline_terminated_json_record() {
        assert!(parse(basic("").trim_end()).is_err());
        assert!(parse(&(basic("") + "{}\n")).is_err());
        assert!(parse("{\"name\":\"demo\"\n").is_err());
        assert!(
            parse(&format!(
                "{{\"name\":\"demo\",\"name\":\"other\",\"vers\":\"1.2.3\",\
                 \"deps\":[],\"cksum\":\"{CHECKSUM}\",\"yanked\":false}}\n"
            ))
            .unwrap_err()
            .to_string()
            .contains("duplicate JSON")
        );
    }
}
