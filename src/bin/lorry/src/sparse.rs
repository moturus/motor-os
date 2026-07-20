#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use semver::{Version, VersionReq};

use crate::diagnostic::{Error, Result};
use crate::hash::decode_hex;
use crate::json::Value;

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
    pub fn parse(path: &Path, bytes: &[u8]) -> Result<Self> {
        if !bytes.ends_with(b"\n") || bytes[..bytes.len().saturating_sub(1)].contains(&b'\n') {
            return Err(Error::failure(format!(
                "sparse index record `{}` is not exactly one newline-terminated record",
                path.display()
            )));
        }
        let value = Value::parse(path, "sparse index record", &bytes[..bytes.len() - 1])?;
        let object = require_object(path, &value, "record")?;
        reject_unknown_keys(
            path,
            object,
            &[
                "name",
                "vers",
                "deps",
                "cksum",
                "features",
                "yanked",
                "links",
                "v",
                "features2",
                "rust_version",
                "pubtime",
            ],
            "record",
        )?;
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
        if schema > u32::MAX as u64 || !matches!(schema, 1 | 2) {
            return Err(invalid(
                path,
                format!("unsupported sparse index schema version {schema}"),
            ));
        }
        let dependencies =
            parse_dependencies(path, require_array(path, object, "deps", "record")?)?;
        let mut features = match object.get("features") {
            Some(value) => parse_feature_map(
                path,
                require_object(path, value, "record.features")?,
                "features",
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
            )?,
            None => BTreeMap::new(),
        };
        for (name, references) in &features2 {
            let merged = features.entry(name.clone()).or_default();
            for reference in references {
                if merged.contains(reference) {
                    return Err(invalid(
                        path,
                        format!(
                            "sparse index feature `{name}` repeats `{reference}` across `features` and `features2`"
                        ),
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
        let published = optional_nullable_string(path, object, "pubtime", "record")?
            .map(|value| validate_publish_time(path, value).map(|()| value.to_owned()))
            .transpose()?;

        Ok(Self {
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
            published,
            exact_bytes: bytes.to_vec(),
        })
    }
}

fn parse_dependencies(path: &Path, values: &[Value]) -> Result<Vec<Dependency>> {
    let mut dependencies = Vec::with_capacity(values.len());
    let mut exact = BTreeSet::new();
    for (index, value) in values.iter().enumerate() {
        let context = format!("record.deps[{index}]");
        let object = require_object(path, value, &context)?;
        reject_unknown_keys(
            path,
            object,
            &[
                "name",
                "req",
                "features",
                "optional",
                "default_features",
                "target",
                "kind",
                "registry",
                "package",
                "artifact",
                "bindep_target",
                "lib",
            ],
            &context,
        )?;
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
        let features = match object.get("features") {
            Some(value) => parse_string_array(
                path,
                value.as_array().ok_or_else(|| {
                    invalid(
                        path,
                        format!("sparse index {context}.features must be an array"),
                    )
                })?,
                &format!("{context}.features"),
                validate_feature_name,
            )?,
            None => Vec::new(),
        };
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
        let kind = match optional_nullable_string(path, object, "kind", &context)? {
            None | Some("normal") => DependencyKind::Normal,
            Some("build") => DependencyKind::Build,
            Some("dev") => DependencyKind::Dev,
            Some(kind) => {
                return Err(invalid(
                    path,
                    format!("{context}.kind `{kind}` is unsupported"),
                ));
            }
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
    let mut seen = BTreeSet::new();
    for (index, value) in values.iter().enumerate() {
        let value = value
            .as_str()
            .ok_or_else(|| invalid(path, format!("{context}[{index}] must be a string")))?;
        validate(path, value)?;
        if !seen.insert(value) {
            return Err(invalid(
                path,
                format!("{context} contains duplicate value `{value}`"),
            ));
        }
        output.push(value.to_owned());
    }
    Ok(output)
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

fn validate_publish_time(path: &Path, value: &str) -> Result<()> {
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
        return Err(invalid(
            path,
            "sparse index `pubtime` is not canonical UTC ISO-8601",
        ));
    }
    let number = |range: std::ops::Range<usize>| -> u32 {
        std::str::from_utf8(&bytes[range]).unwrap().parse().unwrap()
    };
    if !(1..=12).contains(&number(5..7))
        || !(1..=31).contains(&number(8..10))
        || number(11..13) > 23
        || number(14..16) > 59
        || number(17..19) > 59
    {
        return Err(invalid(
            path,
            "sparse index `pubtime` has an out-of-range field",
        ));
    }
    Ok(())
}

fn validate_package_name(path: &Path, name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && name.bytes().any(|byte| byte.is_ascii_alphabetic());
    if valid {
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
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'+'))
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

fn reject_unknown_keys(
    path: &Path,
    object: &BTreeMap<String, Value>,
    allowed: &[&str],
    context: &str,
) -> Result<()> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid(
            path,
            format!("unknown sparse index {context} key `{key}`"),
        ));
    }
    Ok(())
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
    use std::path::PathBuf;

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
    fn parses_schema_two_dependencies_and_merged_features() {
        let source = format!(
            "{{\
             \"name\":\"demo\",\
             \"vers\":\"1.2.3\",\
             \"deps\":[{{\
               \"name\":\"renamed\",\
               \"req\":\"^2\",\
               \"features\":[\"fast+mode\"],\
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
               \"default\":[\"legacy\",\"renamed?/feature+\"]\
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
            record.features["legacy"],
            ["renamed/feature+", "dep:renamed"]
        );
        assert_eq!(record.features["default"], ["legacy", "renamed?/feature+"]);
        assert_eq!(record.exact_bytes, source.as_bytes());

        let dependency = &record.dependencies[0];
        assert_eq!(dependency.alias, "renamed");
        assert_eq!(dependency.package, "actual-name");
        assert_eq!(dependency.requirement, VersionReq::parse("^2").unwrap());
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
    fn rejects_unknown_fields_sources_artifacts_and_schema_mismatches() {
        let cases = [
            (
                basic(",\"unknown\":true"),
                "unknown sparse index record key",
            ),
            (basic(",\"v\":3"), "unsupported sparse index schema"),
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
            (
                format!(
                    "{{\"name\":\"demo\",\"vers\":\"1.2.3\",\
                     \"deps\":[{{\"name\":\"dependency\",\"req\":\"1\",\
                     \"mystery\":false}}],\
                     \"cksum\":\"{CHECKSUM}\",\"yanked\":false}}\n"
                ),
                "unknown sparse index record.deps",
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
                     \"features\":{{\"bad.name\":[]}},\"yanked\":false}}\n"
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
            (
                format!(
                    "{{\"name\":\"demo\",\"vers\":\"1.2.3\",\"deps\":[],\
                     \"cksum\":\"{CHECKSUM}\",\
                     \"features\":{{\"feature\":[\"same\",\"same\"]}},\
                     \"yanked\":false}}\n"
                ),
                "duplicate value",
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

    #[test]
    fn parses_every_stage_two_seed_record_when_requested() {
        let Some(repository) = std::env::var_os("LORRY_TEST_SEEDED_REPOSITORY") else {
            return;
        };
        let objects = PathBuf::from(repository).join("objects/crates-io/sha256");
        let mut checked = 0;
        for prefix in fs::read_dir(objects).unwrap() {
            for object in fs::read_dir(prefix.unwrap().path()).unwrap() {
                let path = object.unwrap().path().join("index-record.json");
                let bytes = fs::read(&path).unwrap();
                Record::parse(&path, &bytes)
                    .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
                checked += 1;
            }
        }
        assert_eq!(checked, 45);
    }
}
