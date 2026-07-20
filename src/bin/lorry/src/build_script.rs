#![allow(dead_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::diagnostic::{Error, Result};
use crate::source_tree::{Exclusions, Limits as TreeLimits, Tree};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Output {
    pub directives: Vec<Directive>,
    pub diagnostics: Vec<String>,
    pub out_dir: Tree,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Directive {
    RustcCfg(String),
    RustcCheckCfg(String),
    RustcEnv { name: String, value: String },
    RustcLinkLib(String),
    RustcLinkSearch { kind: Option<String>, path: PathBuf },
    RerunIfChanged(PathBuf),
    RerunIfEnvChanged(String),
    Warning(String),
}

pub struct ParseOptions<'a> {
    pub package_root: &'a Path,
    pub out_dir: &'a Path,
    pub approved_environment: &'a BTreeSet<String>,
    pub max_bytes: u64,
    pub out_dir_limits: TreeLimits,
}

pub fn parse(stdout: &[u8], options: &ParseOptions<'_>) -> Result<Output> {
    if stdout.len() as u64 > options.max_bytes {
        return Err(Error::failure(format!(
            "build-script stdout is {} bytes, exceeding the {}-byte limit",
            stdout.len(),
            options.max_bytes
        )));
    }
    let stdout = std::str::from_utf8(stdout)
        .map_err(|_| Error::failure("build-script stdout is not valid UTF-8"))?;
    let package_root = canonical_directory(options.package_root, "package root")?;
    let out_dir = canonical_directory(options.out_dir, "OUT_DIR")?;
    if !out_dir.starts_with(&package_root) && package_root.starts_with(&out_dir) {
        return Err(Error::failure(
            "build-script package root may not be nested inside OUT_DIR",
        ));
    }

    let mut output = Output {
        directives: Vec::new(),
        diagnostics: Vec::new(),
        out_dir: Tree::scan(&out_dir, options.out_dir_limits, Exclusions::None)?,
    };
    for (index, raw_line) in stdout.split('\n').enumerate() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let directive = line
            .strip_prefix("cargo::")
            .or_else(|| line.strip_prefix("cargo:"));
        let Some(directive) = directive else {
            if !line.is_empty() {
                output.diagnostics.push(line.to_owned());
            }
            continue;
        };
        let (name, value) = directive.split_once('=').ok_or_else(|| {
            Error::failure(format!(
                "build-script directive on line {} has no `=` value",
                index + 1
            ))
        })?;
        validate_directive_value(name, value, index + 1)?;
        let parsed = match name {
            "rustc-cfg" => Directive::RustcCfg(value.to_owned()),
            "rustc-check-cfg" => Directive::RustcCheckCfg(value.to_owned()),
            "rustc-env" => {
                let (name, value) = value.split_once('=').ok_or_else(|| {
                    Error::failure(format!(
                        "build-script rustc-env directive on line {} must be NAME=VALUE",
                        index + 1
                    ))
                })?;
                validate_environment_name(name, "rustc-env")?;
                Directive::RustcEnv {
                    name: name.to_owned(),
                    value: value.to_owned(),
                }
            }
            "rustc-link-lib" => Directive::RustcLinkLib(value.to_owned()),
            "rustc-link-search" => {
                let (kind, path) = split_link_search(value)?;
                Directive::RustcLinkSearch {
                    kind: kind.map(str::to_owned),
                    path: resolve_existing(path, &package_root, &[&out_dir], "rustc-link-search")?,
                }
            }
            "rerun-if-changed" => Directive::RerunIfChanged(resolve_existing(
                value,
                &package_root,
                &[&package_root, &out_dir],
                "rerun-if-changed",
            )?),
            "rerun-if-env-changed" => {
                validate_environment_name(value, "rerun-if-env-changed")?;
                if !options.approved_environment.contains(value) {
                    return Err(Error::failure(format!(
                        "build-script rerun-if-env-changed names unapproved environment variable `{value}`"
                    )));
                }
                Directive::RerunIfEnvChanged(value.to_owned())
            }
            "warning" => Directive::Warning(value.to_owned()),
            "error" => {
                return Err(Error::failure(format!(
                    "build script reported an error: {value}"
                )));
            }
            _ => {
                return Err(Error::failure(format!(
                    "unsupported build-script directive `{name}` on line {}",
                    index + 1
                ))
                .with_help("use only the Stage-2 cargo directive subset documented in plan.md"));
            }
        };
        output.directives.push(parsed);
    }
    Ok(output)
}

fn canonical_directory(path: &Path, description: &str) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        Error::failure(format!(
            "failed to canonicalize build-script {description} `{}`: {error}",
            path.display()
        ))
    })?;
    if !canonical.is_dir() {
        return Err(Error::failure(format!(
            "build-script {description} `{}` is not a directory",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn resolve_existing(
    value: &str,
    package_root: &Path,
    allowed_roots: &[&Path],
    directive: &str,
) -> Result<PathBuf> {
    let declared = Path::new(value);
    let path = if declared.is_absolute() {
        declared.to_owned()
    } else {
        package_root.join(declared)
    };
    let canonical = fs::canonicalize(&path).map_err(|error| {
        Error::failure(format!(
            "build-script {directive} path `{}` cannot be resolved: {error}",
            path.display()
        ))
    })?;
    if !allowed_roots.iter().any(|root| canonical.starts_with(root)) {
        return Err(Error::failure(format!(
            "build-script {directive} path `{}` escapes its permitted roots",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn split_link_search(value: &str) -> Result<(Option<&str>, &str)> {
    let Some((kind, path)) = value.split_once('=') else {
        return Ok((None, value));
    };
    if !matches!(
        kind,
        "dependency" | "crate" | "native" | "framework" | "all"
    ) {
        return Err(Error::failure(format!(
            "unsupported rustc-link-search kind `{kind}`"
        )));
    }
    if path.is_empty() {
        return Err(Error::failure(
            "build-script rustc-link-search path is empty",
        ));
    }
    Ok((Some(kind), path))
}

fn validate_directive_value(name: &str, value: &str, line: usize) -> Result<()> {
    if name.is_empty() || value.is_empty() {
        return Err(Error::failure(format!(
            "build-script directive on line {line} has an empty name or value"
        )));
    }
    if name
        .bytes()
        .any(|byte| !(byte.is_ascii_lowercase() || byte == b'-'))
        || value
            .chars()
            .any(|character| character == '\0' || character.is_control())
    {
        return Err(Error::failure(format!(
            "build-script directive on line {line} contains invalid control or name characters"
        )));
    }
    Ok(())
}

fn validate_environment_name(name: &str, directive: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
        && !name.as_bytes()[0].is_ascii_digit();
    if !valid {
        return Err(Error::failure(format!(
            "build-script {directive} has invalid environment name `{name}`"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        out: PathBuf,
        environment: BTreeSet<String>,
    }

    impl Fixture {
        fn new() -> Self {
            let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("lorry-build-output-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            let out = root.join("target/out");
            fs::create_dir_all(&out).unwrap();
            fs::write(root.join("build.rs"), "fn main() {}\n").unwrap();
            fs::write(out.join("libnative.a"), b"archive").unwrap();
            Self {
                root,
                out,
                environment: BTreeSet::from(["TARGET".to_owned(), "RUSTC".to_owned()]),
            }
        }

        fn options(&self) -> ParseOptions<'_> {
            ParseOptions {
                package_root: &self.root,
                out_dir: &self.out,
                approved_environment: &self.environment,
                max_bytes: 1024,
                out_dir_limits: crate::source_tree::DEFAULT_LIMITS,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn parses_the_approved_ordered_protocol() {
        let fixture = Fixture::new();
        let source = format!(
            "diagnostic text\n\
             cargo:rerun-if-changed=build.rs\n\
             cargo::rerun-if-env-changed=TARGET\n\
             cargo:rustc-cfg=portable_atomic_no_atomic_64\n\
             cargo::rustc-check-cfg=cfg(portable_atomic_no_atomic_64)\n\
             cargo:rustc-env=GENERATED=value=with=equals\n\
             cargo:rustc-link-search=native={}\n\
             cargo:rustc-link-lib=static=native\n\
             cargo::warning=reviewed warning\n",
            fixture.out.display()
        );
        let output = parse(source.as_bytes(), &fixture.options()).unwrap();
        assert_eq!(output.diagnostics, ["diagnostic text"]);
        assert_eq!(output.out_dir.file_count, 1);
        assert_eq!(output.out_dir.entries[0].path, "libnative.a");
        assert_eq!(
            output.directives,
            [
                Directive::RerunIfChanged(fixture.root.join("build.rs")),
                Directive::RerunIfEnvChanged("TARGET".to_owned()),
                Directive::RustcCfg("portable_atomic_no_atomic_64".to_owned()),
                Directive::RustcCheckCfg("cfg(portable_atomic_no_atomic_64)".to_owned()),
                Directive::RustcEnv {
                    name: "GENERATED".to_owned(),
                    value: "value=with=equals".to_owned(),
                },
                Directive::RustcLinkSearch {
                    kind: Some("native".to_owned()),
                    path: fixture.out.clone(),
                },
                Directive::RustcLinkLib("static=native".to_owned()),
                Directive::Warning("reviewed warning".to_owned()),
            ]
        );
    }

    #[test]
    fn rejects_unknown_errors_limits_and_unapproved_environment() {
        let fixture = Fixture::new();
        for (source, expected) in [
            ("cargo:metadata=value\n", "unsupported"),
            ("cargo::error=bad input\n", "reported an error"),
            (
                "cargo:rerun-if-env-changed=SECRET\n",
                "unapproved environment",
            ),
            ("cargo:rustc-env=9BAD=value\n", "invalid environment"),
            ("cargo:warning\n", "no `=`"),
        ] {
            assert!(
                parse(source.as_bytes(), &fixture.options())
                    .unwrap_err()
                    .to_string()
                    .contains(expected),
                "{source:?}"
            );
        }
        let mut options = fixture.options();
        options.max_bytes = 3;
        assert!(
            parse(b"four", &options)
                .unwrap_err()
                .to_string()
                .contains("limit")
        );
        assert!(parse(&[0xff], &fixture.options()).is_err());
    }

    #[test]
    fn rejects_paths_outside_the_package_or_out_dir() {
        let fixture = Fixture::new();
        let outside = fixture.root.parent().unwrap().join("outside-build-input");
        fs::write(&outside, b"outside").unwrap();
        for source in [
            format!("cargo:rerun-if-changed={}\n", outside.display()),
            format!(
                "cargo:rustc-link-search=native={}\n",
                fixture.root.display()
            ),
            "cargo:rerun-if-changed=missing\n".to_owned(),
        ] {
            assert!(parse(source.as_bytes(), &fixture.options()).is_err());
        }
        fs::remove_file(outside).unwrap();
    }
}
