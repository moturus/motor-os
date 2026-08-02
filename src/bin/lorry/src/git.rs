use std::fs;
use std::ops::Range;
use std::path::Path;

#[cfg(any(target_os = "linux", test))]
use toml_edit::Item;
use toml_edit::{ImDocument, Value};

#[cfg(target_os = "linux")]
use crate::atomic::AtomicFile;
use crate::config::PolicyLimits;
use crate::diagnostic::{Error, Result};

#[derive(Clone, Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct GitPatch {
    alias: String,
    package: Option<String>,
    url: String,
    selector: Selector,
    locked_commit: Option<String>,
    span: Range<usize>,
}

#[derive(Clone, Debug)]
enum Selector {
    Head,
    Branch(String),
    Tag(String),
    Revision(String),
}

impl Selector {
    fn requested(&self) -> &str {
        match self {
            Self::Head => "HEAD",
            Self::Branch(value) | Self::Tag(value) | Self::Revision(value) => value,
        }
    }

    #[cfg(target_os = "linux")]
    fn fetch_spec(&self) -> String {
        match self {
            Self::Head => "HEAD".to_owned(),
            Self::Branch(value) => format!("refs/heads/{value}"),
            Self::Tag(value) => format!("refs/tags/{value}"),
            Self::Revision(value) => value.clone(),
        }
    }
}

#[cfg(any(target_os = "linux", test))]
struct Materialized {
    path: String,
}

pub fn materialize_manifest_patches(
    root: &Path,
    limits: &PolicyLimits,
    accept_all: bool,
    verbose: bool,
) -> Result<bool> {
    let manifest_path = root.join("Cargo.toml");
    let source = fs::read_to_string(&manifest_path).map_err(|error| {
        Error::failure(format!(
            "failed to read manifest `{}` before Git vendoring: {error}",
            manifest_path.display()
        ))
    })?;
    let document = ImDocument::parse(source.clone()).map_err(|error| {
        Error::failure(format!(
            "invalid Cargo manifest `{}` before Git vendoring: {error}",
            manifest_path.display()
        ))
    })?;
    let patches = parse_git_patches(root, &document)?;
    if patches.is_empty() {
        return Ok(false);
    }

    #[cfg(target_os = "motor")]
    {
        let _ = (limits, accept_all, verbose);
        return Err(Error::failure(
            "Git patch materialization is not supported by `lorry vendor` on Motor OS",
        )
        .with_help(
            "run `lorry vendor` on Linux, then copy the vendored project and repository to Motor OS",
        ));
    }

    #[cfg(not(any(target_os = "linux", target_os = "motor")))]
    return Err(Error::failure(
        "Git patch materialization is supported by `lorry vendor` only on Linux",
    ));

    #[cfg(target_os = "linux")]
    {
        let mut patches = patches;
        let git = linux::find_git()?;
        attach_locked_commits(root, &mut patches)?;
        let tree_limits = linux::tree_limits(limits)?;
        let mut replacements = Vec::new();
        for patch in &patches {
            let materialized =
                linux::materialize_one(root, patch, &git, tree_limits, accept_all, verbose)?;
            replacements.push((patch.alias.clone(), patch.package.clone(), materialized));
        }
        let rewritten = rewrite_manifest(&source, &patches, &replacements)?;
        let mut staged = AtomicFile::new(&manifest_path)?;
        staged.write_all(rewritten.as_bytes())?;
        staged.persist()?;
        staged.commit()?;
        Ok(true)
    }
}

fn parse_git_patches(root: &Path, document: &ImDocument<String>) -> Result<Vec<GitPatch>> {
    let Some(patch) = document.get("patch") else {
        return Ok(Vec::new());
    };
    let patch = patch.as_table().ok_or_else(|| {
        Error::failure("Cargo manifest `[patch]` must be a table before Git vendoring")
    })?;
    let Some(crates_io) = patch.get("crates-io") else {
        return Ok(Vec::new());
    };
    let crates_io = crates_io
        .as_table()
        .ok_or_else(|| Error::failure("Cargo manifest `[patch.crates-io]` must be a table"))?;
    let mut result = Vec::new();
    for (alias, item) in crates_io.iter() {
        let Some(table) = item.as_inline_table() else {
            continue;
        };
        let Some(url) = table.get("git").and_then(Value::as_str) else {
            continue;
        };
        validate_alias(alias)?;
        validate_git_url(url)?;
        for (key, _) in table.iter() {
            if !matches!(key, "git" | "branch" | "tag" | "rev" | "package") {
                return Err(Error::failure(format!(
                    "Git patch `{alias}` contains unsupported key `{key}`"
                ))
                .with_help("use only git, one optional branch/tag/rev, and optional package"));
            }
        }
        let selectors = ["branch", "tag", "rev"]
            .into_iter()
            .filter_map(|key| {
                table
                    .get(key)
                    .and_then(Value::as_str)
                    .map(|value| (key, value))
            })
            .collect::<Vec<_>>();
        if selectors.len() > 1 {
            return Err(Error::failure(format!(
                "Git patch `{alias}` selects more than one of branch, tag, and rev"
            )));
        }
        let selector = match selectors.as_slice() {
            [] => Selector::Head,
            [("branch", value)] => Selector::Branch((*value).to_owned()),
            [("tag", value)] => Selector::Tag((*value).to_owned()),
            [("rev", value)] => Selector::Revision((*value).to_owned()),
            _ => unreachable!(),
        };
        validate_revision(selector.requested())?;
        let package = table
            .get("package")
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or_else(|| {
                    Error::failure(format!("Git patch `{alias}` package must be a string"))
                })
            })
            .transpose()?;
        result.push(GitPatch {
            alias: alias.to_owned(),
            package,
            url: url.to_owned(),
            selector,
            locked_commit: None,
            span: item
                .span()
                .ok_or_else(|| Error::failure(format!("Git patch `{alias}` has no source span")))?,
        });
    }
    if !result.is_empty() && !root.is_absolute() {
        return Err(Error::failure(
            "Git vendoring requires an absolute package root",
        ));
    }
    Ok(result)
}

#[cfg(any(target_os = "linux", test))]
fn attach_locked_commits(root: &Path, patches: &mut [GitPatch]) -> Result<()> {
    let lock_path = root.join("Cargo.lock");
    let Ok(source) = fs::read_to_string(&lock_path) else {
        return Ok(());
    };
    let document = ImDocument::parse(source).map_err(|error| {
        Error::failure(format!(
            "invalid Cargo lockfile `{}` before Git vendoring: {error}",
            lock_path.display()
        ))
    })?;
    let Some(packages) = document.get("package").and_then(Item::as_array_of_tables) else {
        return Ok(());
    };
    for package in packages.iter() {
        let Some(source) = package.get("source").and_then(Item::as_str) else {
            continue;
        };
        let Some((without_fragment, commit)) = source.rsplit_once('#') else {
            continue;
        };
        if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        for patch in patches.iter_mut() {
            let matches = without_fragment.strip_prefix("git+").is_some_and(|value| {
                value == patch.url
                    || value
                        .strip_prefix(&patch.url)
                        .is_some_and(|suffix| suffix.starts_with('?'))
            });
            if !matches {
                continue;
            }
            match &patch.locked_commit {
                Some(existing) if existing != commit => {
                    return Err(Error::failure(format!(
                        "Cargo.lock contains multiple commits for Git patch `{}`",
                        patch.alias
                    )));
                }
                _ => patch.locked_commit = Some(commit.to_ascii_lowercase()),
            }
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn rewrite_manifest(
    source: &str,
    patches: &[GitPatch],
    replacements: &[(String, Option<String>, Materialized)],
) -> Result<String> {
    let mut edits = replacements
        .iter()
        .map(|(alias, package, materialized)| {
            let patch = patches
                .iter()
                .find(|patch| patch.alias == *alias)
                .ok_or_else(|| Error::failure("Git patch disappeared while rewriting manifest"))?;
            let replacement = match package {
                Some(package) => format!(
                    "{{ path = {}, package = {} }}",
                    toml_string(&materialized.path),
                    toml_string(package)
                ),
                None => format!("{{ path = {} }}", toml_string(&materialized.path)),
            };
            Ok((patch.span.clone(), replacement))
        })
        .collect::<Result<Vec<_>>>()?;
    edits.sort_unstable_by(|left, right| right.0.start.cmp(&left.0.start));
    let mut rewritten = source.to_owned();
    for (span, replacement) in edits {
        if span.end > rewritten.len() || !rewritten.is_char_boundary(span.start) {
            return Err(Error::failure("Git patch source span is invalid"));
        }
        rewritten.replace_range(span, &replacement);
    }
    Ok(rewritten)
}

#[cfg(any(target_os = "linux", test))]
fn toml_string(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        match character {
            '\x08' => quoted.push_str("\\b"),
            '\t' => quoted.push_str("\\t"),
            '\n' => quoted.push_str("\\n"),
            '\x0c' => quoted.push_str("\\f"),
            '\r' => quoted.push_str("\\r"),
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\0'..='\x1f' | '\x7f' => {
                use std::fmt::Write as _;
                write!(quoted, "\\u{:04X}", character as u32).unwrap();
            }
            _ => quoted.push(character),
        }
    }
    quoted.push('"');
    quoted
}

fn validate_alias(alias: &str) -> Result<()> {
    if alias.is_empty()
        || alias.len() > 64
        || !alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || !alias.bytes().any(|byte| byte.is_ascii_alphabetic())
    {
        return Err(Error::failure(format!(
            "Git patch alias `{alias}` is not safe for a vendored path"
        )));
    }
    Ok(())
}

fn validate_git_url(url: &str) -> Result<()> {
    if !url.starts_with("https://")
        || !url.is_ascii()
        || url
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
        || url.contains(['#', '?'])
        || url[8..].contains('@')
    {
        return Err(Error::failure(format!(
            "Git patch URL `{url}` is not a canonical anonymous HTTPS URL"
        )));
    }
    Ok(())
}

fn validate_revision(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 1024
        || value.starts_with('-')
        || value.bytes().any(|byte| byte.is_ascii_control())
        || value.contains("..")
        || value.contains(['~', '^', ':', '?', '*', '[', '\\', ' '])
        || value.ends_with(['.', '/'])
        || value.contains("@{")
    {
        return Err(Error::failure(format!(
            "Git patch revision `{value}` is not a safe branch, tag, or revision"
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn document(source: &str) -> ImDocument<String> {
        ImDocument::parse(source.to_owned()).unwrap()
    }

    #[test]
    fn parses_and_rewrites_supported_git_patches() {
        let source = "[package]\nname = \"root\"\nversion = \"0.1.0\"\n\
                      [patch.crates-io]\n\
                      crossterm = { git = \"https://example.com/crossterm.git\", branch = \"motor\" }\n\
                      renamed = { git = \"https://example.com/actual.git\", rev = \"abc123\", package = \"actual\" }\n";
        let patches = parse_git_patches(Path::new("/fixture"), &document(source)).unwrap();
        assert_eq!(patches.len(), 2);
        assert!(matches!(patches[0].selector, Selector::Branch(ref value) if value == "motor"));
        assert!(matches!(patches[1].selector, Selector::Revision(ref value) if value == "abc123"));
        let rewritten = rewrite_manifest(
            source,
            &patches,
            &[
                (
                    "crossterm".to_owned(),
                    None,
                    Materialized {
                        path: ".lorry/vendor/crossterm/source".to_owned(),
                    },
                ),
                (
                    "renamed".to_owned(),
                    Some("actual".to_owned()),
                    Materialized {
                        path: ".lorry/vendor/renamed/source".to_owned(),
                    },
                ),
            ],
        )
        .unwrap();
        assert!(rewritten.contains("crossterm = { path = \".lorry/vendor/crossterm/source\" }"));
        assert!(rewritten.contains(
            "renamed = { path = \".lorry/vendor/renamed/source\", package = \"actual\" }"
        ));
        assert!(!rewritten.contains(" git = "));
        ImDocument::parse(rewritten).unwrap();
    }

    #[test]
    fn preserves_the_matching_locked_commit() {
        let root = std::env::temp_dir().join(format!(
            "lorry-git-lock-{}-{}",
            std::process::id(),
            crate::hash::hex(&[7_u8; 4])
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"patched\"\nversion = \"1.0.0\"\n\
             source = \"git+https://example.com/patched.git?branch=main#0123456789abcdef0123456789abcdef01234567\"\n",
        )
        .unwrap();
        let mut patches = vec![GitPatch {
            alias: "patched".to_owned(),
            package: None,
            url: "https://example.com/patched.git".to_owned(),
            selector: Selector::Branch("main".to_owned()),
            locked_commit: None,
            span: 0..0,
        }];
        attach_locked_commits(&root, &mut patches).unwrap();
        assert_eq!(
            patches[0].locked_commit.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_credentialed_urls_and_ambiguous_selectors() {
        for source in [
            "[patch.crates-io]\nx = { git = \"https://user@example.com/x\" }\n",
            "[patch.crates-io]\nx = { git = \"https://example.com/x\", branch = \"main\", tag = \"v1\" }\n",
        ] {
            assert!(parse_git_patches(&PathBuf::from("/fixture"), &document(source)).is_err());
        }
    }
}
