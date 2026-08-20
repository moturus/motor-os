use std::collections::BTreeSet;
use std::fs;
use std::ops::Range;
use std::path::Path;

use toml_edit::Item;
use toml_edit::{ImDocument, Value};

use crate::atomic::AtomicFile;
use crate::config::{NetworkConfig, PolicyLimits};
use crate::diagnostic::{Error, Result};
use crate::manifest::{GitDependency, GitSelector};
use crate::progress::Progress;

mod direct;
mod http;
mod materialize;

pub(crate) use direct::{
    DirectCatalog, configure_direct, load_locked_dependencies, materialize_locked_dependencies,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LockedSource {
    pub cargo_source: String,
    pub url: String,
    pub selector: GitSelector,
    pub commit: String,
}

impl LockedSource {
    pub(crate) fn matches(&self, dependency: &GitDependency) -> bool {
        self.url == dependency.url && self.selector == dependency.selector
    }
}

pub(crate) fn parse_locked_source(source: &str) -> Result<LockedSource> {
    let value = source
        .strip_prefix("git+")
        .ok_or_else(|| Error::failure("Git lock source is missing its `git+` prefix"))?;
    let (remote, commit) = value
        .rsplit_once('#')
        .ok_or_else(|| Error::failure("Git lock source is missing its commit fragment"))?;
    if commit.len() != 40
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::failure(
            "Git lock source commit is not 40 lowercase hexadecimal digits",
        ));
    }
    let (url, query) = remote
        .split_once('?')
        .map_or((remote, None), |(url, query)| (url, Some(query)));
    validate_git_url(url)?;
    let selector = match query {
        None => GitSelector::Head,
        Some(query) => {
            let (kind, value) = query.split_once('=').ok_or_else(|| {
                Error::failure("Git lock source query is not one branch, tag, or rev selector")
            })?;
            if value.is_empty() || value.contains('&') {
                return Err(Error::failure(
                    "Git lock source query has an empty or multiple selector",
                ));
            }
            let value = percent_decode(value)?;
            validate_revision(&value)?;
            match kind {
                "branch" => GitSelector::Branch(value),
                "tag" => GitSelector::Tag(value),
                "rev" => GitSelector::Revision(value),
                _ => {
                    return Err(Error::failure(format!(
                        "Git lock source has unsupported selector `{kind}`"
                    )));
                }
            }
        }
    };
    Ok(LockedSource {
        cargo_source: source.to_owned(),
        url: url.to_owned(),
        selector,
        commit: commit.to_owned(),
    })
}

fn percent_decode(value: &str) -> Result<String> {
    let mut bytes = Vec::with_capacity(value.len());
    let input = value.as_bytes();
    let mut position = 0;
    while position < input.len() {
        if input[position] != b'%' {
            bytes.push(input[position]);
            position += 1;
            continue;
        }
        let digits = input
            .get(position + 1..position + 3)
            .ok_or_else(|| Error::failure("Git lock source has incomplete percent encoding"))?;
        let high = hex_digit(digits[0])?;
        let low = hex_digit(digits[1])?;
        bytes.push((high << 4) | low);
        position += 3;
    }
    String::from_utf8(bytes)
        .map_err(|_| Error::failure("Git lock source selector is not valid UTF-8"))
}

fn hex_digit(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(Error::failure(
            "Git lock source has invalid percent encoding",
        )),
    }
}

#[derive(Clone, Debug)]
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
}

struct Materialized {
    path: String,
}

pub fn materialize_manifest_patches(
    root: &Path,
    network: &NetworkConfig,
    limits: &PolicyLimits,
    accept_all: bool,
    verbose: bool,
    progress: Progress,
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

    let mut patches = patches;
    attach_locked_commits(root, &mut patches)?;
    let mut replacements = Vec::new();
    for patch in &patches {
        progress.report(format_args!("Fetching Git patch `{}`", patch.alias))?;
        let materialized =
            materialize::materialize_one(root, patch, network, limits, accept_all, verbose)?;
        replacements.push((patch.alias.clone(), patch.package.clone(), materialized));
    }
    let rewritten = rewrite_manifest(&source, &patches, &replacements)?;
    let lock_path = root.join("Cargo.lock");
    let rewritten_lock = fs::read_to_string(&lock_path)
        .ok()
        .map(|source| rewrite_materialized_lock(&source, &patches))
        .transpose()?;
    let mut staged = AtomicFile::new(&manifest_path)?;
    staged.write_all(rewritten.as_bytes())?;
    staged.persist()?;
    let mut staged_lock = rewritten_lock
        .as_ref()
        .map(|rewritten| -> Result<AtomicFile> {
            let mut staged = AtomicFile::new(&lock_path)?;
            staged.write_all(rewritten.as_bytes())?;
            staged.persist()?;
            Ok(staged)
        })
        .transpose()?;
    staged.commit()?;
    if let Some(staged_lock) = staged_lock.take() {
        staged_lock.commit()?;
    }
    Ok(true)
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
        let Some(git) = table.get("git") else {
            continue;
        };
        let url = git.as_str().ok_or_else(|| {
            Error::failure(format!("Git patch `{alias}` git URL must be a string"))
        })?;
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
    edits.sort_unstable_by_key(|edit| std::cmp::Reverse(edit.0.start));
    let mut rewritten = source.to_owned();
    for (span, replacement) in edits {
        if span.end > rewritten.len() || !rewritten.is_char_boundary(span.start) {
            return Err(Error::failure("Git patch source span is invalid"));
        }
        rewritten.replace_range(span, &replacement);
    }
    Ok(rewritten)
}

fn rewrite_materialized_lock(source: &str, patches: &[GitPatch]) -> Result<String> {
    let document = ImDocument::parse(source.to_owned()).map_err(|error| {
        Error::failure(format!("invalid Cargo.lock before Git vendoring: {error}"))
    })?;
    let Some(packages) = document.get("package").and_then(Item::as_array_of_tables) else {
        return Ok(source.to_owned());
    };
    let mut sources = BTreeSet::new();
    for package in packages.iter() {
        let Some(value) = package.get("source").and_then(Item::as_str) else {
            continue;
        };
        let Ok(locked) = parse_locked_source(value) else {
            continue;
        };
        if patches.iter().any(|patch| {
            patch.url == locked.url
                && patch
                    .locked_commit
                    .as_deref()
                    .is_none_or(|commit| commit == locked.commit)
        }) {
            sources.insert(value.to_owned());
        }
    }
    if sources.is_empty() {
        return Ok(source.to_owned());
    }
    let mut edits = Vec::new();
    for package in packages.iter() {
        let materialized = package
            .get("source")
            .and_then(Item::as_str)
            .is_some_and(|source| sources.contains(source));
        if materialized {
            edits.push((
                lock_key_line(source, package.get("source").unwrap(), "source")?,
                String::new(),
            ));
            if let Some(checksum) = package.get("checksum") {
                edits.push((lock_key_line(source, checksum, "checksum")?, String::new()));
            }
        }
        let Some(dependencies) = package.get("dependencies").and_then(Item::as_array) else {
            continue;
        };
        for dependency in dependencies.iter() {
            let Some(spelling) = dependency.as_str() else {
                continue;
            };
            let Some((identity, source)) = spelling
                .strip_suffix(')')
                .and_then(|value| value.rsplit_once(" ("))
            else {
                continue;
            };
            if sources.contains(source) {
                let span = dependency
                    .span()
                    .ok_or_else(|| Error::failure("Cargo.lock dependency has no source span"))?;
                edits.push((span, toml_string(identity)));
            }
        }
    }
    edits.sort_unstable_by_key(|edit| std::cmp::Reverse(edit.0.start));
    let mut rewritten = source.to_owned();
    let mut previous_start = source.len();
    for (span, replacement) in edits {
        if span.end > previous_start
            || span.end > rewritten.len()
            || !rewritten.is_char_boundary(span.start)
        {
            return Err(Error::failure(
                "Cargo.lock rewrite spans overlap or are invalid",
            ));
        }
        previous_start = span.start;
        rewritten.replace_range(span, &replacement);
    }
    Ok(rewritten)
}

fn lock_key_line(source: &str, item: &Item, key: &str) -> Result<Range<usize>> {
    let span = item
        .span()
        .ok_or_else(|| Error::failure(format!("Cargo.lock `{key}` has no source span")))?;
    let start = source[..span.start]
        .rfind('\n')
        .map_or(0, |position| position + 1);
    let end = source[span.end..]
        .find('\n')
        .map_or(source.len(), |position| span.end + position + 1);
    let prefix = source[start..span.start].trim();
    let suffix = source[span.end..end].trim();
    if prefix != format!("{key} =") || (!suffix.is_empty() && !suffix.starts_with('#')) {
        return Err(Error::failure(format!(
            "Cargo.lock `{key}` is not on a replaceable canonical line"
        )));
    }
    Ok(start..end)
}

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
                      tokio = { git = \"https://example.com/tokio.git\", branch = \"motor\" }\n\
                      renamed = { git = \"https://example.com/actual.git\", rev = \"abc123\", package = \"actual\" }\n";
        let patches = parse_git_patches(Path::new("/fixture"), &document(source)).unwrap();
        assert_eq!(patches.len(), 3);
        assert!(matches!(patches[0].selector, Selector::Branch(ref value) if value == "motor"));
        assert!(matches!(patches[2].selector, Selector::Revision(ref value) if value == "abc123"));
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
                    "tokio".to_owned(),
                    None,
                    Materialized {
                        path: ".lorry/vendor/tokio/source/tokio".to_owned(),
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
        assert!(rewritten.contains("tokio = { path = \".lorry/vendor/tokio/source/tokio\" }"));
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
    fn rewrites_materialized_git_patch_lock_nodes_to_paths() {
        let git = "git+https://example.com/patched.git?branch=main#0123456789abcdef0123456789abcdef01234567";
        let other = "git+https://example.com/other.git#89abcdef0123456789abcdef0123456789abcdef";
        let source = format!(
            "version = 3\n\n\
             [[package]]\nname = \"root\"\nversion = \"0.1.0\"\n\
             dependencies = [\"helper 1.0.0 ({git})\"]\n\n\
             [[package]]\nname = \"patched\"\nversion = \"1.0.0\"\nsource = \"{git}\"\n\
             dependencies = [\"helper\"]\n\n\
             [[package]]\nname = \"helper\"\nversion = \"1.0.0\"\nsource = \"{git}\"\n\n\
             [[package]]\nname = \"other\"\nversion = \"1.0.0\"\nsource = \"{other}\"\n"
        );
        let patches = vec![GitPatch {
            alias: "patched".to_owned(),
            package: None,
            url: "https://example.com/patched.git".to_owned(),
            selector: Selector::Branch("main".to_owned()),
            locked_commit: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
            span: 0..0,
        }];
        let rewritten = rewrite_materialized_lock(&source, &patches).unwrap();
        assert!(rewritten.starts_with("version = 3"));
        assert!(!rewritten.contains(git));
        assert!(rewritten.contains(other));
        assert!(rewritten.contains("dependencies = [\"helper 1.0.0\"]"));
        assert_eq!(rewritten.matches("source = ").count(), 1);
        ImDocument::parse(rewritten).unwrap();
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

    #[test]
    fn parses_cargo_git_lock_identity() {
        let source = "git+https://example.com/repository.git?branch=feature%2Fmotor#0123456789abcdef0123456789abcdef01234567";
        let locked = parse_locked_source(source).unwrap();
        assert_eq!(locked.cargo_source, source);
        assert_eq!(locked.url, "https://example.com/repository.git");
        assert_eq!(
            locked.selector,
            GitSelector::Branch("feature/motor".to_owned())
        );
        assert_eq!(locked.commit, "0123456789abcdef0123456789abcdef01234567");

        for invalid in [
            "git+http://example.com/repository#0123456789abcdef0123456789abcdef01234567",
            "git+https://user@example.com/repository#0123456789abcdef0123456789abcdef01234567",
            "git+https://example.com/repository?branch=one&tag=two#0123456789abcdef0123456789abcdef01234567",
            "git+https://example.com/repository#0123456789ABCDEF0123456789ABCDEF01234567",
        ] {
            assert!(
                parse_locked_source(invalid).is_err(),
                "accepted `{invalid}`"
            );
        }
    }
}
