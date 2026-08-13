use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

use semver::Version;
use toml_edit::{ImDocument, Item, Value};

use crate::admission_state::{Review, TRANSACTION_RELATIVE_PATH};
use crate::atomic::{AtomicDirectory, AtomicFile};
use crate::cli::UpgradeOptions;
use crate::diagnostic::{Error, Result};
use crate::hash::{Sha256, hex};
use crate::lockfile::write_toml_string;
use crate::manifest::{Dependency, DependencySource, Manifest};
use crate::toml::Document;

pub struct Candidate {
    pub manifest: Manifest,
    pub manifest_source: Option<Vec<u8>>,
    pub forced: Option<(String, Option<Version>, Version)>,
}

pub fn package_candidate(root: &Path, selector: &str, version: &str) -> Result<Candidate> {
    let requested = Version::parse(version).map_err(|error| {
        Error::usage(
            format!("upgrade version `{version}` is not a complete semantic version: {error}"),
            "use `--to MAJOR.MINOR.PATCH` with optional semantic prerelease/build components",
        )
    })?;
    let current = Manifest::load_for_vendor(root)?;
    let (name, old_version) = parse_selector(selector)?;
    let direct = direct_match(&current, name)?;
    let (manifest, manifest_source, forced_package, forced_old) = if let Some(dependency) = direct {
        if old_version.is_some() {
            return Err(Error::usage(
                format!("direct dependency `{name}` must not include an old version"),
                "select a direct dependency by alias or package name",
            ));
        }
        let source = fs::read_to_string(&current.path).map_err(|error| {
            Error::failure(format!(
                "failed to read manifest `{}` for dependency upgrade: {error}",
                current.path.display()
            ))
        })?;
        let rewritten = rewrite_direct_version(&source, dependency, version)?;
        let manifest = Manifest::load_for_vendor_source(root, rewritten.clone())?;
        (
            manifest,
            Some(rewritten.into_bytes()),
            dependency.package.clone(),
            None,
        )
    } else {
        let lock = current.lock.as_ref().ok_or_else(|| {
            Error::failure(format!(
                "upgrade package `{name}` is not a direct dependency and Cargo.lock is missing"
            ))
        })?;
        let mut versions = lock
            .packages
            .iter()
            .filter(|package| {
                package.name == name
                    && package.source.as_deref()
                        == Some("registry+https://github.com/rust-lang/crates.io-index")
            })
            .map(|package| package.version.original.clone())
            .collect::<Vec<_>>();
        versions.sort_unstable();
        versions.dedup();
        if versions.is_empty() {
            return Err(Error::failure(format!(
                "upgrade package `{name}` is neither a direct dependency nor a locked crates.io package"
            )));
        }
        let old = if let Some(old) = old_version {
            if !versions.iter().any(|version| version == old) {
                return Err(Error::failure(format!(
                    "Cargo.lock does not contain `{name} {old}`"
                )));
            }
            old
        } else if versions.len() != 1 {
            return Err(Error::usage(
                format!(
                    "locked package `{name}` is ambiguous because Cargo.lock contains versions {}",
                    versions.join(", ")
                ),
                format!("select one with `{name}@OLD_VERSION`"),
            ));
        } else {
            &versions[0]
        };
        let old = Version::parse(old).map_err(|error| {
            Error::failure(format!("locked package `{name} {old}` is invalid: {error}"))
        })?;
        (current, None, name.to_owned(), Some(old))
    };
    Ok(Candidate {
        manifest,
        manifest_source,
        forced: Some((forced_package, forced_old, requested)),
    })
}

pub fn lock_candidate(root: &Path) -> Result<Candidate> {
    Ok(Candidate {
        manifest: Manifest::load_for_vendor(root)?,
        manifest_source: None,
        forced: None,
    })
}

pub fn command_id(options: &UpgradeOptions) -> String {
    match options {
        UpgradeOptions::Package { package, version } => format!("package\0{package}\0{version}"),
        UpgradeOptions::FromCargoLock => "from-cargo-lock".to_owned(),
    }
}

/// Displays the dependency change for approval. With a reconstructible
/// committed baseline this is a five-group semantic diff; without one (the
/// `--from-cargo-lock` recovery), the prior commitment and the complete
/// candidate report are shown instead.
pub fn approve(
    previous: Option<&Review>,
    previous_sha256: &str,
    next: &Review,
    terminal: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<()> {
    match previous {
        Some(previous) if previous == next => return Ok(()),
        Some(previous) => {
            writeln!(output, "Dependency upgrade review:").map_err(|error| {
                Error::failure(format!("failed to write upgrade review: {error}"))
            })?;
            write_difference(
                output,
                "direct requirement",
                &previous.direct_registry,
                &next.direct_registry,
                |value| (value.alias.clone(), value.kind, value.target.clone()),
            )?;
            write_difference(
                output,
                "root feature",
                &previous.root_features,
                &next.root_features,
                |value| value.name.clone(),
            )?;
            write_difference(
                output,
                "crates.io patch",
                &previous.crates_io_patches,
                &next.crates_io_patches,
                |value| value.alias.clone(),
            )?;
            write_difference(
                output,
                "locked package",
                &previous.locked_registry,
                &next.locked_registry,
                |value| value.name.clone(),
            )?;
            write_difference(
                output,
                "context",
                &previous.contexts,
                &next.contexts,
                |value| (value.host.clone(), value.target.clone()),
            )?;
            write_difference(
                output,
                "context package",
                &previous.context_registry,
                &next.context_registry,
                |value| (value.host.clone(), value.target.clone(), value.name.clone()),
            )?;
            write_difference(
                output,
                "source evidence",
                &previous.registry_sources,
                &next.registry_sources,
                |value| value.name.clone(),
            )?;
            write_difference(
                output,
                "capability",
                &previous.capabilities,
                &next.capabilities,
                |value| value.package.clone(),
            )?;
        }
        None => {
            let report = next.render()?;
            writeln!(
                output,
                "The previous admission commitment was {previous_sha256}.\n\
                 Cargo.lock has already changed, so no semantic diff is available.\n\
                 Complete candidate review document:"
            )
            .and_then(|()| output.write_all(&report))
            .map_err(|error| Error::failure(format!("failed to write upgrade review: {error}")))?;
        }
    }
    if !terminal {
        return Err(Error::failure(
            "dependency upgrade requires confirmation, but no interactive terminal is available",
        )
        .with_help(
            "rerun the command from an interactive terminal and review the displayed graph",
        ));
    }
    write!(
        output,
        "Approve this dependency and capability change? [y/N]: "
    )
    .and_then(|()| output.flush())
    .map_err(|error| Error::failure(format!("failed to write upgrade prompt: {error}")))?;
    let mut response = String::new();
    std::io::Read::take(&mut *input, 65)
        .read_line(&mut response)
        .map_err(|error| Error::failure(format!("failed to read upgrade approval: {error}")))?;
    if matches!(response.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(Error::failure("dependency upgrade approval was declined"))
    }
}

fn write_difference<T, K>(
    output: &mut impl Write,
    label: &str,
    previous: &[T],
    next: &[T],
    change_key: impl Fn(&T) -> K,
) -> Result<()>
where
    T: Ord + std::fmt::Debug,
    K: Ord,
{
    let mut removed = Vec::new();
    let mut added = Vec::new();
    let (mut previous_index, mut next_index) = (0, 0);
    while previous_index < previous.len() && next_index < next.len() {
        match previous[previous_index].cmp(&next[next_index]) {
            std::cmp::Ordering::Less => {
                removed.push(&previous[previous_index]);
                previous_index += 1;
            }
            std::cmp::Ordering::Greater => {
                added.push(&next[next_index]);
                next_index += 1;
            }
            std::cmp::Ordering::Equal => {
                previous_index += 1;
                next_index += 1;
            }
        }
    }
    removed.extend(&previous[previous_index..]);
    added.extend(&next[next_index..]);

    let mut matches = BTreeMap::<K, (usize, Vec<usize>)>::new();
    for value in &removed {
        matches.entry(change_key(value)).or_default().0 += 1;
    }
    for (index, value) in added.iter().enumerate() {
        matches.entry(change_key(value)).or_default().1.push(index);
    }
    let mut paired_additions = vec![false; added.len()];
    for value in removed {
        write_difference_line(output, '-', label, value)?;
        let Some((1, additions)) = matches.get(&change_key(value)) else {
            continue;
        };
        if additions.len() == 1 {
            let index = additions[0];
            write_difference_line(output, '+', label, added[index])?;
            paired_additions[index] = true;
        }
    }
    for (index, value) in added.into_iter().enumerate() {
        if !paired_additions[index] {
            write_difference_line(output, '+', label, value)?;
        }
    }
    Ok(())
}

fn write_difference_line(
    output: &mut impl Write,
    sign: char,
    label: &str,
    value: &impl std::fmt::Debug,
) -> Result<()> {
    writeln!(output, "  {sign} {label}: {value:?}")
        .map_err(|error| Error::failure(format!("failed to write upgrade review: {error}")))
}

pub fn commit(
    root: &Path,
    command: &str,
    manifest: Option<&[u8]>,
    lock: &[u8],
    state: &[u8],
) -> Result<()> {
    let manifest = match manifest {
        Some(bytes) => bytes.to_vec(),
        None => read_required(&root.join("Cargo.toml"))?,
    };
    let replacements = [
        Replacement::new(root.join("Cargo.toml"), "Cargo.toml", manifest)?,
        Replacement::new(root.join("Cargo.lock"), "Cargo.lock", lock.to_vec())?,
        Replacement::new(
            root.join(".lorry/dependencies-v2.toml"),
            "dependencies-v2.toml",
            state.to_vec(),
        )?,
    ];
    create_journal(root, command, &replacements)?;
    if !resume(root, command)? {
        return Err(Error::failure(
            "dependency upgrade journal disappeared before commit",
        ));
    }
    Ok(())
}

pub fn resume(root: &Path, command: &str) -> Result<bool> {
    let transaction = root.join(TRANSACTION_RELATIVE_PATH);
    match fs::symlink_metadata(&transaction) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(Error::failure(format!(
                "dependency transaction `{}` is not a real directory",
                transaction.display()
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(Error::failure(format!(
                "failed to inspect dependency transaction `{}`: {error}",
                transaction.display()
            )));
        }
    }
    let journal = Journal::load(&transaction.join("journal.toml"))?;
    if journal.command != command {
        return Err(Error::failure(
            "an unfinished dependency upgrade was created by a different command",
        )
        .with_help("rerun the exact original `lorry vendor upgrade` command"));
    }
    for file in &journal.files {
        file.install(root, &transaction)?;
    }
    fs::remove_dir_all(&transaction).map_err(|error| {
        Error::failure(format!(
            "dependency files were committed but transaction cleanup failed at `{}`: {error}",
            transaction.display()
        ))
    })?;
    sync_directory(&root.join(".lorry/transactions"))?;
    Ok(true)
}

struct Replacement {
    destination: PathBuf,
    staging_name: &'static str,
    original: String,
    candidate: String,
    bytes: Vec<u8>,
}

impl Replacement {
    fn new(destination: PathBuf, staging_name: &'static str, bytes: Vec<u8>) -> Result<Self> {
        let original = file_identity(&destination)?;
        let candidate = bytes_identity(&bytes);
        Ok(Self {
            destination,
            staging_name,
            original,
            candidate,
            bytes,
        })
    }
}

fn create_journal(root: &Path, command: &str, replacements: &[Replacement; 3]) -> Result<()> {
    let lorry = root.join(".lorry");
    ensure_private_directory(&lorry)?;
    let transactions = lorry.join("transactions");
    ensure_private_directory(&transactions)?;
    let destination = root.join(TRANSACTION_RELATIVE_PATH);
    if destination.exists() {
        return Err(Error::failure(format!(
            "dependency transaction `{}` already exists",
            destination.display()
        )));
    }
    let staging = AtomicDirectory::new(&transactions, "dependency-upgrade")?;
    for replacement in replacements {
        write_persisted(
            &staging.path().join(replacement.staging_name),
            &replacement.bytes,
        )?;
    }
    write_persisted(
        &staging.path().join("journal.toml"),
        render_journal(command, replacements).as_bytes(),
    )?;
    sync_directory(staging.path())?;
    if !staging.commit_no_replace(&destination)? {
        return Err(Error::failure(format!(
            "dependency transaction `{}` appeared concurrently",
            destination.display()
        )));
    }
    sync_directory(&transactions)
}

fn render_journal(command: &str, replacements: &[Replacement; 3]) -> String {
    let mut output = String::from("format-version = 1\ncommand = ");
    write_toml_string(&mut output, command);
    output.push('\n');
    for replacement in replacements {
        output.push_str("\n[[file]]\ndestination = ");
        write_toml_string(
            &mut output,
            replacement
                .destination
                .file_name()
                .and_then(|name| name.to_str())
                .expect("fixed destination is UTF-8"),
        );
        output.push_str("\nstaging = ");
        write_toml_string(&mut output, replacement.staging_name);
        output.push_str("\noriginal-sha256 = ");
        write_toml_string(&mut output, &replacement.original);
        output.push_str("\ncandidate-sha256 = ");
        write_toml_string(&mut output, &replacement.candidate);
        output.push('\n');
    }
    output
}

struct Journal {
    command: String,
    files: Vec<JournalFile>,
}

struct JournalFile {
    destination: String,
    staging: String,
    original: String,
    candidate: String,
}

impl Journal {
    fn load(path: &Path) -> Result<Self> {
        let document = Document::load(path, "Lorry dependency upgrade journal")?;
        for (key, _) in document.root().iter() {
            if !matches!(key, "format-version" | "command" | "file") {
                return Err(Error::failure(format!(
                    "dependency upgrade journal contains unknown key `{key}`"
                )));
            }
        }
        if document
            .root()
            .get("format-version")
            .and_then(Item::as_integer)
            != Some(1)
        {
            return Err(Error::failure(
                "dependency upgrade journal has unsupported format-version",
            ));
        }
        let command = journal_string(document.root().get("command"), "command")?;
        let tables = document
            .root()
            .get("file")
            .and_then(Item::as_array_of_tables)
            .ok_or_else(|| Error::failure("dependency upgrade journal is missing file entries"))?;
        let mut files = Vec::new();
        for table in tables.iter() {
            for (key, _) in table.iter() {
                if !matches!(
                    key,
                    "destination" | "staging" | "original-sha256" | "candidate-sha256"
                ) {
                    return Err(Error::failure(format!(
                        "dependency upgrade journal file contains unknown key `{key}`"
                    )));
                }
            }
            files.push(JournalFile {
                destination: journal_string(table.get("destination"), "destination")?,
                staging: journal_string(table.get("staging"), "staging")?,
                original: journal_string(table.get("original-sha256"), "original-sha256")?,
                candidate: journal_string(table.get("candidate-sha256"), "candidate-sha256")?,
            });
        }
        if files.len() != 3
            || files
                .iter()
                .map(|file| file.destination.as_str())
                .collect::<Vec<_>>()
                != ["Cargo.toml", "Cargo.lock", "dependencies-v2.toml"]
        {
            return Err(Error::failure(
                "dependency upgrade journal does not contain the exact ordered file set",
            ));
        }
        Ok(Self { command, files })
    }
}

impl JournalFile {
    fn install(&self, root: &Path, transaction: &Path) -> Result<()> {
        if !matches!(
            (self.destination.as_str(), self.staging.as_str()),
            ("Cargo.toml", "Cargo.toml")
                | ("Cargo.lock", "Cargo.lock")
                | ("dependencies-v2.toml", "dependencies-v2.toml")
        ) {
            return Err(Error::failure(
                "dependency upgrade journal contains an unsafe file mapping",
            ));
        }
        validate_identity(&self.original)?;
        validate_identity(&self.candidate)?;
        let source = transaction.join(&self.staging);
        let bytes = read_required(&source)?;
        if bytes_identity(&bytes) != self.candidate {
            return Err(Error::failure(format!(
                "staged dependency upgrade file `{}` changed",
                source.display()
            )));
        }
        let destination = if self.destination == "dependencies-v2.toml" {
            root.join(".lorry/dependencies-v2.toml")
        } else {
            root.join(&self.destination)
        };
        let current = file_identity(&destination)?;
        if current == self.candidate {
            return Ok(());
        }
        if current != self.original {
            return Err(Error::failure(format!(
                "dependency upgrade cannot resume because `{}` changed outside the transaction",
                destination.display()
            ))
            .with_help("restore the original or staged file contents, then rerun the command"));
        }
        let mut staged = AtomicFile::new(&destination)?;
        staged.write_all(&bytes)?;
        staged.persist()?;
        staged.commit()
    }
}

fn journal_string(item: Option<&Item>, name: &str) -> Result<String> {
    item.and_then(Item::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            Error::failure(format!(
                "dependency upgrade journal `{name}` is missing or not a string"
            ))
        })
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(Error::failure(format!(
                "refusing unsafe dependency state directory `{}`",
                path.display()
            )));
        }
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(Error::failure(format!(
                "failed to inspect dependency state directory `{}`: {error}",
                path.display()
            )));
        }
    }
    #[cfg(unix)]
    let mut builder = fs::DirBuilder::new();
    #[cfg(not(unix))]
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|error| {
        Error::failure(format!(
            "failed to create dependency state directory `{}`: {error}",
            path.display()
        ))
    })
}

fn write_persisted(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        Error::failure(format!(
            "failed to create staged file `{}`: {error}",
            path.display()
        ))
    })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            Error::failure(format!(
                "failed to persist staged file `{}`: {error}",
                path.display()
            ))
        })
}

fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            Error::failure(format!(
                "failed to persist directory `{}`: {error}",
                path.display()
            ))
        })
}

fn read_required(path: &Path) -> Result<Vec<u8>> {
    fs::read(path)
        .map_err(|error| Error::failure(format!("failed to read `{}`: {error}", path.display())))
}

fn file_identity(path: &Path) -> Result<String> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes_identity(&bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok("missing".to_owned()),
        Err(error) => Err(Error::failure(format!(
            "failed to read `{}`: {error}",
            path.display()
        ))),
    }
}

fn bytes_identity(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    hex(&digest.finish())
}

fn validate_identity(identity: &str) -> Result<()> {
    if identity == "missing"
        || (identity.len() == 64
            && identity
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
        Ok(())
    } else {
        Err(Error::failure(
            "dependency upgrade journal contains an invalid file identity",
        ))
    }
}

fn parse_selector(selector: &str) -> Result<(&str, Option<&str>)> {
    let Some((name, old)) = selector.rsplit_once('@') else {
        return Ok((selector, None));
    };
    if name.is_empty() || Version::parse(old).is_err() {
        return Err(Error::usage(
            format!("invalid upgrade package selector `{selector}`"),
            "use PACKAGE or PACKAGE@OLD_VERSION",
        ));
    }
    Ok((name, Some(old)))
}

fn direct_match<'a>(manifest: &'a Manifest, selector: &str) -> Result<Option<&'a Dependency>> {
    let by_alias = manifest
        .dependencies
        .iter()
        .filter(|dependency| dependency.alias == selector)
        .collect::<Vec<_>>();
    let matches = if by_alias.is_empty() {
        manifest
            .dependencies
            .iter()
            .filter(|dependency| dependency.package == selector)
            .collect::<Vec<_>>()
    } else {
        by_alias
    };
    if matches
        .iter()
        .any(|dependency| dependency.source != DependencySource::CratesIo)
    {
        return Err(Error::failure(format!(
            "direct dependency `{selector}` is not a crates.io dependency"
        ))
        .with_help("only direct crates.io version declarations can be upgraded"));
    }
    let matches = matches
        .into_iter()
        .filter(|dependency| dependency.source == DependencySource::CratesIo)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok(None),
        [dependency] => Ok(Some(*dependency)),
        _ => Err(Error::usage(
            format!("direct dependency selector `{selector}` is ambiguous"),
            "use a unique dependency alias; target-conditioned declarations may need distinct aliases",
        )),
    }
}

fn rewrite_direct_version(source: &str, dependency: &Dependency, version: &str) -> Result<String> {
    let document = ImDocument::parse(source.to_owned()).map_err(|error| {
        Error::failure(format!(
            "failed to parse Cargo.toml for dependency upgrade: {error}"
        ))
    })?;
    let item = dependency_item(&document, dependency)?;
    let span = version_span(item, &dependency.alias)?;
    replace_span(source, span, &toml_string(&format!("={version}")))
}

fn dependency_item<'a>(
    document: &'a ImDocument<String>,
    dependency: &Dependency,
) -> Result<&'a Item> {
    let table = if let Some(target) = &dependency.target {
        document
            .get("target")
            .and_then(Item::as_table)
            .and_then(|targets| targets.get(target))
            .and_then(Item::as_table)
            .and_then(|target| target.get("dependencies"))
            .and_then(Item::as_table)
    } else {
        document.get("dependencies").and_then(Item::as_table)
    }
    .ok_or_else(|| Error::failure("direct dependency table disappeared during upgrade"))?;
    table.get(&dependency.alias).ok_or_else(|| {
        Error::failure(format!(
            "direct dependency `{}` disappeared during upgrade",
            dependency.alias
        ))
    })
}

fn version_span(item: &Item, alias: &str) -> Result<Range<usize>> {
    if item.as_str().is_some() {
        return item.span().ok_or_else(|| {
            Error::failure(format!("direct dependency `{alias}` has no source span"))
        });
    }
    let value = match item {
        Item::Value(Value::InlineTable(table)) => table.get("version"),
        Item::Table(table) => table.get("version").and_then(Item::as_value),
        _ => None,
    }
    .ok_or_else(|| {
        Error::failure(format!(
            "direct crates.io dependency `{alias}` has no version value"
        ))
    })?;
    value.span().ok_or_else(|| {
        Error::failure(format!(
            "direct dependency `{alias}` version has no source span"
        ))
    })
}

fn replace_span(source: &str, span: Range<usize>, replacement: &str) -> Result<String> {
    if span.end > source.len()
        || span.start > span.end
        || !source.is_char_boundary(span.start)
        || !source.is_char_boundary(span.end)
    {
        return Err(Error::failure("dependency version source span is invalid"));
    }
    let mut result = source.to_owned();
    result.replace_range(span, replacement);
    Ok(result)
}

fn toml_string(value: &str) -> String {
    format!("\"{value}\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission_state::RegistrySource;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(manifest: &str) -> Self {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "lorry-upgrade-manifest-{}-{id}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("src")).unwrap();
            fs::write(root.join("src/lib.rs"), "pub fn root() {}\n").unwrap();
            fs::write(root.join("Cargo.toml"), manifest).unwrap();
            Self(root)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn rewrites_only_direct_version_spelling() {
        for (source, expected) in [
            (
                "[package]\nname='root'\nversion='0.1.0'\n[dependencies]\nlibc = '0.2.1' # keep\n",
                "[package]\nname='root'\nversion='0.1.0'\n[dependencies]\nlibc = \"=0.2.2\" # keep\n",
            ),
            (
                "[package]\nname='root'\nversion='0.1.0'\n[dependencies]\nsys = { package='libc', version = '0.2.1', features=[] }\n",
                "[package]\nname='root'\nversion='0.1.0'\n[dependencies]\nsys = { package='libc', version = \"=0.2.2\", features=[] }\n",
            ),
            (
                "[package]\nname='root'\nversion='0.1.0'\n[target.'cfg(unix)'.dependencies]\nlibc = { version='0.2.1' }\n",
                "[package]\nname='root'\nversion='0.1.0'\n[target.'cfg(unix)'.dependencies]\nlibc = { version=\"=0.2.2\" }\n",
            ),
            (
                "[package]\nname='root'\nversion='0.1.0'\n[dependencies.libc]\nversion = '0.2.1'\ndefault-features = false\n",
                "[package]\nname='root'\nversion='0.1.0'\n[dependencies.libc]\nversion = \"=0.2.2\"\ndefault-features = false\n",
            ),
        ] {
            let fixture = Fixture::new(source);
            let candidate = package_candidate(&fixture.0, "libc", "0.2.2").unwrap();
            assert_eq!(candidate.manifest_source.unwrap(), expected.as_bytes());
            assert_eq!(
                fs::read(fixture.0.join("Cargo.toml")).unwrap(),
                source.as_bytes()
            );
        }
    }

    #[test]
    fn rejects_ambiguous_direct_and_locked_packages() {
        let fixture = Fixture::new(
            "[package]\nname='root'\nversion='0.1.0'\n[dependencies]\na={package='libc',version='0.2'}\nb={package='libc',version='0.2'}\n",
        );
        assert!(package_candidate(&fixture.0, "libc", "0.2.2").is_err());
    }

    #[test]
    fn pairs_changed_review_items_before_unpaired_additions() {
        let source = |version: &str, checksum: &str| RegistrySource {
            name: "example".to_owned(),
            version: version.to_owned(),
            checksum: checksum.repeat(64),
            license: "MIT".to_owned(),
            source_tree_sha256: checksum.repeat(64),
            build_script: false,
        };
        let previous = Review {
            registry_sources: vec![source("1.0.0", "1")],
            ..Review::default()
        };
        let next = Review {
            registry_sources: vec![
                source("2.0.0", "2"),
                RegistrySource {
                    name: "new-package".to_owned(),
                    version: "1.0.0".to_owned(),
                    checksum: "3".repeat(64),
                    license: "MIT".to_owned(),
                    source_tree_sha256: "3".repeat(64),
                    build_script: false,
                },
            ],
            ..Review::default()
        };
        let mut output = Vec::new();
        let error = approve(
            Some(&previous),
            &"0".repeat(64),
            &next,
            false,
            &mut "".as_bytes(),
            &mut output,
        )
        .unwrap_err();
        assert!(error.render().contains("interactive terminal"));
        let output = String::from_utf8(output).unwrap();
        let removal = output.find("- source evidence").unwrap();
        let changed_addition = output[removal..].find("+ source evidence").unwrap() + removal;
        let unpaired_addition = output.find("new-package").unwrap();
        assert!(removal < changed_addition);
        assert!(changed_addition < unpaired_addition, "{output}");
        assert!(!output[removal..changed_addition].contains("new-package"));
    }

    #[test]
    fn journal_commits_state_last_and_recovers_an_interruption() {
        let fixture = Fixture::new(
            "[package]\nname='root'\nversion='0.1.0'\n[dependencies]\nlibc='=0.2.1'\n",
        );
        fs::create_dir_all(fixture.0.join(".lorry")).unwrap();
        fs::write(fixture.0.join("Cargo.lock"), b"old-lock").unwrap();
        fs::write(fixture.0.join(".lorry/dependencies-v2.toml"), b"old-state").unwrap();
        let command = "package\0libc\00.2.2";
        let replacements = [
            Replacement::new(
                fixture.0.join("Cargo.toml"),
                "Cargo.toml",
                b"new-manifest".to_vec(),
            )
            .unwrap(),
            Replacement::new(
                fixture.0.join("Cargo.lock"),
                "Cargo.lock",
                b"new-lock".to_vec(),
            )
            .unwrap(),
            Replacement::new(
                fixture.0.join(".lorry/dependencies-v2.toml"),
                "dependencies-v2.toml",
                b"new-state".to_vec(),
            )
            .unwrap(),
        ];
        create_journal(&fixture.0, command, &replacements).unwrap();
        fs::write(fixture.0.join("Cargo.toml"), b"new-manifest").unwrap();
        assert!(
            crate::admission_state::require_no_transaction(&fixture.0)
                .unwrap_err()
                .render()
                .contains("unfinished")
        );
        assert!(resume(&fixture.0, command).unwrap());
        assert_eq!(fs::read(fixture.0.join("Cargo.lock")).unwrap(), b"new-lock");
        assert_eq!(
            fs::read(fixture.0.join(".lorry/dependencies-v2.toml")).unwrap(),
            b"new-state"
        );
        assert!(!fixture.0.join(TRANSACTION_RELATIVE_PATH).exists());
    }

    #[test]
    fn journal_rejects_wrong_command_and_external_edits() {
        let fixture = Fixture::new("[package]\nname='root'\nversion='0.1.0'\n");
        fs::create_dir_all(fixture.0.join(".lorry")).unwrap();
        fs::write(fixture.0.join("Cargo.lock"), b"old-lock").unwrap();
        fs::write(fixture.0.join(".lorry/dependencies-v2.toml"), b"old-state").unwrap();
        let command = "from-cargo-lock";
        let replacements = [
            Replacement::new(
                fixture.0.join("Cargo.toml"),
                "Cargo.toml",
                b"new-manifest".to_vec(),
            )
            .unwrap(),
            Replacement::new(
                fixture.0.join("Cargo.lock"),
                "Cargo.lock",
                b"new-lock".to_vec(),
            )
            .unwrap(),
            Replacement::new(
                fixture.0.join(".lorry/dependencies-v2.toml"),
                "dependencies-v2.toml",
                b"new-state".to_vec(),
            )
            .unwrap(),
        ];
        create_journal(&fixture.0, command, &replacements).unwrap();
        assert!(resume(&fixture.0, "different").is_err());
        fs::write(fixture.0.join("Cargo.lock"), b"external-edit").unwrap();
        assert!(resume(&fixture.0, command).is_err());
        assert!(fixture.0.join(TRANSACTION_RELATIVE_PATH).exists());
    }
}
