use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use semver::Version;
use toml_edit::Item;

use crate::admission_state::TRANSACTION_RELATIVE_PATH;
use crate::atomic::{AtomicDirectory, AtomicFile};
use crate::cli::UpgradeOptions;
use crate::diagnostic::{Error, Result};
use crate::hash::{Sha256, hex};
use crate::lockfile::write_toml_string;
use crate::manifest::{DependencySource, Manifest};
use crate::toml::Document;

pub struct Candidate {
    pub manifest: Manifest,
    pub manifest_source: Option<Vec<u8>>,
    pub forced: Option<(String, Option<Version>, Version)>,
}

#[derive(Debug)]
pub struct Selection {
    name: String,
    old: Version,
    requested: Version,
}

impl Selection {
    pub fn as_resolver_input(&self) -> (&str, Option<&Version>, &Version) {
        (&self.name, Some(&self.old), &self.requested)
    }
}

pub fn transitive_selection(
    manifest: &Manifest,
    selector: &str,
    version: &str,
) -> Result<Selection> {
    let requested = Version::parse(version).map_err(|error| {
        Error::usage(
            format!("upgrade version `{version}` is not a complete semantic version: {error}"),
            "use `--to MAJOR.MINOR.PATCH` with optional semantic prerelease/build components",
        )
    })?;
    let (name, old_version) = parse_selector(selector)?;
    reject_direct(manifest, name)?;
    let lock = manifest.lock.as_ref().ok_or_else(|| {
        Error::failure(format!(
            "transitive upgrade package `{name}` requires Cargo.lock"
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
            "upgrade package `{name}` is not a locked transitive crates.io package"
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
    Ok(Selection {
        name: name.to_owned(),
        old,
        requested,
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

fn reject_direct(manifest: &Manifest, selector: &str) -> Result<()> {
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
        [] => Ok(()),
        [_] => Err(Error::usage(
            format!("`{selector}` is a direct dependency"),
            "edit its version requirement in Cargo.toml, then run `lorry vendor`",
        )),
        _ => Err(Error::usage(
            format!("direct dependency selector `{selector}` is ambiguous"),
            "use a unique dependency alias; target-conditioned declarations may need distinct aliases",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn directs_manifest_dependencies_to_ordinary_vendoring() {
        let fixture = Fixture::new(
            "[package]\nname='root'\nversion='0.1.0'\n[dependencies]\na={package='libc',version='0.2'}\nb={package='libc',version='0.2'}\n",
        );
        let manifest = Manifest::load_for_vendor(&fixture.0).unwrap();
        assert!(
            transitive_selection(&manifest, "libc", "0.2.2")
                .unwrap_err()
                .render()
                .contains("ambiguous")
        );
        let error = transitive_selection(&manifest, "a", "0.2.2").unwrap_err();
        assert!(error.render().contains("edit its version requirement"));
    }

    #[test]
    fn selects_one_locked_transitive_identity() {
        let fixture = Fixture::new("[package]\nname='root'\nversion='0.1.0'\n");
        fs::write(
            fixture.0.join("Cargo.lock"),
            format!(
                "version = 4\n\n\
                 [[package]]\nname = \"root\"\nversion = \"0.1.0\"\n\n\
                 [[package]]\nname = \"demo\"\nversion = \"1.2.3\"\n\
                 source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                 checksum = \"{}\"\n\n\
                 [[package]]\nname = \"demo\"\nversion = \"2.0.0\"\n\
                 source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                 checksum = \"{}\"\n",
                "1".repeat(64),
                "2".repeat(64),
            ),
        )
        .unwrap();
        let manifest = Manifest::load_for_vendor(&fixture.0).unwrap();
        assert!(
            transitive_selection(&manifest, "demo", "1.2.4")
                .unwrap_err()
                .render()
                .contains("ambiguous")
        );
        let selection = transitive_selection(&manifest, "demo@1.2.3", "1.2.4").unwrap();
        let (name, old, requested) = selection.as_resolver_input();
        assert_eq!(name, "demo");
        assert_eq!(old.unwrap(), &Version::parse("1.2.3").unwrap());
        assert_eq!(requested, &Version::parse("1.2.4").unwrap());
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
