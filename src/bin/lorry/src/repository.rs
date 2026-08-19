#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use semver::Version;
use toml_edit::{Item, Table};

use crate::archive::{ExtractedArchive, Limits as ArchiveLimits, extract_crate};
use crate::atomic::{AtomicDirectory, move_no_replace};
use crate::config::Repositories;
use crate::diagnostic::{Error, Result};
use crate::hash::{Sha256, decode_hex, hex};
use crate::json::Value;
use crate::lockfile::write_toml_string;
use crate::manifest::Manifest;
use crate::source_tree::{Exclusions, Limits, Tree};
use crate::sparse::Record as SparseRecord;
use crate::toml::Document;
use crate::validation::ValidationMode;

const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
const INDEX_RECORD_LIMIT: usize = 16 * 1024 * 1024;
const MANIFEST_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Layer {
    Local,
    User,
    System,
}

impl Layer {
    fn name(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::User => "user",
            Self::System => "system",
        }
    }
}

#[derive(Clone, Debug)]
struct Repository {
    layer: Layer,
    root: PathBuf,
    present: bool,
}

#[derive(Clone, Debug)]
pub struct RepositorySet {
    layers: Vec<Repository>,
    limits: Limits,
    max_archive_bytes: u64,
    validation: ValidationMode,
    /// Objects verified by this set (and its clones). Repository objects are
    /// content-addressed and never replaced in place, so within one process a
    /// verified object stays valid; caching avoids re-hashing archives and
    /// source trees on every lookup.
    verified_registry: Arc<Mutex<BTreeMap<String, RegistryObject>>>,
    verified_seeded_git: Arc<Mutex<BTreeMap<String, SeededGitObject>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryObject {
    pub layer: Layer,
    pub root: PathBuf,
    pub name: String,
    pub version: Version,
    pub checksum: [u8; 32],
    pub license: String,
    pub archive_bytes: u64,
    pub extracted_bytes: u64,
    pub file_count: u64,
    pub directory_count: u64,
    pub source_tree_sha256: [u8; 32],
    pub retained_archive: bool,
    pub retained_source: bool,
    /// The verified retained source tree, when the object retains one.
    pub source_tree: Option<Tree>,
    pub index: SparseRecord,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeededGitObject {
    pub layer: Layer,
    pub root: PathBuf,
    pub name: String,
    pub version: Version,
    pub cargo_source: String,
    pub git_url: String,
    pub requested_revision: String,
    pub resolved_commit: String,
    pub git_tree: String,
    pub patch_files: Vec<String>,
    pub upstream_crates_io_checksum: [u8; 32],
    pub source_tree_sha256: [u8; 32],
    pub license: String,
    pub extracted_bytes: u64,
    pub file_count: u64,
    pub directory_count: u64,
}

#[derive(Debug)]
pub struct RepositoryWriter {
    root: PathBuf,
    sync_file: File,
    layer: Layer,
    limits: Limits,
    archive_limits: ArchiveLimits,
    keep_artifacts: bool,
    keep_sources: bool,
}

#[derive(Debug)]
pub struct RepositoryTransaction {
    writer: RepositoryWriter,
    staging: AtomicDirectory,
    objects: Vec<StagedRegistryObject>,
}

#[derive(Debug)]
pub struct StagedRegistryObject {
    object: RegistryObject,
    manifest: Manifest,
    inspection: Option<ExtractedArchive>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedRegistryObject {
    pub object: RegistryObject,
    pub added: bool,
}

impl RepositorySet {
    pub fn open(
        repositories: &Repositories,
        limits: Limits,
        max_archive_bytes: u64,
    ) -> Result<Self> {
        Self::open_with_validation(
            repositories,
            limits,
            max_archive_bytes,
            ValidationMode::Strict,
        )
    }

    pub fn open_with_validation(
        repositories: &Repositories,
        limits: Limits,
        max_archive_bytes: u64,
        validation: ValidationMode,
    ) -> Result<Self> {
        let mut layers = Vec::new();
        for (layer, path) in [
            (Layer::Local, repositories.local.as_deref()),
            (Layer::User, repositories.user.as_deref()),
            (Layer::System, repositories.system.as_deref()),
        ] {
            if let Some(path) = path {
                layers.push(Repository::open(layer, path)?);
            }
        }
        Ok(Self {
            layers,
            limits,
            max_archive_bytes,
            validation,
            verified_registry: Arc::new(Mutex::new(BTreeMap::new())),
            verified_seeded_git: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    pub fn lookup_registry(&self, checksum: &str) -> Result<Option<RegistryObject>> {
        let checksum_bytes = decode_hex::<32>(checksum).map_err(|error| {
            Error::failure(format!(
                "invalid crates.io object checksum `{checksum}`: {error}"
            ))
        })?;
        if let Some(object) = lock_cache(&self.verified_registry).get(checksum) {
            return Ok(Some(object.clone()));
        }
        for repository in &self.layers {
            if !repository.present {
                continue;
            }
            let object_path = repository
                .root
                .join("objects/crates-io/sha256")
                .join(&checksum[..2])
                .join(checksum);
            if !entry_exists(&object_path)? {
                continue;
            }
            let object = verify_registry_object(
                repository.layer,
                &object_path,
                checksum_bytes,
                self.limits,
                self.max_archive_bytes,
                self.validation.is_strict(),
            )
            .map_err(|error| shadow_error(repository, &object_path, error))?;
            lock_cache(&self.verified_registry).insert(checksum.to_owned(), object.clone());
            return Ok(Some(object));
        }
        Ok(None)
    }

    pub fn lookup_seeded_git(&self, source_tree_sha256: &str) -> Result<Option<SeededGitObject>> {
        let digest = decode_hex::<32>(source_tree_sha256).map_err(|error| {
            Error::failure(format!(
                "invalid seeded-Git source-tree digest `{source_tree_sha256}`: {error}"
            ))
        })?;
        if let Some(object) = lock_cache(&self.verified_seeded_git).get(source_tree_sha256) {
            return Ok(Some(object.clone()));
        }
        for repository in &self.layers {
            if !repository.present {
                continue;
            }
            let object_path = repository
                .root
                .join("objects/seeded-git/sha256")
                .join(&source_tree_sha256[..2])
                .join(source_tree_sha256);
            if !entry_exists(&object_path)? {
                continue;
            }
            let object = verify_seeded_git_object(
                repository.layer,
                &object_path,
                digest,
                self.limits,
                self.validation.is_strict(),
            )
            .map_err(|error| shadow_error(repository, &object_path, error))?;
            lock_cache(&self.verified_seeded_git)
                .insert(source_tree_sha256.to_owned(), object.clone());
            return Ok(Some(object));
        }
        Ok(None)
    }
}

/// Locks a verification cache, recovering from a poisoned lock: cache entries
/// are only inserted after a completed verification, so the map is always
/// internally consistent.
fn lock_cache<T>(
    cache: &Mutex<BTreeMap<String, T>>,
) -> std::sync::MutexGuard<'_, BTreeMap<String, T>> {
    cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Repository {
    fn open(layer: Layer, root: &Path) -> Result<Self> {
        let metadata = match fs::symlink_metadata(root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    layer,
                    root: root.to_owned(),
                    present: false,
                });
            }
            Err(error) => {
                return Err(Error::failure(format!(
                    "failed to inspect {} repository `{}`: {error}",
                    layer.name(),
                    root.display()
                )));
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::failure(format!(
                "{} repository `{}` is not a real directory",
                layer.name(),
                root.display()
            )));
        }
        verify_repository_header(root).map_err(|error| {
            Error::failure(format!(
                "invalid {} repository `{}`: {error}",
                layer.name(),
                root.display()
            ))
        })?;
        Ok(Self {
            layer,
            root: root.to_owned(),
            present: true,
        })
    }
}

impl RepositoryWriter {
    pub fn open(
        repositories: &Repositories,
        limits: Limits,
        archive_limits: ArchiveLimits,
    ) -> Result<Self> {
        let (layer, root) = if let Some(root) = &repositories.local {
            (Layer::Local, root.clone())
        } else if let Some(root) = &repositories.user {
            (Layer::User, root.clone())
        } else {
            return Err(Error::failure(
                "vendoring registry packages requires a writable Lorry repository",
            )
            .with_help("configure an absolute `repositories.local` or `repositories.user` path"));
        };
        initialize_repository(&root)?;
        verify_repository_header(&root)?;
        for relative in [
            "objects",
            "objects/crates-io",
            "objects/crates-io/sha256",
            "objects/seeded-git",
            "objects/seeded-git/sha256",
            ".staging",
        ] {
            require_real_directory(&root.join(relative), "repository directory")?;
        }
        Ok(Self {
            sync_file: open_repository_sync_file(&root)?,
            root,
            layer,
            limits,
            archive_limits,
            keep_artifacts: repositories.keep_artifacts,
            keep_sources: repositories.keep_sources,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn begin(self) -> Result<RepositoryTransaction> {
        let staging = AtomicDirectory::new(&self.root.join(".staging"), "vendor")?;
        Ok(RepositoryTransaction {
            writer: self,
            staging,
            objects: Vec::new(),
        })
    }
}

impl RepositoryTransaction {
    pub fn path(&self) -> &Path {
        self.staging.path()
    }

    pub fn stage_registry(
        &mut self,
        record: &SparseRecord,
        archive: &Path,
    ) -> Result<&StagedRegistryObject> {
        if self
            .objects
            .iter()
            .any(|object| object.object.checksum == record.checksum)
        {
            return Err(Error::failure(format!(
                "vendor transaction repeats crates.io object `{}`",
                hex(&record.checksum)
            )));
        }
        let checksum = hex(&record.checksum);
        let objects = self.staging.path().join("objects");
        if !objects.exists() {
            fs::create_dir(&objects).map_err(|error| {
                Error::failure(format!(
                    "failed to create vendor object staging `{}`: {error}",
                    objects.display()
                ))
            })?;
        }
        let object_path = objects.join(&checksum);
        fs::create_dir(&object_path).map_err(|error| {
            Error::failure(format!(
                "failed to create repository object staging `{}`: {error}",
                object_path.display()
            ))
        })?;

        let archive_bytes = fs::symlink_metadata(archive)
            .map_err(|error| {
                Error::failure(format!(
                    "failed to inspect downloaded archive `{}`: {error}",
                    archive.display()
                ))
            })?
            .len();
        let extraction_parent = if self.writer.keep_sources {
            object_path.clone()
        } else {
            let inspections = self.staging.path().join("inspections");
            if !inspections.exists() {
                fs::create_dir(&inspections).map_err(|error| {
                    Error::failure(format!(
                        "failed to create inspection staging `{}`: {error}",
                        inspections.display()
                    ))
                })?;
            }
            inspections
        };
        let extracted = extract_crate(
            archive,
            record.checksum,
            &extraction_parent,
            &record.name,
            &record.version,
            self.writer.archive_limits,
        )?;
        let manifest = Manifest::load_path_dependency(extracted.path())?;
        let manifest_version = Version::parse(&manifest.version.original).map_err(|error| {
            Error::failure(format!(
                "downloaded package has invalid version `{} {}`: {error}",
                manifest.name, manifest.version.original
            ))
        })?;
        if manifest.name != record.name || manifest_version != record.version {
            return Err(Error::failure(format!(
                "downloaded archive identifies `{} {}`, but sparse index selected `{} {}`",
                manifest.name, manifest.version.original, record.name, record.version
            )));
        }
        if manifest.metadata.license.is_empty() {
            return Err(Error::failure(format!(
                "downloaded package `{} {}` has no license expression",
                record.name, record.version
            )));
        }
        let tree = extracted.tree().clone();
        write_new(
            &object_path.join("package.toml"),
            &registry_package_toml(
                record,
                &manifest.metadata.license,
                archive_bytes,
                &tree,
                self.writer.keep_artifacts,
                self.writer.keep_sources,
            ),
        )?;
        write_new(&object_path.join("index-record.json"), &record.exact_bytes)?;
        if self.writer.keep_artifacts {
            copy_new(archive, &object_path.join("package.crate"))?;
        }
        let (manifest, inspection) = if self.writer.keep_sources {
            write_new(
                &object_path.join("source-manifest.json"),
                &tree.manifest_bytes(),
            )?;
            extracted.commit(&object_path.join("source"))?;
            (
                Manifest::load_path_dependency(&object_path.join("source"))?,
                None,
            )
        } else {
            (manifest, Some(extracted))
        };
        let object = verify_registry_object(
            self.writer.layer,
            &object_path,
            record.checksum,
            self.writer.limits,
            self.writer.archive_limits.max_compressed_bytes,
            true,
        )?;
        self.objects.push(StagedRegistryObject {
            object,
            manifest,
            inspection,
        });
        Ok(self.objects.last().unwrap())
    }

    pub fn objects(&self) -> &[StagedRegistryObject] {
        &self.objects
    }

    pub fn publish(self) -> Result<Vec<PublishedRegistryObject>> {
        for staged in &self.objects {
            persist_object_tree(&staged.object.root, &self.writer.sync_file)?;
            let verified = verify_registry_object(
                self.writer.layer,
                &staged.object.root,
                staged.object.checksum,
                self.writer.limits,
                self.writer.archive_limits.max_compressed_bytes,
                true,
            )?;
            if verified != staged.object {
                return Err(Error::failure(format!(
                    "staged repository object `{}` changed before publication",
                    staged.object.root.display()
                )));
            }

            let destination = self.object_destination(&staged.object)?;
            ensure_object_prefix(destination.parent().unwrap(), &self.writer.sync_file)?;
            if entry_exists(&destination)? {
                verify_matching_object(&self.writer, staged, &destination)?;
            }
        }

        let mut published = Vec::with_capacity(self.objects.len());
        for staged in &self.objects {
            let destination = self.object_destination(&staged.object)?;
            let added = move_no_replace(&staged.object.root, &destination)?;
            if added {
                sync_directory(destination.parent().unwrap(), &self.writer.sync_file)?;
            }
            let object = verify_matching_object(&self.writer, staged, &destination)?;
            published.push(PublishedRegistryObject { object, added });
        }
        drop(self);
        Ok(published)
    }

    fn object_destination(&self, object: &RegistryObject) -> Result<PathBuf> {
        let checksum = hex(&object.checksum);
        let prefix = checksum.get(..2).ok_or_else(|| {
            Error::failure(format!("invalid staged repository checksum `{checksum}`"))
        })?;
        Ok(self
            .writer
            .root
            .join("objects/crates-io/sha256")
            .join(prefix)
            .join(checksum))
    }
}

impl StagedRegistryObject {
    pub fn object(&self) -> &RegistryObject {
        &self.object
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The staged package's verified source tree: the retained tree when
    /// sources are kept, or the inspection extraction's tree otherwise.
    pub fn source_tree(&self) -> Result<&Tree> {
        if let Some(tree) = &self.object.source_tree {
            return Ok(tree);
        }
        match &self.inspection {
            Some(extracted) => Ok(extracted.tree()),
            None => Err(Error::failure(format!(
                "staged object `{} {}` retains no source tree",
                self.object.name, self.object.version
            ))),
        }
    }
}

fn registry_package_toml(
    record: &SparseRecord,
    license: &str,
    archive_bytes: u64,
    tree: &Tree,
    retained_archive: bool,
    retained_source: bool,
) -> Vec<u8> {
    let mut output = String::from("format-version = 1\nname = ");
    write_toml_string(&mut output, &record.name);
    output.push_str("\nversion = ");
    write_toml_string(&mut output, &record.version.to_string());
    output.push_str("\nsource = ");
    write_toml_string(&mut output, CRATES_IO_SOURCE);
    output.push_str("\nchecksum = ");
    write_toml_string(&mut output, &hex(&record.checksum));
    output.push_str("\nlicense = ");
    write_toml_string(&mut output, license);
    writeln!(
        output,
        "\narchive-bytes = {archive_bytes}\nextracted-bytes = {}\nfile-count = {}\n\
         directory-count = {}\nsource-tree-sha256 = \"{}\"\nretained-archive = \
         {retained_archive}\nretained-source = {retained_source}",
        tree.total_bytes,
        tree.file_count,
        tree.directory_count,
        hex(&tree.sha256),
    )
    .unwrap();
    output.into_bytes()
}

fn copy_new(source: &Path, destination: &Path) -> Result<()> {
    let mut source_file = File::open(source).map_err(|error| {
        Error::failure(format!("failed to open `{}`: {error}", source.display()))
    })?;
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| {
            Error::failure(format!(
                "failed to create `{}`: {error}",
                destination.display()
            ))
        })?;
    std::io::copy(&mut source_file, &mut destination_file)
        .and_then(|_| destination_file.sync_all())
        .map_err(|error| {
            Error::failure(format!(
                "failed to persist `{}`: {error}",
                destination.display()
            ))
        })
}

fn initialize_repository(root: &Path) -> Result<()> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(Error::failure(format!(
                "writable repository `{}` is not a real directory",
                root.display()
            )));
        }
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(Error::failure(format!(
                "failed to inspect writable repository `{}`: {error}",
                root.display()
            )));
        }
    }
    let parent = root.parent().ok_or_else(|| {
        Error::failure(format!(
            "writable repository `{}` has no parent",
            root.display()
        ))
    })?;
    require_real_directory(parent, "writable repository parent")?;
    let label = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("repository");
    let staging = AtomicDirectory::new(parent, label)?;
    write_new(
        &staging.path().join("repository.toml"),
        b"format-version = 1\nobject-hash = \"sha256\"\n",
    )?;
    let sync_file = open_repository_sync_file(staging.path())?;
    for relative in [
        "objects",
        "objects/crates-io",
        "objects/crates-io/sha256",
        "objects/seeded-git",
        "objects/seeded-git/sha256",
        ".staging",
    ] {
        fs::create_dir(staging.path().join(relative)).map_err(|error| {
            Error::failure(format!(
                "failed to create repository directory `{relative}`: {error}"
            ))
        })?;
    }
    persist_repository_tree(staging.path(), &sync_file)?;
    if !staging.commit_no_replace(root)? {
        verify_repository_header(root)?;
    }
    sync_directory(parent, &sync_file)?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            Error::failure(format!("failed to create `{}`: {error}", path.display()))
        })?;
    std::io::Write::write_all(&mut file, bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| Error::failure(format!("failed to persist `{}`: {error}", path.display())))
}

fn persist_repository_tree(root: &Path, sync_file: &File) -> Result<()> {
    for relative in [
        "objects/crates-io/sha256",
        "objects/crates-io",
        "objects/seeded-git/sha256",
        "objects/seeded-git",
        "objects",
        ".staging",
        "",
    ] {
        sync_directory(&root.join(relative), sync_file)?;
    }
    Ok(())
}

fn persist_object_tree(root: &Path, sync_file: &File) -> Result<()> {
    require_real_directory(root, "staged repository object")?;
    for entry in fs::read_dir(root).map_err(|error| {
        Error::failure(format!(
            "failed to read staged repository object `{}`: {error}",
            root.display()
        ))
    })? {
        let path = entry
            .map_err(|error| {
                Error::failure(format!(
                    "failed to read staged repository object `{}`: {error}",
                    root.display()
                ))
            })?
            .path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            Error::failure(format!(
                "failed to inspect staged repository entry `{}`: {error}",
                path.display()
            ))
        })?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            persist_object_tree(&path, sync_file)?;
        } else if metadata.is_file() && !metadata.file_type().is_symlink() {
            File::open(&path)
                .and_then(|file| file.sync_all())
                .map_err(|error| {
                    Error::failure(format!(
                        "failed to persist staged repository entry `{}`: {error}",
                        path.display()
                    ))
                })?;
        } else {
            return Err(Error::failure(format!(
                "staged repository entry `{}` is not a real file or directory",
                path.display()
            )));
        }
    }
    sync_directory(root, sync_file)
}

fn ensure_object_prefix(path: &Path, sync_file: &File) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => sync_directory(path.parent().unwrap(), sync_file)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(Error::failure(format!(
                "failed to create repository object prefix `{}`: {error}",
                path.display()
            )));
        }
    }
    require_real_directory(path, "repository object prefix")
}

fn verify_matching_object(
    writer: &RepositoryWriter,
    staged: &StagedRegistryObject,
    destination: &Path,
) -> Result<RegistryObject> {
    let object = verify_registry_object(
        writer.layer,
        destination,
        staged.object.checksum,
        writer.limits,
        writer.archive_limits.max_compressed_bytes,
        true,
    )?;
    let mut expected = staged.object.clone();
    expected.root = destination.to_owned();
    if object != expected {
        return Err(Error::failure(format!(
            "repository object `{}` differs from the verified staged object",
            destination.display()
        ))
        .with_help(
            "fix or replace the corrupt object; Lorry never overwrites repository objects",
        ));
    }
    Ok(object)
}

fn open_repository_sync_file(root: &Path) -> Result<File> {
    let path = root.join("repository.toml");
    File::open(&path).map_err(|error| {
        Error::failure(format!(
            "failed to open repository durability handle `{}`: {error}",
            path.display()
        ))
    })
}

#[cfg(not(target_os = "motor"))]
fn sync_directory(path: &Path, _sync_file: &File) -> Result<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            Error::failure(format!(
                "failed to persist repository directory `{}`: {error}",
                path.display()
            ))
        })
}

#[cfg(target_os = "motor")]
fn sync_directory(path: &Path, sync_file: &File) -> Result<()> {
    use std::os::fd::AsRawFd;

    require_real_directory(path, "repository durability directory")?;
    moto_rt::fs::flush(sync_file.as_raw_fd()).map_err(|error| {
        Error::failure(format!(
            "failed to persist repository directory `{}`: {error}",
            path.display()
        ))
    })
}

fn shadow_error(repository: &Repository, object_path: &Path, error: Error) -> Error {
    Error::failure(format!(
        "corrupt object in {} repository `{}`; refusing to fall through to a lower layer: {error}",
        repository.layer.name(),
        object_path.display()
    ))
}

fn verify_repository_header(root: &Path) -> Result<()> {
    let path = root.join("repository.toml");
    require_real_file(&path, "repository header")?;
    let document = Document::load(&path, "Lorry repository header")?;
    reject_unknown_keys(
        &path,
        &document,
        document.root(),
        &["format-version", "object-hash"],
    )?;
    require_exact_keys(&path, document.root(), &["format-version", "object-hash"])?;
    let version = require_u64(&path, &document, document.root(), "format-version")?;
    if version != 1 {
        return Err(field_error(
            &path,
            &document,
            document.root().get("format-version").unwrap(),
            format!("unsupported repository format version {version}"),
        ));
    }
    let hash = require_string(&path, &document, document.root(), "object-hash")?;
    if hash != "sha256" {
        return Err(field_error(
            &path,
            &document,
            document.root().get("object-hash").unwrap(),
            format!("unsupported repository object hash `{hash}`"),
        ));
    }
    Ok(())
}

fn verify_registry_object(
    layer: Layer,
    object_path: &Path,
    expected_checksum: [u8; 32],
    limits: Limits,
    max_archive_bytes: u64,
    strict: bool,
) -> Result<RegistryObject> {
    require_real_directory(object_path, "crates.io object")?;
    let package_path = object_path.join("package.toml");
    require_real_file(&package_path, "crates.io package metadata")?;
    let document = Document::load(&package_path, "crates.io repository package metadata")?;
    const KEYS: &[&str] = &[
        "format-version",
        "name",
        "version",
        "source",
        "checksum",
        "license",
        "archive-bytes",
        "extracted-bytes",
        "file-count",
        "directory-count",
        "source-tree-sha256",
        "retained-archive",
        "retained-source",
    ];
    reject_unknown_keys(&package_path, &document, document.root(), KEYS)?;
    require_exact_keys(&package_path, document.root(), KEYS)?;
    require_format_one(&package_path, &document)?;

    let name = require_nonempty_string(&package_path, &document, document.root(), "name")?;
    validate_package_name(&package_path, &name)?;
    let version = parse_version(&package_path, &document, document.root(), "version")?;
    let source = require_string(&package_path, &document, document.root(), "source")?;
    if source != CRATES_IO_SOURCE {
        return Err(Error::failure(format!(
            "`{}` has unsupported crates.io source `{source}`",
            package_path.display()
        )));
    }
    let checksum = require_digest(&package_path, &document, document.root(), "checksum")?;
    if checksum != expected_checksum {
        return Err(Error::failure(format!(
            "`{}` checksum does not match its object address",
            package_path.display()
        )));
    }
    let license = require_nonempty_string(&package_path, &document, document.root(), "license")?;
    let archive_bytes = require_u64(&package_path, &document, document.root(), "archive-bytes")?;
    let extracted_bytes =
        require_u64(&package_path, &document, document.root(), "extracted-bytes")?;
    let file_count = require_u64(&package_path, &document, document.root(), "file-count")?;
    let directory_count =
        require_u64(&package_path, &document, document.root(), "directory-count")?;
    let source_tree_sha256 = require_digest(
        &package_path,
        &document,
        document.root(),
        "source-tree-sha256",
    )?;
    let retained_archive = require_bool(
        &package_path,
        &document,
        document.root(),
        "retained-archive",
    )?;
    let retained_source =
        require_bool(&package_path, &document, document.root(), "retained-source")?;
    if !retained_archive && !retained_source {
        return Err(Error::failure(format!(
            "`{}` retains neither archive nor source",
            package_path.display()
        )));
    }
    if archive_bytes > max_archive_bytes {
        return Err(Error::failure(format!(
            "`{}` archive size exceeds the configured limit of {max_archive_bytes}",
            package_path.display()
        )));
    }
    validate_recorded_tree_limits(
        &package_path,
        limits,
        extracted_bytes,
        file_count,
        directory_count,
    )?;

    let mut expected_entries = BTreeSet::from(["index-record.json", "package.toml"]);
    if retained_archive {
        expected_entries.insert("package.crate");
    }
    if retained_source {
        expected_entries.insert("source");
        expected_entries.insert("source-manifest.json");
    }
    verify_exact_entries(object_path, &expected_entries)?;

    let index = verify_index_record(
        &object_path.join("index-record.json"),
        &name,
        &version,
        checksum,
    )?;
    if strict && retained_archive {
        let archive_path = object_path.join("package.crate");
        let (actual_bytes, actual_checksum) = hash_bounded_file(&archive_path, max_archive_bytes)?;
        if actual_bytes != archive_bytes || actual_checksum != checksum {
            return Err(Error::failure(format!(
                "retained archive `{}` does not match package metadata",
                archive_path.display()
            )));
        }
    }
    let source_tree = if strict && retained_source {
        Some(verify_retained_tree(
            object_path,
            limits,
            source_tree_sha256,
            extracted_bytes,
            file_count,
            directory_count,
        )?)
    } else {
        None
    };

    Ok(RegistryObject {
        layer,
        root: object_path.to_owned(),
        name,
        version,
        checksum,
        license,
        archive_bytes,
        extracted_bytes,
        file_count,
        directory_count,
        source_tree_sha256,
        retained_archive,
        retained_source,
        source_tree,
        index,
    })
}

fn verify_seeded_git_object(
    layer: Layer,
    object_path: &Path,
    expected_digest: [u8; 32],
    limits: Limits,
    strict: bool,
) -> Result<SeededGitObject> {
    require_real_directory(object_path, "seeded-Git object")?;
    let expected_entries = BTreeSet::from(["package.toml", "source", "source-manifest.json"]);
    verify_exact_entries(object_path, &expected_entries)?;

    let package_path = object_path.join("package.toml");
    require_real_file(&package_path, "seeded-Git package metadata")?;
    let document = Document::load(&package_path, "seeded-Git repository package metadata")?;
    const KEYS: &[&str] = &[
        "format-version",
        "name",
        "version",
        "cargo-source",
        "git-url",
        "requested-revision",
        "resolved-commit",
        "git-tree",
        "patch-files",
        "upstream-crates-io-checksum",
        "source-tree-sha256",
        "license",
        "extracted-bytes",
        "file-count",
        "directory-count",
        "retained-source",
    ];
    reject_unknown_keys(&package_path, &document, document.root(), KEYS)?;
    require_exact_keys(&package_path, document.root(), KEYS)?;
    require_format_one(&package_path, &document)?;

    let name = require_nonempty_string(&package_path, &document, document.root(), "name")?;
    validate_package_name(&package_path, &name)?;
    let version = parse_version(&package_path, &document, document.root(), "version")?;
    let cargo_source =
        require_nonempty_string(&package_path, &document, document.root(), "cargo-source")?;
    let git_url = require_nonempty_string(&package_path, &document, document.root(), "git-url")?;
    let requested_revision = require_nonempty_string(
        &package_path,
        &document,
        document.root(),
        "requested-revision",
    )?;
    let resolved_commit = require_hex_string(&package_path, &document, "resolved-commit", 40)?;
    let git_tree = require_hex_string(&package_path, &document, "git-tree", 40)?;
    let patch_files =
        require_string_array(&package_path, &document, document.root(), "patch-files")?;
    if patch_files.is_empty()
        || patch_files.iter().any(|path| {
            path.is_empty()
                || path.len() > 4096
                || path.starts_with('/')
                || path.contains('\\')
                || path
                    .split('/')
                    .any(|component| component.is_empty() || component == "." || component == "..")
        })
        || patch_files.iter().collect::<BTreeSet<_>>().len() != patch_files.len()
    {
        return Err(Error::failure(format!(
            "`{}` has invalid or duplicate Git patch paths",
            package_path.display()
        )));
    }
    let upstream_crates_io_checksum = require_digest(
        &package_path,
        &document,
        document.root(),
        "upstream-crates-io-checksum",
    )?;
    let source_tree_sha256 = require_digest(
        &package_path,
        &document,
        document.root(),
        "source-tree-sha256",
    )?;
    if source_tree_sha256 != expected_digest {
        return Err(Error::failure(format!(
            "`{}` source-tree digest does not match its object address",
            package_path.display()
        )));
    }
    let license = require_nonempty_string(&package_path, &document, document.root(), "license")?;
    let extracted_bytes =
        require_u64(&package_path, &document, document.root(), "extracted-bytes")?;
    let file_count = require_u64(&package_path, &document, document.root(), "file-count")?;
    let directory_count =
        require_u64(&package_path, &document, document.root(), "directory-count")?;
    let retained_source =
        require_bool(&package_path, &document, document.root(), "retained-source")?;
    if !retained_source {
        return Err(Error::failure(format!(
            "`{}` must retain its seeded-Git source",
            package_path.display()
        )));
    }
    if !git_url.starts_with("https://") || git_url.contains('#') || git_url.contains('?') {
        return Err(Error::failure(format!(
            "`{}` has a non-canonical seeded-Git URL",
            package_path.display()
        )));
    }
    let expected_cargo_source =
        format!("git+{git_url}?branch={requested_revision}#{resolved_commit}");
    if cargo_source != expected_cargo_source {
        return Err(Error::failure(format!(
            "`{}` cargo-source does not match its pinned Git provenance",
            package_path.display()
        )));
    }
    validate_recorded_tree_limits(
        &package_path,
        limits,
        extracted_bytes,
        file_count,
        directory_count,
    )?;
    if strict {
        verify_retained_tree(
            object_path,
            limits,
            source_tree_sha256,
            extracted_bytes,
            file_count,
            directory_count,
        )?;
    }

    Ok(SeededGitObject {
        layer,
        root: object_path.to_owned(),
        name,
        version,
        cargo_source,
        git_url,
        requested_revision,
        resolved_commit,
        git_tree,
        patch_files,
        upstream_crates_io_checksum,
        source_tree_sha256,
        license,
        extracted_bytes,
        file_count,
        directory_count,
    })
}

fn verify_retained_tree(
    object_path: &Path,
    limits: Limits,
    expected_digest: [u8; 32],
    expected_bytes: u64,
    expected_files: u64,
    expected_directories: u64,
) -> Result<Tree> {
    let tree = Tree::scan(&object_path.join("source"), limits, Exclusions::None)?;
    if tree.sha256 != expected_digest
        || tree.total_bytes != expected_bytes
        || tree.file_count as u64 != expected_files
        || tree.directory_count as u64 != expected_directories
    {
        return Err(Error::failure(format!(
            "retained source tree `{}` does not match package metadata",
            object_path.join("source").display()
        )));
    }
    let manifest_path = object_path.join("source-manifest.json");
    let bytes = read_bounded_file(&manifest_path, MANIFEST_LIMIT as u64)?;
    let value = Value::parse(&manifest_path, "source manifest", &bytes)?;
    if value.canonical_bytes() != bytes || tree.manifest_bytes() != bytes {
        return Err(Error::failure(format!(
            "source manifest `{}` is non-canonical or does not match the retained tree",
            manifest_path.display()
        )));
    }
    Ok(tree)
}

fn verify_index_record(
    path: &Path,
    expected_name: &str,
    expected_version: &Version,
    expected_checksum: [u8; 32],
) -> Result<SparseRecord> {
    let bytes = read_bounded_file(path, INDEX_RECORD_LIMIT as u64)?;
    let record = SparseRecord::parse(path, &bytes)?;
    if record.name != expected_name
        || record.version != *expected_version
        || record.checksum != expected_checksum
    {
        return Err(Error::failure(format!(
            "sparse index record `{}` does not match package metadata",
            path.display()
        )));
    }
    Ok(record)
}

fn validate_recorded_tree_limits(
    path: &Path,
    limits: Limits,
    bytes: u64,
    files: u64,
    directories: u64,
) -> Result<()> {
    let entries = files
        .checked_add(directories)
        .ok_or_else(|| Error::failure(format!("`{}` entry count overflowed", path.display())))?;
    if bytes > limits.max_tree_bytes
        || files > limits.max_entries as u64
        || entries > limits.max_entries as u64
    {
        return Err(Error::failure(format!(
            "`{}` recorded source tree exceeds configured limits",
            path.display()
        )));
    }
    Ok(())
}

fn verify_exact_entries(root: &Path, expected: &BTreeSet<&str>) -> Result<()> {
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(root).map_err(|error| {
        Error::failure(format!(
            "failed to read repository object `{}`: {error}",
            root.display()
        ))
    })? {
        let entry = entry.map_err(|error| {
            Error::failure(format!(
                "failed to read an entry in repository object `{}`: {error}",
                root.display()
            ))
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            Error::failure(format!(
                "repository object `{}` contains a non-UTF-8 entry",
                root.display()
            ))
        })?;
        actual.insert(name);
    }
    let expected_owned = expected.iter().map(|name| (*name).to_owned()).collect();
    if actual != expected_owned {
        return Err(Error::failure(format!(
            "repository object `{}` entries differ: expected {:?}, got {:?}",
            root.display(),
            expected,
            actual
        )));
    }
    Ok(())
}

fn require_real_directory(path: &Path, context: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Error::failure(format!(
            "failed to inspect {context} `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::failure(format!(
            "{context} `{}` is not a real directory",
            path.display()
        )));
    }
    Ok(())
}

fn require_real_file(path: &Path, context: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Error::failure(format!(
            "failed to inspect {context} `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::failure(format!(
            "{context} `{}` is not a real regular file",
            path.display()
        )));
    }
    Ok(())
}

fn entry_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::failure(format!(
            "failed to inspect repository object `{}`: {error}",
            path.display()
        ))),
    }
}

fn hash_bounded_file(path: &Path, limit: u64) -> Result<(u64, [u8; 32])> {
    let bytes = read_bounded_file(path, limit)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok((bytes.len() as u64, hasher.finish()))
}

fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path).map_err(|error| {
        Error::failure(format!("failed to inspect `{}`: {error}", path.display()))
    })?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(Error::failure(format!(
            "`{}` is not a real regular file",
            path.display()
        )));
    }
    if before.len() > limit {
        return Err(Error::failure(format!(
            "`{}` exceeds the byte limit of {limit}",
            path.display()
        )));
    }
    let before_identity = path_file_identity(path, &before)?;
    let before_modified = file_modified(path, &before)?;
    let mut file = File::open(path)
        .map_err(|error| Error::failure(format!("failed to open `{}`: {error}", path.display())))?;
    let opened = file.metadata().map_err(|error| {
        Error::failure(format!(
            "failed to inspect open file `{}`: {error}",
            path.display()
        ))
    })?;
    if !same_file_metadata(
        &before,
        before_modified,
        &opened,
        file_modified(path, &opened)?,
    ) || before_identity != open_file_identity(&file, &opened)?
    {
        return Err(Error::failure(format!(
            "`{}` changed while being opened",
            path.display()
        )));
    }
    let capacity = usize::try_from(before.len()).unwrap_or(usize::MAX);
    let mut bytes = Vec::with_capacity(capacity.min(1024 * 1024));
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| Error::failure(format!("failed to read `{}`: {error}", path.display())))?;
    if bytes.len() as u64 > limit {
        return Err(Error::failure(format!(
            "`{}` exceeds the byte limit of {limit}",
            path.display()
        )));
    }
    let after = file.metadata().map_err(|error| {
        Error::failure(format!("failed to recheck `{}`: {error}", path.display()))
    })?;
    let path_after = fs::symlink_metadata(path).map_err(|error| {
        Error::failure(format!("failed to recheck `{}`: {error}", path.display()))
    })?;
    if !same_file_metadata(
        &before,
        before_modified,
        &after,
        file_modified(path, &after)?,
    ) || !same_file_metadata(
        &before,
        before_modified,
        &path_after,
        file_modified(path, &path_after)?,
    ) || before_identity != open_file_identity(&file, &after)?
        || before_identity != path_file_identity(path, &path_after)?
        || bytes.len() as u64 != before.len()
    {
        return Err(Error::failure(format!(
            "`{}` changed while being read",
            path.display()
        )));
    }
    Ok(bytes)
}

fn same_file_metadata(
    left: &Metadata,
    left_modified: std::time::SystemTime,
    right: &Metadata,
    right_modified: std::time::SystemTime,
) -> bool {
    left.is_file()
        && right.is_file()
        && left.len() == right.len()
        && left_modified == right_modified
}

fn file_modified(path: &Path, metadata: &Metadata) -> Result<std::time::SystemTime> {
    metadata.modified().map_err(|error| {
        Error::failure(format!(
            "failed to read modification time for `{}`: {error}",
            path.display()
        ))
    })
}

#[cfg(unix)]
fn path_file_identity(_path: &Path, metadata: &Metadata) -> Result<(u128, u128)> {
    use std::os::unix::fs::MetadataExt;
    Ok((metadata.dev() as u128, metadata.ino() as u128))
}

#[cfg(target_os = "motor")]
fn path_file_identity(path: &Path, _metadata: &Metadata) -> Result<(u128, u128)> {
    let path = path.to_str().ok_or_else(|| {
        Error::failure(format!(
            "repository path is not UTF-8: `{}`",
            path.display()
        ))
    })?;
    let attr = moto_rt::fs::stat(path).map_err(|error| {
        Error::failure(format!(
            "failed to inspect Motor file identity `{path}`: {error}"
        ))
    })?;
    Ok((0, attr.entry_id))
}

#[cfg(not(any(unix, target_os = "motor")))]
fn path_file_identity(path: &Path, _metadata: &Metadata) -> Result<(u128, u128)> {
    Err(Error::failure(format!(
        "repository file identity is unsupported on this platform: `{}`",
        path.display()
    )))
}

#[cfg(unix)]
fn open_file_identity(_file: &File, metadata: &Metadata) -> Result<(u128, u128)> {
    path_file_identity(Path::new(""), metadata)
}

#[cfg(target_os = "motor")]
fn open_file_identity(file: &File, _metadata: &Metadata) -> Result<(u128, u128)> {
    use std::os::fd::AsRawFd;
    let attr = moto_rt::fs::get_file_attr(file.as_raw_fd()).map_err(|error| {
        Error::failure(format!(
            "failed to inspect open Motor file identity: {error}"
        ))
    })?;
    Ok((0, attr.entry_id))
}

#[cfg(not(any(unix, target_os = "motor")))]
fn open_file_identity(_file: &File, _metadata: &Metadata) -> Result<(u128, u128)> {
    Err(Error::failure(
        "repository file identity is unsupported on this platform",
    ))
}

fn require_format_one(path: &Path, document: &Document) -> Result<()> {
    let version = require_u64(path, document, document.root(), "format-version")?;
    if version != 1 {
        return Err(Error::failure(format!(
            "`{}` has unsupported package format version {version}",
            path.display()
        )));
    }
    Ok(())
}

fn reject_unknown_keys(
    path: &Path,
    document: &Document,
    table: &Table,
    allowed: &[&str],
) -> Result<()> {
    for (key, item) in table.iter() {
        if !allowed.contains(&key) {
            return Err(field_error(
                path,
                document,
                item,
                format!("unknown repository metadata key `{key}`"),
            ));
        }
    }
    Ok(())
}

fn require_exact_keys(path: &Path, table: &Table, required: &[&str]) -> Result<()> {
    for key in required {
        if !table.contains_key(key) {
            return Err(Error::failure(format!(
                "`{}` is missing required repository metadata key `{key}`",
                path.display()
            )));
        }
    }
    Ok(())
}

fn require_item<'a>(path: &Path, table: &'a Table, key: &str) -> Result<&'a Item> {
    table.get(key).ok_or_else(|| {
        Error::failure(format!(
            "`{}` is missing required repository metadata key `{key}`",
            path.display()
        ))
    })
}

fn require_string(path: &Path, document: &Document, table: &Table, key: &str) -> Result<String> {
    let item = require_item(path, table, key)?;
    item.as_str().map(str::to_owned).ok_or_else(|| {
        field_error(
            path,
            document,
            item,
            format!("repository metadata `{key}` must be a string"),
        )
    })
}

fn require_nonempty_string(
    path: &Path,
    document: &Document,
    table: &Table,
    key: &str,
) -> Result<String> {
    let value = require_string(path, document, table, key)?;
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(Error::failure(format!(
            "`{}` repository metadata `{key}` is empty or invalid",
            path.display()
        )));
    }
    Ok(value)
}

fn require_u64(path: &Path, document: &Document, table: &Table, key: &str) -> Result<u64> {
    let item = require_item(path, table, key)?;
    let value = item.as_integer().ok_or_else(|| {
        field_error(
            path,
            document,
            item,
            format!("repository metadata `{key}` must be a nonnegative integer"),
        )
    })?;
    u64::try_from(value).map_err(|_| {
        field_error(
            path,
            document,
            item,
            format!("repository metadata `{key}` must be a nonnegative integer"),
        )
    })
}

fn require_bool(path: &Path, document: &Document, table: &Table, key: &str) -> Result<bool> {
    let item = require_item(path, table, key)?;
    item.as_bool().ok_or_else(|| {
        field_error(
            path,
            document,
            item,
            format!("repository metadata `{key}` must be true or false"),
        )
    })
}

fn require_string_array(
    path: &Path,
    document: &Document,
    table: &Table,
    key: &str,
) -> Result<Vec<String>> {
    let item = require_item(path, table, key)?;
    let array = item.as_array().ok_or_else(|| {
        field_error(
            path,
            document,
            item,
            format!("repository metadata `{key}` must be an array of strings"),
        )
    })?;
    array
        .iter()
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                field_error(
                    path,
                    document,
                    item,
                    format!("repository metadata `{key}` must contain only strings"),
                )
            })
        })
        .collect()
}

fn require_digest(path: &Path, document: &Document, table: &Table, key: &str) -> Result<[u8; 32]> {
    let item = require_item(path, table, key)?;
    let value = item.as_str().ok_or_else(|| {
        field_error(
            path,
            document,
            item,
            format!("repository metadata `{key}` must be a SHA-256 string"),
        )
    })?;
    decode_hex(value).map_err(|error| {
        field_error(
            path,
            document,
            item,
            format!("invalid repository metadata `{key}`: {error}"),
        )
    })
}

fn require_hex_string(
    path: &Path,
    document: &Document,
    key: &str,
    digits: usize,
) -> Result<String> {
    let item = require_item(path, document.root(), key)?;
    let value = item.as_str().ok_or_else(|| {
        field_error(
            path,
            document,
            item,
            format!("repository metadata `{key}` must be hexadecimal"),
        )
    })?;
    if value.len() != digits
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(field_error(
            path,
            document,
            item,
            format!("repository metadata `{key}` must be {digits} lowercase hexadecimal digits"),
        ));
    }
    Ok(value.to_owned())
}

fn parse_version(path: &Path, document: &Document, table: &Table, key: &str) -> Result<Version> {
    let item = require_item(path, table, key)?;
    let value = item.as_str().ok_or_else(|| {
        field_error(
            path,
            document,
            item,
            format!("repository metadata `{key}` must be a semantic version"),
        )
    })?;
    Version::parse(value).map_err(|error| {
        field_error(
            path,
            document,
            item,
            format!("invalid repository package version `{value}`: {error}"),
        )
    })
}

fn validate_package_name(path: &Path, name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Error::failure(format!(
            "`{}` contains invalid package name `{name}`",
            path.display()
        )));
    }
    Ok(())
}

fn field_error(
    path: &Path,
    document: &Document,
    item: &Item,
    message: impl std::fmt::Display,
) -> Error {
    Error::at(
        path,
        document.line_of_item(item),
        message,
        "fix or replace the corrupt repository object; Lorry never repairs it in place",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "lorry-repository-{name}-{}-{id}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn repository(path: &Path) {
        fs::create_dir_all(path).unwrap();
        fs::write(
            path.join("repository.toml"),
            "format-version = 1\nobject-hash = \"sha256\"\n",
        )
        .unwrap();
    }

    fn registry_object(repository: &Path, archive: &[u8]) -> (String, PathBuf) {
        let mut archive_hash = Sha256::new();
        archive_hash.update(archive);
        let checksum = hex(&archive_hash.finish());
        let object = repository
            .join("objects/crates-io/sha256")
            .join(&checksum[..2])
            .join(&checksum);
        fs::create_dir_all(object.join("source/src")).unwrap();
        fs::write(object.join("package.crate"), archive).unwrap();
        fs::write(
            object.join("source/Cargo.toml"),
            "[package]\nname=\"demo\"\nversion=\"1.2.3\"\n",
        )
        .unwrap();
        fs::write(object.join("source/src/lib.rs"), b"pub fn demo() {}\n").unwrap();
        let tree = Tree::scan(
            &object.join("source"),
            crate::source_tree::DEFAULT_LIMITS,
            Exclusions::None,
        )
        .unwrap();
        fs::write(object.join("source-manifest.json"), tree.manifest_bytes()).unwrap();
        fs::write(
            object.join("index-record.json"),
            format!(
                "{{\"name\":\"demo\",\"vers\":\"1.2.3\",\"deps\":[],\"cksum\":\"{checksum}\",\"features\":{{}},\"yanked\":false}}\n"
            ),
        )
        .unwrap();
        fs::write(
            object.join("package.toml"),
            format!(
                "format-version = 1\n\
                 name = \"demo\"\n\
                 version = \"1.2.3\"\n\
                 source = \"{CRATES_IO_SOURCE}\"\n\
                 checksum = \"{checksum}\"\n\
                 license = \"MIT\"\n\
                 archive-bytes = {}\n\
                 extracted-bytes = {}\n\
                 file-count = {}\n\
                 directory-count = {}\n\
                 source-tree-sha256 = \"{}\"\n\
                 retained-archive = true\n\
                 retained-source = true\n",
                archive.len(),
                tree.total_bytes,
                tree.file_count,
                tree.directory_count,
                hex(&tree.sha256),
            ),
        )
        .unwrap();
        (checksum, object)
    }

    fn seeded_git_object(repository: &Path) -> (String, PathBuf) {
        let staging = repository.join("seed-source");
        fs::create_dir_all(&staging).unwrap();
        fs::write(
            staging.join("Cargo.toml"),
            "[package]\nname=\"ring\"\nversion=\"0.17.14\"\n",
        )
        .unwrap();
        let tree = Tree::scan(
            &staging,
            crate::source_tree::DEFAULT_LIMITS,
            Exclusions::None,
        )
        .unwrap();
        let digest = hex(&tree.sha256);
        let object = repository
            .join("objects/seeded-git/sha256")
            .join(&digest[..2])
            .join(&digest);
        fs::create_dir_all(object.parent().unwrap()).unwrap();
        fs::rename(&staging, object.join("source")).unwrap_or_else(|_| {
            fs::create_dir_all(&object).unwrap();
            fs::rename(&staging, object.join("source")).unwrap();
        });
        fs::create_dir_all(&object).unwrap();
        fs::write(object.join("source-manifest.json"), tree.manifest_bytes()).unwrap();
        let commit = "1111111111111111111111111111111111111111";
        let git_tree = "2222222222222222222222222222222222222222";
        let upstream = "3333333333333333333333333333333333333333333333333333333333333333";
        fs::write(
            object.join("package.toml"),
            format!(
                "format-version = 1\n\
                 name = \"ring\"\n\
                 version = \"0.17.14\"\n\
                 cargo-source = \"git+https://github.com/moturus/ring.git?branch=motor-os-0.17.14#{commit}\"\n\
                 git-url = \"https://github.com/moturus/ring.git\"\n\
                 requested-revision = \"motor-os-0.17.14\"\n\
                 resolved-commit = \"{commit}\"\n\
                 git-tree = \"{git_tree}\"\n\
                 patch-files = [\"build.rs\", \"src/rand.rs\"]\n\
                 upstream-crates-io-checksum = \"{upstream}\"\n\
                 source-tree-sha256 = \"{digest}\"\n\
                 license = \"Apache-2.0 AND ISC\"\n\
                 extracted-bytes = {}\n\
                 file-count = {}\n\
                 directory-count = {}\n\
                 retained-source = true\n",
                tree.total_bytes, tree.file_count, tree.directory_count,
            ),
        )
        .unwrap();
        (digest, object)
    }

    fn configurations(local: Option<&Path>, system: Option<&Path>) -> Repositories {
        Repositories {
            system: system.map(Path::to_owned),
            user: None,
            local: local.map(Path::to_owned),
            keep_artifacts: true,
            keep_sources: true,
        }
    }

    fn archive_limits() -> ArchiveLimits {
        ArchiveLimits {
            max_compressed_bytes: 1024,
            max_expanded_bytes: 4096,
            max_files: 32,
            max_path_bytes: 256,
            max_file_bytes: 1024,
        }
    }

    fn crate_archive(name: &str, version: &str) -> Vec<u8> {
        fn put_octal(field: &mut [u8], value: u64) {
            let text = format!("{value:0width$o}", width = field.len() - 1);
            field[..text.len()].copy_from_slice(text.as_bytes());
        }
        fn append_file(tar: &mut Vec<u8>, path: &str, contents: &[u8]) {
            let mut header = [0_u8; 512];
            header[..path.len()].copy_from_slice(path.as_bytes());
            put_octal(&mut header[100..108], 0o644);
            put_octal(&mut header[108..116], 0);
            put_octal(&mut header[116..124], 0);
            put_octal(&mut header[124..136], contents.len() as u64);
            put_octal(&mut header[136..148], 0);
            header[148..156].fill(b' ');
            header[156] = b'0';
            header[257..263].copy_from_slice(b"ustar\0");
            header[263..265].copy_from_slice(b"00");
            let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
            header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
            tar.extend_from_slice(&header);
            tar.extend_from_slice(contents);
            tar.resize(tar.len().div_ceil(512) * 512, 0);
        }

        let root = format!("{name}-{version}");
        let mut tar = Vec::new();
        append_file(
            &mut tar,
            &format!("{root}/Cargo.toml"),
            format!(
                "[package]\nname = \"{name}\"\nversion = \"{version}\"\n\
                 edition = \"2021\"\nlicense = \"MIT OR Apache-2.0\"\n"
            )
            .as_bytes(),
        );
        append_file(
            &mut tar,
            &format!("{root}/src/lib.rs"),
            b"pub fn fixture() {}\n",
        );
        tar.resize(tar.len() + 1024, 0);
        let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
        gzip.write_all(&tar).unwrap();
        gzip.finish().unwrap()
    }

    fn stage_package(transaction: &mut RepositoryTransaction, name: &str, version: &str) -> String {
        let archive = transaction.path().join(format!("{name}-{version}.crate"));
        let bytes = crate_archive(name, version);
        fs::write(&archive, &bytes).unwrap();
        let mut digest = Sha256::new();
        digest.update(&bytes);
        let checksum = hex(&digest.finish());
        let record_bytes = format!(
            "{{\"name\":\"{name}\",\"vers\":\"{version}\",\"deps\":[],\
             \"cksum\":\"{checksum}\",\"features\":{{}},\"yanked\":false}}\n"
        );
        let record = SparseRecord::parse(
            Path::new("/fixture/index-record.json"),
            record_bytes.as_bytes(),
        )
        .unwrap();
        transaction.stage_registry(&record, &archive).unwrap();
        checksum
    }

    fn stage_demo(repositories: &Repositories) -> (RepositoryTransaction, String) {
        let writer = RepositoryWriter::open(
            repositories,
            crate::source_tree::DEFAULT_LIMITS,
            archive_limits(),
        )
        .unwrap();
        let mut transaction = writer.begin().unwrap();
        let checksum = stage_package(&mut transaction, "demo", "1.2.3");
        (transaction, checksum)
    }

    #[test]
    fn initializes_the_preferred_writable_repository_and_cleans_staging() {
        let root = TempDir::new("writer");
        let local = root.0.join("local");
        let user = root.0.join("user");
        let repositories = Repositories {
            local: Some(local.clone()),
            user: Some(user),
            ..Repositories::default()
        };

        let writer = RepositoryWriter::open(
            &repositories,
            crate::source_tree::DEFAULT_LIMITS,
            archive_limits(),
        )
        .unwrap();
        assert_eq!(writer.root(), local);
        verify_repository_header(&local).unwrap();
        for relative in [
            "objects/crates-io/sha256",
            "objects/seeded-git/sha256",
            ".staging",
        ] {
            assert!(local.join(relative).is_dir());
        }

        let transaction = writer.begin().unwrap();
        assert!(transaction.path().is_dir());
        drop(transaction);
        assert_eq!(fs::read_dir(local.join(".staging")).unwrap().count(), 0);
    }

    #[test]
    fn stages_and_reverifies_a_downloaded_registry_object() {
        let root = TempDir::new("stage-registry");
        let repository = root.0.join("repository");
        let repositories = Repositories {
            local: Some(repository),
            ..Repositories::default()
        };
        let (transaction, _) = stage_demo(&repositories);
        let staged = &transaction.objects()[0];

        assert_eq!(staged.object().name, "demo");
        assert_eq!(staged.manifest().metadata.license, "MIT OR Apache-2.0");
        assert!(staged.manifest().root.is_dir());
        assert!(staged.manifest().path.is_file());
        assert!(staged.object().root.join("source/src/lib.rs").is_file());
        assert_eq!(transaction.objects().len(), 1);
    }

    #[test]
    fn retains_a_private_inspection_tree_without_publishing_sources() {
        let root = TempDir::new("stage-registry-inspection");
        let repository = root.0.join("repository");
        let repositories = Repositories {
            local: Some(repository),
            keep_sources: false,
            ..Repositories::default()
        };
        let (transaction, _) = stage_demo(&repositories);
        let staged = &transaction.objects()[0];
        let inspection_root = staged.manifest().root.clone();

        assert!(inspection_root.is_dir());
        assert!(staged.manifest().path.is_file());
        assert!(!inspection_root.starts_with(&staged.object().root));
        assert!(!staged.object().root.join("source").exists());
        assert!(!staged.object().retained_source);

        drop(transaction);
        assert!(!inspection_root.exists());
    }

    #[test]
    fn publishes_once_and_reuses_an_identical_registry_object() {
        let root = TempDir::new("publish-registry");
        let repository = root.0.join("repository");
        let repositories = Repositories {
            local: Some(repository.clone()),
            ..Repositories::default()
        };
        let (winner, checksum) = stage_demo(&repositories);
        let (competitor, repeated_checksum) = stage_demo(&repositories);
        assert_eq!(repeated_checksum, checksum);

        let published = winner.publish().unwrap();
        assert_eq!(published.len(), 1);
        assert!(published[0].added);
        assert_eq!(
            published[0].object.root,
            repository
                .join("objects/crates-io/sha256")
                .join(&checksum[..2])
                .join(&checksum)
        );
        assert_eq!(
            fs::read_dir(repository.join(".staging")).unwrap().count(),
            1
        );

        let reused = competitor.publish().unwrap();
        assert_eq!(reused.len(), 1);
        assert!(!reused[0].added);
        assert_eq!(reused[0].object, published[0].object);
        assert_eq!(
            fs::read_dir(repository.join(".staging")).unwrap().count(),
            0
        );
    }

    #[test]
    fn prepublication_failure_exposes_none_of_the_staged_objects() {
        let root = TempDir::new("publish-all-or-none");
        let repository = root.0.join("repository");
        let repositories = Repositories {
            local: Some(repository.clone()),
            ..Repositories::default()
        };
        let writer = RepositoryWriter::open(
            &repositories,
            crate::source_tree::DEFAULT_LIMITS,
            archive_limits(),
        )
        .unwrap();
        let mut transaction = writer.begin().unwrap();
        let first = stage_package(&mut transaction, "first", "1.0.0");
        let second = stage_package(&mut transaction, "second", "2.0.0");
        fs::write(
            transaction.objects()[1]
                .object()
                .root
                .join("index-record.json"),
            b"changed after staging\n",
        )
        .unwrap();

        let error = transaction.publish().unwrap_err();
        assert!(
            error.to_string().contains("index-record.json"),
            "unexpected validation error: {error}"
        );
        for checksum in [first, second] {
            assert!(
                !repository
                    .join("objects/crates-io/sha256")
                    .join(&checksum[..2])
                    .join(checksum)
                    .exists()
            );
        }
        assert_eq!(
            fs::read_dir(repository.join(".staging")).unwrap().count(),
            0
        );
    }

    #[test]
    fn interrupted_registry_transaction_child() {
        let Some(repository) = std::env::var_os("LORRY_INTERRUPTED_REPOSITORY") else {
            return;
        };
        let ready = PathBuf::from(std::env::var_os("LORRY_INTERRUPTED_READY").unwrap());
        let repositories = Repositories {
            local: Some(PathBuf::from(repository)),
            ..Repositories::default()
        };
        let (_transaction, checksum) = stage_demo(&repositories);
        fs::write(ready, checksum).unwrap();
        thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn abrupt_interruption_keeps_registry_objects_private() {
        let root = TempDir::new("publish-interrupted");
        let repository = root.0.join("repository");
        let ready = root.0.join("ready");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "repository::tests::interrupted_registry_transaction_child",
                "--nocapture",
            ])
            .env("LORRY_INTERRUPTED_REPOSITORY", &repository)
            .env("LORRY_INTERRUPTED_READY", &ready)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() {
            assert!(
                Instant::now() < deadline,
                "interruption child did not stage"
            );
            thread::sleep(Duration::from_millis(10));
        }
        let checksum = fs::read_to_string(&ready).unwrap();
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());

        assert!(
            !repository
                .join("objects/crates-io/sha256")
                .join(&checksum[..2])
                .join(&checksum)
                .exists()
        );
        assert_eq!(
            fs::read_dir(repository.join(".staging")).unwrap().count(),
            1
        );
    }

    #[test]
    fn refuses_a_different_object_at_the_same_immutable_address() {
        let root = TempDir::new("publish-conflict");
        let repository = root.0.join("repository");
        let repositories = Repositories {
            local: Some(repository.clone()),
            ..Repositories::default()
        };
        let (transaction, _) = stage_demo(&repositories);
        transaction.publish().unwrap();

        let source_only = Repositories {
            keep_artifacts: false,
            ..repositories
        };
        let (transaction, _) = stage_demo(&source_only);
        let staged = transaction.objects()[0].object.root.clone();
        let error = transaction.publish().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("differs from the verified staged object")
        );
        assert!(!staged.exists());
    }

    #[test]
    fn writer_requires_a_configured_writable_layer() {
        let error = RepositoryWriter::open(
            &Repositories::default(),
            crate::source_tree::DEFAULT_LIMITS,
            archive_limits(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("writable Lorry repository"));
    }

    #[test]
    fn verifies_registry_and_seeded_git_objects() {
        let root = TempDir::new("valid");
        repository(&root.0);
        let (checksum, _) = registry_object(&root.0, b"archive");
        let (digest, _) = seeded_git_object(&root.0);
        let set = RepositorySet::open(
            &configurations(Some(&root.0), None),
            crate::source_tree::DEFAULT_LIMITS,
            1024,
        )
        .unwrap();

        let registry = set.lookup_registry(&checksum).unwrap().unwrap();
        assert_eq!(registry.name, "demo");
        assert_eq!(registry.layer, Layer::Local);
        assert_eq!(hex(&registry.checksum), checksum);
        let git = set.lookup_seeded_git(&digest).unwrap().unwrap();
        assert_eq!(git.name, "ring");
        assert_eq!(git.layer, Layer::Local);
    }

    #[test]
    fn trusted_lookup_does_not_rehash_retained_content() {
        let root = TempDir::new("trusted");
        repository(&root.0);
        let (checksum, object) = registry_object(&root.0, b"archive");
        fs::write(object.join("source/src/lib.rs"), b"changed\n").unwrap();
        let repositories = configurations(Some(&root.0), None);

        let trusted = RepositorySet::open_with_validation(
            &repositories,
            crate::source_tree::DEFAULT_LIMITS,
            1024,
            ValidationMode::Trusted,
        )
        .unwrap();
        let object = trusted.lookup_registry(&checksum).unwrap().unwrap();
        assert!(object.source_tree.is_none());

        let strict = RepositorySet::open_with_validation(
            &repositories,
            crate::source_tree::DEFAULT_LIMITS,
            1024,
            ValidationMode::Strict,
        )
        .unwrap();
        assert!(strict.lookup_registry(&checksum).is_err());
    }

    #[test]
    fn absent_layer_falls_through_but_corruption_never_does() {
        let root = TempDir::new("layers");
        let local = root.0.join("local");
        let system = root.0.join("system");
        repository(&local);
        repository(&system);
        let (checksum, _) = registry_object(&system, b"same archive");
        let set = RepositorySet::open(
            &configurations(Some(&local), Some(&system)),
            crate::source_tree::DEFAULT_LIMITS,
            1024,
        )
        .unwrap();
        assert_eq!(
            set.lookup_registry(&checksum).unwrap().unwrap().layer,
            Layer::System
        );

        let (_, corrupt) = registry_object(&local, b"same archive");
        fs::write(corrupt.join("unexpected"), b"shadow").unwrap();
        // The set already verified this content-addressed object, so within
        // one process the cached object keeps serving lookups.
        assert_eq!(
            set.lookup_registry(&checksum).unwrap().unwrap().layer,
            Layer::System
        );
        // A fresh set — as any new process starts with — sees the corrupt
        // local shadow and refuses to fall through to the intact system copy.
        let fresh = RepositorySet::open(
            &configurations(Some(&local), Some(&system)),
            crate::source_tree::DEFAULT_LIMITS,
            1024,
        )
        .unwrap();
        let error = fresh.lookup_registry(&checksum).unwrap_err();
        assert!(error.to_string().contains("local repository"));
        assert!(error.to_string().contains("refusing to fall through"));
    }

    #[test]
    fn retention_flags_define_the_exact_registry_object_shape() {
        let root = TempDir::new("retention");
        repository(&root.0);

        let (source_only_checksum, source_only) = registry_object(&root.0, b"source-only archive");
        fs::remove_file(source_only.join("package.crate")).unwrap();
        replace_metadata(
            &source_only.join("package.toml"),
            "retained-archive = true",
            "retained-archive = false",
        );

        let (archive_only_checksum, archive_only) =
            registry_object(&root.0, b"archive-only archive");
        fs::remove_dir_all(archive_only.join("source")).unwrap();
        fs::remove_file(archive_only.join("source-manifest.json")).unwrap();
        replace_metadata(
            &archive_only.join("package.toml"),
            "retained-source = true",
            "retained-source = false",
        );

        let set = RepositorySet::open(
            &configurations(Some(&root.0), None),
            crate::source_tree::DEFAULT_LIMITS,
            1024,
        )
        .unwrap();
        let source_only = set.lookup_registry(&source_only_checksum).unwrap().unwrap();
        assert!(!source_only.retained_archive);
        assert!(source_only.retained_source);
        let archive_only = set
            .lookup_registry(&archive_only_checksum)
            .unwrap()
            .unwrap();
        assert!(archive_only.retained_archive);
        assert!(!archive_only.retained_source);
    }

    #[test]
    fn rejects_unknown_headers_and_noncanonical_manifests() {
        let root = TempDir::new("corrupt");
        repository(&root.0);
        fs::write(
            root.0.join("repository.toml"),
            "format-version = 1\nobject-hash = \"sha256\"\nextra = true\n",
        )
        .unwrap();
        let error = RepositorySet::open(
            &configurations(Some(&root.0), None),
            crate::source_tree::DEFAULT_LIMITS,
            1024,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown"));

        repository(&root.0);
        let (checksum, object) = registry_object(&root.0, b"archive");
        let manifest = fs::read_to_string(object.join("source-manifest.json")).unwrap();
        fs::write(
            object.join("source-manifest.json"),
            manifest.replace(",", ", "),
        )
        .unwrap();
        let set = RepositorySet::open(
            &configurations(Some(&root.0), None),
            crate::source_tree::DEFAULT_LIMITS,
            1024,
        )
        .unwrap();
        let error = set.lookup_registry(&checksum).unwrap_err();
        assert!(error.to_string().contains("non-canonical"));
    }

    #[test]
    fn verifies_external_seed_when_requested() {
        let Some(root) = std::env::var_os("LORRY_TEST_SEEDED_REPOSITORY") else {
            return;
        };
        let root = PathBuf::from(root);
        let set = RepositorySet::open(
            &configurations(Some(&root), None),
            crate::source_tree::DEFAULT_LIMITS,
            16 * 1024 * 1024,
        )
        .unwrap();

        let registry = object_identities(&root.join("objects/crates-io/sha256"));
        assert_eq!(registry.len(), 45);
        for checksum in registry {
            set.lookup_registry(&checksum).unwrap().unwrap();
        }
        let seeded_git = object_identities(&root.join("objects/seeded-git/sha256"));
        assert_eq!(seeded_git.len(), 1);
        for digest in seeded_git {
            set.lookup_seeded_git(&digest).unwrap().unwrap();
        }
    }

    fn object_identities(namespace: &Path) -> Vec<String> {
        let mut identities = Vec::new();
        for prefix in fs::read_dir(namespace).unwrap() {
            let prefix = prefix.unwrap().path();
            for object in fs::read_dir(prefix).unwrap() {
                identities.push(object.unwrap().file_name().into_string().unwrap());
            }
        }
        identities.sort();
        identities
    }

    fn replace_metadata(path: &Path, old: &str, new: &str) {
        let contents = fs::read_to_string(path).unwrap();
        assert!(contents.contains(old));
        fs::write(path, contents.replace(old, new)).unwrap();
    }
}
