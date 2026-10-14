use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Component, Path};
use std::time::SystemTime;

use crate::diagnostic::{Error, Result};
use crate::fs_check::{file_identity, path_identity};
use crate::hash::{FieldDigest, Sha256, decode_hex, hex};
use crate::json::Value;

const FORMAT_TAG: &[u8] = b"lorry-source-tree-v1\0";
const ZERO_SHA256: [u8; 32] = [0; 32];

pub const DEFAULT_LIMITS: Limits = Limits {
    max_entries: 20_000,
    max_path_bytes: 4_096,
    max_file_bytes: 128 * 1024 * 1024,
    max_tree_bytes: 128 * 1024 * 1024,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_entries: usize,
    pub max_path_bytes: usize,
    pub max_file_bytes: u64,
    pub max_tree_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    Directory,
    File,
}

impl EntryKind {
    fn digest_byte(self) -> u8 {
        match self {
            Self::Directory => 1,
            Self::File => 2,
        }
    }

    fn manifest_name(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::File => "file",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    pub path: String,
    pub kind: EntryKind,
    pub executable: bool,
    pub length: u64,
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tree {
    pub entries: Vec<Entry>,
    pub file_count: usize,
    pub directory_count: usize,
    pub total_bytes: u64,
    pub sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exclusions {
    None,
    GitAndTarget,
    CargoRegistryMarker,
}

impl Tree {
    pub fn scan(root: &Path, limits: Limits, exclusions: Exclusions) -> Result<Self> {
        Ok(Self::scan_with(root, limits, exclusions, true)?.0)
    }

    /// Scans like `scan`, but reuses the tree recorded at `record` while every
    /// entry keeps the kind, size, mode, and times recorded with it, so no
    /// file is read. Ordinary validation trusts such a record, as it trusts
    /// immutable repository objects; strict validation scans instead.
    pub fn scan_recorded(
        root: &Path,
        limits: Limits,
        exclusions: Exclusions,
        record: &Path,
    ) -> Result<Self> {
        let (_, stats) = Self::scan_with(root, limits, exclusions, false)?;
        if let Some(tree) = read_record(record, &stats, limits) {
            return Ok(tree);
        }
        let (tree, stats) = Self::scan_with(root, limits, exclusions, true)?;
        let _ = write_record(record, &stats, &tree);
        Ok(tree)
    }

    /// Without `hash`, files are not read and their entries carry no digest.
    /// The second result digests every entry's file-system metadata.
    fn scan_with(
        root: &Path,
        limits: Limits,
        exclusions: Exclusions,
        hash: bool,
    ) -> Result<(Self, [u8; 32])> {
        let root_metadata = fs::symlink_metadata(root).map_err(|error| {
            Error::failure(format!(
                "failed to inspect source root `{}`: {error}",
                root.display()
            ))
        })?;
        if !root_metadata.is_dir() {
            return Err(Error::failure(format!(
                "source root `{}` is not a directory",
                root.display()
            )));
        }

        let mut scanner = Scanner {
            root,
            limits,
            exclusions,
            hash,
            stats: FieldDigest::tagged(b"lorry-tree-stats-v1\0"),
            entries: Vec::new(),
            file_count: 0,
            directory_count: 0,
            total_bytes: 0,
        };
        scanner.scan_directory(root)?;
        scanner
            .entries
            .sort_unstable_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        let sha256 = digest_entries(&scanner.entries, limits)?;
        Ok((
            Self {
                entries: scanner.entries,
                file_count: scanner.file_count,
                directory_count: scanner.directory_count,
                total_bytes: scanner.total_bytes,
                sha256,
            },
            scanner.stats.finish(),
        ))
    }

    /// Parses `manifest_bytes` output and checks that it is consistent.
    fn from_manifest(path: &Path, bytes: &[u8], limits: Limits) -> Result<Self> {
        let invalid = || Error::failure(format!("source manifest `{}` is invalid", path.display()));
        let value = Value::parse(path, "source manifest", bytes)?;
        let object = value.as_object().ok_or_else(invalid)?;
        if value.canonical_bytes() != bytes
            || object.get("format-version").and_then(Value::as_u64) != Some(1)
        {
            return Err(invalid());
        }
        let entries = object
            .get("entries")
            .and_then(Value::as_array)
            .ok_or_else(invalid)?
            .iter()
            .map(|entry| {
                let field = |name: &str| entry.as_object().and_then(|entry| entry.get(name));
                Some(Entry {
                    path: field("path")?.as_str()?.to_owned(),
                    kind: match field("kind")?.as_str()? {
                        "directory" => EntryKind::Directory,
                        "file" => EntryKind::File,
                        _ => return None,
                    },
                    executable: field("executable")?.as_bool()?,
                    length: field("length")?.as_u64()?,
                    sha256: decode_hex(field("sha256")?.as_str()?).ok()?,
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(invalid)?;
        let sha256 = digest_entries(&entries, limits)?;
        if object.get("source-tree-sha256").and_then(Value::as_str) != Some(&hex(&sha256)) {
            return Err(invalid());
        }
        let file_count = entries
            .iter()
            .filter(|entry| entry.kind == EntryKind::File)
            .count();
        Ok(Self {
            file_count,
            directory_count: entries.len() - file_count,
            total_bytes: entries.iter().map(|entry| entry.length).sum(),
            entries,
            sha256,
        })
    }

    pub fn manifest_bytes(&self) -> Vec<u8> {
        let entries = self
            .entries
            .iter()
            .map(|entry| {
                Value::Object(BTreeMap::from([
                    ("executable".to_owned(), Value::Bool(entry.executable)),
                    (
                        "kind".to_owned(),
                        Value::String(entry.kind.manifest_name().to_owned()),
                    ),
                    ("length".to_owned(), Value::Number(entry.length.into())),
                    ("path".to_owned(), Value::String(entry.path.clone())),
                    ("sha256".to_owned(), Value::String(hex(&entry.sha256))),
                ]))
            })
            .collect();
        Value::Object(BTreeMap::from([
            ("entries".to_owned(), Value::Array(entries)),
            ("format-version".to_owned(), Value::Number(1_u64.into())),
            (
                "source-tree-sha256".to_owned(),
                Value::String(hex(&self.sha256)),
            ),
        ]))
        .canonical_bytes()
    }

    /// Derives a package tree from an already verified containing tree without
    /// reading the same files again.
    pub fn subtree(&self, root: &str, limits: Limits) -> Result<Self> {
        if root.is_empty() {
            return Ok(self.clone());
        }
        validate_portable_path(root, limits)?;
        if !self
            .entries
            .iter()
            .any(|entry| entry.path == root && entry.kind == EntryKind::Directory)
        {
            return Err(Error::failure(format!(
                "source tree has no directory `{root}`"
            )));
        }
        let prefix = format!("{root}/");
        let entries = self
            .entries
            .iter()
            .filter_map(|entry| {
                entry.path.strip_prefix(&prefix).map(|path| {
                    let mut entry = entry.clone();
                    entry.path = path.to_owned();
                    entry
                })
            })
            .collect::<Vec<_>>();
        let file_count = entries
            .iter()
            .filter(|entry| entry.kind == EntryKind::File)
            .count();
        let directory_count = entries.len() - file_count;
        let total_bytes = entries.iter().try_fold(0_u64, |total, entry| {
            total
                .checked_add(entry.length)
                .ok_or_else(|| Error::failure("source subtree byte count overflowed"))
        })?;
        let sha256 = digest_entries(&entries, limits)?;
        Ok(Self {
            entries,
            file_count,
            directory_count,
            total_bytes,
            sha256,
        })
    }
}

struct Scanner<'a> {
    root: &'a Path,
    limits: Limits,
    exclusions: Exclusions,
    hash: bool,
    stats: FieldDigest,
    entries: Vec<Entry>,
    file_count: usize,
    directory_count: usize,
    total_bytes: u64,
}

impl Scanner<'_> {
    fn scan_directory(&mut self, directory: &Path) -> Result<()> {
        let read_dir = fs::read_dir(directory).map_err(|error| {
            Error::failure(format!(
                "failed to read source directory `{}`: {error}",
                directory.display()
            ))
        })?;
        let mut children = Vec::new();
        for child in read_dir {
            let child = child.map_err(|error| {
                Error::failure(format!(
                    "failed to read an entry in source directory `{}`: {error}",
                    directory.display()
                ))
            })?;
            children.push(child.path());
        }
        children.sort_unstable_by(|left, right| {
            left.file_name()
                .and_then(|name| name.to_str())
                .map(str::as_bytes)
                .cmp(
                    &right
                        .file_name()
                        .and_then(|name| name.to_str())
                        .map(str::as_bytes),
                )
        });

        for path in children {
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                Error::failure(format!(
                    "failed to inspect source entry `{}`: {error}",
                    path.display()
                ))
            })?;
            let name = portable_file_name(&path)?;
            if self.excluded(&path, name, &metadata) {
                continue;
            }
            let relative = portable_path(&path, self.root, self.limits)?;
            if metadata.file_type().is_symlink() {
                return Err(unsupported_entry(&path, "symbolic link"));
            }
            self.record_stats(&path, &relative, &metadata)?;
            if metadata.is_dir() {
                self.push(Entry {
                    path: relative,
                    kind: EntryKind::Directory,
                    executable: false,
                    length: 0,
                    sha256: ZERO_SHA256,
                })?;
                self.directory_count += 1;
                self.scan_directory(&path)?;
            } else if metadata.is_file() {
                let (length, sha256, executable) = if self.hash {
                    hash_file(&path, &metadata, self.limits.max_file_bytes)?
                } else {
                    (metadata.len(), ZERO_SHA256, false)
                };
                self.total_bytes = self.total_bytes.checked_add(length).ok_or_else(|| {
                    Error::failure("source tree byte count overflowed its representation")
                })?;
                if self.total_bytes > self.limits.max_tree_bytes {
                    return Err(Error::failure(format!(
                        "source tree `{}` exceeds the byte limit of {}",
                        self.root.display(),
                        self.limits.max_tree_bytes
                    )));
                }
                self.push(Entry {
                    path: relative,
                    kind: EntryKind::File,
                    executable,
                    length,
                    sha256,
                })?;
                self.file_count += 1;
            } else {
                return Err(unsupported_entry(&path, "special file"));
            }
        }
        Ok(())
    }

    fn record_stats(&mut self, path: &Path, relative: &str, metadata: &Metadata) -> Result<()> {
        self.stats.field(relative.as_bytes());
        self.stats.field(&[u8::from(metadata.is_dir())]);
        if metadata.is_dir() {
            return Ok(());
        }
        self.stats.field(&metadata.len().to_le_bytes());
        self.stats
            .field(&[u8::from(path_executable(path, metadata)?)]);
        let modified = modified(path, metadata)?
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        self.stats.field(&modified.as_nanos().to_le_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            self.stats.field(&metadata.ctime().to_le_bytes());
            self.stats.field(&metadata.ctime_nsec().to_le_bytes());
            self.stats.field(&metadata.dev().to_le_bytes());
            self.stats.field(&metadata.ino().to_le_bytes());
        }
        Ok(())
    }

    fn excluded(&self, path: &Path, name: &str, metadata: &Metadata) -> bool {
        match self.exclusions {
            Exclusions::None => false,
            Exclusions::GitAndTarget => (name == ".git") || (name == "target" && metadata.is_dir()),
            Exclusions::CargoRegistryMarker => {
                name == ".cargo-ok"
                    && path.parent() == Some(self.root)
                    && metadata.is_file()
                    && !metadata.file_type().is_symlink()
            }
        }
    }

    fn push(&mut self, entry: Entry) -> Result<()> {
        if self.entries.len() >= self.limits.max_entries {
            return Err(Error::failure(format!(
                "source tree `{}` exceeds the entry-count limit of {}",
                self.root.display(),
                self.limits.max_entries
            )));
        }
        self.entries.push(entry);
        Ok(())
    }
}

fn portable_file_name(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            Error::failure(format!(
                "source path is not valid UTF-8: `{}`",
                path.display()
            ))
        })
}

fn portable_path(path: &Path, root: &Path, limits: Limits) -> Result<String> {
    let relative = path.strip_prefix(root).map_err(|_| {
        Error::failure(format!(
            "source path `{}` is outside root `{}`",
            path.display(),
            root.display()
        ))
    })?;
    let mut output = String::new();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(nonportable_path(path));
        };
        let component = component.to_str().ok_or_else(|| {
            Error::failure(format!(
                "source path is not valid UTF-8: `{}`",
                path.display()
            ))
        })?;
        if component.is_empty()
            || component == "."
            || component == ".."
            || component
                .bytes()
                .any(|byte| byte == 0 || byte == b'\\' || byte < 0x20 || byte == 0x7f)
        {
            return Err(nonportable_path(path));
        }
        if !output.is_empty() {
            output.push('/');
        }
        output.push_str(component);
    }
    validate_portable_path(&output, limits)?;
    Ok(output)
}

fn validate_portable_path(path: &str, limits: Limits) -> Result<()> {
    if path.is_empty()
        || path.len() > limits.max_path_bytes
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path
            .bytes()
            .any(|byte| byte == 0 || byte < 0x20 || byte == 0x7f)
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(Error::failure(format!("non-portable source path `{path}`")));
    }
    if u32::try_from(path.len()).is_err() {
        return Err(Error::failure(format!(
            "source path `{path}` is too long for the source-tree format"
        )));
    }
    Ok(())
}

fn nonportable_path(path: &Path) -> Error {
    Error::failure(format!("non-portable source path `{}`", path.display()))
}

fn unsupported_entry(path: &Path, kind: &str) -> Error {
    Error::failure(format!(
        "unsupported source entry ({kind}): `{}`",
        path.display()
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileSnapshot {
    identity: (u128, u128),
    length: u64,
    modified: SystemTime,
    executable: bool,
}

fn hash_file(
    path: &Path,
    initial_metadata: &Metadata,
    max_file_bytes: u64,
) -> Result<(u64, [u8; 32], bool)> {
    let initial = snapshot_path(path, initial_metadata)?;
    if initial.length > max_file_bytes {
        return Err(file_limit_error(path, max_file_bytes));
    }

    let mut file = File::open(path).map_err(|error| {
        Error::failure(format!(
            "failed to open source file `{}`: {error}",
            path.display()
        ))
    })?;
    let opened = snapshot_file(path, &file)?;
    if initial != opened {
        return Err(changed_while_hashing(path));
    }

    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            Error::failure(format!(
                "failed to hash source file `{}`: {error}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        length = length
            .checked_add(read as u64)
            .ok_or_else(|| file_limit_error(path, max_file_bytes))?;
        if length > max_file_bytes {
            return Err(file_limit_error(path, max_file_bytes));
        }
        hasher.update(&buffer[..read]);
    }

    let opened_after = snapshot_file(path, &file)?;
    let path_metadata = fs::symlink_metadata(path).map_err(|error| {
        Error::failure(format!(
            "failed to recheck source file `{}`: {error}",
            path.display()
        ))
    })?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(changed_while_hashing(path));
    }
    let path_after = snapshot_path(path, &path_metadata)?;
    if opened != opened_after || opened != path_after || length != opened.length {
        return Err(changed_while_hashing(path));
    }
    Ok((length, hasher.finish(), opened.executable))
}

fn file_limit_error(path: &Path, limit: u64) -> Error {
    Error::failure(format!(
        "source file `{}` exceeds the byte limit of {limit}",
        path.display()
    ))
}

fn changed_while_hashing(path: &Path) -> Error {
    Error::failure(format!(
        "source file `{}` changed while hashing",
        path.display()
    ))
}

fn snapshot_path(path: &Path, metadata: &Metadata) -> Result<FileSnapshot> {
    Ok(FileSnapshot {
        identity: path_identity(path, metadata)?,
        length: metadata.len(),
        modified: modified(path, metadata)?,
        executable: path_executable(path, metadata)?,
    })
}

fn snapshot_file(path: &Path, file: &File) -> Result<FileSnapshot> {
    let metadata = file.metadata().map_err(|error| {
        Error::failure(format!(
            "failed to inspect open source file `{}`: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(changed_while_hashing(path));
    }
    Ok(FileSnapshot {
        identity: file_identity(file, &metadata)?,
        length: metadata.len(),
        modified: modified(path, &metadata)?,
        executable: file_executable(file, &metadata)?,
    })
}

fn modified(path: &Path, metadata: &Metadata) -> Result<SystemTime> {
    metadata.modified().map_err(|error| {
        Error::failure(format!(
            "failed to read source modification time `{}`: {error}",
            path.display()
        ))
    })
}

#[cfg(unix)]
fn path_executable(_path: &Path, metadata: &Metadata) -> Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    Ok(metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(target_os = "motor")]
fn path_executable(path: &Path, _metadata: &Metadata) -> Result<bool> {
    let path = path.to_str().ok_or_else(|| {
        Error::failure(format!(
            "source path is not valid UTF-8: `{}`",
            path.display()
        ))
    })?;
    let attr = moto_rt::fs::stat(path).map_err(|error| {
        Error::failure(format!(
            "failed to inspect Motor source permissions `{path}`: {error}"
        ))
    })?;
    Ok(attr.perm & moto_rt::fs::PERM_EXEC != 0)
}

#[cfg(not(any(unix, target_os = "motor")))]
fn path_executable(path: &Path, _metadata: &Metadata) -> Result<bool> {
    Err(Error::failure(format!(
        "source permissions are unsupported on this platform: `{}`",
        path.display()
    )))
}

#[cfg(unix)]
fn file_executable(_file: &File, metadata: &Metadata) -> Result<bool> {
    path_executable(Path::new(""), metadata)
}

#[cfg(target_os = "motor")]
fn file_executable(file: &File, _metadata: &Metadata) -> Result<bool> {
    use std::os::fd::AsRawFd;
    let attr = moto_rt::fs::get_file_attr(file.as_raw_fd()).map_err(|error| {
        Error::failure(format!(
            "failed to inspect open Motor source permissions: {error}"
        ))
    })?;
    Ok(attr.perm & moto_rt::fs::PERM_EXEC != 0)
}

#[cfg(not(any(unix, target_os = "motor")))]
fn file_executable(_file: &File, _metadata: &Metadata) -> Result<bool> {
    Err(Error::failure(
        "source permissions are unsupported on this platform",
    ))
}

const RECORD_HEADER: &str = "lorry-tree-record-v1\n";

fn read_record(record: &Path, stats: &[u8; 32], limits: Limits) -> Option<Tree> {
    let bytes = fs::read(record).ok()?;
    let rest = bytes.strip_prefix(RECORD_HEADER.as_bytes())?;
    let (line, manifest) = rest.split_at(rest.iter().position(|byte| *byte == b'\n')? + 1);
    (line == format!("stats={}\n", hex(stats)).as_bytes()).then_some(())?;
    Tree::from_manifest(record, manifest, limits).ok()
}

fn write_record(record: &Path, stats: &[u8; 32], tree: &Tree) -> Result<()> {
    if let Some(parent) = record.parent() {
        fs::create_dir_all(parent).map_err(|error| Error::failure(error.to_string()))?;
    }
    let mut file = crate::atomic::AtomicFile::new(record)?;
    file.write_all(format!("{RECORD_HEADER}stats={}\n", hex(stats)).as_bytes())?;
    file.write_all(&tree.manifest_bytes())?;
    file.commit()
}

pub fn digest_entries(entries: &[Entry], limits: Limits) -> Result<[u8; 32]> {
    validate_entries(entries, limits)?;
    let mut hasher = Sha256::new();
    hasher.update(FORMAT_TAG);
    hasher.update(&(entries.len() as u64).to_be_bytes());
    for entry in entries {
        hasher.update(&[entry.kind.digest_byte(), u8::from(entry.executable)]);
        hasher.update(&(entry.path.len() as u32).to_be_bytes());
        hasher.update(entry.path.as_bytes());
        hasher.update(&entry.length.to_be_bytes());
        hasher.update(&entry.sha256);
    }
    Ok(hasher.finish())
}

fn validate_entries(entries: &[Entry], limits: Limits) -> Result<()> {
    if entries.len() > limits.max_entries {
        return Err(Error::failure(format!(
            "source manifest exceeds the entry-count limit of {}",
            limits.max_entries
        )));
    }
    let mut previous: Option<&str> = None;
    let mut directories = BTreeSet::new();
    let mut total_bytes = 0_u64;
    for entry in entries {
        validate_portable_path(&entry.path, limits)?;
        if previous.is_some_and(|previous| previous.as_bytes() >= entry.path.as_bytes()) {
            return Err(Error::failure(
                "source manifest entries are not in strict portable path order",
            ));
        }
        previous = Some(&entry.path);
        if let Some((parent, _)) = entry.path.rsplit_once('/')
            && !directories.contains(parent)
        {
            return Err(Error::failure(format!(
                "source manifest entry `{}` is missing parent directory `{parent}`",
                entry.path
            )));
        }
        match entry.kind {
            EntryKind::Directory => {
                if entry.executable || entry.length != 0 || entry.sha256 != ZERO_SHA256 {
                    return Err(Error::failure(format!(
                        "source manifest directory `{}` has file metadata",
                        entry.path
                    )));
                }
                directories.insert(entry.path.as_str());
            }
            EntryKind::File => {
                if entry.length > limits.max_file_bytes {
                    return Err(file_limit_error(
                        Path::new(&entry.path),
                        limits.max_file_bytes,
                    ));
                }
                total_bytes = total_bytes.checked_add(entry.length).ok_or_else(|| {
                    Error::failure("source manifest byte count overflowed its representation")
                })?;
                if total_bytes > limits.max_tree_bytes {
                    return Err(Error::failure(format!(
                        "source manifest exceeds the tree byte limit of {}",
                        limits.max_tree_bytes
                    )));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::decode_hex;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "lorry-source-tree-{name}-{}-{id}",
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

    #[test]
    fn recorded_scans_reuse_a_tree_until_file_metadata_changes() {
        let root = TempDir::new("recorded");
        let tree_root = root.0.join("tree");
        let other = root.0.join("other");
        fs::create_dir_all(tree_root.join("src")).unwrap();
        fs::create_dir_all(&other).unwrap();
        fs::write(tree_root.join("src/lib.rs"), "pub fn one() {}\n").unwrap();
        fs::write(other.join("decoy"), "not the scanned tree\n").unwrap();
        let record = root.0.join("records/tree");
        let scan = || Tree::scan_recorded(&tree_root, DEFAULT_LIMITS, Exclusions::None, &record);
        let first = scan().unwrap();
        assert_eq!(
            first,
            Tree::scan(&tree_root, DEFAULT_LIMITS, Exclusions::None).unwrap()
        );
        // A record whose metadata still matches is trusted without reading
        // any file: here it holds another tree.
        let stats = fs::read_to_string(&record)
            .unwrap()
            .lines()
            .nth(1)
            .unwrap()
            .to_owned();
        let decoy = Tree::scan(&other, DEFAULT_LIMITS, Exclusions::None).unwrap();
        let mut forged = format!("{RECORD_HEADER}{stats}\n").into_bytes();
        forged.extend(decoy.manifest_bytes());
        fs::write(&record, &forged).unwrap();
        assert_eq!(scan().unwrap(), decoy);
        // Any metadata change rescans and rewrites the record.
        fs::write(tree_root.join("src/lib.rs"), "pub fn two() {}\n").unwrap();
        let edited = scan().unwrap();
        assert_ne!(edited, first);
        assert_eq!(
            edited,
            Tree::scan(&tree_root, DEFAULT_LIMITS, Exclusions::None).unwrap()
        );
        assert_ne!(fs::read(&record).unwrap(), forged);
        fs::write(&record, b"lorry-tree-record-v1\ngarbage").unwrap();
        assert_eq!(scan().unwrap(), edited);
    }

    #[test]
    fn matches_golden_vectors() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/source-tree-v1-vectors.json");
        let document = Value::load(&path, "source-tree golden vectors").unwrap();
        let vectors = document.get("vectors").and_then(Value::as_array).unwrap();
        for vector in vectors {
            let name = vector.get("name").and_then(Value::as_str).unwrap();
            let entries = vector
                .get("entries")
                .and_then(Value::as_array)
                .unwrap()
                .iter()
                .map(vector_entry)
                .collect::<Vec<_>>();
            let expected = vector
                .get("source-tree-sha256")
                .and_then(Value::as_str)
                .unwrap();
            assert_eq!(
                hex(&digest_entries(&entries, DEFAULT_LIMITS).unwrap()),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn scans_the_portable_tree_and_renders_a_canonical_manifest() {
        let root = TempDir::new("portable");
        fs::create_dir(root.0.join("bin")).unwrap();
        fs::create_dir(root.0.join("empty")).unwrap();
        fs::write(root.0.join("bin/tool"), b"#!/bin/sh\nexit 0\n").unwrap();
        fs::write(root.0.join("caf\u{e9}.txt"), "caf\u{e9}\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.0.join("bin/tool"), fs::Permissions::from_mode(0o755))
                .unwrap();
        }

        let tree = Tree::scan(&root.0, DEFAULT_LIMITS, Exclusions::None).unwrap();
        assert_eq!(tree.file_count, 2);
        assert_eq!(tree.directory_count, 2);
        assert_eq!(tree.total_bytes, 23);
        assert_eq!(
            hex(&tree.sha256),
            "a0bba2df187c38aa673c7feb41af19de82915ef9ef514589bc142fbb9a5720ed"
        );
        let manifest = Value::parse(
            Path::new("source-manifest.json"),
            "rendered source manifest",
            &tree.manifest_bytes(),
        )
        .unwrap();
        assert_eq!(
            manifest.get("source-tree-sha256").and_then(Value::as_str),
            Some("a0bba2df187c38aa673c7feb41af19de82915ef9ef514589bc142fbb9a5720ed")
        );
    }

    #[test]
    fn derives_the_same_subtree_as_a_direct_scan() {
        let root = TempDir::new("subtree");
        fs::create_dir_all(root.0.join("package/src")).unwrap();
        fs::create_dir(root.0.join("package/empty")).unwrap();
        fs::write(root.0.join("outside"), "outside\n").unwrap();
        fs::write(root.0.join("package/Cargo.toml"), "[package]\n").unwrap();
        fs::write(root.0.join("package/src/lib.rs"), "pub fn demo() {}\n").unwrap();

        let containing = Tree::scan(&root.0, DEFAULT_LIMITS, Exclusions::None).unwrap();
        let derived = containing.subtree("package", DEFAULT_LIMITS).unwrap();
        let scanned =
            Tree::scan(&root.0.join("package"), DEFAULT_LIMITS, Exclusions::None).unwrap();

        assert_eq!(derived, scanned);
    }

    #[test]
    fn applies_only_the_requested_directory_exclusions() {
        let root = TempDir::new("exclusions");
        fs::create_dir(root.0.join(".git")).unwrap();
        fs::write(root.0.join(".git/config"), b"ignored").unwrap();
        fs::create_dir(root.0.join("target")).unwrap();
        fs::write(root.0.join("target/output"), b"ignored").unwrap();
        fs::write(root.0.join("target-file"), b"kept").unwrap();

        let tree = Tree::scan(&root.0, DEFAULT_LIMITS, Exclusions::GitAndTarget).unwrap();
        assert_eq!(
            tree.entries
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            ["target-file"]
        );
    }

    #[test]
    fn cargo_registry_exclusion_removes_only_the_root_marker() {
        let root = TempDir::new("cargo-marker");
        fs::write(root.0.join(".cargo-ok"), b"{\"v\":1}").unwrap();
        fs::create_dir(root.0.join("nested")).unwrap();
        fs::write(root.0.join("nested/.cargo-ok"), b"package data").unwrap();

        let tree = Tree::scan(&root.0, DEFAULT_LIMITS, Exclusions::CargoRegistryMarker).unwrap();
        assert_eq!(
            tree.entries
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            ["nested", "nested/.cargo-ok"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_links_special_names_and_limits() {
        use std::os::unix::fs::symlink;

        let links = TempDir::new("link");
        fs::write(links.0.join("file"), b"x").unwrap();
        symlink("file", links.0.join("link")).unwrap();
        let error = Tree::scan(&links.0, DEFAULT_LIMITS, Exclusions::None).unwrap_err();
        assert!(error.to_string().contains("symbolic link"));

        let names = TempDir::new("name");
        fs::write(names.0.join("bad\nname"), b"x").unwrap();
        let error = Tree::scan(&names.0, DEFAULT_LIMITS, Exclusions::None).unwrap_err();
        assert!(error.to_string().contains("non-portable"));

        let limits = TempDir::new("limits");
        fs::write(limits.0.join("large"), b"12345").unwrap();
        let error = Tree::scan(
            &limits.0,
            Limits {
                max_file_bytes: 4,
                ..DEFAULT_LIMITS
            },
            Exclusions::None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("byte limit of 4"));
    }

    #[test]
    fn rejects_noncanonical_manifest_entries() {
        let file = Entry {
            path: "dir/file".to_owned(),
            kind: EntryKind::File,
            executable: false,
            length: 0,
            sha256: Sha256::new().finish(),
        };
        let error = digest_entries(&[file], DEFAULT_LIMITS).unwrap_err();
        assert!(error.to_string().contains("missing parent directory"));

        let directory = Entry {
            path: "dir".to_owned(),
            kind: EntryKind::Directory,
            executable: true,
            length: 0,
            sha256: ZERO_SHA256,
        };
        let error = digest_entries(&[directory], DEFAULT_LIMITS).unwrap_err();
        assert!(error.to_string().contains("file metadata"));
    }

    fn vector_entry(value: &Value) -> Entry {
        let kind = match value.get("kind").and_then(Value::as_str).unwrap() {
            "directory" => EntryKind::Directory,
            "file" => EntryKind::File,
            other => panic!("unknown vector entry kind {other}"),
        };
        if let Some(content) = value.get("content-hex").and_then(Value::as_str) {
            let expected =
                decode_hex::<32>(value.get("sha256").and_then(Value::as_str).unwrap()).unwrap();
            let mut bytes = Vec::new();
            for pair in content.as_bytes().as_chunks::<2>().0 {
                bytes.push((nibble(pair[0]) << 4) | nibble(pair[1]));
            }
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            assert_eq!(hasher.finish(), expected);
            assert_eq!(
                value.get("length").and_then(Value::as_u64),
                Some(bytes.len() as u64)
            );
        }
        Entry {
            path: value
                .get("path")
                .and_then(Value::as_str)
                .unwrap()
                .to_owned(),
            kind,
            executable: value.get("executable").and_then(Value::as_bool).unwrap(),
            length: value.get("length").and_then(Value::as_u64).unwrap(),
            sha256: decode_hex::<32>(value.get("sha256").and_then(Value::as_str).unwrap()).unwrap(),
        }
    }

    fn nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("invalid test hex"),
        }
    }
}
