use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use crate::atomic::AtomicFile;
use crate::diagnostic::{Error, Result};
use crate::hash::Sha256;
use crate::resolver::{PackageKey, PackageSourceKey};

const FILE_NAME: &str = ".lorry-owner-v1";
const PRIMARY_SUFFIX: &str = ".lorry-owner-v1";

fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update(&(bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

pub fn identity(package: &PackageKey) -> [u8; 32] {
    let mut hash = Sha256::new();
    field(&mut hash, b"lorry-artifact-owner-v1");
    field(&mut hash, package.name.as_bytes());
    field(&mut hash, package.version.to_string().as_bytes());
    match &package.source {
        PackageSourceKey::CratesIo => field(&mut hash, b"crates.io"),
        PackageSourceKey::Git(source) => {
            field(&mut hash, b"git");
            field(&mut hash, source.as_bytes());
        }
        PackageSourceKey::Path(path) => {
            field(&mut hash, b"path");
            field(&mut hash, path.as_os_str().as_encoded_bytes());
        }
    }
    hash.finish()
}

pub fn write(directory: &Path, package: &PackageKey) -> Result<()> {
    let mut owner = AtomicFile::new(&directory.join(FILE_NAME))?;
    owner.write_all(&identity(package))?;
    owner.commit()
}

pub fn matches(directory: &Path, package: &PackageKey) -> bool {
    matches_record(&directory.join(FILE_NAME), package)
}

fn matches_record(path: &Path, package: &PackageKey) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    metadata.file_type().is_file()
        && metadata.len() == 32
        && fs::read(path).ok().as_deref() == Some(identity(package).as_slice())
}

pub fn primary_record(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| Error::failure("primary artifact has no file name"))?;
    let mut record_name = OsString::from(name);
    record_name.push(PRIMARY_SUFFIX);
    Ok(path.with_file_name(record_name))
}

pub fn invalidate_primary(path: &Path) -> Result<()> {
    let record = primary_record(path)?;
    match fs::symlink_metadata(&record) {
        Ok(metadata) if metadata.file_type().is_file() => {
            fs::remove_file(&record).map_err(|error| {
                Error::failure(format!(
                    "failed to invalidate primary artifact owner `{}`: {error}",
                    record.display()
                ))
            })
        }
        Ok(_) => Err(Error::failure(format!(
            "primary artifact owner `{}` is not a regular file",
            record.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::failure(format!(
            "failed to inspect primary artifact owner `{}`: {error}",
            record.display()
        ))),
    }
}

pub fn write_primary(path: &Path, package: &PackageKey) -> Result<()> {
    let mut owner = AtomicFile::new(&primary_record(path)?)?;
    owner.write_all(&identity(package))?;
    owner.commit()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn ownership_distinguishes_packages_and_rejects_unmarked_outputs() {
        let directory = std::env::temp_dir().join(format!(
            "lorry-owner-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let package = PackageKey {
            name: "app".to_owned(),
            version: "1.0.0".parse().unwrap(),
            source: PackageSourceKey::Path(PathBuf::from("/workspace/app")),
        };
        let other = PackageKey {
            source: PackageSourceKey::Path(PathBuf::from("/workspace/other")),
            ..package.clone()
        };
        assert!(!matches(&directory, &package));
        write(&directory, &package).unwrap();
        assert!(matches(&directory, &package));
        assert!(!matches(&directory, &other));
        let primary = directory.join("app");
        write_primary(&primary, &package).unwrap();
        let record = primary_record(&primary).unwrap();
        assert!(matches_record(&record, &package));
        assert!(!matches_record(&record, &other));
        invalidate_primary(&primary).unwrap();
        assert!(!matches_record(&record, &package));
        fs::remove_dir_all(directory).unwrap();
    }
}
