use std::fs;
use std::path::Path;

use crate::atomic::AtomicFile;
use crate::diagnostic::Result;
use crate::hash::Sha256;
use crate::resolver::{PackageKey, PackageSourceKey};

const FILE_NAME: &str = ".lorry-owner-v1";

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
    let path = directory.join(FILE_NAME);
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        return false;
    };
    metadata.file_type().is_file()
        && metadata.len() == 32
        && fs::read(path).ok().as_deref() == Some(identity(package).as_slice())
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
        fs::remove_dir_all(directory).unwrap();
    }
}
