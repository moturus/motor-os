#![allow(dead_code)]

use semver::Version;
use std::fs::{self, File};
use std::path::Path;
use std::path::PathBuf;

use crate::atomic::AtomicDirectory;
use crate::diagnostic::{Error, Result};
use crate::hash::hex;
use crate::source_tree::{EntryKind, Exclusions, Limits, Tree};

pub fn publish_package(
    cache_root: &Path,
    name: &str,
    version: &Version,
    source: &Path,
    expected_sha256: [u8; 32],
    limits: Limits,
    exclusions: Exclusions,
) -> Result<PathBuf> {
    let sources = cache_root.join("sources");
    let destination = sources.join(format!("{name}-{version}-{}", hex(&expected_sha256)));
    match fs::symlink_metadata(&destination) {
        Ok(_) => return verify(&destination, expected_sha256, limits),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(Error::failure(format!(
                "failed to inspect source view `{}`: {error}",
                destination.display()
            )));
        }
    }

    let tree = Tree::scan(source, limits, exclusions)?;
    if tree.sha256 != expected_sha256 {
        return Err(Error::failure(format!(
            "prepared source for `{name} {version}` changed before publication"
        )));
    }
    let staging = AtomicDirectory::new(&sources, name)?;
    copy_tree(source, staging.path(), &tree)?;
    verify(staging.path(), expected_sha256, limits)?;
    if !staging.commit_no_replace(&destination)? {
        verify(&destination, expected_sha256, limits)?;
    }
    Ok(destination)
}

fn verify(path: &Path, expected_sha256: [u8; 32], limits: Limits) -> Result<PathBuf> {
    let tree = Tree::scan(path, limits, Exclusions::None).map_err(|error| {
        Error::failure(format!(
            "cached source view `{}` is invalid: {error}",
            path.display()
        ))
        .with_help("run `lorry cache clean` to remove invalid cached source views")
    })?;
    if tree.sha256 != expected_sha256 {
        return Err(Error::failure(format!(
            "cached source view `{}` does not match its content address",
            path.display()
        ))
        .with_help("run `lorry cache clean` to remove invalid cached source views"));
    }
    Ok(path.to_owned())
}

fn copy_tree(source: &Path, destination: &Path, tree: &Tree) -> Result<()> {
    for entry in &tree.entries {
        let from = source.join(&entry.path);
        let to = destination.join(&entry.path);
        match entry.kind {
            EntryKind::Directory => fs::create_dir(&to).map_err(|error| {
                Error::failure(format!(
                    "failed to create source-view directory `{}`: {error}",
                    to.display()
                ))
            })?,
            EntryKind::File => {
                fs::copy(&from, &to).map_err(|error| {
                    Error::failure(format!(
                        "failed to copy source-view file `{}`: {error}",
                        from.display()
                    ))
                })?;
                File::open(&to)
                    .and_then(|file| file.sync_all())
                    .map_err(|error| {
                        Error::failure(format!(
                            "failed to persist source-view file `{}`: {error}",
                            to.display()
                        ))
                    })?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_tree::DEFAULT_LIMITS;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "lorry-source-view-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir(&root).unwrap();
            fs::create_dir_all(root.join("source/src")).unwrap();
            fs::write(
                root.join("source/Cargo.toml"),
                "[package]\nname = \"demo\"\nversion = \"1.2.3\"\n",
            )
            .unwrap();
            fs::write(
                root.join("source/src/lib.rs"),
                "pub fn answer() -> u8 { 42 }\n",
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    root.join("source/src/lib.rs"),
                    fs::Permissions::from_mode(0o755),
                )
                .unwrap();
            }
            fs::write(root.join("source/.cargo-ok"), "ignored marker\n").unwrap();
            Self(root)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn atomically_publishes_reuses_and_reverifies_source_views() {
        let fixture = Fixture::new();
        let source = fixture.0.join("source");
        let cache = fixture.0.join("cache");
        let tree = Tree::scan(&source, DEFAULT_LIMITS, Exclusions::CargoRegistryMarker).unwrap();
        let version = Version::parse("1.2.3").unwrap();

        let paths = std::thread::scope(|scope| {
            let workers = (0..2)
                .map(|_| {
                    scope.spawn(|| {
                        publish_package(
                            &cache,
                            "demo",
                            &version,
                            &source,
                            tree.sha256,
                            DEFAULT_LIMITS,
                            Exclusions::CargoRegistryMarker,
                        )
                        .unwrap()
                    })
                })
                .collect::<Vec<_>>();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(paths[0], paths[1]);
        assert!(!paths[0].join(".cargo-ok").exists());
        assert_eq!(
            Tree::scan(&paths[0], DEFAULT_LIMITS, Exclusions::None)
                .unwrap()
                .sha256,
            tree.sha256
        );

        fs::write(paths[0].join("src/lib.rs"), "changed\n").unwrap();
        let error = publish_package(
            &cache,
            "demo",
            &version,
            &source,
            tree.sha256,
            DEFAULT_LIMITS,
            Exclusions::CargoRegistryMarker,
        )
        .unwrap_err();
        assert!(error.render().contains("lorry cache clean"));
    }

    #[test]
    fn changed_prepared_source_is_never_published() {
        let fixture = Fixture::new();
        let cache = fixture.0.join("cache");
        let error = publish_package(
            &cache,
            "demo",
            &Version::parse("1.2.3").unwrap(),
            &fixture.0.join("source"),
            [7; 32],
            DEFAULT_LIMITS,
            Exclusions::CargoRegistryMarker,
        )
        .unwrap_err();
        assert!(error.render().contains("changed before publication"));
        assert!(!cache.exists());
    }
}
