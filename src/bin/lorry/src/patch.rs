#![allow(dead_code)]

use std::fs;
use std::path::Path;

use crate::diagnostic::{Error, Result};
use crate::manifest::{Manifest, Patch, PatchSource};
use crate::resolver::Catalog;
use crate::source_tree::{DEFAULT_LIMITS, Exclusions, Tree};

pub fn configure(manifest: &Manifest, catalog: &mut Catalog) -> Result<()> {
    configure_mode(manifest, catalog, false)
}

pub(crate) fn configure_sources(manifest: &Manifest, catalog: &mut Catalog) -> Result<()> {
    configure_mode(manifest, catalog, true)
}

fn configure_mode(manifest: &Manifest, catalog: &mut Catalog, describe: bool) -> Result<()> {
    for patch in &manifest.patches {
        match &patch.source {
            PatchSource::Path(path) => load_local_patch(manifest, patch, path, catalog, describe)?,
            PatchSource::Git(_) => {}
        }
    }
    Ok(())
}

fn load_local_patch(
    workspace: &Manifest,
    patch: &Patch,
    path: &Path,
    catalog: &mut Catalog,
    describe: bool,
) -> Result<()> {
    let physical_root = fs::canonicalize(path).map_err(|error| {
        Error::failure(format!(
            "failed to resolve local patch `{}` at `{}`: {error}",
            patch.alias,
            path.display()
        ))
    })?;
    let mut manifest = if describe {
        Manifest::load_source_dependency(&physical_root)?
    } else {
        Manifest::load_path_dependency(&physical_root)?
    };
    manifest.editable = workspace
        .workspace_members
        .values()
        .any(|member| *member == physical_root);
    if manifest.editable {
        manifest
            .workspace_root
            .clone_from(&workspace.workspace_root);
        manifest
            .workspace_members
            .clone_from(&workspace.workspace_members);
    }
    if manifest.name != patch.package {
        return Err(Error::failure(format!(
            "local patch `{}` declares package `{}`, expected `{}`",
            patch.alias, manifest.name, patch.package
        )));
    }
    let sha256 = if manifest.editable {
        crate::member_source::snapshot(&manifest, true)?.sha256
    } else {
        Tree::scan(&manifest.root, DEFAULT_LIMITS, Exclusions::GitAndTarget)?.sha256
    };
    catalog.insert_path_patch(manifest, physical_root.clone(), physical_root, sha256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::{Options, ResolvedSource, resolve_member};
    use crate::sparse::Record;
    use semver::Version;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("lorry-patch-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn package(&self, relative: &str, name: &str, version: &str) {
            let root = self.0.join(relative);
            fs::create_dir_all(root.join("src")).unwrap();
            fs::write(
                root.join("Cargo.toml"),
                format!(
                    "[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n"
                ),
            )
            .unwrap();
            fs::write(root.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn manifest(root: &Path) -> Manifest {
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "").unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\ndemo = \"=1.2.3\"\n\
             [patch.crates-io]\ndemo = { path = \"../patched\" }\n",
        )
        .unwrap();
        fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"root\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        Manifest::load_for_build(root).unwrap()
    }

    #[test]
    fn ordinary_path_patch_shadows_the_same_registry_version() {
        let fixture = Fixture::new();
        fixture.package("patched", "demo", "1.2.3");
        let manifest = manifest(&fixture.0.join("root"));
        let checksum = "44".repeat(32);
        let record = Record::parse(
            Path::new("/index-record.json"),
            format!(
                "{{\"name\":\"demo\",\"vers\":\"1.2.3\",\"deps\":[],\
                 \"cksum\":\"{checksum}\",\"features\":{{}},\"yanked\":false}}\n"
            )
            .as_bytes(),
        )
        .unwrap();
        let mut catalog = Catalog::default();
        catalog.insert(record).unwrap();
        configure(&manifest, &mut catalog).unwrap();

        let options = Options {
            resolver: crate::manifest::Resolver::V2,
            incompatible_rust_versions: None,
            rust_versions: vec![Version::parse("1.85.0").unwrap()],
            package_limit: crate::policy::PackageLimit::with_max(16),
            max_depth: Some(8),
        };
        let resolution =
            resolve_member(
                &manifest,
                &mut catalog,
                &options,
                &[],
                &mut |_, _, _| Ok(()),
            )
            .unwrap();
        assert!(matches!(
            resolution.packages[0].source,
            ResolvedSource::Path {
                patched_crates_io: true,
                ..
            }
        ));
    }
}
