#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use semver::{Op, Version, VersionReq};

use crate::config::{Config, RequiredPatch};
use crate::diagnostic::{Error, Result};
use crate::hash::decode_hex;
use crate::manifest::{Manifest, PathPatch};
use crate::repository::{RepositorySet, SeededGitObject};
use crate::resolver::Catalog;
use crate::source_tree::{DEFAULT_LIMITS, Exclusions, Tree};

pub fn configure(
    manifest: &Manifest,
    config: &Config,
    repositories: &RepositorySet,
    catalog: &mut Catalog,
) -> Result<()> {
    configure_with(
        manifest,
        config,
        RequiredSource::Repository(repositories),
        catalog,
    )
}

pub fn configure_cargo_registry(
    manifest: &Manifest,
    config: &Config,
    catalog: &mut Catalog,
) -> Result<()> {
    configure_with(manifest, config, RequiredSource::DeclaredPath, catalog)
}

#[derive(Clone, Copy)]
enum RequiredSource<'a> {
    Repository(&'a RepositorySet),
    DeclaredPath,
}

fn configure_with(
    manifest: &Manifest,
    config: &Config,
    source: RequiredSource<'_>,
    catalog: &mut Catalog,
) -> Result<()> {
    validate_distinct_guards(&config.required_patches)?;
    let mut claimed = BTreeSet::new();

    for (id, rule) in &config.required_patches {
        let version = exact_version(&rule.version)?;
        let logical_root = logical_root(&manifest.root, id);
        let matches = manifest
            .patches
            .iter()
            .enumerate()
            .filter(|(_, patch)| {
                patch.package == rule.name && normalize_path(&patch.path) == logical_root
            })
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return Err(Error::failure(format!(
                "multiple `[patch.crates-io]` entries match required patch `{id}` from `{}`",
                rule.provenance.display()
            )));
        }

        let failure = if let Some((index, _)) = matches.first() {
            claimed.insert(*index);
            match load_required_patch(id, rule, &version, &logical_root, source) {
                Ok(loaded) => {
                    catalog.insert_path_patch(
                        loaded.manifest,
                        logical_root,
                        loaded.physical_root,
                        loaded.source_tree_sha256,
                        Some(id.clone()),
                    )?;
                    None
                }
                Err(error) => Some(match source {
                    RequiredSource::Repository(_) => required_source_error(id, rule, error),
                    RequiredSource::DeclaredPath => required_cargo_source_error(id, rule, error),
                }),
            }
        } else {
            Some(required_manifest_error(id, rule))
        };
        catalog.register_required_patch(id, &rule.name, version, &rule.provenance, failure)?;
    }

    for (index, patch) in manifest.patches.iter().enumerate() {
        if !claimed.contains(&index) {
            load_local_patch(patch, catalog)?;
        }
    }
    Ok(())
}

struct LoadedPatch {
    manifest: Manifest,
    physical_root: PathBuf,
    source_tree_sha256: [u8; 32],
}

fn load_required_patch(
    id: &str,
    rule: &RequiredPatch,
    version: &Version,
    logical_root: &Path,
    source: RequiredSource<'_>,
) -> Result<LoadedPatch> {
    match source {
        RequiredSource::Repository(repositories) => {
            load_required_patch_object(id, rule, version, logical_root, repositories)
        }
        RequiredSource::DeclaredPath => load_required_patch_path(id, rule, version, logical_root),
    }
}

fn load_required_patch_object(
    id: &str,
    rule: &RequiredPatch,
    version: &Version,
    logical_root: &Path,
    repositories: &RepositorySet,
) -> Result<LoadedPatch> {
    let object = repositories
        .lookup_seeded_git(&rule.source_tree_sha256)?
        .ok_or_else(|| {
            Error::failure(format!(
                "verified seeded source object `{}` is unavailable",
                rule.source_tree_sha256
            ))
        })?;
    verify_required_object(id, rule, version, &object)?;
    let physical_root = object.root.join("source");
    let manifest = Manifest::load_path_dependency(&physical_root)?;
    let source_version = Version::parse(&manifest.version.original).map_err(|error| {
        Error::failure(format!(
            "seeded source manifest has invalid version `{} {}`: {error}",
            manifest.name, manifest.version.original
        ))
    })?;
    if manifest.name != rule.name || source_version != *version {
        return Err(Error::failure(format!(
            "seeded source manifest identifies `{} {source_version}`, expected `{} {version}`",
            manifest.name, rule.name
        )));
    }
    if manifest.metadata.license != object.license {
        return Err(Error::failure(
            "seeded source manifest license does not match repository metadata",
        ));
    }
    if logical_root.as_os_str().is_empty() {
        return Err(Error::failure(format!(
            "required patch `{id}` produced an empty logical source path"
        )));
    }
    Ok(LoadedPatch {
        physical_root: manifest.root.clone(),
        manifest,
        source_tree_sha256: object.source_tree_sha256,
    })
}

fn load_required_patch_path(
    id: &str,
    rule: &RequiredPatch,
    version: &Version,
    logical_root: &Path,
) -> Result<LoadedPatch> {
    let metadata = fs::symlink_metadata(logical_root).map_err(|error| {
        Error::failure(format!(
            "required patch `{id}` is not materialized at Cargo path `{}`: {error}",
            logical_root.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::failure(format!(
            "required patch `{id}` Cargo path `{}` is not a real directory",
            logical_root.display()
        )));
    }
    let manifest = Manifest::load_path_dependency(logical_root)?;
    let source_version = Version::parse(&manifest.version.original).map_err(|error| {
        Error::failure(format!(
            "required patch Cargo manifest has invalid version `{} {}`: {error}",
            manifest.name, manifest.version.original
        ))
    })?;
    if manifest.name != rule.name || source_version != *version {
        return Err(Error::failure(format!(
            "required patch Cargo manifest identifies `{} {source_version}`, expected `{} {version}`",
            manifest.name, rule.name
        )));
    }
    let tree = Tree::scan(&manifest.root, DEFAULT_LIMITS, Exclusions::GitAndTarget)?;
    let expected = decode_hex::<32>(&rule.source_tree_sha256).map_err(|error| {
        Error::failure(format!(
            "required patch `{id}` has invalid configured source-tree digest: {error}"
        ))
    })?;
    if tree.sha256 != expected {
        return Err(Error::failure(format!(
            "required patch `{id}` Cargo path `{}` does not match its configured source-tree digest",
            logical_root.display()
        )));
    }
    Ok(LoadedPatch {
        physical_root: manifest.root.clone(),
        manifest,
        source_tree_sha256: tree.sha256,
    })
}

fn verify_required_object(
    id: &str,
    rule: &RequiredPatch,
    version: &Version,
    object: &SeededGitObject,
) -> Result<()> {
    let upstream = decode_hex::<32>(&rule.upstream_checksum).map_err(|error| {
        Error::failure(format!(
            "required patch `{id}` has invalid configured upstream checksum: {error}"
        ))
    })?;
    let expected_tree = decode_hex::<32>(&rule.source_tree_sha256).map_err(|error| {
        Error::failure(format!(
            "required patch `{id}` has invalid configured source-tree digest: {error}"
        ))
    })?;
    if object.name != rule.name
        || object.version != *version
        || object.upstream_crates_io_checksum != upstream
        || object.git_url != rule.git_url
        || object.resolved_commit != rule.git_commit
        || object.source_tree_sha256 != expected_tree
    {
        return Err(Error::failure(format!(
            "seeded source object metadata does not match the exact identity and provenance required by `{id}`"
        )));
    }
    Ok(())
}

fn load_local_patch(patch: &PathPatch, catalog: &mut Catalog) -> Result<()> {
    let physical_root = fs::canonicalize(&patch.path).map_err(|error| {
        Error::failure(format!(
            "failed to resolve local patch `{}` at `{}`: {error}",
            patch.alias,
            patch.path.display()
        ))
    })?;
    let manifest = Manifest::load_path_dependency(&physical_root)?;
    if manifest.name != patch.package {
        return Err(Error::failure(format!(
            "local patch `{}` declares package `{}`, expected `{}`",
            patch.alias, manifest.name, patch.package
        )));
    }
    let tree = Tree::scan(&manifest.root, DEFAULT_LIMITS, Exclusions::GitAndTarget)?;
    catalog.insert_path_patch(
        manifest,
        physical_root.clone(),
        physical_root,
        tree.sha256,
        None,
    )
}

fn validate_distinct_guards(rules: &BTreeMap<String, RequiredPatch>) -> Result<()> {
    let mut seen: BTreeMap<(String, Version), (&str, &Path)> = BTreeMap::new();
    for (id, rule) in rules {
        let version = exact_version(&rule.version)?;
        if let Some((other, provenance)) =
            seen.insert((rule.name.clone(), version.clone()), (id, &rule.provenance))
        {
            return Err(Error::failure(format!(
                "required patch `{id}` from `{}` conflicts with `{other}` from `{}`: both guard `{} {version}`",
                rule.provenance.display(),
                provenance.display(),
                rule.name
            )));
        }
    }
    Ok(())
}

fn exact_version(requirement: &VersionReq) -> Result<Version> {
    let [comparator] = requirement.comparators.as_slice() else {
        return Err(Error::failure(
            "required patch version is not one exact major.minor.patch version",
        ));
    };
    let (Op::Exact, Some(minor), Some(patch)) = (comparator.op, comparator.minor, comparator.patch)
    else {
        return Err(Error::failure(
            "required patch version is not one exact major.minor.patch version",
        ));
    };
    let mut version = Version::new(comparator.major, minor, patch);
    version.pre = comparator.pre.clone();
    Ok(version)
}

fn logical_root(package_root: &Path, id: &str) -> PathBuf {
    normalize_path(
        &package_root
            .join(".lorry")
            .join("vendor")
            .join(id)
            .join("source"),
    )
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

fn required_manifest_error(id: &str, rule: &RequiredPatch) -> String {
    format!(
        "required patch `{id}` from `{}` applies, but Cargo.toml does not contain the required root path patch\n\
         add this exact entry:\n\
         [patch.crates-io]\n\
         {} = {{ path = \".lorry/vendor/{id}/source\" }}\n\
         then run `lorry vendor` to populate an approved repository",
        rule.provenance.display(),
        rule.name
    )
}

fn required_source_error(id: &str, rule: &RequiredPatch, error: Error) -> String {
    format!(
        "required patch `{id}` from `{}` cannot use its verified source: {error}\n\
         run `lorry vendor`; if this is a system seed, repair it with the host seeder",
        rule.provenance.display()
    )
}

fn required_cargo_source_error(id: &str, rule: &RequiredPatch, error: Error) -> String {
    format!(
        "required patch `{id}` from `{}` cannot use its declared Cargo path: {error}\n\
         materialize the verified source at `.lorry/vendor/{id}/source` before using --use-cargo-registry",
        rule.provenance.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Repositories;
    use crate::hash::hex;
    use crate::offline;
    use crate::repository::Layer;
    use crate::resolver::{Options, ResolvedSource, resolve};
    use crate::source_tree::Limits;
    use crate::sparse::Record;
    use std::sync::atomic::{AtomicU64, Ordering};

    const UPSTREAM: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const COMMIT: &str = "1111111111111111111111111111111111111111";
    const GIT_URL: &str = "https://github.com/moturus/ring.git";
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

        fn package(&self, relative: &str, name: &str, version: &str) -> PathBuf {
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
            root
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn root(root: &Path, dependencies: &str, patches: &str) -> Manifest {
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "").unwrap();
        fs::write(
            root.join("Cargo.toml"),
            format!(
                "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [dependencies]\n{dependencies}\n{patches}"
            ),
        )
        .unwrap();
        fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"root\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        Manifest::load(root).unwrap()
    }

    fn registry(name: &str, version: &str) -> Record {
        let checksum = "44".repeat(32);
        Record::parse(
            Path::new("/index-record.json"),
            format!(
                "{{\"name\":\"{name}\",\"vers\":\"{version}\",\"deps\":[],\
                 \"cksum\":\"{checksum}\",\"features\":{{}},\"yanked\":false}}\n"
            )
            .as_bytes(),
        )
        .unwrap()
    }

    fn rule(digest: &str, provenance: &Path) -> RequiredPatch {
        RequiredPatch {
            name: "ring".to_owned(),
            version: VersionReq::parse("=0.17.14").unwrap(),
            upstream_checksum: UPSTREAM.to_owned(),
            git_url: GIT_URL.to_owned(),
            git_commit: COMMIT.to_owned(),
            source_tree_sha256: digest.to_owned(),
            provenance: provenance.to_owned(),
        }
    }

    fn options() -> Options {
        Options {
            resolver: crate::manifest::Resolver::V2,
            incompatible_rust_versions: None,
            rust_version: Version::parse("1.85.0").unwrap(),
            max_packages: 16,
            max_depth: 8,
        }
    }

    fn empty_repositories() -> RepositorySet {
        RepositorySet::open(
            &Repositories::default(),
            Limits {
                max_entries: 100,
                max_path_bytes: 1024,
                max_file_bytes: 1024 * 1024,
                max_tree_bytes: 1024 * 1024,
            },
            1024 * 1024,
        )
        .unwrap()
    }

    #[test]
    fn ordinary_path_patch_shadows_the_same_registry_version() {
        let fixture = Fixture::new();
        fixture.package("patched", "demo", "1.2.3");
        let manifest = root(
            &fixture.0.join("root"),
            "demo = \"=1.2.3\"",
            "[patch.crates-io]\ndemo = { path = \"../patched\" }\n",
        );
        let mut catalog = Catalog::default();
        catalog.insert(registry("demo", "1.2.3")).unwrap();
        configure(
            &manifest,
            &Config::default(),
            &empty_repositories(),
            &mut catalog,
        )
        .unwrap();

        let resolution = resolve(&manifest, &catalog, &options(), &[]).unwrap();
        assert!(matches!(
            resolution.packages[0].source,
            ResolvedSource::Path {
                patched_crates_io: true,
                ..
            }
        ));
    }

    #[test]
    fn missing_required_patch_is_reported_only_when_its_version_is_selected() {
        let fixture = Fixture::new();
        let manifest = root(&fixture.0.join("selected"), "ring = \"=0.17.14\"", "");
        let mut config = Config::default();
        config.required_patches.insert(
            "ring-0_17_14".to_owned(),
            rule(&"55".repeat(32), Path::new("/system/lorry.toml")),
        );
        let mut catalog = Catalog::default();
        catalog.insert(registry("ring", "0.17.14")).unwrap();
        configure(&manifest, &config, &empty_repositories(), &mut catalog).unwrap();
        let error = resolve(&manifest, &catalog, &options(), &[]).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("/system/lorry.toml"));
        assert!(message.contains("[patch.crates-io]"));
        assert!(message.contains("ring = { path = \".lorry/vendor/ring-0_17_14/source\" }"));
        assert!(message.contains("lorry vendor"));

        let unselected = root(&fixture.0.join("unselected"), "", "");
        let mut catalog = Catalog::default();
        configure(&unselected, &config, &empty_repositories(), &mut catalog).unwrap();
        resolve(&unselected, &catalog, &options(), &[]).unwrap();
    }

    #[test]
    fn verified_seeded_object_binds_logical_and_physical_paths() {
        let fixture = Fixture::new();
        let repository = fixture.0.join("repository");
        fs::create_dir_all(&repository).unwrap();
        fs::write(
            repository.join("repository.toml"),
            "format-version = 1\nobject-hash = \"sha256\"\n",
        )
        .unwrap();
        let staging = fixture.package("seed", "ring", "0.17.14");
        fs::write(
            staging.join("Cargo.toml"),
            "[package]\nname = \"ring\"\nversion = \"0.17.14\"\n\
             edition = \"2021\"\nlicense = \"Apache-2.0 AND ISC\"\n",
        )
        .unwrap();
        let tree = Tree::scan(&staging, DEFAULT_LIMITS, Exclusions::None).unwrap();
        let digest = hex(&tree.sha256);
        let object = repository
            .join("objects/seeded-git/sha256")
            .join(&digest[..2])
            .join(&digest);
        fs::create_dir_all(&object).unwrap();
        fs::rename(&staging, object.join("source")).unwrap();
        fs::write(object.join("source-manifest.json"), tree.manifest_bytes()).unwrap();
        fs::write(
            object.join("package.toml"),
            format!(
                "format-version = 1\n\
                 name = \"ring\"\n\
                 version = \"0.17.14\"\n\
                 cargo-source = \"git+{GIT_URL}?branch=motor-os-0.17.14#{COMMIT}\"\n\
                 git-url = \"{GIT_URL}\"\n\
                 requested-revision = \"motor-os-0.17.14\"\n\
                 resolved-commit = \"{COMMIT}\"\n\
                 git-tree = \"2222222222222222222222222222222222222222\"\n\
                 upstream-crates-io-checksum = \"{UPSTREAM}\"\n\
                 source-tree-sha256 = \"{digest}\"\n\
                 license = \"Apache-2.0 AND ISC\"\n\
                 extracted-bytes = {}\n\
                 file-count = {}\n\
                 directory-count = {}\n\
                 retained-source = true\n",
                tree.total_bytes, tree.file_count, tree.directory_count
            ),
        )
        .unwrap();

        let project = fixture.0.join("project");
        root(
            &project,
            "ring = \"=0.17.14\"",
            "[patch.crates-io]\nring = { path = \".lorry/vendor/ring-0_17_14/source\" }\n",
        );
        fs::write(
            project.join("Cargo.lock"),
            "version = 4\n\n\
             [[package]]\nname = \"ring\"\nversion = \"0.17.14\"\n\n\
             [[package]]\nname = \"root\"\nversion = \"0.1.0\"\ndependencies = [\"ring\"]\n",
        )
        .unwrap();
        let manifest = Manifest::load(&project).unwrap();
        let mut config = Config::default();
        config.repositories.local = Some(repository.clone());
        config.required_patches.insert(
            "ring-0_17_14".to_owned(),
            rule(&digest, Path::new("/system/lorry.toml")),
        );
        let repositories =
            RepositorySet::open(&config.repositories, DEFAULT_LIMITS, 1024 * 1024).unwrap();
        let mut catalog = Catalog::default();
        catalog.insert(registry("ring", "0.17.14")).unwrap();
        configure(&manifest, &config, &repositories, &mut catalog).unwrap();
        assert!(catalog.contains_required_patch("ring-0_17_14"));

        let resolution = resolve(&manifest, &catalog, &options(), &[]).unwrap();
        let ResolvedSource::Path {
            logical_root,
            physical_root,
            source_tree_sha256,
            patched_crates_io,
            required_patch,
        } = &resolution.packages[0].source
        else {
            panic!("required patch did not resolve as a path source");
        };
        assert!(logical_root.ends_with(".lorry/vendor/ring-0_17_14/source"));
        assert_eq!(physical_root, &object.join("source"));
        assert_eq!(*source_tree_sha256, tree.sha256);
        assert!(*patched_crates_io);
        assert_eq!(required_patch.as_deref(), Some("ring-0_17_14"));
        offline::validate_resolution(&manifest, &resolution).unwrap();
        assert_eq!(
            repositories
                .lookup_seeded_git(&digest)
                .unwrap()
                .unwrap()
                .layer,
            Layer::Local
        );

        let mut wrong = config.clone();
        wrong
            .required_patches
            .get_mut("ring-0_17_14")
            .unwrap()
            .upstream_checksum = "66".repeat(32);
        let mut rejected = Catalog::default();
        rejected.insert(registry("ring", "0.17.14")).unwrap();
        configure(&manifest, &wrong, &repositories, &mut rejected).unwrap();
        let error = resolve(&manifest, &rejected, &options(), &[]).unwrap_err();
        assert!(error.to_string().contains("exact identity and provenance"));
        assert!(!rejected.contains_required_patch("ring-0_17_14"));
    }

    #[test]
    fn cargo_registry_mode_uses_the_materialized_required_patch_path() {
        let fixture = Fixture::new();
        let project = fixture.0.join("project");
        root(
            &project,
            "ring = \"=0.17.14\"",
            "[patch.crates-io]\nring = { path = \".lorry/vendor/ring-0_17_14/source\" }\n",
        );
        let source = fixture.package(
            "project/.lorry/vendor/ring-0_17_14/source",
            "ring",
            "0.17.14",
        );
        fs::write(
            project.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"ring\"\nversion = \"0.17.14\"\n\n\
             [[package]]\nname = \"root\"\nversion = \"0.1.0\"\n\
             dependencies = [\"ring\"]\n",
        )
        .unwrap();
        let manifest = Manifest::load(&project).unwrap();
        let tree = Tree::scan(&source, DEFAULT_LIMITS, Exclusions::GitAndTarget).unwrap();
        let mut config = Config::default();
        config.required_patches.insert(
            "ring-0_17_14".to_owned(),
            rule(&hex(&tree.sha256), Path::new("/system/lorry.toml")),
        );
        let mut catalog = Catalog::default();
        configure_cargo_registry(&manifest, &config, &mut catalog).unwrap();
        assert!(catalog.contains_required_patch("ring-0_17_14"));

        fs::write(source.join("src/lib.rs"), "pub fn changed() {}\n").unwrap();
        let manifest = Manifest::load(&project).unwrap();
        let mut catalog = Catalog::default();
        configure_cargo_registry(&manifest, &config, &mut catalog).unwrap();
        let error = resolve(&manifest, &catalog, &options(), &[]).unwrap_err();
        assert!(error.to_string().contains("declared Cargo path"));
        assert!(error.to_string().contains("source-tree digest"));
    }

    #[test]
    fn binds_the_external_ring_seed_when_requested() {
        let Some(repository) = std::env::var_os("LORRY_TEST_SEEDED_REPOSITORY") else {
            return;
        };
        let fixture = Fixture::new();
        let manifest = root(
            &fixture.0.join("project"),
            "ring = \"=0.17.14\"",
            "[patch.crates-io]\nring = { path = \".lorry/vendor/ring-0_17_14/source\" }\n",
        );
        let mut config = Config::default();
        config.repositories.local = Some(PathBuf::from(repository));
        config.required_patches.insert(
            "ring-0_17_14".to_owned(),
            RequiredPatch {
                name: "ring".to_owned(),
                version: VersionReq::parse("=0.17.14").unwrap(),
                upstream_checksum:
                    "a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7".to_owned(),
                git_url: "https://github.com/moturus/ring.git".to_owned(),
                git_commit: "b1dad2579de791d0c31ad33300187e584ba6c268".to_owned(),
                source_tree_sha256:
                    "776e07288265b7ececb54ef5ed914c3a6093f00b49bd4d12d34764325659b351".to_owned(),
                provenance: PathBuf::from("/system/lorry.toml"),
            },
        );
        let repositories =
            RepositorySet::open(&config.repositories, DEFAULT_LIMITS, 16 * 1024 * 1024).unwrap();
        let mut catalog = Catalog::default();
        configure(&manifest, &config, &repositories, &mut catalog).unwrap();
        assert!(catalog.contains_required_patch("ring-0_17_14"));
    }
}
