use crate::cli::{CleanOptions, Verbosity};
use crate::config::Config;
use crate::diagnostic::{Error, Result};
use crate::resolver::PackageKey;
use std::env;
use std::fs;
use std::path::Path;

pub fn execute(options: &CleanOptions, package: Option<&str>, verbosity: Verbosity) -> Result<i32> {
    let current = env::current_dir()
        .map_err(|error| Error::failure(format!("failed to read current directory: {error}")))?;
    let manifest = crate::manifest::Manifest::load_selected(&current, package)?;
    let config = Config::load(&current, &manifest)?;
    let target_directory = config.target_directory(
        &current,
        &manifest.workspace_root,
        options.build.target_dir.as_deref(),
    );
    let _artifact_lock = crate::artifact_lock::ArtifactLock::acquire(&target_directory)?;
    let artifact_root = super::engine::artifact_root_in(&manifest, &target_directory);

    let target = if options.build.release || options.build.target.is_some() {
        config.selected_target(options.build.target.as_deref())?
    } else {
        None
    };
    if (package.is_some() || options.build.release || target.is_some()) && artifact_root.exists() {
        crate::engine::migrate_artifact_layout(&artifact_root)?;
    }
    let removed = clean_manifest_artifacts(
        &manifest,
        &target_directory,
        options.build.release,
        target.as_deref(),
        package.is_some(),
    )?;
    if verbosity != Verbosity::Quiet {
        if removed {
            eprintln!("Removed Lorry artifacts from `{}`", artifact_root.display());
        } else {
            eprintln!("Removed 0 Lorry artifacts");
        }
    }
    Ok(0)
}

#[cfg(test)]
fn clean_artifacts(root: &Path, release: bool, target: Option<&str>) -> Result<bool> {
    clean_artifacts_root(&root.join("target/lorry"), release, target)
}

fn clean_manifest_artifacts(
    manifest: &crate::manifest::Manifest,
    target_parent: &Path,
    release: bool,
    target: Option<&str>,
    package_selected: bool,
) -> Result<bool> {
    if package_selected {
        if !real_directory(target_parent, "artifact parent")? {
            return Ok(false);
        }
        let package = crate::unit::selected_library_key(manifest)?.package;
        return clean_package_artifacts(
            &target_parent.join("lorry"),
            manifest,
            &package,
            release,
            target,
        );
    }
    clean_artifacts_root(&target_parent.join("lorry"), release, target)
}

fn clean_package_artifacts(
    root: &Path,
    manifest: &crate::manifest::Manifest,
    package: &PackageKey,
    release: bool,
    target: Option<&str>,
) -> Result<bool> {
    if !real_directory(root, "Lorry artifact root")? {
        return Ok(false);
    }
    let mut profile = root.to_owned();
    if let Some(target) = target {
        profile.push(target);
    }
    profile.push(if release { "release" } else { "debug" });
    let mut removed = false;
    if real_directory(&profile, "selected profile")? {
        let package_units = profile.join("build").join(&package.name);
        if real_directory(&package_units, "package unit directory")? {
            for child in fs::read_dir(&package_units)
                .map_err(|error| Error::failure(format!("failed to list package units: {error}")))?
            {
                let path = child
                    .map_err(|error| {
                        Error::failure(format!("failed to read package unit: {error}"))
                    })?
                    .path();
                if real_directory(&path, "package unit")?
                    && crate::artifact_owner::matches(&path, package)
                {
                    remove_directory(&path)?;
                    removed = true;
                }
            }
        }
        for child in fs::read_dir(&profile)
            .map_err(|error| Error::failure(format!("failed to list profile: {error}")))?
        {
            let child = child
                .map_err(|error| Error::failure(format!("failed to read profile: {error}")))?;
            let name = child.file_name();
            let Some(primary_name) = name
                .to_str()
                .and_then(|name| name.strip_suffix(crate::artifact_owner::PRIMARY_SUFFIX))
            else {
                continue;
            };
            let primary = profile.join(primary_name);
            if crate::artifact_owner::matches_primary(&primary, package) {
                if primary.exists() {
                    fs::remove_file(&primary).map_err(|error| {
                        Error::failure(format!(
                            "failed to remove primary artifact `{}`: {error}",
                            primary.display()
                        ))
                    })?;
                }
                fs::remove_file(child.path()).map_err(|error| {
                    Error::failure(format!("failed to remove primary owner: {error}"))
                })?;
                removed = true;
            }
        }
        let freshness = crate::engine::fresh_record_path(&profile, &manifest.root);
        if freshness.exists() {
            fs::remove_file(&freshness).map_err(|error| {
                Error::failure(format!(
                    "failed to remove package freshness record: {error}"
                ))
            })?;
            removed = true;
        }
    }
    let units = root.join(".cache/v1/units/sha256");
    if real_directory(&units, "project unit cache")? {
        for prefix in fs::read_dir(&units)
            .map_err(|error| Error::failure(format!("failed to list project cache: {error}")))?
        {
            let prefix = prefix
                .map_err(|error| Error::failure(format!("failed to read cache prefix: {error}")))?
                .path();
            if !real_directory(&prefix, "cache prefix")? {
                continue;
            }
            for entry in fs::read_dir(&prefix)
                .map_err(|error| Error::failure(format!("failed to list cache prefix: {error}")))?
            {
                let entry = entry
                    .map_err(|error| {
                        Error::failure(format!("failed to read cache entry: {error}"))
                    })?
                    .path();
                if real_directory(&entry, "cache entry")?
                    && crate::artifact_owner::matches(&entry, package)
                {
                    remove_directory(&entry)?;
                    removed = true;
                }
            }
        }
    }
    Ok(removed)
}

fn clean_artifacts_root(root: &Path, release: bool, target: Option<&str>) -> Result<bool> {
    let parent = root
        .parent()
        .ok_or_else(|| Error::failure("artifact root has no parent"))?;
    if !real_directory(parent, "artifact parent")? || !real_directory(root, "Lorry artifact root")?
    {
        return Ok(false);
    }
    if !release && target.is_none() {
        remove_directory(root)?;
        return Ok(true);
    }
    let mut selected_parent = root.to_owned();
    if let Some(target) = target {
        selected_parent.push(target);
        real_directory(&selected_parent, "target artifact directory")?;
    }
    let selected = if release {
        selected_parent.join("release")
    } else {
        selected_parent
    };
    let selected_exists = real_directory(&selected, "selected artifact directory")?;
    let cache = root.join(".cache");
    let cache_exists = real_directory(&cache, "Lorry artifact cache")?;
    if selected_exists {
        remove_directory(&selected)?;
    }
    if cache_exists && cache != selected {
        remove_directory(&cache)?;
    }
    Ok(selected_exists || cache_exists)
}

fn real_directory(path: &Path, description: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(Error::failure(format!(
                "refusing to clean {description} `{}` because it is not a real directory",
                path.display()
            )))
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::failure(format!(
            "failed to inspect {description} `{}`: {error}",
            path.display()
        ))),
    }
}

fn remove_directory(path: &Path) -> Result<()> {
    fs::remove_dir_all(path).map_err(|error| {
        Error::failure(format!(
            "failed to remove Lorry artifacts `{}`: {error}",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(label: &str) -> Self {
            let path = env::temp_dir().join(format!(
                "lorry-clean-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn directory(&self, relative: &str) -> PathBuf {
            let path = self.0.join(relative);
            fs::create_dir_all(&path).unwrap();
            path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn cleans_only_lorrys_complete_artifact_root() {
        let fixture = Fixture::new("all");
        fixture.directory("target/debug");
        fixture.directory("target/lorry/debug/deps");
        fixture.directory("target/lorry/.cache/objects");
        fixture.directory("global-cache/v1/units");

        assert!(clean_artifacts(&fixture.0, false, None).unwrap());
        assert!(!fixture.0.join("target/lorry").exists());
        assert!(fixture.0.join("target/debug").is_dir());
        assert!(fixture.0.join("global-cache/v1/units").is_dir());
        assert!(!clean_artifacts(&fixture.0, false, None).unwrap());
    }

    #[test]
    fn selective_clean_removes_profile_and_project_cache() {
        let fixture = Fixture::new("release");
        fixture.directory("target/lorry/debug");
        fixture.directory("target/lorry/release/deps");
        fixture.directory("target/lorry/.cache/objects");

        assert!(clean_artifacts(&fixture.0, true, None).unwrap());
        assert!(fixture.0.join("target/lorry/debug").is_dir());
        assert!(!fixture.0.join("target/lorry/release").exists());
        assert!(!fixture.0.join("target/lorry/.cache").exists());

        fixture.directory("target/lorry/x86_64-unknown-motor/debug/deps");
        fixture.directory("target/lorry/x86_64-unknown-motor/release/deps");
        assert!(clean_artifacts(&fixture.0, false, Some("x86_64-unknown-motor")).unwrap());
        assert!(!fixture.0.join("target/lorry/x86_64-unknown-motor").exists());
        assert!(fixture.0.join("target/lorry/debug").is_dir());
    }

    #[test]
    fn unselected_clean_removes_the_shared_artifact_tree() {
        let fixture = Fixture::new("workspace");
        fs::create_dir_all(fixture.0.join("app/src")).unwrap();
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        fs::write(
            fixture.0.join("app/Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(fixture.0.join("app/src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(
            fixture.0.join("Cargo.lock"),
            "version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fixture.directory("target/lorry/debug/build/app");
        fixture.directory("target/lorry/debug/build/other");
        let manifest = crate::manifest::Manifest::load_selected(&fixture.0, Some("app")).unwrap();
        assert_eq!(
            Config::default().target_directory(&manifest.root, &manifest.workspace_root, None),
            fixture.0.join("target")
        );
        assert_eq!(
            Config::default().target_directory(
                &manifest.root,
                &manifest.workspace_root,
                Some("editor-target"),
            ),
            manifest.root.join("editor-target")
        );

        assert!(
            clean_manifest_artifacts(&manifest, &fixture.0.join("target"), false, None, false)
                .unwrap()
        );
        assert!(!fixture.0.join("target/lorry").exists());

        fixture.directory("editor-target/lorry/debug/build/app");
        fixture.directory("editor-target/lorry/debug/build/other");
        assert!(
            clean_manifest_artifacts(
                &manifest,
                &fixture.0.join("editor-target"),
                false,
                None,
                false
            )
            .unwrap()
        );
        assert!(!fixture.0.join("editor-target/lorry").exists());
    }

    #[test]
    fn package_clean_preserves_other_owners_and_release_outputs() {
        let fixture = Fixture::new("package");
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fixture.directory("src");
        fs::write(fixture.0.join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(
            fixture.0.join("Cargo.lock"),
            "version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let manifest = crate::manifest::Manifest::load_selected(&fixture.0, None).unwrap();
        let package = crate::unit::selected_library_key(&manifest)
            .unwrap()
            .package;
        let other = PackageKey {
            source: crate::resolver::PackageSourceKey::Path(fixture.0.join("other")),
            ..package.clone()
        };
        let owned = fixture.directory("target/lorry/debug/build/app/owned");
        let foreign = fixture.directory("target/lorry/debug/build/app/foreign");
        let release = fixture.directory("target/lorry/release/build/app/owned");
        crate::artifact_owner::write(&owned, &package).unwrap();
        crate::artifact_owner::write(&foreign, &other).unwrap();
        crate::artifact_owner::write(&release, &package).unwrap();
        let cache_owned = fixture.directory("target/lorry/.cache/v1/units/sha256/aa/owned");
        let cache_foreign = fixture.directory("target/lorry/.cache/v1/units/sha256/bb/foreign");
        crate::artifact_owner::write(&cache_owned, &package).unwrap();
        crate::artifact_owner::write(&cache_foreign, &other).unwrap();
        let profile = fixture.0.join("target/lorry/debug");
        let primary = profile.join("app");
        let other_primary = profile.join("other");
        fs::write(&primary, b"app").unwrap();
        fs::write(&other_primary, b"other").unwrap();
        crate::artifact_owner::write_primary(&primary, &package).unwrap();
        crate::artifact_owner::write_primary(&other_primary, &other).unwrap();
        let fresh = crate::engine::fresh_record_path(&profile, &manifest.root);
        fs::write(&fresh, b"record").unwrap();

        assert!(
            clean_manifest_artifacts(&manifest, &fixture.0.join("target"), false, None, true,)
                .unwrap()
        );
        assert!(!owned.exists());
        assert!(foreign.exists());
        assert!(release.exists());
        assert!(!cache_owned.exists());
        assert!(cache_foreign.exists());
        assert!(!primary.exists());
        assert!(other_primary.exists());
        assert!(!fresh.exists());
    }

    #[test]
    fn cleans_a_custom_target_directory_only() {
        let fixture = Fixture::new("custom-target");
        fixture.directory("target/lorry/debug");
        let custom = fixture.directory("editor-target/lorry/debug");

        assert!(clean_artifacts_root(custom.parent().unwrap(), false, None).unwrap());
        assert!(!fixture.0.join("editor-target/lorry").exists());
        assert!(fixture.0.join("target/lorry/debug").is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlinked_artifact_root() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new("symlink");
        let outside = fixture.directory("outside");
        fixture.directory("target");
        symlink(&outside, fixture.0.join("target/lorry")).unwrap();

        let error = clean_artifacts(&fixture.0, false, None).unwrap_err();
        assert!(error.render().contains("not a real directory"));
        assert!(outside.is_dir());
    }
}
