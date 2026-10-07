use std::fs;
use std::path::{Path, PathBuf};

use gix::glob::pattern::Case;
use gix::ignore::Search;

use crate::diagnostic::{Error, Result};
use crate::hash::{FieldDigest, modified_time, sha256_file};
use crate::manifest::Manifest;
use crate::source_tree::{DEFAULT_LIMITS, Limits};

pub(crate) struct Snapshot {
    pub sha256: [u8; 32],
    pub bytes: u64,
    pub files: u64,
}

pub(crate) fn snapshot(manifest: &Manifest, strict: bool) -> Result<Snapshot> {
    snapshot_within(manifest, strict, DEFAULT_LIMITS)
}

// Members are trusted, but a link out of the package must not make Lorry
// walk or hash a whole filesystem. Path packages use the same limits.
fn snapshot_within(manifest: &Manifest, strict: bool, limits: Limits) -> Result<Snapshot> {
    let mut hash = FieldDigest::tagged(b"lorry-editable-source-v1\0");
    let mut bytes = 0_u64;
    let mut count = 0;
    for path in collect(manifest, limits.max_entries)? {
        let relative = path.strip_prefix(&manifest.root).unwrap();
        hash.field(relative.as_os_str().as_encoded_bytes());
        let metadata = match fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => metadata,
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                hash.field(b"absent");
                continue;
            }
            Err(error) => return Err(io_error(&path, error)),
        };
        let resolved = fs::canonicalize(&path).map_err(|error| io_error(&path, error))?;
        let identity = resolved
            .strip_prefix(&manifest.workspace_root)
            .unwrap_or(&resolved);
        bytes = bytes
            .checked_add(metadata.len())
            .filter(|bytes| *bytes <= limits.max_tree_bytes)
            .ok_or_else(|| limit_error(manifest, format!("{} bytes", limits.max_tree_bytes)))?;
        hash.field(identity.as_os_str().as_encoded_bytes());
        hash.field(&metadata.len().to_le_bytes());
        if strict {
            hash.field(&sha256_file(&path)?);
        } else {
            let modified = modified_time(&path, &metadata)?;
            hash.field(&modified.as_secs().to_le_bytes());
            hash.field(&modified.subsec_nanos().to_le_bytes());
        }
        count += 1;
    }
    Ok(Snapshot {
        sha256: hash.finish(),
        bytes,
        files: count,
    })
}

fn limit_error(manifest: &Manifest, limit: String) -> Error {
    Error::failure(format!(
        "editable package `{}` exceeds the source limit of {limit}",
        manifest.name
    ))
    .with_help("exclude large files with `package.exclude`, or remove links that leave the package")
}

#[cfg(test)]
fn files(manifest: &Manifest) -> Result<Vec<PathBuf>> {
    collect(manifest, DEFAULT_LIMITS.max_entries)
}

fn collect(manifest: &Manifest, max_files: usize) -> Result<Vec<PathBuf>> {
    // Cargo uses Git ignores only when the manifest is tracked and no include
    // list replaces that discovery. A plain directory excludes dotfiles.
    let include = manifest.metadata.include.as_deref().unwrap_or_default();
    let repo = if include.is_empty() {
        tracked_repository(&manifest.root)?
    } else {
        None
    };
    let mut excludes = Vec::new();
    if include.is_empty() && repo.is_none() {
        excludes.push(".*".to_owned());
    }
    excludes.extend(manifest.metadata.exclude.clone().unwrap_or_default());
    let filter = FileFilter {
        manifest,
        max_files,
        root: &manifest.root,
        include: (!include.is_empty()).then(|| Search::from_overrides(include, Default::default())),
        exclude: Search::from_overrides(excludes, Default::default()),
    };
    let mut files = Vec::new();
    if let Some(repo) = repo {
        git_files(&repo, &filter, &mut Vec::new(), &mut files)?;
    } else {
        walk(&manifest.root, &filter, &mut Vec::new(), &mut files)?;
    }
    files.sort();
    files.dedup();
    Ok(files)
}

fn tracked_repository(root: &Path) -> Result<Option<gix::Repository>> {
    let Ok(repo) = gix::discover(root) else {
        return Ok(None);
    };
    let Some(workdir) = repo.workdir() else {
        return Ok(None);
    };
    let Ok(relative) = root.strip_prefix(workdir) else {
        return Ok(None);
    };
    let index = repo
        .index_or_empty()
        .map_err(|error| Error::failure(error.to_string()))?;
    let path = gix::path::into_bstr(relative.join("Cargo.toml"));
    if index.entry_index_by_path(&path).is_err() {
        return Ok(None);
    }
    Ok(Some(repo))
}

struct FileFilter<'a> {
    manifest: &'a Manifest,
    max_files: usize,
    root: &'a Path,
    include: Option<Search>,
    exclude: Search,
}

impl FileFilter<'_> {
    fn push(&self, files: &mut Vec<PathBuf>, path: PathBuf) -> Result<()> {
        if files.len() >= self.max_files {
            return Err(limit_error(
                self.manifest,
                format!("{} files", self.max_files),
            ));
        }
        files.push(path);
        Ok(())
    }

    fn accepts(&self, path: &Path, directory: bool) -> bool {
        let Ok(relative) = path.strip_prefix(self.root) else {
            return false;
        };
        if matches!(relative.to_str(), Some("Cargo.toml" | "Cargo.lock")) {
            return true;
        }
        match &self.include {
            Some(include) => directory || matches_patterns(include, relative, false),
            None => !matches_patterns(&self.exclude, relative, directory),
        }
    }
}

fn matches_patterns(patterns: &Search, path: &Path, mut directory: bool) -> bool {
    // A directory rule also covers its children; a nearer negation wins.
    for relative in path
        .ancestors()
        .take_while(|path| !path.as_os_str().is_empty())
    {
        if let Some(matched) = patterns.pattern_matching_relative_path(
            relative.as_os_str().as_encoded_bytes().into(),
            Some(directory),
            Case::Sensitive,
        ) {
            return !matched.pattern.is_negative();
        }
        directory = true;
    }
    false
}

fn walk(
    path: &Path,
    filter: &FileFilter<'_>,
    ancestors: &mut Vec<PathBuf>,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    let directory = path.is_dir();
    if path != filter.root && !filter.accepts(path, directory) {
        return Ok(());
    }
    if !directory {
        return filter.push(files, path.to_owned());
    }
    if path != filter.root
        && (path.join("Cargo.toml").exists() || path == filter.root.join("target"))
    {
        return Ok(());
    }
    let resolved = fs::canonicalize(path).map_err(|error| io_error(path, error))?;
    if ancestors.contains(&resolved) {
        return Ok(());
    }
    ancestors.push(resolved);
    for child in fs::read_dir(path).map_err(|error| io_error(path, error))? {
        let child = child.map_err(|error| io_error(path, error))?;
        walk(&child.path(), filter, ancestors, files)?;
    }
    ancestors.pop();
    Ok(())
}

fn git_files(
    repo: &gix::Repository,
    filter: &FileFilter<'_>,
    ancestors: &mut Vec<PathBuf>,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    use gix_dir::{
        entry::{Kind, Status},
        walk::EmissionMode,
    };
    let root = repo
        .workdir()
        .ok_or_else(|| Error::failure("editable repository is bare"))?;
    let resolved = fs::canonicalize(root).map_err(|error| io_error(root, error))?;
    if ancestors.contains(&resolved) {
        return Ok(());
    }
    ancestors.push(resolved);
    let prefix = filter.root.strip_prefix(root).unwrap_or(Path::new(""));
    let index = repo
        .index_or_empty()
        .map_err(|error| Error::failure(error.to_string()))?;
    let target = gix::path::into_bstr(prefix.join("target/"));
    let capabilities = repo
        .filesystem_options()
        .map_err(|error| Error::failure(error.to_string()))?;
    let lookup = capabilities
        .ignore_case
        .then(|| index.prepare_icase_backing());
    let patterns = [
        format!(":(top){}", prefix.display()),
        format!(":!(exclude,top){}", target),
    ];
    let mut pathspec = repo
        .pathspec(
            false,
            patterns.iter().map(gix::bstr::BStr::new),
            true,
            &index,
            gix::worktree::stack::state::attributes::Source::WorktreeThenIdMapping,
        )
        .map_err(|error| Error::failure(error.to_string()))?
        .search()
        .clone();
    let mut excludes = repo
        .excludes(
            &index,
            None,
            gix::worktree::stack::state::ignore::Source::WorktreeThenIdMappingIfNotSkipped,
        )
        .map_err(|error| Error::failure(error.to_string()))?
        .detach();
    let git_dir =
        fs::canonicalize(repo.git_dir()).map_err(|error| io_error(repo.git_dir(), error))?;
    let mut collected = gix_dir::walk::delegate::Collect::default();
    // Use Cargo's walker directly to avoid another level in the package graph.
    // These internally generated pathspecs never request attribute matching.
    gix_dir::walk(
        root,
        gix_dir::walk::Context {
            should_interrupt: None,
            git_dir_realpath: &git_dir,
            current_dir: repo.current_dir(),
            index: &index,
            ignore_case_index_lookup: lookup.as_ref(),
            pathspec: &mut pathspec,
            pathspec_attributes: &mut |_, _, _, _| false,
            excludes: Some(&mut excludes),
            objects: &repo.objects,
            explicit_traversal_root: Some(root),
        },
        gix_dir::walk::Options {
            precompose_unicode: capabilities.precompose_unicode,
            ignore_case: capabilities.ignore_case,
            emit_tracked: true,
            emit_untracked: EmissionMode::Matching,
            symlinks_to_directories_are_ignored_like_directories: true,
            ..Default::default()
        },
        &mut collected,
    )
    .map_err(|error| Error::failure(error.to_string()))?;
    let mut candidates = Vec::new();
    for (entry, _) in collected.unorded_entries {
        if entry.disk_kind == Some(Kind::Untrackable)
            || (entry.status == Status::Untracked && entry.rela_path == "Cargo.lock")
        {
            continue;
        }
        candidates.push(root.join(gix::path::from_bstr(entry.rela_path)));
    }
    candidates.extend(
        // Cargo retains explicitly tracked artifacts even under target/.
        index
            .prefixed_entries(&target)
            .unwrap_or_default()
            .iter()
            .filter(|entry| entry.stage() == gix::index::entry::Stage::Unconflicted)
            .map(|entry| root.join(gix::path::from_bstr(entry.path(&index)))),
    );
    let subpackages = candidates
        .iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "Cargo.toml"))
        .filter_map(|path| path.parent())
        .filter(|path| *path != filter.root)
        .map(Path::to_owned)
        .collect::<Vec<_>>();
    for path in candidates {
        if subpackages
            .iter()
            .any(|subpackage| path.starts_with(subpackage))
        {
            continue;
        }
        if path.is_dir() {
            if let Ok(repo) = gix::open(&path) {
                git_files(&repo, filter, ancestors, files)?;
            } else {
                walk(&path, filter, ancestors, files)?;
            }
        } else if filter.accepts(&path, false) {
            filter.push(files, path)?;
        }
    }
    ancestors.pop();
    Ok(())
}

fn io_error(path: &Path, error: std::io::Error) -> Error {
    Error::failure(format!(
        "failed to inspect editable source `{}`: {error}",
        path.display()
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn editable_sources_stop_at_the_path_package_limits() {
        let base = std::env::temp_dir().join(format!("lorry-member-limit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let root = base.join("member");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(base.join("outside")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"member\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), "").unwrap();
        for index in 0..4 {
            fs::write(base.join(format!("outside/{index}")), "0123456789").unwrap();
        }
        std::os::unix::fs::symlink(base.join("outside"), root.join("linked")).unwrap();
        let manifest = Manifest::load_for_vendor(&root).unwrap();
        let limits = |max_entries, max_tree_bytes| Limits {
            max_entries,
            max_tree_bytes,
            ..DEFAULT_LIMITS
        };
        let full = snapshot_within(&manifest, true, DEFAULT_LIMITS)
            .ok()
            .unwrap();
        assert_eq!(full.files, 6);
        assert!(snapshot_within(&manifest, true, limits(6, full.bytes)).is_ok());
        let files = snapshot_within(&manifest, true, limits(5, full.bytes))
            .err()
            .unwrap();
        assert!(files.render().contains("source limit of 5 files"));
        let bytes = snapshot_within(&manifest, false, limits(6, full.bytes - 1))
            .err()
            .unwrap();
        let expected = format!("source limit of {} bytes", full.bytes - 1);
        assert!(bytes.render().contains(&expected));
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn editable_files_follow_links_and_stop_at_other_packages() {
        let root = std::env::temp_dir().join(format!("lorry-member-files-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::create_dir_all(root.join("target")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"member\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn value() {}\n").unwrap();
        fs::write(root.join("value.txt"), "before").unwrap();
        fs::write(
            root.join("Cargo.lock"),
            "version = 4\n[[package]]\nname = \"member\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(root.join(".hidden"), "hidden").unwrap();
        fs::write(
            root.join("nested/Cargo.toml"),
            "[package]\nname = \"nested\"\n",
        )
        .unwrap();
        fs::write(root.join("nested/other"), "other package").unwrap();
        fs::write(root.join("target/output"), "artifact").unwrap();
        std::os::unix::fs::symlink("value.txt", root.join("linked.txt")).unwrap();
        std::os::unix::fs::symlink("src", root.join("linked-dir")).unwrap();
        let manifest = Manifest::load_for_vendor(&root).unwrap();
        let compare_cargo = |manifest: &Manifest| {
            let output = std::process::Command::new(env!("CARGO"))
                .args([
                    "package",
                    "--list",
                    "--offline",
                    "--allow-dirty",
                    "--manifest-path",
                ])
                .arg(&manifest.path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let mut cargo = String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .filter(|path| *path != "Cargo.toml.orig")
                .map(|path| root.join(path))
                .collect::<Vec<_>>();
            cargo.sort();
            assert_eq!(files(manifest).unwrap(), cargo);
        };
        compare_cargo(&manifest);
        let selected = files(&manifest).unwrap();
        assert!(selected.contains(&root.join("linked.txt")));
        assert!(selected.contains(&root.join("linked-dir/lib.rs")));
        assert!(!selected.contains(&root.join(".hidden")));
        assert!(
            !selected
                .iter()
                .any(|path| path.starts_with(root.join("nested"))
                    || path.starts_with(root.join("target")))
        );
        let before = snapshot(&manifest, true).unwrap();
        fs::write(root.join("nested/other"), "ignored edit").unwrap();
        assert_eq!(before.sha256, snapshot(&manifest, true).unwrap().sha256);
        fs::write(root.join("value.txt"), "after!").unwrap();
        assert_ne!(before.sha256, snapshot(&manifest, true).unwrap().sha256);
        let mut included = manifest.clone();
        included.metadata.include = Some(vec![
            "/src/**".into(),
            "/linked.txt".into(),
            "/.hidden".into(),
        ]);
        included.metadata.exclude = Some(vec!["*".into()]);
        assert_eq!(
            files(&included).unwrap(),
            [
                ".hidden",
                "Cargo.lock",
                "Cargo.toml",
                "linked.txt",
                "src/lib.rs"
            ]
            .map(|path| root.join(path))
        );
        fs::write(&included.path, fs::read_to_string(&included.path).unwrap().replace(
            "edition = \"2024\"", "edition = \"2024\"\ninclude = [\"/src/**\", \"/linked.txt\", \"/.hidden\"]\nexclude = [\"*\"]"
        )).unwrap();
        compare_cargo(&included);
        fs::write(
            &manifest.path,
            "[package]\nname = \"member\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        for arguments in [
            &["init", "--quiet"][..],
            &["add", "Cargo.toml", "Cargo.lock", ".hidden"],
        ] {
            assert!(
                std::process::Command::new("git")
                    .args(arguments)
                    .current_dir(&root)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        fs::write(root.join(".gitignore"), ".hidden\nvalue.txt\n").unwrap();
        compare_cargo(&manifest);
        fs::remove_dir_all(root).unwrap();
    }
}
