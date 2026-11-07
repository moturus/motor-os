use std::{
    fs,
    io::{self, Write},
    path::Path,
};

use gix::bstr::ByteSlice;

use crate::command_config;

const POLICY_OVERRIDES: [&str; 10] = [
    "core.symlinks=false",
    "clone.rejectShallow=true",
    "core.fileMode=true",
    "core.checkStat=minimal",
    "core.trustCTime=false",
    "gitoxide.core.useNsec=false",
    "core.filesRefLockTimeout=0",
    "core.packedRefsTimeout=0",
    "index.threads=1",
    "pack.threads=1",
];

pub struct OpenedRepository {
    pub repo: gix::Repository,
    pub command_policy: command_config::Policy,
    /// The invocation directory relative to the worktree root, using `/` separators.
    ///
    /// Commands that accept worktree paths resolve them against this prefix, and
    /// `status` reports paths relative to it, matching Git when started in a
    /// subdirectory.
    pub prefix: gix::bstr::BString,
}

pub fn open(
    path: &Path,
    overrides: &[&str],
    report_config_paths: bool,
) -> crate::Result<OpenedRepository> {
    let options = open_options(overrides)?;
    let requested = fs::canonicalize(path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("cannot access repository '{}': {err}", path.display()),
        )
    })?;
    // Like Git, search ancestors so commands work from any worktree subdirectory.
    let discovered = gix::discover::upwards_opts(
        &requested,
        gix::discover::upwards::Options {
            // `open_opts` establishes trust again with our explicit permissions;
            // discovery only needs to locate the worktree.
            trust: gix::discover::upwards::TrustPolicy::Assume(gix::sec::Trust::Full),
            ..Default::default()
        },
    )?
    .0;
    let (repository_dir, worktree_dir) = discovered.into_repository_and_work_tree_directories();
    // Ordinary worktrees return their root. Bare or unusual layouts return only
    // a repository directory, which `validate_locations` rejects.
    let selected = worktree_dir.unwrap_or(repository_dir);
    let mut repo = gix::open_opts(&selected, options)?;
    let command_policy = apply_policy(&mut repo, &selected, report_config_paths)?;
    let prefix = invocation_prefix(&requested, &selected);
    Ok(OpenedRepository {
        repo,
        command_policy,
        prefix,
    })
}

/// The directory Git was started in, relative to the worktree root.
///
/// Discovery and `-r` always select an ancestor of the requested path. `.git`
/// itself and bare repository layouts have no usable worktree-relative prefix.
fn invocation_prefix(requested: &Path, worktree: &Path) -> gix::bstr::BString {
    if !requested.is_dir() {
        return gix::bstr::BString::default();
    }
    let Ok(relative) = requested.strip_prefix(worktree) else {
        return gix::bstr::BString::default();
    };
    if relative.starts_with(".git") {
        return gix::bstr::BString::default();
    }
    gix::path::into_bstr(relative).into_owned()
}

pub(crate) fn open_options(overrides: &[&str]) -> io::Result<gix::open::Options> {
    reject_environment_paths()?;
    reject_config_paths(overrides)?;

    let mut permissions = gix::open::Permissions::isolated();
    permissions.config.git = true;
    permissions.config.user = true;
    permissions.config.includes = true;
    permissions.env.home = gix::sec::Permission::Allow;
    permissions.env.xdg_config_home = gix::sec::Permission::Allow;

    Ok(gix::open::Options::isolated()
        .permissions(permissions)
        .strict_config(true)
        .cli_overrides(overrides.iter().copied())
        .config_overrides(POLICY_OVERRIDES))
}

pub(crate) fn apply_policy(
    repo: &mut gix::Repository,
    selected: &Path,
    report_config_paths: bool,
) -> crate::Result<command_config::Policy> {
    validate_locations(repo, selected)?;
    if report_config_paths {
        report_paths(repo)?;
    }
    let command_policy = command_config::sanitize(repo)?;
    // This handle flag is definitive even if repository configuration loaded replacement refs.
    repo.objects.ignore_replacements = true;
    Ok(command_policy)
}

fn reject_environment_paths() -> io::Result<()> {
    for name in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"] {
        if std::env::var_os(name).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} is not supported; select the worktree with -r"),
            ));
        }
    }
    Ok(())
}

fn reject_config_paths(overrides: &[&str]) -> io::Result<()> {
    for override_value in overrides {
        let key = override_value
            .split_once('=')
            .map_or(*override_value, |(key, _)| key)
            .trim();
        let parsed =
            gix::config::KeyRef::parse_unvalidated(key.as_bytes().as_bstr()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid configuration override '{override_value}'"),
                )
            })?;
        let changes_worktree = parsed.section_name.eq_ignore_ascii_case("core")
            && parsed.subsection_name.is_none()
            && parsed.value_name.eq_ignore_ascii_case("worktree");
        let changes_index = parsed.section_name.eq_ignore_ascii_case("gitoxide")
            && parsed
                .subsection_name
                .is_some_and(|name| name.eq_ignore_ascii_case(b"core"))
            && parsed.value_name.eq_ignore_ascii_case("indexFile");
        if changes_worktree || changes_index {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("configuration override '{key}' cannot change the selected repository"),
            ));
        }
    }
    Ok(())
}

fn validate_locations(repo: &gix::Repository, selected: &Path) -> io::Result<()> {
    if repo.kind() != gix::repository::Kind::Common || repo.common_dir() != repo.git_dir() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "only ordinary, non-linked worktree repositories are supported",
        ));
    }
    let workdir = repo.workdir().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "bare repositories are not supported",
        )
    })?;
    if fs::canonicalize(workdir)? != selected
        || fs::canonicalize(repo.git_dir())? != selected.join(".git")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "repository configuration selected a different worktree",
        ));
    }
    if repo.index_path() != repo.git_dir().join("index") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "repository configuration selected a different index",
        ));
    }
    Ok(())
}

fn report_paths(repo: &gix::Repository) -> io::Result<()> {
    let snapshot = repo.config_snapshot();
    let mut stderr = io::stderr().lock();
    let mut reported = Vec::new();
    for section in snapshot.plumbing().sections() {
        let meta = section.meta();
        let Some(path) = meta.path.as_deref() else {
            continue;
        };
        if reported.contains(&path) {
            continue;
        }
        writeln!(
            stderr,
            "gix: configuration {:?} {}",
            meta.source,
            path.display()
        )?;
        reported.push(path);
    }
    stderr.flush()
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    struct Cleanup(PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(label: &str) -> crate::Result<(PathBuf, Cleanup)> {
        let root = std::env::temp_dir().join(format!(
            "motor-gix-repository-{label}-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir(&root)?;
        Ok((root.clone(), Cleanup(root)))
    }

    fn assert_worktree(opened: &OpenedRepository, expected: &Path) -> crate::Result {
        let workdir = opened
            .repo
            .workdir()
            .ok_or("discovered repository has no worktree")?;
        assert_eq!(fs::canonicalize(workdir)?, fs::canonicalize(expected)?);
        assert_eq!(
            fs::canonicalize(opened.repo.git_dir())?,
            fs::canonicalize(expected.join(".git"))?
        );
        Ok(())
    }

    #[test]
    fn opens_a_worktree_from_a_subdirectory() -> crate::Result {
        let (root, _cleanup) = scratch("subdirectory")?;
        let worktree = root.join("repo");
        gix::init(&worktree)?;
        let nested = worktree.join("nested/deep");
        fs::create_dir_all(&nested)?;

        let opened = open(&nested, &[], false)?;
        assert_worktree(&opened, &worktree)?;
        assert_eq!(opened.prefix.as_bstr(), b"nested/deep".as_bstr());
        let opened = open(&worktree, &[], false)?;
        assert_worktree(&opened, &worktree)?;
        assert!(opened.prefix.is_empty());
        Ok(())
    }

    #[test]
    fn opens_the_nearest_worktree() -> crate::Result {
        let (root, _cleanup) = scratch("nearest")?;
        let outer = root.join("outer");
        gix::init(&outer)?;
        let inner = outer.join("inner");
        gix::init(&inner)?;
        let nested = inner.join("deep");
        fs::create_dir(&nested)?;

        let opened = open(&nested, &[], false)?;
        assert_worktree(&opened, &inner)?;
        assert_eq!(opened.prefix.as_bstr(), b"deep".as_bstr());
        Ok(())
    }

    #[test]
    fn rejects_bare_repositories() -> crate::Result {
        let (root, _cleanup) = scratch("bare")?;
        let bare = root.join("bare.git");
        gix::init_bare(&bare)?;

        let error = open(&bare, &[], false)
            .err()
            .ok_or("a bare repository was accepted")?;
        assert!(
            error
                .to_string()
                .contains("bare repositories are not supported")
        );
        Ok(())
    }
}
