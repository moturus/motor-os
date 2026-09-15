use std::{
    fs,
    io::{self, Write},
    path::Path,
};

use gix::bstr::ByteSlice;

use crate::command_config;

const POLICY_OVERRIDES: [&str; 5] = [
    "core.symlinks=false",
    "core.fileMode=true",
    "core.checkStat=minimal",
    "core.trustCTime=false",
    "gitoxide.core.useNsec=false",
];

pub struct OpenedRepository {
    pub repo: gix::Repository,
    pub command_policy: command_config::Policy,
}

pub fn open(
    path: &Path,
    overrides: &[&str],
    report_config_paths: bool,
) -> crate::Result<OpenedRepository> {
    reject_environment_paths()?;
    reject_config_paths(overrides)?;

    let selected = fs::canonicalize(path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("cannot access repository '{}': {err}", path.display()),
        )
    })?;
    let mut permissions = gix::open::Permissions::isolated();
    permissions.config.git = true;
    permissions.config.user = true;
    permissions.config.includes = true;
    permissions.env.home = gix::sec::Permission::Allow;
    permissions.env.xdg_config_home = gix::sec::Permission::Allow;

    let options = gix::open::Options::isolated()
        .permissions(permissions)
        .strict_config(true)
        .cli_overrides(overrides.iter().copied())
        .config_overrides(POLICY_OVERRIDES);
    let mut repo = gix::open_opts(&selected, options)?;
    validate_locations(&repo, &selected)?;

    if report_config_paths {
        report_paths(&repo)?;
    }
    let command_policy = command_config::sanitize(&mut repo)?;
    // This handle flag is definitive even if repository configuration loaded replacement refs.
    repo.objects.ignore_replacements = true;
    Ok(OpenedRepository {
        repo,
        command_policy,
    })
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
