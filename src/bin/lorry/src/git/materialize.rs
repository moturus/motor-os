use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path};

use crate::config::PolicyLimits;
use crate::diagnostic::{Error, Result};
use crate::source_tree::Limits;

pub(super) fn extract_tree(
    repository: &gix::Repository,
    tree: &gix::Tree<'_>,
    root: &Path,
    limits: Limits,
) -> Result<()> {
    let entries = tree.traverse().breadthfirst.files().map_err(gix_error)?;
    if entries.len() > limits.max_entries {
        return Err(Error::failure(format!(
            "Git source exceeds the entry-count limit of {}",
            limits.max_entries
        )));
    }
    let mut indexed = BTreeMap::new();
    for entry in &entries {
        let relative = portable_git_path(entry.filepath.as_ref(), limits)?.to_owned();
        let kind = if entry.mode.is_tree() {
            ExtractKind::Directory
        } else if entry.mode.is_blob() {
            ExtractKind::File {
                oid: entry.oid,
                executable: entry.mode.is_executable(),
            }
        } else if entry.mode.is_link() {
            let object = repository.find_object(entry.oid).map_err(gix_error)?;
            if object.kind != gix::objs::Kind::Blob {
                return Err(Error::failure(format!(
                    "Git symbolic link `{relative}` is not a valid blob"
                )));
            }
            if object.data.len() > limits.max_path_bytes {
                return Err(Error::failure(format!(
                    "Git symbolic link `{relative}` exceeds the path-byte limit of {}",
                    limits.max_path_bytes
                )));
            }
            let target = std::str::from_utf8(&object.data).map_err(|_| {
                Error::failure(format!(
                    "Git symbolic link `{relative}` target is not valid UTF-8"
                ))
            })?;
            ExtractKind::Link(target.to_owned())
        } else {
            return Err(Error::failure(format!(
                "Git source entry `{relative}` has unsupported mode {:o}",
                entry.mode
            )));
        };
        indexed.insert(relative, kind);
    }

    for (relative, kind) in &indexed {
        if matches!(kind, ExtractKind::Directory) {
            let path = root.join(relative);
            fs::create_dir(&path).map_err(|error| {
                Error::failure(format!(
                    "failed to create Git source directory `{relative}`: {error}"
                ))
            })?;
        }
    }

    let mut total = 0_u64;
    for (relative, kind) in &indexed {
        if matches!(kind, ExtractKind::Directory) {
            continue;
        }
        let (oid, executable) = resolve_materialized_file(relative, &indexed, limits)?;
        let header = repository.find_header(*oid).map_err(gix_error)?;
        if header.size() > limits.max_file_bytes {
            return Err(Error::failure(format!(
                "Git source file `{relative}` exceeds the byte limit of {}",
                limits.max_file_bytes
            )));
        }
        total = total
            .checked_add(header.size())
            .filter(|total| *total <= limits.max_tree_bytes)
            .ok_or_else(|| {
                Error::failure(format!(
                    "Git source exceeds the byte limit of {}",
                    limits.max_tree_bytes
                ))
            })?;
        let object = repository.find_object(*oid).map_err(gix_error)?;
        if object.kind != gix::objs::Kind::Blob || object.data.len() as u64 != header.size() {
            return Err(Error::failure(format!(
                "Git source entry `{relative}` is not a valid blob"
            )));
        }
        let path = root.join(relative);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                Error::failure(format!(
                    "failed to create Git source file `{relative}`: {error}"
                ))
            })?;
        file.write_all(&object.data).map_err(|error| {
            Error::failure(format!(
                "failed to write Git source file `{relative}`: {error}"
            ))
        })?;
        file.flush().map_err(|error| {
            Error::failure(format!(
                "failed to flush Git source file `{relative}`: {error}"
            ))
        })?;
        set_file_mode(&file, &path, executable)?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
enum ExtractKind {
    Directory,
    File {
        oid: gix::ObjectId,
        executable: bool,
    },
    Link(String),
}

fn resolve_materialized_file<'a>(
    path: &str,
    entries: &'a BTreeMap<String, ExtractKind>,
    limits: Limits,
) -> Result<(&'a gix::ObjectId, bool)> {
    let mut current = path.to_owned();
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(current.clone()) {
            return Err(Error::failure(format!(
                "Git symbolic link `{path}` contains a cycle at `{current}`"
            )));
        }
        match entries.get(&current) {
            Some(ExtractKind::File { oid, executable }) => return Ok((oid, *executable)),
            Some(ExtractKind::Link(target)) => {
                current = normalize_link_target(&current, target, limits)?;
            }
            Some(ExtractKind::Directory) => {
                return Err(Error::failure(format!(
                    "Git symbolic link `{path}` resolves to directory `{current}`"
                )));
            }
            None => {
                return Err(Error::failure(format!(
                    "Git symbolic link `{path}` resolves to missing entry `{current}`"
                )));
            }
        }
    }
}

fn normalize_link_target(link: &str, target: &str, limits: Limits) -> Result<String> {
    if target.is_empty()
        || target.len() > limits.max_path_bytes
        || target.starts_with('/')
        || target.contains('\\')
        || target
            .bytes()
            .any(|byte| byte == 0 || byte < 0x20 || byte == 0x7f)
    {
        return Err(Error::failure(format!(
            "Git symbolic link `{link}` has non-portable target `{target}`"
        )));
    }
    let mut components = link
        .rsplit_once('/')
        .map_or(Vec::new(), |(parent, _)| parent.split('/').collect());
    for component in target.split('/') {
        match component {
            "" => {
                return Err(Error::failure(format!(
                    "Git symbolic link `{link}` has non-portable target `{target}`"
                )));
            }
            "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(Error::failure(format!(
                        "Git symbolic link `{link}` escapes the source tree through `{target}`"
                    )));
                }
            }
            _ => components.push(component),
        }
    }
    let resolved = components.join("/");
    if resolved.is_empty() || resolved.len() > limits.max_path_bytes {
        return Err(Error::failure(format!(
            "Git symbolic link `{link}` has non-portable target `{target}`"
        )));
    }
    Ok(resolved)
}

fn portable_git_path(bytes: &[u8], limits: Limits) -> Result<&str> {
    let path = std::str::from_utf8(bytes)
        .map_err(|_| Error::failure("Git source path is not valid UTF-8"))?;
    if path.is_empty()
        || path.len() > limits.max_path_bytes
        || path.contains('\\')
        || path
            .bytes()
            .any(|byte| byte == 0 || byte < 0x20 || byte == 0x7f)
        || Path::new(path)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Error::failure(format!(
            "non-portable Git source path `{path}`"
        )));
    }
    Ok(path)
}

pub(super) fn tree_limits(policy: &PolicyLimits) -> Result<Limits> {
    Ok(Limits {
        max_entries: usize::try_from(policy.max_package_files)
            .map_err(|_| Error::failure("Git source file limit does not fit this platform"))?,
        max_path_bytes: 4096,
        max_file_bytes: policy.max_extracted_package_bytes,
        max_tree_bytes: policy.max_extracted_package_bytes,
    })
}

pub(super) fn gix_error(error: impl std::error::Error) -> Error {
    use std::fmt::Write as _;

    let mut message = format!("Git operation failed: {error}");
    let mut source = error.source();
    while let Some(error) = source {
        let _ = write!(message, ": {error}");
        source = error.source();
    }
    Error::failure(message)
}

fn set_file_mode(_file: &File, _path: &Path, executable: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        _file
            .set_permissions(fs::Permissions::from_mode(if executable {
                0o700
            } else {
                0o600
            }))
            .map_err(|error| {
                Error::failure(format!(
                    "failed to set Git file permissions `{}`: {error}",
                    _path.display()
                ))
            })?;
    }
    #[cfg(target_os = "motor")]
    {
        use std::os::fd::AsRawFd;
        let permissions = if executable {
            moto_rt::fs::PERM_READ | moto_rt::fs::PERM_EXEC
        } else {
            moto_rt::fs::PERM_READ | moto_rt::fs::PERM_WRITE
        };
        moto_rt::fs::set_file_perm(_file.as_raw_fd(), permissions).map_err(|error| {
            Error::failure(format!(
                "failed to set Git file permissions `{}`: {error}",
                _path.display()
            ))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_tree::DEFAULT_LIMITS;

    fn file() -> ExtractKind {
        ExtractKind::File {
            oid: gix::ObjectId::null(gix::hash::Kind::Sha1),
            executable: false,
        }
    }

    #[test]
    fn resolves_only_internal_regular_file_links() {
        let mut entries = BTreeMap::new();
        entries.insert("LICENSE-MIT".to_owned(), file());
        entries.insert(
            "crate/LICENSE-MIT".to_owned(),
            ExtractKind::Link("../LICENSE-MIT".to_owned()),
        );
        entries.insert(
            "crate/COPYING".to_owned(),
            ExtractKind::Link("./LICENSE-MIT".to_owned()),
        );
        entries.insert(
            "crate/LICENSE-APACHE".to_owned(),
            ExtractKind::Link("COPYING".to_owned()),
        );

        assert!(resolve_materialized_file("crate/LICENSE-MIT", &entries, DEFAULT_LIMITS).is_ok());
        assert!(
            resolve_materialized_file("crate/LICENSE-APACHE", &entries, DEFAULT_LIMITS).is_ok()
        );
        assert_eq!(
            normalize_link_target("crate/LICENSE-MIT", "../LICENSE-MIT", DEFAULT_LIMITS).unwrap(),
            "LICENSE-MIT"
        );
    }

    #[test]
    fn rejects_unsafe_or_unresolvable_links() {
        let mut entries = BTreeMap::new();
        entries.insert("directory".to_owned(), ExtractKind::Directory);
        entries.insert(
            "cycle-a".to_owned(),
            ExtractKind::Link("cycle-b".to_owned()),
        );
        entries.insert(
            "cycle-b".to_owned(),
            ExtractKind::Link("cycle-a".to_owned()),
        );
        entries.insert(
            "directory-link".to_owned(),
            ExtractKind::Link("directory".to_owned()),
        );
        entries.insert(
            "missing-link".to_owned(),
            ExtractKind::Link("missing".to_owned()),
        );

        assert!(resolve_materialized_file("cycle-a", &entries, DEFAULT_LIMITS).is_err());
        assert!(resolve_materialized_file("directory-link", &entries, DEFAULT_LIMITS).is_err());
        assert!(resolve_materialized_file("missing-link", &entries, DEFAULT_LIMITS).is_err());
        for target in ["/absolute", "../../escape", "bad\\path", "bad\npath", ""] {
            assert!(normalize_link_target("crate/link", target, DEFAULT_LIMITS).is_err());
        }
    }
}
