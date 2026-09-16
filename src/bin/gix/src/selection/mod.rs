use std::{fs, io, path::Path};

use gix::bstr::{BStr, BString, ByteSlice};

mod enumerate;
pub use enumerate::enumerate;

pub(super) const MAX_CANDIDATES: usize = 65_536;
pub(super) const MAX_PATH_BYTES: usize = 8 * 1024 * 1024;
const MAX_COMPONENT_BYTES: usize = 255;
const MAX_ABSOLUTE_PATH_BYTES: usize = 1024;

/// A validated selection of literal, worktree-relative paths.
pub struct Selection {
    paths: Vec<BString>,
}

impl Selection {
    pub fn all() -> Selection {
        Selection { paths: Vec::new() }
    }

    pub fn from_paths(workdir: &Path, paths: &[String]) -> crate::Result<Selection> {
        if paths.is_empty() {
            return Err(invalid("at least one path is required").into());
        }
        let mut normalized = paths
            .iter()
            .map(|path| normalize(path, workdir))
            .collect::<io::Result<Vec<_>>>()?;
        normalized.sort();
        normalized.dedup();
        Ok(Selection { paths: normalized })
    }

    pub fn selects(&self, path: &BStr) -> bool {
        self.paths.is_empty()
            || self
                .paths
                .iter()
                .any(|parent| contains(parent.as_bstr(), path))
    }

    pub(super) fn paths(&self) -> &[BString] {
        &self.paths
    }

    pub(super) fn pathspecs(&self) -> Vec<BString> {
        if self.paths.is_empty() || self.paths.iter().any(|path| path.is_empty()) {
            return Vec::new();
        }
        self.paths
            .iter()
            .map(|path| {
                let mut spec = Vec::with_capacity(14 + path.len());
                spec.extend_from_slice(b":(top,literal)");
                spec.extend_from_slice(path);
                spec.into()
            })
            .collect()
    }
}

fn normalize(input: &str, workdir: &Path) -> io::Result<BString> {
    if input.is_empty() {
        return Err(invalid("an empty path is not valid"));
    }
    let path = Path::new(input);
    if path.is_absolute() {
        return Err(invalid(format!(
            "path '{}' is absolute",
            input.escape_debug()
        )));
    }
    let mut out = Vec::<u8>::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => continue,
            std::path::Component::Normal(component) => {
                let component = component
                    .to_str()
                    .ok_or_else(|| invalid("path is not UTF-8"))?;
                validate_component(component)?;
                if !out.is_empty() {
                    out.push(b'/');
                }
                out.extend_from_slice(component.as_bytes());
            }
            _ => {
                return Err(invalid(format!(
                    "path '{}' leaves the worktree",
                    input.escape_debug()
                )));
            }
        }
    }
    validate_length(&out, workdir)?;
    Ok(out.into())
}

pub(super) fn validate_normalized(path: &BStr, workdir: &Path) -> io::Result<()> {
    let path = std::str::from_utf8(path)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    if path.is_empty() || path.split('/').any(str::is_empty) {
        return Err(invalid("repository path is not normalized"));
    }
    for component in path.split('/') {
        validate_component(component)?;
    }
    validate_length(path.as_bytes(), workdir)
}

fn validate_component(component: &str) -> io::Result<()> {
    gix::validate::path::component(component.as_bytes().as_bstr(), None, Default::default())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    if component.len() > MAX_COMPONENT_BYTES
        || component.trim().len() != component.len()
        || component.starts_with("..")
    {
        return Err(invalid(format!(
            "path component '{}' is invalid on Motor",
            component.escape_debug()
        )));
    }
    Ok(())
}

fn validate_length(path: &[u8], workdir: &Path) -> io::Result<()> {
    let root = workdir
        .to_str()
        .ok_or_else(|| invalid("worktree path is not UTF-8"))?;
    let separator = usize::from(!path.is_empty() && root != "/");
    if root
        .len()
        .checked_add(separator)
        .and_then(|len| len.checked_add(path.len()))
        .is_none_or(|len| len >= MAX_ABSOLUTE_PATH_BYTES)
    {
        return Err(invalid("absolute worktree path exceeds the Motor limit"));
    }
    Ok(())
}

/// Inspect a validated worktree path without following any symbolic link.
pub(crate) fn checked_symlink_metadata(
    workdir: &Path,
    path: &BStr,
) -> io::Result<Option<fs::Metadata>> {
    if path.is_empty() {
        return Err(invalid("selected path is empty"));
    }
    let display = path.to_str_lossy().escape_debug().to_string();
    let relative = gix::path::from_bstr(path);
    let mut current = workdir.to_owned();
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let std::path::Component::Normal(component) = component else {
            return Err(invalid(format!(
                "selected path '{display}' is not worktree-relative"
            )));
        };
        current.push(component);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                return Ok(None);
            }
            Err(source) => {
                let kind = source.kind();
                return Err(io::Error::new(kind, InspectError(path.to_owned(), source)));
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("selected path '{display}' contains a symbolic link"),
            ));
        }
        if components.peek().is_some() && !metadata.is_dir() {
            return Ok(None);
        }
        if components.peek().is_none() {
            return Ok(Some(metadata));
        }
    }
    Err(invalid(format!(
        "selected path '{display}' has no components"
    )))
}

#[derive(Debug)]
struct InspectError(BString, io::Error);

impl std::fmt::Display for InspectError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            out,
            "cannot inspect selected path '{}': {}",
            self.0.to_str_lossy().escape_debug(),
            self.1
        )
    }
}

impl std::error::Error for InspectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.1)
    }
}

fn contains(parent: &BStr, path: &BStr) -> bool {
    let parent = parent.as_bytes();
    let path = path.as_bytes();
    parent.is_empty()
        || path == parent
        || path
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.first() == Some(&b'/'))
}

pub(super) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_normalization_and_selection() -> crate::Result {
        let root = Path::new("/work");
        assert_eq!(normalize(".", root)?.as_bstr(), "");
        assert_eq!(normalize("./dir//file/", root)?.as_bstr(), "dir/file");
        for invalid in ["", "/file", "dir/../file", ".git/config", "literal*"] {
            assert!(normalize(invalid, root).is_err(), "{invalid}");
        }
        let selection = Selection::from_paths(
            root,
            &[
                "dir/file".into(),
                "dir".into(),
                "dir".into(),
                "literal[ab]".into(),
            ],
        )?;
        assert_eq!(selection.paths.len(), 3);
        assert!(selection.selects(BStr::new(b"dir/child")));
        assert!(!selection.selects(BStr::new(b"directory")));
        assert!(selection.selects(BStr::new(b"literal[ab]")));
        assert!(!selection.selects(BStr::new(b"literala")));
        assert_eq!(
            selection.pathspecs()[2].as_bstr(),
            ":(top,literal)literal[ab]"
        );
        let with_root = Selection::from_paths(root, &[".".into(), "ignored".into()])?;
        assert_eq!(
            with_root.paths,
            [BString::default(), BString::from("ignored")]
        );
        assert!(with_root.pathspecs().is_empty());
        Ok(())
    }
}
