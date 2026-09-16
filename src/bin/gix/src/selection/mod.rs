use std::{io, path::Path};

use gix::bstr::{BStr, BString, ByteSlice};

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

fn contains(parent: &BStr, path: &BStr) -> bool {
    let parent = parent.as_bytes();
    let path = path.as_bytes();
    parent.is_empty()
        || path == parent
        || path
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.first() == Some(&b'/'))
}

fn invalid(message: impl Into<String>) -> io::Error {
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
        let with_root = Selection::from_paths(root, &[".".into(), "ignored".into()])?;
        assert_eq!(
            with_root.paths,
            [BString::default(), BString::from("ignored")]
        );
        Ok(())
    }
}
