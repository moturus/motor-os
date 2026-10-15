//! File-tool paths and per-session data; these checks prevent accidents, and
//! symbolic links are resolved before them.

use std::path::{Component, Path, PathBuf};

use crate::state::StateRoot;

pub struct ToolContext {
    pub workspace: PathBuf,
    pub state: StateRoot,
    pub session: String,
    results: Option<PathBuf>,
}

impl ToolContext {
    pub fn for_event(event: &crate::batteries::Event) -> Result<Self, String> {
        Self::new(
            event.workspace.clone(),
            crate::batteries::default_root()?,
            event.session.id.clone(),
            event.session.path.as_deref(),
        )
    }

    pub fn from_env() -> Result<Self, String> {
        let workspace = std::env::var_os("GEARS_WORKSPACE")
            .map(PathBuf::from)
            .ok_or("GEARS_WORKSPACE is not set")?;
        let session = std::env::var("GEARS_SESSION_ID")
            .map_err(|_| "GEARS_SESSION_ID is not set or not UTF-8")?;
        let path = std::env::var_os("GEARS_SESSION_PATH").map(PathBuf::from);
        Self::new(
            workspace,
            crate::batteries::default_root()?,
            session,
            path.as_deref(),
        )
    }

    pub fn new(
        workspace: PathBuf,
        state: PathBuf,
        session: String,
        path: Option<&Path>,
    ) -> Result<Self, String> {
        if session.is_empty()
            || session.len() > 128
            || !session
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err("invalid session id for batteries data".into());
        }
        let workspace = resolve_links(&normalize(&workspace)?)?;
        if !workspace.is_dir() {
            return Err("selected workspace is not a directory".into());
        }
        let state = resolve_links(&normalize(&state)?)?;
        let state = StateRoot::new(state)?;
        let results = path
            .map(|path| {
                let mut name = path.as_os_str().to_os_string();
                name.push(".results");
                resolve_links(&normalize(Path::new(&name))?)
            })
            .transpose()?;
        Ok(Self {
            workspace,
            state,
            session,
            results,
        })
    }

    pub fn resolve(&self, input: &str, writing: bool) -> Result<PathBuf, String> {
        if input.is_empty() {
            return Err("file path is empty".into());
        }
        let path = Path::new(input);
        let path = resolve_links(&normalize(&if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.workspace.join(path)
        })?)?;
        if path.starts_with(self.state.path())
            && (writing
                || self
                    .results
                    .as_ref()
                    .is_none_or(|results| !path.starts_with(results)))
        {
            return Err("file tools cannot access the Gears directory".into());
        }
        Ok(path)
    }

    pub fn save_result(&self, name: &str, bytes: &[u8]) -> Result<Option<PathBuf>, String> {
        let Some(results) = &self.results else {
            return Ok(None);
        };
        if !results.starts_with(self.state.path()) {
            return Err("saved results must belong to the Gears directory".into());
        }
        let root = StateRoot::new(results.clone())?;
        root.replace_file(Path::new(name), bytes)?;
        Ok(Some(root.file(Path::new(name))?))
    }

    pub fn relative(&self, path: &Path) -> PathBuf {
        let base: Vec<_> = self.workspace.components().collect();
        let target: Vec<_> = path.components().collect();
        let common = base.iter().zip(&target).take_while(|(a, b)| a == b).count();
        let mut relative = PathBuf::new();
        for _ in common..base.len() {
            relative.push("..");
        }
        for component in &target[common..] {
            relative.push(component.as_os_str());
        }
        relative
    }

    pub fn data_file(&self, name: &str) -> Result<PathBuf, String> {
        self.state.file(Path::new(&format!(
            "batteries/sessions/{}/{name}",
            self.session
        )))
    }

    pub fn replace_data(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        self.state.replace_file(
            Path::new(&format!("batteries/sessions/{}/{name}", self.session)),
            bytes,
        )
    }
}

/// Remove `.` and `..` lexically; as in POSIX, `..` at the root stays there.
pub(crate) fn normalize(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("batteries paths must be absolute".into());
    }
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => result.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            _ => return Err(format!("invalid file path {}", path.display())),
        }
    }
    Ok(result)
}

/// Resolve symbolic links in the longest existing ancestor, so checks see the
/// real location; the part that does not exist yet is kept as written.
pub(crate) fn resolve_links(path: &Path) -> Result<PathBuf, String> {
    let mut existing = path;
    let mut missing = Vec::new();
    loop {
        match existing.canonicalize() {
            Ok(mut real) => {
                real.extend(missing.iter().rev());
                return Ok(real);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let (Some(parent), Some(name)) = (existing.parent(), existing.file_name()) else {
                    return Err(format!("{}: {error}", path.display()));
                };
                missing.push(name);
                existing = parent;
            }
            Err(error) => return Err(format!("{}: {error}", existing.display())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_paths_and_protects_gears_state_and_other_sessions_results() {
        let root = std::env::temp_dir().join(format!("batteries-paths-{}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        let state = root.join("state");
        let session_path = state.join("sessions/current.jsonl");
        let context = ToolContext::new(
            root.join("workspace"),
            state.clone(),
            "s1".into(),
            Some(&session_path),
        )
        .unwrap();
        assert_eq!(
            context.resolve("./src/../file name*", false).unwrap(),
            root.join("workspace/file name*")
        );
        assert_eq!(
            context.resolve("../outside", false).unwrap(),
            root.join("outside")
        );
        assert_eq!(
            context.relative(&root.join("outside")),
            Path::new("../outside")
        );
        assert_eq!(context.resolve("/../..", false).unwrap(), Path::new("/"));
        for file in [
            state.join("key"),
            state.join("sessions/other.jsonl.results/1.txt"),
        ] {
            assert!(context.resolve(file.to_str().unwrap(), false).is_err());
        }
        let own_result = state.join("sessions/current.jsonl.results/1.txt");
        assert_eq!(
            context
                .resolve(own_result.to_str().unwrap(), false)
                .unwrap(),
            own_result
        );
        assert!(context.resolve(own_result.to_str().unwrap(), true).is_err());
        assert!(
            ToolContext::new(
                context.workspace.clone(),
                state.clone(),
                "../escape".into(),
                None
            )
            .is_err()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let real = root.canonicalize().unwrap();
            std::fs::create_dir(root.join("outside")).unwrap();
            symlink(root.join("outside"), context.workspace.join("link")).unwrap();
            assert_eq!(
                context.resolve("link/file", false).unwrap(),
                real.join("outside/file")
            );
            std::fs::create_dir_all(&state).unwrap();
            symlink(&state, context.workspace.join("state-link")).unwrap();
            assert!(context.resolve("state-link/key", true).is_err());
            // A linked ancestor of both roots no longer disables the tools.
            symlink(&root, real.with_extension("alias")).unwrap();
            let alias = real.with_extension("alias");
            let linked = ToolContext::new(
                alias.join("workspace"),
                alias.join("state"),
                "s1".into(),
                None,
            )
            .unwrap();
            assert_eq!(linked.workspace, real.join("workspace"));
            assert!(
                linked
                    .resolve(alias.join("state/key").to_str().unwrap(), false)
                    .is_err()
            );
            std::fs::remove_file(alias).unwrap();
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
