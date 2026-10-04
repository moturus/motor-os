//! File-tool paths and per-session data; these checks prevent accidents.

use std::path::{Component, Path, PathBuf};

use gears::state::StateRoot;

pub struct ToolContext {
    pub workspace: PathBuf,
    pub state: StateRoot,
    pub session: String,
    results: Option<PathBuf>,
}

impl ToolContext {
    pub fn for_event(event: &crate::Event) -> Result<Self, String> {
        Self::new(
            event.workspace.clone(),
            crate::default_root()?,
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
        Self::new(workspace, crate::default_root()?, session, path.as_deref())
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
        let workspace = normalize(&workspace)?;
        no_links(&workspace)?;
        if !workspace.is_dir() {
            return Err("selected workspace is not a directory".into());
        }
        let state = normalize(&state)?;
        no_links(&state)?;
        let state = StateRoot::new(state)?;
        let results = path
            .map(|path| {
                let mut name = path.as_os_str().to_os_string();
                name.push(".results");
                normalize(Path::new(&name))
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
        let path = normalize(&if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.workspace.join(path)
        })?;
        if path.starts_with(self.state.path())
            && (writing
                || self
                    .results
                    .as_ref()
                    .is_none_or(|results| !path.starts_with(results)))
        {
            return Err("file tools cannot access the Gears directory".into());
        }
        no_links(&path)?;
        Ok(path)
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

fn normalize(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("batteries roots must be absolute".into());
    }
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => result.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir if result.pop() => {}
            _ => return Err(format!("invalid file path {}", path.display())),
        }
    }
    Ok(result)
}

fn no_links(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("symbolic link refused: {}", current.display()));
            }
            Ok(metadata) if current != path && !metadata.is_dir() => {
                return Err(format!("not a directory: {}", current.display()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("{}: {error}", current.display())),
        }
    }
    Ok(())
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
            ToolContext::new(context.workspace.clone(), state, "../escape".into(), None).is_err()
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("outside"), context.workspace.join("link"))
                .unwrap();
            assert!(
                context
                    .resolve("link/file", false)
                    .unwrap_err()
                    .contains("symbolic link")
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
