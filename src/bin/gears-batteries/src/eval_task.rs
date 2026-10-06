//! User-authored task inputs; prompts and executable criteria remain separate.

use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub version: u32,
    pub workspace: PathBuf,
    pub prompt: String,
    #[serde(default)]
    pub exclude: Vec<PathBuf>,
    pub check: Vec<String>,
    pub acceptance: Vec<Vec<String>>,
    pub regressions: Vec<Vec<String>>,
}

pub struct Loaded {
    pub path: PathBuf,
    pub name: String,
    pub task: Task,
    pub hash: String,
}

pub fn command(arguments: &[String]) -> Result<(), String> {
    if arguments.is_empty()
        || arguments.len() > 64
        || arguments[0].is_empty()
        || arguments.iter().any(|argument| argument.contains('\0'))
        || arguments.iter().map(String::len).sum::<usize>() > 65536
    {
        return Err(
            "evaluation commands need 1–64 literal arguments, a program and at most 64 KiB".into(),
        );
    }
    Ok(())
}

impl Task {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || self.workspace.as_os_str().is_empty()
            || self.prompt.trim().is_empty()
            || self.prompt.len() > 32768
            || self
                .prompt
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
        {
            return Err("invalid evaluation task version, workspace or prompt".into());
        }
        if self.acceptance.is_empty()
            || self.regressions.is_empty()
            || self.acceptance.len() > 16
            || self.regressions.len() > 16
        {
            return Err(
                "evaluation tasks need 1–16 acceptance commands and 1–16 regression commands"
                    .into(),
            );
        }
        command(&self.check)?;
        crate::check_config::validate(&self.check)?;
        for arguments in self.acceptance.iter().chain(&self.regressions) {
            command(arguments)?;
        }
        if self.exclude.len() > 64
            || self.exclude.iter().any(|path| {
                path.as_os_str().is_empty()
                    || path
                        .components()
                        .any(|c| !matches!(c, std::path::Component::Normal(_)))
            })
        {
            return Err(
                "evaluation exclusions must be bounded relative paths without traversal".into(),
            );
        }
        Ok(())
    }
}

pub fn load(path: &Path) -> Result<Loaded, String> {
    let path = if path.is_absolute() {
        path.into()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    let mut checked = PathBuf::new();
    for component in path.components() {
        checked.push(component);
        if std::fs::symlink_metadata(&checked)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("symbolic evaluation task path refused".into());
        }
    }
    let name = path
        .file_stem()
        .and_then(|name| name.to_str())
        .filter(|name| crate::skill_format::valid_name(name))
        .ok_or("evaluation task filename needs a valid lowercase name")?
        .to_string();
    if path.extension().is_none_or(|extension| extension != "toml") || !path.is_file() {
        return Err("evaluation task must be a regular TOML file".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&path)
        .map_err(|e| e.to_string())?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 65536 {
        return Err("evaluation task exceeds 64 KiB".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
    let mut task: Task =
        toml::from_str(text).map_err(|e| format!("invalid evaluation task: {e}"))?;
    task.validate()?;
    if !task.workspace.is_absolute() {
        task.workspace = path.parent().unwrap().join(&task.workspace);
    }
    let context = crate::paths::ToolContext::new(
        task.workspace.clone(),
        path.parent().unwrap().into(),
        "eval-task".into(),
        None,
    )?;
    task.workspace = context.workspace;
    Ok(Loaded {
        name,
        task,
        hash: crate::snapshot::digest(&bytes),
        path,
    })
}
