//! A frozen source template supplies fresh independent trial workspaces and state.

use crate::{
    eval_config::{self, Pinned},
    eval_state::{self, Frozen},
    eval_task::Loaded,
    paths::ToolContext,
};
use gears::state::StateRoot;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub struct Prepared {
    pub task: Loaded,
    pub config: Pinned,
    pub identity: Value,
    pub root: StateRoot,
    template: crate::eval_task::Task,
    frozen: Frozen,
}

pub struct Trial {
    pub workspace: PathBuf,
    pub state: PathBuf,
    pub versions: Value,
}

pub fn prepare(
    context: &ToolContext,
    task: Loaded,
    config: &Path,
    destination: &Path,
    batteries: &Path,
) -> Result<Prepared, String> {
    if context.workspace != task.task.workspace {
        return Err("evaluation task and source workspace disagree".into());
    }
    let selected = ToolContext::new(
        context.workspace.clone(),
        destination.into(),
        "eval-prepare".into(),
        None,
    )?;
    let root = selected.state;
    if root.path().starts_with(&context.workspace) || context.workspace.starts_with(root.path()) {
        return Err("evaluation output must be separate from its source workspace".into());
    }
    match std::fs::symlink_metadata(root.path()) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err("evaluation output directory must not exist".into()),
    }
    let frozen = eval_state::capture(context)?;
    let mut source = task.task.clone();
    source
        .exclude
        .extend([PathBuf::from(".git"), PathBuf::from(".gears")]);
    if let Ok(relative) = context.state.path().strip_prefix(&context.workspace) {
        if relative.as_os_str().is_empty() {
            return Err("evaluation workspace cannot be the Gears directory".into());
        }
        source.exclude.push(relative.into());
    }
    if let Ok(relative) = task.path.strip_prefix(&context.workspace) {
        source.exclude.push(relative.into());
    }
    for argv in task.task.acceptance.iter().chain(&task.task.regressions) {
        let program = Path::new(&argv[0]);
        if !program.is_absolute() && !argv[0].contains('/') {
            continue;
        }
        let path = if program.is_absolute() {
            program.to_path_buf()
        } else {
            context.workspace.join(program)
        };
        let parent = ToolContext::new(
            path.parent()
                .ok_or("criterion has no program directory")?
                .into(),
            context.state.path().into(),
            "eval-criterion".into(),
            None,
        )?;
        let path = parent.workspace.join(
            path.file_name()
                .ok_or("criterion needs a program filename")?,
        );
        if let Ok(relative) = path.strip_prefix(&context.workspace) {
            source.exclude.push(relative.into());
        }
    }
    source.exclude.sort();
    source.exclude.dedup();
    root.directory(Path::new(""))?;
    let workspace = crate::eval_copy::copy(
        &source.workspace,
        &root.path().join("template"),
        &source.exclude,
    )?;
    let pinned = eval_config::prepare(
        context,
        &task.task,
        config,
        &root.path().join("config"),
        batteries,
    )?;
    let identity = json!({"version":1,"task":task.name,"task_hash":task.hash,
        "source_workspace":workspace,"exclusions":source.exclude,"configuration":pinned.identity});
    source.workspace = root.path().join("template");
    source.exclude.clear();
    root.replace_file(
        Path::new("inputs.json"),
        &serde_json::to_vec_pretty(&identity).map_err(|e| e.to_string())?,
    )?;
    Ok(Prepared {
        task,
        config: pinned,
        identity,
        root,
        template: source,
        frozen,
    })
}

impl Prepared {
    pub fn trial(&self, ordinal: usize, learning: bool) -> Result<Trial, String> {
        if ordinal >= 128 {
            return Err("evaluation trial ordinal exceeds 127".into());
        }
        let directory = self.root.path().join(format!("trial-{ordinal:03}"));
        let workspace = directory.join("workspace");
        let state = directory.join("state");
        crate::eval_copy::workspace(&self.template, &workspace)?;
        let versions = self.frozen.install(&workspace, &state, learning)?;
        let context = ToolContext::new(workspace.clone(), state.clone(), "eval".into(), None)?;
        crate::eval_policy::install(&context, &self.task.task.check)?;
        Ok(Trial {
            workspace,
            state,
            versions,
        })
    }
}
