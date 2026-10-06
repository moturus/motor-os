//! Copy the two executable versions into the owned evaluation output.

use gears::state::StateRoot;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub fn pin(root: &StateRoot, gears: &Path, batteries: &Path) -> Result<Value, String> {
    let relative = Path::new("bin");
    match std::fs::symlink_metadata(root.path().join(relative)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err("evaluation executable directory must be fresh".into()),
    }
    root.directory(relative)?;
    let mut manifest = serde_json::Map::new();
    for (name, source) in [("gears", gears), ("gears-batteries", batteries)] {
        let source = if source.is_absolute() {
            source.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|e| e.to_string())?
                .join(source)
        };
        let parent = crate::paths::ToolContext::new(
            source
                .parent()
                .ok_or("program needs a parent directory")?
                .into(),
            root.path().into(),
            "eval-binary".into(),
            None,
        )?;
        let source = parent
            .workspace
            .join(source.file_name().ok_or("program needs a filename")?);
        let destination = root.file(&PathBuf::from("bin").join(name))?;
        let (bytes, hash) = crate::eval_copy::file(&source, &destination, 256 * 1024 * 1024)?;
        let hash: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
        manifest.insert(
            name.into(),
            json!({"source":source,"bytes":bytes,"hash":hash}),
        );
    }
    Ok(json!(manifest))
}
