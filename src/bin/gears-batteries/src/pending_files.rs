//! Shared bounded content-addressed files for memory and skill proposals.

use std::io::Read;
use std::path::{Path, PathBuf};

use gears::state::StateRoot;
use serde::Serialize;
use serde_json::Value;

const MAX_BYTES: usize = 1024 * 1024;

fn relative(directory: &Path, id: &str) -> Result<PathBuf, String> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid pending proposal id".into());
    }
    Ok(directory.join(format!("{id}.json")))
}

pub fn stage(
    root: &StateRoot,
    directory: &Path,
    proposal: &impl Serialize,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(proposal).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_BYTES {
        return Err("proposal exceeds 1 MiB".into());
    }
    let id = crate::snapshot::digest(&bytes);
    root.replace_file(&relative(directory, &id)?, &bytes)?;
    Ok(id)
}

pub fn load(root: &StateRoot, directory: &Path, id: &str) -> Result<Value, String> {
    let path = root
        .existing_file(&relative(directory, id)?)?
        .ok_or("pending proposal is unavailable")?;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > MAX_BYTES || crate::snapshot::digest(&bytes) != id {
        return Err("pending proposal is oversized or its content hash changed".into());
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if value["version"] != 1 {
        return Err("unsupported pending proposal version".into());
    }
    Ok(value)
}

pub fn list(root: &StateRoot, directory: &Path) -> Result<Vec<(String, Value)>, String> {
    let Some(path) = root.existing_directory(directory)? else {
        return Ok(Vec::new());
    };
    let mut proposals = Vec::new();
    for entry in std::fs::read_dir(path).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("pending filename is not ASCII")?;
        if name.starts_with(".gears-tmp-") {
            continue;
        }
        let id = name
            .strip_suffix(".json")
            .ok_or("unrecognized pending filename")?;
        proposals.push((id.to_string(), load(root, directory, id)?));
        if proposals.len() > 1024 {
            return Err("more than 1024 pending changes".into());
        }
    }
    proposals.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(proposals)
}

pub fn remove(root: &StateRoot, directory: &Path, id: &str) -> Result<(), String> {
    let path = root
        .existing_file(&relative(directory, id)?)?
        .ok_or("pending proposal is unavailable")?;
    std::fs::remove_file(path).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mixed_proposal_files_are_checked_before_dispatch_and_incomplete_temporaries_are_ignored() {
        let path =
            std::env::temp_dir().join(format!("batteries-pending-files-{}", std::process::id()));
        let root = StateRoot::new(path.clone()).unwrap();
        let directory = Path::new("batteries/pending");
        let skill = json!({"version": 1, "kind": "skill", "content": "candidate"});
        let id = stage(&root, directory, &skill).unwrap();
        assert_eq!(load(&root, directory, &id).unwrap(), skill);
        std::fs::write(
            path.join(directory).join(".gears-tmp-abandoned"),
            "incomplete",
        )
        .unwrap();
        assert_eq!(list(&root, directory).unwrap(), [(id.clone(), skill)]);
        std::fs::write(path.join(directory).join(format!("{id}.json")), "{}").unwrap();
        assert!(list(&root, directory).unwrap_err().contains("hash changed"));
        assert!(load(&root, directory, "../escape").is_err());
        remove(&root, directory, &id).unwrap();
        assert!(list(&root, directory).unwrap().is_empty());
        let unsupported = stage(&root, directory, &json!({"version": 2})).unwrap();
        assert!(
            load(&root, directory, &unsupported)
                .unwrap_err()
                .contains("unsupported")
        );
        std::fs::remove_dir_all(path).unwrap();
    }
}
