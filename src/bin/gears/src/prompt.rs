//! Assembly and identity of reviewable prompt resources.

use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};

const DEFAULT_SYSTEM: &str = include_str!("../prompts/system.md");
pub const COMPACTION: &str = include_str!("../prompts/compact.md");

#[derive(Debug, Clone)]
pub struct Effective {
    fragments: Vec<String>,
    prompt_hash: String,
    manifest_hash: String,
}

impl Effective {
    pub fn new(workspace: &Path, hook_fragments: Vec<String>, manifest: &Value) -> Self {
        let mut fragments = vec![
            DEFAULT_SYSTEM.trim().to_string(),
            format!("Current working directory: {}", workspace.display()),
        ];
        fragments.extend(
            hook_fragments
                .into_iter()
                .filter(|fragment| !fragment.trim().is_empty()),
        );
        let prompt_hash = hash_json(&fragments);
        let manifest_hash = hash_json(manifest);
        Self {
            fragments,
            prompt_hash,
            manifest_hash,
        }
    }

    pub fn fragments(&self) -> &[String] {
        &self.fragments
    }

    pub fn identity(&self) -> crate::session::RuntimeIdentity {
        crate::session::RuntimeIdentity {
            prompt_hash: self.prompt_hash.clone(),
            manifest_hash: self.manifest_hash.clone(),
        }
    }
}

fn hash_json(value: &impl serde::Serialize) -> String {
    let encoded = serde_json::to_vec(value).expect("prompt identity is serializable");
    let digest = Sha256::digest(encoded);
    let mut result = String::with_capacity(digest.len() * 2);
    for byte in digest {
        result.push_str(&format!("{byte:02x}"));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_and_manifest_affect_identity() {
        let workspace = Path::new("/work");
        let first = Effective::new(
            workspace,
            vec!["one".into(), "two".into()],
            &serde_json::json!({"tools": ["sh"]}),
        );
        let reordered = Effective::new(
            workspace,
            vec!["two".into(), "one".into()],
            &serde_json::json!({"tools": ["sh"]}),
        );
        assert_ne!(
            first.identity().prompt_hash,
            reordered.identity().prompt_hash
        );
        let changed = Effective::new(
            workspace,
            vec!["one".into(), "two".into()],
            &serde_json::json!({"tools": ["sh", "extra"]}),
        );
        assert_ne!(
            first.identity().manifest_hash,
            changed.identity().manifest_hash
        );
    }

    #[test]
    fn working_directory_is_explicit() {
        let prompt = Effective::new(Path::new("/chosen"), Vec::new(), &Value::Null);
        assert!(
            prompt
                .fragments()
                .iter()
                .any(|fragment| fragment.contains("/chosen"))
        );
    }
}
