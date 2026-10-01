use std::path::{Path, PathBuf};

use super::{
    MANIFEST_NAME, Manifest, ManifestMode, canonical_manifest, discover_workspace,
    resolve_target_defaults,
};
use crate::diagnostic::{Error, Result};
use crate::toml::Document;

pub(crate) struct SourceWorkspace {
    pub manifest_path: PathBuf,
    pub root: PathBuf,
    pub packages: Vec<Manifest>,
}

impl SourceWorkspace {
    // Editor discovery describes source targets before dependency preparation.
    // It must neither inspect nor repair Cargo.lock or admission state.
    pub fn load(
        current: &Path,
        manifest_path: Option<&Path>,
        selected: Option<&str>,
    ) -> Result<Self> {
        let manifest_path =
            canonical_manifest(manifest_path.unwrap_or(&current.join(MANIFEST_NAME)))?;
        let root = manifest_path.parent().unwrap();
        let document = Document::load(&manifest_path, "Cargo source manifest")?;
        let (root, members) = match discover_workspace(root, &manifest_path, &document)? {
            Some(workspace) => {
                let members = if selected.is_some() {
                    vec![workspace.select(root, selected)?]
                } else {
                    workspace.members.into_values().collect()
                };
                (workspace.root, members)
            }
            None => (root.to_owned(), vec![root.to_owned()]),
        };
        if members.is_empty() {
            return Err(Error::failure("workspace has no source packages"));
        }
        let mut packages = Vec::with_capacity(members.len());
        for member in members {
            let path = member.join(MANIFEST_NAME);
            let document = Document::load(&path, "Cargo source manifest")?;
            let mut manifest =
                Manifest::parse_document(&member, &path, &document, ManifestMode::Source)?;
            resolve_target_defaults(&mut manifest)?;
            manifest.workspace_root.clone_from(&root);
            packages.push(manifest);
        }
        if let Some(selected) = selected
            && selected != packages[0].name
        {
            return Err(Error::failure(format!(
                "package `{selected}` is not the current package `{}`",
                packages[0].name
            )));
        }
        Ok(Self {
            manifest_path,
            root,
            packages,
        })
    }
}
