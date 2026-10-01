use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::{
    DependencySource, MANIFEST_NAME, MAX_WORKSPACE_MEMBERS, Manifest, ManifestMode, Workspace,
    canonical_manifest, resolve_target_defaults,
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
        let directory = manifest_path.parent().unwrap();
        let (mut root, mut packages) = match nearest_workspace(directory)? {
            Some(workspace) => (workspace.root.clone(), load_members(&workspace)?),
            None => (
                directory.to_owned(),
                vec![load_package(directory, directory)?],
            ),
        };
        // As in Lorry's build path, a package that its nearest workspace does
        // not include is described as a standalone package.
        if directory != root && !packages.iter().any(|package| package.root == directory) {
            root = directory.to_owned();
            packages = vec![load_package(directory, directory)?];
        }
        if let Some(selected) = selected {
            let available = packages
                .iter()
                .map(|package| package.name.clone())
                .collect::<Vec<_>>();
            packages.retain(|package| package.name == selected);
            if packages.is_empty() {
                return Err(
                    Error::failure(format!("workspace has no package named `{selected}`"))
                        .with_help(format!(
                            "available workspace packages: {}",
                            available.join(", ")
                        )),
                );
            }
        }
        if packages.is_empty() {
            return Err(Error::failure("workspace has no source packages"));
        }
        Ok(Self {
            manifest_path,
            root,
            packages,
        })
    }
}

// Cargo selects the nearest enclosing manifest with a `[workspace]` table.
fn nearest_workspace(directory: &Path) -> Result<Option<Workspace>> {
    for ancestor in directory.ancestors() {
        let path = ancestor.join(MANIFEST_NAME);
        if !path.is_file() {
            continue;
        }
        let document = Document::load(&path, "Cargo source manifest")?;
        if document.root().contains_key("workspace") {
            return Workspace::parse(ancestor, &path, &document).map(Some);
        }
    }
    Ok(None)
}

// Path dependencies below the workspace root are implicit members in Cargo.
fn load_members(workspace: &Workspace) -> Result<Vec<Manifest>> {
    let mut pending = workspace.members.values().cloned().collect::<Vec<_>>();
    let mut packages = BTreeMap::new();
    while let Some(directory) = pending.pop() {
        if packages.contains_key(&directory) {
            continue;
        }
        if packages.len() == MAX_WORKSPACE_MEMBERS {
            return Err(Error::failure(format!(
                "workspace has more than {MAX_WORKSPACE_MEMBERS} members"
            )));
        }
        let package = load_package(&directory, &workspace.root)?;
        for dependency in &package.dependencies {
            if let DependencySource::Path(path) = &dependency.source
                && let Ok(path) = fs::canonicalize(path)
                && path.starts_with(&workspace.root)
            {
                pending.push(path);
            }
        }
        packages.insert(directory, package);
    }
    Ok(packages.into_values().collect())
}

fn load_package(directory: &Path, root: &Path) -> Result<Manifest> {
    let path = directory.join(MANIFEST_NAME);
    let document = Document::load(&path, "Cargo source manifest")?;
    let mut manifest = Manifest::parse_document(directory, &path, &document, ManifestMode::Source)?;
    resolve_target_defaults(&mut manifest)?;
    root.clone_into(&mut manifest.workspace_root);
    Ok(manifest)
}
