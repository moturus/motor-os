use super::*;
use crate::admission_state::ReviewScope;
use crate::manifest::SourceWorkspace;
use std::path::PathBuf;

pub(super) struct Records(Vec<(PathBuf, Vec<u8>)>);

impl Records {
    pub(super) fn collect(workspace: &SourceWorkspace, scope: &ReviewScope) -> Result<Self> {
        let mut records = Vec::new();
        for member in &workspace.packages {
            if member.root == workspace.root
                || (!scope.packages.is_empty() && !scope.packages.contains(&member.name))
            {
                continue;
            }
            if let Some(bytes) = read(&member.root)? {
                records.push((member.root.clone(), bytes));
            }
        }
        Ok(Self(records))
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(super) fn report(&self, messages: bool, completed: bool) -> Result<()> {
        if self.is_empty() {
            return Ok(());
        }
        let paths = self
            .0
            .iter()
            .map(|(root, _)| CompactState::path(root))
            .collect::<Vec<_>>();
        let mut output = io::stderr().lock();
        if messages {
            writeln!(
                output,
                "{}",
                serde_json::json!({
                    "reason": "lorry-admission-migration",
                    "stage": if completed { "completed" } else { "proposed" },
                    "replaced_records": paths,
                })
            )
        } else {
            writeln!(
                output,
                "{} per-member admission records:",
                if completed {
                    "Removed replaced"
                } else {
                    "This workspace review replaces"
                }
            )?;
            for path in paths {
                writeln!(output, "  {}", path.display())?;
            }
            Ok(())
        }
        .map_err(|error| Error::failure(format!("failed to report admission migration: {error}")))
    }

    pub(super) fn remove(&self) -> Result<()> {
        // Root approval is already durable. Never unlink a member record that
        // changed during the review or follows a substituted state directory.
        for (root, bytes) in &self.0 {
            if read(root)?.as_ref() != Some(bytes) {
                return Err(Error::failure(format!(
                    "member admission `{}` changed during workspace review; it was not removed",
                    CompactState::path(root).display(),
                )));
            }
            let path = CompactState::path(root);
            fs::remove_file(&path).map_err(|error| {
                Error::failure(format!(
                    "failed to remove replaced member admission `{}`: {error}",
                    path.display(),
                ))
            })?;
        }
        Ok(())
    }
}

fn read(root: &Path) -> Result<Option<Vec<u8>>> {
    let directory = root.join(".lorry");
    match fs::symlink_metadata(&directory) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(Error::failure(format!(
                "member state directory `{}` is not a real directory",
                directory.display(),
            )));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(Error::failure(format!(
                "failed to inspect member state directory `{}`: {error}",
                directory.display(),
            )));
        }
    }
    // Old member records are replaced unparsed; only the root record is reviewed.
    if !CompactState::exists(root)? {
        return Ok(None);
    }
    fs::read(CompactState::path(root))
        .map(Some)
        .map_err(|error| {
            Error::failure(format!(
                "failed to read member admission `{}`: {error}",
                CompactState::path(root).display(),
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_a_member_record_changed_after_review_started() {
        let fixture =
            crate::atomic::AtomicDirectory::new(&env::temp_dir(), "lorry-migrate").unwrap();
        let root = fixture.path();
        fs::create_dir_all(root.join("member/src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = ['member']\n",
        )
        .unwrap();
        fs::write(
            root.join("member/Cargo.toml"),
            "[package]\nname = 'member'\nversion = '1.0.0'\n",
        )
        .unwrap();
        fs::write(root.join("member/src/lib.rs"), "").unwrap();
        let workspace = SourceWorkspace::load(root, None).unwrap();
        let mut state = CompactState {
            scope: ReviewScope::default(),
            review_sha256: "1".repeat(64),
            contexts: vec![Context {
                host: "x86_64-unknown-linux-gnu".into(),
                target: "x86_64-unknown-linux-gnu".into(),
            }],
            capabilities: vec![],
        };
        state.write(&root.join("member")).unwrap();
        let records = Records::collect(&workspace, &ReviewScope::default()).unwrap();
        assert!(!records.is_empty());
        state.review_sha256 = "2".repeat(64);
        state.write(&root.join("member")).unwrap();
        assert!(
            records
                .remove()
                .unwrap_err()
                .render()
                .contains("changed during workspace review")
        );
        assert_eq!(
            CompactState::load(&root.join("member")).unwrap(),
            Some(state)
        );
    }
}
