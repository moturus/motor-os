//! Bounded workspace snapshots with literal exclusions and no linked entries.

use gears::state::StateRoot;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, Serialize)]
pub struct Identity {
    pub version: u32,
    pub files: usize,
    pub bytes: u64,
    pub hash: String,
}

struct Copy<'a> {
    source: &'a Path,
    target: StateRoot,
    exclude: &'a [PathBuf],
    files: usize,
    entries: usize,
    bytes: u64,
    manifest: Sha256,
}

pub fn workspace(task: &crate::eval_task::Task, destination: &Path) -> Result<Identity, String> {
    task.validate()?;
    let context = crate::paths::ToolContext::new(
        task.workspace.clone(),
        destination.into(),
        "eval-copy".into(),
        None,
    )?;
    let source = context.workspace;
    let destination = context.state.path();
    if destination.starts_with(&source) || source.starts_with(destination) {
        return Err("evaluation copy must be separate from its source workspace".into());
    }
    match std::fs::symlink_metadata(destination) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err("evaluation copy destination must not exist".into()),
    }
    context.state.directory(Path::new(""))?;
    let mut copy = Copy {
        source: &source,
        target: context.state.clone(),
        exclude: &task.exclude,
        files: 0,
        entries: 0,
        bytes: 0,
        manifest: Sha256::new(),
    };
    if let Err(error) = copy.directory(Path::new(""), 0) {
        return match std::fs::remove_dir_all(destination) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(format!(
                "{error}; removing incomplete evaluation copy failed: {cleanup}"
            )),
        };
    }
    Ok(Identity {
        version: 1,
        files: copy.files,
        bytes: copy.bytes,
        hash: format!("{:x}", copy.manifest.finalize()),
    })
}

impl Copy<'_> {
    fn directory(&mut self, relative: &Path, depth: usize) -> Result<(), String> {
        if depth > 64 {
            return Err("evaluation copy exceeds 64 directory levels".into());
        }
        let mut entries = std::fs::read_dir(self.source.join(relative))
            .map_err(|e| e.to_string())?
            .take(100_001)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        if entries.len() > 100_000 {
            return Err("evaluation directory exceeds 100000 entries".into());
        }
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = relative.join(entry.file_name());
            if self
                .exclude
                .iter()
                .any(|excluded| path.starts_with(excluded))
            {
                continue;
            }
            self.entries += 1;
            if self.entries > 100_000 {
                return Err("evaluation copy exceeds 100000 entries".into());
            }
            let name = path.to_str().ok_or("evaluation filenames must be UTF-8")?;
            self.manifest.update((name.len() as u64).to_le_bytes());
            self.manifest.update(name.as_bytes());
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            if kind.is_dir() {
                self.manifest.update(b"directory");
                self.target.directory(&path)?;
                self.directory(&path, depth + 1)?;
            } else if kind.is_file() {
                self.file(&path)?;
            } else {
                return Err(format!(
                    "evaluation copy refuses non-regular entry {}",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    fn file(&mut self, relative: &Path) -> Result<(), String> {
        self.files += 1;
        if self.files > 100_000 {
            return Err("evaluation copy exceeds 100000 files".into());
        }
        let source = self.source.join(relative);
        let before = std::fs::symlink_metadata(&source).map_err(|e| e.to_string())?;
        if !before.is_file() {
            return Err("evaluation copy source changed type".into());
        }
        let destination = self.target.file(relative)?;
        let mut input = File::open(&source).map_err(|e| e.to_string())?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
            .map_err(|e| e.to_string())?;
        let mut hash = Sha256::new();
        let mut length = 0u64;
        let mut buffer = [0; 32768];
        loop {
            let count = input.read(&mut buffer).map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            self.bytes += count as u64;
            length += count as u64;
            if self.bytes > 512 * 1024 * 1024 {
                return Err("evaluation copy exceeds 512 MiB; add explicit exclusions".into());
            }
            output
                .write_all(&buffer[..count])
                .map_err(|e| e.to_string())?;
            hash.update(&buffer[..count]);
        }
        let after = input.metadata().map_err(|e| e.to_string())?;
        if length != before.len()
            || before.len() != after.len()
            || before.modified().ok() != after.modified().ok()
        {
            return Err(
                "workspace changed during evaluation copy; freeze it before copying".into(),
            );
        }
        output.sync_all().map_err(|e| e.to_string())?;
        drop(output);
        access(&source, &destination, &before)?;
        self.manifest.update(b"file");
        self.manifest.update(length.to_le_bytes());
        self.manifest.update(hash.finalize());
        Ok(())
    }
}

fn access(source: &Path, destination: &Path, metadata: &std::fs::Metadata) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = source;
        std::fs::set_permissions(
            destination,
            std::fs::Permissions::from_mode(metadata.permissions().mode() & 0o777),
        )
        .map_err(|e| e.to_string())
    }
    #[cfg(not(unix))]
    {
        use moto_rt::fs::{PERM_EXEC, PERM_READ};
        let _ = metadata;
        let source = source.to_str().ok_or("source path is not UTF-8")?;
        let destination = destination
            .to_str()
            .ok_or("destination path is not UTF-8")?;
        let mode = moto_rt::fs::stat(source)
            .map_err(|e| format!("{e:?}"))?
            .perm;
        if mode & PERM_EXEC != 0 {
            moto_rt::fs::set_perm(destination, PERM_READ | PERM_EXEC)
                .map_err(|e| format!("{e:?}"))?;
        }
        moto_rt::fs::set_perm(destination, mode).map_err(|e| format!("{e:?}"))
    }
}
