//! Records a build-script run so a later build can replay its output instead
//! of running the script again. Reruns follow Cargo's `rerun-if` rules.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::atomic::AtomicFile;
use crate::build_script::{self, Directive, Output, RunOptions};
use crate::diagnostic::{Error, Result};
use crate::hash::{FieldDigest, hex};
use crate::json::Value;
use crate::sandbox::Executable;

const FILE_NAME: &str = ".lorry-run-v1";
const FORMAT: &str = "lorry-build-script-run-v1";

/// Identifies a run by the script's bytes, the toolchain, the script's whole
/// environment, and its granted tools, including each tool's file metadata.
pub fn key(
    rustc_version: &str,
    executable_sha256: &[u8; 32],
    environment: &BTreeMap<String, OsString>,
    executables: &[Executable],
) -> Result<[u8; 32]> {
    let mut digest = FieldDigest::tagged(FORMAT.as_bytes());
    digest.bytes("rustc", rustc_version.as_bytes());
    digest.bytes("executable", executable_sha256);
    for (name, value) in environment {
        digest.bytes("environment-name", name.as_bytes());
        digest.bytes("environment-value", value.as_encoded_bytes());
    }
    for tool in executables {
        digest.metadata("tool", &tool.path)?;
        for argument in &tool.argument_prefix {
            digest.bytes("tool-argument", argument.as_encoded_bytes());
        }
    }
    Ok(digest.finish())
}

pub fn now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// Replays the run recorded in `directory` when its key, its OUT_DIR, and the
/// inputs it tracks are unchanged. `package_sources` fingerprints a mutable
/// package; a script that declares no `rerun-if` directive depends on it.
pub fn fresh(
    directory: &Path,
    key: &[u8; 32],
    run: &RunOptions<'_>,
    package_sources: impl Fn() -> Result<Option<[u8; 32]>>,
) -> Option<Output> {
    let path = directory.join(FILE_NAME);
    let record = Value::parse(&path, "build-script run record", &fs::read(&path).ok()?).ok()?;
    let record = record.as_object()?;
    let field = |name: &str| record.get(name).and_then(Value::as_str);
    (field("format")? == FORMAT && field("key")? == hex(key)).then_some(())?;
    let output = build_script::replay(
        run,
        field("stdout")?.as_bytes(),
        field("stderr")?.to_owned(),
    )
    .ok()?;
    (field("out-dir")? == hex(&output.out_dir.sha256)).then_some(())?;
    let out_dir = fs::canonicalize(run.out_dir).ok()?;
    let inputs = match declared_inputs(&output, &out_dir) {
        Some(paths) => Some(build_script::input_digest(&paths).ok()?.0),
        None if tracks_environment(&output) => None,
        None => package_sources().ok()?,
    };
    (inputs.map(|digest| hex(&digest)).as_deref() == field("inputs")).then_some(output)
}

pub fn remove(directory: &Path) -> Result<()> {
    let path = directory.join(FILE_NAME);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::failure(format!(
            "failed to remove build-script run record `{}`: {error}",
            path.display()
        ))),
    }
}

/// Records a completed run. `package_sources` must be taken before the run,
/// and `started` is when it began.
pub fn write(
    directory: &Path,
    key: &[u8; 32],
    run: &RunOptions<'_>,
    output: &Output,
    package_sources: Option<[u8; 32]>,
    started: Duration,
) -> Result<()> {
    let out_dir = fs::canonicalize(run.out_dir).map_err(|error| {
        Error::failure(format!(
            "failed to resolve build-script OUT_DIR `{}`: {error}",
            run.out_dir.display()
        ))
    })?;
    let inputs = match declared_inputs(output, &out_dir) {
        Some(paths) => match build_script::input_digest(&paths) {
            // An input edited while the script ran may be missing from its
            // output, so the next build runs it again.
            Ok((digest, newest)) if newest < started => Some(digest),
            _ => return Ok(()),
        },
        None if tracks_environment(output) => None,
        None => package_sources,
    };
    let string = |value: &str| Value::String(value.to_owned());
    let record = Value::Object(BTreeMap::from([
        ("format".to_owned(), string(FORMAT)),
        ("key".to_owned(), string(&hex(key))),
        ("stdout".to_owned(), string(&output.stdout)),
        ("stderr".to_owned(), string(&output.stderr)),
        ("out-dir".to_owned(), string(&hex(&output.out_dir.sha256))),
        (
            "inputs".to_owned(),
            inputs.map_or(Value::Null, |digest| string(&hex(&digest))),
        ),
    ]));
    let mut file = AtomicFile::new(&directory.join(FILE_NAME))?;
    file.write_all(&record.canonical_bytes())?;
    file.commit()
}

/// Paths named by `rerun-if-changed`, or `None` when there are none. Files in
/// OUT_DIR are already covered by its recorded tree.
fn declared_inputs(output: &Output, out_dir: &Path) -> Option<Vec<PathBuf>> {
    let declared = output
        .directives
        .iter()
        .filter_map(|directive| match directive {
            Directive::RerunIfChanged(path) => Some(path),
            _ => None,
        })
        .collect::<Vec<_>>();
    (!declared.is_empty()).then(|| {
        declared
            .into_iter()
            .filter(|path| !fs::canonicalize(path).is_ok_and(|path| path.starts_with(out_dir)))
            .cloned()
            .collect()
    })
}

fn tracks_environment(output: &Output) -> bool {
    output
        .directives
        .iter()
        .any(|directive| matches!(directive, Directive::RerunIfEnvChanged { .. }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_key_covers_its_tools_files() {
        let root = std::env::temp_dir().join(format!("lorry-run-key-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let tool = Executable {
            path: root.join("cc"),
            argument_prefix: Vec::new(),
        };
        fs::write(&tool.path, b"old compiler").unwrap();
        let key = || {
            key(
                "rustc 1.99",
                &[1; 32],
                &BTreeMap::new(),
                std::slice::from_ref(&tool),
            )
        };
        let before = key().unwrap();
        // An upgraded compiler at the same path runs the script again.
        fs::write(&tool.path, b"upgraded compiler").unwrap();
        assert_ne!(key().unwrap(), before);
        fs::remove_dir_all(root).unwrap();
    }
}
