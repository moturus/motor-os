//! Equal copies, original-byte isolation and portable executable access.

use gears::process::{Cancellation, Request, run};
use gears_batteries::{eval_copy, eval_task::Task};
use std::{path::Path, time::Duration};

pub fn run_fixture(root: &Path, rustc: &str) -> Result<(), String> {
    let source = root.join("source");
    std::fs::create_dir_all(source.join("target")).unwrap();
    std::fs::create_dir(source.join("empty")).unwrap();
    std::fs::write(source.join("target/skip"), "build artifact").unwrap();
    std::fs::write(source.join("a file*"), "original").unwrap();
    std::fs::write(
        source.join("check.rs"),
        "fn main() { println!(\"copy executed\"); }",
    )
    .unwrap();
    let compiled = run(
        &Request {
            program: rustc.into(),
            args: vec![
                source.join("check.rs").display().to_string(),
                "-o".into(),
                source.join("check program*").display().to_string(),
            ],
            cwd: source.clone(),
            stdin: None,
            timeout: Duration::from_secs(60),
            max_output_bytes: 32768,
            env: vec![],
            remove_env: vec![gears::provider::KEY_ENV.into()],
        },
        &Cancellation::new(),
        &mut |_, _| {},
    )
    .map_err(|e| e.to_string())?;
    assert!(compiled.success(), "{}", compiled.stderr);
    let task = Task {
        version: 1,
        workspace: source.clone(),
        prompt: "fix".into(),
        exclude: vec!["target".into()],
        check: vec!["./check program*".into()],
        acceptance: vec![vec!["judge".into()]],
        regressions: vec![vec!["regressions".into()]],
    };
    let a = root.join("a");
    let b = root.join("b");
    let identity = eval_copy::workspace(&task, &a)?;
    assert_eq!(identity.hash, eval_copy::workspace(&task, &b)?.hash);
    assert!(a.join("empty").is_dir());
    assert!(!a.join("target").exists());
    assert_eq!(identity.files, 3);
    assert!(identity.bytes > 8);
    let executable = run(
        &Request {
            program: a.join("check program*").display().to_string(),
            args: vec![],
            cwd: a.clone(),
            stdin: None,
            timeout: Duration::from_secs(10),
            max_output_bytes: 32768,
            env: vec![],
            remove_env: vec![gears::provider::KEY_ENV.into()],
        },
        &Cancellation::new(),
        &mut |_, _| {},
    )
    .map_err(|e| e.to_string())?;
    assert!(executable.success(), "{}", executable.stderr);
    assert_eq!(executable.stdout.trim(), "copy executed");
    std::fs::write(a.join("a file*"), "trial writes").unwrap();
    assert_eq!(std::fs::read(source.join("a file*")).unwrap(), b"original");
    assert_eq!(std::fs::read(b.join("a file*")).unwrap(), b"original");
    assert!(eval_copy::workspace(&task, &a).is_err());
    assert!(eval_copy::workspace(&task, &source.join("nested")).is_err());
    assert!(!source.join("nested").exists());
    std::fs::write(source.join("a file*"), "changed").unwrap();
    assert_ne!(
        identity.hash,
        eval_copy::workspace(&task, &root.join("c"))?.hash
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&b, source.join("linked")).unwrap();
        assert!(eval_copy::workspace(&task, &root.join("linked-copy")).is_err());
        assert!(!root.join("linked-copy").exists());
    }
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())
}
