//! Fixed-argument ripgrep searches under Gears' process ownership.

use std::time::Duration;

use crate::process::{Cancellation, Request, run};
use serde_json::{Value, json};

use crate::batteries::paths::ToolContext;

pub fn files(context: &ToolContext, pattern: &str, input: &str) -> Result<Value, String> {
    let path = context.resolve(input, false)?;
    if context.state.path().starts_with(&path) {
        return Err("search path contains the Gears directory; choose a narrower path".into());
    }
    let metadata = std::fs::metadata(&path).map_err(|error| error.to_string())?;
    if !metadata.is_file() && !metadata.is_dir() {
        return Err("search_files requires a regular file or directory".into());
    }
    #[cfg(unix)]
    let program = "rg";
    #[cfg(not(unix))]
    let program = "/system/bin/rg";
    let output = run(
        &Request {
            program: program.into(),
            args: vec![
                "--json".into(),
                "--no-config".into(),
                "-e".into(),
                pattern.into(),
                "--".into(),
                path.to_str().ok_or("search path is not UTF-8")?.into(),
            ],
            cwd: context.workspace.clone(),
            stdin: None,
            timeout: Duration::from_secs(30),
            max_output_bytes: 128 * 1024,
            env: Vec::new(),
            remove_env: vec![crate::provider::KEY_ENV.into()],
        },
        &Cancellation::new(),
        &mut |_, _| {},
    )
    .map_err(|error| error.to_string())?;
    if output.cancelled || output.timed_out || !matches!(output.code, Some(0 | 1)) {
        return Err(format!(
            "search_files failed ({}): {}",
            output.status, output.stderr
        ));
    }
    Ok(json!({"output": output.stdout, "exit_status": output.code,
        "truncated": output.stdout_dropped != 0, "stderr": output.stderr}))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn literal_paths_and_patterns_and_no_match_are_safe_outcomes() {
        let root = std::env::temp_dir().join(format!("batteries-search-{}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        let context = ToolContext::new(
            root.join("workspace"),
            root.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        std::fs::write(context.workspace.join("a file*"), "literal -pattern\n").unwrap();
        let found = files(&context, "-pattern", "a file*").unwrap();
        assert_eq!(found["exit_status"], 0);
        let events: Vec<Value> = found["output"]
            .as_str()
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert!(events.iter().any(|event| event["type"] == "match"));
        assert_eq!(files(&context, "absent", ".").unwrap()["exit_status"], 1);
        assert!(files(&context, "[", ".").unwrap_err().contains("failed"));
        assert!(
            files(&context, "secret", "..")
                .unwrap_err()
                .contains("Gears directory")
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
