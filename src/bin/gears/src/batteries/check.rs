//! Run exactly the declared argument vector and report its observed status.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::process::{Cancellation, Request, run};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::batteries::paths::ToolContext;

#[derive(Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub version: u32,
    pub kind: String,
    pub argv: Vec<String>,
    pub system: String,
    pub exit_status: Option<i32>,
    pub duration_ms: u64,
    pub passed: bool,
    pub stdout: String,
    pub stderr: String,
    pub output_truncated: bool,
    pub output_file: Option<std::path::PathBuf>,
}

pub fn execute(context: &ToolContext) -> Result<Value, String> {
    let system = crate::batteries::check_config::system();
    let argv = crate::batteries::check_config::load(context, system)?
        .ok_or("no check declared for this platform")?;
    let program = if argv[0].contains('/') && !Path::new(&argv[0]).is_absolute() {
        context
            .workspace
            .join(&argv[0])
            .to_str()
            .ok_or("check program path is not UTF-8")?
            .to_string()
    } else {
        argv[0].clone()
    };
    let started = Instant::now();
    let output = run(
        &Request {
            program,
            args: argv[1..].to_vec(),
            cwd: context.workspace.clone(),
            stdin: None,
            timeout: Duration::from_secs(120),
            max_output_bytes: 128 * 1024,
            env: Vec::new(),
            remove_env: vec![crate::provider::KEY_ENV.into()],
        },
        &Cancellation::new(),
        &mut |_, _| {},
    )
    .map_err(|error| error.to_string())?;
    let duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    let saved = json!({"version": 1, "argv": argv, "system": system,
        "exit_status": output.code, "duration_ms": duration_ms, "passed": output.success(),
        "stdout": output.stdout, "stderr": output.stderr,
        "stdout_dropped": output.stdout_dropped, "stderr_dropped": output.stderr_dropped});
    let bytes = serde_json::to_vec(&saved).map_err(|error| error.to_string())?;
    let name = format!("check-{}.json", crate::batteries::snapshot::digest(&bytes));
    // Full output belongs to this session's allowed saved-results directory.
    let output_file = context.save_result(&name, &bytes);
    let mut receipt = serde_json::to_value(Receipt {
        version: 1,
        kind: "check".into(),
        argv,
        system: system.into(),
        exit_status: output.code,
        duration_ms,
        passed: output.success(),
        stdout: preview(&output.stdout),
        stderr: preview(&output.stderr),
        output_truncated: output.stdout_dropped != 0
            || output.stderr_dropped != 0
            || output.stdout.len() > 1000
            || output.stderr.len() > 1000,
        output_file: output_file
            .as_ref()
            .ok()
            .cloned()
            .flatten()
            .map(|path| context.relative(&path)),
    })
    .map_err(|error| error.to_string())?;
    if let Err(error) = output_file {
        receipt["warning"] = json!(format!("check ran, but saving full output failed: {error}"));
    }
    Ok(receipt)
}

fn preview(text: &str) -> String {
    let mut end = text.len().min(1000);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].into()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn records_literal_arguments_failed_checks_and_full_output_without_shell_interpretation() {
        let root = std::env::temp_dir().join(format!("batteries-check-{}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace/.gears")).unwrap();
        let state = root.join("state");
        let session = state.join("sessions/current.jsonl");
        let context =
            ToolContext::new(root.join("workspace"), state, "s1".into(), Some(&session)).unwrap();
        let config = context.workspace.join(".gears/batteries.toml");
        std::fs::write(
            &config,
            "check = ['/usr/bin/printf', '%s', 'a file*;echo injected']",
        )
        .unwrap();
        let result = execute(&context).unwrap();
        assert_eq!(result["passed"], true);
        assert_eq!(result["stdout"], "a file*;echo injected");
        assert_eq!(result["argv"][2], "a file*;echo injected");
        let path = context
            .resolve(result["output_file"].as_str().unwrap(), false)
            .unwrap();
        let full: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(full["exit_status"], 0);
        assert_eq!(full["version"], 1);
        std::fs::write(&config, "check = ['/usr/bin/false']").unwrap();
        let failed = execute(&context).unwrap();
        assert_eq!(failed["passed"], false);
        assert_eq!(failed["exit_status"], 1);
        std::fs::write(&config, "check = ['/missing/program']").unwrap();
        assert!(execute(&context).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
