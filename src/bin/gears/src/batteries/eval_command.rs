//! Executable criteria are run as literal vectors outside the model conversation.

use crate::process::{self, Cancellation, Request};
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, Instant},
};

pub fn run(
    argv: &[String],
    base: &Path,
    workspace: &Path,
    timeout: Duration,
    cancel: &Cancellation,
) -> Result<Value, String> {
    crate::batteries::eval_task::command(argv)?;
    if timeout < Duration::from_secs(1) || timeout > Duration::from_secs(3600) {
        return Err("evaluation command deadline must be 1–3600 seconds".into());
    }
    let program = if argv[0].contains('/') && !Path::new(&argv[0]).is_absolute() {
        base.join(&argv[0])
            .to_str()
            .ok_or("criterion program path must be UTF-8")?
            .to_string()
    } else {
        argv[0].clone()
    };
    let start = Instant::now();
    let result = process::run(
        &Request {
            program: program.clone(),
            args: argv[1..].to_vec(),
            cwd: workspace.into(),
            stdin: None,
            timeout,
            max_output_bytes: 128 * 1024,
            env: vec![(
                "GEARS_EVAL_WORKSPACE".into(),
                workspace
                    .to_str()
                    .ok_or("criterion workspace must be UTF-8")?
                    .into(),
            )],
            remove_env: vec![crate::provider::KEY_ENV.into()],
        },
        cancel,
        &mut |_, _| {},
    );
    process::ensure_cleanup()?;
    Ok(match result {
        Ok(output) => json!({"version":1,"argv":argv,"program":program,"passed":output.success(),
            "exit_status":output.code,"duration_ms":start.elapsed().as_millis().min(u64::MAX as u128) as u64,
            "timed_out":output.timed_out,"cancelled":output.cancelled,
            "stdout":output.stdout,"stderr":output.stderr,
            "stdout_dropped":output.stdout_dropped,"stderr_dropped":output.stderr_dropped}),
        Err(error) => json!({"version":1,"argv":argv,"program":program,"passed":false,
            "started":error.started,"error":error.to_string(),
            "duration_ms":start.elapsed().as_millis().min(u64::MAX as u128) as u64}),
    })
}
