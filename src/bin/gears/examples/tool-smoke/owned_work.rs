//! The same owned nested-run regression on Linux and Motor OS.

use std::path::Path;
use std::time::Duration;

use gears::mock::{MockServer, sse_response};
use gears::process::{Cancellation, Request, Stream, run};
use serde_json::{Value, json};

pub fn smoke(gears: &Path, sh_directory: &Path) -> Result<(), String> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("gears-owned-work-{}-{stamp}", std::process::id()));
    std::fs::create_dir(&root).map_err(|error| error.to_string())?;
    let result = check(gears, sh_directory, &root);
    if result.is_ok() {
        std::fs::remove_dir_all(&root).map_err(|error| error.to_string())?;
    } else {
        eprintln!("owned-work fixtures retained in {}", root.display());
    }
    result
}

fn check(gears: &Path, sh_directory: &Path, root: &Path) -> Result<(), String> {
    for mode in ["normal", "cancel", "timeout"] {
        let workspace = root.join(mode);
        std::fs::create_dir(&workspace).map_err(|error| error.to_string())?;
        let tools = workspace.join("tool");
        std::fs::create_dir(&tools).map_err(|error| error.to_string())?;
        for file in ["tool.toml", "parameters.json", "run.sh"] {
            let text = std::fs::read_to_string(sh_directory.join(file))
                .map_err(|error| error.to_string())?;
            std::fs::write(
                tools.join(file),
                text.replace("name = \"sh\"", "name = \"owned_tree\""),
            )
            .map_err(|error| error.to_string())?;
        }
        let tree = "printf '%s' $$ > child.pid; sleep 30 & printf '%s' $! > grandchild.pid; printf nested-ready; wait";
        let done = sse_response(&[
            r#"{"choices":[{"index":0,"delta":{"content":"nested done"},"finish_reason":"stop"}]}"#,
        ]);
        // A normal run's background job must not outlive its tool or block the
        // next call; a nested timeout stops only its tool and the run goes on.
        let scripts = match mode {
            "normal" => vec![
                sse_response(&[&call(
                    "first",
                    "sleep 30 & printf '%s' $! > leftover.pid; printf nested-normal",
                    30,
                )]),
                sse_response(&[&call("second", "printf second-ran", 30)]),
                done,
            ],
            "cancel" => vec![sse_response(&[&call("tree", tree, 30)])],
            _ => vec![sse_response(&[&call("tree", tree, 1)]), done],
        };
        let server = MockServer::start(scripts).map_err(|error| error.to_string())?;
        let key = workspace.join("key");
        std::fs::write(&key, "fixture-owned-key").map_err(|error| error.to_string())?;
        #[cfg(unix)]
        let shell = "/bin/sh";
        #[cfg(not(unix))]
        let shell = "/system/bin/rush";
        // Read the hook event without echoing it to the JSON response.
        let policy_file = workspace.join("policy.sh");
        std::fs::write(
            &policy_file,
            "event=$(cat); printf '{\"decision\":\"allow\"}'",
        )
        .map_err(|error| error.to_string())?;
        let config = workspace.join("gears.toml");
        std::fs::write(&config, format!(
            "version = 1\n[provider]\nbase_url = {:?}\nmodel = 'test/model'\napi_key_file = {:?}\n[net]\negress_allowlist = ['127.0.0.1']\nplain_http_allowlist = ['127.0.0.1']\n[[tools]]\ndirectory = {:?}\nenabled = true\n[[hooks]]\nname = 'policy'\nevents = ['permission']\ncommand = [{:?}, {:?}]\n",
            server.url("/v1"), key, tools, shell, policy_file,
        )).map_err(|error| error.to_string())?;
        let cancellation = Cancellation::new();
        let mut streamed = String::new();
        let output = run(
            &Request {
                program: gears.display().to_string(),
                args: vec![
                    "--config".into(),
                    config.display().to_string(),
                    "--workspace".into(),
                    workspace.display().to_string(),
                    "--ephemeral".into(),
                    "--output".into(),
                    "jsonl".into(),
                    "-p".into(),
                    "nested".into(),
                ],
                cwd: workspace.clone(),
                stdin: None,
                timeout: Duration::from_secs(10),
                max_output_bytes: 65536,
                env: vec![
                    ("HOME".into(), workspace.display().to_string()),
                    (
                        gears::directory::ENV.into(),
                        workspace.join(".gears").display().to_string(),
                    ),
                ],
                remove_env: vec![gears::provider::KEY_ENV.into()],
            },
            &cancellation,
            &mut |stream, text| {
                if stream == Stream::Stdout {
                    streamed.push_str(text);
                    if mode == "cancel"
                        && streamed
                            .lines()
                            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                            .any(|record| {
                                record["type"] == "tool_output"
                                    && record["text"]
                                        .as_str()
                                        .is_some_and(|text| text.contains("nested-ready"))
                            })
                    {
                        cancellation.cancel();
                    }
                }
            },
        )
        .map_err(|error| format!("{mode}: {error}"))?;
        if output.timed_out {
            return Err(format!("{mode}: owning runner timed out: {output:?}"));
        }
        if mode == "cancel" {
            // A killed child has no exit code on Linux and -1 on Motor OS.
            if !output.cancelled || output.stdout.contains("\"type\":\"final\"") {
                return Err(format!("cancel: nested run was not killed: {output:?}"));
            }
        } else if !output.success() || !output.stdout.contains("nested done") {
            return Err(format!("{mode}: nested run did not finish: {output:?}"));
        }
        let pids: &[&str] = if mode == "normal" {
            if !output.stdout.contains("second-ran") {
                return Err(format!(
                    "normal: the next tool call did not run: {output:?}"
                ));
            }
            &["leftover.pid"]
        } else {
            if !streamed.contains("nested-ready")
                || (mode == "timeout" && !output.stdout.contains("timed out"))
            {
                return Err(format!("{mode}: missing progress: {output:?}"));
            }
            &["child.pid", "grandchild.pid"]
        };
        for name in pids {
            let pid = std::fs::read_to_string(workspace.join(name))
                .map_err(|error| error.to_string())?
                .parse::<u32>()
                .map_err(|error| error.to_string())?;
            #[cfg(unix)]
            let stopped =
                std::fs::read_to_string(format!("/proc/{pid}/stat")).map_or(true, |stat| {
                    matches!(
                        stat.rsplit_once(") ").unwrap().1.split_whitespace().next(),
                        Some("Z" | "X" | "x")
                    )
                });
            #[cfg(not(unix))]
            let stopped = !gears::platform::process_alive(pid);
            if !stopped {
                return Err(format!("{mode}: descendant {pid} still running"));
            }
        }
    }
    Ok(())
}

fn call(id: &str, command: &str, timeout: u64) -> String {
    json!({"choices": [{"index": 0, "delta": {"tool_calls": [{
        "index": 0, "id": id, "function": {"name": "owned_tree",
        "arguments": json!({"command": command, "timeout": timeout}).to_string()}
    }]}, "finish_reason": "tool_calls"}]})
    .to_string()
}
