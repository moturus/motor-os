//! Nested Gears can select another directory while its ancestor retains its lock.

use gears::{
    mock::{MockServer, sse_response},
    process::{Cancellation, Request, run},
};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};

pub fn smoke(gears: &Path) -> Result<(), String> {
    let root = std::env::temp_dir().join(format!("gears-eval-directory-{}", std::process::id()));
    let workspace = root.join("workspace");
    let parent = root.join("parent");
    let child = workspace.join("child-state");
    let inherited = root.join("inherited");
    for directory in [&workspace, &parent, &child, &inherited] {
        std::fs::create_dir_all(directory).map_err(|e| e.to_string())?;
    }
    let sentinel = inherited.join(".gears-tmp-untouched");
    std::fs::write(&sentinel, "Keep this inherited state.").map_err(|e| e.to_string())?;
    let response = || {
        sse_response(&[
            r#"{"choices":[{"index":0,"delta":{"content":"Isolated response."},"finish_reason":"stop"}]}"#,
        ])
    };
    let server = MockServer::start(vec![response(), response()]).map_err(|e| e.to_string())?;
    let key = root.join("key");
    std::fs::write(&key, "fixture").map_err(|e| e.to_string())?;
    let config = |model: &str| {
        format!(
            "version=1\n[provider]\nbase_url={:?}\napi_key_file={:?}\nmodel={model:?}\n[net]\negress_allowlist=['127.0.0.1']\nplain_http_allowlist=['127.0.0.1']\n",
            server.url("/v1"),
            key
        )
    };
    let child_config = root.join("child.toml");
    std::fs::write(&child_config, config("child-fixture")).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    let shell = "/bin/sh";
    #[cfg(not(unix))]
    let shell = "/system/bin/rush";
    let child_output = root.join("child.jsonl");
    let hook = json!([
        shell,
        "-c",
        "if \"$1\" --config \"$2\" --gears-dir \"$3\" --ephemeral --output jsonl -p child > \"$4\"; then printf '{}'; else exit 1; fi",
        "fixture",
        gears,
        child_config,
        "child-state",
        child_output
    ]);
    let parent_config = root.join("parent.toml");
    std::fs::write(
        &parent_config,
        format!(
            "{}\n[[hooks]]\nname='nested'\nevents=['initialize']\ncommand={hook}\n",
            config("parent-fixture")
        ),
    )
    .map_err(|e| e.to_string())?;
    let mut request = Request {
        program: gears.to_str().ok_or("binary is not UTF-8")?.into(),
        args: vec![
            "--config".into(),
            parent_config.display().to_string(),
            "--gears-dir".into(),
            parent.display().to_string(),
            "--ephemeral".into(),
            "-p".into(),
            "parent".into(),
            "--output".into(),
            "jsonl".into(),
        ],
        cwd: workspace,
        stdin: None,
        timeout: Duration::from_secs(30),
        max_output_bytes: 65536,
        env: vec![(
            gears::directory::ENV.into(),
            inherited.display().to_string(),
        )],
        remove_env: vec!["GEARS_LOCK_OWNER".into(), gears::provider::KEY_ENV.into()],
    };
    let invalid_root = root.join("invalid");
    let valid_args = std::mem::replace(
        &mut request.args,
        vec!["--gears-dir".into(), invalid_root.display().to_string()],
    );
    let invalid = run(&request, &Cancellation::new(), &mut |_, _| {}).map_err(|e| e.to_string())?;
    assert!(!invalid.success());
    assert!(invalid.stderr.contains("--config PATH --ephemeral -p"));
    assert!(!invalid_root.exists());
    assert!(server.requests().is_empty());
    request.args = valid_args;
    let output = run(&request, &Cancellation::new(), &mut |_, _| {}).map_err(|e| e.to_string())?;
    assert!(output.success(), "{output:?}");
    assert!(!output.stdout.contains("hook nested:"), "{output:?}");
    let child_text = std::fs::read_to_string(&child_output).map_err(|e| e.to_string())?;
    let final_record: Value = serde_json::from_str(
        child_text
            .lines()
            .last()
            .ok_or("child has no final record")?,
    )
    .map_err(|e| e.to_string())?;
    assert_eq!(final_record["type"], "final");
    assert_eq!(final_record["success"], true);
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    for (request, model) in requests.iter().zip(["child-fixture", "parent-fixture"]) {
        let body: Value = serde_json::from_slice(&request.body).map_err(|e| e.to_string())?;
        assert_eq!(body["model"], model);
    }
    assert!(sentinel.exists());
    for directory in [&parent, &child] {
        assert!(!directory.join("gears.lock").exists());
        assert!(!directory.join("sessions").exists());
    }
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())?;
    println!("gears evaluation directory CLI ALL PASS");
    Ok(())
}
