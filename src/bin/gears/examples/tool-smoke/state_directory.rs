//! A real child uses one selected directory for defaults, locks and sessions.

use gears::{
    mock::{MockServer, sse_response},
    process::{Cancellation, Request, run},
    session::Store,
};
use serde_json::Value;
use std::{path::Path, time::Duration};

pub fn smoke(gears: &Path) -> Result<(), String> {
    let root = std::env::temp_dir().join(format!("gears-state-directory-{}", std::process::id()));
    let workspace = root.join("workspace");
    let selected = root.join("selected");
    std::fs::create_dir_all(&workspace).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&selected).map_err(|e| e.to_string())?;
    let server = MockServer::start_one(sse_response(&[
        r#"{"choices":[{"index":0,"delta":{"content":"Isolated response."},"finish_reason":"stop"}]}"#
    ])).map_err(|e| e.to_string())?;
    let key = selected.join("key");
    std::fs::write(&key, "fixture").map_err(|e| e.to_string())?;
    let config = selected.join("gears.toml");
    std::fs::write(&config, format!("version=1\n[provider]\nbase_url={:?}\napi_key_file={:?}\nmodel='config-model'\n[net]\negress_allowlist=['127.0.0.1']\nplain_http_allowlist=['127.0.0.1']\n", server.url("/v1"), key)).map_err(|e| e.to_string())?;
    std::fs::write(
        selected.join("provider.toml"),
        "version=1\nprovider='default'\nmodel='isolated-model'\n",
    )
    .map_err(|e| e.to_string())?;
    let marker = selected.join(".gears-tmp-directory-fixture");
    std::fs::write(&marker, "abandoned").map_err(|e| e.to_string())?;
    let mut request = Request {
        program: gears.to_str().ok_or("binary is not UTF-8")?.into(),
        args: vec![
            "--config".into(),
            config.display().to_string(),
            "-p".into(),
            "Do nothing.".into(),
            "--output".into(),
            "jsonl".into(),
        ],
        cwd: workspace.clone(),
        stdin: None,
        timeout: Duration::from_secs(30),
        max_output_bytes: 65536,
        env: vec![(gears::directory::ENV.into(), selected.display().to_string())],
        remove_env: vec!["GEARS_LOCK_OWNER".into(), gears::provider::KEY_ENV.into()],
    };
    std::fs::write(selected.join("tools.toml"), "invalid overrides").map_err(|e| e.to_string())?;
    let output = run(&request, &Cancellation::new(), &mut |_, _| {}).map_err(|e| e.to_string())?;
    assert!(!output.success());
    assert!(output.stderr.contains("tools.toml"), "{output:?}");
    assert!(server.requests().is_empty());
    assert!(!marker.exists());
    // The lock file stays; the next run starting shows the lock was released.
    assert!(selected.join("gears.lock").is_file());
    std::fs::remove_file(selected.join("tools.toml")).map_err(|e| e.to_string())?;
    let output = run(&request, &Cancellation::new(), &mut |_, _| {}).map_err(|e| e.to_string())?;
    assert!(output.success(), "{output:?}");
    assert!(output.stdout.contains("Isolated response."));
    let body: Value =
        serde_json::from_slice(&server.requests()[0].body).map_err(|e| e.to_string())?;
    assert_eq!(body["model"], "isolated-model");
    let store = Store::with_root(&workspace, selected.join("sessions"))?;
    assert!(!store.list()?.is_empty());
    assert!(selected.join("gears.lock").is_file());
    // Bad directory selections fail before any provider request or state creation.
    for directory in ["", "relative"] {
        request.env[0].1 = directory.into();
        let output =
            run(&request, &Cancellation::new(), &mut |_, _| {}).map_err(|e| e.to_string())?;
        assert!(!output.success());
        assert!(output.stderr.contains("GEARS_DIRECTORY"), "{output:?}");
    }
    assert_eq!(server.requests().len(), 1);
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())?;
    println!("gears selected state directory ALL PASS");
    Ok(())
}
