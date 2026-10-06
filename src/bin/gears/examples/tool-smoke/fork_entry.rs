//! The actual CLI selects an old entry while its parent remains writable.

use std::path::Path;
use std::time::Duration;

use gears::mock::MockServer;
use gears::process::{Cancellation, Request, run};
use gears::provider::Message;
use gears::session::{Compaction, Store};

pub fn smoke(gears: &Path) -> Result<(), String> {
    let root = std::env::temp_dir().join(format!("gears-fork-entry-{}", std::process::id()));
    std::fs::create_dir(&root).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    let state = root.join(".gears/sessions");
    #[cfg(not(unix))]
    let state = std::path::PathBuf::from("/user/cfg/gears/sessions");
    let store = Store::with_root(&root, state)?;
    let mut parent = store.create(false, None)?;
    parent.append_message(&Message::user("Saved original task"))?;
    let entry = parent.append_message(&Message::assistant("Saved original answer"))?;
    parent.append_compaction(&Compaction {
        summary: "Later compacted summary".into(),
        retained_tail: Vec::new(),
        tokens_before: 100,
    })?;
    parent.append_message(&Message::user("Later task"))?;
    let path = parent.path().unwrap().to_path_buf();
    let before = std::fs::read(&path).map_err(|error| error.to_string())?;
    let server = MockServer::start(Vec::new()).map_err(|error| error.to_string())?;
    let config = root.join("gears.toml");
    let key = root.join("key");
    std::fs::write(&key, "fixture").map_err(|error| error.to_string())?;
    std::fs::write(&config, format!(
        "version=1\n[provider]\nbase_url={:?}\napi_key_file={:?}\nmodel='fixture'\n[net]\negress_allowlist=['127.0.0.1']\nplain_http_allowlist=['127.0.0.1']\n",
        server.url("/v1"), key,
    )).map_err(|error| error.to_string())?;
    let output = run(
        &Request {
            program: gears.display().to_string(),
            args: vec![
                "--config".into(),
                config.display().to_string(),
                "--workspace".into(),
                root.display().to_string(),
                "--fork".into(),
                path.display().to_string(),
                "--fork-entry".into(),
                entry,
                "--ephemeral".into(),
                "--ui".into(),
                "line".into(),
            ],
            cwd: root.clone(),
            stdin: Some(b"/session\n/quit\n".to_vec()),
            timeout: Duration::from_secs(10),
            max_output_bytes: 65536,
            env: vec![("HOME".into(), root.display().to_string())],
            remove_env: vec![gears::provider::KEY_ENV.into()],
        },
        &Cancellation::new(),
        &mut |_, _| {},
    )
    .map_err(|error| error.to_string())?;
    assert!(output.success(), "{output:?}");
    assert!(output.stdout.contains("Saved original task"), "{output:?}");
    assert!(
        output.stdout.contains("Saved original answer"),
        "{output:?}"
    );
    assert!(!output.stdout.contains("Later"), "{output:?}");
    assert!(server.requests().is_empty());
    assert_eq!(
        std::fs::read(&path).map_err(|error| error.to_string())?,
        before
    );
    parent.append_message(&Message::assistant("Parent continued"))?;
    drop(parent);
    #[cfg(not(unix))]
    std::fs::remove_dir_all(path.parent().unwrap()).map_err(|error| error.to_string())?;
    std::fs::remove_dir_all(root).map_err(|error| error.to_string())?;
    println!("gears CLI saved-entry fork ALL PASS");
    Ok(())
}
