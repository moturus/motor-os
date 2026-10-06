//! The real companion CLI reviews a compacted fork through a loopback model.

use std::path::{Path, PathBuf};
use std::time::Duration;

use gears::{
    mock::{MockServer, Script, sse_response},
    process::{self, Cancellation, Request},
    provider::Message,
    session::{Compaction, RequestPrefix, Store},
    state::StateRoot,
};
use gears_batteries::{
    paths::ToolContext,
    review_config::Model,
    review_marks::{self, Disposition, Reason},
};

struct Restore {
    root: StateRoot,
    files: Vec<(PathBuf, Option<Vec<u8>>)>,
}
impl Drop for Restore {
    fn drop(&mut self) {
        for (relative, bytes) in &self.files {
            if let Some(bytes) = bytes {
                self.root
                    .replace_file(relative, bytes)
                    .expect("restore fixture state");
            } else if let Some(path) = self
                .root
                .existing_file(relative)
                .expect("locate fixture state")
            {
                std::fs::remove_file(path).expect("remove fixture state");
            }
        }
    }
}

pub fn run(batteries: &Path, gears: &Path, fixture: &Path) -> Result<(), String> {
    let base = fixture.join("review-cli");
    let workspace = base.join("workspace");
    let binaries = base.join("bin");
    std::fs::create_dir_all(&workspace).map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&binaries).map_err(|error| error.to_string())?;
    let batteries_copy = binaries.join("gears-batteries");
    std::fs::copy(batteries, &batteries_copy).map_err(|error| error.to_string())?;
    std::fs::copy(gears, binaries.join("gears")).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    let state_path = base.join(".gears");
    #[cfg(not(unix))]
    let state_path = gears_batteries::default_root()?;
    let store = Store::with_root(&workspace, state_path.join("sessions"))?;
    let mut parent = store.create(false, None)?;
    parent.set_provider("default")?;
    parent.set_model("executor")?;
    let prefix = RequestPrefix {
        system: vec!["Saved stable parent instructions".into()],
        tools: Vec::new(),
    };
    parent.record_request_prefix(&prefix)?;
    parent.append_message(&Message::user("Hello"))?;
    let entry = parent.append_message(&Message::assistant("Ordinary answer. ".repeat(2000)))?;
    let context = ToolContext::new(workspace, state_path, parent.id().into(), parent.path())?;
    let mut restore = Restore {
        root: context.state.clone(),
        files: Vec::new(),
    };
    for relative in ["batteries.toml", "batteries/last-review.json"] {
        let relative = PathBuf::from(relative);
        let bytes = context
            .state
            .existing_file(&relative)?
            .map(std::fs::read)
            .transpose()
            .map_err(|error| error.to_string())?;
        restore.files.push((relative, bytes));
    }
    context.state.replace_file(Path::new("batteries.toml"), b"version=1\n[reviews]\nenabled=true\n[reviews.executor]\nprovider='default'\nmodel='executor'\n[reviews.reviewer]\nprovider='default'\nmodel='reviewer'\n")?;
    let model = Model {
        provider: "default".into(),
        model: "executor".into(),
    };
    let id = review_marks::create(&context, &entry, Reason::Command, "", &model)?;
    parent.append_compaction(&Compaction {
        summary: "Later parent summary".into(),
        retained_tail: Vec::new(),
        tokens_before: 8000,
    })?;
    parent.append_message(&Message::user("Later task"))?;
    let before = std::fs::read(parent.path().unwrap()).unwrap();
    let reply = |text| sse_response(&[text, "[DONE]"]);
    let server = MockServer::start(vec![
        reply(r#"{"choices":[{"delta":{"content":"Original greeting and answer."},"finish_reason":"stop"}]}"#),
        reply(r#"{"choices":[{"delta":{"content":"Nothing to save"},"finish_reason":"stop"}]}"#),
        reply(r#"{"choices":[{"delta":{"content":"Original greeting and answer."},"finish_reason":"stop"}]}"#),
        Script::new().write("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: {\"choices\":[{\"delta\":{\"content\":\"Partial review\"},\"finish_reason\":null}]}\n\n")
            .pause(Duration::from_millis(500)).close(),
        reply(r#"{"choices":[{"delta":{"content":"Original greeting and answer."},"finish_reason":"stop"}]}"#),
        reply(r#"{"choices":[{"delta":{"content":"Nothing to save"},"finish_reason":"stop"}]}"#),
    ]).map_err(|error| error.to_string())?;
    let key = base.join("local.key");
    std::fs::write(&key, "fixture").map_err(|error| error.to_string())?;
    let config = base.join("gears.toml");
    std::fs::write(&config, format!("version=1\n[net]\negress_allowlist=['127.0.0.1']\nplain_http_allowlist=['127.0.0.1']\n[provider]\nbase_url={}\nkey_file={}\n[context]\nwindow_tokens=4096\noutput_reserve_tokens=512\nrecent_tail_tokens=128\n[after_turn]\ncommand=['gears-batteries','review']\ntimeout_seconds=10\n[[hooks]]\nname='batteries'\ncommand={}\n",
        serde_json::json!(server.base_url()), serde_json::json!(key), serde_json::json!([batteries_copy, "hook"]))).map_err(|error| error.to_string())?;
    let pending =
        |target| gears_batteries::pending::list(&context, target).map(|items| items.len());
    let before_global = pending(gears_batteries::memory_format::Target::Global)?;
    let before_workspace = pending(gears_batteries::memory_format::Target::Workspace)?;
    let mut request = Request {
        program: batteries_copy.to_str().unwrap().into(),
        args: vec!["review".into()],
        cwd: context.workspace.clone(),
        stdin: None,
        timeout: Duration::from_secs(10),
        max_output_bytes: 65536,
        env: vec![
            ("HOME".into(), base.to_str().unwrap().into()),
            (
                "GEARS_WORKSPACE".into(),
                context.workspace.to_str().unwrap().into(),
            ),
            ("GEARS_SESSION_ID".into(), parent.id().into()),
            (
                "GEARS_SESSION_PATH".into(),
                parent.path().unwrap().to_str().unwrap().into(),
            ),
            ("GEARS_CONFIG_PATH".into(), config.to_str().unwrap().into()),
        ],
        remove_env: vec![gears::provider::KEY_ENV.into()],
    };
    let invoke = |request: &Request| {
        process::run(request, &Cancellation::new(), &mut |_, _| {})
            .map_err(|error| error.to_string())
    };
    let mut new = store.create(false, None)?;
    new.append_message(&Message::assistant("Separate session"))?;
    let saved_env = request.env.clone();
    for (name, value) in &mut request.env {
        match name.as_str() {
            "GEARS_SESSION_ID" => *value = new.id().into(),
            "GEARS_SESSION_PATH" => *value = new.path().unwrap().to_str().unwrap().into(),
            _ => {}
        }
    }
    assert!(invoke(&request)?.success());
    assert!(server.requests().is_empty());
    assert_eq!(review_marks::due(&context)?.len(), 1);
    request.env = saved_env;
    drop(new);
    let output = invoke(&request)?;
    assert!(output.success(), "{output:?}");
    assert_eq!(
        review_marks::load(&context, &id)?.unwrap().disposition,
        Disposition::Completed
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 2, "one summary and one actual review");
    let body: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(body["model"], "reviewer");
    assert_eq!(body["messages"][0]["content"], prefix.system[0]);
    assert!(body["messages"].as_array().unwrap().iter().any(|message| {
        message["content"]
            .as_str()
            .is_some_and(|text| text.contains("\"Nothing to save\" is the default outcome"))
    }));
    assert!(!body.to_string().contains("Later task"));
    assert!(invoke(&request)?.success());
    assert_eq!(
        server.requests().len(),
        2,
        "completed marks never call the model again"
    );
    assert_eq!(std::fs::read(parent.path().unwrap()).unwrap(), before);
    let result: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            context
                .state
                .existing_file(Path::new("batteries/last-review.json"))?
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(result["answer"], "Nothing to save");
    assert_eq!(result["usage"]["completions"], 2, "include summary cost");
    let interrupted =
        review_marks::create(&context, &entry, Reason::Command, "Second review", &model)?;
    let previous_result = std::fs::read(
        context
            .state
            .existing_file(Path::new("batteries/last-review.json"))?
            .unwrap(),
    )
    .unwrap();
    let cancellation = Cancellation::new();
    let output = std::thread::scope(|scope| {
        scope.spawn(|| {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while server.requests().len() < 4 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "review never reached its model request"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            cancellation.cancel();
        });
        process::run(&request, &cancellation, &mut |_, _| {})
    })
    .map_err(|error| error.to_string())?;
    assert!(output.cancelled, "{output:?}");
    assert_eq!(
        review_marks::load(&context, &interrupted)?
            .unwrap()
            .disposition,
        Disposition::Due
    );
    assert_eq!(
        std::fs::read(
            context
                .state
                .existing_file(Path::new("batteries/last-review.json"))?
                .unwrap()
        )
        .unwrap(),
        previous_result
    );
    assert_eq!(std::fs::read(parent.path().unwrap()).unwrap(), before);
    assert!(invoke(&request)?.success());
    assert_eq!(
        review_marks::load(&context, &interrupted)?
            .unwrap()
            .disposition,
        Disposition::Completed
    );
    assert_eq!(server.requests().len(), 6);
    assert!(invoke(&request)?.success());
    assert_eq!(server.requests().len(), 6);
    assert_eq!(std::fs::read(parent.path().unwrap()).unwrap(), before);
    assert_eq!(
        pending(gears_batteries::memory_format::Target::Global)?,
        before_global
    );
    assert_eq!(
        pending(gears_batteries::memory_format::Target::Workspace)?,
        before_workspace
    );
    assert!(gears_batteries::skill_pending::list(&context)?.is_empty());
    let group = parent.path().unwrap().parent().unwrap().to_path_buf();
    drop(parent);
    std::fs::remove_dir_all(group).map_err(|error| error.to_string())?;
    std::fs::remove_dir_all(
        context
            .state
            .path()
            .join("batteries/sessions")
            .join(&context.session),
    )
    .map_err(|error| error.to_string())?;
    drop(restore);
    println!("gears batteries real review CLI ALL PASS");
    Ok(())
}
