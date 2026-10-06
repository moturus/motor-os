//! Real Gears uses scoped write/check authority and keeps partial model costs.

use gears::{
    mock::{MockServer, sse_response},
    process::Cancellation,
};
use gears_batteries::{
    eval_actor::{self, Selection},
    eval_prepare, eval_task,
};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};

pub fn run_fixture(
    root: &Path,
    batteries: &Path,
    gears: &Path,
    compiler: &str,
) -> Result<(), String> {
    let source = super::eval_states::prepare(root)?;
    let binaries = root.join("bin");
    std::fs::create_dir(&binaries).unwrap();
    let batteries_copy = binaries.join("gears-batteries");
    let gears_copy = binaries.join("gears");
    std::fs::copy(batteries, &batteries_copy).unwrap();
    std::fs::copy(gears, &gears_copy).unwrap();
    let batteries = batteries_copy.as_path();
    let gears = gears_copy.as_path();

    for (name, definition, parameters) in [
        (
            "read_file",
            include_str!("../../tools/read_file/tool.toml"),
            include_str!("../../tools/read_file/parameters.json"),
        ),
        (
            "write_file",
            include_str!("../../tools/write_file/tool.toml"),
            include_str!("../../tools/write_file/parameters.json"),
        ),
        (
            "check",
            include_str!("../../tools/check/tool.toml"),
            include_str!("../../tools/check/parameters.json"),
        ),
    ] {
        let directory = source
            .state
            .directory(Path::new(&format!("tools/{name}")))?;
        std::fs::write(directory.join("tool.toml"), definition).unwrap();
        std::fs::write(directory.join("parameters.json"), parameters).unwrap();
    }
    let payloads = [
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"write","type":"function","function":{"name":"write_file","arguments":"{\"path\":\"answer*\",\"content\":\"accepted bytes\"}"}}]},"finish_reason":"tool_calls"}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"check","type":"function","function":{"name":"check","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}"#,
        r#"{"choices":[{"index":0,"delta":{"content":"Done."},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2,"cost":0.25}}"#,
    ];
    let server = MockServer::start(
        (0..2)
            .flat_map(|_| payloads.iter().map(|payload| sse_response(&[payload])))
            .collect(),
    )
    .map_err(|e| e.to_string())?;
    let key = root.join("key");
    std::fs::write(&key, "fixture").unwrap();
    let config = root.join("config.toml");
    std::fs::write(&config,format!("version=1\n[provider]\nbase_url={:?}\nkey_file={key:?}\n[net]\negress_allowlist=['127.0.0.1']\nplain_http_allowlist=['127.0.0.1']\n[[hooks]]\nname='batteries'\ncommand=['gears-batteries','hook']\n[[tools]]\ndirectory='tools/read_file'\nenabled=true\n[[tools]]\ndirectory='tools/write_file'\nenabled=true\n[[tools]]\ndirectory='tools/check'\nenabled=true\n",server.url("/v1"))).unwrap();
    let task_path = root.join("task.toml");
    std::fs::write(&task_path,format!("version=1\nworkspace={:?}\nprompt='Produce a checked result.'\ncheck={:?}\nacceptance=[['judge']]\nregressions=[['regression']]\n",source.workspace,vec![compiler,"--version"])).unwrap();
    let prepared = eval_prepare::prepare(
        &source,
        eval_task::load(&task_path)?,
        &config,
        &root.join("evaluation"),
        batteries,
    )?;
    let selection = Selection {
        gears,
        provider: "default",
        model: "fixture",
        timeout: Duration::from_secs(60),
    };
    for (ordinal, learning) in [(0, false), (1, true)] {
        let trial = prepared.trial(ordinal, learning)?;
        let actor = eval_actor::run(&prepared, &trial, &selection, &Cancellation::new())?;
        assert_eq!(actor["completed"], true, "{actor}");
        assert_eq!(actor["tool_calls"], 2);
        assert_eq!(actor["tool_failures"], 0);
        assert_eq!(actor["usage"]["cost_usd"], json!(0.25));
        assert_eq!(actor["usage"]["cost_is_partial"], true);
        assert_eq!(
            std::fs::read(trial.workspace.join("answer*")).unwrap(),
            b"accepted bytes"
        );
        assert!(
            prepared
                .root
                .path()
                .join(format!("trial-{ordinal:03}/actor.jsonl"))
                .is_file()
        );
        assert!(!trial.state.join("sessions").exists());
    }
    assert!(!source.workspace.join("answer*").exists());
    let requests = server.requests();
    assert_eq!(requests.len(), 6);
    for (index, learning) in [(0, false), (3, true)] {
        let body: Value = serde_json::from_slice(&requests[index].body).unwrap();
        let messages = body["messages"].to_string();
        assert_eq!(messages.contains("Content for learned."), learning);
        assert!(messages.contains("Content for user."));
    }
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())
}
