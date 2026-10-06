//! Manual CLI runs real paired loopback trials with explicit budgets and pinned binaries.

use gears::process::{self, Cancellation, Request};
use serde_json::Value;
use std::{path::Path, time::Duration};

pub fn run_fixture(
    root: &Path,
    batteries: &Path,
    gears: &Path,
    compiler: &str,
) -> Result<(), String> {
    let (source, _prepared, server, gears) =
        super::eval_actor::prepare_fixture(root, batteries, gears, compiler, 8)?;
    std::fs::copy(root.join("task.toml"), root.join("second-task.toml")).unwrap();
    let args = vec![
        "eval".into(),
        "--task".into(),
        root.join("task.toml").display().to_string(),
        "--task".into(),
        root.join("second-task.toml").display().to_string(),
        "--config".into(),
        root.join("config.toml").display().to_string(),
        "--root".into(),
        "state".into(),
        "--gears".into(),
        gears.display().to_string(),
        "--provider".into(),
        "default".into(),
        "--model".into(),
        "fixture".into(),
        "--trials".into(),
        "2".into(),
        "--seconds".into(),
        "60".into(),
        "--command-seconds".into(),
        "60".into(),
        "--criterion".into(),
        "Private criterion: more accepted tasks without regressions.".into(),
        "--output".into(),
        "cli-evaluation".into(),
    ];
    assert!(!root.join("cli-evaluation").exists());
    let output = process::run(
        &Request {
            program: root.join("bin/gears-batteries").display().to_string(),
            args,
            cwd: root.into(),
            stdin: None,
            timeout: Duration::from_secs(120),
            max_output_bytes: 2 * 1024 * 1024,
            env: vec![],
            remove_env: vec![gears::provider::KEY_ENV.into()],
        },
        &Cancellation::new(),
        &mut |_, _| {},
    )
    .map_err(|e| e.to_string())?;
    assert!(output.success(), "{output:?}");
    let report: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(report["status"], "complete");
    assert_eq!(report["task_reports"].as_array().unwrap().len(), 2);
    assert_eq!(report["trials"].as_array().unwrap().len(), 8);
    assert_eq!(report["arms"][0]["accepted"], 3);
    assert_eq!(report["arms"][1]["accepted"], 4);
    assert_eq!(
        report["inputs"]["executables"]["gears"]["hash"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert!(root.join("cli-evaluation/report.json").is_file());
    let row = &report["trials"][0];
    let directory = Path::new(row["artifacts_base"].as_str().unwrap());
    assert!(
        directory
            .join(row["actor"]["events_artifact"].as_str().unwrap())
            .is_file()
    );
    let per_task: Value = serde_json::from_slice(
        &std::fs::read(root.join("cli-evaluation/tasks/task/report.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        report["learning_acquisition"]["approved_proposals"],
        per_task["learning_acquisition"]["approved_proposals"]
    );
    assert_eq!(
        report["learning_acquisition"]["configured_review_pair"]["reviewer"]["model"],
        "reviewer"
    );
    assert!(root.join("cli-evaluation/bin/gears-batteries").is_file());
    assert!(!source.workspace.join("answer*").exists());
    assert!(
        std::fs::read_to_string(source.state.path().join("batteries.toml"))
            .unwrap()
            .contains("enabled=true")
    );
    assert_eq!(server.requests().len(), 24);
    for request in server.requests() {
        assert!(
            !String::from_utf8(request.body)
                .unwrap()
                .contains("Private criterion")
        );
    }
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())
}
