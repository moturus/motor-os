//! Real repeated actors alternate arms; failed criteria and cancellation remain visible.

use gears::batteries::{
    eval_actor::Selection,
    eval_prepare, eval_report,
    eval_suite::{self, Settings},
    eval_task,
};
use gears::process::Cancellation;
use serde_json::{Value, json};
use std::{path::Path, time::Duration};

pub fn run_fixture(
    root: &Path,
    batteries: &Path,
    gears: &Path,
    compiler: &str,
) -> Result<(), String> {
    let (source, prepared, server, gears) =
        super::eval_actor::prepare_fixture(root, batteries, gears, compiler, 4)?;
    let selection = Selection {
        gears: &gears,
        provider: "default",
        model: "fixture",
        timeout: Duration::from_secs(60),
    };
    let settings = Settings {
        repetitions: 2,
        command_timeout: Duration::from_secs(60),
        criterion: "No new regressions; compare accepted outcomes on these held-out tasks.".into(),
    };
    let report = eval_suite::run(
        &prepared,
        &selection,
        &settings,
        eval_report::acquisition(&source)?,
        &Cancellation::new(),
    )?;
    assert_eq!(report["status"], "complete", "{report}");
    let preflight = &report["preflight"]["regressions"][0];
    assert_eq!(preflight["stdout_saved_bytes"], 8192);
    assert!(preflight["stdout"].as_str().unwrap().len() <= 4096);
    let artifact = prepared
        .root
        .path()
        .join(preflight["stdout_artifact"].as_str().unwrap());
    assert_eq!(std::fs::read(artifact).unwrap().len(), 8192);
    assert_eq!(report["trials"].as_array().unwrap().len(), 4);
    assert_eq!(report["arms"][0]["accepted"], 1);
    assert_eq!(report["arms"][1]["accepted"], 2);
    assert_eq!(report["trials"][3]["acceptance"][0]["passed"], false);
    assert!(report["total_cost_usd"].is_null());
    let recorded: Value =
        serde_json::from_slice(&std::fs::read(prepared.root.path().join("report.json")).unwrap())
            .unwrap();
    assert_eq!(recorded, report);
    let requests = server.requests();
    assert_eq!(requests.len(), 12);
    for (index, learning) in [(0, false), (3, true), (6, true), (9, false)] {
        let body: Value = serde_json::from_slice(&requests[index].body).unwrap();
        assert_eq!(
            body["messages"]
                .to_string()
                .contains("Content for learned."),
            learning
        );
    }
    assert!(!source.workspace.join("answer*").exists());
    let task_path = root.join("task.toml");
    let task = std::fs::read_to_string(&task_path).unwrap();
    let mut blocked = eval_task::load(&task_path)?.task;
    blocked.regressions = vec![vec!["./missing-regression".into()]];
    std::fs::write(&task_path, toml::to_string(&blocked).unwrap()).unwrap();
    let blocked = eval_prepare::prepare(
        &source,
        eval_task::load(&task_path)?,
        &root.join("config.toml"),
        &root.join("blocked"),
        &root.join("bin/gears-batteries"),
    )?;
    let report = eval_suite::run(
        &blocked,
        &selection,
        &settings,
        json!({}),
        &Cancellation::new(),
    )?;
    assert_eq!(report["status"], "failed");
    assert_eq!(report["trials"], json!([]));
    assert_eq!(report["preflight"]["regressions"][0]["passed"], false);
    assert_eq!(server.requests().len(), 12);
    std::fs::write(&task_path, task).unwrap();
    let cancelled = eval_prepare::prepare(
        &source,
        eval_task::load(&task_path)?,
        &root.join("config.toml"),
        &root.join("cancelled"),
        &root.join("bin/gears-batteries"),
    )?;
    let cancel = Cancellation::new();
    cancel.cancel();
    let report = eval_suite::run(&cancelled, &selection, &settings, json!({}), &cancel)?;
    assert_eq!(report["status"], "cancelled");
    assert_eq!(report["trials"], json!([]));
    assert_eq!(server.requests().len(), 12);
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())
}
