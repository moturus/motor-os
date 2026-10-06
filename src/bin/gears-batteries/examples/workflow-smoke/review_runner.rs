//! Only a successful child with a complete final record consumes its own mark.

use std::path::Path;

use gears::{
    config::Config,
    process::{Cancellation, Output},
    provider::Message,
    session::Store,
};
use gears_batteries::{
    paths::ToolContext,
    review_config::Model,
    review_marks::{self, Disposition, Reason},
    review_runner,
};
use serde_json::json;

pub fn run(workspace: &Path, root: &Path) -> Result<(), String> {
    let store = Store::with_root(workspace, root.into())?;
    let mut parent = store.create(false, None)?;
    parent.set_provider("default")?;
    parent.set_model("executor")?;
    let entry = parent.append_message(&Message::assistant("Nothing notable"))?;
    let context = ToolContext::new(
        workspace.into(),
        root.into(),
        parent.id().into(),
        parent.path(),
    )?;
    context.state.replace_file(Path::new("batteries.toml"), b"version=1\n[reviews]\nenabled=true\n[reviews.executor]\nprovider='default'\nmodel='executor'\n[reviews.reviewer]\nprovider='default'\nmodel='reviewer'\n")?;
    assert!(gears_batteries::review_status::latest(&context.state)?.is_none());
    let model = Model {
        provider: "default".into(),
        model: "executor".into(),
    };
    let id = review_marks::create(&context, &entry, Reason::Command, "", &model)?;
    let config = Config::parse(
        "version=1\n[after_turn]\ncommand=['gears-batteries','review']\ntimeout_seconds=10\nmax_output_bytes=8192\n[[hooks]]\nname='batteries'\ncommand=['gears-batteries','hook']\n",
    )?;
    let final_record = final_record();
    let child = context.state.file(Path::new("review-child"))?;
    std::fs::copy(
        std::env::current_exe().map_err(|error| error.to_string())?,
        &child,
    )
    .map_err(|error| error.to_string())?;
    let before = std::fs::read(parent.path().unwrap()).unwrap();
    let run = |program: &Path, token: &Cancellation| {
        review_runner::run(&context, parent.path().unwrap(), &config, program, token)
    };
    let cancelled = Cancellation::new();
    cancelled.cancel();
    assert!(run(&child, &cancelled).unwrap_err().contains("interrupted"));
    assert_eq!(review_marks::due(&context)?.len(), 1);
    assert_eq!(run(&child, &Cancellation::new())?, 1);
    assert_eq!(
        review_marks::load(&context, &id)?.unwrap().disposition,
        Disposition::Completed
    );
    assert_eq!(
        run(Path::new("/missing-review-child"), &Cancellation::new())?,
        0
    );
    assert_eq!(std::fs::read(parent.path().unwrap()).unwrap(), before);
    let result_path = context
        .state
        .existing_file(Path::new("batteries/last-review.json"))?
        .unwrap();
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&result_path).unwrap()).unwrap();
    assert_eq!(record["mark"], id);
    assert_eq!(record["answer"], "Nothing to save");
    assert_eq!(record["usage"]["total_tokens"], 15);
    assert!(record["usage"]["cost_usd"].is_null());
    let status = gears_batteries::memory_history::status(&context);
    assert_eq!(status["reviews"], "experimental");
    assert_eq!(status["last_review"], record);
    let original = std::fs::read(&result_path).unwrap();
    for invalid in [
        b"{".to_vec(),
        vec![b' '; 16 * 1024 + 1],
        serde_json::to_vec(&json!({"version": 2})).unwrap(),
    ] {
        context
            .state
            .replace_file(Path::new("batteries/last-review.json"), &invalid)?;
        let status = gears_batteries::memory_history::status(&context);
        assert!(status["last_review"]["unavailable"].is_string());
        assert_eq!(status["pending_global"]["count"], 0);
        assert_eq!(std::fs::read(&result_path).unwrap(), invalid);
    }
    context
        .state
        .replace_file(Path::new("batteries/last-review.json"), &original)?;
    let other = ToolContext::new(workspace.into(), root.into(), "other".into(), None)?;
    assert_eq!(
        review_runner::run(
            &other,
            parent.path().unwrap(),
            &config,
            Path::new("/missing-review-child"),
            &Cancellation::new()
        )?,
        0
    );
    let id = review_marks::create(&context, &entry, Reason::Command, "different focus", &model)?;
    let baseline = std::fs::read(&result_path).unwrap();
    let success = Output {
        stdout: format!("{final_record}\n"),
        stderr: String::new(),
        code: Some(0),
        status: "exited".into(),
        timed_out: false,
        cancelled: false,
        stdout_dropped: 0,
        stderr_dropped: 0,
    };
    for invalid in [
        Output {
            code: Some(1),
            ..success.clone()
        },
        Output {
            cancelled: true,
            ..success.clone()
        },
        Output {
            timed_out: true,
            ..success.clone()
        },
        Output {
            stdout: final_record.clone(),
            ..success.clone()
        },
        Output {
            stdout: "{\"type\":\"final\",\"success\":true}\n".into(),
            ..success.clone()
        },
        Output {
            stdout: format!(
                "{}\n",
                final_record.replace("\"success\":true", "\"success\":false")
            ),
            ..success.clone()
        },
    ] {
        assert!(review_runner::complete(&context, &id, &invalid).is_err());
        assert_eq!(review_marks::due(&context)?.len(), 1);
        assert_eq!(std::fs::read(&result_path).unwrap(), baseline);
    }
    let mut noisy = success.clone();
    noisy.stderr = "Legacy prefix notice".into();
    noisy.stdout = format!(
        "{}\n{}",
        json!({"type": "notice", "text": "Current correction"}),
        noisy.stdout
    );
    review_runner::complete(&context, &id, &noisy)?;
    let displayed = gears_batteries::review_status::latest(&context.state)?.unwrap();
    assert!(
        displayed["diagnostics"]
            .as_str()
            .unwrap()
            .contains("Legacy prefix notice")
    );
    assert!(
        displayed["diagnostics"]
            .as_str()
            .unwrap()
            .contains("Current correction")
    );
    assert!(review_runner::complete(&context, &id, &success).is_err());
    assert!(review_marks::due(&context)?.is_empty());
    let bounded = review_marks::create(
        &context,
        &entry,
        Reason::Command,
        "Bounded diagnostics",
        &model,
    )?;
    let noisy = Output {
        stderr: "字".repeat(3000),
        ..success
    };
    review_runner::complete(&context, &bounded, &noisy)?;
    let displayed = gears_batteries::review_status::latest(&context.state)?.unwrap();
    let diagnostics = displayed["diagnostics"].as_str().unwrap();
    assert!(diagnostics.chars().count() <= 2080);
    assert!(diagnostics.ends_with("[Review diagnostics truncated]"));
    println!("gears batteries review runner ALL PASS");
    Ok(())
}

fn final_record() -> String {
    json!({"type":"final", "success":true, "error":null, "answer":"Nothing to save", "usage": {
        "completions":1, "prompt_tokens":12, "completion_tokens":3, "total_tokens":15,
        "cost_usd":null, "cost_is_partial":false
    }})
    .to_string()
}

pub fn child() {
    println!("{}", final_record());
}
