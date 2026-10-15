//! Trials inherit a frozen template and cannot inherit answers from another trial.

use gears::batteries::{eval_prepare, eval_task, paths::ToolContext};
use std::path::Path;

pub fn run_fixture(root: &Path, batteries: &Path) -> Result<(), String> {
    let source = super::eval_states::prepare(root)?;
    std::fs::create_dir(source.workspace.join(".git")).unwrap();
    std::fs::write(source.workspace.join(".git/leak"), "old worktree pointer").unwrap();
    std::fs::write(source.workspace.join("a file*"), "frozen original").unwrap();
    std::fs::write(
        source.workspace.join("hidden-judge"),
        "held-back assertions",
    )
    .unwrap();
    let task_path = source.workspace.join("held-back.toml");
    let exclusions: Vec<_> = (0..64).map(|i| format!("skip-{i}")).collect();
    std::fs::write(&task_path,format!("version=1\nworkspace={:?}\nprompt='fix'\nexclude={exclusions:?}\ncheck=['compiler']\nacceptance=[['./hidden-judge']]\nregressions=[['regression']]",source.workspace)).unwrap();
    let config = root.join("config.toml");
    std::fs::write(
        &config,
        "version=1\n[[hooks]]\nname='batteries'\ncommand=['gears-batteries','hook']",
    )
    .unwrap();
    let prepared = eval_prepare::prepare(
        &source,
        eval_task::load(&task_path)?,
        &config,
        &root.join("evaluation"),
        batteries,
    )?;
    std::fs::write(source.workspace.join("a file*"), "changed after freeze").unwrap();
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(prepared.root.path().join("task.json")).unwrap())
            .unwrap();
    assert_eq!(saved["task"]["prompt"], prepared.task.task.prompt);
    assert_eq!(saved["source_hash"], prepared.task.hash);
    assert_eq!(
        saved["task"]["workspace"],
        serde_json::json!(source.workspace)
    );
    assert!(!prepared.root.path().join("template/task.json").exists());
    let baseline = prepared.trial(0, false)?;
    let learning = prepared.trial(1, true)?;
    for trial in [&baseline, &learning] {
        assert_eq!(
            std::fs::read(trial.workspace.join("a file*")).unwrap(),
            b"frozen original"
        );
        assert!(!trial.workspace.join("held-back.toml").exists());
        assert!(!trial.workspace.join("hidden-judge").exists());
        assert!(!trial.workspace.join(".git").exists());
        let context = ToolContext::new(
            trial.workspace.clone(),
            trial.state.clone(),
            "eval".into(),
            None,
        )?;
        assert_eq!(
            gears::batteries::check_config::load(
                &context,
                gears::batteries::check_config::system()
            )?
            .unwrap(),
            ["compiler"]
        );
        assert!(!context.state.path().join("sessions").exists());
    }
    std::fs::write(baseline.workspace.join("a file*"), "first trial answer").unwrap();
    assert_eq!(
        std::fs::read(learning.workspace.join("a file*")).unwrap(),
        b"frozen original"
    );
    let later = prepared.trial(2, false)?;
    assert_eq!(
        std::fs::read(later.workspace.join("a file*")).unwrap(),
        b"frozen original"
    );
    assert!(prepared.trial(0, true).is_err());
    assert!(prepared.trial(128, false).is_err());
    assert!(
        eval_prepare::prepare(
            &source,
            eval_task::load(&task_path)?,
            &config,
            &source.workspace.join("nested"),
            batteries
        )
        .is_err()
    );
    assert!(!source.workspace.join("nested").exists());
    assert_ne!(baseline.versions["memory"], learning.versions["memory"]);
    assert_eq!(
        baseline.versions["settings_hash"],
        learning.versions["settings_hash"]
    );
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())
}
