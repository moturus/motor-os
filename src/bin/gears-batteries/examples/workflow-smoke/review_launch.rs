//! Launch preparation makes no provider request and never changes its parent.

use std::path::Path;

use gears::{
    config::Config,
    provider::Message,
    session::{Compaction, HookState, Store},
};
use gears_batteries::{
    paths::ToolContext,
    review_config::Model,
    review_launch,
    review_marks::{self, Disposition, Reason},
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
    let executor = Model {
        provider: "default".into(),
        model: "executor".into(),
    };
    let id = review_marks::create(
        &context,
        &entry,
        Reason::Command,
        "literal $(focus)",
        &executor,
    )?;
    let mut config = Config::parse(
        "version=1\n[after_turn]\ncommand=['gears-batteries','review']\ntimeout_seconds=42\nmax_output_bytes=4096\n[[hooks]]\nname='custom-batteries'\ncommand=['gears-batteries','hook']\n",
    )?;
    let prepare = |config: &Config| {
        review_launch::prepare(
            &context,
            parent.path().unwrap(),
            config,
            &id,
            "Nothing to save",
        )
    };
    assert!(prepare(&config)?.is_none());
    context.state.replace_file(Path::new("batteries.toml"), b"version=1\n[reviews]\nenabled=true\n[reviews.executor]\nprovider='default'\nmodel='executor'\n[reviews.reviewer]\nprovider='default'\nmodel='reviewer'\n")?;
    parent.append_compaction(&Compaction {
        summary: "Later history".into(),
        retained_tail: Vec::new(),
        tokens_before: 100,
    })?;
    // A historical mark remains eligible even if the live model later changes.
    parent.set_model("different")?;
    let before = std::fs::read(parent.path().unwrap()).unwrap();
    config.config_path = Some(workspace.join("config with spaces.toml"));
    let request = review_launch::prepare(
        &context,
        parent.path().unwrap(),
        &config,
        &id,
        "Nothing to save",
    )?
    .unwrap()
    .request;
    let value = |flag: &str| {
        request.args[request.args.iter().position(|arg| arg == flag).unwrap() + 1].as_str()
    };
    assert_eq!(value("--fork-entry"), entry);
    assert_eq!(value("--model"), "reviewer");
    assert_eq!(
        value("--config"),
        workspace.join("config with spaces.toml").to_str().unwrap()
    );
    assert!(request.args.contains(&"--preserve-prefix".into()));
    assert!(request.args.contains(&"--ephemeral".into()));
    let (hook, overlay) = value("--hook-state").split_once('=').unwrap();
    assert_eq!(hook, "custom-batteries");
    let overlay: serde_json::Value = serde_json::from_str(overlay).unwrap();
    assert_eq!(overlay["run_kind"], "review");
    assert_eq!(overlay["review_run"]["session"], parent.id());
    assert_eq!(overlay["review_run"]["mark"], id);
    assert_eq!(request.timeout.as_secs(), 42);
    assert_eq!(request.max_output_bytes, 4096);
    assert_eq!(request.remove_env, [gears::provider::KEY_ENV]);
    assert_eq!(request.cwd, workspace);
    assert!(request.stdin.is_none());
    assert_eq!(std::fs::read(parent.path().unwrap()).unwrap(), before);
    let before = std::fs::read(parent.path().unwrap()).unwrap();
    config.hooks[0].events = Some(vec!["initialize".into()]);
    assert!(
        review_launch::prepare(&context, parent.path().unwrap(), &config, &id, "")
            .err()
            .unwrap()
            .contains("permission")
    );
    config.hooks[0].events = None;
    config.hooks.push(config.hooks[0].clone());
    assert!(
        review_launch::prepare(&context, parent.path().unwrap(), &config, &id, "")
            .err()
            .unwrap()
            .contains("exactly one")
    );
    config.hooks.pop();
    assert_eq!(std::fs::read(parent.path().unwrap()).unwrap(), before);
    for state in [
        json!({"reviews_paused": true}),
        json!({"run_kind": "review"}),
    ] {
        parent.append_hook_state(&HookState {
            hook: "custom-batteries".into(),
            state,
            context: None,
        })?;
        assert!(
            review_launch::prepare(&context, parent.path().unwrap(), &config, &id, "")?.is_none()
        );
    }
    let other = ToolContext::new(workspace.into(), root.into(), "other".into(), None)?;
    let other_id = review_marks::create(&other, &entry, Reason::Command, "", &executor)?;
    assert!(
        review_launch::prepare(&other, parent.path().unwrap(), &config, &other_id, "")
            .err()
            .unwrap()
            .contains("another session")
    );
    review_marks::finish(&context, &id, Disposition::Completed)?;
    assert!(review_launch::prepare(&context, parent.path().unwrap(), &config, &id, "")?.is_none());
    println!("gears batteries review launch ALL PASS");
    Ok(())
}
