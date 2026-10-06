//! Pinned tools and resolved keys survive source edits without contacting providers.

use gears::{config::Config, tools::Registry};
use gears_batteries::{eval_config, eval_task::Task, paths::ToolContext};
use std::path::Path;

pub fn run_fixture(root: &Path, batteries: &Path) -> Result<(), String> {
    std::fs::create_dir_all(root.join("workspace")).unwrap();
    let context = ToolContext::new(
        root.join("workspace"),
        root.join("state"),
        "eval".into(),
        None,
    )?;
    let path = root.join("source.toml");
    let source = "version=1\n[provider]\nkey_file='key-file'\n[after_turn]\ncommand=['gears-batteries','review']\n[[hooks]]\nname='batteries'\ncommand=['gears-batteries','hook']\n[[tools]]\ndirectory='tools/read_file'\nenabled=true\n";
    let tool = context.state.directory(Path::new("tools/read_file"))?;
    std::fs::write(
        tool.join("tool.toml"),
        include_str!("../../tools/read_file/tool.toml"),
    )
    .unwrap();
    std::fs::write(
        tool.join("parameters.json"),
        include_str!("../../tools/read_file/parameters.json"),
    )
    .unwrap();
    std::fs::write(&path, source).unwrap();
    let task = Task {
        version: 1,
        workspace: context.workspace.clone(),
        prompt: "fix".into(),
        exclude: vec![],
        check: vec!["compiler".into()],
        acceptance: vec![vec!["judge".into()]],
        regressions: vec![vec!["regression".into()]],
    };
    let pinned = eval_config::prepare(&context, &task, &path, &root.join("pinned"), batteries)?;
    let before = std::fs::read(&pinned.path).unwrap();
    let config = Config::load_user(Some(&pinned.path))?;
    assert_eq!(config.key_file, Some(root.join("key-file")));
    assert!(config.after_turn.is_none());
    assert_eq!(config.hooks[0].command[0], batteries.to_str().unwrap());
    let registry = Registry::load(&config.tools, context.state.path())?;
    assert_eq!(registry.tools().len(), 1);
    assert_eq!(registry.tools()[0].name, "read_file");
    std::fs::write(tool.join("tool.toml"), "damaged source definition").unwrap();
    std::fs::write(&path, "version=2").unwrap();
    assert_eq!(std::fs::read(&pinned.path).unwrap(), before);
    assert_eq!(
        Registry::load(&config.tools, context.state.path())?.tools()[0].name,
        "read_file"
    );
    assert_eq!(pinned.identity["tools"].as_array().unwrap().len(), 1);
    assert!(
        eval_config::prepare(&context, &task, &path, &root.join("invalid"), batteries).is_err()
    );
    assert!(!root.join("invalid").exists());
    #[cfg(unix)]
    {
        std::fs::create_dir_all(root.join("outside/nested")).unwrap();
        std::fs::write(
            root.join("outside/source.toml"),
            "version=1\n[[hooks]]\nname='batteries'\ncommand=['gears-batteries','hook']",
        )
        .unwrap();
        std::os::unix::fs::symlink(root.join("outside/nested"), root.join("linked")).unwrap();
        assert!(
            eval_config::prepare(
                &context,
                &task,
                &root.join("linked/../source.toml"),
                &root.join("symbolic"),
                batteries
            )
            .is_err()
        );
        assert!(!root.join("symbolic").exists());
    }
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())
}
