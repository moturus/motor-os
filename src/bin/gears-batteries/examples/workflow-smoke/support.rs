//! Isolated workspace and real shipped tool manifests for both systems.

use std::path::{Path, PathBuf};
use std::time::Duration;

use gears::config::{Config, HookConfig, ToolDirectory};

pub struct Fixture {
    pub root: PathBuf,
    pub workspace: PathBuf,
    pub state: PathBuf,
    pub config: Config,
    pub hook: String,
    pub label: String,
}

impl Fixture {
    pub fn new(binary: &Path, compiler: &str) -> Result<Self, String> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos();
        let label = format!("workflow-{}-{stamp}", std::process::id());
        let root = std::env::temp_dir().join(format!("gears-batteries-{label}"));
        let workspace = root.join("workspace");
        let home = root.join("home");
        #[cfg(unix)]
        let state = home.join(".gears");
        #[cfg(not(unix))]
        let state = gears_batteries::default_root()?;
        std::fs::create_dir_all(workspace.join("src")).map_err(|error| error.to_string())?;
        std::fs::write(
            workspace.join("Cargo.toml"),
            "[package]\nname = 'fixture'\nversion = '0.0.0'\nedition = '2024'\n",
        )
        .map_err(|error| error.to_string())?;
        std::fs::write(
            workspace.join("src/lib.rs"),
            "const _: () = assert!(1 + 1 == 3);\n",
        )
        .map_err(|error| error.to_string())?;
        std::fs::write(
            workspace.join("AGENTS.md"),
            format!("Fixture instructions: {label}. Keep the assertion.\n"),
        )
        .map_err(|error| error.to_string())?;
        std::fs::create_dir(workspace.join(".gears")).map_err(|error| error.to_string())?;
        let argv = [
            compiler,
            "--edition=2024",
            "--crate-type=lib",
            "--emit=metadata",
            "src/lib.rs",
            "-o",
            "checked.rmeta",
        ];
        std::fs::write(
            workspace.join(".gears/batteries.toml"),
            format!("check = {}\n", serde_json::to_string(&argv).unwrap()),
        )
        .map_err(|error| error.to_string())?;
        let binary = binary
            .to_str()
            .ok_or("batteries binary path is not UTF-8")?;
        let command = |arguments: &[&str]| {
            let mut command = Vec::new();
            if cfg!(unix) {
                command.push("/usr/bin/env".to_string());
                command.push(format!("HOME={}", home.display()));
            }
            command.push(binary.to_string());
            command.extend(arguments.iter().map(|argument| argument.to_string()));
            command
        };
        let hook = format!("fixture-{label}");
        let mut config = Config {
            hooks: vec![HookConfig {
                name: hook.clone(),
                command: command(&["hook"]),
                events: Some(
                    [
                        "initialize",
                        "permission",
                        "tool_execute",
                        "tool_result",
                        "turn_start",
                        "entry",
                        "before_stop",
                        "turn_end",
                        "answer",
                        "context",
                        "command",
                    ]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                ),
                timeout: Duration::from_secs(30),
                max_output_bytes: 1024 * 1024,
            }],
            ..Config::default()
        };
        for (name, manifest, parameters) in [
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
                "patch",
                include_str!("../../tools/patch/tool.toml"),
                include_str!("../../tools/patch/parameters.json"),
            ),
            (
                "search_files",
                include_str!("../../tools/search_files/tool.toml"),
                include_str!("../../tools/search_files/parameters.json"),
            ),
            (
                "check",
                include_str!("../../tools/check/tool.toml"),
                include_str!("../../tools/check/parameters.json"),
            ),
            (
                "session_search",
                include_str!("../../tools/session_search/tool.toml"),
                include_str!("../../tools/session_search/parameters.json"),
            ),
        ] {
            let directory = root.join("tools").join(name);
            std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
            let replacement = format!(
                "common = {}",
                serde_json::to_string(&command(&["tool", name])).unwrap()
            );
            let manifest = manifest
                .lines()
                .map(|line| {
                    if line.starts_with("common = ") {
                        replacement.as_str()
                    } else {
                        line
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write(directory.join("tool.toml"), manifest)
                .map_err(|error| error.to_string())?;
            std::fs::write(directory.join("parameters.json"), parameters)
                .map_err(|error| error.to_string())?;
            config.tools.push(ToolDirectory {
                directory,
                enabled: true,
            });
        }
        Ok(Self {
            root,
            workspace,
            state,
            config,
            hook,
            label,
        })
    }

    pub fn cleanup(
        &self,
        group: &Path,
        sessions: &[String],
        snapshots: &[String],
    ) -> Result<(), String> {
        #[cfg(unix)]
        let _ = (group, sessions, snapshots);
        #[cfg(not(unix))]
        {
            if group.parent() != Some(self.state.as_path()) {
                return Err("fixture group is outside its state root".into());
            }
            std::fs::remove_dir_all(group).map_err(|error| error.to_string())?;
            for id in sessions {
                if !id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                {
                    return Err("invalid fixture session id".into());
                }
                let path = self.state.join("batteries/sessions").join(id);
                if path.exists() {
                    std::fs::remove_dir_all(path).map_err(|error| error.to_string())?;
                }
            }
            for hash in snapshots.iter().collect::<std::collections::HashSet<_>>() {
                if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err("invalid fixture snapshot hash".into());
                }
                std::fs::remove_file(
                    self.state
                        .join("batteries/snapshots")
                        .join(format!("{hash}.json")),
                )
                .map_err(|error| error.to_string())?;
            }
        }
        std::fs::remove_dir_all(&self.root).map_err(|error| error.to_string())
    }
}
