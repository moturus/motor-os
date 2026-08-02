//! Building and testing: the same process machinery as `run.rs`, with the
//! argument vector built by a [`Toolchain`] rather than by the model.
//!
//! The seam exists because the host builds with `cargo` and Motor OS builds
//! with `lorry` (plan step 10), and the difference between them is a command
//! line. What the tools relay either way is the compiler's own diagnostics,
//! verbatim: that is the agent's feedback signal, and paraphrasing it would
//! lose exactly the part that says how to fix the code.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::run::{Job, execute, timeout_arg, timeout_property};
use super::{Tool, Workspace, bool_arg, opt_string, schema, string_list};
use crate::provider::ToolSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Build,
    Test,
}

impl Action {
    fn verb(self) -> &'static str {
        match self {
            Action::Build => "build",
            Action::Test => "test",
        }
    }
}

/// What a build was asked for, in terms every toolchain has.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Options {
    pub release: bool,
    pub target: Option<String>,
    /// Where build output goes. Step 9 depends on this: gears building itself
    /// must not write into the target directory the *outer* build holds a lock
    /// on.
    pub target_dir: Option<PathBuf>,
    pub offline: bool,
    /// Extra arguments for the build tool itself, appended verbatim.
    pub args: Vec<String>,
}

pub trait Toolchain: Send + Sync {
    /// What it is called, for messages and for the tool descriptions.
    fn name(&self) -> &'static str;

    /// The whole command line, `argv[0]` included — or why there is none: a
    /// toolchain refuses an option it cannot express (lorry has no
    /// `--target-dir`) rather than dropping it on the floor.
    fn command(&self, action: Action, options: &Options) -> Result<Vec<String>, String>;
}

pub struct CargoToolchain;

impl Toolchain for CargoToolchain {
    fn name(&self) -> &'static str {
        "cargo"
    }

    fn command(&self, action: Action, options: &Options) -> Result<Vec<String>, String> {
        let mut argv = vec!["cargo".to_string(), action.verb().to_string()];
        // Colour is for a terminal; what reaches the model should be text.
        argv.push("--color=never".to_string());
        if options.release {
            argv.push("--release".to_string());
        }
        if options.offline {
            argv.push("--offline".to_string());
        }
        if let Some(target) = &options.target {
            argv.push("--target".to_string());
            argv.push(target.clone());
        }
        if let Some(dir) = &options.target_dir {
            argv.push("--target-dir".to_string());
            argv.push(dir.display().to_string());
        }
        argv.extend(options.args.iter().cloned());
        Ok(argv)
    }
}

/// The Motor OS toolchain: `lorry` (plan step 10). Its command line is the
/// audited cargo subset — build and test, `--release`, `--target` — and what
/// it does not have is refused rather than dropped. lorry builds are offline
/// by construction (`lorry vendor` is the online step), so `offline` asks for
/// nothing; build output always lands under `target/lorry/`.
pub struct LorryToolchain {
    program: String,
}

impl LorryToolchain {
    pub fn new(program: impl Into<String>) -> LorryToolchain {
        LorryToolchain {
            program: program.into(),
        }
    }

    /// Where the image installs lorry. An absolute path on purpose: Motor OS
    /// spawns take the name as given, with no PATH search to lean on.
    pub fn motor() -> LorryToolchain {
        LorryToolchain::new("/bin/lorry")
    }
}

impl Toolchain for LorryToolchain {
    fn name(&self) -> &'static str {
        "lorry"
    }

    fn command(&self, action: Action, options: &Options) -> Result<Vec<String>, String> {
        if let Some(dir) = &options.target_dir {
            return Err(format!(
                "lorry has no --target-dir (asked for '{}'): build output \
                 always goes under target/lorry",
                dir.display()
            ));
        }
        let mut argv = vec![
            self.program.clone(),
            "--color".to_string(),
            "never".to_string(),
            action.verb().to_string(),
        ];
        if options.release {
            argv.push("--release".to_string());
        }
        if let Some(target) = &options.target {
            argv.push("--target".to_string());
            argv.push(target.clone());
        }
        argv.extend(options.args.iter().cloned());
        Ok(argv)
    }
}

/// The host's cargo toolchain, for callers that know they are on one.
pub fn host() -> Arc<dyn Toolchain> {
    Arc::new(CargoToolchain)
}

/// The `build` and `test` tools for the platform gears is running on: cargo
/// on the host, `lorry` on Motor OS.
pub fn for_platform(workspace: Arc<Workspace>, timeout: Duration) -> Vec<Box<dyn Tool>> {
    #[cfg(unix)]
    {
        tools(host(), workspace, timeout)
    }
    #[cfg(not(unix))]
    {
        tools(Arc::new(LorryToolchain::motor()), workspace, timeout)
    }
}

pub struct ToolchainTool {
    action: Action,
    toolchain: Arc<dyn Toolchain>,
    workspace: Arc<Workspace>,
    timeout: Duration,
}

/// The `build` and `test` tools, sharing one toolchain and one workspace.
pub fn tools(
    toolchain: Arc<dyn Toolchain>,
    workspace: Arc<Workspace>,
    timeout: Duration,
) -> Vec<Box<dyn Tool>> {
    [Action::Build, Action::Test]
        .into_iter()
        .map(|action| {
            Box::new(ToolchainTool {
                action,
                toolchain: toolchain.clone(),
                workspace: workspace.clone(),
                timeout,
            }) as Box<dyn Tool>
        })
        .collect()
}

impl Tool for ToolchainTool {
    fn name(&self) -> &'static str {
        self.action.verb()
    }

    fn spec(&self) -> ToolSpec {
        let what = match self.action {
            Action::Build => "Compile a crate",
            Action::Test => "Compile and run a crate's tests",
        };
        ToolSpec::new(
            self.name(),
            format!(
                "{what} with {}. The compiler's own diagnostics come back \
                 verbatim, and the first line says how it ended.",
                self.toolchain.name()
            ),
            schema(
                json!({
                    "path": {"type": "string", "description":
                        "The crate directory, relative to the workspace root (default: the root)."},
                    "release": {"type": "boolean"},
                    "target": {"type": "string", "description": "Target triple."},
                    "target_dir": {"type": "string", "description":
                        "Where build output goes, relative to the workspace root."},
                    "offline": {"type": "boolean", "description":
                        "Build without the network, from what is already vendored."},
                    "args": {"type": "array", "items": {"type": "string"}, "description":
                        format!("Extra arguments for {}, e.g. [\"--lib\"].", self.toolchain.name())},
                    "timeout_seconds": timeout_property(self.timeout),
                }),
                &[],
            ),
        )
    }

    fn mutates(&self) -> bool {
        true
    }

    fn call(&self, args: &Value) -> Result<String, String> {
        let cwd = match opt_string(args, "path")? {
            Some(given) => {
                let path = self.workspace.resolve(&given)?;
                if !path.is_dir() {
                    return Err(format!("'{given}' is not a directory"));
                }
                path
            }
            None => self.workspace.root().to_path_buf(),
        };
        let options = Options {
            release: bool_arg(args, "release", false)?,
            target: opt_string(args, "target")?,
            target_dir: match opt_string(args, "target_dir")? {
                Some(given) => Some(self.workspace.resolve(&given)?),
                None => None,
            },
            offline: bool_arg(args, "offline", false)?,
            args: string_list(args, "args")?,
        };
        let mut argv = self.toolchain.command(self.action, &options)?;
        let program = argv.remove(0);
        let job = Job {
            program,
            args: argv,
            cwd,
            timeout: timeout_arg(args, self.timeout)?,
        };
        execute(&job)
    }

    fn cap(&self) -> usize {
        64 * 1024
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargos_command_line_is_what_it_was_asked_for() {
        let cargo = CargoToolchain;
        assert_eq!(
            cargo.command(Action::Build, &Options::default()).unwrap(),
            ["cargo", "build", "--color=never"]
        );
        let options = Options {
            release: true,
            target: Some("x86_64-unknown-motor".to_string()),
            target_dir: Some(PathBuf::from("/work/target/self")),
            offline: true,
            args: vec!["--lib".to_string()],
        };
        assert_eq!(
            cargo.command(Action::Test, &options).unwrap(),
            [
                "cargo",
                "test",
                "--color=never",
                "--release",
                "--offline",
                "--target",
                "x86_64-unknown-motor",
                "--target-dir",
                "/work/target/self",
                "--lib",
            ]
        );
    }

    #[test]
    fn lorrys_command_line_is_the_audited_subset() {
        let lorry = LorryToolchain::motor();
        assert_eq!(
            lorry.command(Action::Build, &Options::default()).unwrap(),
            ["/bin/lorry", "--color", "never", "build"]
        );
        // `offline` asks for nothing lorry does not already do; the rest maps
        // one to one.
        let options = Options {
            release: true,
            target: Some("x86_64-unknown-motor".to_string()),
            offline: true,
            args: vec!["--no-run".to_string()],
            ..Options::default()
        };
        assert_eq!(
            lorry.command(Action::Test, &options).unwrap(),
            [
                "/bin/lorry",
                "--color",
                "never",
                "test",
                "--release",
                "--target",
                "x86_64-unknown-motor",
                "--no-run",
            ]
        );
        // What lorry cannot express is refused, not dropped: build output
        // lands under target/lorry wherever the caller wanted it.
        let options = Options {
            target_dir: Some(PathBuf::from("/work/target/self")),
            ..Options::default()
        };
        let err = lorry.command(Action::Build, &options).unwrap_err();
        assert!(err.contains("target-dir"), "{err}");
        assert!(err.contains("/work/target/self"), "{err}");
    }

    /// A toolchain that records what it was asked to run, so the tools can be
    /// checked without a compiler.
    struct Echo;

    impl Toolchain for Echo {
        fn name(&self) -> &'static str {
            "echo-toolchain"
        }

        fn command(&self, action: Action, options: &Options) -> Result<Vec<String>, String> {
            let mut argv = vec!["echo".to_string(), action.verb().to_string()];
            argv.extend(options.args.iter().cloned());
            Ok(argv)
        }
    }

    fn fixture(name: &str) -> (PathBuf, Vec<Box<dyn Tool>>) {
        let dir = std::env::temp_dir().join(format!("gears-tc-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("crate")).unwrap();
        let workspace = Arc::new(Workspace::new(&dir).unwrap());
        let tools = tools(Arc::new(Echo), workspace, Duration::from_secs(30));
        (dir, tools)
    }

    #[cfg(unix)]
    #[test]
    fn the_tools_run_what_the_toolchain_names() {
        let (dir, tools) = fixture("names");
        assert_eq!(tools[0].name(), "build");
        assert_eq!(tools[1].name(), "test");
        assert!(
            tools[0]
                .spec()
                .function
                .description
                .contains("echo-toolchain")
        );

        let out = tools[1]
            .call(&json!({"path": "crate", "args": ["--lib"]}))
            .unwrap();
        assert_eq!(out, "exit status 0\ntest --lib\n");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_directory_that_is_not_one_is_refused() {
        let (dir, tools) = fixture("path");
        std::fs::write(dir.join("f.txt"), "x").unwrap();
        for bad in ["f.txt", "/etc", "../elsewhere"] {
            assert!(tools[0].call(&json!({ "path": bad })).is_err(), "{bad}");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
