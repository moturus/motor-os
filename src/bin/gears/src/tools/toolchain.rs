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

use super::run::{Job, execute, execute_with, invoke_recorded, timeout_arg, timeout_property};
use super::{Execution, Tool, ToolResult, Workspace, bool_arg, opt_string, schema, string_list};
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

    /// Backend-specific limits shown to the model with the generic tool.
    fn limits(&self) -> &'static str;

    /// Context for a command the platform could not start.
    fn spawn_context(&self, _command: &[String]) -> Option<String> {
        None
    }
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

    fn limits(&self) -> &'static str {
        "Cargo accepts release, offline, target, target_dir, and extra Cargo arguments."
    }
}

/// The Motor OS toolchain: `lorry` (plan Step 1). Its command line is the
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

    /// Resolve Lorry through the launcher's `PATH`; the root layout is not a
    /// Gears interface.
    pub fn motor() -> LorryToolchain {
        LorryToolchain::new("lorry")
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

    fn limits(&self) -> &'static str {
        "Lorry is a strict Cargo subset: it accepts release, target, and supported extra Lorry arguments; builds are already offline and target_dir is unsupported."
    }

    fn spawn_context(&self, command: &[String]) -> Option<String> {
        Some(format!(
            "Motor OS attempted argument vector {command:?}; make lorry available through PATH (an unset, empty, or unsuitable PATH has no Gears fallback)"
        ))
    }
}

/// The host's cargo toolchain, for callers that know they are on one.
pub fn host() -> Arc<dyn Toolchain> {
    Arc::new(CargoToolchain)
}

/// The `build` and `test` tools for the platform gears is running on: cargo
/// on the host, `lorry` on Motor OS.
pub fn for_platform(
    workspace: Arc<Workspace>,
    timeout: Duration,
    output_limit: usize,
) -> Vec<Box<dyn Tool>> {
    #[cfg(unix)]
    {
        tools(host(), workspace, timeout, output_limit)
    }
    #[cfg(not(unix))]
    {
        tools(
            Arc::new(LorryToolchain::motor()),
            workspace,
            timeout,
            output_limit,
        )
    }
}

pub struct ToolchainTool {
    action: Action,
    toolchain: Arc<dyn Toolchain>,
    workspace: Arc<Workspace>,
    timeout: Duration,
    output_limit: usize,
}

/// The `build` and `test` tools, sharing one toolchain and one workspace.
pub fn tools(
    toolchain: Arc<dyn Toolchain>,
    workspace: Arc<Workspace>,
    timeout: Duration,
    output_limit: usize,
) -> Vec<Box<dyn Tool>> {
    [Action::Build, Action::Test]
        .into_iter()
        .map(|action| {
            Box::new(ToolchainTool {
                action,
                toolchain: toolchain.clone(),
                workspace: workspace.clone(),
                timeout,
                output_limit,
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
                 verbatim, and the first line says how it ended. {}",
                self.toolchain.name(),
                self.toolchain.limits()
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
        execute(&self.job(args)?)
    }

    fn execute(&self, args: &Value, execution: &Execution) -> Result<String, String> {
        execute_with(&self.job(args)?, execution)
    }

    fn invoke(&self, args: &Value, execution: &Execution) -> ToolResult {
        match self.job(args) {
            Ok(job) => {
                let started_unix_millis = unix_millis();
                let git_revision = crate::tools::vcs::revision_for_platform(self.workspace.root());
                let (mut result, end, raw_output) =
                    invoke_recorded(&job, execution, self.name(), self.output_limit);
                let raw_output = match raw_output {
                    Ok(output) => output,
                    Err(error) => {
                        result.outcome = crate::tools::ToolOutcome::ProtocolFailed;
                        result.content.push_str(&format!(
                            "\n{}: verification evidence was not recorded: {error}",
                            self.name()
                        ));
                        return result;
                    }
                };
                let ended_git_revision =
                    crate::tools::vcs::revision_for_platform(self.workspace.root());
                let cwd = self.workspace.display(&job.cwd);
                let cwd = if cwd.is_empty() { ".".to_string() } else { cwd };
                let diagnostics = crate::agent::verification::normalize_diagnostics(
                    &raw_output,
                    self.toolchain.name(),
                    &self.workspace,
                    &cwd,
                );
                result.verification = Some(crate::agent::verification::Captured {
                    candidate: crate::agent::verification::Candidate {
                        backend: match self.toolchain.name() {
                            "cargo" => crate::agent::verification::Backend::Cargo,
                            "lorry" => crate::agent::verification::Backend::Lorry,
                            _ => crate::agent::verification::Backend::Process,
                        },
                        argv: std::iter::once(job.program.clone())
                            .chain(job.args.iter().cloned())
                            .collect(),
                        cwd,
                        source: format!("{} tool call", self.name()),
                    },
                    started_unix_millis,
                    ended_unix_millis: unix_millis(),
                    end,
                    git_revision,
                    ended_git_revision,
                    diagnostics,
                    raw_output,
                    output_artifact: None,
                });
                result
            }
            Err(message) => ToolResult::error(format!("{}: {message}", self.name())),
        }
    }

    fn cap(&self) -> usize {
        64 * 1024
    }
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(1)
        .max(1)
}

impl ToolchainTool {
    fn job(&self, args: &Value) -> Result<Job, String> {
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
        let spawn_context = self.toolchain.spawn_context(&argv);
        let program = argv.remove(0);
        Ok(Job {
            program,
            args: argv,
            cwd,
            timeout: timeout_arg(args, self.timeout)?,
            spawn_context,
        })
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
            ["lorry", "--color", "never", "build"]
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
                "lorry",
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

    #[test]
    fn tool_descriptions_name_each_backends_limits() {
        let dir = std::env::temp_dir().join(format!("gears-tc-spec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let workspace = Arc::new(Workspace::new(&dir).unwrap());

        let cargo = tools(
            host(),
            workspace.clone(),
            Duration::from_secs(30),
            1_000_000,
        );
        let cargo_description = &cargo[0].spec().function.description;
        assert!(
            cargo_description.contains("with cargo"),
            "{cargo_description}"
        );
        assert!(
            cargo_description.contains("target_dir"),
            "{cargo_description}"
        );

        let lorry = tools(
            Arc::new(LorryToolchain::motor()),
            workspace,
            Duration::from_secs(30),
            1_000_000,
        );
        let lorry_description = &lorry[0].spec().function.description;
        assert!(
            lorry_description.contains("with lorry"),
            "{lorry_description}"
        );
        assert!(
            lorry_description.contains("strict Cargo subset"),
            "{lorry_description}"
        );
        assert!(
            lorry_description.contains("target_dir is unsupported"),
            "{lorry_description}"
        );
        std::fs::remove_dir_all(dir).unwrap();
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

        fn limits(&self) -> &'static str {
            "Only the arguments used by this test."
        }
    }

    fn fixture(name: &str) -> (PathBuf, Vec<Box<dyn Tool>>) {
        let dir = std::env::temp_dir().join(format!("gears-tc-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("crate")).unwrap();
        let workspace = Arc::new(Workspace::new(&dir).unwrap());
        let tools = tools(
            Arc::new(Echo),
            workspace,
            Duration::from_secs(30),
            1_000_000,
        );
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

    #[cfg(unix)]
    #[test]
    fn a_registry_retains_exact_native_check_facts_and_raw_output() {
        let (dir, tools) = fixture("evidence");
        let artifacts = Arc::new(
            crate::agent::artifact::LazyStore::new(
                dir.clone(),
                "1-2".to_string(),
                1_000_000,
                2_000_000,
            )
            .unwrap(),
        );
        let mut registry = crate::tools::Registry::new().with_artifacts(artifacts.clone());
        for tool in tools {
            registry.register(tool);
        }
        let (tx, _rx) = crate::agent::event_channel();
        let bus = crate::agent::Bus::new(crate::agent::ROOT, tx);
        let result = registry.dispatch_call(
            "test",
            r#"{"path":"crate","args":["--lib"]}"#,
            "check-1",
            &bus.execution(),
        );

        assert_eq!(result.outcome, crate::tools::ToolOutcome::Completed);
        let captured = result.verification.unwrap();
        assert_eq!(
            captured.candidate.backend,
            crate::agent::verification::Backend::Process
        );
        assert_eq!(captured.candidate.argv, ["echo", "test", "--lib"]);
        assert_eq!(captured.candidate.cwd, "crate");
        assert_eq!(captured.candidate.source, "test tool call");
        assert!(captured.started_unix_millis <= captured.ended_unix_millis);
        assert!(matches!(
            captured.end,
            crate::agent::verification::ProcessEnd::Exited { success: true, .. }
        ));
        assert!(captured.raw_output.is_empty());
        assert_eq!(captured.output_artifact, Some(1));
        let metadata = artifacts.get().unwrap().metadata(1).unwrap();
        assert_eq!(
            metadata.artifact_type,
            crate::agent::artifact::VERIFICATION_OUTPUT
        );
        assert_eq!(artifacts.get().unwrap().read(1).unwrap(), b"test --lib\n");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_large_failing_check_keeps_complete_output_beside_a_bounded_view() {
        struct FailingOutput;

        impl Toolchain for FailingOutput {
            fn name(&self) -> &'static str {
                "test-process"
            }

            fn command(&self, _action: Action, _options: &Options) -> Result<Vec<String>, String> {
                Ok(vec!["sh".into(), "-c".into(), "seq 1 10000; exit 7".into()])
            }

            fn limits(&self) -> &'static str {
                "Test fixture."
            }
        }

        let (dir, _) = fixture("large-evidence");
        let workspace = Arc::new(Workspace::new(&dir).unwrap());
        let artifacts = Arc::new(
            crate::agent::artifact::LazyStore::new(
                dir.clone(),
                "1-3".to_string(),
                1_000_000,
                2_000_000,
            )
            .unwrap(),
        );
        let mut registry = crate::tools::Registry::new().with_artifacts(artifacts.clone());
        for tool in tools(
            Arc::new(FailingOutput),
            workspace,
            Duration::from_secs(30),
            1_000_000,
        ) {
            registry.register(tool);
        }
        let (tx, _rx) = crate::agent::event_channel();
        let execution = crate::agent::Bus::new(crate::agent::ROOT, tx).execution();
        let result = registry.dispatch_call("test", "{}", "large-1", &execution);

        assert_eq!(result.outcome, crate::tools::ToolOutcome::Completed);
        assert!(
            result.content.contains("bytes elided"),
            "{}",
            result.content.len()
        );
        let captured = result.verification.unwrap();
        assert!(matches!(
            captured.end,
            crate::agent::verification::ProcessEnd::Exited { success: false, .. }
        ));
        let raw = artifacts
            .get()
            .unwrap()
            .read(captured.output_artifact.unwrap())
            .unwrap();
        assert!(raw.len() > 32 * 1024, "{}", raw.len());
        assert!(raw.starts_with(b"1\n2\n"));
        assert!(raw.ends_with(b"9999\n10000\n"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Build and test are generic names over the same cancellable process
    /// path as `run`; neither may wait out its normal tool timeout after ^C.
    #[cfg(unix)]
    #[test]
    fn build_and_test_take_cancellation_from_their_execution() {
        struct Slow;

        impl Toolchain for Slow {
            fn name(&self) -> &'static str {
                "slow-toolchain"
            }

            fn command(&self, action: Action, _options: &Options) -> Result<Vec<String>, String> {
                Ok(vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    format!("printf '{} ready\\n'; sleep 30", action.verb()),
                ])
            }

            fn limits(&self) -> &'static str {
                "Only the cancellation path used by this test."
            }
        }

        let dir = std::env::temp_dir().join(format!("gears-tc-cancel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let workspace = Arc::new(Workspace::new(&dir).unwrap());
        for tool in tools(
            Arc::new(Slow),
            workspace,
            Duration::from_secs(30),
            1_000_000,
        ) {
            let name = tool.name();
            let (tx, rx) = crate::agent::event_channel();
            let bus = crate::agent::Bus::new(crate::agent::ROOT, tx);
            let execution = bus.execution();
            let running = std::thread::spawn(move || tool.invoke(&json!({}), &execution));
            assert!(matches!(
                rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                crate::agent::Event::ToolOutput { text, .. } if text == format!("{name} ready\n")
            ));

            let cancelled_at = std::time::Instant::now();
            bus.canceller().raise();
            let result = running.join().unwrap();
            assert!(cancelled_at.elapsed() < Duration::from_secs(1));
            assert_eq!(result.outcome, super::super::ToolOutcome::Cancelled);
            assert!(result.content.contains(&format!("{name} ready")));
        }
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

    #[test]
    fn a_missing_lorry_names_path_and_the_attempted_command() {
        let dir =
            std::env::temp_dir().join(format!("gears-tc-missing-lorry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let workspace = Arc::new(Workspace::new(&dir).unwrap());
        let tools = tools(
            Arc::new(LorryToolchain::new("gears-no-such-lorry")),
            workspace,
            Duration::from_secs(30),
            1_000_000,
        );
        let error = tools[0].call(&json!({})).unwrap_err();
        assert!(error.contains("gears-no-such-lorry"), "{error}");
        assert!(error.contains("PATH"), "{error}");
        assert!(error.contains("[\"gears-no-such-lorry\""), "{error}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
