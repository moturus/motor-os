//! Self-hosting: gears keeping, installing and running new versions of itself.
//!
//! The loop this exists for is the plan's stated bar — edit, build, validate,
//! restart into the result — and what it needs beyond the tools that already
//! exist is somewhere for a freshly built binary to live, a way to install one,
//! and a way to start it. Three small tools, and they work only where the user
//! has said gears may work on itself. Where they do not, they are still *there*
//! — and refuse, saying why. That is the whole of the difference: a model told
//! to update itself and shown no way to cannot tell "not allowed" from "not a
//! thing gears does", so it improvises with the tools it does have, which on
//! the first real run meant building and running gears over and over until the
//! user's quota went.
//!
//! Two things here are the whole of the safety story. A candidate is *asked
//! what it is* before it is kept, so a binary that cannot say `gears <version>`
//! never becomes one. And a restart is performed by the interface after the
//! session is closed, never by the tool: the new gears takes a lock this one is
//! still holding, and the two must not overlap.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use super::run::{Job, capture};
use super::{Tool, Workspace, opt_string, schema, string_arg, usize_arg};
use crate::provider::ToolSpec;
use crate::state::StateDir;

/// Where candidates live, relative to the workspace root. Under `.gears`, so
/// the file tools cannot reach a binary that is about to be run.
pub const CANDIDATES_DIR: &str = ".gears/candidates";

/// The same location, relative to the shared gears state boundary.
const CANDIDATES_STATE_DIR: &str = "candidates";

/// What `promote_candidate` leaves behind: the binary it replaced. If a
/// promoted gears turns out not to work, this is what there is to go back to.
pub const PREVIOUS: &str = "previous";

/// How long a candidate has to say what it is.
const IDENTIFY_TIMEOUT: Duration = Duration::from_secs(30);

/// What the user has allowed gears to do to itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// Whether the tools below do anything. Off, they still answer — see
    /// [`OFF`].
    pub enabled: bool,
    /// Where `promote_candidate` installs. `None` is the running binary's own
    /// path, which is right until gears is *running* a candidate — then it is
    /// the one thing that has to be said out loud.
    pub install: Option<PathBuf>,
}

/// What a `restart` call decided, once the user allowed it. The tool leaves it
/// here and the interface acts on it after everything is closed.
#[derive(Clone, Default)]
pub struct Restart(Arc<Mutex<Option<Plan>>>);

/// The new gears, and what to tell it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub program: PathBuf,
    /// The session to carry on, which is what makes this a restart rather
    /// than a new beginning.
    pub session: String,
    /// A prompt for the new gears to answer, or `None` to leave it at its own
    /// prompt.
    pub prompt: Option<String>,
}

impl Restart {
    pub fn new() -> Restart {
        Restart::default()
    }

    pub fn pending(&self) -> bool {
        self.0.lock().unwrap().is_some()
    }

    /// Take the request, so that it is acted on once.
    pub fn take(&self) -> Option<Plan> {
        self.0.lock().unwrap().take()
    }

    fn request(&self, plan: Plan) {
        *self.0.lock().unwrap() = Some(plan);
    }
}

/// The candidates directory: built gears binaries, numbered in the order they
/// were made.
#[derive(Clone)]
pub struct Candidates {
    state: StateDir,
    dir: PathBuf,
}

/// A binary that was kept, and what it said it was.
#[derive(Debug)]
pub struct Staged {
    pub number: usize,
    pub path: PathBuf,
    pub version: String,
}

impl Candidates {
    pub fn new(root: &Path) -> Result<Candidates, String> {
        let root = root
            .canonicalize()
            .map_err(|error| format!("workspace {}: {error}", root.display()))?;
        Ok(Candidates {
            state: StateDir::new(&root)?,
            dir: root.join(CANDIDATES_DIR),
        })
    }

    fn relative(number: usize) -> PathBuf {
        Path::new(CANDIDATES_STATE_DIR).join(format!("gears-{number}"))
    }

    pub fn path(&self, number: usize) -> Result<PathBuf, String> {
        self.state.file(&Self::relative(number))
    }

    fn existing(&self, number: usize) -> Result<Option<PathBuf>, String> {
        self.state.existing_file(&Self::relative(number))
    }

    /// Every candidate there is, oldest first.
    pub fn list(&self) -> Result<Vec<usize>, String> {
        let Some(dir) = self
            .state
            .existing_directory(Path::new(CANDIDATES_STATE_DIR))?
        else {
            return Ok(Vec::new());
        };
        let entries =
            std::fs::read_dir(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
        let mut numbers = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| format!("{}: {error}", dir.display()))?;
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let Ok(number) = name.strip_prefix("gears-").unwrap_or("").parse::<usize>() else {
                continue;
            };
            if number == 0 || name != format!("gears-{number}") {
                continue;
            }
            if self.existing(number)?.is_some() {
                numbers.push(number);
            }
        }
        numbers.sort_unstable();
        Ok(numbers)
    }

    pub fn newest(&self) -> Result<Option<usize>, String> {
        Ok(self.list()?.last().copied())
    }

    /// Keep a copy of a freshly built gears, after asking it what it is.
    pub fn stage(&self, binary: &Path) -> Result<Staged, String> {
        if !binary.is_file() {
            return Err(format!("{}: not a file", binary.display()));
        }
        let version = identify(binary)?;
        let number = self
            .newest()?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or("candidate number space is exhausted")?;
        let path = self.path(number)?;
        copy_new(binary, &path)?;
        Ok(Staged {
            number,
            path,
            version,
        })
    }

    /// Put a candidate where gears itself lives. It is copied in beside the
    /// destination and renamed over it, because a file that is executing
    /// cannot be written to — and a rename is atomic besides, so there is no
    /// moment at which the installed gears is half a binary.
    pub fn install(&self, candidate: &Path, destination: &Path) -> Result<PathBuf, String> {
        let mut name = destination
            .file_name()
            .ok_or_else(|| format!("{}: no file to replace", destination.display()))?
            .to_os_string();
        name.push(".new");
        let staging = destination.with_file_name(name);

        copy_new(candidate, &staging)?;
        let result = (|| {
            let previous = self
                .state
                .file(Path::new(CANDIDATES_STATE_DIR).join(PREVIOUS).as_path())?;
            if destination.exists() {
                std::fs::copy(destination, &previous)
                    .map_err(|e| format!("{}: {e}", previous.display()))?;
            }
            std::fs::rename(&staging, destination)
                .map_err(|e| format!("{}: {e}", destination.display()))?;
            Ok(previous)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&staging);
        }
        result
    }
}

/// Copy a binary without ever following or replacing an entry already at the
/// destination. The open file receives the source permissions before it is
/// renamed into service.
fn copy_new(source: &Path, destination: &Path) -> Result<(), String> {
    let mut source_file =
        std::fs::File::open(source).map_err(|error| format!("{}: {error}", source.display()))?;
    let metadata = source_file
        .metadata()
        .map_err(|error| format!("{}: {error}", source.display()))?;
    if !metadata.is_file() {
        return Err(format!("{}: not a regular file", source.display()));
    }
    let mut destination_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| format!("{}: {error}", destination.display()))?;
    let copied = std::io::copy(&mut source_file, &mut destination_file)
        .and_then(|_| destination_file.flush())
        .and_then(|_| destination_file.set_permissions(metadata.permissions()));
    if let Err(error) = copied {
        drop(destination_file);
        let _ = std::fs::remove_file(destination);
        return Err(format!("{}: {error}", destination.display()));
    }
    Ok(())
}

/// Ask a binary what it is. A candidate that cannot answer `--version` the way
/// gears does is not a gears, and finding that out now is a great deal cheaper
/// than finding it out after the restart.
fn identify(binary: &Path) -> Result<String, String> {
    let job = Job {
        program: binary.display().to_string(),
        args: vec!["--version".to_string()],
        cwd: binary.parent().unwrap_or(Path::new(".")).to_path_buf(),
        timeout: IDENTIFY_TIMEOUT,
        spawn_context: None,
    };
    let outcome = capture(&job)?;
    let said = outcome.output.trim().to_string();
    match outcome.ok && said.starts_with("gears ") {
        true => Ok(said),
        false => Err(format!(
            "{} does not answer --version as gears does ({}: {said})",
            binary.display(),
            outcome.status
        )),
    }
}

/// Where a promotion or a plain restart goes: what the user named, or the
/// binary this process is running.
fn installed(policy: &Policy) -> Result<PathBuf, String> {
    match &policy.install {
        Some(path) => Ok(path.clone()),
        None => std::env::current_exe().map_err(|e| format!("cannot find my own binary: {e}")),
    }
}

struct Stage {
    workspace: Arc<Workspace>,
    candidates: Candidates,
}

struct Promote {
    candidates: Candidates,
    policy: Policy,
}

struct RestartTool {
    candidates: Candidates,
    policy: Policy,
    session: String,
    request: Restart,
}

/// What the three say where gears has not been told it may work on itself. It
/// is addressed to the model, because the model is who reads a tool result —
/// and it names the setting, because "ask the user to allow it" without saying
/// what to ask for is how a model ends up guessing.
pub const OFF: &str = "self-hosting is off in this gears' configuration, so it \
                       cannot build, install or start a new version of itself. \
                       Do not try to do it by other means: say so, and tell the \
                       user they can allow it with `enabled = true` under \
                       `[selfhost]` in the config.";

/// The three names, which exist whether or not there is anything behind them.
const NAMES: [&str; 3] = ["stage_candidate", "promote_candidate", "restart"];

/// One of the three where self-hosting is off: present, so that the question
/// has an answer, and refusing, so that it is the right one.
struct Disabled(&'static str);

impl Tool for Disabled {
    fn name(&self) -> &'static str {
        self.0
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            self.0,
            format!("Unavailable: {OFF}"),
            schema(json!({}), &[]),
        )
    }

    /// What the working tool would be, so that who is shown it does not change
    /// with the setting: a read-only sub-agent has no business restarting gears
    /// whether or not gears may restart.
    fn mutates(&self) -> bool {
        true
    }

    /// Nothing to put to the user, though: a refusal changes nothing, and
    /// asking permission for one is a question with a single answer.
    fn gated(&self, _args: &Value) -> bool {
        false
    }

    fn call(&self, _args: &Value) -> Result<String, String> {
        Err(OFF.to_string())
    }
}

/// The self-hosting tools, or three that say why there are none.
pub fn tools(
    root: &Path,
    session: &str,
    workspace: Arc<Workspace>,
    policy: &Policy,
    request: &Restart,
) -> Result<Vec<Box<dyn Tool>>, String> {
    if !policy.enabled {
        return Ok(NAMES
            .into_iter()
            .map(|name| Box::new(Disabled(name)) as Box<dyn Tool>)
            .collect());
    }
    let candidates = Candidates::new(root)?;
    Ok(vec![
        Box::new(Stage {
            workspace,
            candidates: candidates.clone(),
        }),
        Box::new(Promote {
            candidates: candidates.clone(),
            policy: policy.clone(),
        }),
        Box::new(RestartTool {
            candidates,
            policy: policy.clone(),
            session: session.to_string(),
            request: request.clone(),
        }),
    ])
}

/// Which candidate a call meant: the one it named, or the newest there is.
/// Zero is how an absent number arrives, and no candidate is numbered zero.
fn chosen(candidates: &Candidates, args: &Value) -> Result<(usize, PathBuf), String> {
    let number = match usize_arg(args, "candidate", 0)? {
        0 => candidates
            .newest()?
            .ok_or("there are no candidates; build one and stage it first")?,
        given => given,
    };
    match candidates.existing(number)? {
        Some(path) => Ok((number, path)),
        None => Err(format!(
            "there is no candidate {number}; kept: {:?}",
            candidates.list()?
        )),
    }
}

impl Tool for Stage {
    fn name(&self) -> &'static str {
        "stage_candidate"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "stage_candidate",
            "Keep a freshly built gears binary as a numbered candidate, out of \
             reach of later builds. The binary is asked for its --version \
             first, so one that does not run is refused here.",
            schema(
                json!({"path": {"type": "string", "description":
                    "The built binary, relative to the workspace root."}}),
                &["path"],
            ),
        )
    }

    fn mutates(&self) -> bool {
        true
    }

    fn call(&self, args: &Value) -> Result<String, String> {
        let path = self.workspace.resolve(&string_arg(args, "path")?)?;
        let staged = self.candidates.stage(&path)?;
        Ok(format!(
            "candidate {} is {} ({})",
            staged.number,
            staged.version,
            staged.path.display()
        ))
    }
}

impl Tool for Promote {
    fn name(&self) -> &'static str {
        "promote_candidate"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "promote_candidate",
            "Install a candidate where gears itself lives, so that later runs \
             use it. The binary it replaces is kept.",
            schema(
                json!({"candidate": {"type": "integer", "description":
                    "Which candidate (default: the newest)."}}),
                &[],
            ),
        )
    }

    fn mutates(&self) -> bool {
        true
    }

    fn call(&self, args: &Value) -> Result<String, String> {
        let (number, candidate) = chosen(&self.candidates, args)?;
        let destination = installed(&self.policy)?;
        // Running a candidate and promoting into it would mean nothing, and
        // the user is the only one who knows where gears really lives.
        if destination.starts_with(self.candidates.dir.as_path()) {
            return Err(format!(
                "this gears is itself a candidate ({}), so there is nowhere to \
                 install to; set selfhost.install in the config",
                destination.display()
            ));
        }
        let previous = self.candidates.install(&candidate, &destination)?;
        Ok(format!(
            "installed candidate {number} at {}; the binary it replaced is at {}",
            destination.display(),
            previous.display()
        ))
    }
}

impl Tool for RestartTool {
    fn name(&self) -> &'static str {
        "restart"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "restart",
            "Stop this gears and start another one on the same session, so that \
             work carries on in a new binary. Say what you are doing and end \
             your turn: the restart happens when the turn does.",
            schema(
                json!({
                    "candidate": {"type": "integer", "description":
                        "Restart into this candidate rather than into the installed gears."},
                    "prompt": {"type": "string", "description":
                        "What to ask the new gears to do first. Without one it waits for the user."},
                }),
                &[],
            ),
        )
    }

    fn mutates(&self) -> bool {
        true
    }

    fn call(&self, args: &Value) -> Result<String, String> {
        let program = match usize_arg(args, "candidate", 0)? {
            0 => installed(&self.policy)?,
            _ => chosen(&self.candidates, args)?.1,
        };
        if !program.is_file() {
            return Err(format!("{}: there is no such binary", program.display()));
        }
        self.request.request(Plan {
            program: program.clone(),
            session: self.session.clone(),
            prompt: opt_string(args, "prompt")?,
        });
        Ok(format!(
            "gears will restart into {} and carry on session {} when this turn ends",
            program.display(),
            self.session
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn workspace(name: &str) -> PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "gears-selfhost-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A candidate, put there by hand. Nothing below runs one: a test that
    /// writes an executable and then executes it races every other test that
    /// spawns anything — a fork between the write and the exec inherits the
    /// descriptor and the exec comes back `ETXTBSY`. What staging does with a
    /// *real* binary is `tests/selfhost.rs`, which runs one it did not write.
    fn candidate(dir: &Path, number: usize, contents: &str) -> PathBuf {
        let candidates = Candidates::new(dir).unwrap();
        let path = candidates.path(number).unwrap();
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn kit(dir: &Path, policy: Policy) -> (Vec<Box<dyn Tool>>, Restart) {
        let workspace = Arc::new(Workspace::new(dir).unwrap());
        let request = Restart::new();
        let tools = tools(dir, "17-3", workspace, &policy, &request).unwrap();
        (tools, request)
    }

    #[test]
    fn the_tools_are_the_same_three_whether_or_not_they_work() {
        let dir = workspace("names");
        let policy = Policy {
            enabled: true,
            install: None,
        };
        let (working, _) = kit(&dir, policy);
        let names: Vec<&str> = working.iter().map(|t| t.name()).collect();
        assert_eq!(names, NAMES);
        // All three change something, so all three are put to the user.
        assert!(working.iter().all(|t| t.mutates()));

        // Same names, and the same answer to who may be shown them: a
        // read-only sub-agent is not offered a restart either way.
        let (off, _) = kit(&dir, Policy::default());
        let names: Vec<&str> = off.iter().map(|t| t.name()).collect();
        assert_eq!(names, NAMES);
        assert!(off.iter().all(|t| t.mutates()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The point of the disabled three: a model that asks is told why not, and
    /// told what to say to the user, rather than left to work it out by trying
    /// things — which is what it does, expensively.
    #[test]
    fn a_gears_that_may_not_work_on_itself_says_so() {
        let dir = workspace("off");
        let (tools, request) = kit(&dir, Policy::default());

        for tool in &tools {
            let refusal = tool.call(&json!({})).unwrap_err();
            assert!(refusal.contains("[selfhost]"), "{refusal}");
            assert!(refusal.contains("enabled = true"), "{refusal}");
            // In the description too, so it is known before it is called.
            assert!(
                tool.spec().function.description.contains("[selfhost]"),
                "{}",
                tool.name()
            );
            // Nothing to approve, and nothing happened.
            assert!(!tool.gated(&json!({})));
        }
        assert!(!request.pending());
        assert!(!dir.join(CANDIDATES_DIR).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn candidates_are_numbered_in_the_order_they_were_made() {
        let dir = workspace("numbering");
        let candidates = Candidates::new(&dir).unwrap();
        assert_eq!(candidates.newest().unwrap(), None);
        assert!(candidates.list().unwrap().is_empty());

        candidate(&dir, 1, "first");
        candidate(&dir, 2, "second");
        // What is not a candidate is not counted as one, however it got there.
        std::fs::write(dir.join(CANDIDATES_DIR).join(PREVIOUS), "old").unwrap();
        std::fs::write(dir.join(CANDIDATES_DIR).join("gears-x"), "?").unwrap();

        assert_eq!(candidates.list().unwrap(), [1, 2]);
        assert_eq!(candidates.newest().unwrap(), Some(2));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn promoting_installs_the_candidate_and_keeps_what_it_replaced() {
        let dir = workspace("promote");
        let install = dir.join("bin/gears");
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::write(&install, "the old gears").unwrap();
        let candidate = candidate(&dir, 1, "the new gears");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o751)).unwrap();
        }

        let policy = Policy {
            enabled: true,
            install: Some(install.clone()),
        };
        let (tools, _) = kit(&dir, policy);

        let said = tools[1].call(&json!({})).unwrap();
        assert!(said.contains("installed candidate 1"), "{said}");
        assert_eq!(
            std::fs::read_to_string(&install).unwrap(),
            "the new gears",
            "the new binary is not installed"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&install).unwrap().permissions().mode() & 0o777,
                0o751
            );
        }
        // The one it replaced is still there to go back to.
        let previous = dir.join(CANDIDATES_DIR).join(PREVIOUS);
        assert_eq!(std::fs::read_to_string(&previous).unwrap(), "the old gears");
        // Nothing is left beside the destination once the rename is done.
        assert!(!dir.join("bin/gears.new").exists());
        assert!(tools[1].call(&json!({"candidate": 7})).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn promotion_refuses_a_preexisting_staging_symlink() {
        use std::os::unix::fs::symlink;

        let dir = workspace("promote-link");
        let outside = workspace("promote-link-outside");
        let install = dir.join("bin/gears");
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::write(&install, "the old gears").unwrap();
        candidate(&dir, 1, "the new gears");
        let target = outside.join("must-not-change");
        std::fs::write(&target, "safe").unwrap();
        symlink(&target, dir.join("bin/gears.new")).unwrap();

        let candidates = Candidates::new(&dir).unwrap();
        let error = candidates
            .install(&candidates.path(1).unwrap(), &install)
            .unwrap_err();
        assert!(error.contains("gears.new"), "{error}");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "safe");
        assert_eq!(std::fs::read_to_string(&install).unwrap(), "the old gears");
        assert!(dir.join("bin/gears.new").is_symlink());
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&outside).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn candidate_state_refuses_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = workspace("candidate-link");
        let outside = workspace("candidate-link-outside");
        std::fs::create_dir_all(dir.join(".gears")).unwrap();
        symlink(&outside, dir.join(CANDIDATES_DIR)).unwrap();

        let candidates = Candidates::new(&dir).unwrap();
        let error = candidates.list().unwrap_err();
        assert!(error.contains("symlink"), "{error}");
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&outside).unwrap();
    }

    /// A gears that is itself a candidate has nowhere to install to, and says
    /// so rather than writing over the candidate it is running.
    #[test]
    fn promoting_from_a_candidate_asks_where_gears_really_lives() {
        let dir = workspace("promote-self");
        candidate(&dir, 1, "the new gears");
        let policy = Policy {
            enabled: true,
            install: Some(dir.join(CANDIDATES_DIR).join("gears-1")),
        };
        let (tools, _) = kit(&dir, policy);

        let error = tools[1].call(&json!({})).unwrap_err();
        assert!(error.contains("selfhost.install"), "{error}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_restart_names_a_binary_a_session_and_what_to_ask_it() {
        let dir = workspace("restart");
        let install = dir.join("bin/gears");
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::write(&install, "the installed gears").unwrap();
        candidate(&dir, 1, "the new gears");

        let policy = Policy {
            enabled: true,
            install: Some(install.clone()),
        };
        let (tools, request) = kit(&dir, policy);

        // Nothing happens when the tool runs: the request is left for the
        // interface, which is the only place that knows the session is closed.
        assert!(!request.pending());
        let said = tools[2]
            .call(&json!({"candidate": 1, "prompt": "carry on"}))
            .unwrap();
        assert!(said.contains("session 17-3"), "{said}");
        assert!(request.pending());

        let plan = request.take().unwrap();
        assert_eq!(
            plan.program,
            Candidates::new(&dir).unwrap().path(1).unwrap()
        );
        assert_eq!(plan.session, "17-3");
        assert_eq!(plan.prompt.as_deref(), Some("carry on"));
        // And it is acted on once.
        assert!(!request.pending());

        // Without a candidate it is the installed gears, and without a prompt
        // the new one is left at its own prompt.
        tools[2].call(&json!({})).unwrap();
        let plan = request.take().unwrap();
        assert_eq!(plan.program, install);
        assert_eq!(plan.prompt, None);
        assert!(tools[2].call(&json!({"candidate": 9})).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
