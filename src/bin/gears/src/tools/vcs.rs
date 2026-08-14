//! Version control, as the model sees it.
//!
//! gears does not commit on its own — that is plan decision D3, and the undo
//! log is the automatic safety net instead. What lives here is the deliberate
//! kind: five verbs the model can ask for, two of which change something and
//! are put to the user every time.
//!
//! There is a seam because Motor OS has no git (proposal, "Version control:
//! options"), and v1 there has no backend at all: [`Vcs::capabilities`] comes
//! back empty, the tools are never registered, and the undo log goes on
//! working. No cfg says so — the probe is the portable question, and a machine
//! without git answers it by not having one.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::run::{Job, capture};
use super::{Tool, Workspace, schema, string_arg, string_list, usize_arg};
use crate::provider::ToolSpec;

/// What a backend can be asked to do. A set rather than a flag because
/// answering questions and rewriting history are different powers — and
/// because an empty one is how "there is no version control here" is said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Status,
    Diff,
    Log,
    Commit,
    Restore,
}

impl Op {
    pub const ALL: [Op; 5] = [Op::Status, Op::Diff, Op::Log, Op::Commit, Op::Restore];

    /// What the tool is called. `git_` rather than something backend-neutral
    /// on purpose: a model already knows what `git_commit` means, and that is
    /// worth more than a name nothing has ever been trained on.
    pub fn tool_name(self) -> &'static str {
        match self {
            Op::Status => "git_status",
            Op::Diff => "git_diff",
            Op::Log => "git_log",
            Op::Commit => "git_commit",
            Op::Restore => "git_restore",
        }
    }

    pub fn mutates(self) -> bool {
        matches!(self, Op::Commit | Op::Restore)
    }
}

/// One backend. Paths arrive workspace-relative and already checked — a
/// backend is given paths, never asked to judge them.
pub trait Vcs: Send + Sync {
    /// What it can do here, which on a directory under no version control at
    /// all is nothing.
    fn capabilities(&self) -> Vec<Op>;

    fn status(&self) -> Result<String, String>;

    /// Uncommitted changes as a patch; empty `paths` means the workspace.
    fn diff(&self, paths: &[String]) -> Result<String, String>;

    fn log(&self, count: usize) -> Result<String, String>;

    /// Commit `paths` — or, empty, everything under the workspace.
    fn commit(&self, message: &str, paths: &[String]) -> Result<String, String>;

    /// Put `paths` back the way the last commit has them.
    fn restore(&self, paths: &[String]) -> Result<String, String>;
}

/// The trailer every commit carries (plan decision 6). The identity stays the
/// checkout's own — gears commits as whoever owns it, because that is who is
/// answerable for the result — and this is what says how it was written.
pub const TRAILER: &str = "Co-authored-by: gears <gears@invalid>";

/// gears' own state, kept out by pathspec rather than by hoping the user
/// gitignored it. It is off limits to the file tools, and a session transcript
/// has no business in somebody's history either.
const OURS: &str = ":(exclude).gears";

/// How long one git command may take. Local work, so this is not a budget but
/// a backstop: a `git` waiting on a lock nobody will release must not take the
/// session with it.
const TIMEOUT: Duration = Duration::from_secs(60);

pub struct HostGit {
    root: PathBuf,
    ops: Vec<Op>,
}

impl HostGit {
    /// Probe once, for a `git` and for a work tree to use it on. Once, because
    /// the tools a run offers are fixed anyway: the model is shown the schemas
    /// on the way in.
    pub fn open(root: &Path) -> HostGit {
        let mut git = HostGit {
            root: root.to_path_buf(),
            ops: Vec::new(),
        };
        if git.git(&["rev-parse", "--is-inside-work-tree"]).is_ok() {
            git.ops = Op::ALL.to_vec();
        }
        git
    }

    /// One git command: an argument vector, no shell, run in the workspace.
    /// A non-zero status *is* an error here, unlike in `run` — what a failed
    /// commit has to say is why it did not happen.
    fn git(&self, args: &[impl AsRef<str>]) -> Result<String, String> {
        let mut argv = vec!["-C".to_string(), self.root.display().to_string()];
        argv.extend(args.iter().map(|arg| arg.as_ref().to_string()));
        let outcome = capture(&Job {
            program: "git".to_string(),
            args: argv,
            cwd: self.root.clone(),
            timeout: TIMEOUT,
            spawn_context: None,
        })?;
        let said = outcome.output.trim_end();
        match outcome.ok {
            true => Ok(said.to_string()),
            false => Err(format!("{}\n{said}", outcome.status).trim_end().to_string()),
        }
    }

    /// Whether there is a commit to compare against yet.
    fn has_head(&self) -> bool {
        self.git(&["rev-parse", "--verify", "--quiet", "HEAD"])
            .is_ok()
    }
}

impl Vcs for HostGit {
    fn capabilities(&self) -> Vec<Op> {
        self.ops.clone()
    }

    fn status(&self) -> Result<String, String> {
        // The short form, and only the workspace: gears may be working in one
        // directory of a much larger repository, and what it cannot touch is
        // not its business to report.
        let out = self.git(&about(&["status", "--short", "--branch"], &[]))?;
        Ok(or_else(out, "nothing has changed"))
    }

    fn diff(&self, paths: &[String]) -> Result<String, String> {
        if !self.has_head() {
            return Ok(NO_HEAD.to_string());
        }
        // Against HEAD, so that "changed" means what the model means by it,
        // staged or not; `--relative` so the paths in the patch are the paths
        // the file tools take; `--no-ext-diff` so that a difftool somebody
        // configured is not what answers.
        let out = self.git(&about(
            &["diff", "--no-color", "--no-ext-diff", "--relative", "HEAD"],
            paths,
        ))?;
        Ok(or_else(out, "no changes since the last commit"))
    }

    fn log(&self, count: usize) -> Result<String, String> {
        // The repository's history rather than the workspace's: a commit is
        // about the whole tree, and its subject is what this is read for.
        self.git(&[
            "log",
            "--no-color",
            "--oneline",
            format!("--max-count={count}").as_str(),
        ])
    }

    fn commit(&self, message: &str, paths: &[String]) -> Result<String, String> {
        // Staged first: a file the model has just written is untracked, and a
        // commit naming it would not find it.
        self.git(&about(&["add"], paths))?;
        let message = with_trailer(message);
        self.git(&about(&["commit", "--message", &message], paths))
    }

    fn restore(&self, paths: &[String]) -> Result<String, String> {
        if paths.is_empty() {
            return Err("name the files to put back".to_string());
        }
        self.git(&about(
            &["restore", "--source=HEAD", "--staged", "--worktree"],
            paths,
        ))?;
        Ok(format!("put back: {}", paths.join(", ")))
    }
}

const NO_HEAD: &str = "no commits yet: there is nothing to compare against, \
                       and git_status lists what is here";

/// The backend for this machine, whatever it turns out to be capable of.
pub fn host(root: &Path) -> Arc<dyn Vcs> {
    Arc::new(HostGit::open(root))
}

/// The git tools for the platform gears is running on. On the host the probe
/// decides: a workspace under no version control gets no tools, because there
/// genuinely is none there. Motor OS v1 has no git *anywhere*, and that is
/// said out loud instead — a stub per verb, refusing with the reason — since
/// "no version control on this machine" is a platform fact the model would
/// otherwise misread as a fact about the workspace.
pub fn for_platform(root: &Path, workspace: Arc<Workspace>) -> Vec<Box<dyn Tool>> {
    #[cfg(unix)]
    {
        tools(host(root), workspace)
    }
    #[cfg(not(unix))]
    {
        let _ = (root, workspace);
        Op::ALL
            .into_iter()
            .map(|op| {
                super::unsupported::tool(
                    op.tool_name(),
                    "Motor OS has no git in v1; the undo log still protects \
                     every change, and /undo puts files back",
                )
            })
            .collect()
    }
}

/// How many commits `git_log` shows when it is not told.
const COMMITS: usize = 20;

pub struct VcsTool {
    op: Op,
    vcs: Arc<dyn Vcs>,
    workspace: Arc<Workspace>,
}

/// One tool per verb the backend has — and, where it has none, no tools at
/// all: the model is never shown version control that is not there.
pub fn tools(vcs: Arc<dyn Vcs>, workspace: Arc<Workspace>) -> Vec<Box<dyn Tool>> {
    vcs.capabilities()
        .into_iter()
        .map(|op| {
            Box::new(VcsTool {
                op,
                vcs: vcs.clone(),
                workspace: workspace.clone(),
            }) as Box<dyn Tool>
        })
        .collect()
}

impl VcsTool {
    /// The `paths` argument, each one checked the way a file tool checks one:
    /// inside the workspace, and not something off limits.
    fn paths(&self, args: &Value) -> Result<Vec<PathBuf>, String> {
        string_list(args, "paths")?
            .iter()
            .map(|given| self.workspace.resolve(given))
            .collect()
    }

    /// A path as git will be given it: relative to the workspace root, which
    /// is where git runs.
    fn relative(&self, path: &Path) -> String {
        match self.workspace.display(path).as_str() {
            "" => ".".to_string(),
            relative => relative.to_string(),
        }
    }
}

impl Tool for VcsTool {
    fn name(&self) -> &'static str {
        self.op.tool_name()
    }

    fn spec(&self) -> ToolSpec {
        let (what, properties, required): (&str, Value, &[&str]) = match self.op {
            Op::Status => (
                "What has changed in the workspace and is not committed yet. \
                 Untracked files are marked '??'.",
                json!({}),
                &[],
            ),
            Op::Diff => (
                "The uncommitted changes as a patch, against the last commit. A file \
                 that has never been committed does not appear in a diff: git_status \
                 is what lists those.",
                json!({"paths": {"type": "array", "items": {"type": "string"},
                    "description": "Only these (default: everything in the workspace)."}}),
                &[],
            ),
            Op::Log => (
                "The most recent commits, one line each.",
                json!({"count": {"type": "integer",
                    "description": format!("How many (default {COMMITS}).")}}),
                &[],
            ),
            Op::Commit => (
                "Commit what has changed in the workspace, files not yet tracked \
                 included. Commit when you were asked to and not otherwise, and say \
                 in the message what changed and why rather than how.",
                json!({
                    "message": {"type": "string"},
                    "paths": {"type": "array", "items": {"type": "string"},
                        "description": "Commit only these (default: everything in the workspace)."},
                }),
                &["message"],
            ),
            Op::Restore => (
                "Put files back the way the last commit has them, throwing away the \
                 uncommitted changes to them.",
                json!({"paths": {"type": "array", "items": {"type": "string"},
                    "description": "The files to put back — files, not directories."}}),
                &["paths"],
            ),
        };
        ToolSpec::new(self.name(), what, schema(properties, required))
    }

    fn mutates(&self) -> bool {
        self.op.mutates()
    }

    fn call(&self, args: &Value) -> Result<String, String> {
        let paths = self.paths(args)?;
        let named: Vec<String> = paths.iter().map(|path| self.relative(path)).collect();
        match self.op {
            Op::Status => self.vcs.status(),
            Op::Diff => self.vcs.diff(&named),
            Op::Log => self.vcs.log(usize_arg(args, "count", COMMITS)?),
            Op::Commit => self.vcs.commit(&string_arg(args, "message")?, &named),
            Op::Restore => {
                // Throwing a change away is changing a file, so the undo log
                // takes its copy first — otherwise `/undo` could not put back
                // what a restore discarded. A directory has no copy to take,
                // which is why this asks for files.
                for path in &paths {
                    if path.is_dir() {
                        return Err(format!(
                            "'{}' is a directory: name the files to put back",
                            self.workspace.display(path)
                        ));
                    }
                    self.workspace.before_write(path)?;
                }
                self.vcs.restore(&named)
            }
        }
    }
}

/// A command, then `--`, then what it is about — the shape all of these take.
/// The paths a call named, or the whole workspace when it named none.
fn about(head: &[&str], paths: &[String]) -> Vec<String> {
    let mut argv: Vec<String> = head.iter().map(|word| word.to_string()).collect();
    argv.push("--".to_string());
    match paths.is_empty() {
        true => argv.extend([".".to_string(), OURS.to_string()]),
        false => argv.extend(paths.iter().cloned()),
    }
    argv
}

/// Something to read rather than nothing: an empty result leaves a model
/// wondering whether the tool worked.
fn or_else(text: String, instead: &str) -> String {
    match text.trim().is_empty() {
        true => instead.to_string(),
        false => text,
    }
}

/// The message as it will be written: the model's own words, then the trailer.
fn with_trailer(message: &str) -> String {
    let body = message.trim_end();
    if body.lines().any(|line| line.trim() == TRAILER) {
        return format!("{body}\n");
    }
    // A blank line first, unless the message already ends in trailers of its
    // own: git reads only the last paragraph as trailers, so a `Signed-off-by`
    // must not be left in one of its own.
    let gap = match body.rsplit('\n').next().is_some_and(is_trailer) {
        true => "\n",
        false => "\n\n",
    };
    format!("{body}{gap}{TRAILER}\n")
}

fn is_trailer(line: &str) -> bool {
    line.split_once(": ").is_some_and(|(key, _)| {
        !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn temp(name: &str) -> PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "gears-vcs-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A repository with an identity of its own, so that the host's global git
    /// configuration — or its absence — is not part of what is under test.
    fn repo(name: &str) -> PathBuf {
        let dir = temp(name);
        for args in [
            ["init", "--quiet"].as_slice(),
            &["config", "user.email", "gears@invalid"],
            &["config", "user.name", "gears test"],
            &["config", "commit.gpgsign", "false"],
        ] {
            git(&dir, args);
        }
        dir
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        HostGit {
            root: dir.to_path_buf(),
            ops: Vec::new(),
        }
        .git(args)
        .unwrap()
    }

    #[test]
    fn a_directory_under_no_version_control_offers_nothing() {
        let dir = temp("bare");
        assert!(HostGit::open(&dir).capabilities().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn what_changed_is_seen_committed_and_carries_the_trailer() {
        let dir = repo("commit");
        let vcs = HostGit::open(&dir);
        assert_eq!(vcs.capabilities(), Op::ALL);

        std::fs::write(dir.join("a.txt"), "one\n").unwrap();
        std::fs::create_dir_all(dir.join(".gears")).unwrap();
        std::fs::write(dir.join(".gears/session.jsonl"), "private\n").unwrap();

        let status = vcs.status().unwrap();
        assert!(status.contains("?? a.txt"), "{status}");
        assert!(!status.contains(".gears"), "{status}");
        // Before the first commit there is nothing to compare against, and
        // saying so beats relaying a fatal from git.
        assert!(vcs.diff(&[]).unwrap().contains("no commits yet"));

        vcs.commit("add a note", &[]).unwrap();
        let log = vcs.log(10).unwrap();
        assert!(log.contains("add a note"), "{log}");
        let message = git(&dir, &["log", "-1", "--format=%B"]);
        assert!(message.ends_with(TRAILER), "{message}");
        // gears' own state stayed out of somebody else's history.
        assert_eq!(git(&dir, &["ls-files"]), "a.txt");

        // And the round trip: change it, see the change, put it back.
        std::fs::write(dir.join("a.txt"), "two\n").unwrap();
        let diff = vcs.diff(&[]).unwrap();
        assert!(diff.contains("-one") && diff.contains("+two"), "{diff}");
        assert_eq!(
            vcs.restore(&["a.txt".to_string()]).unwrap(),
            "put back: a.txt"
        );
        assert_eq!(std::fs::read_to_string(dir.join("a.txt")).unwrap(), "one\n");
        assert_eq!(vcs.diff(&[]).unwrap(), "no changes since the last commit");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// gears may be working in one directory of a repository it does not own
    /// the whole of. What it commits is what is under its workspace.
    #[test]
    fn a_commit_is_bounded_to_the_workspace() {
        let dir = repo("bounded");
        std::fs::create_dir_all(dir.join("work")).unwrap();
        std::fs::write(dir.join("work/inside.txt"), "mine\n").unwrap();
        std::fs::write(dir.join("outside.txt"), "not mine\n").unwrap();

        let vcs = HostGit::open(&dir.join("work"));
        vcs.commit("only what is mine", &[]).unwrap();
        assert_eq!(git(&dir, &["ls-files"]), "work/inside.txt");
        let status = vcs.status().unwrap();
        assert!(!status.contains("outside.txt"), "{status}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A commit that did not happen must not read like one that did.
    #[test]
    fn a_commit_with_nothing_to_say_fails_in_gits_own_words() {
        let dir = repo("nothing");
        let vcs = HostGit::open(&dir);
        // An empty repository: git names the pathspec that found nothing.
        let error = vcs.commit("nothing at all", &[]).unwrap_err();
        assert!(error.starts_with("exit status 1"), "{error}");
        assert!(error.contains("pathspec"), "{error}");

        // And with a commit behind it, the everyday form of the same answer.
        std::fs::write(dir.join("a.txt"), "one\n").unwrap();
        vcs.commit("something", &[]).unwrap();
        let error = vcs.commit("again", &[]).unwrap_err();
        assert!(error.contains("nothing to commit"), "{error}");

        // Restoring everything is not a thing to ask for by accident.
        assert!(vcs.restore(&[]).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// What is registered is what the backend can do — and where it can do
    /// nothing, the model is not shown version control at all.
    #[test]
    fn the_tools_are_exactly_what_the_backend_can_do() {
        struct Fake(Vec<Op>);

        impl Vcs for Fake {
            fn capabilities(&self) -> Vec<Op> {
                self.0.clone()
            }
            fn status(&self) -> Result<String, String> {
                Ok("clean".to_string())
            }
            fn diff(&self, _: &[String]) -> Result<String, String> {
                Ok(String::new())
            }
            fn log(&self, _: usize) -> Result<String, String> {
                Ok(String::new())
            }
            fn commit(&self, _: &str, _: &[String]) -> Result<String, String> {
                Ok(String::new())
            }
            fn restore(&self, _: &[String]) -> Result<String, String> {
                Ok(String::new())
            }
        }

        let dir = temp("registered");
        let workspace = Arc::new(Workspace::new(&dir).unwrap());
        let registered = |ops: Vec<Op>| tools(Arc::new(Fake(ops)), workspace.clone());
        assert!(registered(Vec::new()).is_empty());

        let all = registered(Op::ALL.to_vec());
        let names: Vec<&str> = all.iter().map(|tool| tool.name()).collect();
        assert_eq!(
            names,
            [
                "git_status",
                "git_diff",
                "git_log",
                "git_commit",
                "git_restore"
            ]
        );
        // Only the two that change something are put to the user.
        let asked: Vec<&str> = all
            .iter()
            .filter(|tool| tool.gated(&json!({})))
            .map(|tool| tool.name())
            .collect();
        assert_eq!(asked, ["git_commit", "git_restore"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A restore throws work away, so it goes through what a write goes
    /// through: the workspace bounds it, and the undo log takes its copy
    /// first — otherwise `/undo` could not put back what it discarded.
    #[test]
    fn a_restore_is_checked_and_recorded_before_it_happens() {
        let dir = repo("restore");
        std::fs::write(dir.join("a.txt"), "committed\n").unwrap();
        let vcs = host(&dir);
        vcs.commit("first", &[]).unwrap();
        std::fs::write(dir.join("a.txt"), "changed\n").unwrap();

        let workspace = Workspace::new(&dir).unwrap();
        let undo = Arc::new(crate::agent::undo::UndoLog::new(workspace.root(), "s1"));
        let workspace = Arc::new(workspace.with_undo(undo.clone()));
        let all = tools(vcs, workspace);
        let restore = all
            .iter()
            .find(|tool| tool.name() == "git_restore")
            .unwrap();

        assert!(restore.call(&json!({"paths": ["../elsewhere"]})).is_err());
        let error = restore.call(&json!({"paths": ["."]})).unwrap_err();
        assert!(error.contains("is a directory"), "{error}");
        // Neither of those threw anything away.
        assert_eq!(
            std::fs::read_to_string(dir.join("a.txt")).unwrap(),
            "changed\n"
        );

        restore.call(&json!({"paths": ["a.txt"]})).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("a.txt")).unwrap(),
            "committed\n"
        );
        assert_eq!(undo.files(), ["a.txt"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_message_ends_with_exactly_one_trailer() {
        let one = format!("subject\n\n{TRAILER}\n");
        assert_eq!(with_trailer("subject"), one);
        assert_eq!(with_trailer("subject\n"), one);
        assert_eq!(with_trailer(&one), one);
        // A message already ending in trailers gets another line, not another
        // paragraph.
        let signed = "subject\n\nSigned-off-by: someone <s@example.com>";
        assert_eq!(with_trailer(signed), format!("{signed}\n{TRAILER}\n"));
        assert!(!is_trailer("no colon here"));
        assert!(!is_trailer("not a key: value"));
    }
}
