//! File tools, and the confinement every one of them goes through.
//!
//! [`Workspace`] is the only door: a tool never touches a path the model
//! supplied, only one that came back from [`Workspace::resolve`]. Resolution
//! is deliberately paranoid, because the model is not the adversary here —
//! its *input* is, and a repository full of symlinks is an ordinary thing.
//!
//! This is policy inside gears, not enforcement by the OS: an honest v1
//! posture, stated in the proposal. `run` remains the deliberate escape
//! hatch, gated separately.

use std::ffi::OsString;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use serde_json::{Value, json};

use super::{Tool, bool_arg, opt_string, schema, string_arg, string_list, usize_arg};
use crate::provider::ToolSpec;

/// Conventional directory names that repository-wide tools step over. The
/// rule is by *name*, so an explicit safe path into one still works — a model
/// that asks for `target/debug` gets it. `.gears` is separately denied because
/// it contains internal state.
pub const SKIPPED: [&str; 11] = [
    ".git",
    ".hg",
    ".svn",
    ".gears",
    "target",
    "build",
    "dist",
    "out",
    "generated",
    "vendor",
    "node_modules",
];

/// The directory the fs tools may see, plus paths that are off limits inside
/// it (gears' own state, the API key file).
pub struct Workspace {
    root: PathBuf,
    denied: Vec<PathBuf>,
    undo: Option<Arc<crate::agent::undo::UndoLog>>,
    checkpoints: Option<Arc<crate::agent::checkpoint::LazyStore>>,
    mutation: Mutex<()>,
}

impl Workspace {
    /// `root` must exist: it is canonicalized once, and every later check is
    /// a prefix comparison against the result.
    pub fn new(root: &Path) -> Result<Workspace, String> {
        let canonical = root
            .canonicalize()
            .map_err(|e| format!("workspace {}: {e}", root.display()))?;
        if !canonical.is_dir() {
            return Err(format!("workspace {} is not a directory", root.display()));
        }
        let denied = vec![canonical.join(".gears")];
        Ok(Workspace {
            root: canonical,
            denied,
            undo: None,
            checkpoints: None,
            mutation: Mutex::new(()),
        })
    }

    /// Take a copy of each file before the first change to it (plan D3). The
    /// log lives here rather than in the agent layer because this is the last
    /// place that knows a file is about to be written.
    pub fn with_undo(mut self, undo: Arc<crate::agent::undo::UndoLog>) -> Workspace {
        self.undo = Some(undo);
        self
    }

    pub fn with_checkpoints(
        mut self,
        checkpoints: Arc<crate::agent::checkpoint::LazyStore>,
    ) -> Workspace {
        self.checkpoints = Some(checkpoints);
        self
    }

    pub fn create_checkpoint(
        &self,
        name: &str,
        task_generation: u64,
        mutation_generation: u64,
    ) -> Result<crate::agent::checkpoint::Metadata, String> {
        let _mutation = self.mutation()?;
        self.checkpoints
            .as_ref()
            .ok_or("checkpoint storage is unavailable")?
            .create(name, task_generation, mutation_generation)
    }

    pub fn checkpoints(&self) -> Result<Vec<crate::agent::checkpoint::Metadata>, String> {
        self.checkpoints
            .as_ref()
            .ok_or("checkpoint storage is unavailable")?
            .list()
    }

    pub fn checkpoint_files(
        &self,
        id: u64,
    ) -> Result<Vec<crate::agent::checkpoint::FileState>, String> {
        self.checkpoints
            .as_ref()
            .ok_or("checkpoint storage is unavailable")?
            .files(id)
    }

    /// Called by a tool that is about to change `path`. An undo log that
    /// cannot record the file stops the change: writing anyway would leave
    /// the user with no way back and no warning.
    pub fn before_write(&self, path: &Path) -> Result<(), String> {
        match &self.undo {
            Some(undo) => undo.note(path),
            None => Ok(()),
        }?;
        match &self.checkpoints {
            Some(checkpoints) => checkpoints.note(path),
            None => Ok(()),
        }
    }

    /// Serialize the final identity check and filesystem change. Without this
    /// boundary, two approved changes prepared from the same input could both
    /// validate before either one writes.
    pub(crate) fn mutation(&self) -> Result<MutexGuard<'_, ()>, String> {
        self.mutation
            .lock()
            .map_err(|_| "workspace mutation lock is poisoned".to_string())
    }

    /// Put a path off limits. The API key file goes here: the agent must not
    /// be able to read its own credentials.
    pub fn deny(mut self, path: &Path) -> Workspace {
        // Canonical if it exists, absolute otherwise — denying a file that is
        // not there yet still has to work.
        let path = path
            .canonicalize()
            .or_else(|_| std::path::absolute(path))
            .unwrap_or_else(|_| path.to_path_buf());
        self.denied.push(path);
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The path as the model should see it: relative to the root.
    pub fn display(&self, path: &Path) -> String {
        path.strip_prefix(&self.root)
            .unwrap_or(path)
            .display()
            .to_string()
    }

    /// Turn a model-supplied path into one a tool may use, or explain why
    /// not. Relative paths are taken against the root; absolute ones must
    /// already be inside it.
    pub fn resolve(&self, given: &str) -> Result<PathBuf, String> {
        let asked = Path::new(given);
        let target = if asked.is_absolute() {
            asked.to_path_buf()
        } else {
            self.root.join(asked)
        };
        // Lexical first: `..` is refused outright rather than resolved, so
        // there is no arithmetic to get wrong.
        if target
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(format!("'{given}': paths must not contain '..'"));
        }

        // Then the real filesystem: canonicalizing the deepest part that
        // exists is what catches a symlink pointing out of the workspace,
        // while still allowing a file that is about to be created.
        let (existing, rest) = anchor(&target)?;
        if !existing.starts_with(&self.root) {
            return Err(format!(
                "'{given}' is outside the workspace ({})",
                self.root.display()
            ));
        }
        let resolved = rest.iter().fold(existing, |path, part| path.join(part));
        if let Some(denied) = self.denied_by(&resolved) {
            return Err(format!(
                "'{given}' is off limits to tools ({})",
                self.display(denied)
            ));
        }
        Ok(resolved)
    }

    /// Off limits, for callers that walk the tree themselves — `resolve`
    /// guards the door, and a search must not stroll in through the window.
    pub fn is_denied(&self, path: &Path) -> bool {
        self.denied_by(path).is_some()
    }

    fn denied_by(&self, path: &Path) -> Option<&Path> {
        self.denied
            .iter()
            .find(|denied| path.starts_with(denied))
            .map(PathBuf::as_path)
    }
}

/// Split `target` into its deepest existing ancestor, canonicalized, and the
/// components below it that do not exist yet.
fn anchor(target: &Path) -> Result<(PathBuf, Vec<OsString>), String> {
    let mut rest = Vec::new();
    let mut probe = target.to_path_buf();
    loop {
        if let Ok(real) = probe.canonicalize() {
            rest.reverse();
            return Ok((real, rest));
        }
        match (probe.file_name(), probe.parent()) {
            (Some(name), Some(parent)) => {
                rest.push(name.to_os_string());
                probe = parent.to_path_buf();
            }
            // Walked off the top without finding anything real.
            _ => return Err(format!("{}: no such path", target.display())),
        }
    }
}

// ---- the tools -------------------------------------------------------------

enum Kind {
    Read,
    Write,
    Edit,
    List,
    Grep,
}

pub struct FsTool {
    kind: Kind,
    workspace: Arc<Workspace>,
    resources: crate::config::Resources,
}

/// The file tools, all sharing one workspace.
pub fn tools(workspace: Arc<Workspace>) -> Vec<Box<dyn Tool>> {
    tools_with_resources(workspace, crate::config::Resources::default())
}

pub fn tools_with_resources(
    workspace: Arc<Workspace>,
    resources: crate::config::Resources,
) -> Vec<Box<dyn Tool>> {
    [Kind::Read, Kind::Write, Kind::Edit, Kind::List, Kind::Grep]
        .into_iter()
        .map(|kind| {
            Box::new(FsTool {
                kind,
                workspace: workspace.clone(),
                resources,
            }) as Box<dyn Tool>
        })
        .collect()
}

impl Tool for FsTool {
    fn name(&self) -> &'static str {
        match self.kind {
            Kind::Read => "read_file",
            Kind::Write => "write_file",
            Kind::Edit => "edit_file",
            Kind::List => "list_dir",
            Kind::Grep => "grep",
        }
    }

    fn spec(&self) -> ToolSpec {
        let path = json!({"type": "string", "description": "Path relative to the workspace root."});
        let (description, properties, required): (&str, Value, &[&str]) = match self.kind {
            Kind::Read => (
                "Read a bounded file slice with total size and a SHA-256 content identity. \
                 With no range, reads the first configured-limit bytes. Byte offsets are \
                 zero-based and line numbers are one-based; supply the returned identity to \
                 reject content that changed between reads. Binary or control-byte content \
                 is returned as exact lowercase hex.",
                json!({
                    "path": path,
                    "expected_identity": {"type": "string", "description":
                        "Optional identity from an earlier read; fails if the file changed."},
                    "byte_start": {"type": "integer", "minimum": 0},
                    "byte_length": {"type": "integer", "minimum": 1,
                        "maximum": self.resources.max_range_read_bytes},
                    "line_start": {"type": "integer", "minimum": 1},
                    "line_count": {"type": "integer", "minimum": 1, "description":
                        "The selected lines must fit the configured byte-range limit."},
                }),
                &["path"],
            ),
            Kind::Write => (
                "Create a file or replace one entirely. Missing parent \
                 directories are created. To change part of an existing file, \
                 prefer edit_file.",
                json!({ "path": path, "content": {"type": "string"} }),
                &["path", "content"],
            ),
            Kind::Edit => (
                "Replace one exact occurrence of 'old' with 'new'. 'old' must \
                 appear exactly once, so include enough surrounding text to \
                 make it unique.",
                json!({ "path": path, "old": {"type": "string"}, "new": {"type": "string"} }),
                &["path", "old", "new"],
            ),
            Kind::List => (
                "List one directory. Directories end in '/', symlinks in '@'. \
                 Conventional VCS, generated, vendor, build, dependency, and \
                 gears-state directories are not listed unless explicitly requested.",
                json!({ "path": path }),
                &[],
            ),
            Kind::Grep => (
                "Search text files using a bounded native matcher. Reports one line per \
                 match as path:line:text. Conventional VCS, generated, vendor, build, \
                 dependency, and gears-state directories are skipped unless explicitly \
                 requested; symlinks are not followed.",
                json!({
                    "pattern": {"type": "string"},
                    "path": {"type": "string", "description":
                        "File or directory to search, relative to the workspace root \
                         (default: the whole workspace)."},
                    "include": {"type": "string", "description":
                        "Deprecated single include glob; use 'includes' for new calls."},
                    "includes": {"type": "array", "items": {"type": "string"},
                        "description": "Include paths matching any glob."},
                    "excludes": {"type": "array", "items": {"type": "string"},
                        "description": "Exclude paths matching any glob."},
                    "regex": {"type": "boolean", "description":
                        "Interpret pattern as a regular expression (default: false)."},
                    "ignore_case": {"type": "boolean"},
                    "files_only": {"type": "boolean", "description":
                        "Match workspace-relative file paths instead of file contents."},
                    "cursor": {"type": "integer", "minimum": 0,
                        "description": "Resume at a cursor returned by the same search."},
                    "max_results": {"type": "integer", "minimum": 1,
                        "maximum": self.resources.search_max_results_per_page,
                        "description": format!("Default {}.",
                            self.resources.search_default_results)},
                }),
                &["pattern"],
            ),
        };
        ToolSpec::new(self.name(), description, schema(properties, required))
    }

    fn mutates(&self) -> bool {
        matches!(self.kind, Kind::Write | Kind::Edit)
    }

    fn prepare_mutation(&self, args: &Value) -> Result<Option<super::mutation::Prepared>, String> {
        let prepared = match self.kind {
            Kind::Write => self.prepare_write(args)?,
            Kind::Edit => self.prepare_edit(args)?,
            _ => return Ok(None),
        };
        Ok(Some(prepared))
    }

    fn apply_mutation(&self, prepared: &super::mutation::Prepared) -> Result<String, String> {
        if prepared.tool() != self.name() {
            return Err(format!(
                "prepared for {}, not {}",
                prepared.tool(),
                self.name()
            ));
        }
        let applied = prepared.apply(&self.workspace)?;
        match self.kind {
            Kind::Write => Ok(format!(
                "wrote {} bytes to {}{}",
                applied.bytes,
                applied.paths[0],
                pending_cleanup(&applied)
            )),
            Kind::Edit => Ok(format!(
                "edited {}{}",
                applied.paths[0],
                pending_cleanup(&applied)
            )),
            _ => Err(format!(
                "{} does not accept prepared mutations",
                self.name()
            )),
        }
    }

    fn call(&self, args: &Value) -> Result<String, String> {
        match self.kind {
            Kind::Read => self.read(args),
            Kind::Write | Kind::Edit => {
                let prepared = self
                    .prepare_mutation(args)?
                    .ok_or_else(|| format!("{} did not prepare a mutation", self.name()))?;
                self.apply_mutation(&prepared)
            }
            Kind::List => self.list(args),
            Kind::Grep => self.grep(args, None),
        }
    }

    fn execute(&self, args: &Value, execution: &super::Execution) -> Result<String, String> {
        match self.kind {
            Kind::Grep => self.grep(args, Some(execution)),
            _ => self.call(args),
        }
    }

    fn cap(&self) -> usize {
        match self.kind {
            // Hex needs twice the source bytes; the rest covers metadata and
            // a long workspace-relative path.
            Kind::Read => super::DEFAULT_CAP.max(
                self.resources
                    .max_range_read_bytes
                    .saturating_mul(2)
                    .saturating_add(8 * 1024),
            ),
            _ => super::DEFAULT_CAP,
        }
    }
}

fn pending_cleanup(applied: &super::mutation::Applied) -> &'static str {
    if applied.recovery_pending {
        "; transaction cleanup is pending until the next Gears start"
    } else {
        ""
    }
}

impl FsTool {
    fn read(&self, args: &Value) -> Result<String, String> {
        let given = string_arg(args, "path")?;
        let path = self.workspace.resolve(&given)?;
        super::file::read(&path, &given, args, self.resources.max_range_read_bytes)
    }

    fn prepare_write(&self, args: &Value) -> Result<super::mutation::Prepared, String> {
        let given = string_arg(args, "path")?;
        let content = string_arg(args, "content")?;
        super::mutation::Prepared::one_file(
            &self.workspace,
            self.name(),
            self.permission_key(args),
            given,
            content.into_bytes(),
        )
    }

    fn prepare_edit(&self, args: &Value) -> Result<super::mutation::Prepared, String> {
        let given = string_arg(args, "path")?;
        let old = string_arg(args, "old")?;
        let new = string_arg(args, "new")?;
        if old.is_empty() {
            return Err("'old' must not be empty".to_string());
        }
        if old == new {
            return Err("'old' and 'new' are identical".to_string());
        }
        super::mutation::Prepared::transform_file(
            &self.workspace,
            self.name(),
            self.permission_key(args),
            given.clone(),
            |bytes| {
                let text =
                    std::str::from_utf8(bytes).map_err(|error| format!("{given}: {error}"))?;
                match text.matches(&old).count() {
                    0 => Err(format!("'old' does not appear in {given}")),
                    1 => Ok(text.replacen(&old, &new, 1).into_bytes()),
                    n => Err(format!(
                        "'old' appears {n} times in {given}; include enough surrounding \
                         text to make it unique"
                    )),
                }
            },
        )
    }

    fn list(&self, args: &Value) -> Result<String, String> {
        let given = opt_string(args, "path")?.unwrap_or_else(|| ".".to_string());
        let path = self.workspace.resolve(&given)?;
        let mut entries = Vec::new();
        let mut skipped = Vec::new();
        for entry in std::fs::read_dir(&path).map_err(|e| format!("{given}: {e}"))? {
            let entry = entry.map_err(|e| format!("{given}: {e}"))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if SKIPPED.contains(&name.as_str()) {
                skipped.push(format!("{name}/"));
                continue;
            }
            let kind = entry.file_type().map_err(|e| format!("{given}: {e}"))?;
            entries.push(if kind.is_symlink() {
                format!("{name}@")
            } else if kind.is_dir() {
                format!("{name}/")
            } else {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                format!("{name} ({size} bytes)")
            });
        }
        if entries.is_empty() && skipped.is_empty() {
            return Ok(format!("{given} is empty"));
        }
        entries.sort();
        if !skipped.is_empty() {
            skipped.sort();
            entries.push(format!("[not listed: {}]", skipped.join(", ")));
        }
        Ok(entries.join("\n"))
    }

    fn grep(&self, args: &Value, execution: Option<&super::Execution>) -> Result<String, String> {
        let pattern = string_arg(args, "pattern")?;
        if pattern.is_empty() {
            return Err("'pattern' must not be empty".to_string());
        }
        let given = opt_string(args, "path")?.unwrap_or_else(|| ".".to_string());
        let mut includes = string_list(args, "includes")?;
        if let Some(include) = opt_string(args, "include")? {
            if !includes.is_empty() {
                return Err("use either 'include' or 'includes', not both".to_string());
            }
            includes.push(include);
        }
        let excludes = string_list(args, "excludes")?;
        let fold = bool_arg(args, "ignore_case", false)?;
        let regex = bool_arg(args, "regex", false)?;
        let files_only = bool_arg(args, "files_only", false)?;
        let cursor = usize_arg(args, "cursor", 0)?;
        let max = usize_arg(args, "max_results", self.resources.search_default_results)?;
        if !(1..=self.resources.search_max_results_per_page).contains(&max) {
            return Err(format!(
                "'max_results' must be between 1 and {}",
                self.resources.search_max_results_per_page
            ));
        }
        let root = self.workspace.resolve(&given)?;
        let matcher = super::search::Matcher::new(&pattern, regex, fold, self.resources)?;
        let filter = super::search::FileFilter::new(&includes, &excludes, self.resources)?;
        let mut page = super::search::Page::new(cursor, max);
        let mut rg = super::search::find_rg();
        let mut batch = Vec::new();
        let mut batch_bytes: usize = 0;
        for file in walk(&self.workspace, &root, &filter)? {
            if execution.is_some_and(super::Execution::cancelled) {
                return Err("search was cancelled".to_string());
            }
            let display = self.workspace.display(&file);
            if files_only {
                if matcher.is_match(&display) {
                    page.push(super::search::Hit {
                        path: display,
                        line: None,
                        text: None,
                    });
                }
                continue;
            }
            if rg.is_some() {
                match acceleration_candidate(&file, &display, self.resources, &mut page)? {
                    Acceleration::Use => {
                        let argument_bytes = file.as_os_str().len().saturating_add(1);
                        if batch.len() == 64
                            || batch_bytes.saturating_add(argument_bytes) > 32 * 1024
                        {
                            flush_rg(
                                &mut rg,
                                &mut batch,
                                &matcher,
                                &pattern,
                                regex,
                                fold,
                                self.resources,
                                &self.workspace,
                                &mut page,
                                execution,
                            )?;
                            batch_bytes = 0;
                        }
                        batch_bytes += argument_bytes;
                        batch.push(file);
                        continue;
                    }
                    Acceleration::Skip => continue,
                    Acceleration::Native => {}
                }
            }
            flush_rg(
                &mut rg,
                &mut batch,
                &matcher,
                &pattern,
                regex,
                fold,
                self.resources,
                &self.workspace,
                &mut page,
                execution,
            )?;
            batch_bytes = 0;
            if let Some(bytes) = read_search_file(&file, &display, self.resources, &mut page)? {
                search_bytes(&matcher, &display, &bytes, &mut page);
            }
        }
        flush_rg(
            &mut rg,
            &mut batch,
            &matcher,
            &pattern,
            regex,
            fold,
            self.resources,
            &self.workspace,
            &mut page,
            execution,
        )?;
        page.render(&pattern)
    }
}

enum Acceleration {
    Use,
    Skip,
    Native,
}

fn acceleration_candidate(
    file: &Path,
    display: &str,
    resources: crate::config::Resources,
    page: &mut super::search::Page,
) -> Result<Acceleration, String> {
    if file.to_str().is_none() {
        return Ok(Acceleration::Native);
    }
    let Ok(metadata) = file.metadata() else {
        return Ok(Acceleration::Native);
    };
    if metadata.len() > resources.search_max_file_bytes as u64 {
        page.skipped(format!(
            "{display} (larger than {} bytes)",
            resources.search_max_file_bytes
        ));
        return Ok(Acceleration::Skip);
    }
    let Ok(mut input) = std::fs::File::open(file) else {
        return Ok(Acceleration::Native);
    };
    let mut prefix = [0_u8; 8192];
    let read = input
        .read(&mut prefix)
        .map_err(|error| format!("{display}: {error}"))?;
    if prefix[..read].contains(&0) {
        return Ok(Acceleration::Skip);
    }
    Ok(Acceleration::Use)
}

fn read_search_file(
    file: &Path,
    display: &str,
    resources: crate::config::Resources,
    page: &mut super::search::Page,
) -> Result<Option<Vec<u8>>, String> {
    let Ok(mut input) = std::fs::File::open(file) else {
        return Ok(None); // It vanished between traversal and open.
    };
    let mut bytes = Vec::new();
    input
        .by_ref()
        .take(
            u64::try_from(resources.search_max_file_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{display}: {error}"))?;
    if bytes.len() > resources.search_max_file_bytes {
        page.skipped(format!(
            "{display} (larger than {} bytes)",
            resources.search_max_file_bytes
        ));
        return Ok(None);
    }
    if bytes.iter().take(8192).any(|byte| *byte == 0) {
        return Ok(None);
    }
    Ok(Some(bytes))
}

fn search_bytes(
    matcher: &super::search::Matcher,
    display: &str,
    bytes: &[u8],
    page: &mut super::search::Page,
) {
    if bytes.is_empty() {
        return;
    }
    let content = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    for (number, line) in content.split(|byte| *byte == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if matcher.is_match_bytes(line) {
            let text = String::from_utf8_lossy(line);
            page.push(super::search::Hit {
                path: display.to_string(),
                line: Some(number + 1),
                text: Some(super::clip(text.trim_end(), 200)),
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn flush_rg(
    program: &mut Option<PathBuf>,
    files: &mut Vec<PathBuf>,
    matcher: &super::search::Matcher,
    pattern: &str,
    regular_expression: bool,
    ignore_case: bool,
    resources: crate::config::Resources,
    workspace: &Workspace,
    page: &mut super::search::Page,
    execution: Option<&super::Execution>,
) -> Result<(), String> {
    if files.is_empty() {
        return Ok(());
    }
    let accelerated = program.as_deref().is_some_and(|program| {
        super::search::rg_batch(
            program,
            workspace.root(),
            files,
            pattern,
            regular_expression,
            ignore_case,
            resources,
            page,
            execution,
        )
    });
    if !accelerated {
        *program = None;
        for file in files.iter() {
            if execution.is_some_and(super::Execution::cancelled) {
                return Err("search was cancelled".to_string());
            }
            let display = workspace.display(file);
            if let Some(bytes) = read_search_file(file, &display, resources, page)? {
                search_bytes(matcher, &display, &bytes, page);
            }
        }
    }
    files.clear();
    Ok(())
}

/// Every file under `root`, deterministically ordered, skipping [`SKIPPED`]
/// directories and anything the workspace denies. Symlinks are never
/// followed: that is both the cycle guard and a second line of defence
/// against leaving the workspace.
fn walk(
    workspace: &Workspace,
    root: &Path,
    filter: &super::search::FileFilter,
) -> Result<Vec<PathBuf>, String> {
    if root.is_file() {
        return Ok(filter
            .accepts(&workspace.display(root))
            .then(|| root.to_path_buf())
            .into_iter()
            .collect());
    }
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .map_err(|e| format!("{}: {e}", workspace.display(&dir)))?
            .filter_map(Result::ok)
            .collect();
        entries.sort_by_key(|entry| entry.file_name());
        let mut subdirs = Vec::new();
        for entry in entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if SKIPPED.contains(&name.as_str())
                || kind.is_symlink()
                || workspace.is_denied(&entry.path())
            {
                continue;
            }
            if kind.is_dir() {
                subdirs.push(entry.path());
            } else if filter.accepts(&workspace.display(&entry.path())) {
                files.push(entry.path());
            }
        }
        subdirs.reverse();
        stack.extend(subdirs);
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A workspace with a file, a subdirectory, and — the interesting part —
    /// symlinks pointing out of it.
    fn workspace(name: &str) -> (PathBuf, PathBuf, Workspace) {
        let base = std::env::temp_dir().join(format!("gears-fs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("work");
        let outside = base.join("outside");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        std::fs::write(outside.join("secret"), "s3cret\n").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
            std::os::unix::fs::symlink(outside.join("secret"), root.join("secret-link")).unwrap();
            std::os::unix::fs::symlink(root.join("src"), root.join("src-link")).unwrap();
        }
        let ws = Workspace::new(&root).unwrap();
        (base, outside, ws)
    }

    #[test]
    fn paths_inside_resolve() {
        let (base, _, ws) = workspace("inside");
        let root = ws.root().to_path_buf();
        assert_eq!(ws.resolve("src/main.rs").unwrap(), root.join("src/main.rs"));
        assert_eq!(ws.resolve("").unwrap(), root);
        assert_eq!(ws.resolve(".").unwrap(), root);
        // Absolute, but inside: allowed, since models emit both forms.
        let absolute = root.join("src/main.rs");
        assert_eq!(ws.resolve(absolute.to_str().unwrap()).unwrap(), absolute);
        // A file that does not exist yet still resolves — write_file needs it.
        assert_eq!(
            ws.resolve("src/new/deep.rs").unwrap(),
            root.join("src/new/deep.rs")
        );
        // A symlink to a directory inside the workspace resolves to the real
        // path rather than being refused.
        #[cfg(unix)]
        assert_eq!(ws.resolve("src-link/main.rs").unwrap(), absolute);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn nothing_escapes_the_workspace() {
        let (base, outside, ws) = workspace("escape");
        let secret = outside.join("secret");
        let mut escapes = vec![
            "..",
            "../outside/secret",
            "src/../../outside/secret",
            "/etc/passwd",
            secret.to_str().unwrap(),
        ];
        if cfg!(unix) {
            // Through a symlink to a directory outside, to a file outside,
            // and to a file outside that does not exist yet.
            escapes.extend(["escape/secret", "secret-link", "escape/planted"]);
        }
        for path in escapes {
            let err = ws.resolve(path).expect_err(path);
            assert!(
                err.contains("outside the workspace") || err.contains("'..'"),
                "{path}: {err}"
            );
        }
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn the_key_file_and_gears_state_are_off_limits() {
        let (base, _, ws) = workspace("denied");
        let key = base.join("work/openrouter.key");
        std::fs::write(&key, "sk-not-for-the-model\n").unwrap();
        std::fs::create_dir_all(base.join("work/.gears/sessions")).unwrap();
        let ws = ws.deny(&key);

        for path in ["openrouter.key", ".gears", ".gears/sessions/1.jsonl"] {
            let err = ws.resolve(path).expect_err(path);
            assert!(err.contains("off limits"), "{path}: {err}");
        }
        // Reaching the same file by another name does not help.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&key, base.join("work/innocent.txt")).unwrap();
            assert!(
                ws.resolve("innocent.txt")
                    .expect_err("via symlink")
                    .contains("off limits")
            );
        }
        std::fs::remove_dir_all(base).unwrap();
    }

    /// The same fixture, reached the way an agent reaches it: by name, with
    /// JSON arguments, through the registry.
    fn tooled(name: &str) -> (PathBuf, PathBuf, crate::tools::Registry) {
        let (base, _, workspace) = workspace(name);
        let root = workspace.root().to_path_buf();
        let mut registry = crate::tools::Registry::new();
        for tool in tools(Arc::new(workspace)) {
            registry.register(tool);
        }
        (base, root, registry)
    }

    fn call(
        registry: &crate::tools::Registry,
        name: &str,
        args: Value,
    ) -> crate::tools::ToolResult {
        let (tx, _rx) = crate::agent::event_channel();
        let execution = crate::agent::Bus::new(crate::agent::ROOT, tx).execution();
        registry.dispatch(name, &args.to_string(), &execution)
    }

    #[test]
    fn files_round_trip_through_the_tools() {
        let (base, root, registry) = tooled("roundtrip");
        let path = "src/new/deep.rs";

        let out = call(
            &registry,
            "write_file",
            json!({"path": path, "content": "fn a() {}\n"}),
        );
        assert_eq!(out.content, "wrote 10 bytes to src/new/deep.rs");
        assert!(!out.is_error());

        assert_eq!(
            call(&registry, "read_file", json!({ "path": path }))
                .content
                .lines()
                .last(),
            Some("fn a() {}")
        );

        let out = call(
            &registry,
            "edit_file",
            json!({"path": path, "old": "fn a", "new": "fn b"}),
        );
        assert_eq!(out.content, "edited src/new/deep.rs");
        assert_eq!(
            std::fs::read_to_string(root.join(path)).unwrap(),
            "fn b() {}\n"
        );
        std::fs::remove_dir_all(base).unwrap();
    }

    /// The other half of the undo log: a tool that changes a file must go
    /// through it, or the safety net has holes exactly where the work is.
    #[test]
    fn writes_and_edits_are_snapshotted_first() {
        let (base, _, workspace) = workspace("undo");
        let root = workspace.root().to_path_buf();
        let undo = Arc::new(crate::agent::undo::UndoLog::new(&root, "s1").unwrap());
        let mut registry = crate::tools::Registry::new();
        for tool in tools(Arc::new(workspace.with_undo(undo.clone()))) {
            registry.register(tool);
        }

        call(
            &registry,
            "edit_file",
            json!({"path": "src/main.rs", "old": "fn main", "new": "fn other"}),
        );
        call(
            &registry,
            "write_file",
            json!({"path": "fresh.txt", "content": "new\n"}),
        );
        // Reading changes nothing, so it is not in the log.
        call(&registry, "read_file", json!({"path": "src/main.rs"}));
        assert_eq!(undo.files(), ["fresh.txt", "src/main.rs"]);

        undo.restore().unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("src/main.rs")).unwrap(),
            "fn main() {}\n"
        );
        assert!(!root.join("fresh.txt").exists());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn edit_refuses_anything_ambiguous() {
        let (base, root, registry) = tooled("edit");
        std::fs::write(root.join("dup.txt"), "x\nx\n").unwrap();

        for (args, expected) in [
            (
                json!({"path": "dup.txt", "old": "x", "new": "y"}),
                "appears 2 times",
            ),
            (
                json!({"path": "dup.txt", "old": "zz", "new": "y"}),
                "does not appear",
            ),
            (
                json!({"path": "dup.txt", "old": "", "new": "y"}),
                "must not be empty",
            ),
            (
                json!({"path": "dup.txt", "old": "x\n", "new": "x\n"}),
                "identical",
            ),
        ] {
            let out = call(&registry, "edit_file", args);
            assert!(out.is_error() && out.content.contains(expected), "{out:?}");
        }
        // Every refusal left the file exactly as it was.
        assert_eq!(
            std::fs::read_to_string(root.join("dup.txt")).unwrap(),
            "x\nx\n"
        );
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn read_says_what_it_cannot_show() {
        let (base, root, registry) = tooled("read");
        let out = call(&registry, "read_file", json!({"path": "nope.txt"}));
        assert!(
            out.is_error() && out.content.contains("nope.txt"),
            "{out:?}"
        );

        std::fs::write(root.join("empty.txt"), "").unwrap();
        let out = call(&registry, "read_file", json!({"path": "empty.txt"}));
        assert!(out.content.contains("0 bytes returned of 0"), "{out:?}");

        // Not every file in a checkout is text, so preserve it exactly.
        std::fs::write(root.join("bin.dat"), [0xff, 0xfe, b'h', b'i']).unwrap();
        let out = call(&registry, "read_file", json!({"path": "bin.dat"}));
        assert!(!out.is_error());
        assert!(out.content.ends_with("encoding hex\nfffe6869"), "{out:?}");
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn configured_read_limits_reach_the_schema_and_reader() {
        let (base, _, workspace) = workspace("read-limit");
        let resources = crate::config::Resources {
            max_range_read_bytes: 5,
            ..crate::config::Resources::default()
        };
        let mut tools = tools_with_resources(Arc::new(workspace), resources);
        let read = tools
            .iter()
            .find(|tool| tool.name() == "read_file")
            .unwrap();
        assert_eq!(
            read.spec().function.parameters["properties"]["byte_length"]["maximum"],
            5
        );
        let mut registry = crate::tools::Registry::new();
        for tool in tools.drain(..) {
            registry.register(tool);
        }
        let out = call(&registry, "read_file", json!({"path": "src/main.rs"}));
        assert!(out.content.contains("bytes 0..5; 5 bytes returned of 13"));
        assert!(out.content.ends_with("encoding utf-8\nfn ma"));
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn list_dir_shows_the_shape_of_a_directory() {
        let (base, root, registry) = tooled("list");
        std::fs::create_dir_all(root.join("target/debug")).unwrap();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join("nothing")).unwrap();
        std::fs::write(root.join("Cargo.toml"), "[package]\n").unwrap();

        let out = call(&registry, "list_dir", json!({}));
        let listed: Vec<&str> = out.content.lines().collect();
        assert!(listed.contains(&"Cargo.toml (10 bytes)"), "{out:?}");
        assert!(listed.contains(&"src/"), "{out:?}");
        #[cfg(unix)]
        assert!(listed.contains(&"src-link@"), "{out:?}");
        assert!(
            out.content.ends_with("[not listed: .git/, target/]"),
            "{out:?}"
        );

        // Skipping is by name, so asking for one of them still works.
        let out = call(&registry, "list_dir", json!({"path": "target"}));
        assert_eq!(out.content, "debug/");
        let out = call(&registry, "list_dir", json!({"path": "nothing"}));
        assert_eq!(out.content, "nothing is empty");
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn grep_reports_every_match_in_a_stable_order() {
        let (base, root, registry) = tooled("grep");
        std::fs::create_dir_all(root.join("src/deep")).unwrap();
        std::fs::write(root.join("src/main.rs"), "fn main() {\n    let x = 1;\n}\n").unwrap();
        std::fs::write(root.join("src/deep/mod.rs"), "// TODO: main\n").unwrap();
        std::fs::write(root.join("notes.txt"), "MAIN street\nmain event\n").unwrap();

        let out = call(&registry, "grep", json!({"pattern": "main"}));
        assert_eq!(
            out.content,
            "notes.txt:2:main event\n\
             src/main.rs:1:fn main() {\n\
             src/deep/mod.rs:1:// TODO: main"
        );

        let out = call(
            &registry,
            "grep",
            json!({"pattern": "MAIN", "ignore_case": true}),
        );
        assert_eq!(out.content.lines().count(), 4, "{out:?}");

        let out = call(
            &registry,
            "grep",
            json!({"pattern": "main", "include": "*.rs"}),
        );
        assert_eq!(out.content.lines().count(), 2, "{out:?}");

        let out = call(
            &registry,
            "grep",
            json!({"pattern": "main", "path": "src/deep"}),
        );
        assert_eq!(out.content, "src/deep/mod.rs:1:// TODO: main");

        let out = call(
            &registry,
            "grep",
            json!({"pattern": "m.in\\(\\)", "path": "src/main.rs", "regex": true}),
        );
        assert_eq!(out.content, "src/main.rs:1:fn main() {");
        let out = call(&registry, "grep", json!({"pattern": "[", "regex": true}));
        assert!(out.is_error() && out.content.contains("regular expression"));

        assert_eq!(
            call(&registry, "grep", json!({"pattern": "zebra"})).content,
            "no matches for 'zebra'"
        );

        // A capped search says so rather than looking complete.
        std::fs::write(root.join("many.txt"), "hit\n".repeat(5)).unwrap();
        let out = call(
            &registry,
            "grep",
            json!({"pattern": "hit", "max_results": 2}),
        );
        assert_eq!(
            out.content,
            "many.txt:1:hit\nmany.txt:2:hit\n[next cursor: 2; showing 1-2 of 5]"
        );
        let out = call(
            &registry,
            "grep",
            json!({"pattern": "hit", "max_results": 2, "cursor": 2}),
        );
        assert_eq!(
            out.content,
            "many.txt:3:hit\nmany.txt:4:hit\n[next cursor: 4; showing 3-4 of 5]"
        );

        let out = call(
            &registry,
            "grep",
            json!({
                "pattern": "main",
                "includes": ["*.rs", "*.txt"],
                "excludes": ["src/deep/**"]
            }),
        );
        assert_eq!(
            out.content,
            "notes.txt:2:main event\nsrc/main.rs:1:fn main() {"
        );
        let out = call(
            &registry,
            "grep",
            json!({"pattern": "mod\\.rs$", "regex": true, "files_only": true}),
        );
        assert_eq!(out.content, "src/deep/mod.rs");
        let out = call(
            &registry,
            "grep",
            json!({"pattern": "main", "include": "*.rs", "includes": ["*.txt"]}),
        );
        assert!(out.is_error() && out.content.contains("either 'include' or 'includes'"));
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn configured_search_limits_reach_the_schema_and_engine() {
        let (base, _, workspace) = workspace("search-limits");
        let root = workspace.root().to_path_buf();
        std::fs::create_dir(root.join("scan")).unwrap();
        std::fs::write(root.join("scan/a.txt"), "hit\nhit\n").unwrap();
        std::fs::write(root.join("scan/big.txt"), "hit hit hit\n").unwrap();
        let resources = crate::config::Resources {
            search_default_results: 1,
            search_max_results_per_page: 2,
            search_max_file_bytes: 8,
            ..crate::config::Resources::default()
        };
        let tools = tools_with_resources(Arc::new(workspace), resources);
        let grep = tools.iter().find(|tool| tool.name() == "grep").unwrap();
        assert_eq!(
            grep.spec().function.parameters["properties"]["max_results"]["maximum"],
            2
        );
        let mut registry = crate::tools::Registry::new();
        for tool in tools {
            registry.register(tool);
        }

        let out = call(&registry, "grep", json!({"pattern": "hit", "path": "scan"}));
        assert_eq!(
            out.content,
            "scan/a.txt:1:hit\n[next cursor: 1; showing 1-1 of 2]\n\
             [skipped oversized files: scan/big.txt (larger than 8 bytes)]"
        );
        let out = call(
            &registry,
            "grep",
            json!({"pattern": "hit", "path": "scan", "max_results": 3}),
        );
        assert!(out.is_error() && out.content.contains("between 1 and 2"));
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn native_and_available_rg_backends_normalize_identically() {
        let Some(rg) = crate::tools::search::find_rg() else {
            return; // Absence is covered separately and means native-only operation.
        };
        let (base, root, workspace) = workspace("rg-equivalence");
        std::fs::create_dir_all(root.join("more")).unwrap();
        std::fs::write(root.join("a.txt"), "Needle one\nnone\nneedle two\n").unwrap();
        std::fs::write(root.join("more/b.txt"), "NEEDLE three\n").unwrap();
        let resources = crate::config::Resources::default();
        let filter = crate::tools::search::FileFilter::new(&[], &[], resources).unwrap();
        let files = walk(&workspace, &root, &filter).unwrap();
        let matcher =
            crate::tools::search::Matcher::new("needle (one|two|three)", true, true, resources)
                .unwrap();
        let mut native = crate::tools::search::Page::new(1, 2);
        for file in &files {
            let display = workspace.display(file);
            let bytes = read_search_file(file, &display, resources, &mut native)
                .unwrap()
                .unwrap();
            search_bytes(&matcher, &display, &bytes, &mut native);
        }
        let mut accelerated = crate::tools::search::Page::new(1, 2);
        assert!(crate::tools::search::rg_batch(
            &rg,
            workspace.root(),
            &files,
            "needle (one|two|three)",
            true,
            true,
            resources,
            &mut accelerated,
            None,
        ));
        assert_eq!(
            accelerated.render("needle").unwrap(),
            native.render("needle").unwrap()
        );
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn grep_stays_out_of_what_it_should_not_read() {
        let (base, root, registry) = tooled("grep-skip");
        for dir in SKIPPED {
            std::fs::create_dir_all(root.join(dir)).unwrap();
            std::fs::write(root.join(dir).join("f.txt"), "needle\n").unwrap();
        }
        std::fs::write(root.join("bin.dat"), b"\x00needle\n").unwrap();
        std::fs::write(root.join("bad.txt"), b"needle \xff\n").unwrap();
        std::fs::write(root.join("ok.txt"), "needle\n").unwrap();

        let out = call(&registry, "grep", json!({"pattern": "needle"}));
        assert_eq!(out.content, "bad.txt:1:needle �\nok.txt:1:needle");
        for dir in SKIPPED.into_iter().filter(|dir| *dir != ".gears") {
            let out = call(&registry, "grep", json!({"pattern": "needle", "path": dir}));
            assert_eq!(out.content, format!("{dir}/f.txt:1:needle"));
        }
        // And the symlink out of the workspace is not a way around it.
        assert_eq!(
            call(&registry, "grep", json!({"pattern": "s3cret"})).content,
            "no matches for 's3cret'"
        );
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn a_missing_root_is_refused() {
        let missing = std::env::temp_dir().join(format!("gears-no-root-{}", std::process::id()));
        assert!(Workspace::new(&missing).is_err());
    }
}
