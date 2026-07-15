//! Shell state (Phase 3): variables, positional parameters, and `$?`.
//!
//! Exported variables live in the real process environment (`std::env`), so
//! children inherit them and `PATH`-based command resolution works for free;
//! non-exported shell variables live in a side map that shadows the
//! environment. Assigning to a name that is already exported keeps it exported
//! (POSIX §2.5.3); a brand-new bare assignment creates an unexported shell
//! variable. `readonly` names reject assignment.
//!
//! The struct also implements [`arith::ArithEnv`] so `$(( … ))` reads and
//! writes shell variables directly.
//!
//! Phase 4 adds shell functions and a [`Flow`] signal: `break`/`continue`/
//! `return` set a pending flow that the executor propagates up through lists and
//! loops (loops decrement `break n`/`continue n`, functions absorb `return`).
//!
//! Phase 6 adds the [`Options`] set (`set -e`/`-u`/`-x`/…), which the executor
//! and the expansion engine consult, and the `-e` suppression depth that marks
//! condition contexts where a failure must not exit the shell.
//!
//! Phase 7 adds the background [`Jobs`] table (backing `$!`, `wait` and `jobs`)
//! and gives the stored traps real teeth — see [`crate::signal`].

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use crate::arith::ArithEnv;
use crate::ast::FunctionBody;
use crate::jobs::Jobs;
use crate::options::{Opt, Options};

/// A pending non-local control-flow transfer, set by the `break`/`continue`/
/// `return` builtins and consumed by the executor. `Normal` means ordinary
/// sequential flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Normal,
    /// `break n`: stop the innermost `n` enclosing loops.
    Break(u32),
    /// `continue n`: resume the `n`-th enclosing loop's next iteration.
    Continue(u32),
    /// `return n`: leave the current function (or sourced script) with status `n`.
    Return(i32),
}

pub struct Shell {
    /// Unexported shell variables; these shadow the process environment.
    vars: HashMap<String, String>,
    /// Names that reject assignment.
    readonly: HashSet<String>,
    /// Defined shell functions, by name. Stored behind `Rc` so a call can clone
    /// the handle out and execute the body while the shell is mutably borrowed.
    functions: HashMap<String, Rc<FunctionBody>>,
    /// Positional parameters `$1`, `$2`, … (index 0 is `$1`).
    params: Vec<String>,
    /// `$0` — the shell or script name.
    name: String,
    /// `$?` — the status of the most recently executed command.
    status: i32,
    /// `$$` — the shell's process id, fixed for the shell's lifetime. `u64`
    /// because Motor OS pids do not fit in `u32`.
    pid: u64,
    /// Pending control-flow transfer (`break`/`continue`/`return`).
    flow: Flow,
    /// Number of lexically enclosing loops currently executing. `break`/
    /// `continue` are no-ops when this is 0 (matching dash), and it resets across
    /// a function-call boundary.
    loop_depth: u32,
    /// Shell options (`set -e`, `-u`, `-x`, …) — see [`crate::options`].
    pub opts: Options,
    /// Nesting depth of contexts where `set -e` must be ignored: the condition
    /// of an `if`/`while`/`until`, a non-final operand of an `&&`/`||` list, and
    /// a `!`-negated pipeline (POSIX §2.8.1). A counter rather than a flag
    /// because those contexts nest, and it propagates naturally into function
    /// calls (which run in-process).
    errexit_suppress: u32,
    /// Command aliases (`alias name=value`), expanded in command position.
    aliases: HashMap<String, String>,
    /// `getopts` internal cursor: the 1-based index of the character within the
    /// current argument still to be scanned (0 = start of a fresh argument).
    /// Companion to the `OPTIND` shell variable.
    getopts_char: usize,
    /// File-creation mask, tracked by the `umask` builtin. Motor OS `std` exposes
    /// no `umask` syscall, so this is display/bookkeeping only for now and does
    /// not affect the mode of files the shell creates.
    umask: u32,
    /// Traps set by the `trap` builtin, keyed by canonical condition name
    /// (`EXIT`, `INT`, …) — the key [`crate::signal::condition_name`] produces,
    /// so `trap 'x' 2` and `trap 'x' SIGINT` are the same entry. An empty action
    /// means "ignore". [`crate::signal`] dispatches them.
    traps: HashMap<String, String>,
    /// The subshell depth at which the `EXIT` trap was set — see
    /// [`Shell::exit_trap_set_here`].
    exit_trap_depth: u32,
    /// Background jobs (`&`), backing `$!`, `wait`, `jobs` and `kill %n`.
    pub jobs: Jobs,
    /// Whether this is an interactive shell. A *non-interactive* shell exits on a
    /// special-builtin usage/assignment error (POSIX §2.8.1); an interactive one
    /// reports and continues.
    interactive: bool,
    /// A pending fatal error (a special-builtin usage/assignment error), carrying
    /// the exit status. Set by the offending builtin/assignment and consumed by
    /// the executor, which exits a non-interactive shell.
    fatal: Option<i32>,
    /// Status of the most recent command substitution performed while expanding
    /// the current command; `None` if it performed none. See
    /// [`Shell::cmdsub_status`].
    cmdsub_status: Option<i32>,
    /// Depth of emulated subshells (`$(…)`, `( … )`, pipeline stages) currently
    /// executing. A fatal error inside one must not take down the whole shell
    /// (there is no `fork`), so the fatal-exit is suppressed when this is > 0.
    subshell_depth: u32,
}

impl Shell {
    pub fn new() -> Self {
        Self {
            vars: HashMap::new(),
            readonly: HashSet::new(),
            functions: HashMap::new(),
            params: Vec::new(),
            name: "rush".to_string(),
            status: 0,
            pid: crate::sys::pid(),
            flow: Flow::Normal,
            loop_depth: 0,
            opts: Options::new(),
            errexit_suppress: 0,
            aliases: HashMap::new(),
            getopts_char: 0,
            umask: 0o022,
            traps: HashMap::new(),
            exit_trap_depth: 0,
            jobs: Jobs::new(),
            interactive: false,
            fatal: None,
            cmdsub_status: None,
            subshell_depth: 0,
        }
    }

    /// Establish the variables POSIX expects a shell to maintain: `PWD` (and
    /// `OLDPWD`, which `cd` needs), and the `PS1`/`PS2`/`PS4` prompts. Existing
    /// (inherited) values win, so `PS1=… rush` and a `PWD` from the parent
    /// survive. Call once, at startup.
    pub fn init_environment(&mut self) {
        // An inherited `PWD` is only trustworthy if it still names the cwd: a
        // parent that chdir'd without updating it would otherwise mislead
        // every relative path `cd` computes.
        let pwd_ok = std::env::var("PWD").is_ok_and(|p| {
            std::path::Path::new(&p).is_absolute()
                && std::fs::canonicalize(&p).ok() == std::env::current_dir().ok()
        });
        if !pwd_ok && let Ok(cwd) = std::env::current_dir() {
            let _ = self.export("PWD", Some(cwd.to_string_lossy().into_owned()));
        }
        for name in ["PS1", "PS2", "PS4"] {
            if self.get(name).is_none() {
                // Inserted directly rather than via `set`: these are the shell's
                // own defaults, not a user assignment, so `set -a` must not
                // export them to children (as in dash). Safe because `get`
                // above proved the name is unset, so nothing is being shadowed.
                self.vars
                    .insert(name.to_string(), default_prompt(name).to_string());
            }
        }
    }

    // ---- ordinary variables ------------------------------------------------

    /// The value of a variable: a shell variable shadows an exported one, which
    /// falls through to the process environment. `None` if unset.
    pub fn get(&self, name: &str) -> Option<String> {
        if let Some(v) = self.vars.get(name) {
            return Some(v.clone());
        }
        std::env::var(name).ok()
    }

    // `export`, `unset`, `set_readonly`, and `is_set` are the variable API the
    // `export`/`readonly`/`unset` builtins will use in Phase 5 (already covered
    // by unit tests here).
    #[allow(dead_code)]
    pub fn is_set(&self, name: &str) -> bool {
        self.vars.contains_key(name) || std::env::var_os(name).is_some()
    }

    /// Assign a value, preserving export status. Errors if the name is readonly.
    ///
    /// Under `set -a` (allexport) an assignment also exports the name, which is
    /// why this — rather than each caller — is the single assignment funnel.
    pub fn set(&mut self, name: &str, value: String) -> Result<(), String> {
        if self.readonly.contains(name) {
            return Err(format!("{name}: is read only"));
        }
        if self.opts.get(Opt::AllExport) {
            return self.export(name, Some(value));
        }
        if std::env::var_os(name).is_some() {
            // Already exported: keep it in the environment.
            // SAFETY: the shell is single-threaded control flow.
            unsafe { std::env::set_var(name, &value) };
        } else {
            self.vars.insert(name.to_string(), value);
        }
        Ok(())
    }

    /// Mark a variable exported (moving any shell-local value into the
    /// environment). With `value`, assign it too.
    pub fn export(&mut self, name: &str, value: Option<String>) -> Result<(), String> {
        if self.readonly.contains(name) && value.is_some() {
            return Err(format!("{name}: is read only"));
        }
        let v = value
            .or_else(|| self.vars.get(name).cloned())
            .or_else(|| std::env::var(name).ok())
            .unwrap_or_default();
        self.vars.remove(name);
        // SAFETY: single-threaded control flow.
        unsafe { std::env::set_var(name, v) };
        Ok(())
    }

    pub fn set_readonly(&mut self, name: &str) {
        self.readonly.insert(name.to_string());
    }

    /// Remove a variable. Returns an error (without unsetting) if it is readonly.
    pub fn unset(&mut self, name: &str) -> Result<(), String> {
        if self.readonly.contains(name) {
            return Err(format!("{name}: is read only"));
        }
        self.vars.remove(name);
        // SAFETY: single-threaded control flow.
        unsafe { std::env::remove_var(name) };
        Ok(())
    }

    /// Every variable name→value pair currently visible: unexported shell
    /// variables plus the process environment (the shell value wins), sorted by
    /// name. Backs the no-operand `set` and `readonly -p` listings.
    pub fn vars_sorted(&self) -> Vec<(String, String)> {
        let mut map: std::collections::BTreeMap<String, String> = std::env::vars().collect();
        for (k, v) in &self.vars {
            map.insert(k.clone(), v.clone());
        }
        map.into_iter().collect()
    }

    /// Whether a name is currently exported (lives in the process environment).
    pub fn is_exported(&self, name: &str) -> bool {
        !self.vars.contains_key(name) && std::env::var_os(name).is_some()
    }

    /// Sorted names of the readonly-marked variables.
    pub fn readonly_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.readonly.iter().cloned().collect();
        v.sort();
        v
    }

    /// `IFS`, or the POSIX default (space, tab, newline) when unset.
    pub fn ifs(&self) -> String {
        self.get("IFS").unwrap_or_else(|| " \t\n".to_string())
    }

    // ---- functions ---------------------------------------------------------

    /// Define (or redefine) a shell function.
    pub fn define_function(&mut self, name: &str, body: Rc<FunctionBody>) {
        self.functions.insert(name.to_string(), body);
    }

    /// The function named `name`, if defined. Returns a cloned handle so the
    /// body can be executed while `self` is mutably borrowed.
    pub fn get_function(&self, name: &str) -> Option<Rc<FunctionBody>> {
        self.functions.get(name).cloned()
    }

    /// Remove a function definition; returns whether it existed.
    pub fn unset_function(&mut self, name: &str) -> bool {
        self.functions.remove(name).is_some()
    }

    // ---- aliases -----------------------------------------------------------

    pub fn set_alias(&mut self, name: &str, value: String) {
        self.aliases.insert(name.to_string(), value);
    }

    pub fn get_alias(&self, name: &str) -> Option<&str> {
        self.aliases.get(name).map(String::as_str)
    }

    /// Remove an alias; returns whether it existed.
    pub fn unset_alias(&mut self, name: &str) -> bool {
        self.aliases.remove(name).is_some()
    }

    /// All aliases as (name, value) pairs, sorted by name (for `alias` listing).
    pub fn aliases_sorted(&self) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = self
            .aliases
            .iter()
            .map(|(k, val)| (k.clone(), val.clone()))
            .collect();
        v.sort();
        v
    }

    // ---- getopts state -----------------------------------------------------

    pub fn getopts_char(&self) -> usize {
        self.getopts_char
    }

    pub fn set_getopts_char(&mut self, pos: usize) {
        self.getopts_char = pos;
    }

    // ---- umask -------------------------------------------------------------

    pub fn umask(&self) -> u32 {
        self.umask
    }

    pub fn set_umask(&mut self, mask: u32) {
        self.umask = mask;
    }

    // ---- interactivity & fatal errors --------------------------------------

    pub fn set_interactive(&mut self, yes: bool) {
        self.interactive = yes;
        // `$-` reports interactivity via the `i` option; keep the two in step so
        // there is only one answer to "is this shell interactive".
        self.opts.set(Opt::Interactive, yes);
    }

    pub fn is_interactive(&self) -> bool {
        self.interactive
    }

    // ---- `set -e` suppression ----------------------------------------------

    /// Enter a context where a failing command must not trigger `set -e`
    /// (an `if`/`while`/`until` condition, a non-final `&&`/`||` operand, a
    /// `!`-negated pipeline). Pair with [`Shell::exit_condition`].
    pub fn enter_condition(&mut self) {
        self.errexit_suppress += 1;
    }

    pub fn exit_condition(&mut self) {
        self.errexit_suppress = self.errexit_suppress.saturating_sub(1);
    }

    /// Whether a non-zero status here should exit the shell: `set -e` is on and
    /// we are not inside a condition context.
    pub fn errexit_applies(&self) -> bool {
        self.opts.get(Opt::ErrExit) && self.errexit_suppress == 0
    }

    /// Flag a fatal special-builtin usage/assignment error with its exit status.
    pub fn mark_fatal(&mut self, status: i32) {
        self.fatal = Some(status);
    }

    /// Consume any pending fatal error.
    pub fn take_fatal(&mut self) -> Option<i32> {
        self.fatal.take()
    }

    /// Whether a fatal error is flagged but not yet consumed. Lets the executor
    /// abandon a command whose *expansion* failed (`set -u`, `${x?}`) before
    /// running it.
    pub fn fatal_pending(&self) -> bool {
        self.fatal.is_some()
    }

    // ---- command-substitution status ---------------------------------------

    /// The status of the most recent command substitution, if one has run since
    /// [`Shell::clear_cmdsub_status`]. POSIX gives a command with no name but a
    /// substitution (`x=$(false)`) that substitution's status.
    pub fn cmdsub_status(&self) -> Option<i32> {
        self.cmdsub_status
    }

    pub fn clear_cmdsub_status(&mut self) {
        self.cmdsub_status = None;
    }

    pub fn set_cmdsub_status(&mut self, status: i32) {
        self.cmdsub_status = Some(status);
    }

    pub fn enter_subshell(&mut self) {
        self.subshell_depth += 1;
    }

    pub fn exit_subshell(&mut self) {
        self.subshell_depth = self.subshell_depth.saturating_sub(1);
    }

    pub fn in_subshell(&self) -> bool {
        self.subshell_depth > 0
    }

    // ---- traps -------------------------------------------------------------

    pub fn set_trap(&mut self, cond: &str, action: String) {
        if cond == "EXIT" {
            // Remember where this one was set, so a subshell can tell its own
            // `EXIT` trap from the parent's — see [`Shell::exit_trap_set_here`].
            self.exit_trap_depth = self.subshell_depth;
        }
        self.traps.insert(cond.to_string(), action);
    }

    pub fn clear_trap(&mut self, cond: &str) {
        self.traps.remove(cond);
    }

    /// Whether the current `EXIT` trap was set at the current subshell depth,
    /// rather than inherited from an enclosing one.
    ///
    /// POSIX gives a subshell a copy of its parent's traps, but that copy is the
    /// *parent's* obligation: `trap 'x' EXIT; (true)` runs `x` when the shell
    /// exits, not when the subshell ends, while `(trap 'x' EXIT; true)` runs it
    /// at the subshell's end (both verified against dash). A real `fork` gets
    /// this for free — the child's copy dies with it — so the emulated subshell
    /// has to remember which one it is holding.
    pub fn exit_trap_set_here(&self) -> bool {
        self.traps.contains_key("EXIT") && self.exit_trap_depth == self.subshell_depth
    }

    pub fn get_trap(&self, cond: &str) -> Option<&str> {
        self.traps.get(cond).map(String::as_str)
    }

    /// All traps as (condition, action) pairs, sorted by condition.
    pub fn traps_sorted(&self) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = self
            .traps
            .iter()
            .map(|(k, val)| (k.clone(), val.clone()))
            .collect();
        v.sort();
        v
    }

    // ---- control flow (break / continue / return) --------------------------

    pub fn flow(&self) -> Flow {
        self.flow
    }

    pub fn set_flow(&mut self, flow: Flow) {
        self.flow = flow;
    }

    pub fn clear_flow(&mut self) {
        self.flow = Flow::Normal;
    }

    /// Whether a `break`/`continue` currently has an enclosing loop to act on.
    pub fn in_loop(&self) -> bool {
        self.loop_depth > 0
    }

    pub fn enter_loop(&mut self) {
        self.loop_depth += 1;
    }

    pub fn exit_loop(&mut self) {
        self.loop_depth = self.loop_depth.saturating_sub(1);
    }

    /// Save-and-reset the loop nesting for a function call (a function's
    /// `break`/`continue` only see loops defined within it); pair with
    /// [`Shell::set_loop_depth`] to restore.
    pub fn take_loop_depth(&mut self) -> u32 {
        std::mem::take(&mut self.loop_depth)
    }

    pub fn set_loop_depth(&mut self, depth: u32) {
        self.loop_depth = depth;
    }

    // ---- positional & special parameters -----------------------------------

    pub fn set_params(&mut self, params: Vec<String>) {
        self.params = params;
    }

    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    pub fn params(&self) -> &[String] {
        &self.params
    }

    pub fn param_count(&self) -> usize {
        self.params.len()
    }

    /// A positional parameter `$n` (1-based), or `None` if out of range.
    pub fn positional(&self, n: usize) -> Option<&str> {
        if n == 0 {
            Some(self.name.as_str())
        } else {
            self.params.get(n - 1).map(String::as_str)
        }
    }

    #[allow(dead_code)]
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn status(&self) -> i32 {
        self.status
    }

    pub fn set_status(&mut self, status: i32) {
        self.status = status;
    }

    pub fn pid(&self) -> u64 {
        self.pid
    }

    // ---- subshell isolation (command substitution) -------------------------

    /// Capture the mutable shell state that a subshell must not leak back into
    /// the parent: shell variables, functions, and the working directory.
    /// Exported-variable mutations inside a subshell may still leak (a documented
    /// Phase 3 limit).
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            vars: self.vars.clone(),
            readonly: self.readonly.clone(),
            functions: self.functions.clone(),
            aliases: self.aliases.clone(),
            traps: self.traps.clone(),
            exit_trap_depth: self.exit_trap_depth,
            // A subshell's `set -e`/`set -f`/… must not leak out: `(set -f)`
            // leaves the parent's `$-` alone.
            opts: self.opts,
            cwd: std::env::current_dir().ok(),
            // `PWD`/`OLDPWD` are exported (they live in the environment), so the
            // generic var restore would miss them; capture and restore them with
            // the working directory so a subshell `cd` cannot leak.
            pwd: std::env::var("PWD").ok(),
            oldpwd: std::env::var("OLDPWD").ok(),
        }
    }

    pub fn restore(&mut self, snap: Snapshot) {
        self.vars = snap.vars;
        self.readonly = snap.readonly;
        self.functions = snap.functions;
        self.aliases = snap.aliases;
        self.traps = snap.traps;
        self.exit_trap_depth = snap.exit_trap_depth;
        self.opts = snap.opts;
        if let Some(cwd) = snap.cwd {
            let _ = std::env::set_current_dir(cwd);
        }
        restore_env("PWD", snap.pwd);
        restore_env("OLDPWD", snap.oldpwd);
    }
}

/// The default value of a prompt variable.
///
/// `PS2`/`PS4` match dash. `PS1` deliberately does not: rush keeps its colored
/// `rush:<cwd>$ ` prompt (dash's is a bare `$ `). It is an ordinary variable
/// holding ordinary ANSI escapes, so `PS1='$ '` gets dash's prompt back, and
/// `$PWD` in it tracks the working directory through the normal expansion the
/// prompt already undergoes.
pub fn default_prompt(name: &str) -> &'static str {
    match name {
        "PS1" => "\x1b[1;32mrush\x1b[0m:\x1b[1;34m$PWD\x1b[0m$ ",
        "PS2" => "> ",
        "PS4" => "+ ",
        _ => "",
    }
}

/// Set or remove an environment variable to match a captured value.
fn restore_env(name: &str, value: Option<String>) {
    // SAFETY: single-threaded control flow.
    unsafe {
        match value {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        }
    }
}

pub struct Snapshot {
    vars: HashMap<String, String>,
    readonly: HashSet<String>,
    functions: HashMap<String, Rc<FunctionBody>>,
    aliases: HashMap<String, String>,
    traps: HashMap<String, String>,
    exit_trap_depth: u32,
    opts: Options,
    cwd: Option<std::path::PathBuf>,
    pwd: Option<String>,
    oldpwd: Option<String>,
}

impl ArithEnv for Shell {
    fn get(&self, name: &str) -> Option<String> {
        Shell::get(self, name)
    }
    fn set(&mut self, name: &str, value: i64) {
        // Arithmetic assignment silently no-ops on a readonly variable.
        let _ = Shell::set(self, name, value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::Shell;

    #[test]
    fn set_and_get_shell_var() {
        let mut sh = Shell::new();
        assert_eq!(sh.get("FOO"), None);
        sh.set("FOO", "bar".into()).unwrap();
        assert_eq!(sh.get("FOO").as_deref(), Some("bar"));
        assert!(sh.is_set("FOO"));
        // A bare shell variable is NOT exported to the environment.
        assert!(std::env::var_os("FOO").is_none());
    }

    #[test]
    fn export_reaches_the_environment() {
        let mut sh = Shell::new();
        sh.set("EXP_ME", "1".into()).unwrap();
        assert!(std::env::var_os("EXP_ME").is_none());
        sh.export("EXP_ME", None).unwrap();
        assert_eq!(std::env::var("EXP_ME").as_deref(), Ok("1"));
        // Reassigning an exported var keeps it in the environment.
        sh.set("EXP_ME", "2".into()).unwrap();
        assert_eq!(std::env::var("EXP_ME").as_deref(), Ok("2"));
        sh.unset("EXP_ME").unwrap();
        assert!(std::env::var_os("EXP_ME").is_none());
    }

    #[test]
    fn readonly_rejects_assignment() {
        let mut sh = Shell::new();
        sh.set("RO", "x".into()).unwrap();
        sh.set_readonly("RO");
        assert!(sh.set("RO", "y".into()).is_err());
        assert_eq!(sh.get("RO").as_deref(), Some("x"));
    }

    #[test]
    fn positional_parameters() {
        let mut sh = Shell::new();
        sh.set_name("script".into());
        sh.set_params(vec!["a".into(), "b".into(), "c".into()]);
        assert_eq!(sh.positional(0), Some("script"));
        assert_eq!(sh.positional(1), Some("a"));
        assert_eq!(sh.positional(3), Some("c"));
        assert_eq!(sh.positional(4), None);
        assert_eq!(sh.param_count(), 3);
    }

    #[test]
    fn ifs_defaults() {
        let mut sh = Shell::new();
        assert_eq!(sh.ifs(), " \t\n");
        sh.set("IFS", ":".into()).unwrap();
        assert_eq!(sh.ifs(), ":");
    }
}
