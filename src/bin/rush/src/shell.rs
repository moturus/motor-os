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

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use crate::arith::ArithEnv;
use crate::ast::FunctionBody;

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
    /// `set -f`: pathname expansion (globbing) disabled. Wired to the `set`
    /// builtin in Phase 6; default off.
    pub noglob: bool,
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
            noglob: false,
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
    pub fn set(&mut self, name: &str, value: String) -> Result<(), String> {
        if self.readonly.contains(name) {
            return Err(format!("{name}: is read only"));
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
    #[allow(dead_code)]
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

    #[allow(dead_code)]
    pub fn set_readonly(&mut self, name: &str) {
        self.readonly.insert(name.to_string());
    }

    #[allow(dead_code)]
    pub fn unset(&mut self, name: &str) {
        self.vars.remove(name);
        // SAFETY: single-threaded control flow.
        unsafe { std::env::remove_var(name) };
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
            cwd: std::env::current_dir().ok(),
        }
    }

    pub fn restore(&mut self, snap: Snapshot) {
        self.vars = snap.vars;
        self.readonly = snap.readonly;
        self.functions = snap.functions;
        if let Some(cwd) = snap.cwd {
            let _ = std::env::set_current_dir(cwd);
        }
    }
}

pub struct Snapshot {
    vars: HashMap<String, String>,
    readonly: HashSet<String>,
    functions: HashMap<String, Rc<FunctionBody>>,
    cwd: Option<std::path::PathBuf>,
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
        sh.unset("EXP_ME");
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
