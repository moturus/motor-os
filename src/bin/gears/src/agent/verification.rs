//! Typed verification candidates and the exact workspace state they cover.

use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 1;
const MAX_ARGV: usize = 128;
const MAX_DIAGNOSTICS: usize = 4096;
const MAX_TEXT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Cargo,
    Lorry,
    Process,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub backend: Backend,
    /// The complete argument vector, including the program at index zero.
    pub argv: Vec<String>,
    /// Workspace-relative directory, with `.` denoting the workspace root.
    pub cwd: String,
    /// Where this candidate came from, such as `Cargo.toml` or project instructions.
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub task_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<u64>,
    pub mutation_generation: u64,
    /// Read old evidence records without retaining a core Git dependency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_revision: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ProcessEnd {
    Exited { status: String, success: bool },
    TimedOut,
    Cancelled,
    SpawnFailed,
    ExecutionFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Captured {
    pub candidate: Candidate,
    pub started_unix_millis: u64,
    pub ended_unix_millis: u64,
    pub end: ProcessEnd,
    pub diagnostics: Vec<Diagnostic>,
    pub raw_output: String,
    pub output_artifact: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
    Note,
    Help,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u64>,
    pub severity: Severity,
    pub message: String,
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Passed,
    Failed,
    Skipped,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub version: u32,
    pub id: u64,
    pub candidate: Candidate,
    pub scope: Scope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_unix_millis: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_unix_millis: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<ProcessEnd>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_artifact: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
}

impl Evidence {
    pub fn status(&self, current_mutation_generation: u64) -> Status {
        if self.scope.mutation_generation != current_mutation_generation {
            return Status::Stale;
        }
        match &self.end {
            Some(ProcessEnd::Exited { success: true, .. }) => Status::Passed,
            Some(_) => Status::Failed,
            None => Status::Skipped,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != VERSION || self.id == 0 {
            return Err("unsupported or invalid verification evidence version".to_string());
        }
        self.candidate.validate()?;
        self.scope.validate()?;
        if self.diagnostics.len() > MAX_DIAGNOSTICS {
            return Err("too many normalized diagnostics".to_string());
        }
        for diagnostic in &self.diagnostics {
            diagnostic.validate()?;
        }
        match (
            &self.started_unix_millis,
            &self.ended_unix_millis,
            &self.end,
        ) {
            (Some(started), Some(ended), Some(end))
                if *started > 0
                    && ended >= started
                    && self.output_artifact.is_some_and(|id| id > 0)
                    && self.skip_reason.is_none() =>
            {
                if let ProcessEnd::Exited { status, .. } = end {
                    valid_text(status, "process exit status")?;
                }
                Ok(())
            }
            (None, None, None)
                if self.output_artifact.is_none()
                    && self.diagnostics.is_empty()
                    && self.skip_reason.is_some() =>
            {
                valid_text(self.skip_reason.as_deref().unwrap(), "skip reason")
            }
            _ => Err("inconsistent verification result fields".to_string()),
        }
    }
}

impl Candidate {
    pub fn validate(&self) -> Result<(), String> {
        if self.argv.is_empty() || self.argv.len() > MAX_ARGV {
            return Err(format!("a check must have 1..={MAX_ARGV} arguments"));
        }
        for argument in &self.argv {
            valid_text(argument, "check argument")?;
        }
        valid_text(&self.cwd, "check cwd")?;
        valid_text(&self.source, "check source")
    }
}

impl Scope {
    pub fn validate(&self) -> Result<(), String> {
        if self.task_generation == 0 || self.checkpoint == Some(0) {
            return Err("invalid verification scope".to_string());
        }
        if let Some(revision) = &self.git_revision {
            valid_text(revision, "git revision")?;
        }
        Ok(())
    }
}

impl Diagnostic {
    fn validate(&self) -> Result<(), String> {
        if self.line == Some(0)
            || self.column == Some(0)
            || (self.line.is_none() && self.column.is_some())
        {
            return Err("invalid diagnostic position".to_string());
        }
        if let Some(path) = &self.path {
            valid_text(path, "diagnostic path")?;
        }
        valid_text(&self.message, "diagnostic message")?;
        valid_text(&self.source, "diagnostic source")
    }
}

fn valid_text(value: &str, what: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.contains('\0') {
        return Err(format!("invalid {what}"));
    }
    Ok(())
}

/// Normalize only compiler forms whose meaning is unambiguous. Everything
/// else remains available in the raw output artifact.
pub(crate) fn normalize_diagnostics(
    output: &str,
    source: &str,
    workspace: &crate::tools::Workspace,
    cwd: &str,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for line in output.lines() {
        if let Some((severity, message)) = diagnostic_heading(line) {
            if diagnostics.len() == MAX_DIAGNOSTICS {
                break;
            }
            diagnostics.push(Diagnostic {
                path: None,
                line: None,
                column: None,
                severity,
                message: bounded(message),
                source: bounded(source),
            });
            continue;
        }
        let Some(last) = diagnostics.last_mut() else {
            continue;
        };
        let Some((path, line, column)) = diagnostic_location(line) else {
            continue;
        };
        let asked = std::path::Path::new(cwd).join(path);
        let Some(asked) = asked.to_str() else {
            continue;
        };
        let Ok(resolved) = workspace.resolve(asked) else {
            continue;
        };
        if resolved.is_file() {
            last.path = Some(workspace.display(&resolved));
            last.line = Some(line);
            last.column = Some(column);
        }
    }
    diagnostics
}

fn diagnostic_heading(line: &str) -> Option<(Severity, &str)> {
    let line = line.trim_start();
    for (prefix, severity) in [
        ("warning: ", Severity::Warning),
        ("note: ", Severity::Note),
        ("help: ", Severity::Help),
        ("= note: ", Severity::Note),
        ("= help: ", Severity::Help),
    ] {
        if let Some(message) = line.strip_prefix(prefix) {
            return (!message.is_empty()).then_some((severity, message));
        }
    }
    let error = line.strip_prefix("error")?;
    let message = match error.strip_prefix(": ") {
        Some(message) => message,
        None if error.starts_with('[') => error.split_once("]: ")?.1,
        None => return None,
    };
    (!message.is_empty()).then_some((Severity::Error, message))
}

fn diagnostic_location(line: &str) -> Option<(&str, u64, u64)> {
    let location = line.trim_start().strip_prefix("--> ")?;
    let (path_and_line, column) = location.rsplit_once(':')?;
    let (path, line) = path_and_line.rsplit_once(':')?;
    let line = line.parse().ok().filter(|value| *value > 0)?;
    let column = column.parse().ok().filter(|value| *value > 0)?;
    (!path.is_empty()).then_some((path, line, column))
}

fn bounded(value: &str) -> String {
    if value.len() <= MAX_TEXT_BYTES {
        return value.to_string();
    }
    let mut end = MAX_TEXT_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(end: Option<ProcessEnd>) -> Evidence {
        let ran = end.is_some();
        Evidence {
            version: VERSION,
            id: 1,
            candidate: Candidate {
                backend: Backend::Cargo,
                argv: vec!["cargo".into(), "test".into(), "--offline".into()],
                cwd: ".".into(),
                source: "Cargo.toml".into(),
            },
            scope: Scope {
                task_generation: 4,
                checkpoint: Some(2),
                mutation_generation: 3,
                git_revision: Some("abc123".into()),
            },
            started_unix_millis: ran.then_some(10),
            ended_unix_millis: ran.then_some(12),
            end,
            output_artifact: ran.then_some(7),
            skip_reason: (!ran).then(|| "documentation-only change".into()),
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn status_is_derived_from_recorded_facts_and_workspace_generation() {
        let passed = evidence(Some(ProcessEnd::Exited {
            status: "exit status 0".into(),
            success: true,
        }));
        assert_eq!(passed.status(3), Status::Passed);
        assert_eq!(passed.status(4), Status::Stale);
        assert_eq!(
            evidence(Some(ProcessEnd::TimedOut)).status(3),
            Status::Failed
        );
        assert_eq!(evidence(None).status(3), Status::Skipped);
    }

    #[test]
    fn evidence_requires_an_exact_run_or_an_explicit_skip() {
        let mut ran = evidence(Some(ProcessEnd::Cancelled));
        ran.validate().unwrap();
        ran.output_artifact = None;
        assert!(ran.validate().is_err());

        let mut skipped = evidence(None);
        skipped.validate().unwrap();
        skipped.started_unix_millis = Some(10);
        assert!(skipped.validate().is_err());
    }

    #[test]
    fn compiler_diagnostics_are_typed_only_for_confined_existing_paths() {
        let root = std::env::temp_dir().join(format!(
            "gears-verification-diagnostics-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("crate/src")).unwrap();
        std::fs::write(root.join("crate/src/lib.rs"), "fn broken() {}\n").unwrap();
        let workspace = crate::tools::Workspace::new(&root).unwrap();
        let output = concat!(
            "error[E0425]: cannot find value `missing`\n",
            "  --> src/lib.rs:1:4\n",
            "warning: still useful\n",
            "  --> ../outside.rs:2:3\n",
            "not a diagnostic\n",
        );

        let diagnostics = normalize_diagnostics(output, "cargo", &workspace, "crate");
        assert_eq!(diagnostics.len(), 2);
        assert_eq!(diagnostics[0].severity, Severity::Error);
        assert_eq!(diagnostics[0].path.as_deref(), Some("crate/src/lib.rs"));
        assert_eq!(
            (diagnostics[0].line, diagnostics[0].column),
            (Some(1), Some(4))
        );
        assert_eq!(diagnostics[1].severity, Severity::Warning);
        assert!(diagnostics[1].path.is_none());
        std::fs::remove_dir_all(root).unwrap();
    }
}
