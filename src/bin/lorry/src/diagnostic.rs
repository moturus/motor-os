use std::fmt;
use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Usage,
    Failure,
    Interrupted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    help: Option<String>,
    location: Option<(PathBuf, usize)>,
    // Cargo's cache lacks what the command needs; see `cargo_registry`.
    cargo_cache_miss: bool,
}

impl Error {
    pub fn usage(message: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Usage,
            message: message.into(),
            help: Some(help.into()),
            location: None,
            cargo_cache_miss: false,
        }
    }

    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Failure,
            message: message.into(),
            help: None,
            location: None,
            cargo_cache_miss: false,
        }
    }

    pub fn interrupted(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Interrupted,
            message: message.into(),
            help: None,
            location: None,
            cargo_cache_miss: false,
        }
    }

    pub fn at(
        path: &Path,
        line: usize,
        message: impl fmt::Display,
        help: impl Into<String>,
    ) -> Self {
        Self {
            kind: ErrorKind::Failure,
            message: message.to_string(),
            help: Some(help.into()),
            location: Some((path.to_owned(), line)),
            cargo_cache_miss: false,
        }
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    /// Marks a failure that only means Cargo's cache lacks something.
    pub(crate) fn cargo_cache_miss(mut self) -> Self {
        self.cargo_cache_miss = true;
        self
    }

    pub(crate) fn is_cargo_cache_miss(&self) -> bool {
        self.cargo_cache_miss
    }

    pub(crate) fn with_context(mut self, context: &str) -> Self {
        self.message = format!("{context}: {}", self.message);
        self
    }

    #[cfg(test)]
    pub fn is_usage(&self) -> bool {
        self.kind == ErrorKind::Usage
    }

    pub fn exit_code(&self) -> i32 {
        match self.kind {
            ErrorKind::Usage => 1,
            ErrorKind::Failure => 101,
            ErrorKind::Interrupted => 130,
        }
    }

    pub fn render(&self) -> String {
        match &self.help {
            Some(help) => format!("error: {self}\nhelp: {help}\n"),
            None => format!("error: {self}\n"),
        }
    }

    pub fn render_json(&self) -> String {
        let kind = match self.kind {
            ErrorKind::Usage => "usage",
            ErrorKind::Failure => "failure",
            ErrorKind::Interrupted => "interrupted",
        };
        let message = serde_json::json!({
            "reason": "lorry-error",
            "kind": kind,
            "text": self.message,
            "file": self.location.as_ref().map(|(path, _)| path.display().to_string()),
            "line": self.location.as_ref().map(|(_, line)| *line),
            "help": self.help,
            "exit_code": self.exit_code(),
        });
        format!("{message}\n")
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(formatter)?;
        if let Some((path, line)) = &self.location {
            write!(formatter, "\n  --> {}:{line}", path.display())?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::Interrupted {
            Error::interrupted(error.to_string())
        } else {
            Error::failure(error.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_have_stable_prefixes_and_codes() {
        let usage = Error::usage("bad flag", "remove it");
        assert_eq!(usage.exit_code(), 1);
        assert_eq!(usage.render(), "error: bad flag\nhelp: remove it\n");

        let failure = Error::failure("compiler failed");
        assert_eq!(failure.exit_code(), 101);
        assert_eq!(failure.render(), "error: compiler failed\n");
    }

    #[test]
    fn json_errors_keep_locations_separate_and_escape_user_text() {
        let error = Error::at(
            Path::new("package/Cargo.toml"),
            7,
            "bad \"value\"\nnext",
            "fix it",
        );
        let json: serde_json::Value = serde_json::from_str(&error.render_json()).unwrap();
        assert_eq!(json["reason"], "lorry-error");
        assert_eq!(json["kind"], "failure");
        assert_eq!(json["text"], "bad \"value\"\nnext");
        assert_eq!(json["file"], "package/Cargo.toml");
        assert_eq!(json["line"], 7);
        assert_eq!(json["help"], "fix it");
        assert_eq!(json["exit_code"], 101);
        assert_eq!(error.render_json().lines().count(), 1);
        assert_eq!(
            error.render(),
            "error: bad \"value\"\nnext\n  --> package/Cargo.toml:7\nhelp: fix it\n"
        );
        let interrupted = Error::from(std::io::Error::from(std::io::ErrorKind::Interrupted));
        let json: serde_json::Value = serde_json::from_str(&interrupted.render_json()).unwrap();
        assert_eq!(json["kind"], "interrupted");
        assert_eq!(json["exit_code"], 130);
        assert!(json["file"].is_null());
        assert!(json["line"].is_null());
    }
}
