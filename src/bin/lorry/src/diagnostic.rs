use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Usage,
    Failure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    help: Option<String>,
}

impl Error {
    pub fn usage(message: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Usage,
            message: message.into(),
            help: Some(help.into()),
        }
    }

    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Failure,
            message: message.into(),
            help: None,
        }
    }

    pub fn unsupported(subject: impl fmt::Display, stage: u8) -> Self {
        Self {
            kind: ErrorKind::Failure,
            message: format!("`{subject}` is not supported in Lorry Stage {stage}"),
            help: Some(format!(
                "remove `{subject}` or use a Lorry stage that supports it"
            )),
        }
    }

    #[cfg(test)]
    pub fn is_usage(&self) -> bool {
        self.kind == ErrorKind::Usage
    }

    pub fn exit_code(&self) -> i32 {
        match self.kind {
            ErrorKind::Usage => 1,
            ErrorKind::Failure => 101,
        }
    }

    pub fn render(&self) -> String {
        match &self.help {
            Some(help) => format!("error: {}\nhelp: {help}\n", self.message),
            None => format!("error: {}\n", self.message),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(formatter)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::failure(error.to_string())
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
}
