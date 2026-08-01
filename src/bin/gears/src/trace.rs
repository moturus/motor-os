//! A small leveled file logger — an agent harness is undebuggable without a
//! wire log. No `log` crate. Secrets (API keys) must never reach the log:
//! callers register them with [`Tracer::redact`] / [`redact`] and every
//! message is scrubbed before it is written.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
}

impl Level {
    pub const NAMES: &str = "error, warn, info, debug";

    pub fn parse(name: &str) -> Option<Level> {
        match name {
            "error" => Some(Level::Error),
            "warn" => Some(Level::Warn),
            "info" => Some(Level::Info),
            "debug" => Some(Level::Debug),
            _ => None,
        }
    }

    fn tag(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
        }
    }
}

pub struct Tracer {
    file: Mutex<File>,
    level: Level,
    secrets: Mutex<Vec<String>>,
}

impl Tracer {
    /// Open `path` for appending.
    pub fn to_file(path: &Path, level: Level) -> std::io::Result<Tracer> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Tracer {
            file: Mutex::new(file),
            level,
            secrets: Mutex::new(Vec::new()),
        })
    }

    /// Register a secret: every logged message has it replaced with
    /// `[redacted]` from now on.
    pub fn redact(&self, secret: &str) {
        if !secret.is_empty() {
            self.secrets.lock().unwrap().push(secret.to_string());
        }
    }

    pub fn enabled(&self, level: Level) -> bool {
        level <= self.level
    }

    pub fn log(&self, level: Level, msg: &str) {
        if !self.enabled(level) {
            return;
        }
        let mut text = msg.to_string();
        for secret in self.secrets.lock().unwrap().iter() {
            text = text.replace(secret, "[redacted]");
        }
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        // A failed trace write must not take gears down.
        let _ = writeln!(
            self.file.lock().unwrap(),
            "[{}.{:03} {}] {}",
            ts.as_secs(),
            ts.subsec_millis(),
            level.tag(),
            text
        );
    }
}

// The process-global tracer. Absent (e.g. no --log-file) it makes every log
// call a cheap no-op.
static TRACER: OnceLock<Tracer> = OnceLock::new();

/// Install the global tracer. The first call wins; later calls are ignored.
pub fn init(tracer: Tracer) {
    let _ = TRACER.set(tracer);
}

pub fn redact(secret: &str) {
    if let Some(tracer) = TRACER.get() {
        tracer.redact(secret);
    }
}

pub fn log(level: Level, msg: &str) {
    if let Some(tracer) = TRACER.get() {
        tracer.log(level, msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("gears-trace-{tag}-{}.log", std::process::id()))
    }

    #[test]
    fn levels_parse_and_order() {
        assert_eq!(Level::parse("debug"), Some(Level::Debug));
        assert_eq!(Level::parse("verbose"), None);
        assert!(Level::Error < Level::Warn && Level::Info < Level::Debug);
    }

    #[test]
    fn filters_below_the_configured_level() {
        let path = temp_log("filter");
        let tracer = Tracer::to_file(&path, Level::Info).unwrap();
        tracer.log(Level::Warn, "kept");
        tracer.log(Level::Debug, "dropped");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(text.contains("WARN] kept"), "{text}");
        assert!(!text.contains("dropped"), "{text}");
    }

    #[test]
    fn registered_secrets_never_reach_the_file() {
        let path = temp_log("redact");
        let tracer = Tracer::to_file(&path, Level::Debug).unwrap();
        tracer.redact("sk-sekrit-123");
        tracer.log(Level::Info, "auth: Bearer sk-sekrit-123 sent");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(!text.contains("sekrit"), "{text}");
        assert!(text.contains("Bearer [redacted] sent"), "{text}");
    }

    // The one test touching the process-global tracer (OnceLock: first init
    // wins for the whole test process).
    #[test]
    fn global_face_logs_after_init() {
        log(Level::Error, "no tracer yet: a no-op");
        let path = temp_log("global");
        init(Tracer::to_file(&path, Level::Info).unwrap());
        redact("hunter2");
        log(Level::Info, "password is hunter2");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(text.contains("password is [redacted]"), "{text}");
    }
}
