use std::fmt;
use std::io::{self, Write};
use std::time::Duration;

use crate::diagnostic::{Error, Result};
use crate::identity::CargoDebugInfo;
use crate::manifest::Profile;
use crate::resolver::{PackageKey, PackageSourceKey};

pub fn package_label(package: &PackageKey) -> String {
    let mut label = format!("{} v{}", package.name, package.version);
    match &package.source {
        PackageSourceKey::CratesIo => {}
        PackageSourceKey::Path(path) => label.push_str(&format!(" ({})", path.display())),
        PackageSourceKey::Git(source) => {
            let source = source.strip_prefix("git+").unwrap_or(source);
            // Cargo displays the Git URL and eight revision digits, never the
            // physical checkout path or Lorry's source digest.
            let source = source.rsplit_once('#').map_or_else(
                || source.to_owned(),
                |(url, revision)| format!("{url}#{:.8}", revision),
            );
            label.push_str(&format!(" ({source})"));
        }
    }
    label
}

#[derive(Clone, Copy)]
pub struct Progress {
    enabled: bool,
}

impl Progress {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    pub fn report(&self, message: impl fmt::Display) -> Result<()> {
        self.write_to(&mut io::stderr().lock(), message)
    }

    pub fn status(&self, color: bool, status: &str, message: impl fmt::Display) -> Result<()> {
        self.report(status_line(color, status, message))
    }

    pub fn finished(
        &self,
        color: bool,
        name: &str,
        profile: &Profile,
        elapsed: Duration,
    ) -> Result<()> {
        self.status(color, "Finished", finished_message(name, profile, elapsed))
    }

    fn write_to(&self, output: &mut impl Write, message: impl fmt::Display) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        writeln!(output, "{message}")
            .and_then(|()| output.flush())
            .map_err(|error| Error::failure(format!("failed to write progress: {error}")))
    }
}

fn status_line(color: bool, status: &str, message: impl fmt::Display) -> String {
    if color {
        // Use the same amber as Rush's Interactive prompt.
        format!("\x1b[1m\x1b[38;5;214m{status:>12}\x1b[0m {message}")
    } else {
        format!("{status:>12} {message}")
    }
}

fn finished_message(name: &str, profile: &Profile, elapsed: Duration) -> String {
    let optimization = if profile.opt_level == "0" {
        "unoptimized"
    } else {
        "optimized"
    };
    let debug = if profile.debug == Some(CargoDebugInfo::None) {
        ""
    } else {
        " + debuginfo"
    };
    let elapsed = if elapsed.as_secs() < 60 {
        format!("{:.2}s", elapsed.as_secs_f64())
    } else {
        format!("{}m {:02}s", elapsed.as_secs() / 60, elapsed.as_secs() % 60)
    };
    format!("`{name}` profile [{optimization}{debug}] target(s) in {elapsed}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_status_spacing_and_amber_color() {
        assert_eq!(
            status_line(false, "Compiling", "demo v1.0.0"),
            "   Compiling demo v1.0.0"
        );
        assert_eq!(
            status_line(true, "Compiling", "demo v1.0.0"),
            "\x1b[1m\x1b[38;5;214m   Compiling\x1b[0m demo v1.0.0"
        );
        assert_eq!(status_line(false, "Finished", "done"), "    Finished done");
    }

    #[test]
    fn cargo_package_sources() {
        let mut package = PackageKey {
            name: "demo".into(),
            version: "1.0.0".parse().unwrap(),
            source: PackageSourceKey::CratesIo,
        };
        assert_eq!(package_label(&package), "demo v1.0.0");
        package.source = PackageSourceKey::Path("/workspace/demo".into());
        assert_eq!(package_label(&package), "demo v1.0.0 (/workspace/demo)");
        package.source = PackageSourceKey::Git(
            "git+https://example.invalid/demo?branch=main#0123456789012345678901234567890123456789"
                .into(),
        );
        assert_eq!(
            package_label(&package),
            "demo v1.0.0 (https://example.invalid/demo?branch=main#01234567)"
        );
    }

    #[test]
    fn cargo_profile_and_elapsed_time() {
        for (name, opt_level, debug, elapsed, expected) in [
            (
                "dev",
                "0",
                CargoDebugInfo::Full,
                Duration::from_millis(1234),
                "`dev` profile [unoptimized + debuginfo] target(s) in 1.23s",
            ),
            (
                "release",
                "3",
                CargoDebugInfo::None,
                Duration::from_secs(60),
                "`release` profile [optimized] target(s) in 1m 00s",
            ),
            (
                "small",
                "z",
                CargoDebugInfo::Limited,
                Duration::from_secs(125),
                "`small` profile [optimized + debuginfo] target(s) in 2m 05s",
            ),
            (
                "plain",
                "0",
                CargoDebugInfo::None,
                Duration::ZERO,
                "`plain` profile [unoptimized] target(s) in 0.00s",
            ),
        ] {
            let profile = Profile {
                opt_level,
                debug: Some(debug),
                ..Profile::default()
            };
            assert_eq!(finished_message(name, &profile, elapsed), expected);
        }
    }

    struct Output {
        bytes: Vec<u8>,
        flushed: bool,
    }

    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushed = true;
            Ok(())
        }
    }

    #[test]
    fn enabled_progress_writes_and_flushes_each_line() {
        let mut output = Output {
            bytes: Vec::new(),
            flushed: false,
        };
        Progress::new(true)
            .write_to(&mut output, "Downloading demo v1.0.0")
            .unwrap();

        assert_eq!(output.bytes, b"Downloading demo v1.0.0\n");
        assert!(output.flushed);
    }

    #[test]
    fn disabled_progress_writes_nothing() {
        let mut output = Output {
            bytes: Vec::new(),
            flushed: false,
        };
        Progress::new(false)
            .write_to(&mut output, "hidden")
            .unwrap();

        assert!(output.bytes.is_empty());
        assert!(!output.flushed);
    }
}
