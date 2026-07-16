//! Editor configuration, read from a small TOML file at startup.
//!
//! Only the `key = value` subset of TOML is understood, which is all the config
//! file uses -- red has no dependencies, so there is no TOML crate behind this.
//! Option names mirror their vim equivalents.

use std::path::PathBuf;

/// Largest accepted `tabstop`. Rendering a tab pushes up to this many cells, so
/// a wild value is a rendering hazard rather than a preference.
const MAX_TABSTOP: usize = 32;

/// The options red reads from the config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Width of a tab character, in columns. Invariant: > 0, so that the
    /// renderer's `rx % tabstop` cannot divide by zero.
    pub tabstop: usize,
    /// Whether pressing Tab inserts spaces instead of a tab character.
    pub expandtab: bool,
}

impl Default for Config {
    /// The defaults, used when there is no config file. These match the file
    /// shipped at `/user/cfg/red.toml`.
    fn default() -> Self {
        Self {
            tabstop: 4,
            expandtab: true,
        }
    }
}

impl Config {
    /// Where the config file lives, or `None` on a platform we have no location
    /// for (red then runs with the defaults).
    pub fn path() -> Option<PathBuf> {
        // Motor OS sets no target family, so `unix` below is never true here;
        // the `not(motor)` guard just keeps the two arms exclusive if that ever
        // changes.
        #[cfg(target_os = "motor")]
        {
            Some(PathBuf::from("/user/cfg/red.toml"))
        }

        #[cfg(all(unix, not(target_os = "motor")))]
        {
            std::env::home_dir().map(|home| home.join(".config/red.toml"))
        }

        #[cfg(not(any(target_os = "motor", unix)))]
        {
            None
        }
    }

    /// Load the config file. Returns the config plus a message to show in the
    /// status bar, if anything was wrong with the file.
    ///
    /// A missing file is not a problem: red runs with the defaults.
    pub fn load() -> (Self, Option<String>) {
        let Some(path) = Self::path() else {
            return (Self::default(), None);
        };

        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let (config, complaint) = Self::parse(&text);
                (
                    config,
                    complaint.map(|c| format!("{}: {c}", path.display())),
                )
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Self::default(), None),
            Err(e) => (Self::default(), Some(format!("{}: {e}", path.display()))),
        }
    }

    /// Parse the config file's contents. Every well-formed entry is applied even
    /// if another entry is bad; the first thing wrong with the file is returned
    /// so the user hears about it instead of silently getting a default.
    pub fn parse(text: &str) -> (Self, Option<String>) {
        let mut config = Self::default();
        let mut complaint: Option<String> = None;
        let mut complain = |line_no: usize, msg: String| {
            if complaint.is_none() {
                complaint = Some(format!("line {line_no}: {msg}"));
            }
        };

        for (idx, raw_line) in text.lines().enumerate() {
            let line_no = idx + 1;
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }

            let Some((key, value)) = line.split_once('=') else {
                complain(line_no, format!("expected 'key = value', found '{line}'"));
                continue;
            };
            let (key, value) = (key.trim(), value.trim());

            match key {
                "tabstop" | "ts" => match value.parse::<usize>() {
                    Ok(0) => complain(line_no, "tabstop must be > 0".to_string()),
                    Ok(n) if n > MAX_TABSTOP => {
                        complain(line_no, format!("tabstop must be <= {MAX_TABSTOP}"))
                    }
                    Ok(n) => config.tabstop = n,
                    Err(_) => complain(line_no, format!("tabstop: not a number: '{value}'")),
                },
                "expandtab" | "et" => match value.parse::<bool>() {
                    Ok(b) => config.expandtab = b,
                    Err(_) => complain(line_no, format!("expandtab: not a boolean: '{value}'")),
                },
                _ => complain(line_no, format!("unknown option '{key}'")),
            }
        }

        (config, complaint)
    }
}

/// Drop a trailing `#` comment. No option takes a string value, so a `#`
/// anywhere outside a key or value starts a comment.
fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let config = Config::default();
        assert_eq!(config.tabstop, 4);
        assert!(config.expandtab);
    }

    #[test]
    fn test_empty_file_yields_defaults() {
        let (config, complaint) = Config::parse("");
        assert_eq!(config, Config::default());
        assert_eq!(complaint, None);
    }

    #[test]
    fn test_parses_shipped_config() {
        // The file shipped at /user/cfg/red.toml, comments and all.
        let (config, complaint) = Config::parse(
            "# Configuration file for the 'red' editor.\n\
             \n\
             # tabstop (ts): the width of a tab character, in spaces.\n\
             tabstop = 4\n\
             \n\
             # expandtab (et)\n\
             expandtab = true\n",
        );
        assert_eq!(complaint, None);
        assert_eq!(config.tabstop, 4);
        assert!(config.expandtab);
    }

    #[test]
    fn test_values_override_defaults() {
        let (config, complaint) = Config::parse("tabstop = 8\nexpandtab = false\n");
        assert_eq!(complaint, None);
        assert_eq!(config.tabstop, 8);
        assert!(!config.expandtab);
    }

    #[test]
    fn test_vim_short_names() {
        let (config, complaint) = Config::parse("ts = 2\net = false\n");
        assert_eq!(complaint, None);
        assert_eq!(config.tabstop, 2);
        assert!(!config.expandtab);
    }

    #[test]
    fn test_whitespace_and_trailing_comments() {
        let (config, complaint) = Config::parse("   tabstop=3   # inline comment\n\n\n");
        assert_eq!(complaint, None);
        assert_eq!(config.tabstop, 3);
    }

    #[test]
    fn test_zero_tabstop_rejected() {
        // A zero tabstop would divide by zero in the renderer.
        let (config, complaint) = Config::parse("tabstop = 0\n");
        assert_eq!(config.tabstop, Config::default().tabstop);
        assert!(complaint.unwrap().contains("must be > 0"));
    }

    #[test]
    fn test_huge_tabstop_rejected() {
        let (config, complaint) = Config::parse("tabstop = 100000\n");
        assert_eq!(config.tabstop, Config::default().tabstop);
        assert!(complaint.unwrap().contains("must be <="));
    }

    #[test]
    fn test_bad_values_rejected() {
        let (_, complaint) = Config::parse("tabstop = wide\n");
        assert!(complaint.unwrap().contains("not a number"));

        let (_, complaint) = Config::parse("expandtab = yes\n");
        assert!(complaint.unwrap().contains("not a boolean"));
    }

    #[test]
    fn test_unknown_option_reported() {
        let (_, complaint) = Config::parse("shiftwidth = 4\n");
        assert!(complaint.unwrap().contains("unknown option 'shiftwidth'"));
    }

    #[test]
    fn test_junk_line_reported() {
        let (_, complaint) = Config::parse("this is not toml\n");
        assert!(complaint.unwrap().contains("expected 'key = value'"));
    }

    #[test]
    fn test_good_entries_survive_a_bad_one() {
        // A bad line must not cost the user the rest of their config.
        let (config, complaint) = Config::parse("tabstop = nope\nexpandtab = false\n");
        assert_eq!(config.tabstop, Config::default().tabstop);
        assert!(!config.expandtab);
        assert!(complaint.unwrap().contains("line 1"));
    }

    #[test]
    fn test_first_complaint_wins() {
        let (_, complaint) = Config::parse("bogus = 1\nalso_bogus = 2\n");
        assert!(complaint.unwrap().contains("unknown option 'bogus'"));
    }
}
