//! Foreground-command titles for an interactive Rush inside rmux.

use std::io::Write;
use std::path::Path;

use crate::shell::Shell;

const RMUX_PANE_ENV_KEY: &str = "RMUX_PANE";
const MAX_TITLE_CHARS: usize = 64;

/// Restores the shell's title whenever a foreground execution path returns.
pub struct ForegroundTitle {
    idle: Option<String>,
}

impl ForegroundTitle {
    pub fn new(program: &str, shell: &Shell) -> Self {
        if !shell.is_interactive() || shell.get(RMUX_PANE_ENV_KEY).as_deref() != Some("1") {
            return Self { idle: None };
        }

        let idle = display_name(shell.name());
        write_title(&display_name(program));
        Self { idle: Some(idle) }
    }
}

impl Drop for ForegroundTitle {
    fn drop(&mut self) {
        if let Some(idle) = &self.idle {
            write_title(idle);
        }
    }
}

/// Reduce a resolved executable path to a bounded title that cannot terminate
/// the OSC string and inject terminal controls of its own.
fn display_name(program: &str) -> String {
    let basename = Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(program)
        .trim_start_matches('-');
    let title: String = basename
        .chars()
        .take(MAX_TITLE_CHARS)
        .map(|ch| if ch.is_control() { '?' } else { ch })
        .collect();
    if title.is_empty() {
        "rush".to_owned()
    } else {
        title
    }
}

fn write_title(title: &str) {
    let mut out = std::io::stdout().lock();
    let _ = write!(out, "\x1b]2;{title}\x07");
    let _ = out.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names_are_basenames_without_terminal_controls() {
        assert_eq!(display_name("/system/bin/sleep"), "sleep");
        assert_eq!(display_name("-rush"), "rush");
        assert_eq!(display_name("/tmp/\x1b]2;owned\x07"), "?]2;owned?");
        assert_eq!(display_name(&"x".repeat(80)), "x".repeat(MAX_TITLE_CHARS));
    }
}
