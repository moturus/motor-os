//! `rmux.toml`: what a user changes, on top of what is compiled in.
//!
//! The defaults are `~/.tmux.conf` itself, compiled in as `bindings::defaults`
//! and the values below (details.md §2.1). **rmux never parses tmux's
//! configuration language** — no `bind`/`unbind`/`set -g` grammar, no
//! `if-shell`, no sourcing. This file only overrides.
//!
//! Only the `key = value` subset of TOML is understood, plus `#` comments and
//! the three binding tables (§2.2). rmux has no dependencies, so there is no
//! TOML crate behind this, and the same restraint red documents applies here.
//!
//! Two rules that matter more than they look:
//!
//! - **A malformed entry is skipped and reported; the rest of the file still
//!   applies.** A typo in one binding must not cost a user their config.
//! - **Config is injected, not loaded** by the server core, per red's rationale
//!   (`red/src/editor.rs:121-124`): construction does no file I/O, so tests
//!   "are not at the mercy of the config file on the machine running them"
//!   (§9.3). [`Config::load`] is the only thing here that touches a disk, and
//!   nothing calls it but `main`.

use crate::bindings::Bindings;
use crate::bindings::Command;
use crate::bindings::ModeKeys;
use crate::bindings::Table;
use crate::keys::Key;

#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;

fn native_shell() -> &'static str {
    #[cfg(target_os = "linux")]
    if let Some(path) = std::env::var_os("PATH") {
        let bash_available = std::env::split_paths(&path).any(|dir| {
            dir.join("bash").metadata().is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        });
        if bash_available {
            return "bash";
        }
    }

    "sh"
}

/// What a new pane takes from the config, and all it takes.
///
/// Handed down rather than reached for, which is the same rule as the config
/// itself (§9.3): a window has no business asking a global what shell to run,
/// and a test that opens one says so in the call. Two settings today —
/// `default-shell` (§4.3) and `history-limit` (§7.5) — and they travel
/// together because every pane needs both at the moment it is born.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaneOpts {
    pub shell: String,
    pub history_limit: usize,
}

impl PaneOpts {
    /// Options for a pane running `shell`, with the default scrollback.
    pub fn new(shell: &str) -> PaneOpts {
        PaneOpts {
            shell: shell.to_owned(),
            history_limit: crate::grid::DEFAULT_HISTORY_LIMIT,
        }
    }
}

pub struct Config {
    pub prefix: Key,
    pub default_shell: String,
    /// Scrollback lines per pane. Ten million, per the config — a *cap*, not a
    /// preallocation, and the reason history is compacted (§7.5).
    pub history_limit: usize,
    pub renumber_windows: bool,
    pub aggressive_resize: bool,
    pub mode_keys: ModeKeys,
    pub status: bool,
    pub bindings: Bindings,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            // `unbind C-b` / `set -g prefix C-a`.
            prefix: Key::ctrl('a'),
            // Prefer bash on Linux when PATH can resolve it; Motor uses
            // `/system/bin/sh` -> rush (§4.3). `$SHELL` is not consulted.
            default_shell: native_shell().to_owned(),
            history_limit: crate::grid::DEFAULT_HISTORY_LIMIT,
            renumber_windows: true,
            aggressive_resize: true,
            mode_keys: ModeKeys::Vi,
            status: true,
            bindings: Bindings::defaults(),
        }
    }
}

impl Config {
    /// What every pane this config opens is given.
    pub fn pane_opts(&self) -> PaneOpts {
        PaneOpts {
            shell: self.default_shell.clone(),
            history_limit: self.history_limit,
        }
    }

    /// Read the config file, if there is one.
    ///
    /// A missing file is not a problem (§2.1) — it means the compiled-in
    /// defaults, which are the whole point.
    pub fn load() -> (Config, Vec<String>) {
        match std::fs::read_to_string(crate::sys::config_file()) {
            Ok(text) => Config::parse(&text),
            Err(_) => (Config::default(), Vec::new()),
        }
    }

    /// Apply `text` to the defaults, and say what could not be applied.
    ///
    /// The complaints are returned rather than printed: the server has no
    /// console of its own (§4.4), and where they belong is the status line
    /// (§2.2), which arrives with M6.
    pub fn parse(text: &str) -> (Config, Vec<String>) {
        let mut config = Config::default();
        let mut complaints = Vec::new();
        let mut table = None;
        // Bindings are held back until the whole file has been read, because
        // `mode-keys` decides which copy table a `[bind-copy]` entry is
        // overriding and a config file is not obliged to say so first.
        let mut binds = Vec::new();

        for (number, line) in text.lines().enumerate() {
            let line = strip_comment(line).trim();
            if line.is_empty() {
                continue;
            }
            let at = number + 1;

            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                table = match name.trim() {
                    "bind" => Some(Table::Prefix),
                    "bind-root" => Some(Table::Root),
                    "bind-copy" => Some(Table::Copy),
                    other => {
                        complaints.push(format!("{at}: no table called [{other}]"));
                        None
                    }
                };
                continue;
            }

            let Some((key, value)) = line.split_once('=') else {
                complaints.push(format!("{at}: not a setting"));
                continue;
            };
            let (key, value) = (key.trim(), value.trim());

            match table {
                Some(table) => binds.push((table, key, value, at)),
                None => config.apply_setting(key, value, at, &mut complaints),
            }
        }

        config.bindings.copy_keys(config.mode_keys);
        for (table, key, value, at) in binds {
            config.apply_binding(table, key, value, at, &mut complaints);
        }
        // Line order, which is the order a reader of the file expects, rather
        // than the order the two passes above happen to produce.
        complaints.sort_by_key(|why| {
            why.split_once(':')
                .and_then(|(at, _)| at.parse::<usize>().ok())
                .unwrap_or(0)
        });

        (config, complaints)
    }

    fn apply_setting(&mut self, key: &str, value: &str, at: usize, complaints: &mut Vec<String>) {
        let mut complain = |why: &str| complaints.push(format!("{at}: {why}"));
        match key {
            "prefix" => match string(value).as_deref().and_then(Key::parse) {
                Some(key) => self.prefix = key,
                None => complain(&format!("{value} is not a key")),
            },
            "default-shell" => match string(value) {
                Some(shell) => self.default_shell = shell,
                None => complain("default-shell wants a string"),
            },
            "history-limit" => match value.parse() {
                Ok(limit) => self.history_limit = limit,
                Err(_) => complain("history-limit wants a number"),
            },
            "renumber-windows" => match boolean(value) {
                Some(on) => self.renumber_windows = on,
                None => complain("renumber-windows wants true or false"),
            },
            "aggressive-resize" => match boolean(value) {
                Some(on) => self.aggressive_resize = on,
                None => complain("aggressive-resize wants true or false"),
            },
            "status" => match boolean(value) {
                Some(on) => self.status = on,
                None => complain("status wants true or false"),
            },
            "mode-keys" => match string(value).as_deref() {
                Some("vi") => self.mode_keys = ModeKeys::Vi,
                Some("emacs") => self.mode_keys = ModeKeys::Emacs,
                _ => complain("mode-keys wants \"vi\" or \"emacs\""),
            },
            other => complain(&format!("no setting called {other}")),
        }
    }

    fn apply_binding(
        &mut self,
        table: Table,
        key: &str,
        value: &str,
        at: usize,
        complaints: &mut Vec<String>,
    ) {
        let Some(name) = string(key) else {
            complaints.push(format!("{at}: a binding's key must be quoted"));
            return;
        };
        let Some(key) = Key::parse(&name) else {
            complaints.push(format!("{at}: {name} is not a key"));
            return;
        };
        let Some(command) = string(value) else {
            complaints.push(format!("{at}: a binding's command must be quoted"));
            return;
        };

        // An empty string unbinds -- which is how `unbind '"'` is written, and
        // why unbinding has to remove rather than shadow (§2.2).
        if command.is_empty() {
            self.bindings.unbind(table, key);
            return;
        }
        match Command::parse(&command) {
            Some(parsed) => self.bindings.bind(table, key, parsed),
            None => complaints.push(format!("{at}: rmux has no command {command}")),
        }
    }
}

/// Drop a trailing `#` comment, leaving one inside a quoted string alone.
fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    let mut escaped = false;
    for (at, c) in line.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            '#' if !quoted => return &line[..at],
            _ => {}
        }
    }
    line
}

/// A quoted TOML string, with the two escapes rmux's own example needs.
fn string(value: &str) -> Option<String> {
    let inner = value.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            // Only the two escapes rmux's own example needs (§2.2). An
            // escape this parser does not know makes the whole entry
            // malformed, which is a skipped line with a complaint rather than
            // a key name quietly mangled into something else.
            '\\' => match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                _ => return None,
            },
            c => out.push(c),
        }
    }
    Some(out)
}

fn boolean(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bindings::CopyCommand;
    use crate::bindings::Direction;
    use crate::bindings::Split;
    use crate::copy::Motion;

    fn key(name: &str) -> Key {
        Key::parse(name).unwrap()
    }

    #[test]
    fn no_config_file_at_all_is_the_config_this_project_specifies() {
        // §2.1: a user who has never written an rmux.toml gets all of this.
        let config = Config::default();
        assert_eq!(config.prefix, key("C-a"));
        assert_eq!(config.default_shell, native_shell());
        assert_eq!(config.history_limit, 9_999_999);
        assert!(config.renumber_windows);
        assert!(config.aggressive_resize);
        assert_eq!(config.mode_keys, ModeKeys::Vi);
        assert!(config.status);
    }

    #[test]
    fn the_example_in_the_plan_is_a_no_op() {
        // §2.2's example deliberately restates the defaults. If applying it
        // changes anything, one of the two representations has drifted.
        let text = format!(
            r#"
prefix            = "C-a"
default-shell     = "{}"
history-limit     = 9999999
renumber-windows  = true
aggressive-resize = true
mode-keys         = "vi"
status            = true

[bind]
"|"  = "split-window -h"
"-"  = "split-window -v"
"\"" = ""
"%"  = ""
"C-a" = "send-prefix"

[bind-root]
"S-Left"  = "previous-window"
"S-Right" = "next-window"
"M-Left"  = "select-pane -L"

[bind-copy]
"q" = "cancel"
"#,
            native_shell()
        );
        let (config, complaints) = Config::parse(&text);
        assert!(complaints.is_empty(), "{complaints:?}");

        let defaults = Config::default();
        assert_eq!(config.prefix, defaults.prefix);
        assert_eq!(config.default_shell, defaults.default_shell);
        assert_eq!(config.history_limit, defaults.history_limit);
        assert_eq!(config.mode_keys, defaults.mode_keys);
        for (table, name) in [
            (Table::Prefix, "|"),
            (Table::Prefix, "-"),
            (Table::Prefix, "C-a"),
            (Table::Root, "S-Left"),
            (Table::Root, "M-Left"),
            (Table::Copy, "q"),
        ] {
            assert_eq!(
                config.bindings.get(table, key(name)),
                defaults.bindings.get(table, key(name)),
                "{name}"
            );
        }
        assert_eq!(config.bindings.get(Table::Prefix, key("\"")), None);
        assert_eq!(config.bindings.get(Table::Prefix, key("%")), None);
    }

    #[test]
    fn what_a_pane_is_opened_with_is_what_the_config_says() {
        // The two settings a pane cannot ask anyone else for (§4.3, §7.5).
        let (config, complaints) = Config::parse("default-shell = \"dash\"\nhistory-limit = 100\n");
        assert!(complaints.is_empty(), "{complaints:?}");
        assert_eq!(
            config.pane_opts(),
            PaneOpts {
                shell: "dash".to_owned(),
                history_limit: 100,
            }
        );
    }

    #[test]
    fn an_empty_string_unbinds() {
        let (config, complaints) = Config::parse("[bind]\n\"c\" = \"\"\n");
        assert!(complaints.is_empty(), "{complaints:?}");
        assert_eq!(config.bindings.get(Table::Prefix, key("c")), None);
    }

    #[test]
    fn a_binding_can_be_moved_to_another_key() {
        let (config, _) = Config::parse("[bind]\n\"v\" = \"split-window -h\"\n");
        assert_eq!(
            config.bindings.get(Table::Prefix, key("v")),
            Some(Command::SplitWindow(Split::Horizontal))
        );
        // And the default it did not mention is still there.
        assert_eq!(
            config.bindings.get(Table::Prefix, key("|")),
            Some(Command::SplitWindow(Split::Horizontal))
        );
    }

    #[test]
    fn the_prefix_can_be_changed() {
        let (config, complaints) = Config::parse("prefix = \"C-b\"\n");
        assert!(complaints.is_empty(), "{complaints:?}");
        assert_eq!(config.prefix, key("C-b"));
    }

    #[test]
    fn a_malformed_entry_is_skipped_and_the_rest_of_the_file_still_applies() {
        // The rule that matters most (§2.2): a typo in one binding must not
        // cost a user the rest of their config.
        let text = concat!(
            "prefix = \"C-b\"\n",
            "history-limit = banana\n",
            "no-such-setting = true\n",
            "[bind]\n",
            "\"Nonsense\" = \"new-window\"\n",
            "\"v\" = \"if-shell true x\"\n",
            "\"w\" = \"new-window\"\n",
        );
        let (config, complaints) = Config::parse(text);
        assert_eq!(complaints.len(), 4, "{complaints:?}");
        // Everything well-formed took effect regardless.
        assert_eq!(config.prefix, key("C-b"));
        assert_eq!(config.history_limit, 9_999_999);
        assert_eq!(
            config.bindings.get(Table::Prefix, key("w")),
            Some(Command::NewWindow)
        );
    }

    #[test]
    fn every_complaint_names_the_line_it_is_about() {
        let (_, complaints) = Config::parse("\n\nnot-a-setting = 1\n");
        assert_eq!(complaints.len(), 1);
        assert!(complaints[0].starts_with("3:"), "{complaints:?}");
    }

    #[test]
    fn comments_and_blank_lines_are_not_settings() {
        let text = "# a comment\n\n  # an indented one\nprefix = \"C-b\" # trailing\n";
        let (config, complaints) = Config::parse(text);
        assert!(complaints.is_empty(), "{complaints:?}");
        assert_eq!(config.prefix, key("C-b"));
    }

    #[test]
    fn an_escape_this_parser_does_not_know_is_a_complaint_not_a_mangled_key() {
        let (config, complaints) = Config::parse("[bind]\n\"\\n\" = \"new-window\"\n");
        assert_eq!(complaints.len(), 1, "{complaints:?}");
        assert_eq!(
            config.bindings.get(Table::Prefix, key("c")),
            Some(Command::NewWindow)
        );
    }

    #[test]
    fn a_hash_inside_a_quoted_string_is_not_a_comment() {
        let (config, complaints) = Config::parse("[bind]\n\"#\" = \"new-window\"\n");
        assert!(complaints.is_empty(), "{complaints:?}");
        assert_eq!(
            config.bindings.get(Table::Prefix, key("#")),
            Some(Command::NewWindow)
        );
    }

    #[test]
    fn mode_keys_emacs_puts_the_other_vocabulary_in_the_copy_table() {
        // A whole table, not a flag: what changes is which keys copy mode has,
        // and nothing downstream of the table knows either name (§7.6).
        let (config, complaints) = Config::parse("mode-keys = \"emacs\"\n");
        assert!(complaints.is_empty(), "{complaints:?}");
        assert_eq!(config.mode_keys, ModeKeys::Emacs);
        assert_eq!(
            config.bindings.get(Table::Copy, key("C-n")),
            Some(Command::Copy(CopyCommand::Move(Motion::Down)))
        );
        // And vi's are gone rather than left lying about: `j` is a letter again.
        assert_eq!(config.bindings.get(Table::Copy, key("j")), None);
    }

    #[test]
    fn mode_keys_decides_the_table_a_bind_copy_entry_overrides() {
        // Wherever in the file it is. The entry below is written before
        // `mode-keys`, and installing the emacs table afterwards would
        // otherwise wipe it (`Config::parse` holds the bindings back).
        let text = "[bind-copy]\n\"C-n\" = \"cursor-up\"\n[bind]\n\"w\" = \"new-window\"\n";
        let (config, complaints) = Config::parse(&format!("mode-keys = \"emacs\"\n{text}"));
        assert!(complaints.is_empty(), "{complaints:?}");
        assert_eq!(
            config.bindings.get(Table::Copy, key("C-n")),
            Some(Command::Copy(CopyCommand::Move(Motion::Up)))
        );

        let (config, _) = Config::parse(&format!("{text}mode-keys = \"emacs\"\n"));
        assert_eq!(
            config.bindings.get(Table::Copy, key("C-n")),
            Some(Command::Copy(CopyCommand::Move(Motion::Up))),
            "the copy table was installed on top of the user's entry"
        );
    }

    #[test]
    fn mode_keys_wants_a_vocabulary_it_has() {
        let (config, complaints) = Config::parse("mode-keys = \"acme\"\n");
        assert_eq!(complaints.len(), 1, "{complaints:?}");
        assert_eq!(config.mode_keys, ModeKeys::Vi);
    }

    #[test]
    fn a_table_rmux_does_not_have_swallows_its_entries_rather_than_the_file() {
        let text = "[bind-mouse]\n\"a\" = \"new-window\"\n[bind]\n\"w\" = \"new-window\"\n";
        let (config, complaints) = Config::parse(text);
        assert!(!complaints.is_empty());
        assert_eq!(
            config.bindings.get(Table::Prefix, key("w")),
            Some(Command::NewWindow)
        );
    }

    #[test]
    fn a_root_binding_is_kept_apart_from_a_prefix_one() {
        let text = "[bind-root]\n\"M-Up\" = \"select-pane -U\"\n";
        let (config, _) = Config::parse(text);
        assert_eq!(
            config.bindings.get(Table::Root, key("M-Up")),
            Some(Command::SelectPane(Direction::Up))
        );
        // The prefix table has an `M-Up` of its own -- tmux's resize -- and a
        // `[bind-root]` entry must leave it exactly as it was.
        assert_eq!(
            config.bindings.get(Table::Prefix, key("M-Up")),
            Some(Command::ResizePane(Direction::Up, 5))
        );
    }
}
