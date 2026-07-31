//! The key tables, and the commands they name.
//!
//! Three tables, exactly as tmux (details.md §8.2): **root**, which fires with no
//! prefix; **prefix**, after `C-a`; and **copy mode** (§7.6). A config file
//! manipulates all three, and `unbind` must *remove* rather than shadow,
//! because the config this project is built to unbinds `"` and `%` (§2.1).
//!
//! # This module is where `~/.tmux.conf` stops being prose
//!
//! [`Bindings::defaults`] *is* §2.1's table, compiled in: every line of that
//! config, plus the tmux defaults it is written against, as data. A user with
//! no `rmux.toml` gets exactly this (§2.1), and `rmux.toml` overrides it rather
//! than replacing it (§2.2).
//!
//! # The vocabulary is the whole of it
//!
//! Every command named here runs: windows landed in M6, panes in M7, copy mode
//! in M8. The list was written in full before any of them did, deliberately —
//! a key bound to a command that has not been built yet is a gap with a name,
//! whereas leaving it out of the vocabulary would make a config file's binding
//! an error (§2.2: an unknown command is a skipped entry with a message).
//! What is *not* here is anything rmux has no plan to implement.
//!
//! # Copy mode's keys are commands too
//!
//! `mode-keys vi` (§2.1) is a *table*, not a hardcoded key handler: `h` names
//! `cursor-left` exactly as `|` names `split-window -h`, and both are
//! rebindable in `rmux.toml`'s `[bind-copy]` (§2.2). The names are tmux's own
//! `send -X` vocabulary, so a user translating their tmux config finds the
//! words they already know.

use std::collections::HashMap;

use crate::copy::Motion;
use crate::keys::Code;
use crate::keys::Key;

/// Which way a split divides a pane, in tmux's spelling: `-h` puts the panes
/// side by side, `-v` stacks them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Split {
    Horizontal,
    Vertical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Up,
    Down,
    Left,
    Right,
}

/// Which key vocabulary copy mode uses (§2.1, §7.6).
///
/// A *table*, not a mode: `mode-keys` picks which set of default bindings the
/// copy table starts as, and `[bind-copy]` overrides whichever was picked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeKeys {
    Vi,
    Emacs,
}

/// Which way a copy-mode search runs (§7.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Search {
    Forward,
    Backward,
}

/// What a key does while copy mode is up — the `[bind-copy]` table's half of
/// the vocabulary, named as tmux's `send -X` names them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyCommand {
    Move(Motion),
    /// `Space`: start selecting where the cursor is.
    BeginSelection,
    /// `Enter`: take the selection into a paste buffer and leave (§7.6).
    CopySelection,
    /// `/` and `?`: type a needle on the status row, then jump to it.
    Search(Search),
    /// `n` and `N`: the same needle again, the same way or the other way.
    SearchAgain,
    SearchReverse,
    /// `q` and `Esc`.
    Cancel,
}

/// Everything a key can be bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// Send one literal prefix key to the pane (§8.2).
    SendPrefix,
    DetachClient,

    NewWindow,
    NextWindow,
    PreviousWindow,
    SelectWindow(u8),
    RenameWindow,
    KillWindow,

    SplitWindow(Split),
    SelectPane(Direction),
    /// Move the border next to the active pane, by that many cells (§7.1).
    ResizePane(Direction, u8),
    NextPane,
    ZoomPane,
    KillPane,

    NextSession,
    PreviousSession,
    RenameSession,
    ChooseSession,

    CopyMode,
    PasteBuffer,
    CommandPrompt,
    /// Repaint the console from scratch (§6.2, §9.2).
    ///
    /// The one command whose effect is *no* change on screen: what it fixes is
    /// a console that has been written on behind rmux's back, which the frame
    /// diff cannot know about and will therefore never repair on its own.
    RefreshClient,
    /// A key of the copy-mode table, which fires only while it is up (§7.6).
    Copy(CopyCommand),
}

impl Command {
    /// Parse a command as a config file writes it: `split-window -h`.
    ///
    /// Not a command *language* (§2.2): the value is split on whitespace into a
    /// name and flags, and nothing more. No quoting, no arguments beyond what
    /// the flags carry, no `if-shell`.
    pub fn parse(value: &str) -> Option<Command> {
        let mut words = value.split_whitespace();
        let name = words.next()?;
        let flags: Vec<&str> = words.collect();
        let flag = |wanted: &str| flags.contains(&wanted);
        // tmux's `resize-pane -L 5`: the number after the flag, and one cell
        // when there is none, which is what its own `C-Left` binding means.
        let resize = |direction| {
            let by = flags.iter().find_map(|word| word.parse::<u8>().ok());
            Command::ResizePane(direction, by.unwrap_or(1).max(1))
        };

        Some(match name {
            "send-prefix" => Command::SendPrefix,
            "detach-client" | "detach" => Command::DetachClient,
            "new-window" => Command::NewWindow,
            "next-window" => Command::NextWindow,
            "previous-window" => Command::PreviousWindow,
            "select-window" => {
                let target = flags.iter().position(|f| *f == "-t")?;
                Command::SelectWindow(flags.get(target + 1)?.parse().ok()?)
            }
            "rename-window" => Command::RenameWindow,
            "kill-window" => Command::KillWindow,
            "split-window" if flag("-h") => Command::SplitWindow(Split::Horizontal),
            // tmux's own default: a split with no flag is a vertical one.
            "split-window" => Command::SplitWindow(Split::Vertical),
            "select-pane" if flag("-U") => Command::SelectPane(Direction::Up),
            "select-pane" if flag("-D") => Command::SelectPane(Direction::Down),
            "select-pane" if flag("-L") => Command::SelectPane(Direction::Left),
            "select-pane" if flag("-R") => Command::SelectPane(Direction::Right),
            "select-pane" => Command::NextPane,
            "resize-pane" if flag("-Z") => Command::ZoomPane,
            "resize-pane" if flag("-U") => resize(Direction::Up),
            "resize-pane" if flag("-D") => resize(Direction::Down),
            "resize-pane" if flag("-L") => resize(Direction::Left),
            "resize-pane" if flag("-R") => resize(Direction::Right),
            "kill-pane" => Command::KillPane,
            "switch-client" if flag("-n") => Command::NextSession,
            "switch-client" if flag("-p") => Command::PreviousSession,
            "rename-session" => Command::RenameSession,
            "choose-session" => Command::ChooseSession,
            "copy-mode" => Command::CopyMode,
            "paste-buffer" => Command::PasteBuffer,
            "command-prompt" => Command::CommandPrompt,
            // rmux has no client to name and no pane offsets to move, so
            // tmux's `-c`, `-U`, `-D`, `-L` and `-R` have nothing to mean here;
            // the bare command is the whole of it.
            "refresh-client" => Command::RefreshClient,
            _ => return Command::parse_copy(name),
        })
    }

    /// The copy-mode half of the vocabulary (§7.6).
    ///
    /// Separate only because it is a separate table's worth of names; a config
    /// writes them the same way, and binding one outside `[bind-copy]` simply
    /// never fires.
    fn parse_copy(name: &str) -> Option<Command> {
        let motion = |motion| Some(Command::Copy(CopyCommand::Move(motion)));
        let copy = |command| Some(Command::Copy(command));
        match name {
            "cursor-left" => motion(Motion::Left),
            "cursor-down" => motion(Motion::Down),
            "cursor-up" => motion(Motion::Up),
            "cursor-right" => motion(Motion::Right),
            "next-word" => motion(Motion::NextWord),
            "previous-word" => motion(Motion::PreviousWord),
            "start-of-line" => motion(Motion::LineStart),
            "end-of-line" => motion(Motion::LineEnd),
            "history-top" => motion(Motion::Top),
            "history-bottom" => motion(Motion::Bottom),
            "halfpage-up" => motion(Motion::HalfPageUp),
            "halfpage-down" => motion(Motion::HalfPageDown),
            "page-up" => motion(Motion::PageUp),
            "page-down" => motion(Motion::PageDown),
            "begin-selection" => copy(CopyCommand::BeginSelection),
            // tmux's own binding is `copy-selection-and-cancel`, and rmux has
            // only the one behaviour (§7.6), so both names reach it.
            "copy-selection" | "copy-selection-and-cancel" => copy(CopyCommand::CopySelection),
            "search-forward" => copy(CopyCommand::Search(Search::Forward)),
            "search-backward" => copy(CopyCommand::Search(Search::Backward)),
            "search-again" => copy(CopyCommand::SearchAgain),
            "search-reverse" => copy(CopyCommand::SearchReverse),
            "cancel" => copy(CopyCommand::Cancel),
            _ => None,
        }
    }
}

/// Which table a binding lives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Table {
    /// Fires with no prefix at all — tmux's `bind -n`.
    Root,
    /// Fires after the prefix key.
    Prefix,
    /// Fires in copy mode (§7.6).
    Copy,
}

/// The three tables.
pub struct Bindings {
    root: HashMap<Key, Command>,
    prefix: HashMap<Key, Command>,
    copy: HashMap<Key, Command>,
}

impl Default for Bindings {
    fn default() -> Bindings {
        Bindings::defaults()
    }
}

impl Bindings {
    /// §2.1's config, compiled in.
    ///
    /// The lines of `~/.tmux.conf` itself, plus the tmux defaults it is written
    /// against — because a config that only *changes* `S-Left` still expects
    /// `prefix c` to make a window.
    pub fn defaults() -> Bindings {
        let mut bindings = Bindings {
            root: HashMap::new(),
            prefix: HashMap::new(),
            copy: HashMap::new(),
        };

        // `bind -n S-Left previous-window` and the rest of the root table: the
        // bindings that fire with no prefix.
        bindings.bind(
            Table::Root,
            Key::with(Code::Left, Key::SHIFT),
            Command::PreviousWindow,
        );
        bindings.bind(
            Table::Root,
            Key::with(Code::Right, Key::SHIFT),
            Command::NextWindow,
        );
        for (code, direction) in [
            (Code::Left, Direction::Left),
            (Code::Right, Direction::Right),
            (Code::Up, Direction::Up),
            (Code::Down, Direction::Down),
        ] {
            bindings.bind(
                Table::Root,
                Key::with(code, Key::ALT),
                Command::SelectPane(direction),
            );
            // The prefix table's arrows select panes too -- a tmux default the
            // config leaves alone. Its modified arrows resize, by one cell with
            // control and by five with alt, which are tmux defaults as well:
            // `C-a M-Left` is a resize even though the config's own `M-Left`,
            // in the root table, selects.
            bindings.bind(
                Table::Prefix,
                Key::plain(code),
                Command::SelectPane(direction),
            );
            bindings.bind(
                Table::Prefix,
                Key::with(code, Key::CTRL),
                Command::ResizePane(direction, 1),
            );
            bindings.bind(
                Table::Prefix,
                Key::with(code, Key::ALT),
                Command::ResizePane(direction, 5),
            );
        }

        // `bind C-a send-prefix`, and the splits the config rebinds. It also
        // unbinds `"` and `%`, which here means simply never binding them.
        bindings.bind(Table::Prefix, Key::ctrl('a'), Command::SendPrefix);
        bindings.bind(
            Table::Prefix,
            Key::plain(Code::Char('|')),
            Command::SplitWindow(Split::Horizontal),
        );
        bindings.bind(
            Table::Prefix,
            Key::plain(Code::Char('-')),
            Command::SplitWindow(Split::Vertical),
        );

        // The tmux defaults §2.1 says have to exist because the config is
        // written against them.
        for (c, command) in [
            ('c', Command::NewWindow),
            ('n', Command::NextWindow),
            ('p', Command::PreviousWindow),
            (',', Command::RenameWindow),
            ('&', Command::KillWindow),
            ('x', Command::KillPane),
            ('o', Command::NextPane),
            ('z', Command::ZoomPane),
            ('d', Command::DetachClient),
            ('[', Command::CopyMode),
            (']', Command::PasteBuffer),
            (':', Command::CommandPrompt),
            // `r`, and not `C-l`: tmux binds the redraw here and leaves `C-l`
            // to the pane, where a shell clears its own screen with it. A
            // multiplexer that took `C-l` would be taking it from every
            // program in every pane.
            ('r', Command::RefreshClient),
            // The session bindings of §7.3.
            ('(', Command::PreviousSession),
            (')', Command::NextSession),
            ('$', Command::RenameSession),
            ('s', Command::ChooseSession),
        ] {
            bindings.bind(Table::Prefix, Key::plain(Code::Char(c)), command);
        }
        for digit in 0..=9_u8 {
            bindings.bind(
                Table::Prefix,
                Key::plain(Code::Char((b'0' + digit) as char)),
                Command::SelectWindow(digit),
            );
        }

        bindings.copy_keys(ModeKeys::Vi);
        bindings
    }

    /// Replace the copy-mode table with the one `mode-keys` names (§2.1).
    ///
    /// Both vocabularies are data, which is the whole reason the second one
    /// cost a table rather than a mode: `h` names `cursor-left` in one and
    /// `C-b` names it in the other, and everything downstream of the table --
    /// copy mode itself -- cannot tell which was chosen.
    pub fn copy_keys(&mut self, mode: ModeKeys) {
        self.copy.clear();
        match mode {
            ModeKeys::Vi => self.vi_copy_keys(),
            ModeKeys::Emacs => self.emacs_copy_keys(),
        }
        // The arrows and the page keys do the same thing in both, as they do
        // in tmux, because a user who has learned neither vocabulary still has
        // to be able to leave the screen behind.
        for (code, motion) in [
            (Code::Left, Motion::Left),
            (Code::Down, Motion::Down),
            (Code::Up, Motion::Up),
            (Code::Right, Motion::Right),
            (Code::PageUp, Motion::PageUp),
            (Code::PageDown, Motion::PageDown),
        ] {
            self.bind(
                Table::Copy,
                Key::plain(code),
                Command::Copy(CopyCommand::Move(motion)),
            );
        }
        for key in [Key::plain(Code::Char('q')), Key::plain(Code::Escape)] {
            self.bind(Table::Copy, key, Command::Copy(CopyCommand::Cancel));
        }
    }

    /// `mode-keys vi` (§2.1): vi's motions, its search and its selection.
    fn vi_copy_keys(&mut self) {
        let bindings = self;
        for (c, motion) in [
            ('h', Motion::Left),
            ('j', Motion::Down),
            ('k', Motion::Up),
            ('l', Motion::Right),
            ('w', Motion::NextWord),
            ('b', Motion::PreviousWord),
            ('0', Motion::LineStart),
            ('$', Motion::LineEnd),
            ('g', Motion::Top),
            ('G', Motion::Bottom),
        ] {
            bindings.bind(
                Table::Copy,
                Key::plain(Code::Char(c)),
                Command::Copy(CopyCommand::Move(motion)),
            );
        }
        for (c, motion) in [
            ('u', Motion::HalfPageUp),
            ('d', Motion::HalfPageDown),
            ('b', Motion::PageUp),
            ('f', Motion::PageDown),
        ] {
            bindings.bind(
                Table::Copy,
                Key::ctrl(c),
                Command::Copy(CopyCommand::Move(motion)),
            );
        }
        for (key, command) in [
            (Key::plain(Code::Char(' ')), CopyCommand::BeginSelection),
            (Key::plain(Code::Enter), CopyCommand::CopySelection),
            (
                Key::plain(Code::Char('/')),
                CopyCommand::Search(Search::Forward),
            ),
            (
                Key::plain(Code::Char('?')),
                CopyCommand::Search(Search::Backward),
            ),
            (Key::plain(Code::Char('n')), CopyCommand::SearchAgain),
            (Key::plain(Code::Char('N')), CopyCommand::SearchReverse),
        ] {
            bindings.bind(Table::Copy, key, Command::Copy(command));
        }
    }

    /// `mode-keys emacs` (§2.2), read off `tmux list-keys -T copy-mode`.
    ///
    /// The subset of it rmux has words for. tmux's `M-f` is `next-word-end`
    /// and this is `next-word`, because a word here is a run of non-blanks and
    /// there is only the one word motion (§7.6); its `C-r`/`C-s` are
    /// incremental and this search is not, which is the same divergence vi's
    /// `/` already has.
    fn emacs_copy_keys(&mut self) {
        for (c, motion) in [
            ('b', Motion::Left),
            ('f', Motion::Right),
            ('n', Motion::Down),
            ('p', Motion::Up),
            ('a', Motion::LineStart),
            ('e', Motion::LineEnd),
            ('v', Motion::PageDown),
        ] {
            self.bind(
                Table::Copy,
                Key::ctrl(c),
                Command::Copy(CopyCommand::Move(motion)),
            );
        }
        for (c, motion) in [
            ('b', Motion::PreviousWord),
            ('f', Motion::NextWord),
            ('v', Motion::PageUp),
            ('<', Motion::Top),
            ('>', Motion::Bottom),
        ] {
            self.bind(
                Table::Copy,
                Key::with(Code::Char(c), Key::ALT),
                Command::Copy(CopyCommand::Move(motion)),
            );
        }
        for (code, motion) in [
            (Code::Up, Motion::HalfPageUp),
            (Code::Down, Motion::HalfPageDown),
        ] {
            self.bind(
                Table::Copy,
                Key::with(code, Key::ALT),
                Command::Copy(CopyCommand::Move(motion)),
            );
        }
        self.bind(
            Table::Copy,
            Key::plain(Code::Char(' ')),
            Command::Copy(CopyCommand::Move(Motion::PageDown)),
        );
        for (key, command) in [
            (Key::ctrl(' '), CopyCommand::BeginSelection),
            (Key::ctrl('w'), CopyCommand::CopySelection),
            (
                Key::with(Code::Char('w'), Key::ALT),
                CopyCommand::CopySelection,
            ),
            (Key::ctrl('s'), CopyCommand::Search(Search::Forward)),
            (Key::ctrl('r'), CopyCommand::Search(Search::Backward)),
            (Key::plain(Code::Char('n')), CopyCommand::SearchAgain),
            (Key::plain(Code::Char('N')), CopyCommand::SearchReverse),
            (Key::ctrl('c'), CopyCommand::Cancel),
        ] {
            self.bind(Table::Copy, key, Command::Copy(command));
        }
    }

    pub fn bind(&mut self, table: Table, key: Key, command: Command) {
        self.table_mut(table).insert(key, command);
    }

    /// Remove a binding. Removing, not shadowing: `unbind '"'` has to leave the
    /// key doing nothing at all (§2.1).
    pub fn unbind(&mut self, table: Table, key: Key) {
        self.table_mut(table).remove(&key);
    }

    pub fn get(&self, table: Table, key: Key) -> Option<Command> {
        self.table(table).get(&key).copied()
    }

    fn table(&self, table: Table) -> &HashMap<Key, Command> {
        match table {
            Table::Root => &self.root,
            Table::Prefix => &self.prefix,
            Table::Copy => &self.copy,
        }
    }

    fn table_mut(&mut self, table: Table) -> &mut HashMap<Key, Command> {
        match table {
            Table::Root => &mut self.root,
            Table::Prefix => &mut self.prefix,
            Table::Copy => &mut self.copy,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str) -> Key {
        Key::parse(name).unwrap_or_else(|| panic!("not a key: {name}"))
    }

    #[test]
    fn the_config_at_the_head_of_this_project_is_what_the_defaults_are() {
        // Read straight off §2.1's table, line by line. If this test and that
        // table disagree, one of them is a lie.
        let bindings = Bindings::defaults();
        assert_eq!(
            bindings.get(Table::Prefix, key("C-a")),
            Some(Command::SendPrefix)
        );
        assert_eq!(
            bindings.get(Table::Root, key("S-Left")),
            Some(Command::PreviousWindow)
        );
        assert_eq!(
            bindings.get(Table::Root, key("S-Right")),
            Some(Command::NextWindow)
        );
        assert_eq!(
            bindings.get(Table::Root, key("M-Left")),
            Some(Command::SelectPane(Direction::Left))
        );
        assert_eq!(
            bindings.get(Table::Root, key("M-Down")),
            Some(Command::SelectPane(Direction::Down))
        );
        assert_eq!(
            bindings.get(Table::Prefix, key("|")),
            Some(Command::SplitWindow(Split::Horizontal))
        );
        assert_eq!(
            bindings.get(Table::Prefix, key("-")),
            Some(Command::SplitWindow(Split::Vertical))
        );
    }

    #[test]
    fn the_split_bindings_the_config_unbinds_are_not_there() {
        // `unbind '"'` and `unbind %`: the config removes tmux's own splits in
        // favour of `|` and `-`, so these must do nothing at all.
        let bindings = Bindings::defaults();
        assert_eq!(bindings.get(Table::Prefix, key("\"")), None);
        assert_eq!(bindings.get(Table::Prefix, key("%")), None);
    }

    #[test]
    fn the_tmux_defaults_the_config_is_written_against_are_there_too() {
        // §2.1's last paragraph: the config only makes sense on top of these.
        let bindings = Bindings::defaults();
        let expected = [
            ("c", Command::NewWindow),
            ("n", Command::NextWindow),
            ("p", Command::PreviousWindow),
            (",", Command::RenameWindow),
            ("&", Command::KillWindow),
            ("x", Command::KillPane),
            ("o", Command::NextPane),
            ("z", Command::ZoomPane),
            ("d", Command::DetachClient),
            ("[", Command::CopyMode),
            ("]", Command::PasteBuffer),
            (":", Command::CommandPrompt),
            ("r", Command::RefreshClient),
        ];
        for (name, command) in expected {
            assert_eq!(
                bindings.get(Table::Prefix, key(name)),
                Some(command),
                "{name}"
            );
        }
        assert_eq!(
            bindings.get(Table::Prefix, key("Left")),
            Some(Command::SelectPane(Direction::Left))
        );
        assert_eq!(
            bindings.get(Table::Prefix, key("4")),
            Some(Command::SelectWindow(4))
        );
    }

    #[test]
    fn the_modified_arrows_resize_because_that_is_where_tmux_binds_it() {
        // `tmux list-keys`: `C-Left` is `resize-pane -L` and `M-Left` is
        // `resize-pane -L 5`, both on the prefix table. The config's own
        // `M-Left` is a *root* binding and selects a pane, which is why these
        // two can coexist (§8.2).
        let bindings = Bindings::defaults();
        assert_eq!(
            bindings.get(Table::Prefix, key("C-Left")),
            Some(Command::ResizePane(Direction::Left, 1))
        );
        assert_eq!(
            bindings.get(Table::Prefix, key("M-Down")),
            Some(Command::ResizePane(Direction::Down, 5))
        );
        assert_eq!(
            bindings.get(Table::Root, key("M-Down")),
            Some(Command::SelectPane(Direction::Down))
        );
    }

    #[test]
    fn the_session_bindings_are_there_because_sessions_are_real() {
        // §7.3's surface, which exists because a session is what survives.
        let bindings = Bindings::defaults();
        assert_eq!(
            bindings.get(Table::Prefix, key("(")),
            Some(Command::PreviousSession)
        );
        assert_eq!(
            bindings.get(Table::Prefix, key(")")),
            Some(Command::NextSession)
        );
        assert_eq!(
            bindings.get(Table::Prefix, key("$")),
            Some(Command::RenameSession)
        );
        assert_eq!(
            bindings.get(Table::Prefix, key("s")),
            Some(Command::ChooseSession)
        );
    }

    #[test]
    fn copy_mode_has_vi_keys_because_the_config_asks_for_them() {
        // `setw -g mode-keys vi` (§2.1), which is this table and no other.
        let bindings = Bindings::defaults();
        let expected = [
            ("h", CopyCommand::Move(Motion::Left)),
            ("j", CopyCommand::Move(Motion::Down)),
            ("k", CopyCommand::Move(Motion::Up)),
            ("l", CopyCommand::Move(Motion::Right)),
            ("w", CopyCommand::Move(Motion::NextWord)),
            ("b", CopyCommand::Move(Motion::PreviousWord)),
            ("0", CopyCommand::Move(Motion::LineStart)),
            ("$", CopyCommand::Move(Motion::LineEnd)),
            ("g", CopyCommand::Move(Motion::Top)),
            ("G", CopyCommand::Move(Motion::Bottom)),
            ("C-u", CopyCommand::Move(Motion::HalfPageUp)),
            ("C-d", CopyCommand::Move(Motion::HalfPageDown)),
            ("C-b", CopyCommand::Move(Motion::PageUp)),
            ("C-f", CopyCommand::Move(Motion::PageDown)),
            ("Space", CopyCommand::BeginSelection),
            ("Enter", CopyCommand::CopySelection),
            ("/", CopyCommand::Search(Search::Forward)),
            ("?", CopyCommand::Search(Search::Backward)),
            ("n", CopyCommand::SearchAgain),
            ("N", CopyCommand::SearchReverse),
            ("q", CopyCommand::Cancel),
            ("Escape", CopyCommand::Cancel),
        ];
        for (name, command) in expected {
            assert_eq!(
                bindings.get(Table::Copy, key(name)),
                Some(Command::Copy(command)),
                "{name}"
            );
        }
    }

    #[test]
    fn mode_keys_emacs_is_the_other_vocabulary_and_the_same_commands() {
        // Read off `tmux list-keys -T copy-mode`, which is the emacs table
        // because emacs is tmux's own default there. Only the part rmux has
        // words for: no `jump-to`, no marks, no rectangle (§7.6).
        let mut bindings = Bindings::defaults();
        bindings.copy_keys(ModeKeys::Emacs);
        let expected = [
            ("C-b", CopyCommand::Move(Motion::Left)),
            ("C-f", CopyCommand::Move(Motion::Right)),
            ("C-n", CopyCommand::Move(Motion::Down)),
            ("C-p", CopyCommand::Move(Motion::Up)),
            ("C-a", CopyCommand::Move(Motion::LineStart)),
            ("C-e", CopyCommand::Move(Motion::LineEnd)),
            ("M-b", CopyCommand::Move(Motion::PreviousWord)),
            ("M-f", CopyCommand::Move(Motion::NextWord)),
            ("M-<", CopyCommand::Move(Motion::Top)),
            ("M->", CopyCommand::Move(Motion::Bottom)),
            ("C-v", CopyCommand::Move(Motion::PageDown)),
            ("M-v", CopyCommand::Move(Motion::PageUp)),
            ("M-Up", CopyCommand::Move(Motion::HalfPageUp)),
            ("M-Down", CopyCommand::Move(Motion::HalfPageDown)),
            ("Space", CopyCommand::Move(Motion::PageDown)),
            ("C-Space", CopyCommand::BeginSelection),
            ("M-w", CopyCommand::CopySelection),
            ("C-w", CopyCommand::CopySelection),
            ("C-s", CopyCommand::Search(Search::Forward)),
            ("C-r", CopyCommand::Search(Search::Backward)),
            ("n", CopyCommand::SearchAgain),
            ("N", CopyCommand::SearchReverse),
            ("q", CopyCommand::Cancel),
            ("Escape", CopyCommand::Cancel),
            ("C-c", CopyCommand::Cancel),
        ];
        for (name, command) in expected {
            assert_eq!(
                bindings.get(Table::Copy, key(name)),
                Some(Command::Copy(command)),
                "{name}"
            );
        }
        // One table or the other, never both at once: vi's `j` is a letter here
        // and `Space` means something else entirely.
        for name in ["h", "j", "k", "l", "g", "G", "$", "0", "/", "?"] {
            assert_eq!(bindings.get(Table::Copy, key(name)), None, "{name}");
        }
        // The other two tables are untouched by the choice.
        assert_eq!(
            bindings.get(Table::Prefix, key("[")),
            Some(Command::CopyMode)
        );
    }

    #[test]
    fn a_copy_mode_key_is_only_a_copy_mode_key() {
        // The tables are separate, and `q` in a pane is a `q` (§8.2).
        let bindings = Bindings::defaults();
        assert_eq!(bindings.get(Table::Prefix, key("h")), None);
        assert_eq!(bindings.get(Table::Root, key("q")), None);
    }

    #[test]
    fn the_copy_commands_parse_as_tmux_names_them() {
        assert_eq!(
            Command::parse("cursor-left"),
            Some(Command::Copy(CopyCommand::Move(Motion::Left)))
        );
        assert_eq!(
            Command::parse("halfpage-up"),
            Some(Command::Copy(CopyCommand::Move(Motion::HalfPageUp)))
        );
        assert_eq!(
            Command::parse("begin-selection"),
            Some(Command::Copy(CopyCommand::BeginSelection))
        );
        // tmux's own spelling of what `Enter` does, and rmux's shorter one.
        assert_eq!(
            Command::parse("copy-selection-and-cancel"),
            Some(Command::Copy(CopyCommand::CopySelection))
        );
        assert_eq!(
            Command::parse("copy-selection"),
            Some(Command::Copy(CopyCommand::CopySelection))
        );
        assert_eq!(
            Command::parse("search-backward"),
            Some(Command::Copy(CopyCommand::Search(Search::Backward)))
        );
        assert_eq!(
            Command::parse("cancel"),
            Some(Command::Copy(CopyCommand::Cancel))
        );
    }

    #[test]
    fn unbinding_removes_rather_than_shadows() {
        let mut bindings = Bindings::defaults();
        bindings.unbind(Table::Prefix, key("c"));
        assert_eq!(bindings.get(Table::Prefix, key("c")), None);
    }

    #[test]
    fn a_command_parses_as_a_config_file_writes_it() {
        assert_eq!(Command::parse("send-prefix"), Some(Command::SendPrefix));
        assert_eq!(
            Command::parse("split-window -h"),
            Some(Command::SplitWindow(Split::Horizontal))
        );
        assert_eq!(
            Command::parse("split-window -v"),
            Some(Command::SplitWindow(Split::Vertical))
        );
        // tmux's own default for a bare split.
        assert_eq!(
            Command::parse("split-window"),
            Some(Command::SplitWindow(Split::Vertical))
        );
        assert_eq!(
            Command::parse("select-pane -L"),
            Some(Command::SelectPane(Direction::Left))
        );
        assert_eq!(Command::parse("select-pane"), Some(Command::NextPane));
        assert_eq!(
            Command::parse("select-window -t 7"),
            Some(Command::SelectWindow(7))
        );
        assert_eq!(Command::parse("resize-pane -Z"), Some(Command::ZoomPane));
        assert_eq!(
            Command::parse("switch-client -n"),
            Some(Command::NextSession)
        );
    }

    #[test]
    fn a_command_rmux_does_not_have_is_refused_rather_than_ignored() {
        // §2.2: an unknown command is a skipped entry with a message, not a
        // silent no-op -- so the parser has to say no.
        assert_eq!(Command::parse("if-shell true 'foo'"), None);
        assert_eq!(Command::parse("run-shell ls"), None);
        assert_eq!(Command::parse("select-layout even-horizontal"), None);
        assert_eq!(Command::parse(""), None);
        // A command that needs a target and is not given one is not a command.
        assert_eq!(Command::parse("select-window"), None);
    }
}
