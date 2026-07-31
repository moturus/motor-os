//! The session list: what survives a detach.
//!
//! Real, multiple, named sessions (details.md §7.3), not one implicit session with
//! many windows. A session is the unit that outlives its client: you detach
//! from `build`, attach to `notes`, and the shells in `build` keep compiling.
//! Without that, a server is only a second process for no reason.
//!
//! A window belongs to **exactly one** session (§7.3). tmux can link one window
//! into several; that is `link-window` and it stays a non-goal (§1.2). Without
//! it the session tree is a tree, and `renumber-windows` has one list to
//! renumber rather than several.
//!
//! A session holds [`Windows`], and a window holds panes (§7.1). What a client
//! is looking at is therefore two lookups deep, and the accessors below are the
//! only ones that should ever do it.

use std::sync::mpsc::Sender;

use crate::config::PaneOpts;
use crate::pane::Pane;
use crate::pane::PaneId;
use crate::server::Event;
use crate::window::Windows;

/// A session's identity, stable across renames.
///
/// Names are what the user says and can change (`prefix-$`); this is what the
/// server keys on, so a rename is not a relocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(u64);

/// One session: a name, and the windows running under it.
pub struct Session {
    id: SessionId,
    name: String,
    windows: Windows,
    /// Bumped whenever a client attaches, so a bare `rmux` can find the
    /// most recently used session (§7.3).
    used: u64,
}

impl Session {
    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn rename(&mut self, name: String) {
        self.name = name;
    }

    pub fn windows(&self) -> &Windows {
        &self.windows
    }

    pub fn windows_mut(&mut self) -> &mut Windows {
        &mut self.windows
    }

    /// The pane a client attached here is looking at.
    ///
    /// `None` only in the moment between a window closing and the session
    /// following it, which the server does not let a client observe.
    pub fn pane(&self) -> Option<&Pane> {
        self.windows.current().and_then(|window| window.pane())
    }

    pub fn pane_mut(&mut self) -> Option<&mut Pane> {
        self.windows
            .current_mut()
            .and_then(|window| window.pane_mut())
    }
}

/// Every session the server holds.
#[derive(Default)]
pub struct Sessions {
    sessions: Vec<Session>,
    next_id: u64,
    next_auto_name: u64,
    clock: u64,
}

impl Sessions {
    pub fn new() -> Sessions {
        Sessions::default()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Session> {
        self.sessions.iter()
    }

    /// Every session's identity, for a caller that needs to walk them mutably.
    pub fn iter_ids(&self) -> Vec<SessionId> {
        self.sessions.iter().map(|session| session.id).collect()
    }

    /// Start a session, its first window running what `opts` says (§2.2).
    ///
    /// An unnamed session is called `0`, `1`, ... as tmux does — and the
    /// counter only ever goes up, so killing `0` does not hand its name to the
    /// next session and confuse whoever is still typing `rmux attach -t 0`.
    pub fn create(
        &mut self,
        name: Option<String>,
        opts: &PaneOpts,
        size: (u16, u16),
        renumber: bool,
        events: Sender<Event>,
    ) -> std::io::Result<SessionId> {
        let name = match name {
            Some(name) => name,
            None => {
                let name = self.next_auto_name.to_string();
                self.next_auto_name += 1;
                name
            }
        };

        let mut windows = Windows::new(renumber);
        windows.open(opts, size, events)?;

        let id = SessionId(self.next_id);
        self.next_id += 1;
        self.clock += 1;
        self.sessions.push(Session {
            id,
            name,
            windows,
            used: self.clock,
        });
        Ok(id)
    }

    pub fn get(&self, id: SessionId) -> Option<&Session> {
        self.sessions.iter().find(|session| session.id == id)
    }

    pub fn get_mut(&mut self, id: SessionId) -> Option<&mut Session> {
        self.sessions.iter_mut().find(|session| session.id == id)
    }

    pub fn by_name(&self, name: &str) -> Option<SessionId> {
        self.sessions
            .iter()
            .find(|session| session.name == name)
            .map(|session| session.id)
    }

    /// The session a bare `rmux` should attach to (§7.3).
    pub fn most_recent(&self) -> Option<SessionId> {
        self.sessions
            .iter()
            .max_by_key(|session| session.used)
            .map(|session| session.id)
    }

    /// Note that a client just attached to `id`.
    pub fn touch(&mut self, id: SessionId) {
        self.clock += 1;
        let clock = self.clock;
        if let Some(session) = self.get_mut(id) {
            session.used = clock;
        }
    }

    /// Which session owns `pane`, if any.
    pub fn holding(&self, pane: PaneId) -> Option<SessionId> {
        self.sessions
            .iter()
            .find(|session| session.windows.holding(pane).is_some())
            .map(|session| session.id)
    }

    /// A pane by identity, wherever it is.
    ///
    /// Output has to reach the pane that wrote it even when nobody is looking
    /// at that window: a background build still scrolls.
    pub fn pane_mut(&mut self, pane: PaneId) -> Option<&mut Pane> {
        self.sessions
            .iter_mut()
            .find_map(|session| session.windows.pane_mut(pane))
    }

    /// Remove a session, returning it so the caller can shut it down.
    pub fn remove(&mut self, id: SessionId) -> Option<Session> {
        let at = self.sessions.iter().position(|session| session.id == id)?;
        Some(self.sessions.remove(at))
    }

    /// One line per session, as `rmux ls` prints them.
    pub fn describe(&self, attached: impl Fn(SessionId) -> bool) -> Vec<String> {
        self.sessions
            .iter()
            .map(|session| {
                let windows = session.windows.len();
                let plural = if windows == 1 { "window" } else { "windows" };
                let attached = if attached(session.id) {
                    " (attached)"
                } else {
                    ""
                };
                format!("{}: {windows} {plural}{attached}", session.name)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn sessions() -> (Sessions, mpsc::Receiver<Event>, Sender<Event>) {
        let (tx, rx) = mpsc::channel();
        (Sessions::new(), rx, tx)
    }

    /// A pane running `true`, which exits at once and exists long enough to be
    /// named and counted.
    fn opts() -> PaneOpts {
        PaneOpts::new("true")
    }

    #[test]
    fn an_unnamed_session_is_numbered_as_tmux_numbers_them() {
        let (mut sessions, _rx, tx) = sessions();
        sessions
            .create(None, &opts(), (24, 80), true, tx.clone())
            .unwrap();
        sessions.create(None, &opts(), (24, 80), true, tx).unwrap();
        let names: Vec<_> = sessions.iter().map(|s| s.name().to_owned()).collect();
        assert_eq!(names, ["0", "1"]);
    }

    #[test]
    fn a_killed_sessions_name_is_not_handed_to_the_next_one() {
        // Someone still typing `rmux attach -t 0` should get "no such
        // session", not somebody else's shell.
        let (mut sessions, _rx, tx) = sessions();
        let first = sessions
            .create(None, &opts(), (24, 80), true, tx.clone())
            .unwrap();
        sessions.remove(first);
        sessions.create(None, &opts(), (24, 80), true, tx).unwrap();
        assert_eq!(sessions.by_name("0"), None);
        assert!(sessions.by_name("1").is_some());
    }

    #[test]
    fn a_bare_attach_finds_the_most_recently_used_session() {
        let (mut sessions, _rx, tx) = sessions();
        let first = sessions
            .create(None, &opts(), (24, 80), true, tx.clone())
            .unwrap();
        let second = sessions.create(None, &opts(), (24, 80), true, tx).unwrap();
        assert_eq!(sessions.most_recent(), Some(second));
        sessions.touch(first);
        assert_eq!(sessions.most_recent(), Some(first));
    }

    #[test]
    fn a_session_is_found_by_the_name_it_was_given() {
        let (mut sessions, _rx, tx) = sessions();
        let id = sessions
            .create(Some("build".into()), &opts(), (24, 80), true, tx)
            .unwrap();
        assert_eq!(sessions.by_name("build"), Some(id));
        assert_eq!(sessions.by_name("notes"), None);
    }

    #[test]
    fn a_rename_moves_the_name_and_not_the_session() {
        let (mut sessions, _rx, tx) = sessions();
        let id = sessions
            .create(Some("build".into()), &opts(), (24, 80), true, tx)
            .unwrap();
        sessions.get_mut(id).unwrap().rename("notes".into());
        assert_eq!(sessions.by_name("build"), None);
        assert_eq!(sessions.by_name("notes"), Some(id));
        assert_eq!(sessions.get(id).unwrap().id(), id);
    }

    #[test]
    fn the_listing_says_what_rmux_ls_says() {
        let (mut sessions, _rx, tx) = sessions();
        let build = sessions
            .create(Some("build".into()), &opts(), (24, 80), true, tx.clone())
            .unwrap();
        sessions
            .create(Some("notes".into()), &opts(), (24, 80), true, tx)
            .unwrap();
        assert_eq!(
            sessions.describe(|id| id == build),
            ["build: 1 window (attached)", "notes: 1 window"]
        );
    }
}
