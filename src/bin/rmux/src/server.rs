//! The server: everything rmux owns, and the one loop that touches it.
//!
//! tmux's split, and the right one (details.md §4.1). The server holds the session
//! list, every pane and its child, every emulator, and does **all** rendering,
//! because the server is where the state is. The client is thin enough that
//! detach and attach are just a connection closing and opening.
//!
//! One channel, one loop (§4.5). Every byte source — a pane's pumps, a client's
//! reader, the listener — is a thread that sends an [`Event`] here and never
//! touches a pane or a screen itself. The loop drains everything pending before
//! it renders once (§6.4), so a pane producing a megabyte produces as many
//! frames as the console can show rather than as many as it wrote.
//!
//! # The frame diff is per client, not per session
//!
//! Two clients on the same session have two consoles in two different states,
//! so each carries its own [`Screen`]. Sharing one would mean sending a client
//! the difference against a screen it never had.
//!
//! # The prefix is the server's business
//!
//! The client relays bytes and knows nothing about them (§4.1), so it is here
//! that `C-a d` becomes a detach rather than two characters in a shell. What
//! decides that is `bindings` — §2.1's config, compiled in, and whatever
//! `rmux.toml` said on top of it (§2.2).
//!
//! Three rules from §8.1 and §8.2, in the order the code applies them:
//!
//! - a key equal to the **prefix** is held, and reaches nobody;
//! - the key after it is looked up in the **prefix table**. `send-prefix` is
//!   the one command that produces bytes rather than an action, and what it
//!   produces are the prefix's *own* bytes as they arrived — rmux never
//!   re-encodes a key (§8.1). An unbound key after the prefix does nothing at
//!   all, so a mistyped prefix is harmless rather than surprising;
//! - anything else is looked up in the **root table**, and if it is not there
//!   it goes to the pane as the bytes it was made of.

use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::mpsc::channel;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::Instant;

use crate::bindings::Command;
use crate::bindings::CopyCommand;
use crate::bindings::Search;
use crate::bindings::Table;
use crate::config::Config;
use crate::copy::CopyMode;
use crate::grid::Cell;
use crate::keys::Code;
use crate::keys::Key;
use crate::pane::PaneId;
use crate::proto;
use crate::proto::Frames;
use crate::proto::ToClient;
use crate::proto::ToServer;
use crate::screen::Frame;
use crate::screen::Screen;
use crate::session::Session;
use crate::session::SessionId;
use crate::session::Sessions;
use crate::status;
use crate::window::Window;

/// A connected client's identity.
pub type ClientId = u64;

/// Everything the server's one loop reacts to.
pub enum Event {
    /// Bytes a pane's child wrote, on either of its streams.
    Output { pane: PaneId, bytes: Vec<u8> },
    /// A pane's output has ended, so its child is gone and everything it wrote
    /// is in the grid (§4.5). The status is collected here, where the child
    /// handle lives.
    Drained { pane: PaneId },
    /// A client connected; this is the server's end of it.
    ClientArrived(Client),
    /// A client said something.
    FromClient(ClientId, ToServer),
    /// A client's connection ended, however it ended.
    ClientGone(ClientId),
}

/// The server's end of a client, which it writes to and never reads.
///
/// A channel rather than a socket, so the loop cannot be stalled by a client
/// that has stopped reading, and so the transport is somebody else's problem.
pub struct Client {
    pub id: ClientId,
    pub out: Sender<ToClient>,
    /// The thread draining `out` onto the socket, kept so that the server can
    /// wait for it. See [`Server::run`].
    pub farewell: JoinHandle<()>,
}

/// What a client's keys are going to instead of its pane.
///
/// Three of them: a line being typed (`prefix ,` renames a window, `prefix $` a
/// session, §7.3), the plain session list, and copy mode (§7.6). None is a
/// window of its own -- a prompt borrows the status row, the list is drawn over
/// the pane, and copy mode replaces one pane's box with a view of its
/// scrollback -- which is why they live here rather than in `window`.
///
/// **A mode owns every key while it is up, the prefix included.** tmux lets the
/// prefix table fire in copy mode, so `C-a c` opens a window from there; rmux
/// does not, and the divergence is deliberate -- it is the same rule the rename
/// prompt has had since M6, and one rule is better than two. `q` first, then
/// the prefix.
enum Mode {
    Normal,
    Prompt {
        what: Prompt,
        typed: String,
    },
    /// The numbered menu of §7.3, *not* `choose-tree` (§1.2).
    Sessions {
        at: usize,
    },
    /// Reading one pane's scrollback (§7.6), and the needle being typed into
    /// it if `/` or `?` has been pressed.
    Copy {
        copy: CopyMode,
        typing: Option<(Search, String)>,
    },
}

#[derive(Clone, Copy)]
enum Prompt {
    RenameWindow,
    RenameSession,
    /// `prefix :`: a command in the vocabulary of `bindings::Command`, typed
    /// rather than bound (§2.1's `:`).
    Command,
}

impl Prompt {
    fn label(self) -> &'static str {
        match self {
            Prompt::RenameWindow => "(rename-window)",
            Prompt::RenameSession => "(rename-session)",
            Prompt::Command => ":",
        }
    }
}

/// What one key turns out to mean, once the client's state has been consulted.
enum Act {
    /// Bytes for the pane in front, which coalesce with the next key's if that
    /// one is bytes too — one write for a run of ordinary typing.
    Forward(Vec<u8>),
    Run(Command),
    /// A key for whatever mode the client is in.
    Mode(Key),
    /// The prefix, held; or a key bound to nothing after it. Either way there
    /// is nothing to do and nothing reaches the pane (§8.2).
    Nothing,
}

/// A client, and what it is looking at.
struct Attached {
    id: ClientId,
    out: Sender<ToClient>,
    /// `None` between connecting and attaching.
    session: Option<SessionId>,
    rows: u16,
    cols: u16,
    screen: Screen,
    mode: Mode,
    /// Whether the prefix is held, while rmux is waiting to see what follows it.
    prefix_held: bool,
    /// The last thing searched for, and which way, so that `n` and `N` still
    /// mean something after copy mode has been left and entered again.
    search: Option<(String, Search)>,
    /// What rmux has to say to this client, on the status row until its next
    /// key (§2.2). See [`Server::say`].
    message: Option<String>,
    farewell: JoinHandle<()>,
}

/// How many paste buffers the server keeps (§7.6). tmux's `buffer-limit` is
/// 50; rmux's stack is not settable, and this is deep enough that the buffer a
/// user wants is on it and shallow enough that nothing has to prune it.
const BUFFERS: usize = 10;

/// Observe an asynchronous shell-to-command pty handoff without polling while
/// rmux is otherwise idle. The backoff keeps an Enter on a builtin cheap; the
/// bound keeps it finite when no process-group change will happen at all.
const FOREGROUND_HANDOFF_FIRST: Duration = Duration::from_millis(20);
const FOREGROUND_HANDOFF_MAX: Duration = Duration::from_millis(250);
const FOREGROUND_HANDOFF_LIMIT: Duration = Duration::from_secs(2);

struct Retitle {
    at: Instant,
    until: Instant,
    delay: Duration,
}

pub struct Server {
    sessions: Sessions,
    clients: Vec<Attached>,
    config: Config,
    events: Sender<Event>,
    /// The paste buffers, newest last.
    ///
    /// **Server-global, not per-session** (§7.3, §7.6), as in tmux: copy in one
    /// pane and paste in any other, in any window, in any session. It is the
    /// only state that crosses a session boundary, and it is what the brief
    /// asks for -- copying between two `red`s, or from rush to red.
    buffers: Vec<String>,
    /// A session has existed at some point, so an empty list now means the
    /// work is over rather than not yet begun.
    ever_had_a_session: bool,
    /// Likewise for clients, which is what catches a server nobody ever gave
    /// any work to.
    ever_had_a_client: bool,
    /// The writer threads of clients that have left the list, still owing the
    /// wire whatever was last queued for them. See [`Server::run`].
    farewells: Vec<JoinHandle<()>>,
    /// A bounded series of name checks after a line enters a pane. A pty echoes
    /// Enter before a shell hands it to the command, and a silent command sends
    /// no output event on which to notice that later transition.
    retitle: Option<Retitle>,
    /// When a client first had a half-arrived key sequence in hand, so that
    /// `ESCAPE_TIME` is measured against a clock rather than against however
    /// many times a wait happened to return. See [`Server::run`].
    /// What the config file could not be read as (§2.2), waiting for someone
    /// to say it to. The server is started before any client has attached, so
    /// at the moment it reads the file there is no status row to put this on.
    greeting: Option<String>,
}

impl Server {
    /// Build a server around `config`.
    ///
    /// Injected rather than loaded (§9.3, and red's `editor.rs:121-124`): this
    /// does no file I/O, so a test is not at the mercy of the config on the
    /// machine running it. `complaints` are what the config could not be read
    /// as -- they arrive with it because a config is only half itself without
    /// them, and the pair is what stops them being dropped on the floor.
    pub fn new(config: Config, complaints: &[String], events: Sender<Event>) -> Server {
        Server {
            sessions: Sessions::new(),
            clients: Vec::new(),
            config,
            events,
            buffers: Vec::new(),
            ever_had_a_session: false,
            ever_had_a_client: false,
            farewells: Vec::new(),
            retitle: None,
            greeting: (!complaints.is_empty())
                .then(|| format!("rmux.toml: {}", complaints.join("; "))),
        }
    }

    /// Say something to a client, on the status row until its next key (§2.2).
    ///
    /// The four things rmux has to say -- a config it could not read, a split
    /// with no room, a needle that is not there, a command it does not have --
    /// are all *the thing that did not happen*, and without somewhere to say
    /// them each of those is silence. There is no timer behind this: tmux's
    /// `display-time` would mean waking the server on a clock, which is the
    /// same price a status-line clock costs and is refused for the same reason
    /// (`status`, §4.5). A key is what takes the row back.
    fn say(&mut self, id: ClientId, what: impl Into<String>) {
        if let Some(client) = self.client_mut(id) {
            client.message = Some(what.into());
        }
    }

    /// Run until there is nothing left to serve.
    ///
    /// A detach leaves the sessions behind -- that is the whole point of the
    /// server -- so what ends it is the *work* finishing, not the last client
    /// leaving. The second condition below is narrower and easy to miss: a
    /// client that connects and goes without ever getting a session (an attach
    /// to a name that does not exist, say) would otherwise leave a server
    /// waiting for company that is never coming.
    pub fn run(&mut self, queue: Receiver<Event>) {
        loop {
            // This blocks, and an idle server costs nothing at all. The only
            // deadlines are the bounded foreground-command checks armed by
            // Enter; key decoding's `escape-time` lives in the client terminal
            // layer, where the bytes are (`keys`).
            let mut event = match self.retitle.as_ref().map(|retitle| retitle.at) {
                Some(at) => {
                    match queue.recv_timeout(at.saturating_duration_since(Instant::now())) {
                        Ok(event) => event,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            self.poll_foreground_handoff();
                            self.render();
                            continue;
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                None => match queue.recv() {
                    Ok(event) => event,
                    Err(_) => break,
                },
            };
            loop {
                self.handle(event);
                match queue.try_recv() {
                    Ok(next) => event = next,
                    Err(_) => break,
                }
            }

            if self.track_titles() {
                self.retitle = None;
            }
            self.track_copy();
            self.render();
            let nothing_to_serve = self.sessions.is_empty()
                && (self.ever_had_a_session || (self.ever_had_a_client && self.clients.is_empty()));
            if nothing_to_serve {
                break;
            }
        }
        self.say_goodbye();
    }

    /// Let every client's last message reach it before the process goes.
    ///
    /// The exit code a session ended with is the *last* thing written to a
    /// client, and the process exiting closes the socket under it -- which can
    /// discard exactly that write (§4.2, from `systest/src/tcp.rs:250`).
    /// [`write_client`] already waits for the client to close before dropping
    /// the socket; this is the other half, waiting for `write_client`. Without
    /// it `rmux; exit 5` exits 5 nearly always and 1 about once in a hundred
    /// runs, because the client saw the connection go instead of the status.
    ///
    /// Bounded by the same `FAREWELL` the writers use, so a client that has
    /// stopped reading delays this and cannot stop it.
    fn say_goodbye(&mut self) {
        // Dropping the client takes its channel with it, which is what tells
        // its writer there is nothing more to send.
        for client in std::mem::take(&mut self.clients) {
            self.farewells.push(client.farewell);
        }
        for farewell in std::mem::take(&mut self.farewells) {
            let _ = farewell.join();
        }
    }

    /// Take clients off the list, keeping the threads that still owe them bytes.
    fn part_with(&mut self, doomed: impl Fn(&Attached) -> bool) {
        let (gone, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.clients)
            .into_iter()
            .partition(doomed);
        self.clients = kept;
        for client in gone {
            self.farewells.push(client.farewell);
        }
    }

    fn handle(&mut self, event: Event) {
        match event {
            Event::ClientArrived(client) => {
                self.ever_had_a_client = true;
                self.clients.push(Attached {
                    id: client.id,
                    out: client.out,
                    session: None,
                    rows: 24,
                    cols: 80,
                    screen: Screen::new(),
                    mode: Mode::Normal,
                    prefix_held: false,
                    search: None,
                    message: None,
                    farewell: client.farewell,
                });
            }
            Event::ClientGone(id) => self.part_with(|client| client.id == id),
            Event::FromClient(id, message) => self.request(id, message),
            // Straight to the pane that wrote it, wherever it is: a build in a
            // background window still scrolls.
            Event::Output { pane, bytes } => {
                if let Some(pane) = self.sessions.pane_mut(pane) {
                    pane.feed(&bytes);
                }
            }
            // A window's name follows what is running in it until a user says
            // otherwise (`window`). Its explicit title arrives as output and
            // its foreground command is read from the pane's terminal.
            Event::Drained { pane } => {
                let code = self
                    .sessions
                    .pane_mut(pane)
                    .and_then(crate::pane::Pane::reap)
                    .unwrap_or(0);
                if let Some(session) = self.sessions.holding(pane) {
                    self.close_window(session, pane, code);
                }
            }
        }
    }

    fn request(&mut self, id: ClientId, message: ToServer) {
        match message {
            ToServer::Attach {
                session,
                detach_others,
                rows,
                cols,
            } => self.attach(id, session, detach_others, rows, cols),
            ToServer::NewSession { name, rows, cols } => self.new_session(id, name, rows, cols),
            ToServer::Key(key) => self.key(id, key),
            ToServer::Resize { rows, cols } => {
                if let Some(client) = self.client_mut(id) {
                    client.rows = rows;
                    client.cols = cols;
                    // The console is a different shape than the one the last
                    // frame was painted on (§6.2).
                    client.screen.invalidate();
                }
                self.fit(id);
            }
            ToServer::EndInput => {
                if let Some(session) = self.client(id).and_then(|client| client.session)
                    && let Some(pane) = self.sessions.get_mut(session).and_then(Session::pane_mut)
                {
                    pane.end_input();
                }
            }
            ToServer::Detach => self.detach(id),
            ToServer::List => {
                let lines = self.describe();
                self.send(id, ToClient::Sessions(lines));
            }
            ToServer::Kill(name) => match self.sessions.by_name(&name) {
                Some(session) => {
                    self.end_session(session, 0);
                    // `end_session` answers the clients that were *attached* to
                    // it; the one that asked for the kill is not one of them, and
                    // it is blocked on a reply until it hears something.
                    self.send(id, ToClient::Done);
                }
                None => self.send(id, ToClient::Failed(format!("no session named {name}"))),
            },
        }
    }

    /// `rmux new`: always a new session, named or numbered (§7.3).
    fn new_session(&mut self, id: ClientId, name: Option<String>, rows: u16, cols: u16) {
        if let Some(name) = &name
            && self.sessions.by_name(name).is_some()
        {
            self.send(id, ToClient::Failed(format!("session {name} exists")));
            return;
        }
        match self.sessions.create(
            name,
            &self.config.pane_opts(),
            self.pane_size(rows, cols),
            self.config.renumber_windows,
            self.events.clone(),
        ) {
            Ok(session) => {
                self.ever_had_a_session = true;
                self.show(id, session, rows, cols);
            }
            Err(err) => self.send(id, ToClient::Failed(format!("{err}"))),
        }
    }

    /// Put a client on a session and repaint it from nothing.
    fn show(&mut self, id: ClientId, session: SessionId, rows: u16, cols: u16) {
        self.sessions.touch(session);
        if let Some(client) = self.client_mut(id) {
            client.session = Some(session);
            client.rows = rows;
            client.cols = cols;
            // A client that has just arrived, or just changed session, has a
            // console that owes nothing to the last frame (§6.2).
            client.screen.invalidate();
        }
        self.fit_session(session);
    }

    /// The size a pane gets on a console of `rows` x `cols`.
    fn pane_size(&self, rows: u16, cols: u16) -> (u16, u16) {
        (rows.saturating_sub(self.chrome_rows()).max(1), cols)
    }

    /// Move a client to the session before or after its own (§7.3).
    fn switch_session(&mut self, id: ClientId, forward: bool) {
        let Some(current) = self.client(id).and_then(|client| client.session) else {
            return;
        };
        let order = self.sessions.iter_ids();
        if order.len() < 2 {
            return;
        }
        let Some(at) = order.iter().position(|held| *held == current) else {
            return;
        };
        let next = if forward {
            (at + 1) % order.len()
        } else {
            (at + order.len() - 1) % order.len()
        };
        let (rows, cols) = self
            .client(id)
            .map(|client| (client.rows, client.cols))
            .unwrap_or((24, 80));
        self.show(id, order[next], rows, cols);
    }

    fn attach(
        &mut self,
        id: ClientId,
        name: Option<String>,
        detach_others: bool,
        rows: u16,
        cols: u16,
    ) {
        let session = match &name {
            Some(name) => self.sessions.by_name(name),
            // A bare `rmux` takes the most recent session, or starts one when
            // the server has none (§7.3).
            None => self.sessions.most_recent(),
        };

        let session = match session {
            Some(session) => session,
            None => {
                if let Some(name) = &name
                    && !name.is_empty()
                {
                    // Naming a session that is not there is a mistake worth
                    // reporting, not a reason to invent one.
                    self.send(id, ToClient::Failed(format!("no session named {name}")));
                    return;
                }
                match self.sessions.create(
                    None,
                    &self.config.pane_opts(),
                    self.pane_size(rows, cols),
                    self.config.renumber_windows,
                    self.events.clone(),
                ) {
                    Ok(session) => {
                        self.ever_had_a_session = true;
                        session
                    }
                    Err(err) => {
                        self.send(id, ToClient::Failed(format!("{err}")));
                        return;
                    }
                }
            }
        };

        if detach_others {
            for client in self
                .clients
                .iter()
                .filter(|client| client.id != id && client.session == Some(session))
            {
                let _ = client.out.send(ToClient::Detached);
            }
            self.part_with(|client| client.id != id && client.session == Some(session));
        }

        self.show(id, session, rows, cols);
        // The first client to attach is the one that started this server, so
        // it is the one whose config file the complaints are about. Taken
        // rather than kept: a client attaching an hour later would be told off
        // for a file it has not touched.
        if let Some(greeting) = self.greeting.take() {
            self.say(id, greeting);
        }
    }

    /// Act on one key: what the pane gets, or what rmux does instead.
    ///
    /// **One key at a time, in the order they were typed**, because what a key
    /// means depends on the state it is reached in rather than the state it
    /// arrived in: `prefix [` and the vi keys typed straight after it can all be
    /// waiting at once, and deciding for them up front would send the motions to
    /// the shell, the copy mode they are meant for not being up yet.
    fn key(&mut self, id: ClientId, key: Key) {
        // Cleared before the key is decided rather than after, so that a key
        // which has something to say leaves it up: what clears a message is the
        // *next* key (§2.2).
        if let Some(client) = self.client_mut(id) {
            client.message = None;
        }
        match self.decide(id, key) {
            Act::Forward(bytes) => self.forward(id, &bytes),
            Act::Run(command) => self.apply(id, command),
            Act::Mode(key) => self.mode_key(id, key),
            Act::Nothing => {}
        }
    }

    /// What one key means to a client as it is now (§8.1, §8.2).
    fn decide(&mut self, id: ClientId, key: Key) -> Act {
        let prefix = self.config.prefix;
        let Some(client) = self.clients.iter_mut().find(|client| client.id == id) else {
            return Act::Nothing;
        };
        // A mode owns every key while it lasts, prefix included: there is
        // nothing to send to a pane while a name is being typed or a
        // scrollback read.
        if !matches!(client.mode, Mode::Normal) {
            return Act::Mode(key);
        }
        if !std::mem::take(&mut client.prefix_held) {
            if key == prefix {
                client.prefix_held = true;
                return Act::Nothing;
            }
            return match self.config.bindings.get(Table::Root, key) {
                Some(command) => Act::Run(command),
                None => Act::Forward(key.encode()),
            };
        }
        match self.config.bindings.get(Table::Prefix, key) {
            // The one command that is bytes rather than an action: the prefix
            // itself, typed into the pane (§8.2).
            Some(Command::SendPrefix) => Act::Forward(prefix.encode()),
            Some(command) => Act::Run(command),
            None => Act::Nothing,
        }
    }

    /// Bytes to the pane the client is looking at.
    fn forward(&mut self, id: ClientId, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if let Some(session) = self.client(id).and_then(|client| client.session)
            && let Some(pane) = self.sessions.get_mut(session).and_then(Session::pane_mut)
        {
            let _ = pane.write(bytes);
            if crate::sys::HAS_FOREGROUND_COMMAND
                && bytes.iter().any(|byte| matches!(byte, b'\r' | b'\n'))
            {
                // Observe the shell transferring the pty's foreground process
                // group. The checks stop at the transition or their bound;
                // they are not an idle status clock.
                let now = Instant::now();
                self.retitle = Some(Retitle {
                    at: now + FOREGROUND_HANDOFF_FIRST,
                    until: now + FOREGROUND_HANDOFF_LIMIT,
                    delay: FOREGROUND_HANDOFF_FIRST,
                });
            }
        }
    }

    /// A key while a prompt, the session list or copy mode is up.
    fn mode_key(&mut self, id: ClientId, key: Key) {
        if matches!(
            self.client(id).map(|client| &client.mode),
            Some(Mode::Copy { .. })
        ) {
            self.copy_key(id, key);
            return;
        }
        let count = self.sessions.iter().count();
        let Some(client) = self.clients.iter_mut().find(|client| client.id == id) else {
            return;
        };
        match &mut client.mode {
            Mode::Normal => {}
            Mode::Prompt { what, typed } => match key.code {
                Code::Enter => {
                    let (what, name) = (*what, std::mem::take(typed));
                    client.mode = Mode::Normal;
                    if !name.is_empty() {
                        self.commit_prompt(id, what, name);
                    }
                }
                Code::Escape => client.mode = Mode::Normal,
                Code::Backspace => {
                    typed.pop();
                }
                Code::Char(c) if key.mods == 0 => typed.push(c),
                _ => {}
            },
            // Handled above, where the copy table is looked up.
            Mode::Copy { .. } => {}
            Mode::Sessions { at } => {
                match key.code {
                    Code::Escape | Code::Char('q') => client.mode = Mode::Normal,
                    Code::Up => *at = at.saturating_sub(1),
                    Code::Down => *at = (*at + 1).min(count.saturating_sub(1)),
                    Code::Enter => {
                        let chosen = *at;
                        client.mode = Mode::Normal;
                        self.choose_session(id, chosen);
                    }
                    // Pick by digit, which is what makes it a menu rather than
                    // a list you have to walk (§7.3).
                    Code::Char(c) if c.is_ascii_digit() => {
                        let chosen = (c as u8 - b'0') as usize;
                        client.mode = Mode::Normal;
                        self.choose_session(id, chosen);
                    }
                    _ => {}
                }
            }
        }
    }

    /// A key in copy mode, looked up in the copy table (§7.6, §8.2).
    ///
    /// An unbound key does nothing at all, which is what makes copy mode safe:
    /// a stray keystroke cannot reach the shell whose scrollback is being read.
    fn copy_key(&mut self, id: ClientId, key: Key) {
        // A needle being typed owns every key until `Enter` or `Esc`, exactly
        // as the rename prompt does (§7.3) -- otherwise a `q` in the middle of
        // a word would leave copy mode.
        if matches!(
            self.client(id).map(|client| &client.mode),
            Some(Mode::Copy {
                typing: Some(_),
                ..
            })
        ) {
            self.search_key(id, key);
            return;
        }
        let Some(Command::Copy(command)) = self.config.bindings.get(Table::Copy, key) else {
            return;
        };
        match command {
            CopyCommand::Move(motion) => self.with_copy(id, |copy, grid| copy.apply(motion, grid)),
            CopyCommand::BeginSelection => self.with_copy(id, |copy, _| copy.begin_selection()),
            CopyCommand::CopySelection => {
                let mut copied = None;
                self.with_copy(id, |copy, grid| copied = copy.text(grid));
                if let Some(text) = copied {
                    self.remember(text);
                }
                // `copy-selection-and-cancel`, which is tmux's own binding for
                // `Enter` and the only behaviour rmux has (`bindings`).
                self.leave_copy(id);
            }
            CopyCommand::Cancel => self.leave_copy(id),
            // `/` and `?` open the prompt; what they find is up to `search_key`.
            CopyCommand::Search(which) => {
                if let Some(client) = self.client_mut(id)
                    && let Mode::Copy { typing, .. } = &mut client.mode
                {
                    *typing = Some((which, String::new()));
                }
            }
            CopyCommand::SearchAgain => self.repeat_search(id, false),
            CopyCommand::SearchReverse => self.repeat_search(id, true),
        }
    }

    /// A key while a needle is being typed on the status row.
    fn search_key(&mut self, id: ClientId, key: Key) {
        let mut go = None;
        {
            let Some(client) = self.clients.iter_mut().find(|client| client.id == id) else {
                return;
            };
            let Mode::Copy { typing, .. } = &mut client.mode else {
                return;
            };
            let Some((which, typed)) = typing.as_mut() else {
                return;
            };
            match key.code {
                Code::Enter => {
                    let (which, needle) = (*which, std::mem::take(typed));
                    *typing = None;
                    // An empty needle is `Enter` on an empty prompt: nothing to
                    // look for, and the last search is left alone.
                    if !needle.is_empty() {
                        client.search = Some((needle.clone(), which));
                        go = Some((needle, which));
                    }
                }
                Code::Escape => *typing = None,
                Code::Backspace => {
                    typed.pop();
                }
                Code::Char(c) if key.mods == 0 => typed.push(c),
                _ => {}
            }
        }
        if let Some((needle, which)) = go {
            self.jump(id, &needle, which);
        }
    }

    /// `n` and `N`: the last needle again, the same way or the other way.
    fn repeat_search(&mut self, id: ClientId, reverse: bool) {
        let Some((needle, which)) = self.client(id).and_then(|client| client.search.clone()) else {
            return;
        };
        let which = match (which, reverse) {
            (Search::Forward, false) | (Search::Backward, true) => Search::Forward,
            _ => Search::Backward,
        };
        self.jump(id, &needle, which);
    }

    fn jump(&mut self, id: ClientId, needle: &str, which: Search) {
        let forward = which == Search::Forward;
        let mut found = false;
        self.with_copy(id, |copy, grid| {
            if let Some(at) = crate::copy::find(grid, needle, copy.at(), forward) {
                copy.go_to(at, grid);
                found = true;
            }
        });
        // A search that finds nothing leaves the cursor where it was, and
        // without the message that is indistinguishable from a search that
        // found what is already under it.
        if !found {
            self.say(id, format!("not found: {needle}"));
        }
    }

    /// Do something to a client's copy mode, with the grid it is reading.
    ///
    /// The pane is looked up by the identity copy mode was entered on rather
    /// than by "whatever is in front", because those are not the same thing
    /// once a pane exits underneath it (`track_copy`).
    fn with_copy(&mut self, id: ClientId, act: impl FnOnce(&mut CopyMode, &crate::grid::Grid)) {
        let Some(client) = self.clients.iter_mut().find(|client| client.id == id) else {
            return;
        };
        let Mode::Copy { copy, .. } = &mut client.mode else {
            return;
        };
        if let Some(pane) = self.sessions.pane_mut(copy.pane()) {
            act(copy, pane.grid());
        }
    }

    fn leave_copy(&mut self, id: ClientId) {
        if let Some(client) = self.client_mut(id) {
            client.mode = Mode::Normal;
        }
    }

    /// Put text on the paste-buffer stack, keeping the last [`BUFFERS`] of it.
    fn remember(&mut self, text: String) {
        self.buffers.push(text);
        if self.buffers.len() > BUFFERS {
            self.buffers.remove(0);
        }
    }

    /// `prefix ]`: the top buffer into the pane in front, as if it were typed.
    ///
    /// Pasting *is* typing (§7.6), and that is worth stating plainly: the bytes
    /// go through the same path as a keystroke, so a paste with newlines in it
    /// runs whatever commands those newlines end. Enter is the one thing rmux
    /// re-encodes rather than forwards (§3.4, `sys::ENTER`), because these
    /// bytes were never typed at a console and there is nothing to forward.
    ///
    /// A pane that asked for bracketed paste gets the markers it asked for; one
    /// that did not is sent the text bare.
    fn paste(&mut self, id: ClientId) {
        let Some(text) = self.buffers.last().cloned() else {
            return;
        };
        let Some(session) = self.client(id).and_then(|client| client.session) else {
            return;
        };
        let Some(pane) = self.sessions.get_mut(session).and_then(Session::pane_mut) else {
            return;
        };

        let bracketed = pane.grid().bracketed_paste();
        let mut bytes = Vec::new();
        if bracketed {
            bytes.extend_from_slice(b"\x1b[200~");
        }
        for (at, line) in text.split('\n').enumerate() {
            if at > 0 {
                bytes.extend_from_slice(crate::sys::ENTER);
            }
            bytes.extend_from_slice(line.as_bytes());
        }
        if bracketed {
            bytes.extend_from_slice(b"\x1b[201~");
        }
        let _ = pane.write(&bytes);
    }

    /// Keep every client's copy mode pointing at something that still exists.
    ///
    /// A pane goes on printing while its scrollback is being read, so the
    /// buffer grows under the viewport; and a pane whose program exits takes
    /// its grid with it, which is the only thing that ends copy mode without
    /// the user saying so.
    fn track_copy(&mut self) {
        for client in &mut self.clients {
            let Mode::Copy { copy, .. } = &mut client.mode else {
                continue;
            };
            match self.sessions.pane_mut(copy.pane()) {
                Some(pane) => copy.clamp(pane.grid()),
                None => client.mode = Mode::Normal,
            }
        }
    }

    fn open_prompt(&mut self, id: ClientId, what: Prompt) {
        if let Some(client) = self.client_mut(id) {
            client.mode = Mode::Prompt {
                what,
                typed: String::new(),
            };
        }
    }

    /// What an answered prompt does, which for `prefix :` is a command.
    ///
    /// The typed line is parsed by the same `Command::parse` a config file's
    /// values go through (§2.2) -- it is not a command *language*, and the
    /// prompt does not make it one. A line that names no command rmux has is
    /// said back on the message line, in tmux's words for it.
    fn commit_prompt(&mut self, id: ClientId, what: Prompt, typed: String) {
        if let Prompt::Command = what {
            match Command::parse(&typed) {
                Some(command) => self.apply(id, command),
                None => self.say(id, format!("unknown command: {typed}")),
            }
            return;
        }
        let Some(session) = self.client(id).and_then(|client| client.session) else {
            return;
        };
        if let Some(held) = self.sessions.get_mut(session) {
            match what {
                Prompt::RenameWindow => {
                    if let Some(window) = held.windows_mut().current_mut() {
                        window.rename(typed);
                    }
                }
                Prompt::RenameSession => held.rename(typed),
                Prompt::Command => unreachable!("handled above"),
            }
        }
    }

    fn choose_session(&mut self, id: ClientId, at: usize) {
        let order = self.sessions.iter_ids();
        let Some(chosen) = order.get(at).copied() else {
            return;
        };
        let (rows, cols) = self
            .client(id)
            .map(|client| (client.rows, client.cols))
            .unwrap_or((24, 80));
        self.show(id, chosen, rows, cols);
    }

    /// Do what a binding names.
    ///
    /// Every `Command` is dispatched here, and this is the only place any of
    /// them is: a key from a table, a value from a config file and a line typed
    /// at `prefix :` all arrive as the same enum, so there is one meaning of
    /// `split-window -h` rather than three (`bindings`).
    fn apply(&mut self, id: ClientId, command: Command) {
        let Some(session) = self.client(id).and_then(|client| client.session) else {
            return;
        };
        match command {
            Command::DetachClient => self.detach(id),
            // Handled where the bytes are, because it produces bytes.
            Command::SendPrefix => {}

            // The client's own screen, not the session's: what is stale is one
            // console's idea of what is on it (§6.2), and two clients watching
            // the same window have two of those. The repaint itself is the
            // render at the end of this event -- forgetting is all this does.
            Command::RefreshClient => {
                if let Some(client) = self.client_mut(id) {
                    client.screen.invalidate();
                }
            }

            Command::NewWindow => {
                let size = self
                    .client(id)
                    .map(|client| self.pane_size(client.rows, client.cols))
                    .unwrap_or((24, 80));
                let opts = self.config.pane_opts();
                let events = self.events.clone();
                if let Some(session) = self.sessions.get_mut(session) {
                    let _ = session.windows_mut().open(&opts, size, events);
                }
                self.fit_session(session);
            }
            Command::NextWindow | Command::PreviousWindow | Command::SelectWindow(_) => {
                if let Some(session) = self.sessions.get_mut(session) {
                    let windows = session.windows_mut();
                    match command {
                        Command::NextWindow => windows.next(),
                        Command::PreviousWindow => windows.previous(),
                        // A number nobody answers to leaves the front window
                        // where it was, rather than picking a neighbour.
                        Command::SelectWindow(number) => {
                            windows.select(number as usize);
                        }
                        _ => unreachable!(),
                    }
                }
                // The window in front is a different shape's worth of client
                // now, so it gets fitted; the frame diff finds the rest.
                self.fit_session(session);
            }
            Command::KillWindow => {
                let alive = match self.sessions.get_mut(session) {
                    Some(held) => {
                        // Every pane in it, not just the one in front: a window
                        // is what is being killed (§3.6).
                        if let Some(window) = held.windows_mut().current_mut() {
                            window.kill_panes();
                        }
                        held.windows_mut().close_current()
                    }
                    None => false,
                };
                if alive {
                    self.fit_session(session);
                } else {
                    self.end_session(session, 0);
                }
            }

            // The pane commands, all of them the current window's business: a
            // pane belongs to a window, and only the window in front is on
            // screen (§7.1).
            Command::SplitWindow(how) => {
                let opts = self.config.pane_opts();
                let events = self.events.clone();
                // A window too small to divide is the one command whose
                // failure is invisible: the screen after it is the screen
                // before it (`layout::room_for`).
                let split = match self.window_mut(session) {
                    Some(window) => window.split(how, &opts, events),
                    None => Ok(true),
                };
                match split {
                    Ok(true) => {}
                    Ok(false) => self.say(id, "no room to split"),
                    Err(err) => self.say(id, format!("split: {err}")),
                }
            }
            Command::SelectPane(direction) => {
                if let Some(window) = self.window_mut(session) {
                    window.select(direction);
                }
            }
            // A border already against the edge of what it divides says so by
            // staying there, as tmux's does -- silently, because these keys are
            // held down and a message per repeat would be noise, not news.
            Command::ResizePane(direction, by) => {
                if let Some(window) = self.window_mut(session) {
                    window.resize_pane(direction, by as usize);
                }
            }
            Command::NextPane => {
                if let Some(window) = self.window_mut(session) {
                    window.next_pane();
                }
            }
            Command::ZoomPane => {
                if let Some(window) = self.window_mut(session) {
                    window.zoom();
                }
            }
            // Killing a pane is killing its child; the pane goes when its
            // output has drained (`window`), which is also what closes the
            // window behind the last one.
            Command::KillPane => {
                if let Some(window) = self.window_mut(session) {
                    window.kill_pane();
                }
            }

            // Copy mode is entered on the pane in front, and reads *that*
            // pane's buffer for as long as it is up (§7.6).
            Command::CopyMode(motion) => {
                let copy = self
                    .sessions
                    .get(session)
                    .and_then(Session::pane)
                    .map(|pane| {
                        let mut copy = CopyMode::enter(pane.id(), pane.grid());
                        if let Some(motion) = motion {
                            copy.apply(motion, pane.grid());
                        }
                        copy
                    });
                if let Some(copy) = copy
                    && let Some(client) = self.client_mut(id)
                {
                    client.mode = Mode::Copy { copy, typing: None };
                }
            }
            Command::PasteBuffer => self.paste(id),

            Command::NextSession => self.switch_session(id, true),
            Command::PreviousSession => self.switch_session(id, false),
            Command::RenameWindow => self.open_prompt(id, Prompt::RenameWindow),
            Command::RenameSession => self.open_prompt(id, Prompt::RenameSession),
            Command::CommandPrompt => self.open_prompt(id, Prompt::Command),
            Command::ChooseSession => {
                if let Some(client) = self.client_mut(id) {
                    client.mode = Mode::Sessions { at: 0 };
                }
            }

            // A copy-mode command reaches this only if a config bound one
            // outside `[bind-copy]` (`bindings`): recognized, and named, and
            // doing nothing here.
            _ => {}
        }
    }

    /// Send a client away, leaving its session running.
    fn detach(&mut self, id: ClientId) {
        self.send(id, ToClient::Detached);
        self.part_with(|client| client.id == id);
    }

    /// A window's program has exited, so the window goes -- and with the last
    /// window, the session.
    ///
    /// Painting comes first, and this is the third place that has been true:
    /// before rmux leaves (M3), before a session ends (M4), and here. The shape
    /// is always the same -- a pane's exit is reported only once its output has
    /// been drained (§4.5), so the last thing it printed is in the grid, and
    /// whatever is about to drop that grid has to paint it first. Removing the
    /// window takes the grid with it, so a render after this point has nothing
    /// left to draw.
    fn close_window(&mut self, session: SessionId, pane: PaneId, code: i32) {
        self.render();
        let alive = self
            .sessions
            .get_mut(session)
            .map(|session| session.windows_mut().close_holding(pane))
            .unwrap_or(false);
        if alive {
            self.fit_session(session);
        } else {
            self.end_session(session, code);
        }
    }

    /// A session's work is over: tell whoever is watching, and let it go.
    ///
    /// Painting comes first. A pane's exit is reported only once its output has
    /// been drained (§4.5), so the last thing the program printed is in the
    /// grid by now -- and telling the client to leave before painting it throws
    /// that away, which is the same loss the drain exists to prevent, two
    /// layers up. The loop's own render is too late: the client is gone from
    /// the list by then.
    fn end_session(&mut self, session: SessionId, code: i32) {
        self.render();
        // Nothing in it should outlive it (§3.6: terminate is all there is).
        if let Some(held) = self.sessions.get_mut(session) {
            held.windows_mut().kill_all();
        }
        for client in &mut self.clients {
            if client.session == Some(session) {
                let _ = client.out.send(ToClient::Exit(code));
            }
        }
        self.part_with(|client| client.session == Some(session));
        self.sessions.remove(session);
    }

    /// Size a session's window to the smallest client *viewing* it.
    ///
    /// `aggressive-resize on` (§2.1, §7.4). With one client it is a no-op,
    /// which is why the size lives on the client rather than on the session.
    fn fit(&mut self, id: ClientId) {
        if let Some(session) = self.client(id).and_then(|client| client.session) {
            self.fit_session(session);
        }
    }

    fn fit_session(&mut self, session: SessionId) {
        let chrome = self.chrome_rows();
        let size = self
            .clients
            .iter()
            .filter(|client| client.session == Some(session))
            .fold(None, |smallest: Option<(u16, u16)>, client| {
                // The pane gets the rows the status line does not.
                let rows = client.rows.saturating_sub(chrome).max(1);
                Some(match smallest {
                    Some((held, cols)) => (held.min(rows), cols.min(client.cols)),
                    None => (rows, client.cols),
                })
            });
        let Some(size) = size else {
            return;
        };
        let aggressive = self.config.aggressive_resize;
        if let Some(session) = self.sessions.get_mut(session) {
            if aggressive {
                // Only the window being looked at. A background one keeps its
                // size until it comes to the front, which is what makes the
                // option mean anything at all.
                if let Some(window) = session.windows_mut().current_mut() {
                    window.resize(size);
                }
            } else {
                session.windows_mut().resize(size);
            }
        }
    }

    /// Let every window's name catch up with what is running in it, which is
    /// what the status line shows (`window`).
    fn track_titles(&mut self) -> bool {
        let mut changed = false;
        for session in self.sessions.iter_ids() {
            if let Some(session) = self.sessions.get_mut(session) {
                changed |= session.windows_mut().track_titles();
            }
        }
        changed
    }

    fn poll_foreground_handoff(&mut self) {
        let Some(mut retitle) = self.retitle.take() else {
            return;
        };
        if self.track_titles() {
            return;
        }

        let now = Instant::now();
        if now >= retitle.until {
            return;
        }
        retitle.delay = (retitle.delay * 2).min(FOREGROUND_HANDOFF_MAX);
        retitle.at = (now + retitle.delay).min(retitle.until);
        self.retitle = Some(retitle);
    }

    /// How many rows of the console rmux keeps for itself.
    fn chrome_rows(&self) -> u16 {
        if self.config.status {
            status::HEIGHT as u16
        } else {
            0
        }
    }

    /// Paint every attached client, each against its own screen.
    fn render(&mut self) {
        let status_shown = self.config.status;
        let listing = self.describe();
        for client in &mut self.clients {
            let Some(session) = client.session.and_then(|id| self.sessions.get(id)) else {
                continue;
            };
            let Some(window) = session.windows().current() else {
                continue;
            };
            let (rows, cols) = (client.rows as usize, client.cols as usize);
            let mut frame = Frame::new(rows, cols);
            // Where copy mode puts the console's cursor, and what its status
            // row says: both are the copy pane's business, and this is the one
            // place that pane and its box are both in hand.
            let mut reading: Option<((usize, usize), String)> = None;
            // Every pane at the box the layout gives it, then the borders over
            // them (§7.1) -- one pane and no borders while a window is zoomed.
            for (pane, at) in window.on_screen() {
                match &client.mode {
                    // Copy mode replaces one pane's box with a view of that
                    // pane's whole buffer, history included (§7.6). Every other
                    // pane is painted exactly as it always was, and goes on
                    // printing while its neighbour is being read.
                    Mode::Copy { copy, .. } if copy.pane() == pane.id() => {
                        for (row, cells) in copy.view(pane.grid()).iter().enumerate() {
                            frame.set_row_at(at.top + row, at.left, cells);
                        }
                        let (row, col) = copy.cursor();
                        reading =
                            Some(((at.top + row, at.left + col), copy.indicator(pane.grid())));
                    }
                    _ => frame.blit(at.top, at.left, pane.grid()),
                }
            }
            for (row, col, glyph) in window.borders() {
                frame.set_cell(
                    row,
                    col,
                    Cell {
                        ch: glyph,
                        attrs: status::border(),
                    },
                );
            }
            match (&client.mode, client.message.as_deref()) {
                // A message owns the status row until the next key takes it
                // back (§2.2). It can only be up in these two modes -- a key is
                // what sets one and a key is what clears one, so nothing rmux
                // says can outlive the prompt or the search it was said during.
                (Mode::Normal | Mode::Copy { typing: None, .. }, Some(text))
                    if rows > status::HEIGHT =>
                {
                    frame.set_row(rows - status::HEIGHT, &status::message_row(text, cols));
                }
                // vi shows the needle where it shows everything else, and so
                // does this: on the row the status line was using.
                (
                    Mode::Copy {
                        typing: Some((which, typed)),
                        ..
                    },
                    _,
                ) if rows > status::HEIGHT => {
                    let label = if *which == Search::Forward { "/" } else { "?" };
                    frame.set_row(
                        rows - status::HEIGHT,
                        &status::prompt_row(label, typed, cols),
                    );
                }
                // The indicator is the only thing on screen that says copy mode
                // is up at all, as tmux's `[0/128]` is.
                (Mode::Copy { .. }, _) if rows > status::HEIGHT => {
                    let indicator = reading.as_ref().map_or("", |(_, text)| text.as_str());
                    frame.set_row(
                        rows - status::HEIGHT,
                        &status::prompt_row("-- copy mode --", indicator, cols),
                    );
                }
                (Mode::Prompt { what, typed }, _) if rows > status::HEIGHT => {
                    frame.set_row(
                        rows - status::HEIGHT,
                        &status::prompt_row(what.label(), typed, cols),
                    );
                }
                (Mode::Sessions { at }, _) => {
                    for (row, cells) in status::session_overlay(&listing, *at, cols)
                        .iter()
                        .enumerate()
                    {
                        frame.set_row(row, cells);
                    }
                }
                _ if status_shown && rows > status::HEIGHT => {
                    frame.set_row(rows - status::HEIGHT, &status::row(session, cols));
                }
                _ => {}
            }
            // Only the active pane's cursor is composited, moved into that
            // pane's box, and only when the pane wants it shown (§3.2). In copy
            // mode it is copy mode's cursor instead, and always shown: it is
            // the user's own, not the program's.
            frame.set_cursor(match &reading {
                Some((cursor, _)) => Some(*cursor),
                None => window.cursor(),
            });

            let bytes = client.screen.draw(frame);
            if !bytes.is_empty() {
                let _ = client.out.send(ToClient::Write(bytes));
            }
        }
    }

    fn describe(&self) -> Vec<String> {
        let attached: Vec<_> = self.clients.iter().filter_map(|c| c.session).collect();
        self.sessions.describe(|id| attached.contains(&id))
    }

    fn send(&self, id: ClientId, message: ToClient) {
        if let Some(client) = self.client(id) {
            let _ = client.out.send(message);
        }
    }

    /// The window in front of a session, which is the one a client sees.
    fn window_mut(&mut self, session: SessionId) -> Option<&mut Window> {
        self.sessions
            .get_mut(session)
            .and_then(|held| held.windows_mut().current_mut())
    }

    fn client(&self, id: ClientId) -> Option<&Attached> {
        self.clients.iter().find(|client| client.id == id)
    }

    fn client_mut(&mut self, id: ClientId) -> Option<&mut Attached> {
        self.clients.iter_mut().find(|client| client.id == id)
    }
}

/// Hand out client identities that are never reused.
#[derive(Default)]
pub struct ClientIds(u64);

impl ClientIds {
    pub fn allocate(&mut self) -> ClientId {
        self.0 += 1;
        self.0
    }
}

/// How long a finished connection waits for its client to go away.
///
/// Long enough that a client reading its last message always wins the race,
/// short enough that a client which never reads cannot pin a thread.
const FAREWELL: Duration = Duration::from_secs(5);

/// Bind, publish the port, and serve until the last session ends.
///
/// Loopback TCP, because the client and the server are unrelated processes and
/// standard Rust has nothing else that works on both platforms (§4.2): Motor
/// sets no target family, so Unix domain sockets do not exist there, and
/// `moto-ipc` is not standard Rust. systest already proves loopback works here
/// (`systest/src/tcp.rs:241-262` binds `127.0.0.1:0` and connects to the port
/// it got), which is why this needed no spike.
pub fn serve() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    let (events, queue) = channel();
    let arrivals = events.clone();
    std::thread::spawn(move || accept(listener, arrivals));

    // Published only once the door is open, so a client that reads this file
    // and connects immediately cannot beat the listener to it. The directory
    // may not exist yet: on Motor rmux makes its own scratch space (`sys`).
    let port_file = crate::sys::port_file();
    if let Some(parent) = port_file.parent() {
        if !parent.is_dir() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&port_file, port.to_string())?;
    let _ = std::fs::remove_file(crate::sys::port_file().with_extension("lock"));

    // The one place a config file is read (§9.3). What could not be applied
    // is the first thing the client that started this server will be told.
    let (config, complaints) = Config::load();
    Server::new(config, &complaints, events).run(queue);

    // Nothing is listening on that port any more, and a stale file would send
    // the next client to a closed door before it thought to start a server.
    let _ = std::fs::remove_file(crate::sys::port_file());
    Ok(())
}

fn accept(listener: TcpListener, events: Sender<Event>) {
    let mut ids = ClientIds::default();
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        let Ok(writer) = stream.try_clone() else {
            continue;
        };
        let id = ids.allocate();

        let (out, outbox) = channel();
        let farewell = std::thread::spawn(move || write_client(writer, outbox));
        if events
            .send(Event::ClientArrived(Client { id, out, farewell }))
            .is_err()
        {
            break;
        }
        let reader_events = events.clone();
        std::thread::spawn(move || read_client(id, stream, reader_events));
    }
}

fn read_client(id: ClientId, mut stream: TcpStream, events: Sender<Event>) {
    let mut frames = Frames::new();
    let mut buf = [0_u8; 4096];
    loop {
        let read = match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        frames.feed(&buf[..read]);
        while let Some(message) = frames.take::<ToServer>() {
            if let Some(message) = message
                && events.send(Event::FromClient(id, message)).is_err()
            {
                return;
            }
        }
        if frames.is_broken() {
            break;
        }
    }
    let _ = events.send(Event::ClientGone(id));
}

/// Write to one client, and take its leave properly.
///
/// The channel closing means the server has nothing more to say -- including,
/// most importantly, after an `Exit`. Dropping the socket here can discard what
/// was just written (§4.2, from `systest/src/tcp.rs:250`), so this waits for
/// the client to close first, which it does once it has read that last message.
fn write_client(mut stream: TcpStream, outbox: Receiver<ToClient>) {
    while let Ok(message) = outbox.recv() {
        if stream.write_all(&proto::encode(&message)).is_err() || stream.flush().is_err() {
            return;
        }
    }

    // Bounded by the clock, not by the first timeout the socket reports: an
    // early one would drop the connection with the `Exit` still unread, which is
    // the race `say_goodbye` exists to close.
    let deadline = Instant::now() + FAREWELL;
    let _ = stream.set_read_timeout(Some(FAREWELL));
    let mut buf = [0_u8; 64];
    loop {
        match stream.read(&mut buf) {
            // The client has closed, which is what this was waiting for.
            Ok(0) => break,
            Ok(_) => {}
            Err(err) if proto::timed_out(&err) && Instant::now() < deadline => {}
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;

    /// Type `text` at the server, one key at a time.
    ///
    /// What a terminal would make of those characters, which is the client's
    /// job now (`keys::Key::from_event`): the printable ones stand for
    /// themselves, and the control bytes for the keys they have always been.
    fn typed(server: &mut Server, id: ClientId, text: &str) {
        for c in text.chars() {
            let key = match c {
                '\r' | '\n' => Key::plain(Code::Enter),
                '\t' => Key::plain(Code::Tab),
                '\x7f' => Key::plain(Code::Backspace),
                '\x1b' => Key::plain(Code::Escape),
                c if (c as u32) < 0x20 => Key::ctrl((c as u8 + 0x60) as char),
                c => Key::plain(Code::Char(c)),
            };
            server.key(id, key);
        }
    }

    /// Stand in for a client, with a writer thread the test can watch.
    fn attached(id: ClientId, out: Sender<ToClient>, farewell: JoinHandle<()>) -> Attached {
        Attached {
            id,
            out,
            session: None,
            rows: 24,
            cols: 80,
            screen: Screen::new(),
            mode: Mode::Normal,
            prefix_held: false,
            search: None,
            message: None,
            farewell,
        }
    }

    /// A writer that takes its time, and says whether it got there in the end.
    fn slow_writer() -> (Sender<ToClient>, JoinHandle<()>, Arc<AtomicBool>) {
        let delivered = Arc::new(AtomicBool::new(false));
        let (out, outbox) = channel();
        let seen = Arc::clone(&delivered);
        let farewell = std::thread::spawn(move || {
            while outbox.recv().is_ok() {
                std::thread::sleep(Duration::from_millis(50));
                seen.store(true, Ordering::SeqCst);
            }
        });
        (out, farewell, delivered)
    }

    /// A server with one client on a session running `cat`, which echoes what
    /// is written to it — so a paste can be seen arriving.
    fn served() -> (Server, Receiver<Event>, Receiver<ToClient>, ClientId) {
        let (events, queue) = channel();
        let config = Config {
            default_shell: "cat".to_owned(),
            ..Config::default()
        };
        let mut server = Server::new(config, &[], events);
        let (out, outbox) = channel();
        server
            .clients
            .push(attached(1, out, std::thread::spawn(|| {})));
        server.attach(1, None, false, 24, 80);
        (server, queue, outbox, 1)
    }

    /// The pane the client is looking at.
    fn front_pane(server: &mut Server) -> &mut crate::pane::Pane {
        let session = server.clients[0]
            .session
            .expect("the client never attached");
        server
            .sessions
            .get_mut(session)
            .and_then(Session::pane_mut)
            .expect("the session has no pane")
    }

    #[test]
    fn copy_mode_takes_what_is_on_the_screen_into_a_paste_buffer() {
        // `prefix [`, three `k`s up, `Space`, `$`, `Enter` — §7.6's keys, from
        // the outside, through the tables and the modes rather than by calling
        // copy mode directly.
        let (mut server, _queue, _outbox, id) = served();
        front_pane(&mut server).feed(b"alpha\r\nbravo\r\ncharlie\r\n");

        typed(&mut server, id, "\x01[");
        typed(&mut server, id, "kkk0 $\r");
        assert_eq!(server.buffers.last().map(String::as_str), Some("alpha"));
        // `Enter` copies *and* leaves, as tmux's own binding does.
        assert!(matches!(server.clients[0].mode, Mode::Normal));
    }

    #[test]
    fn a_mode_takes_the_keys_that_arrived_with_the_key_that_opened_it() {
        // One read, all of it: `prefix ,` and the name typed after it. What a
        // key means depends on the state it is *reached* in rather than the
        // state it arrived in -- deciding a whole read up front typed the name
        // into the shell, with the prompt sitting open and empty above it.
        let (mut server, _queue, _outbox, id) = served();
        typed(&mut server, id, "\x01,build\r");

        let session = server.clients[0]
            .session
            .expect("the client never attached");
        let name = server
            .sessions
            .get(session)
            .and_then(|held| held.windows().current())
            .map(|window| window.name().to_owned());
        assert_eq!(name.as_deref(), Some("build"));
    }

    #[test]
    fn copy_mode_takes_the_motions_typed_in_the_same_breath() {
        // The same shape, and where it was found: `prefix [` and the vi keys
        // after it, which went to the shell as a search needle and a selection
        // command until each key was decided as it was reached.
        let (mut server, _queue, _outbox, id) = served();
        front_pane(&mut server).feed(b"alpha\r\nbravo\r\n");
        typed(&mut server, id, "\x01[kk0 $\r");
        assert_eq!(server.buffers.last().map(String::as_str), Some("alpha"));
    }

    #[test]
    fn a_key_in_copy_mode_never_reaches_the_pane() {
        // What makes reading a shell's scrollback safe: `k` is a motion here,
        // not a letter in whatever command was half-typed. `cat` echoes what it
        // is given, so the marker typed *after* copy mode ends is what says
        // everything that was ever going to arrive has.
        let (mut server, queue, _outbox, id) = served();
        typed(&mut server, id, "\x01[");
        typed(&mut server, id, "kkk");
        typed(&mut server, id, "q");
        typed(&mut server, id, "Z");

        let seen = echoed(&queue, b'Z');
        assert!(
            seen.contains(&b'Z'),
            "the pane never echoed the marker: {:?}",
            String::from_utf8_lossy(&seen)
        );
        assert!(
            !seen.contains(&b'k'),
            "a copy-mode key reached the pane: {:?}",
            String::from_utf8_lossy(&seen)
        );
    }

    #[test]
    fn control_c_is_reoriginated_normally_but_stays_local_in_copy_mode() {
        let (mut server, _queue, _outbox, id) = served();
        match server.decide(id, Key::ctrl('c')) {
            Act::Forward(bytes) => assert_eq!(bytes, b"\x03"),
            _ => panic!("an unbound normal-mode C-c was not forwarded"),
        }

        typed(&mut server, id, "\x01[");
        assert!(matches!(
            server.decide(id, Key::ctrl('c')),
            Act::Mode(Key {
                code: Code::Char('c'),
                mods: Key::CTRL,
            })
        ));
    }

    /// Everything the panes wrote up to and including `marker`.
    fn echoed(queue: &Receiver<Event>, marker: u8) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut seen = Vec::new();
        while Instant::now() < deadline {
            let left = deadline.saturating_duration_since(Instant::now());
            match queue.recv_timeout(left) {
                Ok(Event::Output { bytes, .. }) => {
                    seen.extend_from_slice(&bytes);
                    if seen.contains(&marker) {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        seen
    }

    #[test]
    fn a_search_goes_to_what_it_names_and_a_q_in_it_is_a_letter() {
        // `?needle Enter`, then `0 Space $ Enter` to take the line it landed
        // on. The needle starts with `q`, which is bound to `cancel` — while
        // one is being typed it has to be a letter, or no needle with a `q` in
        // it can ever be typed at all.
        let (mut server, _queue, _outbox, id) = served();
        front_pane(&mut server).feed(b"alpha\r\nquick brown\r\ncharlie\r\n");

        typed(&mut server, id, "\x01[");
        typed(&mut server, id, "?quick\r");
        typed(&mut server, id, "0 $\r");
        assert_eq!(
            server.buffers.last().map(String::as_str),
            Some("quick brown")
        );
    }

    #[test]
    fn n_repeats_the_last_search_without_retyping_it() {
        let (mut server, _queue, _outbox, id) = served();
        front_pane(&mut server).feed(b"mark one\r\nmark two\r\nend\r\n");

        typed(&mut server, id, "\x01[");
        typed(&mut server, id, "?mark\r");
        typed(&mut server, id, "n");
        typed(&mut server, id, " $\r");
        assert_eq!(server.buffers.last().map(String::as_str), Some("mark one"));
    }

    #[test]
    fn pasting_types_the_buffer_into_the_pane() {
        // `prefix ]` (§7.6). `cat` gives the bytes straight back, so what comes
        // out of the pane is proof of what went in.
        let (mut server, queue, _outbox, id) = served();
        server.buffers.push("pasted".to_owned());
        typed(&mut server, id, "\x01]");

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut seen = Vec::new();
        while Instant::now() < deadline {
            let left = deadline.saturating_duration_since(Instant::now());
            match queue.recv_timeout(left) {
                Ok(Event::Output { bytes, .. }) => {
                    seen.extend_from_slice(&bytes);
                    if seen.windows(6).any(|window| window == b"pasted") {
                        return;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        panic!(
            "the paste never reached the pane: {:?}",
            String::from_utf8_lossy(&seen)
        );
    }

    #[test]
    fn a_paste_with_nothing_to_paste_is_not_an_error() {
        let (mut server, _queue, _outbox, id) = served();
        typed(&mut server, id, "\x01]");
        assert!(server.buffers.is_empty());
    }

    #[test]
    fn the_buffer_stack_keeps_the_last_few_and_no_more() {
        let (mut server, _queue, _outbox, _id) = served();
        for n in 0..BUFFERS + 3 {
            server.remember(n.to_string());
        }
        assert_eq!(server.buffers.len(), BUFFERS);
        assert_eq!(server.buffers[0], "3");
        assert_eq!(server.buffers.last().unwrap(), &(BUFFERS + 2).to_string());
    }

    #[test]
    fn the_server_does_not_go_while_a_writer_still_holds_a_message() {
        // What `say_goodbye` is for. The thread stands in for `write_client`: it
        // takes its time over the message and ends only when the channel
        // closes. Nothing is asserted about *how* the wait works -- only that
        // the message was through before the wait was over, which is the
        // difference between `rmux; exit 5` exiting 5 and exiting 1.
        let (events, _queue) = channel();
        let mut server = Server::new(Config::default(), &[], events);
        let (out, farewell, delivered) = slow_writer();
        server.clients.push(attached(1, out, farewell));

        server.send(1, ToClient::Exit(5));
        server.say_goodbye();
        assert!(
            delivered.load(Ordering::SeqCst),
            "the server left before its last message did"
        );
    }

    #[test]
    fn a_client_that_leaves_is_still_waited_for() {
        // The message that matters most is the one sent *as* a client is taken
        // off the list -- `end_session` sends `Exit` and drops the client in the
        // same breath -- so the wait has to outlive the list entry. `part_with`
        // is what keeps the thread.
        let (events, _queue) = channel();
        let mut server = Server::new(Config::default(), &[], events);
        let (out, farewell, delivered) = slow_writer();
        server.clients.push(attached(1, out, farewell));

        server.send(1, ToClient::Exit(5));
        server.part_with(|client| client.id == 1);
        assert!(server.clients.is_empty());
        server.say_goodbye();
        assert!(
            delivered.load(Ordering::SeqCst),
            "a client off the list stopped being waited for"
        );
    }

    /// What a client is being told, if anything.
    fn said(server: &Server) -> Option<&str> {
        server.clients[0].message.as_deref()
    }

    /// Everything queued for a client, as one string.
    fn written(outbox: &Receiver<ToClient>) -> String {
        let mut out = String::new();
        while let Ok(ToClient::Write(bytes)) = outbox.try_recv() {
            out.push_str(&String::from_utf8_lossy(&bytes));
        }
        out
    }

    #[test]
    fn a_refresh_repaints_a_console_rmux_has_no_way_to_know_is_stale() {
        // §9.2: a full repaint happens only on a resize and on `prefix r`.
        // The diff never resends what it believes is already on screen (§6.2),
        // which is exactly the belief a stray write to the console breaks --
        // so the fix cannot be automatic, and this is the key it needs.
        let (mut server, _queue, outbox, id) = served();
        front_pane(&mut server).feed(b"hello\r\n");
        server.render();
        assert!(written(&outbox).contains("hello"));

        // Nothing has changed, so the next paint costs nothing at all.
        server.render();
        assert_eq!(written(&outbox), "");

        typed(&mut server, id, "\x01r");
        server.render();
        assert!(
            written(&outbox).contains("hello"),
            "a refresh painted less than the whole screen"
        );
    }

    #[test]
    fn a_needle_that_is_not_there_is_said_rather_than_ignored() {
        // A failed search leaves the cursor where it was, and so does a search
        // that finds what is already under it -- without the message those two
        // are the same screen (§2.2).
        let (mut server, _queue, _outbox, id) = served();
        front_pane(&mut server).feed(b"alpha\r\nbravo\r\n");
        typed(&mut server, id, "\x01[");
        typed(&mut server, id, "/zulu\r");
        assert_eq!(said(&server), Some("not found: zulu"));
    }

    #[test]
    fn the_next_key_takes_the_row_back() {
        // No timer behind a message, so a key is the only thing that ends one
        // -- and the key that *set* it must not be the key that clears it.
        let (mut server, _queue, _outbox, id) = served();
        typed(&mut server, id, "\x01:frobnicate\r");
        assert_eq!(said(&server), Some("unknown command: frobnicate"));
        typed(&mut server, id, "x");
        assert_eq!(said(&server), None);
    }

    #[test]
    fn a_window_with_no_room_for_another_pane_says_so() {
        // Three rows: one is the status line and a split needs a row each side
        // of a border (`layout::divisible`). The screen after the refused split
        // is the screen before it, which is what makes this one worth saying.
        let (mut server, _queue, _outbox, id) = served();
        server.request(id, ToServer::Resize { rows: 3, cols: 40 });
        typed(&mut server, id, "\x01-");
        assert_eq!(said(&server), Some("no room to split"));
    }

    #[test]
    fn a_config_rmux_could_not_read_is_said_to_whoever_started_the_server() {
        // §2.2: a malformed entry is skipped and reported. The skipping is
        // `config`'s and has always worked; this is the reporting, which needs
        // a client, there being no screen at the moment the file is read.
        let (events, queue) = channel();
        let config = Config {
            default_shell: "cat".to_owned(),
            ..Config::default()
        };
        let mut server = Server::new(config, &["3: not a setting".to_owned()], events);
        let (out, _outbox) = channel();
        server
            .clients
            .push(attached(1, out, std::thread::spawn(|| {})));
        server.attach(1, None, false, 24, 80);
        assert_eq!(said(&server), Some("rmux.toml: 3: not a setting"));

        // Said once, to that client. Whoever attaches next has not touched the
        // file and is not the one who can fix it.
        let (out, _outbox2) = channel();
        server
            .clients
            .push(attached(2, out, std::thread::spawn(|| {})));
        server.attach(2, None, false, 24, 80);
        assert_eq!(server.clients[1].message, None);
        drop(queue);
    }

    #[test]
    fn an_exclusive_attach_detaches_the_sessions_other_clients() {
        let (mut server, _queue, old_outbox, _) = served();
        let session = server.clients[0].session;
        let (out, _outbox) = channel();
        server
            .clients
            .push(attached(2, out, std::thread::spawn(|| {})));

        server.attach(2, None, true, 24, 80);

        assert_eq!(old_outbox.try_recv(), Ok(ToClient::Detached));
        assert_eq!(server.clients.len(), 1);
        assert_eq!(server.clients[0].id, 2);
        assert_eq!(server.clients[0].session, session);
    }
}
