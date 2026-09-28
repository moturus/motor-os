//! The Motor OS transport: `moto-ipc` connections instead of loopback TCP.
//!
//! A server often holds more capabilities than its clients, and TCP tells it
//! only an address. An IPC connection is bound to the process on the other
//! end, so each side asks the kernel what the other may do
//! (details.md §4.2.1, docs/caps.md "Named IPC services").
//!
//! A `sync` connection carries one request at a time, and rmux talks both
//! ways at once, so a client holds two small connections:
//!
//! - *output*: each request is a long poll, answered with the next bytes of
//!   `ToClient` frames;
//! - *input*: each request carries `ToServer` bytes and is answered at once.
//!
//! Both carry bytes rather than messages: [`Frames`] reassembles any split.
//!
//! The server registers a name made of its own capability mask. A client
//! looks up the mask its own server would get, and checks the server's actual
//! mask before it sends anything.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::io::Read;
use std::io::Write;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::mpsc::channel;
use std::time::Duration;
use std::time::Instant;

use moto_ipc::sync::ChannelSize;
use moto_ipc::sync::ClientConnection;
use moto_ipc::sync::LocalServer;
use moto_ipc::sync::RequestHeader;
use moto_ipc::sync::ResponseHeader;
use moto_rt::ErrorCode;
use moto_sys::SysCpu;
use moto_sys::SysHandle;
use moto_sys::SysObj;
use moto_sys::caps::CAP_SPAWN;
use moto_sys::caps::CAP_SPAWN_DETACHED;
use moto_sys::caps::default_child_capabilities;

use crate::proto;
use crate::proto::Frames;
use crate::proto::ToClient;
use crate::proto::ToServer;
use crate::server::Client;
use crate::server::ClientId;
use crate::server::ClientIds;
use crate::server::Event;

// The wire format, public for the adversarial probe (src/bin/rmux-probe.rs).
pub const CMD_OPEN_OUTPUT: u16 = 1;
pub const CMD_OPEN_INPUT: u16 = 2;
pub const CMD_INPUT: u16 = 3;
pub const CMD_POLL: u16 = 4;

// The page after moto-ipc's 16-byte header: a token, a length, then data.
pub const TOKEN_AT: usize = 16;
pub const LEN_AT: usize = 24;
pub const DATA_AT: usize = 32;
const DATA_MAX: usize = 4096 - DATA_AT;

/// How long opening a connection may take once the server holds its name.
const OPEN_TIMEOUT: Duration = Duration::from_secs(5);
/// A server must acknowledge each input request before another can be sent.
const INPUT_TIMEOUT: Duration = Duration::from_secs(5);

/// Two connections per client.
const MAX_CONNECTIONS: u64 = 64;
const MAX_LISTENERS: u64 = 4;

fn own_capabilities() -> u64 {
    moto_sys::ProcessStaticPage::get().capabilities
}

/// The mask of the server this process would start, which is the key it
/// looks up: a server spawned with the default mask gets exactly this.
pub fn profile() -> u64 {
    default_child_capabilities(own_capabilities())
}

/// The service name of the server running with `caps`.
///
/// `TMPDIR` selects a private server, as the port file's directory did. An
/// ordinary session leaves it unset, so its name reveals no path.
pub fn service_name(caps: u64) -> String {
    match std::env::var("TMPDIR") {
        Ok(dir) if !dir.is_empty() => {
            let mut name = format!("rmux/{caps:x}/");
            // Shared URLs are split on ';' before decoding, and the common
            // encoder introduces ';' for &, :, and =. Escape those here,
            // including '%' so literal escape spellings remain distinct.
            for ch in dir.chars() {
                match ch {
                    '%' => name.push_str("%25"),
                    ';' => name.push_str("%3B"),
                    '&' => name.push_str("%26"),
                    ':' => name.push_str("%3A"),
                    '=' => name.push_str("%3D"),
                    _ => name.push(ch),
                }
            }
            name
        }
        _ => format!("rmux/{caps:x}"),
    }
}

/// Whether a client running with `client` may use a server running with
/// `server`: it holds every bit the server holds, or would give it to its own
/// children (a System process grants `CAP_SPAWN` and `CAP_LOG` unheld).
fn may_use(client: u64, server: u64) -> bool {
    server & !(client | default_child_capabilities(client)) == 0
}

fn os_error(err: ErrorCode) -> std::io::Error {
    std::io::Error::from_raw_os_error(err as i32)
}

fn put_u64(page: &mut [u8], at: usize, value: u64) {
    page[at..at + 8].copy_from_slice(&value.to_ne_bytes());
}

fn get_u64(page: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(page[at..at + 8].try_into().unwrap())
}

fn put_len(page: &mut [u8], len: usize) {
    page[LEN_AT..LEN_AT + 4].copy_from_slice(&(len as u32).to_ne_bytes());
}

/// The data length a peer wrote, which is its word and so is bounded here.
fn get_len(page: &[u8]) -> usize {
    (u32::from_ne_bytes(page[LEN_AT..LEN_AT + 4].try_into().unwrap()) as usize).min(DATA_MAX)
}

// ---- the client ---------------------------------------------------------------

/// The client's half that carries `ToServer` bytes.
pub struct Writer {
    conn: ClientConnection,
    /// A timed-out request may still be outstanding on this connection.
    stuck: bool,
}

/// The client's half that long-polls for `ToClient` bytes.
pub struct Reader {
    conn: ClientConnection,
    held: Vec<u8>,
    at: usize,
    timeout: Option<Duration>,
    /// A poll timed out and is still outstanding, so this connection cannot
    /// ask another question.
    stuck: bool,
}

fn request(
    conn: &mut ClientConnection,
    cmd: u16,
    token: u64,
    data: &[u8],
    timeout: Option<Duration>,
) -> std::io::Result<()> {
    let header = conn.req::<RequestHeader>();
    header.cmd = cmd;
    header.ver = 0;
    header.flags = 0;
    let page = conn.data_mut();
    put_u64(page, TOKEN_AT, token);
    put_len(page, data.len());
    page[DATA_AT..DATA_AT + data.len()].copy_from_slice(data);
    conn.do_rpc(timeout.map(|timeout| moto_rt::time::Instant::now() + timeout))
        .map_err(os_error)?;
    match conn.resp::<ResponseHeader>().result {
        moto_rt::E_OK => Ok(()),
        err => Err(os_error(err)),
    }
}

/// A connection to `name`, if a server running with `profile` holds it and
/// has a listener free.
fn open(name: &str, profile: u64) -> std::io::Result<Option<ClientConnection>> {
    let mut conn = ClientConnection::new(ChannelSize::Small).map_err(os_error)?;
    let deadline = Instant::now() + OPEN_TIMEOUT;
    loop {
        match conn.connect(name) {
            Ok(()) => break,
            Err(moto_rt::E_NOT_FOUND) => return Ok(None),
            // Connect notifications let the server refill the pool. A busy
            // live service must never be mistaken for one we need to start.
            Err(moto_rt::E_NOT_READY) => {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("the rmux server is busy: {name}"),
                    ));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(err) => return Err(os_error(err)),
        }
    }
    // Before a byte is sent: whoever holds the name with another mask is not
    // the server this client means to type into.
    let caps = SysObj::get_capabilities(conn.handle()).map_err(os_error)?;
    if caps != profile {
        let pid = SysObj::get_pid(conn.handle()).unwrap_or(0);
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("process {pid} holds {name} with capabilities {caps:#x}, not {profile:#x}"),
        ));
    }
    Ok(Some(conn))
}

/// Connect to the server holding `name`, which must run with `profile`.
///
/// `Ok(None)` means nothing holds the name.
pub fn connect(name: &str, profile: u64) -> std::io::Result<Option<(Writer, Reader)>> {
    let Some(mut output) = open(name, profile)? else {
        return Ok(None);
    };
    request(&mut output, CMD_OPEN_OUTPUT, 0, &[], Some(OPEN_TIMEOUT))?;
    let token = get_u64(output.data(), TOKEN_AT);
    let server = SysObj::get_pid(output.handle()).map_err(os_error)?;

    let Some(mut input) = open(name, profile)? else {
        return Ok(None);
    };
    if SysObj::get_pid(input.handle()).map_err(os_error)? != server {
        return Err(std::io::Error::other(format!(
            "{name} changed hands while connecting"
        )));
    }
    request(&mut input, CMD_OPEN_INPUT, token, &[], Some(OPEN_TIMEOUT))?;

    let reader = Reader {
        conn: output,
        held: Vec::new(),
        at: 0,
        timeout: None,
        stuck: false,
    };
    Ok(Some((
        Writer {
            conn: input,
            stuck: false,
        },
        reader,
    )))
}

/// Connect to this process's server, starting one with `spawn` if none runs.
///
/// No lock file: if two clients start two servers, the kernel gives the name
/// to one, the other exits, and both clients reach the winner.
pub fn connect_or_start(
    spawn: impl FnOnce() -> std::io::Result<()>,
    patience: Duration,
) -> std::io::Result<(Writer, Reader)> {
    let profile = profile();
    let name = service_name(profile);
    if let Some(link) = connect(&name, profile)? {
        return Ok(link);
    }

    let caps = own_capabilities();
    for (bit, what) in [
        (CAP_SPAWN, "CAP_SPAWN"),
        (CAP_SPAWN_DETACHED, "CAP_SPAWN_DETACHED"),
    ] {
        if caps & bit == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "no server runs with capabilities {profile:#x}, and starting one needs {what}"
                ),
            ));
        }
    }
    // Panes inherit `TMPDIR`, and Rush stages pipelines there. The port file
    // used to create it before a server started, so keep doing that, but only
    // when it is absent (docs/fs-permissions.md, "rmux creates ...").
    if let Some(dir) = std::env::var_os("TMPDIR").map(std::path::PathBuf::from)
        && !dir.is_dir()
    {
        let _ = std::fs::create_dir_all(dir);
    }
    spawn()?;

    let deadline = Instant::now() + patience;
    while Instant::now() < deadline {
        if let Some(link) = connect(&name, profile)? {
            return Ok(link);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "the rmux server did not start",
    ))
}

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.stuck {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        let len = buf.len().min(DATA_MAX);
        match request(
            &mut self.conn,
            CMD_INPUT,
            0,
            &buf[..len],
            Some(INPUT_TIMEOUT),
        ) {
            Ok(()) => Ok(len),
            Err(err) if err.raw_os_error() == Some(moto_rt::E_TIMED_OUT as i32) => {
                self.stuck = true;
                Err(std::io::ErrorKind::TimedOut.into())
            }
            Err(err) => Err(err),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Reader {
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.timeout = timeout;
        Ok(())
    }
}

impl Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.at == self.held.len() {
            if self.stuck {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            match request(&mut self.conn, CMD_POLL, 0, &[], self.timeout) {
                Ok(()) => {}
                Err(err) if err.raw_os_error() == Some(moto_rt::E_TIMED_OUT as i32) => {
                    self.stuck = true;
                    return Err(std::io::ErrorKind::TimedOut.into());
                }
                // The server is gone, or has refused this client.
                Err(_) => return Ok(0),
            }
            let page = self.conn.data();
            let len = get_len(page);
            self.held.clear();
            self.held.extend_from_slice(&page[DATA_AT..DATA_AT + len]);
            self.at = 0;
        }
        let len = buf.len().min(self.held.len() - self.at);
        buf[..len].copy_from_slice(&self.held[self.at..self.at + len]);
        self.at += len;
        Ok(len)
    }
}

// ---- the server ---------------------------------------------------------------

/// What the server has queued for one client, shared between the IPC thread
/// and that client's forwarder.
#[derive(Default)]
struct Outbox {
    bytes: VecDeque<u8>,
    /// The client has a poll outstanding.
    awaiting: bool,
    /// The forwarder stopped waiting for the client to take its last bytes.
    abandoned: bool,
}

#[derive(Default)]
struct Outboxes {
    map: Mutex<BTreeMap<ClientId, Outbox>>,
    changed: Condvar,
}

/// A client's two connections, known to the IPC thread only.
struct Peer {
    output: SysHandle,
    input: Option<SysHandle>,
    pid: u64,
    frames: Frames,
}

/// Register this server's name, then serve its clients on a thread of their
/// own. Fails when another server won the race for the name.
pub fn listen(events: Sender<Event>) -> std::io::Result<()> {
    let (started, outcome) = channel();
    std::thread::spawn(move || {
        let caps = own_capabilities();
        let setup = SysObj::create_ipc_pair(SysHandle::SELF, SysHandle::SELF, 0).and_then(
            |(ring, doorbell)| {
                LocalServer::new(
                    &service_name(caps),
                    ChannelSize::Small,
                    MAX_CONNECTIONS,
                    MAX_LISTENERS,
                )
                .map(|server| (ring, doorbell, server))
            },
        );
        match setup {
            Ok((ring, doorbell, server)) => {
                let _ = started.send(Ok(()));
                Ipc {
                    server,
                    caps,
                    ring,
                    doorbell,
                    events,
                    outboxes: Arc::new(Outboxes::default()),
                    ids: ClientIds::default(),
                    conns: BTreeMap::new(),
                    peers: BTreeMap::new(),
                }
                .run();
            }
            Err(err) => {
                let _ = started.send(Err(err));
            }
        }
    });
    match outcome.recv() {
        Ok(result) => result.map_err(os_error),
        Err(_) => Err(std::io::Error::other("the IPC thread died")),
    }
}

struct Ipc {
    server: LocalServer,
    caps: u64,
    /// Woken by forwarders; its other end, `doorbell`, is waited on here. An
    /// object wake stays latched until waited for, which a thread wake does
    /// not: an unrelated futex wait on this thread could consume that.
    ring: SysHandle,
    doorbell: SysHandle,
    events: Sender<Event>,
    outboxes: Arc<Outboxes>,
    ids: ClientIds,
    /// Every authenticated connection, and the client it belongs to.
    conns: BTreeMap<SysHandle, Option<ClientId>>,
    peers: BTreeMap<ClientId, Peer>,
}

impl Ipc {
    fn run(mut self) {
        loop {
            match self.server.wait(SysHandle::NONE, &[self.doorbell]) {
                Ok(ready) => {
                    for handle in ready {
                        if handle != self.doorbell {
                            self.serve(handle);
                        }
                    }
                }
                Err(dead) => {
                    for handle in dead {
                        self.forget(handle);
                    }
                }
            }
            self.deliver();
        }
    }

    fn serve(&mut self, handle: SysHandle) {
        let Some(conn) = self.server.get_connection(handle) else {
            return;
        };
        // Connect wakes us even if the peer sends nothing. Authenticate it
        // now so silent unauthorized clients cannot occupy the listener pool.
        if !self.conns.contains_key(&handle) {
            let allowed =
                SysObj::get_capabilities(handle).is_ok_and(|client| may_use(client, self.caps));
            if !allowed {
                if conn.have_req() {
                    self.refuse(handle, moto_rt::E_NOT_ALLOWED);
                } else {
                    conn.disconnect();
                }
                return;
            }
            self.conns.insert(handle, None);
        }

        let conn = self.server.get_connection(handle).unwrap();
        if !conn.have_req() {
            return;
        }
        let cmd = conn.req::<RequestHeader>().cmd;
        // Read once: the client can change its page at any time.
        let page = conn.data();
        let token = get_u64(page, TOKEN_AT);
        let data = page[DATA_AT..DATA_AT + get_len(page)].to_vec();

        match (cmd, self.conns[&handle]) {
            (CMD_OPEN_OUTPUT, None) => self.open_output(handle),
            (CMD_OPEN_INPUT, None) => self.open_input(handle, token),
            (CMD_INPUT, Some(id)) if self.peers[&id].input == Some(handle) => {
                self.input(handle, id, &data)
            }
            (CMD_POLL, Some(id)) if self.peers[&id].output == handle => {
                if let Some(outbox) = self.outboxes.map.lock().unwrap().get_mut(&id) {
                    outbox.awaiting = true;
                }
            }
            _ => self.refuse(handle, moto_rt::E_INVALID_ARGUMENT),
        }
    }

    fn open_output(&mut self, handle: SysHandle) {
        let Ok(pid) = SysObj::get_pid(handle) else {
            return self.refuse(handle, moto_rt::E_NOT_ALLOWED);
        };
        let id = self.ids.allocate();
        self.peers.insert(
            id,
            Peer {
                output: handle,
                input: None,
                pid,
                frames: Frames::new(),
            },
        );
        self.conns.insert(handle, Some(id));
        self.outboxes
            .map
            .lock()
            .unwrap()
            .insert(id, Outbox::default());
        self.reply(handle, moto_rt::E_OK, id, &[]);
    }

    /// Pair an input connection with the output connection `token` names.
    /// Both must come from one process, so the token need not be secret.
    fn open_input(&mut self, handle: SysHandle, token: u64) {
        let pid = SysObj::get_pid(handle).ok();
        let Some(peer) = self.peers.get_mut(&token) else {
            return self.refuse(handle, moto_rt::E_NOT_ALLOWED);
        };
        if peer.input.is_some() || pid != Some(peer.pid) {
            return self.refuse(handle, moto_rt::E_NOT_ALLOWED);
        }
        peer.input = Some(handle);
        self.conns.insert(handle, Some(token));

        let (out, outbox) = channel();
        let outboxes = self.outboxes.clone();
        let ring = self.ring;
        let farewell = std::thread::spawn(move || forward(token, outbox, outboxes, ring));
        let _ = self.events.send(Event::ClientArrived(Client {
            id: token,
            out,
            farewell,
        }));
        self.reply(handle, moto_rt::E_OK, 0, &[]);
    }

    fn input(&mut self, handle: SysHandle, id: ClientId, data: &[u8]) {
        let peer = self.peers.get_mut(&id).unwrap();
        peer.frames.feed(data);
        while let Some(message) = peer.frames.take::<ToServer>() {
            if let Some(message) = message {
                let _ = self.events.send(Event::FromClient(id, message));
            }
        }
        if peer.frames.is_broken() {
            self.refuse(handle, moto_rt::E_INVALID_ARGUMENT);
        } else {
            self.reply(handle, moto_rt::E_OK, 0, &[]);
        }
    }

    fn reply(&mut self, handle: SysHandle, result: ErrorCode, token: u64, data: &[u8]) {
        let Some(conn) = self.server.get_connection(handle) else {
            return;
        };
        conn.resp::<ResponseHeader>().result = result;
        let page = conn.data_mut();
        put_u64(page, TOKEN_AT, token);
        put_len(page, data.len());
        page[DATA_AT..DATA_AT + data.len()].copy_from_slice(data);
        if conn.finish_rpc().is_err() {
            self.forget(handle);
        }
    }

    /// Answer `handle` with an error and close it, with its client.
    fn refuse(&mut self, handle: SysHandle, result: ErrorCode) {
        self.reply(handle, result, 0, &[]);
        if let Some(conn) = self.server.get_connection(handle) {
            conn.disconnect();
        }
        self.forget(handle);
    }

    /// A connection is gone: its client goes with it.
    fn forget(&mut self, handle: SysHandle) {
        if let Some(Some(id)) = self.conns.remove(&handle) {
            self.end(id);
        }
    }

    fn end(&mut self, id: ClientId) {
        let Some(peer) = self.peers.remove(&id) else {
            return;
        };
        for handle in std::iter::once(peer.output).chain(peer.input) {
            self.conns.remove(&handle);
            if let Some(conn) = self.server.get_connection(handle) {
                conn.disconnect();
            }
        }
        // Only a paired client was announced.
        if peer.input.is_some() {
            let _ = self.events.send(Event::ClientGone(id));
        }
        self.outboxes.map.lock().unwrap().remove(&id);
        self.outboxes.changed.notify_all();
    }

    /// Answer outstanding polls with bytes, and end clients whose farewell
    /// deadline expired. A final poll alone does not acknowledge the exit.
    fn deliver(&mut self) {
        let mut finished = Vec::new();
        let mut failed = Vec::new();
        {
            let mut map = self.outboxes.map.lock().unwrap();
            for (id, outbox) in map.iter_mut() {
                if outbox.awaiting && !outbox.bytes.is_empty() {
                    let len = outbox.bytes.len().min(DATA_MAX);
                    let chunk: Vec<u8> = outbox.bytes.drain(..len).collect();
                    outbox.awaiting = false;
                    let output = self.peers[id].output;
                    let Some(conn) = self.server.get_connection(output) else {
                        failed.push(output);
                        continue;
                    };
                    conn.resp::<ResponseHeader>().result = moto_rt::E_OK;
                    let page = conn.data_mut();
                    put_len(page, chunk.len());
                    page[DATA_AT..DATA_AT + chunk.len()].copy_from_slice(&chunk);
                    if conn.finish_rpc().is_err() {
                        failed.push(output);
                    }
                }
                // The reader can poll again before the relay processes Exit.
                // Keep input alive until the client closes or farewell expires.
                if outbox.abandoned {
                    finished.push(*id);
                }
            }
        }
        self.outboxes.changed.notify_all();
        for handle in failed {
            self.forget(handle);
        }
        for id in finished {
            self.end(id);
        }
    }
}

/// Carry one client's messages from the server loop to the IPC thread, and
/// then, like the TCP writer, wait a bounded time for the client to take the
/// last of them.
fn forward(id: ClientId, messages: Receiver<ToClient>, outboxes: Arc<Outboxes>, ring: SysHandle) {
    while let Ok(message) = messages.recv() {
        if let Some(outbox) = outboxes.map.lock().unwrap().get_mut(&id) {
            outbox.bytes.extend(proto::encode(&message));
        }
        let _ = SysCpu::wake(ring);
    }

    let deadline = Instant::now() + crate::server::FAREWELL;
    let mut map = outboxes.map.lock().unwrap();
    while map.contains_key(&id) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            if let Some(outbox) = map.get_mut(&id) {
                outbox.abandoned = true;
            }
            let _ = SysCpu::wake(ring);
            return;
        }
        map = outboxes.changed.wait_timeout(map, left).unwrap().0;
    }
}
