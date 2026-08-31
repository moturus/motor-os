use crate::io_thread;
use moto_ipc::sync::*;
use moto_sys::{SysHandle, SysObj};
use std::collections::{HashMap, HashSet};
use std::mem::size_of;

#[derive(Clone)]
pub struct Connection {
    pub tag: String,
    pub canonical_tag: String,
    pub tag_id: u64,
    pub handle: SysHandle,
}

pub struct LogRecord {
    pub handle: SysHandle,
    pub log_level: u8,
    pub tag_id: u64,
    pub timestamp: u64,
    pub msg: String,
}

pub struct RawLogRecord {
    pub handle: SysHandle,
    pub tag_id: u64,
    pub data: Vec<u8>,
}

struct Registration {
    tag_id: u64,
    canonical_tag: String,
}

struct RpcOutcome {
    result: u16,
    disconnect: bool,
}

impl RpcOutcome {
    const fn keep(result: u16) -> Self {
        Self {
            result,
            disconnect: false,
        }
    }

    const fn disconnect(result: u16) -> Self {
        Self {
            result,
            disconnect: true,
        }
    }
}

pub struct LogServer {
    ipc_server: LocalServer,
    sender: std::sync::mpsc::SyncSender<io_thread::Msg>,
    next_tag_id: u64,
    registrations: HashMap<SysHandle, Registration>,
    active_tags: HashMap<String, SysHandle>,
    closing: HashSet<SysHandle>,
}

fn canonicalize_tag(tag: &str) -> String {
    tag.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn remove_registration(
    handle: SysHandle,
    registrations: &mut HashMap<SysHandle, Registration>,
    active_tags: &mut HashMap<String, SysHandle>,
    sender: &std::sync::mpsc::SyncSender<io_thread::Msg>,
) {
    let Some(registration) = registrations.remove(&handle) else {
        return;
    };
    if active_tags.get(&registration.canonical_tag) == Some(&handle) {
        active_tags.remove(&registration.canonical_tag);
    }
    let _ = sender.send(io_thread::Msg::DroppedConnection(handle));
}

impl LogServer {
    fn process_connect_request(
        conn: &mut LocalServerConnection,
        caps: u64,
        sender: &std::sync::mpsc::SyncSender<io_thread::Msg>,
        next_tag_id: &mut u64,
        registrations: &mut HashMap<SysHandle, Registration>,
        active_tags: &mut HashMap<String, SysHandle>,
    ) -> RpcOutcome {
        use moto_log::implementation::*;

        if registrations.contains_key(&conn.handle()) {
            return RpcOutcome::disconnect(moto_rt::E_INVALID_ARGUMENT);
        }
        let req = conn.req::<ConnectRequest>();
        let payload_size = req.payload_size as usize;
        let Some(payload_end) = size_of::<ConnectRequest>().checked_add(payload_size) else {
            return RpcOutcome::disconnect(moto_rt::E_INVALID_ARGUMENT);
        };
        if req.header.ver != 0
            || payload_size > moto_log::MAX_TAG_LEN
            || payload_end > conn.channel_size()
        {
            return RpcOutcome::disconnect(moto_rt::E_INVALID_ARGUMENT);
        }

        let tag_bytes = &conn.data()[size_of::<ConnectRequest>()..payload_end];
        let Ok(tag) = std::str::from_utf8(tag_bytes) else {
            return RpcOutcome::disconnect(moto_rt::E_INVALID_ARGUMENT);
        };
        let canonical_tag = canonicalize_tag(tag);
        if canonical_tag == "kernel" && caps & moto_sys::caps::CAP_IO_MANAGER == 0 {
            return RpcOutcome::disconnect(moto_rt::E_NOT_ALLOWED);
        }
        if let Some(active_handle) = active_tags.get(&canonical_tag).copied() {
            match SysObj::get_capabilities(active_handle) {
                Err(moto_rt::E_BAD_HANDLE) => {
                    remove_registration(active_handle, registrations, active_tags, sender);
                }
                _ => return RpcOutcome::keep(moto_rt::E_ALREADY_IN_USE),
            }
        }

        let tag_id = *next_tag_id;
        let Some(following_tag_id) = tag_id.checked_add(1) else {
            return RpcOutcome::disconnect(moto_rt::E_INTERNAL_ERROR);
        };
        let connection = Connection {
            tag_id,
            tag: tag.to_owned(),
            canonical_tag: canonical_tag.clone(),
            handle: conn.handle(),
        };
        if sender
            .send(io_thread::Msg::NewConnection(connection))
            .is_err()
        {
            return RpcOutcome::disconnect(moto_rt::E_INTERNAL_ERROR);
        }

        *next_tag_id = following_tag_id;
        active_tags.insert(canonical_tag.clone(), conn.handle());
        registrations.insert(
            conn.handle(),
            Registration {
                tag_id,
                canonical_tag,
            },
        );
        conn.resp::<ConnectResponse>().tag_id = tag_id;
        RpcOutcome::keep(moto_rt::E_OK)
    }

    fn process_log_request(
        conn: &LocalServerConnection,
        sender: &std::sync::mpsc::SyncSender<io_thread::Msg>,
        registrations: &HashMap<SysHandle, Registration>,
    ) -> RpcOutcome {
        use moto_log::implementation::*;

        let Some(registration) = registrations.get(&conn.handle()) else {
            return RpcOutcome::disconnect(moto_rt::E_INVALID_ARGUMENT);
        };
        let req = conn.req::<LogRequest>();
        let payload_size = req.payload_size as usize;
        let Some(payload_end) = size_of::<LogRequest>().checked_add(payload_size) else {
            return RpcOutcome::disconnect(moto_rt::E_INVALID_ARGUMENT);
        };
        if req.header.ver != 0
            || req.tag_id != registration.tag_id
            || payload_end > conn.channel_size()
        {
            return RpcOutcome::disconnect(moto_rt::E_INVALID_ARGUMENT);
        }
        let Ok(payload) = std::str::from_utf8(&conn.data()[size_of::<LogRequest>()..payload_end])
        else {
            return RpcOutcome::disconnect(moto_rt::E_INVALID_ARGUMENT);
        };

        let record = LogRecord {
            handle: conn.handle(),
            log_level: req.log_level,
            tag_id: req.tag_id,
            timestamp: req.timestamp,
            msg: payload.to_owned(),
        };
        if sender.send(io_thread::Msg::Record(record)).is_err() {
            return RpcOutcome::disconnect(moto_rt::E_INTERNAL_ERROR);
        }
        RpcOutcome::keep(moto_rt::E_OK)
    }

    fn process_raw_log_request(
        conn: &LocalServerConnection,
        caps: u64,
        sender: &std::sync::mpsc::SyncSender<io_thread::Msg>,
        registrations: &HashMap<SysHandle, Registration>,
    ) -> RpcOutcome {
        use moto_log::implementation::*;

        let Some(registration) = registrations.get(&conn.handle()) else {
            return RpcOutcome::disconnect(moto_rt::E_INVALID_ARGUMENT);
        };
        if registration.canonical_tag != "kernel" || caps & moto_sys::caps::CAP_IO_MANAGER == 0 {
            return RpcOutcome::disconnect(moto_rt::E_NOT_ALLOWED);
        }
        let req = conn.req::<RawLogRequest>();
        let payload_size = req.payload_size as usize;
        let Some(payload_end) = size_of::<RawLogRequest>().checked_add(payload_size) else {
            return RpcOutcome::disconnect(moto_rt::E_INVALID_ARGUMENT);
        };
        if req.header.ver != 0
            || req.tag_id != registration.tag_id
            || payload_end > conn.channel_size()
        {
            return RpcOutcome::disconnect(moto_rt::E_INVALID_ARGUMENT);
        }

        let record = RawLogRecord {
            handle: conn.handle(),
            tag_id: req.tag_id,
            data: conn.data()[size_of::<RawLogRequest>()..payload_end].to_vec(),
        };
        if sender.send(io_thread::Msg::RawRecord(record)).is_err() {
            return RpcOutcome::disconnect(moto_rt::E_INTERNAL_ERROR);
        }
        RpcOutcome::keep(moto_rt::E_OK)
    }

    fn process_ipc(&mut self, waker: SysHandle) {
        use moto_log::implementation::*;

        let LogServer {
            sender,
            ipc_server,
            next_tag_id,
            registrations,
            active_tags,
            closing,
        } = self;
        if closing.remove(&waker) {
            remove_registration(waker, registrations, active_tags, sender);
            if let Some(conn) = ipc_server.get_connection(waker) {
                conn.disconnect();
            }
            return;
        }
        let Some(conn) = ipc_server.get_connection(waker) else {
            return;
        };
        if !conn.connected() || !conn.have_req() {
            return;
        }

        let outcome = match SysObj::get_capabilities(conn.handle()) {
            Ok(caps) if caps & moto_sys::caps::CAP_LOG != 0 => {
                match conn.req::<RequestHeader>().cmd {
                    CMD_CONNECT => Self::process_connect_request(
                        conn,
                        caps,
                        sender,
                        next_tag_id,
                        registrations,
                        active_tags,
                    ),
                    CMD_LOG => Self::process_log_request(conn, sender, registrations),
                    CMD_LOG_RAW => Self::process_raw_log_request(conn, caps, sender, registrations),
                    _ => RpcOutcome::disconnect(moto_rt::E_INVALID_ARGUMENT),
                }
            }
            _ => RpcOutcome::disconnect(moto_rt::E_NOT_ALLOWED),
        };

        conn.resp::<ResponseHeader>().result = outcome.result;
        if conn.finish_rpc().is_err() {
            remove_registration(waker, registrations, active_tags, sender);
            conn.disconnect();
        } else if outcome.disconnect {
            // Keep the endpoint alive until the peer has observed this reply.
            // Its next request or close only triggers cleanup; it is never
            // processed as another protocol operation.
            closing.insert(waker);
        }
    }

    fn run(&mut self) -> ! {
        loop {
            match self.ipc_server.wait(SysHandle::NONE, &[]) {
                Ok(wakers) => {
                    for waker in wakers {
                        self.process_ipc(waker);
                    }
                }
                Err(dropped_conns) => {
                    for handle in dropped_conns {
                        self.closing.remove(&handle);
                        remove_registration(
                            handle,
                            &mut self.registrations,
                            &mut self.active_tags,
                            &self.sender,
                        );
                    }
                }
            }
        }
    }

    pub fn start() -> ! {
        let (sender, receiver) = std::sync::mpsc::sync_channel(64);
        crate::io_thread::spawn(receiver);

        let mut log_server = LogServer {
            ipc_server: LocalServer::new("sys-log", ChannelSize::Small, 11, 2).unwrap(),
            next_tag_id: 1,
            sender,
            registrations: HashMap::new(),
            active_tags: HashMap::new(),
            closing: HashSet::new(),
        };

        #[cfg(debug_assertions)]
        moto_sys::SysRay::log("strobe::LogServer started").ok();

        log_server.run()
    }
}
