use std::mem::size_of;

use moto_ipc::sync::*;
use moto_sys::SysHandle;
use moto_sys::SysRay;

mod io_thread;

#[derive(Clone)]
struct Connection {
    tag: String,
    tag_id: u64,
    handle: SysHandle,
}

struct LogRecord {
    handle: SysHandle,
    log_level: u8,
    tag_id: u64,
    timestamp: u64,
    msg: String,
}

struct LogServer {
    ipc_server: LocalServer,
    sender: std::sync::mpsc::Sender<io_thread::Msg>,
    next_tag_id: u64,
}

impl LogServer {
    fn process_connect_request(
        conn: &mut LocalServerConnection,
        sender: &std::sync::mpsc::Sender<io_thread::Msg>,
        next_tag_id: &mut u64,
    ) -> Result<(), ()> {
        use moto_log::implementation::*;
        let req = unsafe {
            (conn.data().as_ptr() as *const ConnectRequest)
                .as_ref()
                .unwrap()
        };
        if req.header.cmd != CMD_CONNECT || req.header.ver != 0 {
            SysRay::log("Bad ConnectRequest.").ok();
            return Err(());
        }

        if (req.payload_size as usize) > moto_log::MAX_TAG_LEN {
            return Err(());
        }

        let tag_bytes = &conn.data()[size_of::<ConnectRequest>()
            ..(size_of::<ConnectRequest>() + (req.payload_size as usize))];
        let Ok(tag) = std::str::from_utf8(tag_bytes) else {
            SysRay::log("Bad tag.").ok();
            return Err(());
        };

        let tag_id = *next_tag_id;
        *next_tag_id += 1;

        let conn_obj = Connection {
            tag_id,
            tag: tag.to_owned(),
            handle: conn.handle(),
        };

        // We offload most processing to a separate IO thread to respond faster.
        sender
            .send(io_thread::Msg::NewConnection(conn_obj))
            .unwrap();

        let resp = unsafe {
            (conn.data_mut().as_ptr() as *mut ConnectResponse)
                .as_mut()
                .unwrap()
        };
        resp.tag_id = tag_id;
        resp.header.result = 0;

        Ok(())
    }

    fn process_log_request(
        conn: &mut LocalServerConnection,
        sender: &std::sync::mpsc::Sender<io_thread::Msg>,
    ) -> Result<(), ()> {
        use moto_log::implementation::*;

        let req = unsafe {
            (conn.data().as_ptr() as *const LogRequest)
                .as_ref()
                .unwrap()
        };
        assert_eq!(req.header.cmd, CMD_LOG);

        if req.header.ver != 0 {
            return Err(());
        }

        let payload_bytes = &conn.data()
            [size_of::<LogRequest>()..(size_of::<LogRequest>() + (req.payload_size as usize))];

        let payload = std::str::from_utf8(payload_bytes).map_err(|_| ())?;

        let record = LogRecord {
            handle: conn.handle(),
            log_level: req.log_level,
            tag_id: req.tag_id,
            timestamp: req.timestamp,
            msg: payload.to_owned(),
        };

        // We offload most processing to a separate IO thread to respond faster.
        sender.send(io_thread::Msg::Record(record)).unwrap();

        let resp = unsafe {
            (conn.data_mut().as_ptr() as *mut LogResponse)
                .as_mut()
                .unwrap()
        };
        resp.header.result = 0;

        Ok(())
    }

    fn process_ipc(&mut self, waker: SysHandle) {
        use moto_log::implementation::*;

        let LogServer {
            sender,
            ipc_server,
            next_tag_id,
        } = self;

        let conn = ipc_server.get_connection(waker).unwrap();
        assert!(conn.connected());
        if !conn.have_req() {
            return;
        }

        let cmd = unsafe { conn.raw_channel().get::<RequestHeader>().cmd };

        let res = match cmd {
            CMD_LOG => Self::process_log_request(conn, sender),
            CMD_CONNECT => Self::process_connect_request(conn, sender, next_tag_id),
            _ => Err(()),
        };

        if res.is_err() && conn.connected() {
            unsafe {
                conn.raw_channel().get_mut::<ResponseHeader>().result = moto_rt::E_INVALID_ARGUMENT
            };
        }

        let _ = conn.finish_rpc();
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
                    for conn in dropped_conns {
                        self.sender
                            .send(io_thread::Msg::DroppedConnection(conn))
                            .unwrap();
                    }
                }
            }
        }
    }

    fn start() -> ! {
        // We offload most processing to a separate IO thread to respond faster.
        let (sender, receiver) = std::sync::mpsc::channel();
        io_thread::spawn(receiver);

        let mut log_server = LogServer {
            ipc_server: LocalServer::new("sys-log", ChannelSize::Small, 10, 2).unwrap(),
            next_tag_id: 1,
            sender,
        };

        #[cfg(debug_assertions)]
        SysRay::log("sys-log started").ok();
        log_server.run()
    }
}

fn main() {
    LogServer::start()
}
