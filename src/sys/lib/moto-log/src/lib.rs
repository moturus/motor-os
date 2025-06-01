//! Provides a centralized implementation of log interface/facade for motor-os.
//! See sys-log for more details on where log entries go.

// TODO: at the moment moto-log is very simple (synchronous) and slow. A faster
// implementation could cache logs locally per-cpu or per-thread
// and flush to moto-logger asynchronously.
//
// TL;DR: use it for logging, not tracing.

use std::{
    fmt::Display,
    sync::atomic::{AtomicUsize, Ordering},
};

use log::Record;
use moto_ipc::sync::ClientConnection;

pub const MAX_TAG_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub tag: String,
    pub timestamp: moto_rt::time::Instant,
    pub level: u8,
    pub msg: String,
}

impl LogEntry {
    pub fn level(&self) -> log::Level {
        match self.level {
            1 => log::Level::Error,
            2 => log::Level::Warn,
            3 => log::Level::Info,
            4 => log::Level::Debug,
            5 => log::Level::Trace,
            x => panic!("bad log level {x}"),
        }
    }
}

impl Display for LogEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            // Safety: todo: make it more precise, maybe by converting
            // from instant to systemtime in sys-log.
            unsafe { moto_rt::time::UtcDateTime::from_instant(self.timestamp) },
            self.tag,
            self.level(),
            self.msg
        )
    }
}

struct MotoLogger {
    tag_id: u64,
    conn: std::sync::Mutex<ClientConnection>,
}

static MOTO_LOGGER: AtomicUsize = AtomicUsize::new(0);

impl log::Log for MotoLogger {
    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let mut conn = self.conn.lock().unwrap();
            implementation::LogRequest::prepare(conn.data_mut(), self.tag_id, record);
            if conn.do_rpc(None).is_err()
                || implementation::LogResponse::parse(conn.data()).is_err()
            {
                todo!("implement fallback logging: to stderr, if available, or to the kernel (SysRay)");
            }
        }
    }

    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn flush(&self) {}
}

pub type StdError = Box<dyn std::error::Error + Send + Sync>;

/// Install Motor OS system logger as the default logger in the process.
pub fn init(tag: &str) -> Result<(), StdError> {
    if tag.len() > MAX_TAG_LEN {
        return Err(StdError::from("Tag string is too long."));
    }

    let mut conn = ClientConnection::new(moto_ipc::sync::ChannelSize::Small)
        .map_err(|e| StdError::from(format!("ClientConnection failed (1) with error {e:?}.")))?;

    conn.connect("sys-log")
        .map_err(|e| StdError::from(format!("ClientConnection failed (2) with error {e:?}.")))?;

    implementation::ConnectRequest::prepare(conn.data_mut(), tag);
    conn.do_rpc(None)
        .map_err(|e| StdError::from(format!("ClientConnection failed (3) with error {e:?}.")))?;

    let tag_id = implementation::ConnectResponse::parse(conn.data())
        .map_err(|e| StdError::from(format!("ClientConnection failed (4) with error {e:?}.")))?;

    let logger = Box::leak(Box::new(MotoLogger {
        tag_id,
        conn: std::sync::Mutex::new(conn),
    }));

    assert_eq!(
        0,
        MOTO_LOGGER.swap(logger as *mut _ as usize, Ordering::AcqRel)
    );

    log::set_logger(logger)
        .map_err(|err| StdError::from(format!("{err}")))
        .map(|()| log::set_max_level(log::LevelFilter::Info))
}

// Implementation details.
#[doc(hidden)]
pub mod implementation {
    // use moto_ipc::sync::{RequestHeader, ResponseHeader};
    use moto_sys::ErrorCode;
    use std::mem::size_of;

    pub const CMD_CONNECT: u16 = 1;
    pub const CMD_LOG: u16 = 2;
    pub const CMD_DISCONNECT: u16 = 3;
    pub const CMD_GET_TAIL_ENTRIES: u16 = 4;

    pub const LOG_LEVEL_FATAL: u8 = 0;
    pub const LOG_LEVEL_ERROR: u8 = 1;
    pub const LOG_LEVEL_WARN: u8 = 2;
    pub const LOG_LEVEL_INFO: u8 = 3;
    pub const LOG_LEVEL_DEBUG: u8 = 4;
    pub const LOG_LEVEL_TRACE: u8 = 5;

    pub fn level_as_u8(level: log::Level) -> u8 {
        level as usize as u8
    }

    #[repr(C, align(8))]
    pub struct ConnectRequest {
        pub header: moto_ipc::sync::RequestHeader,
        pub payload_size: u8, // The tag is the payload.
    }

    impl ConnectRequest {
        pub fn prepare(buffer: &mut [u8], tag: &str) {
            assert!(tag.len() <= u8::MAX as usize);
            assert!(buffer.len() >= size_of::<Self>() + tag.len());

            // Safe because Self is POD, so transmuting into it is safe.
            let (prefix, data, _) = unsafe { buffer.align_to_mut::<Self>() };
            assert!(prefix.is_empty());
            assert!(!data.is_empty());

            let req = &mut data[0];
            req.header.cmd = CMD_CONNECT;
            req.header.ver = 0;
            req.payload_size = tag.len() as u8;

            let payload = &mut buffer[size_of::<Self>()..(size_of::<Self>() + tag.len())];
            payload.copy_from_slice(tag.as_bytes());
        }
    }

    #[repr(C, align(8))]
    pub struct ConnectResponse {
        pub header: moto_ipc::sync::ResponseHeader,
        pub tag_id: u64, // ID associated with the tag.
    }

    impl ConnectResponse {
        pub fn parse(buffer: &[u8]) -> Result<u64, ErrorCode> {
            assert!(buffer.len() >= size_of::<Self>());

            // Safe because Self is POD, so transmuting into it is safe.
            let (prefix, data, _) = unsafe { buffer.align_to::<Self>() };
            assert!(prefix.is_empty());

            match data[0].header.result {
                0 => Ok(data[0].tag_id),
                e => Err(e),
            }
        }
    }

    #[repr(C, align(8))]
    pub struct LogRequest {
        pub header: moto_ipc::sync::RequestHeader,
        pub log_level: u8,
        pub payload_size: u32,
        pub tag_id: u64,
        pub timestamp: u64, // Instant::as_u64().
    }

    impl LogRequest {
        pub fn prepare(buffer: &mut [u8], tag_id: u64, record: &log::Record) {
            let buf_len = buffer.len();

            // Safe because Self is POD, so transmuting into it is safe, and because we validate
            // that prefix is empty (i.e. that the buffer is already properly aligned).
            let (prefix, data, _) = unsafe { buffer.align_to_mut::<Self>() };
            assert!(prefix.is_empty());
            assert!(!data.is_empty());

            let req = &mut data[0];
            req.header.cmd = CMD_LOG;
            req.header.ver = 0;
            req.log_level = level_as_u8(record.level());
            req.tag_id = tag_id;
            req.timestamp = moto_rt::time::Instant::now().as_u64();

            let payload = format!(
                "{}:{} - {}",
                record.target(),
                record.line().unwrap_or(0),
                record.args()
            );

            let payload_size = std::cmp::min(buf_len - size_of::<Self>(), payload.len());
            req.payload_size = payload_size as u32;

            let payload_buf = &mut buffer[size_of::<Self>()..(size_of::<Self>() + payload_size)];
            payload_buf.copy_from_slice(&payload.as_bytes()[0..payload_size]);
        }
    }

    #[repr(C, align(8))]
    pub struct LogResponse {
        pub header: moto_ipc::sync::ResponseHeader,
    }

    impl LogResponse {
        pub fn parse(buffer: &[u8]) -> Result<(), ErrorCode> {
            assert!(buffer.len() >= size_of::<Self>());

            // Safe because Self is POD, so transmuting into it is safe.
            let (prefix, data, _) = unsafe { buffer.align_to::<Self>() };
            assert_eq!(prefix.len(), 0);

            match data[0].header.result {
                0 => Ok(()),
                e => Err(e),
            }
        }
    }
}
