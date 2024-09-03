// Provides a centralized implementation of log interface/facade for motor-os.
// Somewhat outdated/unused.

// TODO: at the moment moto-log is very simple and rather slow. A faster
// implementation could cache logs locally per-cpu or per-thread
// and flush to moto-logger asynchronously.

use std::{
    fmt::Display,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use implementation::{GetTailEntriesRequest, GetTailEntriesResponse};
use log::Record;
use moto_ipc::sync::ClientConnection;

pub const LOG_ERROR_EXIT_CODE: i32 = 0xbad106;

#[derive(Debug)]
pub struct LogEntry {
    pub tag: String,
    pub timestamp: std::time::SystemTime,
    pub level: u8,
    pub msg: String,
}

fn log_level_to_str(level: u8) -> &'static str {
    match level {
        0 => "FATAL",
        1 => "ERROR",
        2 => "WARN",
        3 => "INFO",
        4 => "DEBUG",
        5 => "TRACE",
        _ => "UNKNOWN",
    }
}

impl Display for LogEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            moto_rt::time::UtcDateTime::from_unix_nanos(
                self.timestamp
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ),
            self.tag,
            log_level_to_str(self.level),
            self.msg
        )
    }
}

struct BasicLogger {
    _tag: String,
    tag_id: u64,
    enabled: AtomicBool,
    conn: spin::Mutex<ClientConnection>,
}

impl Drop for BasicLogger {
    fn drop(&mut self) {
        todo!("disconnect") // This seems to never happen.
    }
}

static BASIC_LOGGER: AtomicUsize = AtomicUsize::new(0);

impl log::Log for BasicLogger {
    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let mut conn = self.conn.lock();
            implementation::LogRequest::prepare(conn.data_mut(), self.tag_id, record);
            if conn.do_rpc(None).is_err()
                || implementation::LogResponse::parse(conn.data()).is_err()
            {
                panic!("error logging: what do we do here?");
                // std::process::exit(LOG_ERROR_EXIT_CODE);
            }
        }
    }

    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    fn flush(&self) {}
}

pub type StdError = Box<dyn std::error::Error + Send + Sync>;

pub fn init(tag: &str) -> Result<(), StdError> {
    let mut conn = ClientConnection::new(moto_ipc::sync::ChannelSize::Small)
        .map_err(|e| StdError::from(format!("ClientConnection failed (1) with error {:?}.", e)))?;

    conn.connect("sys-log")
        .map_err(|e| StdError::from(format!("ClientConnection failed (2) with error {:?}.", e)))?;

    implementation::ConnectRequest::prepare(conn.data_mut(), tag);
    conn.do_rpc(None)
        .map_err(|e| StdError::from(format!("ClientConnection failed (3) with error {:?}.", e)))?;

    let tag_id = implementation::ConnectResponse::parse(conn.data())
        .map_err(|e| StdError::from(format!("ClientConnection failed (4) with error {:?}.", e)))?;

    let logger = Box::leak(Box::new(BasicLogger {
        _tag: tag.to_owned(),
        tag_id,
        enabled: AtomicBool::new(true),
        conn: spin::Mutex::new(conn),
    }));

    assert_eq!(
        0,
        BASIC_LOGGER.swap(logger as *mut _ as usize, Ordering::Relaxed)
    );

    log::set_logger(logger).map_err(|err| StdError::from(format!("{err}")))
}

pub fn get_tail_entries() -> Result<Vec<LogEntry>, StdError> {
    // Safe because BASIC_LOGGER is either null or points to a valid BasicLogger.
    let logger =
        match unsafe { (BASIC_LOGGER.load(Ordering::Relaxed) as *const BasicLogger).as_ref() } {
            Some(obj) => obj,
            None => {
                return Err(StdError::from(format!("Moturus logging not initialized.")));
            }
        };

    let mut conn = logger.conn.lock();
    GetTailEntriesRequest::prepare(
        conn.data_mut(),
        implementation::level_as_u8(log::Level::Trace),
        0,
    );

    conn.do_rpc(None)
        .map_err(|e| StdError::from(format!("GetUtf8TailRequest failed with error {:?}.", e)))?;

    let resp = match GetTailEntriesResponse::parse(conn.data()) {
        Ok(vec) => vec,
        Err(e) => return Err(StdError::from(format!("Bad GetUtf8TailResponse: {:?}", e))),
    };

    let mut result = vec![];
    result.reserve(resp.len());

    for idx in (0..resp.len()).rev() {
        let entry = &resp[idx];
        result.push(LogEntry {
            tag: entry.tag_id.to_string(),
            // timestamp: moto_sys_rt::time::system_time_from_u64(entry.timestamp),
            timestamp: std::time::UNIX_EPOCH + std::time::Duration::from_nanos(entry.timestamp),
            level: entry.log_level,
            msg: std::str::from_utf8(entry.bytes).unwrap().to_owned(),
        });
    }

    Ok(result)
}

// Implementation details.
#[doc(hidden)]
pub mod implementation {
    use moto_ipc::sync::{RequestHeader, ResponseHeader};
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
        // log::Level has repr(usize)
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
            assert_eq!(prefix.len(), 0);
            assert!(data.len() > 0);

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
            assert_eq!(prefix.len(), 0);

            match data[0].header.result {
                0 => Ok(data[0].tag_id),
                e => Err(e.into()),
            }
        }
    }

    #[repr(C, align(8))]
    pub struct LogRequest {
        pub header: moto_ipc::sync::RequestHeader,
        pub log_level: u8,
        pub payload_size: u32,
        pub tag_id: u64,
        pub timestamp: u64,
    }

    impl LogRequest {
        pub fn prepare(buffer: &mut [u8], tag_id: u64, record: &log::Record) {
            let buf_len = buffer.len();

            // Safe because Self is POD, so transmuting into it is safe.
            let (prefix, data, _) = unsafe { buffer.align_to_mut::<Self>() };
            assert_eq!(prefix.len(), 0);
            assert!(data.len() > 0);

            let req = &mut data[0];
            req.header.cmd = CMD_LOG;
            req.header.ver = 0;
            req.log_level = level_as_u8(record.level());
            req.tag_id = tag_id;
            // req.timestamp = std::time::SystemTime::now()
            //     .duration_since(std::time::UNIX_EPOCH)
            //     .unwrap()
            //     .as_nanos() as u64;
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
                e => Err(e.into()),
            }
        }
    }

    #[repr(C, align(8))]
    pub struct DisconnectRequest {
        pub header: RequestHeader,
    }

    #[repr(C, align(8))]
    pub struct DisconnectResponse {
        pub header: ResponseHeader,
    }

    #[repr(C, align(8))]
    pub struct GetTailEntriesRequest {
        pub header: RequestHeader,
        pub log_level: u8,
        pub _pad: u32,
        pub tag_id: u64,
    }

    impl GetTailEntriesRequest {
        pub fn prepare(buffer: &mut [u8], log_level: u8, tag_id: u64) {
            // Safe because Self is POD, so transmuting into it is safe.
            let (prefix, data, _) = unsafe { buffer.align_to_mut::<Self>() };
            assert_eq!(prefix.len(), 0);
            assert!(data.len() > 0);

            let req = &mut data[0];
            req.header.cmd = CMD_GET_TAIL_ENTRIES;
            req.header.ver = 0;
            req.log_level = log_level;
            req.tag_id = tag_id;
        }
    }

    #[repr(C, align(8))]
    pub struct GetTailEntriesResponse {
        pub header: ResponseHeader,
        pub num_entries: u32, // Size of the payload.
    }

    pub struct LogEntry<'a> {
        pub tag_id: u64,
        pub timestamp: u64,
        pub log_level: u8,
        pub bytes: &'a [u8],
    }

    impl GetTailEntriesResponse {
        pub fn parse<'a>(buffer: &'a [u8]) -> Result<Vec<LogEntry<'a>>, ErrorCode> {
            assert!(buffer.len() >= size_of::<Self>());

            // Safe because Self is POD, so transmuting into it is safe.
            let (prefix, data, _) = unsafe { buffer.align_to::<Self>() };
            assert_eq!(prefix.len(), 0);

            match data[0].header.result {
                0 => {
                    let mut pos = size_of::<Self>();
                    let num_entries = data[0].num_entries as usize;
                    let mut result = vec![];
                    result.reserve(num_entries);

                    for _ in 0..num_entries {
                        pos = (pos + 7) & !7; // Align to 8 bytes.
                        if pos >= buffer.len() {
                            moto_sys::SysRay::log("bad tail entries response (1)").ok();
                            return Err(ErrorCode::InternalError);
                        }
                        let curr_buffer = &buffer[pos..];
                        if curr_buffer.len() < size_of::<LogEntryHeader>() {
                            moto_sys::SysRay::log("bad tail entries response (2)").ok();
                            return Err(ErrorCode::InternalError);
                        }

                        // Safe because we aligned curr_buffer properly and ensured it is large enough.
                        let header = unsafe {
                            (curr_buffer.as_ptr() as *const LogEntryHeader)
                                .as_ref()
                                .unwrap()
                        };

                        if pos + size_of::<LogEntryHeader>() + (header.payload_size as usize)
                            > buffer.len()
                        {
                            moto_sys::SysRay::log("bad tail entries response (3)").ok();
                            return Err(ErrorCode::InternalError);
                        }

                        let bytes = &curr_buffer[size_of::<LogEntryHeader>()
                            ..(size_of::<LogEntryHeader>() + (header.payload_size as usize))];

                        result.push(LogEntry {
                            tag_id: header.tag_id,
                            timestamp: header.timestamp,
                            log_level: header.log_level,
                            bytes,
                        });

                        pos += size_of::<LogEntryHeader>() + (header.payload_size as usize);
                    }

                    Ok(result)
                }
                e => Err(ErrorCode::from(e)),
            }
        }
    }

    // When querying the server, e.g. via CMD_GET_UTF8_TAIL, this precedes raw bytes.
    #[repr(C, align(8))]
    pub struct LogEntryHeader {
        pub tag_id: u64,
        pub timestamp: u64,
        pub payload_size: u32,
        pub log_level: u8,
    }
}
