use crate::logging::{LogRecord, RawLogRecord};
use moto_io::fs::{AccessPermissions, EntryKind, FsClient, RolePermissions};
use moto_sys::SysHandle;
use std::{
    collections::{HashMap, VecDeque},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[path = "io_thread_tests.rs"]
pub mod tests;

// Only System strobe mutates this tree; lower roles submit records over IPC.
const LOG_DIR_PATH: &str = "/system/logs";
const LOG_FILE_MAX_BYTES: u64 = 4 * 1024 * 1024;
const MIN_AVAILABLE_BYTES: u64 = 50 * 1024 * 1024;
// Records wait here, per connection, while sys-io refuses writes under
// memory pressure; a drain writes them out once the flag is down.
const BACKLOG_CAPACITY: usize = 64 * 1024;
const DRAIN_INTERVAL: Duration = Duration::from_millis(100);
// A failed rotation step is retried this often: forever for kernel.log,
// this many times for other files, which are then switched off.
const ROTATION_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const ROTATION_RETRIES: u32 = 10;
const LOG_FILE_PERMISSIONS: RolePermissions = RolePermissions::new(
    AccessPermissions::Rw,
    AccessPermissions::R,
    AccessPermissions::None,
);

fn available_bytes() -> Option<u64> {
    let provider = moto_stats::Collector::provider_by_name("sys-io")?;
    let metric = moto_stats::Collector::describe(&provider)
        .ok()?
        .into_iter()
        .find(|metric| metric.name == "fs.available_bytes")?;
    moto_stats::Collector::read(&provider, metric.id, moto_stats::SCOPE_GLOBAL).ok()
}

fn oldest_previous_log() -> Option<PathBuf> {
    std::fs::read_dir(LOG_DIR_PATH)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let is_previous = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".prev"));
            if !is_previous || !entry.file_type().ok()?.is_file() {
                return None;
            }
            Some((entry.metadata().ok()?.modified().ok()?, path))
        })
        .min_by_key(|(modified, _)| *modified)
        .map(|(_, path)| path)
}

fn reclaim_previous_logs() {
    while available_bytes().is_some_and(|bytes| bytes < MIN_AVAILABLE_BYTES) {
        let Some(path) = oldest_previous_log() else {
            return;
        };
        if let Err(err) = std::fs::remove_file(&path) {
            moto_rt::moto_log!("Error deleting old log {}: {err:?}.", path.display());
            return;
        }
    }
}

/// Creates the file with the log permissions, over a fresh sys-io
/// connection that pressure refuses like any request.
fn create_log_file(name: &str) -> std::io::Result<()> {
    reclaim_previous_logs();
    moto_async::LocalRuntime::new()
        .block_on(async {
            let client = FsClient::connect()?;
            let (parent_id, kind) = client.stat(LOG_DIR_PATH).await?;
            if kind != EntryKind::Directory {
                return Err(moto_rt::Error::InvalidArgument);
            }
            client
                .create_entry_with_permissions(
                    parent_id,
                    EntryKind::File,
                    name,
                    LOG_FILE_PERMISSIONS,
                )
                .await?;
            Ok(())
        })
        .map_err(|err| std::io::Error::from_raw_os_error(err as u16 as i32))
}

fn exists(path: &Path) -> std::io::Result<bool> {
    match std::fs::exists(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        result => result,
    }
}

pub enum Msg {
    NewConnection(crate::logging::Connection),
    DroppedConnection(SysHandle),
    Record(LogRecord),
    RawRecord(RawLogRecord),
}

/// How far the file's replacement got. A failed step is retried by a later
/// drain, so an interrupted rotation resumes where it stopped. The first
/// open starts at `Idle` without a file and moves a previous file of the
/// tag aside the same way. Records wait in the backlog meanwhile.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Rotation {
    Idle,
    /// The path is vacant; the old file, if any, carries the `.prev` name.
    Renamed,
    /// The replacement exists at the path and is not open yet.
    Created,
}

struct PendingRecord {
    data: Vec<u8>,
    flush: bool,
}

impl PendingRecord {
    fn write_to(&mut self, file: &mut impl Write, unflushed: &mut bool) -> std::io::Result<usize> {
        let written = loop {
            match file.write(&self.data) {
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                result => break result?,
            }
        };
        if written == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        self.data.drain(..written);
        *unflushed |= self.flush;
        Ok(written)
    }
}

fn flush_pending(file: &mut impl Write, unflushed: &mut bool) -> std::io::Result<()> {
    if *unflushed {
        file.flush()?;
        *unflushed = false;
    }
    Ok(())
}

enum DrainError {
    Rotation(std::io::Error),
    Write(std::io::Error),
    Flush(std::io::Error),
}

// Existing file channels return this code directly, even if pressure has
// cleared by the time strobe receives the refusal.
fn is_pressure_refusal(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::OutOfMemory
        || err.raw_os_error() == Some(moto_rt::E_OUT_OF_MEMORY as i32)
}

// Errors and warnings are flushed; info, debug and trace are not.
fn flushes(log_level: u8) -> bool {
    matches!(log_level, 1 | 2)
}

struct Connection {
    tag: String,
    tag_id: u64,
    file_name: String,
    file_path: PathBuf,
    log_file: Option<std::fs::File>,
    log_file_size: u64,
    raw: bool,
    rotation: Rotation,
    rotation_failures: u32,
    retry_at: Option<Instant>,
    /// Records in order; the front one may be partly written already.
    backlog: VecDeque<PendingRecord>,
    backlog_bytes: usize,
    dropped: u64,
    unflushed: bool,
    disabled: bool,
}

impl Drop for Connection {
    fn drop(&mut self) {
        // One last drain; what it leaves behind is discarded, and the kernel
        // log says so instead of the file.
        self.drain();
        let lost = self.backlog.len() as u64 + self.dropped;
        if lost != 0 {
            moto_rt::moto_log!(
                "strobe: log '{}' closed with {lost} records unwritten; they are lost.",
                self.tag
            );
            return;
        }
        let now = moto_rt::time::UtcDateTime::now();
        self.submit(
            format!("{now}:I - stopped log for '{}'\n", self.tag).into_bytes(),
            true,
        );
    }
}

impl Connection {
    fn new(tag: String, canonical_tag: String, tag_id: u64) -> Self {
        let file_name = format!("{canonical_tag}.log");
        let mut connection = Self {
            tag,
            tag_id,
            file_path: Path::new(LOG_DIR_PATH).join(&file_name),
            file_name,
            log_file: None,
            log_file_size: 0,
            raw: canonical_tag == "kernel",
            rotation: Rotation::Idle,
            rotation_failures: 0,
            retry_at: None,
            backlog: VecDeque::new(),
            backlog_bytes: 0,
            dropped: 0,
            unflushed: false,
            disabled: false,
        };
        connection.drain();
        connection
    }

    // A full backlog keeps what it has; the newcomer is counted instead.
    fn hold(&mut self, record: Vec<u8>, flush: bool) {
        // Empty raw requests are valid and must not occupy queue entries.
        if self.disabled || record.is_empty() {
            return;
        }
        if self.backlog_bytes + record.len() > BACKLOG_CAPACITY {
            self.dropped += 1;
            return;
        }
        self.backlog_bytes += record.len();
        self.backlog.push_back(PendingRecord {
            data: record,
            flush,
        });
    }

    fn push_front(&mut self, record: PendingRecord) {
        self.backlog_bytes += record.data.len();
        self.backlog.push_front(record);
    }

    fn is_holding(&self) -> bool {
        !self.disabled
            && (self.log_file.is_none()
                || self.rotation != Rotation::Idle
                || !self.backlog.is_empty()
                || self.unflushed)
    }

    fn submit(&mut self, record: Vec<u8>, flush: bool) {
        self.hold(record, flush);
        self.drain();
    }

    /// Pressure refusals retain pending work. Other write and flush errors
    /// lose the record on ordinary tags, as they always did, and switch the
    /// raw kernel file off.
    fn drain(&mut self) {
        if self.disabled || moto_sys::memory_pressure() {
            return;
        }
        loop {
            match self.advance() {
                Ok(()) => return,
                Err(DrainError::Write(err) | DrainError::Flush(err))
                    if is_pressure_refusal(&err) =>
                {
                    return;
                }
                Err(DrainError::Write(err) | DrainError::Flush(err)) if self.raw => {
                    return self.switch_off(err);
                }
                Err(DrainError::Write(_)) => {
                    if let Some(record) = self.backlog.pop_front() {
                        self.backlog_bytes -= record.data.len();
                    }
                }
                Err(DrainError::Flush(_)) => self.unflushed = false,
                Err(DrainError::Rotation(err)) => return self.on_rotation_error(err),
            }
        }
    }

    fn on_rotation_error(&mut self, err: std::io::Error) {
        self.rotation_failures += 1;
        if !self.raw && self.rotation_failures > ROTATION_RETRIES {
            return self.switch_off(err);
        }
        if self.rotation_failures == 1 {
            moto_rt::moto_log!("strobe: log '{}': {err:?}; retrying.", self.tag);
        }
        self.retry_at = Some(Instant::now() + ROTATION_RETRY_INTERVAL);
    }

    fn switch_off(&mut self, err: std::io::Error) {
        let lost = self.backlog.len() as u64 + self.dropped;
        moto_rt::moto_log!(
            "strobe: disabling log file for '{}': {err:?}; {lost} records lost.",
            self.tag
        );
        self.disabled = true;
        self.log_file = None;
        self.backlog.clear();
        self.backlog_bytes = 0;
        self.dropped = 0;
        self.unflushed = false;
    }

    fn advance(&mut self) -> Result<(), DrainError> {
        let mut result = Ok(());
        loop {
            // Nothing is written while a rotation is under way, so the old
            // file never grows past the size limit.
            if self.log_file.is_none() || self.rotation != Rotation::Idle || self.needs_room() {
                if self.retry_at.is_some_and(|at| Instant::now() < at) {
                    break;
                }
                match self.rotate_step() {
                    Ok(()) => continue,
                    Err(err) => {
                        result = Err(DrainError::Rotation(err));
                        break;
                    }
                }
            }
            let Some(mut record) = self.backlog.pop_front() else {
                break;
            };
            self.backlog_bytes -= record.data.len();
            let written =
                match record.write_to(self.log_file.as_mut().unwrap(), &mut self.unflushed) {
                    Ok(written) => written,
                    Err(err) => {
                        self.push_front(record);
                        return Err(DrainError::Write(err));
                    }
                };
            self.log_file_size += written as u64;
            if !record.data.is_empty() {
                self.push_front(record);
            } else if self.backlog.is_empty() && self.dropped != 0 {
                let count = std::mem::take(&mut self.dropped);
                let notice = self.notice(count);
                self.push_front(PendingRecord {
                    data: notice,
                    flush: true,
                });
            }
        }
        if let Some(file) = &mut self.log_file {
            flush_pending(file, &mut self.unflushed).map_err(DrainError::Flush)?;
        }
        result
    }

    fn needs_room(&self) -> bool {
        self.backlog.front().is_some_and(|record| {
            self.log_file_size + record.data.len() as u64 > LOG_FILE_MAX_BYTES
        })
    }

    fn rotate_step(&mut self) -> std::io::Result<()> {
        let previous_path = self.file_path.with_extension("log.prev");
        match self.rotation {
            Rotation::Idle => {
                if self.log_file.is_none() && !exists(&self.file_path)? {
                    self.rotation = Rotation::Renamed;
                    return Ok(());
                }
                match std::fs::remove_file(&previous_path) {
                    Err(err) if err.kind() != std::io::ErrorKind::NotFound => return Err(err),
                    _ => {}
                }
                std::fs::rename(&self.file_path, &previous_path)?;
                self.rotation = Rotation::Renamed;
            }
            Rotation::Renamed => {
                create_log_file(&self.file_name)?;
                self.rotation = Rotation::Created;
            }
            Rotation::Created => {
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&self.file_path)?;
                self.log_file = Some(file);
                self.log_file_size = 0;
                self.rotation = Rotation::Idle;
                self.rotation_failures = 0;
                self.retry_at = None;
                let now = moto_rt::time::UtcDateTime::now();
                self.push_front(PendingRecord {
                    data: format!("{now}:I - started log for '{}'\n", self.tag).into_bytes(),
                    flush: true,
                });
            }
        }
        Ok(())
    }

    fn notice(&self, count: u64) -> Vec<u8> {
        if self.raw {
            format!("[kernel log: {count} messages dropped due to memory pressure]\n")
        } else {
            let now = moto_rt::time::UtcDateTime::now();
            format!("{now}:W - {count} messages dropped due to memory pressure\n")
        }
        .into_bytes()
    }

    fn process_log_record(&mut self, log_record: LogRecord) {
        if self.tag_id != log_record.tag_id {
            return;
        }
        // Safe because we don't care much about time skew, and because the TS is ~now.
        let ts = unsafe {
            moto_rt::time::UtcDateTime::from_instant(moto_rt::time::Instant::from_u64(
                log_record.timestamp,
            ))
        };
        let lvl = match log_record.log_level {
            1 => 'E',
            2 => 'W',
            3 => 'I',
            4 => 'D',
            5 => 'T',
            _ => '?',
        };
        self.submit(
            format!("{ts}:{lvl} - {}\n", log_record.msg).into_bytes(),
            flushes(log_record.log_level),
        );
    }

    fn process_raw_log_record(&mut self, record: RawLogRecord) {
        if self.tag_id == record.tag_id {
            self.submit(record.data, true);
        }
    }
}

pub fn spawn(receiver: std::sync::mpsc::Receiver<Msg>) {
    std::thread::spawn(move || {
        let Ok(meta) = std::fs::metadata(LOG_DIR_PATH) else {
            moto_rt::moto_log!("FATAL: {LOG_DIR_PATH} does not exist.");
            return;
        };
        if !(meta.is_dir()) {
            moto_rt::moto_log!("FATAL: {LOG_DIR_PATH} is not a directory.");
            return;
        }

        let mut connections: HashMap<SysHandle, Connection> = HashMap::new();
        // While anything is held, every connection drains at this deadline,
        // however busy the others are.
        let mut drain_at: Option<Instant> = None;

        loop {
            if !connections.values().any(Connection::is_holding) {
                drain_at = None;
            } else if drain_at.is_none() {
                drain_at = Some(Instant::now() + DRAIN_INTERVAL);
            }
            let msg = match drain_at {
                None => receiver.recv().unwrap(),
                Some(deadline) => {
                    let now = Instant::now();
                    if now >= deadline {
                        for connection in connections.values_mut() {
                            connection.drain();
                        }
                        drain_at = None;
                        continue;
                    }
                    match receiver.recv_timeout(deadline - now) {
                        Ok(msg) => msg,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                            panic!("the log server is gone")
                        }
                    }
                }
            };
            match msg {
                Msg::NewConnection(connection) => {
                    let crate::logging::Connection {
                        tag,
                        canonical_tag,
                        tag_id,
                        handle,
                    } = connection;
                    connections
                        .entry(handle)
                        .or_insert_with(|| Connection::new(tag, canonical_tag, tag_id));
                }

                Msg::DroppedConnection(handle) => {
                    connections.remove(&handle);
                }

                Msg::Record(log_record) => {
                    if let Some(connection) = connections.get_mut(&log_record.handle) {
                        connection.process_log_record(log_record);
                    }
                }

                Msg::RawRecord(record) => {
                    if let Some(connection) = connections.get_mut(&record.handle) {
                        connection.process_raw_log_record(record);
                    }
                }
            }
        }
    });
}
