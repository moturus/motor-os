use crate::logging::{LogRecord, RawLogRecord};
use moto_io::fs::{AccessPermissions, EntryKind, FsClient, RolePermissions};
use moto_sys::SysHandle;
use std::{
    collections::HashMap,
    io::Write,
    path::{Path, PathBuf},
};

// Only System strobe mutates this tree; lower roles submit records over IPC.
const LOG_DIR_PATH: &str = "/system/logs";
const LOG_FILE_MAX_BYTES: u64 = 4 * 1024 * 1024;
const MIN_AVAILABLE_BYTES: u64 = 50 * 1024 * 1024;
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

fn create_log_file(path: &Path, name: &str) -> Result<std::fs::File, String> {
    reclaim_previous_logs();
    let result = moto_async::LocalRuntime::new().block_on(async {
        let client = FsClient::connect()?;
        let (parent_id, kind) = client.stat(LOG_DIR_PATH).await?;
        if kind != EntryKind::Directory {
            return Err(moto_rt::Error::InvalidArgument);
        }
        client
            .create_entry_with_permissions(parent_id, EntryKind::File, name, LOG_FILE_PERMISSIONS)
            .await?;
        Ok(())
    });

    if let Err(err) = result {
        return Err(format!("creating {}: {err:?}", path.display()));
    }

    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|err| format!("opening {}: {err:?}", path.display()))
}

pub enum Msg {
    NewConnection(crate::logging::Connection),
    DroppedConnection(SysHandle),
    Record(LogRecord),
    RawRecord(RawLogRecord),
}

struct Connection {
    tag: String,
    tag_id: u64,
    file_name: String,
    file_path: PathBuf,
    log_file: Option<std::fs::File>,
    log_file_size: u64,
    rotation_enabled: bool,
}

impl Drop for Connection {
    fn drop(&mut self) {
        if self.log_file.is_some() {
            let now = moto_rt::time::UtcDateTime::now();
            let msg = format!("{now}:I - stopped log for '{}'\n", self.tag);
            let _ = self.write_bytes(msg.as_bytes(), true);
        }
    }
}

impl Connection {
    fn new(tag: String, canonical_tag: String, tag_id: u64) -> Self {
        let fname = format!("{canonical_tag}.log");
        let log_file_path = Path::new(LOG_DIR_PATH).join(&fname);

        let mut log_file = None;

        if let Ok(true) = std::fs::exists(log_file_path.as_path()) {
            let old_path = format!("{}.prev", log_file_path.to_str().unwrap());
            let _ = std::fs::remove_file(old_path.as_str());

            if std::fs::rename(log_file_path.as_path(), old_path.as_str()).is_err() {
                moto_rt::moto_log!(
                    "Error renaming {} into {old_path}.",
                    log_file_path.to_str().unwrap()
                );
            } else {
                log_file = create_log_file(log_file_path.as_path(), &fname)
                    .inspect_err(|err| moto_rt::moto_log!("Error {err}."))
                    .ok();
            }
        } else {
            log_file = create_log_file(log_file_path.as_path(), &fname)
                .inspect_err(|err| moto_rt::moto_log!("Error {err}."))
                .ok();
        }

        let mut connection = Self {
            tag,
            tag_id,
            file_name: fname,
            file_path: log_file_path,
            log_file,
            log_file_size: 0,
            rotation_enabled: true,
        };
        connection.write_started_record();
        connection
    }

    fn write_started_record(&mut self) {
        let now = moto_rt::time::UtcDateTime::now();
        let msg = format!("{now}:I - started log for '{}'\n", self.tag);
        let _ = self.write_direct(msg.as_bytes(), true);
    }

    fn write_direct(&mut self, bytes: &[u8], flush: bool) -> Option<std::io::Result<()>> {
        let file = self.log_file.as_mut()?;
        let mut result = file.write_all(bytes);
        if result.is_ok() {
            self.log_file_size = self.log_file_size.saturating_add(bytes.len() as u64);
            if flush {
                result = file.flush();
            }
        }
        Some(result)
    }

    fn rotate_if_needed(&mut self, next_write: usize) {
        if !self.rotation_enabled
            || self.log_file.is_none()
            || self.log_file_size.saturating_add(next_write as u64) <= LOG_FILE_MAX_BYTES
        {
            return;
        }

        let previous_path = self.file_path.with_extension("log.prev");
        let result = (|| {
            match std::fs::remove_file(&previous_path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(format!("removing {}: {err:?}", previous_path.display())),
            }
            std::fs::rename(&self.file_path, &previous_path).map_err(|err| {
                format!(
                    "renaming {} into {}: {err:?}",
                    self.file_path.display(),
                    previous_path.display()
                )
            })?;
            match create_log_file(&self.file_path, &self.file_name) {
                Ok(file) => {
                    self.log_file = Some(file);
                    self.log_file_size = 0;
                    self.write_started_record();
                    Ok(())
                }
                Err(err) => {
                    let _ = std::fs::remove_file(&self.file_path);
                    if std::fs::rename(&previous_path, &self.file_path).is_err() {
                        self.log_file = None;
                    }
                    Err(err)
                }
            }
        })();
        if let Err(err) = result {
            self.rotation_enabled = false;
            moto_rt::moto_log!("Disabling rotation for '{}': {err}.", self.tag);
        }
    }

    fn write_bytes(&mut self, bytes: &[u8], flush: bool) -> Option<std::io::Result<()>> {
        self.rotate_if_needed(bytes.len());
        self.write_direct(bytes, flush)
    }

    fn process_log_record(&mut self, log_record: LogRecord) {
        if self.tag_id != log_record.tag_id {
            return;
        }

        if self.log_file.is_some() {
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
            let msg = format!("{ts}:{lvl} - {}\n", log_record.msg);
            let _ = self.write_bytes(msg.as_bytes(), log_record.log_level >= 3);
        }
    }

    fn process_raw_log_record(&mut self, record: RawLogRecord) {
        if self.tag_id != record.tag_id {
            return;
        }
        let result = self.write_bytes(&record.data, true);
        if let Some(Err(err)) = result {
            self.log_file = None;
            moto_rt::moto_log!("Disabling raw log file for '{}': {err:?}.", self.tag);
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

        loop {
            let msg = receiver.recv().unwrap();
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
