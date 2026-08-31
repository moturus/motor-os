use crate::logging::{LogRecord, RawLogRecord};
use moto_io::fs::{AccessPermissions, EntryKind, FsClient, RolePermissions};
use moto_sys::SysHandle;
use std::{collections::HashMap, io::Write, path::Path};

// Only System strobe mutates this tree; lower roles submit records over IPC.
const LOG_DIR_PATH: &str = "/system/logs";
const LOG_FILE_PERMISSIONS: RolePermissions = RolePermissions::new(
    AccessPermissions::Rw,
    AccessPermissions::R,
    AccessPermissions::None,
);

fn create_log_file(path: &Path, name: &str) -> Option<std::fs::File> {
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
        moto_rt::moto_log!("Error creating {}: {err:?}.", path.display());
        return None;
    }

    match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(file) => Some(file),
        Err(err) => {
            moto_rt::moto_log!("Error opening {}: {err:?}.", path.display());
            None
        }
    }
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

    log_file: Option<std::fs::File>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(log_file) = self.log_file.as_mut() {
            let now = moto_rt::time::UtcDateTime::now();
            let msg = format!("{now}:I - stopped log for '{}'\n", self.tag);
            let _ = log_file.write_all(msg.as_bytes());
            let _ = log_file.flush();
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
                log_file = create_log_file(log_file_path.as_path(), &fname);
            }
        } else {
            log_file = create_log_file(log_file_path.as_path(), &fname);
        }

        if let Some(log_file) = log_file.as_mut() {
            let now = moto_rt::time::UtcDateTime::now();
            let msg = format!("{now}:I - started log for '{tag}'\n");
            let _ = log_file.write_all(msg.as_bytes());
            let _ = log_file.flush();
        }

        Self {
            tag,
            tag_id,
            // log_file_path,
            log_file,
        }
    }

    fn process_log_record(&mut self, log_record: LogRecord) {
        if self.tag_id != log_record.tag_id {
            return;
        }

        if let Some(log_file) = self.log_file.as_mut() {
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
            let _ = log_file.write_all(msg.as_bytes());
            if log_record.log_level >= 3 {
                let _ = log_file.flush();
            }
        }
    }

    fn process_raw_log_record(&mut self, record: RawLogRecord) {
        if self.tag_id != record.tag_id {
            return;
        }
        let result = self
            .log_file
            .as_mut()
            .map(|file| file.write_all(&record.data).and_then(|()| file.flush()));
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
