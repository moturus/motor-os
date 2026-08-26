use crate::logging::LogRecord;
use moto_sys::SysHandle;
use std::{collections::HashMap, io::Write, path::PathBuf};

const LOG_DIR_PATH: &str = "/system/logs";

pub enum Msg {
    NewConnection(crate::logging::Connection),
    DroppedConnection(SysHandle),
    Record(LogRecord),
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
        let mut log_file_path = PathBuf::from(LOG_DIR_PATH);
        log_file_path.push(fname);

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
                log_file = std::fs::File::create_new(log_file_path.as_path()).ok();
            }
        } else {
            log_file = std::fs::File::create_new(log_file_path.as_path()).ok();
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
            }
        }
    });
}
