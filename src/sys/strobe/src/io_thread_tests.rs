use super::*;
use std::io::ErrorKind;

#[derive(Default)]
struct Writer {
    data: Vec<u8>,
    write_error: Option<ErrorKind>,
    flush_error: Option<ErrorKind>,
    flushes: usize,
}

impl Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if let Some(error) = self.write_error.take() {
            return Err(error.into());
        }
        let written = bytes.len().min(2);
        self.data.extend_from_slice(&bytes[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flushes += 1;
        match self.flush_error.take() {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }
}

fn write_progress_and_flush_policy() {
    assert!(flushes(1) && flushes(2));
    assert!(!flushes(3) && !flushes(4) && !flushes(5));

    let mut writer = Writer::default();
    let mut unflushed = false;
    let mut info = PendingRecord {
        data: b"info".to_vec(),
        flush: false,
    };
    while !info.data.is_empty() {
        info.write_to(&mut writer, &mut unflushed).unwrap();
    }
    flush_pending(&mut writer, &mut unflushed).unwrap();
    assert_eq!(writer.flushes, 0);

    let mut raw = PendingRecord {
        data: b"kernel".to_vec(),
        flush: true,
    };
    raw.write_to(&mut writer, &mut unflushed).unwrap();
    writer.write_error = Some(ErrorKind::OutOfMemory);
    assert_eq!(
        raw.write_to(&mut writer, &mut unflushed)
            .unwrap_err()
            .kind(),
        ErrorKind::OutOfMemory
    );
    assert_eq!(raw.data, b"rnel");
    while !raw.data.is_empty() {
        raw.write_to(&mut writer, &mut unflushed).unwrap();
    }
    writer.flush_error = Some(ErrorKind::OutOfMemory);
    assert!(flush_pending(&mut writer, &mut unflushed).is_err());
    assert!(unflushed);
    assert_eq!(writer.data, b"infokernel");
    flush_pending(&mut writer, &mut unflushed).unwrap();
    assert!(!unflushed);
    assert_eq!(writer.data, b"infokernel");
    assert_eq!(writer.flushes, 2);
}

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "strobe-io-self-test-{}-{:016x}-{name}",
        moto_sys::current_pid(),
        moto_rt::time::Instant::now().as_u64()
    ))
}

fn create_new(path: &Path) -> std::fs::File {
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .unwrap()
}

fn test_connection(path: &Path, file: Option<std::fs::File>, raw: bool) -> Connection {
    Connection {
        tag: "self-test".into(),
        tag_id: 1,
        file_name: path.file_name().unwrap().to_str().unwrap().into(),
        file_path: path.to_owned(),
        log_file: file,
        log_file_size: 0,
        raw,
        rotation: Rotation::Idle,
        rotation_failures: 0,
        retry_at: None,
        backlog: VecDeque::new(),
        backlog_bytes: 0,
        dropped: 0,
        unflushed: false,
        disabled: false,
    }
}

fn empty_records_and_disconnect() {
    let path = temp_path("raw.log");
    let mut connection = test_connection(&path, Some(create_new(&path)), true);
    for _ in 0..1024 {
        connection.hold(Vec::new(), true);
    }
    assert!(connection.backlog.is_empty());
    assert_eq!(connection.backlog_bytes, 0);
    assert_eq!(connection.dropped, 0);

    connection.hold(b"held under pressure\n".to_vec(), true);
    assert!(is_pressure_refusal(&std::io::Error::from_raw_os_error(
        moto_rt::E_OUT_OF_MEMORY as i32,
    )));
    assert!(connection.is_holding());
    connection.drain();
    assert_eq!(std::fs::read(&path).unwrap(), b"held under pressure\n");

    connection.submit(b"after empty\n".to_vec(), true);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"held under pressure\nafter empty\n"
    );
    connection.hold(b"held before disconnect\n".to_vec(), true);
    drop(connection);
    let log = std::fs::read_to_string(&path).unwrap();
    assert!(log.starts_with("held under pressure\nafter empty\nheld before disconnect\n"));
    assert!(log.ends_with("stopped log for 'self-test'\n"));

    // On kernel.log a real non-pressure write error must terminate the file
    // and its backlog, even when no later record arrives to handle it.
    let mut connection = test_connection(&path, Some(std::fs::File::open(&path).unwrap()), true);
    connection.hold(b"unwritable\n".to_vec(), true);
    connection.drain();
    assert!(connection.disabled);
    assert!(connection.log_file.is_none());
    assert!(!connection.is_holding());
    assert_eq!(connection.backlog_bytes, 0);
    connection.submit(b"must not retry\n".to_vec(), true);
    connection.drain();
    assert!(connection.backlog.is_empty());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), log);
    drop(connection);
    std::fs::remove_file(path).unwrap();
}

/// Ordinary tags lose a record their file refuses and keep the file.
fn ordinary_write_errors() {
    let path = temp_path("ordinary.log");
    let file = create_new(&path);
    let mut connection = test_connection(&path, Some(std::fs::File::open(&path).unwrap()), false);
    connection.submit(b"lost\n".to_vec(), true);
    assert!(!connection.disabled);
    assert!(!connection.is_holding());

    connection.log_file = Some(file);
    connection.submit(b"kept\n".to_vec(), true);
    drop(connection);
    let log = std::fs::read_to_string(&path).unwrap();
    assert!(log.starts_with("kept\n"));
    assert!(log.ends_with("stopped log for 'self-test'\n"));
    std::fs::remove_file(path).unwrap();
}

/// A rotation that cannot move the full file aside writes nothing more into
/// it and is retried once per interval: forever for kernel.log, a limited
/// number of times for other files. A non-empty directory in place of
/// `.prev` makes the first step fail.
fn stuck_rotation() {
    let path = temp_path("rotation.log");
    let blocker = path.with_extension("log.prev");
    std::fs::create_dir(&blocker).unwrap();
    std::fs::write(blocker.join("file"), b"").unwrap();

    for raw in [false, true] {
        let file = std::fs::File::create(&path).unwrap();
        let mut connection = test_connection(&path, Some(file), raw);
        connection.log_file_size = LOG_FILE_MAX_BYTES;
        connection.submit(b"past the limit\n".to_vec(), true);
        assert_eq!(connection.rotation_failures, 1);
        connection.drain();
        assert_eq!(
            connection.rotation_failures, 1,
            "retried before the interval"
        );
        for _ in 0..ROTATION_RETRIES {
            assert!(connection.is_holding());
            connection.retry_at = None;
            connection.drain();
        }
        assert_eq!(connection.disabled, !raw);
        assert!(std::fs::read(&path).unwrap().is_empty());
        // The blocker is still there, so dropping cannot rotate either.
        drop(connection);
    }

    // A first open that has to wait keeps the drain timer armed.
    let mut unopened = test_connection(&path, None, false);
    assert!(unopened.is_holding());
    unopened.disabled = true;
    drop(unopened);

    std::fs::remove_file(blocker.join("file")).unwrap();
    std::fs::remove_dir(&blocker).unwrap();
    std::fs::remove_file(path).unwrap();
}

pub fn run() {
    write_progress_and_flush_policy();
    empty_records_and_disconnect();
    ordinary_write_errors();
    stuck_rotation();
    println!("strobe: I/O self-tests PASS");
}
