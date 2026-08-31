use std::collections::VecDeque;
use std::mem::size_of;
use std::sync::{Arc, Condvar, Mutex};

use moto_ipc::sync::{ChannelSize, ClientConnection, ResponseHeader};
use moto_log::implementation::{ConnectRequest, ConnectResponse, RawLogRequest};

use crate::output::Output;

pub const FILE_QUEUE_CAPACITY: usize = 1024 * 1024;

fn numeric_field(input: &[u8], width: usize) -> Option<&[u8]> {
    let end = input.iter().position(|byte| *byte == b':')?;
    let field = input.get(..end)?;
    if field.len() < width {
        return None;
    }
    let digits = field.iter().position(|byte| *byte != b' ').unwrap_or(end);
    if digits == end || !field[digits..].iter().all(u8::is_ascii_digit) {
        return None;
    }
    input.get(end + 1..)
}

pub fn is_warning_or_error(record: &[u8]) -> bool {
    let Some(after_seconds) = numeric_field(record, 3) else {
        return false;
    };
    let Some((millis, suffix)) = after_seconds.split_at_checked(3) else {
        return false;
    };
    if !millis.iter().all(u8::is_ascii_digit) {
        return false;
    }

    if let Some(level) = suffix.strip_prefix(b": ") {
        return level.starts_with(b"ERROR ") || level.starts_with(b"WARN ");
    }
    let Some(after_cpu) = suffix
        .strip_prefix(b" ")
        .and_then(|suffix| numeric_field(suffix, 2))
        .and_then(|suffix| suffix.strip_prefix(b" "))
    else {
        return false;
    };
    after_cpu.starts_with(b"ERROR  ") || after_cpu.starts_with(b"WARN   ")
}

#[derive(Debug, PartialEq, Eq)]
pub struct Batch {
    pub data: Vec<u8>,
    record_count: u64,
    reported_drops: u64,
}

pub struct FileQueue {
    records: VecDeque<Vec<u8>>,
    bytes: usize,
    dropped: u64,
    capacity: usize,
    disabled: bool,
}

impl FileQueue {
    pub fn new() -> Self {
        Self::with_capacity(FILE_QUEUE_CAPACITY)
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            records: VecDeque::new(),
            bytes: 0,
            dropped: 0,
            capacity,
            disabled: false,
        }
    }

    pub fn offer(&mut self, record: Vec<u8>) -> Result<(), Vec<u8>> {
        if self.disabled {
            return Err(record);
        }
        if record.len() > self.capacity {
            self.dropped = self.dropped.saturating_add(1);
            return Ok(());
        }
        while self.bytes + record.len() > self.capacity {
            let dropped = self.records.pop_front().unwrap();
            self.bytes -= dropped.len();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.bytes += record.len();
        self.records.push_back(record);
        Ok(())
    }

    pub fn take_batch(&mut self, max_payload: usize) -> Option<Batch> {
        while self
            .records
            .front()
            .is_some_and(|record| record.len() > max_payload)
        {
            let record = self.records.pop_front().unwrap();
            self.bytes -= record.len();
            self.dropped = self.dropped.saturating_add(1);
        }
        if self.records.is_empty() {
            return None;
        }

        let reported_drops = self.dropped;
        let marker = if reported_drops == 0 {
            Vec::new()
        } else {
            format!("[kernel log: {reported_drops} records dropped: file backlog]\n").into_bytes()
        };
        if marker.len() > max_payload {
            return None;
        }
        self.dropped = 0;
        if marker.len() + self.records.front().unwrap().len() > max_payload {
            return Some(Batch {
                data: marker,
                record_count: 0,
                reported_drops,
            });
        }

        let mut data = marker;
        let mut record_count = 0_u64;
        while self
            .records
            .front()
            .is_some_and(|record| data.len() + record.len() <= max_payload)
        {
            let record = self.records.pop_front().unwrap();
            self.bytes -= record.len();
            data.extend_from_slice(&record);
            record_count += 1;
        }
        Some(Batch {
            data,
            record_count,
            reported_drops,
        })
    }

    pub fn disable(&mut self, in_flight: Batch) -> u64 {
        let lost = self
            .dropped
            .saturating_add(self.records.len() as u64)
            .saturating_add(in_flight.record_count)
            .saturating_add(in_flight.reported_drops);
        self.records.clear();
        self.bytes = 0;
        self.dropped = 0;
        self.disabled = true;
        lost
    }

    fn disable_pending(&mut self) -> u64 {
        self.disable(Batch {
            data: Vec::new(),
            record_count: 0,
            reported_drops: 0,
        })
    }
}

struct Shared {
    queue: Mutex<FileQueue>,
    changed: Condvar,
}

#[derive(Clone)]
pub struct Forwarder {
    shared: Arc<Shared>,
}

impl Forwarder {
    pub fn start(output: Output) -> Option<Self> {
        let forwarder = Self {
            shared: Arc::new(Shared {
                queue: Mutex::new(FileQueue::new()),
                changed: Condvar::new(),
            }),
        };
        let worker = forwarder.clone();
        if std::thread::Builder::new()
            .name("kernel-log-file".to_owned())
            .spawn(move || worker.run(output))
            .is_err()
        {
            return None;
        }
        Some(forwarder)
    }

    pub fn offer(&self, record: Vec<u8>) -> Result<(), Vec<u8>> {
        let result = self.shared.queue.lock().unwrap().offer(record);
        if result.is_ok() {
            self.shared.changed.notify_one();
        }
        result
    }

    fn connect() -> Result<(ClientConnection, u64), u16> {
        let mut connection = ClientConnection::new(ChannelSize::Small)?;
        connection.connect("sys-log")?;
        ConnectRequest::prepare(connection.data_mut(), "kernel");
        connection.do_rpc(None)?;
        let tag_id = ConnectResponse::parse(connection.data())?;
        Ok((connection, tag_id))
    }

    fn send(connection: &mut ClientConnection, tag_id: u64, batch: &Batch) -> Result<(), u16> {
        RawLogRequest::prepare(connection.data_mut(), tag_id, &batch.data);
        connection.do_rpc(None)?;
        match connection.resp::<ResponseHeader>().result {
            moto_rt::E_OK => Ok(()),
            err => Err(err),
        }
    }

    fn report_disabled(output: &Output, error: u16, lost: u64) {
        let notice = format!(
            "[kernel log: file forwarding disabled with error {error}; {lost} records dropped]\n"
        );
        let _ = output.try_send_kernel(notice.into_bytes());
    }

    fn run(&self, output: Output) {
        let (mut connection, tag_id) = match Self::connect() {
            Ok(connected) => connected,
            Err(error) => {
                let lost = self.shared.queue.lock().unwrap().disable_pending();
                Self::report_disabled(&output, error, lost);
                return;
            }
        };
        let max_payload = connection.data().len() - size_of::<RawLogRequest>();

        loop {
            let batch = {
                let mut queue = self.shared.queue.lock().unwrap();
                loop {
                    if let Some(batch) = queue.take_batch(max_payload) {
                        break batch;
                    }
                    queue = self.shared.changed.wait(queue).unwrap();
                }
            };
            if let Err(error) = Self::send(&mut connection, tag_id, &batch) {
                let lost = self.shared.queue.lock().unwrap().disable(batch);
                Self::report_disabled(&output, error, lost);
                return;
            }
        }
    }
}

pub fn run_self_tests() {
    for record in [
        b"  0:001: ERROR file.rs:1: bad\n".as_slice(),
        b"1234:999: WARN file.rs:2: risky\n",
        b"  0:001  0: ERROR  kernel:1 - bad\n",
        b"1234:999 12: WARN   kernel:2 - risky\n",
    ] {
        assert!(is_warning_or_error(record), "{record:?}");
    }
    for record in [
        b"  0:001: INFO file.rs:1: WARN later\n".as_slice(),
        b"  0:001  0: DEBUG  kernel:1 - ERROR later\n",
        b"0:001: WARN too-short-seconds\n",
        b"  0:01: WARN too-short-millis\n",
        b"free text WARN\n",
    ] {
        assert!(!is_warning_or_error(record), "{record:?}");
    }

    let mut queue = FileQueue::with_capacity(8);
    queue.offer(b"aaa".to_vec()).unwrap();
    queue.offer(b"bbbb".to_vec()).unwrap();
    queue.offer(b"cc".to_vec()).unwrap();
    let batch = queue.take_batch(64).unwrap();
    assert_eq!(
        batch.data,
        b"[kernel log: 1 records dropped: file backlog]\nbbbbcc"
    );

    queue.offer(b"oversized".to_vec()).unwrap();
    queue.offer(b"next".to_vec()).unwrap();
    let expected_marker = b"[kernel log: 1 records dropped: file backlog]\n";
    let marker = queue.take_batch(expected_marker.len()).unwrap();
    assert_eq!(marker.data, expected_marker);
    let next = queue.take_batch(52).unwrap();
    assert_eq!(next.data, b"next");
    queue.offer(b"queued".to_vec()).unwrap();
    assert_eq!(queue.disable(next), 2);
    assert_eq!(queue.offer(b"console".to_vec()), Err(b"console".to_vec()));

    let mut pending = FileQueue::with_capacity(8);
    pending.offer(b"one".to_vec()).unwrap();
    pending.offer(b"two".to_vec()).unwrap();
    assert_eq!(pending.disable_pending(), 2);
    assert_eq!(
        pending.offer(b"fallback".to_vec()),
        Err(b"fallback".to_vec())
    );

    assert_eq!(FileQueue::new().capacity, FILE_QUEUE_CAPACITY);
    println!("sys-tty forwarder self-test PASS");
}
