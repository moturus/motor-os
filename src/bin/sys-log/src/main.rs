use std::mem::size_of;

use moto_ipc::sync::*;
use moto_sys::syscalls::SysMem;
use moto_sys::SysHandle;

struct Connection {
    _tag: String,
    tag_id: u64,
}

struct LogRecord {
    log_level: u8,
    tag_id: u64,
    timestamp: u64,
    msg: String,
}

struct LogServer {
    ipc_server: LocalServer,
    next_tag_id: u64,

    records: Vec<Option<LogRecord>>,
    next_record_id: usize,
}

impl LogServer {
    const MAX_RECORDS: usize = 100;

    fn add_log_record(&mut self, record: LogRecord) {
        self.records[self.next_record_id % Self::MAX_RECORDS] = Some(record);
        self.next_record_id += 1;
    }

    fn process_connect_request(
        conn: &mut LocalServerConnection,
        next_tag_id: u64,
    ) -> Result<(), ()> {
        use moto_log::implementation::*;
        let req = unsafe {
            (conn.data().as_ptr() as *const ConnectRequest)
                .as_ref()
                .unwrap()
        };
        if req.command != CMD_CONNECT || req.version != 0 {
            SysMem::log("Bad ConnectRequest.").ok();
            return Err(());
        }

        let tag_bytes = &conn.data()[size_of::<ConnectRequest>()
            ..(size_of::<ConnectRequest>() + (req.payload_size as usize))];
        if let Ok(tag) = std::str::from_utf8(tag_bytes) {
            conn.set_extension::<Connection>(Box::new(Connection {
                tag_id: next_tag_id,
                _tag: tag.to_owned(),
            }));

            let resp = unsafe {
                (conn.data_mut().as_ptr() as *mut ConnectResponse)
                    .as_mut()
                    .unwrap()
            };
            resp.tag_id = next_tag_id;
            resp.result = 0;

            Ok(())
        } else {
            SysMem::log("Bad tag.").ok();
            Err(())
        }
    }

    fn process_log_request(conn: &mut LocalServerConnection) -> Result<LogRecord, ()> {
        use moto_log::implementation::*;

        let req = unsafe {
            (conn.data().as_ptr() as *const LogRequest)
                .as_ref()
                .unwrap()
        };
        assert_eq!(req.command, CMD_LOG);

        let ext = match conn.extension::<Connection>() {
            Some(ext) => ext,
            None => return Err(()),
        };

        if req.version != 0 || req.tag_id != ext.tag_id {
            return Err(());
        }

        let payload_bytes = &conn.data()
            [size_of::<LogRequest>()..(size_of::<LogRequest>() + (req.payload_size as usize))];

        let payload = std::str::from_utf8(payload_bytes).map_err(|_| ())?;

        let record = LogRecord {
            log_level: req.log_level,
            tag_id: req.tag_id,
            timestamp: req.timestamp,
            msg: payload.to_owned(),
        };

        let resp = unsafe {
            (conn.data_mut().as_ptr() as *mut LogResponse)
                .as_mut()
                .unwrap()
        };
        resp.result = 0;

        Ok(record)
    }

    fn process_get_tail_entries_request(
        conn: &mut LocalServerConnection,
        records: &Vec<Option<LogRecord>>,
        next_record_id: usize,
    ) -> Result<(), ()> {
        use moto_log::implementation::*;

        let req = unsafe {
            (conn.data().as_ptr() as *const GetTailEntriesRequest)
                .as_ref()
                .unwrap()
        };
        assert_eq!(req.command, CMD_GET_TAIL_ENTRIES);

        if req.version != 0 {
            return Err(());
        }
        if req.tag_id != 0 {
            SysMem::log("sys-log: filtering by TAG ID not implemented").ok();
            return Err(());
        }

        let max_sz = conn.channel_size();

        let out_buf = conn.data_mut();

        let mut idx = next_record_id + Self::MAX_RECORDS - 1;
        let mut num_entries = 0_u32;
        let mut pos = size_of::<GetTailEntriesResponse>();
        while idx >= next_record_id {
            if let Some(record) = &records[idx % Self::MAX_RECORDS] {
                let entry_size = size_of::<LogEntryHeader>() + record.msg.len();
                if pos + entry_size > max_sz {
                    break;
                }

                // Safe because we are sure the memory is available and aligned properly.
                let header = unsafe {
                    ((&mut out_buf[pos..]).as_mut_ptr() as *mut LogEntryHeader)
                        .as_mut()
                        .unwrap()
                };
                header.tag_id = record.tag_id;
                header.timestamp = record.timestamp;
                header.log_level = record.log_level;
                header.payload_size = record.msg.len() as u32;

                pos += size_of::<LogEntryHeader>();
                (&mut out_buf[pos..(pos + record.msg.len())])
                    .copy_from_slice(record.msg.as_bytes());

                pos += record.msg.len();
                pos = (pos + 7) & !7; // Align to 8 bytes.
                if pos >= max_sz {
                    break;
                }

                idx -= 1;
                num_entries += 1;
            } else {
                break;
            }
        }

        // Safe because out_buf has more bytes than the response size.
        let resp = unsafe {
            (out_buf.as_mut_ptr() as *mut GetTailEntriesResponse)
                .as_mut()
                .unwrap()
        };

        resp.result = 0;
        resp.num_entries = num_entries;

        Ok(())
    }

    fn process_ipc(&mut self, waker: &SysHandle) {
        use moto_log::implementation::*;

        let conn = self.ipc_server.get_connection(*waker).unwrap();
        assert!(conn.connected());

        let cmd = unsafe { (conn.data().as_ptr() as *const u16).as_ref().unwrap() };

        let mut req_ok = true;
        let mut record = None;

        let res = match *cmd {
            CMD_LOG => {
                if let Ok(rec) = Self::process_log_request(conn) {
                    record = Some(rec);
                    Ok(())
                } else {
                    Err(())
                }
            }
            CMD_CONNECT => {
                let res = Self::process_connect_request(conn, self.next_tag_id);
                if res.is_ok() {
                    self.next_tag_id += 1;
                }
                res
            }
            CMD_GET_TAIL_ENTRIES => {
                Self::process_get_tail_entries_request(conn, &self.records, self.next_record_id)
            }
            _ => Err(()),
        };

        if res.is_err() {
            req_ok = false;
            conn.data_mut()[0] = u8::MAX;
        }

        if conn.finish_rpc().is_err() || !req_ok {
            conn.disconnect();
        }

        if let Some(record) = record {
            self.add_log_record(record);
        }
    }

    fn run(&mut self) -> ! {
        loop {
            let wakers = self.ipc_server.wait(SysHandle::NONE, &[]).unwrap();

            for waker in &wakers {
                self.process_ipc(waker);
            }
        }
    }

    fn start() -> ! {
        let mut records = vec![];
        records.reserve(Self::MAX_RECORDS);
        for _ in 0..Self::MAX_RECORDS {
            records.push(None);
        }

        let mut log_server = LogServer {
            ipc_server: LocalServer::new("sys-log", ChannelSize::Small, 2, 2).unwrap(),
            next_tag_id: 1,
            next_record_id: 0,
            records,
        };

        #[cfg(debug_assertions)]
        SysMem::log("sys-log started").ok();
        log_server.run()
    }
}

fn main() {
    LogServer::start()
}
