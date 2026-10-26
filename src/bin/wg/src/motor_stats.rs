//! Publish a bounded snapshot through Motor's existing statistics protocol.
use crate::schedule::Scheduler;
use moto_sdk::ipc::sync::{ChannelSize, LocalServer, ResponseHeader};
use moto_sdk::stats::{self, Collector, MetricDescWire, MetricEntry};
use moto_sdk::sys::{self, SysHandle};
use std::sync::{Arc, Mutex};

const NAMES: [&str; 12] = [
    "wg.malformed",
    "wg.unauthenticated",
    "wg.unknown_peer",
    "wg.disallowed_source",
    "wg.no_owner",
    "wg.no_endpoint",
    "wg.crypto_errors",
    "wg.outer_dropped",
    "wg.inner_dropped",
    "wg.batches",
    "wg.timer_ticks",
    "wg.transport_failures",
];
type Snapshot = Arc<Mutex<[u64; NAMES.len()]>>;

pub(super) struct Stats {
    values: Snapshot,
    tick: u64,
}

impl Stats {
    pub(super) fn start() -> Self {
        let values = Arc::new(Mutex::new([0; NAMES.len()]));
        let snapshot = values.clone();
        if std::thread::Builder::new()
            .name("wg:stats".into())
            .spawn(move || {
                if serve(snapshot).is_err() {
                    eprintln!("wg: statistics service unavailable");
                }
            })
            .is_err()
        {
            eprintln!("wg: cannot start statistics service");
        }
        Self {
            values,
            tick: u64::MAX,
        }
    }

    pub(super) fn publish(&mut self, scheduler: &Scheduler) {
        if self.tick == scheduler.counters.timer_ticks {
            return;
        }
        self.tick = scheduler.counters.timer_ticks;
        let crypto = &scheduler.crypto.counters;
        let counters = &scheduler.counters;
        // One short copy per timer tick avoids locks in the per-packet path.
        *self.values.lock().unwrap() = [
            crypto.malformed,
            crypto.unauthenticated,
            crypto.unknown_peer,
            crypto.disallowed_source,
            crypto.no_owner,
            crypto.no_endpoint,
            crypto.crypto_errors,
            counters.outer_dropped,
            counters.inner_dropped,
            counters.batches,
            counters.timer_ticks,
            counters.transport_failures,
        ];
    }
}

fn serve(values: Snapshot) -> Result<(), u16> {
    let pid = sys::current_pid();
    let url = format!("wg-stats-{pid}");
    let mut server = LocalServer::new(&url, ChannelSize::Small, 4, 2)?;
    Collector::register(&format!("wg:{pid}"), &url)?;
    let descriptions: [_; NAMES.len()] =
        std::array::from_fn(|index| MetricDescWire::new(index as u32, NAMES[index]));
    loop {
        let Ok(wakers) = server.wait(SysHandle::NONE, &[]) else {
            continue;
        };
        for waker in wakers {
            let Some(connection) = server.get_connection(waker) else {
                continue;
            };
            if !connection.connected() || !connection.have_req() {
                continue;
            }
            // The sync channel holds a complete page, including this fixed header.
            let (version, command, start) = {
                let raw = connection.raw_channel();
                let request = unsafe { raw.get::<stats::PagedRequest>() };
                (request.header.ver, request.header.cmd, request.start_index)
            };
            match (version, command) {
                (0, stats::CMD_QUERY_METRICS) => {
                    let snapshot = *values.lock().unwrap();
                    let entries: [_; NAMES.len()] = std::array::from_fn(|index| {
                        MetricEntry::global(index as u32, snapshot[index])
                    });
                    stats::respond_pods(connection.data_mut(), &entries, start);
                }
                (0, stats::CMD_DESCRIBE) => {
                    stats::respond_pods(connection.data_mut(), &descriptions, start);
                }
                _ => unsafe {
                    connection.raw_channel().get_mut::<ResponseHeader>().result =
                        moto_sdk::rt::E_INVALID_ARGUMENT;
                },
            }
            let _ = connection.finish_rpc();
        }
    }
}
