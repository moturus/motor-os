//! Statistics for Net runtime, including devices and sockets.
//!
//! sys-io's stats provider (`crate::stats_server`) runs on its own thread, but
//! the net stats live in this single-threaded async runtime (`Rc<Cell<..>>`) and
//! can't be read from there directly. Instead the stats-server thread *polls*
//! them: it sends a request over a cross-thread channel that
//! [`stats_responder_task`] (running in the net runtime) answers with a freshly
//! built snapshot. Best effort, never precise.

use moto_stats::{MetricDescWire, MetricEntry};
use std::{cell::Cell, rc::Rc, sync::OnceLock};

/// Net metric ids. They are private to sys-io: collectors learn their names
/// dynamically via `CMD_DESCRIBE` (moto-stats hardcodes no metric ids).
mod ids {
    pub const NET_NUM_DEVICES: u32 = 0;
    pub const NET_ACTIVE_CLIENTS: u32 = 1;
    pub const NET_TOTAL_CLIENTS: u32 = 2;
    pub const NET_TCP_SOCKETS: u32 = 3;
    pub const NET_TOTAL_TCP_SOCKETS: u32 = 4;
    pub const NET_TCP_LISTENING_SOCKETS: u32 = 5;
    pub const NET_UDP_SOCKETS: u32 = 6;
    pub const NET_TOTAL_UDP_SOCKETS: u32 = 7;
}

#[derive(Default)]
pub(super) struct NetStats {
    pub num_devices: Rc<Cell<u64>>,
    pub active_clients: Rc<Cell<u64>>,
    pub total_clients: Rc<Cell<u64>>,
    pub tcp_sockets: Rc<Cell<u64>>,
    pub total_tcp_sockets: Rc<Cell<u64>>,
    pub tcp_listening_sockets: Rc<Cell<u64>>,
    pub udp_sockets: Rc<Cell<u64>>,
    pub total_udp_sockets: Rc<Cell<u64>>,
}

impl NetStats {
    /// Build a snapshot of the metrics in moto-stats wire form. Mirrors
    /// [`descriptors`].
    fn entries(&self) -> Vec<MetricEntry> {
        vec![
            MetricEntry::global(ids::NET_NUM_DEVICES, self.num_devices.get()),
            MetricEntry::global(ids::NET_ACTIVE_CLIENTS, self.active_clients.get()),
            MetricEntry::global(ids::NET_TOTAL_CLIENTS, self.total_clients.get()),
            MetricEntry::global(ids::NET_TCP_SOCKETS, self.tcp_sockets.get()),
            MetricEntry::global(ids::NET_TOTAL_TCP_SOCKETS, self.total_tcp_sockets.get()),
            MetricEntry::global(
                ids::NET_TCP_LISTENING_SOCKETS,
                self.tcp_listening_sockets.get(),
            ),
            MetricEntry::global(ids::NET_UDP_SOCKETS, self.udp_sockets.get()),
            MetricEntry::global(ids::NET_TOTAL_UDP_SOCKETS, self.total_udp_sockets.get()),
        ]
    }
}

/// The metric descriptors this provider exposes (the response to `CMD_DESCRIBE`).
/// Mirrors [`NetStats::entries`]; lets collectors learn metric names at runtime.
/// Static metadata, so the stats-server thread builds it directly.
pub(crate) fn descriptors() -> Vec<MetricDescWire> {
    vec![
        MetricDescWire::new(ids::NET_NUM_DEVICES, "net.num_devices"),
        MetricDescWire::new(ids::NET_ACTIVE_CLIENTS, "net.active_clients"),
        MetricDescWire::new(ids::NET_TOTAL_CLIENTS, "net.total_clients"),
        MetricDescWire::new(ids::NET_TCP_SOCKETS, "net.tcp_sockets"),
        MetricDescWire::new(ids::NET_TOTAL_TCP_SOCKETS, "net.total_tcp_sockets"),
        MetricDescWire::new(ids::NET_TCP_LISTENING_SOCKETS, "net.tcp_listening_sockets"),
        MetricDescWire::new(ids::NET_UDP_SOCKETS, "net.udp_sockets"),
        MetricDescWire::new(ids::NET_TOTAL_UDP_SOCKETS, "net.total_udp_sockets"),
    ]
}

/// A request from the stats-server thread for a metrics snapshot, carrying the
/// one-shot channel to respond on.
struct StatsRequest {
    respond_to: moto_async::oneshot::Sender<Vec<MetricEntry>>,
}

/// Sender half of the request channel. Set once, when the net runtime spawns its
/// responder task; read by the stats-server thread in [`query_metrics`].
static STATS_REQUESTS: OnceLock<moto_async::channel::Sender<StatsRequest>> = OnceLock::new();

/// Capacity of the request channel. The stats-server thread serializes its
/// queries (one outstanding at a time), so this only needs slack for races.
const STATS_REQUEST_CAPACITY: usize = 4;

/// Spawn the task that answers metric-snapshot requests from the stats-server
/// thread. Call once, from the net runtime.
pub(super) fn spawn_stats_responder(stats: Rc<NetStats>) {
    let (tx, rx) = moto_async::channel(STATS_REQUEST_CAPACITY);
    if STATS_REQUESTS.set(tx).is_err() {
        log::error!("sys-io: net stats responder already started");
        return;
    }

    let _ = moto_async::LocalRuntime::spawn(stats_responder_task(stats, rx));
}

/// Listen for stats requests and answer each with a fresh snapshot of the
/// (single-threaded) net stats. Runs in the net runtime.
async fn stats_responder_task(
    stats: Rc<NetStats>,
    mut requests: moto_async::channel::Receiver<StatsRequest>,
) {
    while let Some(req) = requests.recv().await {
        // The receiver is gone if the stats-server thread stopped waiting; ignore.
        let _ = req.respond_to.send(stats.entries());
    }
}

/// Poll a fresh snapshot of the net metrics out of the net runtime. Called from
/// the stats-server thread; returns empty if the net runtime isn't up yet.
pub(crate) fn query_metrics() -> Vec<MetricEntry> {
    let Some(requests) = STATS_REQUESTS.get() else {
        return Vec::new();
    };

    // This thread has no async runtime, so spin up a throwaway one to drive the
    // cross-thread request/response round-trip to completion.
    moto_async::LocalRuntime::new().block_on(async move {
        let (respond_to, response) = moto_async::oneshot();
        if requests.send(StatsRequest { respond_to }).await.is_err() {
            return Vec::new();
        }
        response.await.unwrap_or_default()
    })
}
