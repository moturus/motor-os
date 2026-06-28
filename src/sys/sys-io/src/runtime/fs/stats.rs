//! Statistics for the FS runtime.
//!
//! sys-io's stats provider (`crate::stats_server`) runs on its own thread, but
//! the FS lives in this single-threaded async runtime (`Rc<LocalMutex<FS>>`) and
//! can't be read from there directly. Instead the stats-server thread *polls*
//! them: it sends a request over a cross-thread channel that
//! [`stats_responder_task`] (running in the FS runtime) answers with a freshly
//! built snapshot. Best effort, never precise — mirrors `crate::runtime::net::stats`.

use super::FS;
use async_fs::FileSystem;
use moto_async::LocalMutex;
use moto_stats::{MetricDescWire, MetricEntry};
use std::{rc::Rc, sync::OnceLock};

/// FS metric ids. They are private to sys-io: collectors learn their names
/// dynamically via `CMD_DESCRIBE` (moto-stats hardcodes no metric ids).
mod ids {
    pub const FS_CAPACITY_BYTES: u32 = 1000;
    pub const FS_AVAILABLE_BYTES: u32 = 1001;
}

/// Build a snapshot of the FS metrics in moto-stats wire form. Mirrors
/// [`descriptors`].
async fn entries(fs: &mut FS) -> Vec<MetricEntry> {
    let num_blocks = fs.num_blocks();
    let empty_blocks = fs
        .empty_blocks()
        .await
        .inspect_err(|err| log::error!("FS::empty_blocks() failed: {err:?}"))
        .unwrap_or(0);

    vec![
        MetricEntry::global(ids::FS_CAPACITY_BYTES, num_blocks * 4096),
        MetricEntry::global(ids::FS_AVAILABLE_BYTES, empty_blocks * 4096),
    ]
}

/// The metric descriptors this provider exposes (the response to `CMD_DESCRIBE`).
/// Mirrors [`entries`]; lets collectors learn metric names at runtime. Static
/// metadata, so the stats-server thread builds it directly.
pub(crate) fn descriptors() -> Vec<MetricDescWire> {
    vec![
        MetricDescWire::new(ids::FS_CAPACITY_BYTES, "fs.capacity_bytes"),
        MetricDescWire::new(ids::FS_AVAILABLE_BYTES, "fs.available_bytes"),
    ]
}

/// A request from the stats-server thread for a metrics snapshot, carrying the
/// one-shot channel to respond on.
struct StatsRequest {
    respond_to: moto_async::oneshot::Sender<Vec<MetricEntry>>,
}

/// Sender half of the request channel. Set once, when the FS runtime spawns its
/// responder task; read by the stats-server thread in [`query_metrics`].
static STATS_REQUESTS: OnceLock<moto_async::channel::Sender<StatsRequest>> = OnceLock::new();

/// Capacity of the request channel. The stats-server thread serializes its
/// queries (one outstanding at a time), so this only needs slack for races.
const STATS_REQUEST_CAPACITY: usize = 4;

/// Spawn the task that answers metric-snapshot requests from the stats-server
/// thread. Call once, from the FS runtime.
pub(super) fn spawn_stats_responder(fs: Rc<LocalMutex<FS>>) {
    let (tx, rx) = moto_async::channel(STATS_REQUEST_CAPACITY);
    if STATS_REQUESTS.set(tx).is_err() {
        log::error!("sys-io: fs stats responder already started");
        return;
    }

    let _ = moto_async::LocalRuntime::spawn(stats_responder_task(fs, rx));
}

/// Listen for stats requests and answer each with a fresh snapshot of the
/// (single-threaded) FS stats. Runs in the FS runtime.
async fn stats_responder_task(
    fs: Rc<LocalMutex<FS>>,
    mut requests: moto_async::channel::Receiver<StatsRequest>,
) {
    while let Some(req) = requests.recv().await {
        let snapshot = entries(&mut *fs.lock().await).await;
        // The receiver is gone if the stats-server thread stopped waiting; ignore.
        let _ = req.respond_to.send(snapshot);
    }
}

/// Poll a fresh snapshot of the FS metrics out of the FS runtime. Called from
/// the stats-server thread; returns empty if the FS runtime isn't up yet.
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
