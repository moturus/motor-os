//! Statistics for the FS runtime.
//!
//! sys-io's stats provider (`crate::stats_server`) runs on its own thread, but
//! the FS lives in this single-threaded async runtime (`Rc<LocalRwLock<FS>>`) and
//! can't be read from there directly. Instead the stats-server thread *polls*
//! them: it sends a request over a cross-thread channel that
//! [`stats_responder_task`] (running in the FS runtime) answers with a freshly
//! built snapshot. Best effort, never precise — mirrors `crate::runtime::net::stats`.

use super::FS;
use async_fs::FileSystem;
use moto_async::LocalRwLock;
use moto_stats::{MetricDescWire, MetricEntry};
use std::{rc::Rc, sync::OnceLock};

/// FS metric ids. They are private to sys-io: collectors learn their names
/// dynamically via `CMD_DESCRIBE` (moto-stats hardcodes no metric ids).
mod ids {
    pub const FS_CAPACITY_BYTES: u32 = 1000;
    pub const FS_AVAILABLE_BYTES: u32 = 1001;

    // Data-path performance counters (see `super::super::perf` and
    // `BlockCache::cache_stats`), added to diagnose sequential-read speed.
    // The two *_NS_TOTAL metrics read 0 unless `perf::TIMINGS` is
    // compiled on; the rest are always live.
    pub const FS_CACHE_HITS: u32 = 1002;
    pub const FS_CACHE_MISSES: u32 = 1003;
    pub const FS_CACHE_DEDUP_WAITS: u32 = 1004;
    pub const FS_READ_MSGS: u32 = 1005;
    pub const FS_READ_NS_TOTAL: u32 = 1006;
    pub const FS_READAHEAD_SPAWNS: u32 = 1007;
    pub const FS_DEVICE_READS: u32 = 1008;
    pub const FS_DEVICE_READ_NS_TOTAL: u32 = 1009;
    pub const FS_DEVICE_WRITES: u32 = 1010;
    pub const FS_WRITE_MSGS: u32 = 1011;
    pub const FS_DEVICE_READ_BLOCKS: u32 = 1012;
    pub const FS_DEVICE_WRITE_BLOCKS: u32 = 1013;
}

/// Build a snapshot of the FS metrics in moto-stats wire form. Mirrors
/// [`descriptors`].
async fn entries(fs: &FS) -> Vec<MetricEntry> {
    use super::perf;

    let num_blocks = fs.num_blocks();
    let empty_blocks = fs
        .empty_blocks()
        .await
        .inspect_err(|err| log::error!("FS::empty_blocks() failed: {err:?}"))
        .unwrap_or(0);
    let cache_stats = fs.cache_stats();

    vec![
        MetricEntry::global(ids::FS_CAPACITY_BYTES, num_blocks * 4096),
        MetricEntry::global(ids::FS_AVAILABLE_BYTES, empty_blocks * 4096),
        MetricEntry::global(ids::FS_CACHE_HITS, cache_stats.hits),
        MetricEntry::global(ids::FS_CACHE_MISSES, cache_stats.misses),
        MetricEntry::global(ids::FS_CACHE_DEDUP_WAITS, cache_stats.dedup_waits),
        MetricEntry::global(ids::FS_READ_MSGS, perf::get(&perf::READ_MSGS)),
        MetricEntry::global(
            ids::FS_READ_NS_TOTAL,
            perf::ticks_to_ns(perf::get(&perf::READ_TICKS)),
        ),
        MetricEntry::global(ids::FS_READAHEAD_SPAWNS, perf::get(&perf::READAHEAD_SPAWNS)),
        MetricEntry::global(ids::FS_DEVICE_READS, perf::get(&perf::DEVICE_READS)),
        MetricEntry::global(
            ids::FS_DEVICE_READ_NS_TOTAL,
            perf::ticks_to_ns(perf::get(&perf::DEVICE_READ_TICKS)),
        ),
        MetricEntry::global(ids::FS_DEVICE_WRITES, perf::get(&perf::DEVICE_WRITES)),
        MetricEntry::global(ids::FS_WRITE_MSGS, perf::get(&perf::WRITE_MSGS)),
        MetricEntry::global(
            ids::FS_DEVICE_READ_BLOCKS,
            perf::get(&perf::DEVICE_READ_BLOCKS),
        ),
        MetricEntry::global(
            ids::FS_DEVICE_WRITE_BLOCKS,
            perf::get(&perf::DEVICE_WRITE_BLOCKS),
        ),
    ]
}

/// The metric descriptors this provider exposes (the response to `CMD_DESCRIBE`).
/// Mirrors [`entries`]; lets collectors learn metric names at runtime. Static
/// metadata, so the stats-server thread builds it directly.
pub(crate) fn descriptors() -> Vec<MetricDescWire> {
    vec![
        MetricDescWire::new(ids::FS_CAPACITY_BYTES, "fs.capacity_bytes"),
        MetricDescWire::new(ids::FS_AVAILABLE_BYTES, "fs.available_bytes"),
        MetricDescWire::new(ids::FS_CACHE_HITS, "fs.cache.hits"),
        MetricDescWire::new(ids::FS_CACHE_MISSES, "fs.cache.misses"),
        MetricDescWire::new(ids::FS_CACHE_DEDUP_WAITS, "fs.cache.dedup_waits"),
        MetricDescWire::new(ids::FS_READ_MSGS, "fs.read.msgs"),
        MetricDescWire::new(ids::FS_READ_NS_TOTAL, "fs.read.ns_total"),
        MetricDescWire::new(ids::FS_READAHEAD_SPAWNS, "fs.readahead.spawns"),
        MetricDescWire::new(ids::FS_DEVICE_READS, "fs.device.reads"),
        MetricDescWire::new(ids::FS_DEVICE_READ_NS_TOTAL, "fs.device.read_ns_total"),
        MetricDescWire::new(ids::FS_DEVICE_WRITES, "fs.device.writes"),
        MetricDescWire::new(ids::FS_WRITE_MSGS, "fs.write.msgs"),
        MetricDescWire::new(ids::FS_DEVICE_READ_BLOCKS, "fs.device.read_blocks"),
        MetricDescWire::new(ids::FS_DEVICE_WRITE_BLOCKS, "fs.device.write_blocks"),
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
pub(super) fn spawn_stats_responder(fs: Rc<LocalRwLock<FS>>) {
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
    fs: Rc<LocalRwLock<FS>>,
    mut requests: moto_async::channel::Receiver<StatsRequest>,
) {
    while let Some(req) = requests.recv().await {
        let snapshot = entries(&*fs.read().await).await;
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
