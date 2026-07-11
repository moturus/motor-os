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
use std::{cell::Cell, rc::Rc, sync::OnceLock};

/// Data-path performance counters for the FS runtime. Diagnostics only: pure
/// counters, no behavior. Everything that touches them — the command handlers,
/// the virtio partition, [`stats_responder_task`] — runs on the single-threaded
/// IO runtime, so plain `Cell`s are race-free and cost a few ns to bump.
/// Created once in `super::init` and shared via `Rc` (mirrors
/// `runtime::net::stats::NetStats`).
///
/// The FS runtime is CPU-bound during streaming, so the hot path must stay
/// near-free: durations accumulate in raw TSC ticks and are compile-time
/// gated (see [`TIMINGS`]); the ticks->ns conversion happens only when the
/// stats provider is queried.
#[derive(Default)]
pub(super) struct FsStats {
    /// CMD_READ messages handled.
    pub read_msgs: Cell<u64>,
    /// Total TSC ticks spent in `on_cmd_read` (decode to response sent).
    pub read_ticks: Cell<u64>,
    /// CMD_WRITE messages handled.
    pub write_msgs: Cell<u64>,
    /// Readahead tasks spawned.
    pub readahead_spawns: Cell<u64>,
    /// Read requests submitted to the virtio device (a scatter-gather
    /// request covers up to 16 blocks; see `device_read_blocks`).
    pub device_reads: Cell<u64>,
    /// 4k blocks read from the virtio device.
    pub device_read_blocks: Cell<u64>,
    /// Total TSC ticks from virtio read submission to completion.
    pub device_read_ticks: Cell<u64>,
    /// Write requests submitted to the virtio device (a scatter-gather
    /// request covers up to 16 blocks; see `device_write_blocks`).
    pub device_writes: Cell<u64>,
    /// 4k blocks written to the virtio device.
    pub device_write_blocks: Cell<u64>,
}

/// Compile-time switch for the TSC timing pairs (`read_ticks`,
/// `device_read_ticks`). `Instant::now()` is a vdso rdtsc — cheap on bare
/// metal, but a possible VM exit under some hypervisor configurations,
/// which at two reads per 4KB message is a measurable tax. Timings are
/// only needed when actively diagnosing latency: flip to `true` locally,
/// don't commit it on. Counters are unaffected (a few ns each).
pub(super) const TIMINGS: bool = false;

/// The current TSC value; always 0 when [`TIMINGS`] is off (the const
/// folds the rdtsc away).
pub(super) fn now_ticks() -> u64 {
    if TIMINGS {
        moto_rt::time::Instant::now().as_u64()
    } else {
        0
    }
}

/// Convert accumulated TSC ticks to nanoseconds. Not for the hot path.
fn ticks_to_ns(ticks: u64) -> u64 {
    moto_rt::time::Instant::from_u64(ticks)
        .duration_since(moto_rt::time::Instant::from_u64(0))
        .as_nanos() as u64
}

/// FS metric ids. They are private to sys-io: collectors learn their names
/// dynamically via `CMD_DESCRIBE` (moto-stats hardcodes no metric ids).
mod ids {
    pub const FS_CAPACITY_BYTES: u32 = 1000;
    pub const FS_AVAILABLE_BYTES: u32 = 1001;

    // Data-path performance counters (see [`super::FsStats`] and
    // `BlockCache::cache_stats`), added to diagnose sequential-read speed.
    // The two *_NS_TOTAL metrics read 0 unless [`super::TIMINGS`] is
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
async fn entries(fs: &FS, stats: &FsStats) -> Vec<MetricEntry> {
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
        MetricEntry::global(ids::FS_READ_MSGS, stats.read_msgs.get()),
        MetricEntry::global(ids::FS_READ_NS_TOTAL, ticks_to_ns(stats.read_ticks.get())),
        MetricEntry::global(ids::FS_READAHEAD_SPAWNS, stats.readahead_spawns.get()),
        MetricEntry::global(ids::FS_DEVICE_READS, stats.device_reads.get()),
        MetricEntry::global(
            ids::FS_DEVICE_READ_NS_TOTAL,
            ticks_to_ns(stats.device_read_ticks.get()),
        ),
        MetricEntry::global(ids::FS_DEVICE_WRITES, stats.device_writes.get()),
        MetricEntry::global(ids::FS_WRITE_MSGS, stats.write_msgs.get()),
        MetricEntry::global(ids::FS_DEVICE_READ_BLOCKS, stats.device_read_blocks.get()),
        MetricEntry::global(ids::FS_DEVICE_WRITE_BLOCKS, stats.device_write_blocks.get()),
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
pub(super) fn spawn_stats_responder(runtime: super::FsRuntime) {
    let (tx, rx) = moto_async::channel(STATS_REQUEST_CAPACITY);
    if STATS_REQUESTS.set(tx).is_err() {
        log::error!("sys-io: fs stats responder already started");
        return;
    }

    let _ = moto_async::LocalRuntime::spawn(stats_responder_task(runtime, rx));
}

/// Listen for stats requests and answer each with a fresh snapshot of the
/// (single-threaded) FS stats. Runs in the FS runtime.
async fn stats_responder_task(
    runtime: super::FsRuntime,
    mut requests: moto_async::channel::Receiver<StatsRequest>,
) {
    while let Some(req) = requests.recv().await {
        let snapshot = entries(&*runtime.fs.read().await, &runtime.fs_stats).await;
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
