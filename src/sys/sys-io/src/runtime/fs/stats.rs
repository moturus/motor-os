//! Statistics for the FS runtime.
//!
//! sys-io's stats provider (`crate::stats_server`) runs on its own thread, but
//! the mounted filesystems live in this single-threaded async runtime (the
//! mount table, one `LocalRwLock<FS>` per mount) and can't be read from there
//! directly. Instead the stats-server thread *polls* them: it sends a request
//! over a cross-thread channel that [`stats_responder_task`] (running in the FS
//! runtime) answers with a freshly built snapshot. Best effort, never precise —
//! mirrors `crate::runtime::net::stats`.

use super::{FS, mounts};
use async_fs::FileSystem;
use moto_stats::{MetricDescWire, MetricEntry};
use std::{cell::Cell, sync::OnceLock};

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
    /// FS requests refused under memory pressure.
    pub pressure_refused: Cell<u64>,
    /// New FS clients dropped at accept under memory pressure.
    pub pressure_refused_clients: Cell<u64>,
    /// Memfs allocations refused after reclaiming cached pages and resampling.
    pub reserve_refused: Cell<u64>,
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
    // The data partition (mount 0) only. memfs reports its totals below and
    // per-mount figures through the mount listing.
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

    // Memory-pressure refusals; the FS counterparts of `net.pressure_*`.
    // There is no FS episode counter, and `net.pressure_entries` moves only
    // when a net-side refusal observes the episode: an episode in which only
    // FS traffic was refused is visible solely as deltas in these two.
    pub const FS_PRESSURE_REFUSED: u32 = 1014;
    pub const FS_PRESSURE_REFUSED_CLIENTS: u32 = 1015;
    pub const FS_CHANNELS: u32 = 1016;
    pub const FS_CACHE_CAPACITY_BYTES: u32 = 1017;

    // Spawning (see `super::spawn`).
    pub const EXEC_LOCKED_FILES: u32 = 1018;
    pub const SPAWNS: u32 = 1019;
    pub const SPAWN_BUILD_US: u32 = 1020;
    pub const SPAWN_VDSO_US: u32 = 1021;

    // The executable pager (see `super::spawn::pager`).
    pub const PAGER_MAPPINGS: u32 = 1022;
    pub const PAGER_FAULTS: u32 = 1023;
    pub const PAGER_FILLED_PAGES: u32 = 1024;
    pub const PAGER_FAILED_FILLS: u32 = 1025;
    pub const SPAWN_SCAN_US: u32 = 1026;
    pub const PAGER_SERVE_US: u32 = 1027;
    pub const MEMFS_USED_BYTES: u32 = 1028;
    pub const MEMFS_ENTRIES: u32 = 1029;
    pub const MEMFS_CACHED_FREE_BYTES: u32 = 1030;
    pub const FS_RESERVE_REFUSED: u32 = 1031;
}

/// Build a snapshot of the FS metrics in moto-stats wire form. Mirrors
/// [`descriptors`].
pub(super) async fn entries(runtime: &super::FsRuntime) -> Vec<MetricEntry> {
    let stats = &runtime.fs_stats;
    let channels = runtime.channel_budget.fs_channels();
    let locked_files = runtime.exec_locks.borrow().num_locked() as u64;
    let spawn = &runtime.spawn_stats;
    let pager = &runtime.pager;

    let mut metrics = vec![
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
        MetricEntry::global(ids::FS_PRESSURE_REFUSED, stats.pressure_refused.get()),
        MetricEntry::global(
            ids::FS_PRESSURE_REFUSED_CLIENTS,
            stats.pressure_refused_clients.get(),
        ),
        MetricEntry::global(ids::FS_CHANNELS, channels),
        MetricEntry::global(ids::EXEC_LOCKED_FILES, locked_files),
        MetricEntry::global(ids::SPAWNS, spawn.requests.get()),
        MetricEntry::global(ids::SPAWN_BUILD_US, spawn.build_us.get()),
        MetricEntry::global(ids::SPAWN_VDSO_US, spawn.vdso_us.get()),
        MetricEntry::global(ids::PAGER_MAPPINGS, pager.num_mappings()),
        MetricEntry::global(ids::PAGER_FAULTS, pager.faults.get()),
        MetricEntry::global(ids::PAGER_FILLED_PAGES, pager.filled_pages.get()),
        MetricEntry::global(ids::PAGER_FAILED_FILLS, pager.failed_fills.get()),
        MetricEntry::global(ids::SPAWN_SCAN_US, spawn.scan_us.get()),
        MetricEntry::global(ids::PAGER_SERVE_US, pager.serve_us.get()),
        MetricEntry::global(ids::FS_RESERVE_REFUSED, stats.reserve_refused.get()),
    ];
    if let Ok(root) = runtime.root()
        && let Ok(fs) = root.read().await
        && let Ok(empty) = fs.empty_blocks().await
        && root.healthy().is_ok()
    {
        let blocks = fs.num_blocks();
        let capacity = blocks.checked_mul(async_fs::BLOCK_SIZE as u64);
        metrics.extend(capacity.map(|bytes| MetricEntry::global(ids::FS_CAPACITY_BYTES, bytes)));
        // Omitted when a corrupt superblock counts more free blocks than exist.
        let available = mounts::disk_free(blocks, empty);
        metrics.extend(available.map(|bytes| MetricEntry::global(ids::FS_AVAILABLE_BYTES, bytes)));
        if let Some(cache) = fs.cache_stats() {
            metrics.extend([
                MetricEntry::global(ids::FS_CACHE_HITS, cache.hits),
                MetricEntry::global(ids::FS_CACHE_MISSES, cache.misses),
                MetricEntry::global(ids::FS_CACHE_DEDUP_WAITS, cache.dedup_waits),
                MetricEntry::global(ids::FS_CACHE_CAPACITY_BYTES, cache.capacity * 4096),
            ]);
        }
    }
    if let Some((used, entries, cached)) = memfs_totals(runtime).await {
        metrics.extend([
            MetricEntry::global(ids::MEMFS_USED_BYTES, used),
            MetricEntry::global(ids::MEMFS_ENTRIES, entries),
            MetricEntry::global(ids::MEMFS_CACHED_FREE_BYTES, cached),
        ]);
    }
    metrics
}

async fn memfs_totals(runtime: &super::FsRuntime) -> Option<(u64, u64, u64)> {
    let mut totals = (0, 0, 0);
    let count = runtime.mounts.borrow().iter().count();
    for index in 0..count {
        let (id, kind) = {
            let table = runtime.mounts.borrow();
            let mount = table.iter().nth(index)?;
            (mount.id, mount.kind)
        };
        if kind != moto_sys_io::api_fs::MountKind::MemFs {
            continue;
        }
        let entry = mounts::Resolved::on_mount(&runtime.mounts, id, async_fs::ROOT_ID).ok()?;
        let fs = entry.read().await.ok()?;
        if let FS::MemFs(fs) = &*fs {
            totals.0 += fs.used_bytes();
            totals.1 += fs.entry_count();
            totals.2 += fs.cached_free_bytes();
        }
    }
    if runtime
        .mounts
        .borrow()
        .iter()
        .any(|mount| mount.kind == moto_sys_io::api_fs::MountKind::MemFs && mount.corrupted)
    {
        None
    } else {
        Some(totals)
    }
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
        MetricDescWire::new(ids::FS_PRESSURE_REFUSED, "fs.pressure_refused"),
        MetricDescWire::new(
            ids::FS_PRESSURE_REFUSED_CLIENTS,
            "fs.pressure_refused_clients",
        ),
        MetricDescWire::new(ids::FS_CHANNELS, "fs.channels"),
        MetricDescWire::new(ids::FS_CACHE_CAPACITY_BYTES, "fs.cache.capacity_bytes"),
        MetricDescWire::new(ids::EXEC_LOCKED_FILES, "exec.locked_files"),
        MetricDescWire::new(ids::SPAWNS, "spawn.requests"),
        MetricDescWire::new(ids::SPAWN_BUILD_US, "spawn.build_us"),
        MetricDescWire::new(ids::SPAWN_VDSO_US, "spawn.vdso_us"),
        MetricDescWire::new(ids::PAGER_MAPPINGS, "pager.mappings"),
        MetricDescWire::new(ids::PAGER_FAULTS, "pager.faults"),
        MetricDescWire::new(ids::PAGER_FILLED_PAGES, "pager.filled_pages"),
        MetricDescWire::new(ids::PAGER_FAILED_FILLS, "pager.failed_fills"),
        MetricDescWire::new(ids::SPAWN_SCAN_US, "spawn.scan_us"),
        MetricDescWire::new(ids::PAGER_SERVE_US, "pager.serve_us"),
        MetricDescWire::new(ids::MEMFS_USED_BYTES, "fs.memfs.used_bytes"),
        MetricDescWire::new(ids::MEMFS_ENTRIES, "fs.memfs.entries"),
        MetricDescWire::new(ids::MEMFS_CACHED_FREE_BYTES, "fs.memfs.cached_free_bytes"),
        MetricDescWire::new(ids::FS_RESERVE_REFUSED, "fs.reserve_refused"),
    ]
}

/// Requests handled on the FS runtime, with a one-shot reply to the caller.
enum StatsRequest {
    Snapshot(moto_async::oneshot::Sender<Vec<MetricEntry>>),
    #[cfg(debug_assertions)]
    TestExecutableLocks(moto_async::oneshot::Sender<Result<(), String>>),
    #[cfg(debug_assertions)]
    TestPagerWindows(moto_async::oneshot::Sender<Result<(), String>>),
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
        match req {
            StatsRequest::Snapshot(respond_to) => {
                let snapshot = entries(&runtime).await;
                // The receiver is gone if the stats-server thread stopped waiting; ignore.
                let _ = respond_to.send(snapshot);
            }
            #[cfg(debug_assertions)]
            StatsRequest::TestExecutableLocks(respond_to) => {
                let result = super::spawn::self_test::queued_mutations(&runtime).await;
                let _ = respond_to.send(result);
            }
            #[cfg(debug_assertions)]
            StatsRequest::TestPagerWindows(respond_to) => {
                let result = super::spawn::pager::self_test::coalesced_windows(&runtime).await;
                let _ = respond_to.send(result);
            }
        }
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
        if requests
            .send(StatsRequest::Snapshot(respond_to))
            .await
            .is_err()
        {
            return Vec::new();
        }
        response.await.unwrap_or_default()
    })
}

/// Run a native regression on the FS runtime through the existing on-demand
/// self-test endpoint; only that runtime can touch its locks and poll its
/// handlers. `request` wraps the reply sender in the matching request.
#[cfg(debug_assertions)]
fn run_fs_self_test(
    request: fn(moto_async::oneshot::Sender<Result<(), String>>) -> StatsRequest,
) -> Result<(), String> {
    let requests = STATS_REQUESTS.get().ok_or("FS runtime not started")?;
    moto_async::LocalRuntime::new().block_on(async {
        let (respond_to, response) = moto_async::oneshot();
        requests
            .send(request(respond_to))
            .await
            .map_err(|_| "FS runtime stopped")?;
        response.await.map_err(|_| "FS self-test reply lost")?
    })
}

#[cfg(debug_assertions)]
pub(super) fn test_executable_locks() -> Result<(), String> {
    run_fs_self_test(StatsRequest::TestExecutableLocks)
}

#[cfg(debug_assertions)]
pub(super) fn test_pager_windows() -> Result<(), String> {
    run_fs_self_test(StatsRequest::TestPagerWindows)
}
