//! sys-io stats provider: a synchronous-RPC service ("sys-io-stats") that
//! exposes sys-io's metrics via the moto-stats protocol.
//!
//! sys-io's `NetStats` live inside a single-threaded async runtime
//! (`Rc<Cell<..>>`), so they cannot be read from another thread directly.
//! Instead the net runtime periodically publishes a snapshot into the lock-free
//! [`NET`] atomics here, which the stats-server thread reads on demand. Best
//! effort, never precise — consistent with the rest of Motor OS stats.

use std::sync::atomic::{AtomicU64, Ordering};

use moto_ipc::sync::*;
use moto_stats::{MetricDescWire, MetricEntry};
use moto_sys::SysHandle;

/// This provider's service URL and registry name.
const STATS_URL: &str = "sys-io-stats";
const PROVIDER_NAME: &str = "sys-io";

/// This provider's metric ids. They are private to sys-io: collectors learn
/// their names dynamically via `CMD_DESCRIBE` (moto-stats hardcodes no metric
/// ids). When sys-io is split into sys-io-fs / sys-io-net, each will own its
/// own id space.
mod ids {
    pub const NET_NUM_DEVICES: u32 = 0;
    pub const NET_ACTIVE_CLIENTS: u32 = 1;
    pub const NET_TOTAL_CLIENTS: u32 = 2;
    pub const NET_TCP_SOCKETS: u32 = 3;
    pub const NET_TOTAL_TCP_SOCKETS: u32 = 4;
    pub const NET_TCP_LISTENING_SOCKETS: u32 = 5;
}

/// A lock-free snapshot of the net runtime's stats, written by the net runtime
/// and read by the stats-server thread.
pub struct NetSnapshot {
    num_devices: AtomicU64,
    active_clients: AtomicU64,
    total_clients: AtomicU64,
    tcp_sockets: AtomicU64,
    total_tcp_sockets: AtomicU64,
    tcp_listening_sockets: AtomicU64,
}

impl NetSnapshot {
    const fn new() -> Self {
        Self {
            num_devices: AtomicU64::new(0),
            active_clients: AtomicU64::new(0),
            total_clients: AtomicU64::new(0),
            tcp_sockets: AtomicU64::new(0),
            total_tcp_sockets: AtomicU64::new(0),
            tcp_listening_sockets: AtomicU64::new(0),
        }
    }

    /// Publish the latest values. Called from the net runtime.
    #[allow(clippy::too_many_arguments)]
    pub fn store(
        &self,
        num_devices: u64,
        active_clients: u64,
        total_clients: u64,
        tcp_sockets: u64,
        total_tcp_sockets: u64,
        tcp_listening_sockets: u64,
    ) {
        self.num_devices.store(num_devices, Ordering::Relaxed);
        self.active_clients.store(active_clients, Ordering::Relaxed);
        self.total_clients.store(total_clients, Ordering::Relaxed);
        self.tcp_sockets.store(tcp_sockets, Ordering::Relaxed);
        self.total_tcp_sockets
            .store(total_tcp_sockets, Ordering::Relaxed);
        self.tcp_listening_sockets
            .store(tcp_listening_sockets, Ordering::Relaxed);
    }

    fn entries(&self) -> Vec<MetricEntry> {
        vec![
            MetricEntry::global(ids::NET_NUM_DEVICES, self.num_devices.load(Ordering::Relaxed)),
            MetricEntry::global(
                ids::NET_ACTIVE_CLIENTS,
                self.active_clients.load(Ordering::Relaxed),
            ),
            MetricEntry::global(
                ids::NET_TOTAL_CLIENTS,
                self.total_clients.load(Ordering::Relaxed),
            ),
            MetricEntry::global(ids::NET_TCP_SOCKETS, self.tcp_sockets.load(Ordering::Relaxed)),
            MetricEntry::global(
                ids::NET_TOTAL_TCP_SOCKETS,
                self.total_tcp_sockets.load(Ordering::Relaxed),
            ),
            MetricEntry::global(
                ids::NET_TCP_LISTENING_SOCKETS,
                self.tcp_listening_sockets.load(Ordering::Relaxed),
            ),
        ]
    }
}

pub static NET: NetSnapshot = NetSnapshot::new();

/// The metric descriptors this provider exposes (the response to `CMD_DESCRIBE`).
/// Mirrors [`NetSnapshot::entries`]; lets collectors learn metric names at runtime.
fn descriptors() -> Vec<MetricDescWire> {
    vec![
        MetricDescWire::new(ids::NET_NUM_DEVICES, "net.num_devices"),
        MetricDescWire::new(ids::NET_ACTIVE_CLIENTS, "net.active_clients"),
        MetricDescWire::new(ids::NET_TOTAL_CLIENTS, "net.total_clients"),
        MetricDescWire::new(ids::NET_TCP_SOCKETS, "net.tcp_sockets"),
        MetricDescWire::new(ids::NET_TOTAL_TCP_SOCKETS, "net.total_tcp_sockets"),
        MetricDescWire::new(ids::NET_TCP_LISTENING_SOCKETS, "net.tcp_listening_sockets"),
    ]
}

/// Spawn the stats-server thread. Safe to call before the net runtime is up: the
/// provider simply returns zeros until the first snapshot is published.
pub fn start() {
    let _ = std::thread::Builder::new()
        .name("sys-io:stats".to_owned())
        .spawn(run);
    let _ = std::thread::Builder::new()
        .name("sys-io:stats-reg".to_owned())
        .spawn(register_with_retry);
}

/// Register this provider with the stats registry. sys-io is loaded by the
/// kernel before sys-init launches the registry daemon, so we retry until the
/// registry is up (mirroring `moto_log::init`'s startup retry).
fn register_with_retry() {
    let mut tries = 0u32;
    loop {
        match moto_stats::Collector::register(PROVIDER_NAME, STATS_URL) {
            Ok(()) => {
                log::debug!("sys-io: registered stats provider after {tries} tries");
                return;
            }
            Err(_) => {
                tries += 1;
                // Give up logging-loudly after a while, but keep trying quietly:
                // the registry may start late, or be restarted.
                if tries == 60 {
                    log::warn!("sys-io: stats registry still unreachable; still retrying");
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }
}

fn run() {
    let mut server = match LocalServer::new(STATS_URL, ChannelSize::Small, 4, 2) {
        Ok(s) => s,
        Err(err) => {
            log::error!("sys-io: failed to start stats server: {err:?}");
            return;
        }
    };

    log::debug!("sys-io stats server started");

    loop {
        match server.wait(SysHandle::NONE, &[]) {
            Ok(wakers) => {
                for waker in wakers {
                    process(&mut server, waker);
                }
            }
            // Dropped connections are already cleaned up by wait(); nothing to do.
            Err(_dropped) => {}
        }
    }
}

fn process(server: &mut LocalServer, waker: SysHandle) {
    let Some(conn) = server.get_connection(waker) else {
        return;
    };
    if !conn.connected() || !conn.have_req() {
        return;
    }

    let (cmd, start_index) = {
        let raw = conn.raw_channel();
        let req = unsafe { raw.get::<moto_stats::PagedRequest>() };
        (req.header.cmd, req.start_index)
    };

    match cmd {
        moto_stats::CMD_QUERY_METRICS => {
            let entries = NET.entries();
            moto_stats::respond_pods(conn.data_mut(), &entries, start_index);
        }
        moto_stats::CMD_DESCRIBE => {
            let descs = descriptors();
            moto_stats::respond_pods(conn.data_mut(), &descs, start_index);
        }
        _ => {
            let raw = conn.raw_channel();
            unsafe {
                raw.get_mut::<ResponseHeader>().result = moto_rt::E_INVALID_ARGUMENT;
            }
        }
    }

    let _ = conn.finish_rpc();
}
