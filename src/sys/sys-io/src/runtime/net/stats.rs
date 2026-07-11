//! Statistics for Net runtime, including devices and sockets.
//!
//! sys-io's stats provider (`crate::stats_server`) runs on its own thread, but
//! the net stats live in this single-threaded async runtime (plain `Cell`s) and
//! can't be read from there directly. Instead the stats-server thread *polls*
//! them: it sends a request over a cross-thread channel that
//! [`stats_responder_task`] (running in the net runtime) answers with a freshly
//! built snapshot. Best effort, never precise.
//!
//! This module also hosts the `sys-io-stats-service` sync-RPC service (see
//! [`moto_sys_io::stats`]) that lists live TCP sockets. It runs on its own
//! thread and reuses the same cross-thread polling mechanism to read the socket
//! table out of the net runtime.

use moto_ipc::sync::{ChannelSize, LocalServer, ResponseHeader};
use moto_stats::{MetricDescWire, MetricEntry};
use moto_sys::SysHandle;
use moto_sys_io::stats::{
    CMD_TCP_STATS, GetTcpSocketStatsRequest, GetTcpSocketStatsResponse, MAX_TCP_SOCKET_STATS,
    TcpSocketStatsV1, URL_IO_STATS,
};
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

    // Data-path performance counters (see [`super::NetStats`]), added to
    // diagnose TCP throughput/latency (rnetbench). All always live.
    pub const NET_DEVICE_RX_PACKETS: u32 = 8;
    pub const NET_DEVICE_RX_BYTES: u32 = 9;
    pub const NET_DEVICE_TX_PACKETS: u32 = 10;
    pub const NET_DEVICE_TX_BYTES: u32 = 11;
    pub const NET_TCP_RX_MSGS: u32 = 12;
    pub const NET_TCP_RX_BYTES: u32 = 13;
    pub const NET_TCP_TX_MSGS: u32 = 14;
    pub const NET_TCP_TX_BYTES: u32 = 15;
    pub const NET_TCP_RX_ACKS: u32 = 16;
    pub const NET_TCP_RX_ALLOC_WAITS: u32 = 17;
    pub const NET_POLL_RUNS: u32 = 18;
}

/// Net runtime statistics: socket-count gauges plus data-path performance
/// counters. Everything that touches them runs on the single-threaded net
/// runtime, so plain `Cell`s are race-free and cost a few ns to bump.
/// Created once in [`super::init`] and shared via `Rc` (`NetRuntime::stats`);
/// mirrors `runtime::fs::stats::FsStats`.
#[derive(Default)]
pub(super) struct NetStats {
    pub num_devices: Cell<u64>,
    pub active_clients: Cell<u64>,
    pub total_clients: Cell<u64>,
    pub tcp_sockets: Cell<u64>,
    pub total_tcp_sockets: Cell<u64>,
    pub tcp_listening_sockets: Cell<u64>,
    pub udp_sockets: Cell<u64>,
    pub total_udp_sockets: Cell<u64>,

    // Data-path performance counters, added to diagnose TCP
    // throughput/latency (rnetbench). All always live.
    /// Ethernet frames received from virtio devices (excludes loopback).
    pub device_rx_packets: Cell<u64>,
    /// Bytes in those frames, headers included.
    pub device_rx_bytes: Cell<u64>,
    /// Ethernet frames submitted to virtio devices (excludes loopback).
    pub device_tx_packets: Cell<u64>,
    /// Bytes in those frames, headers included.
    pub device_tx_bytes: Cell<u64>,
    /// TcpStreamRx messages (io_pages) sent to clients.
    pub tcp_rx_msgs: Cell<u64>,
    /// Payload bytes in those messages. Page fill ratio =
    /// tcp_rx_bytes / (tcp_rx_msgs * 4096).
    pub tcp_rx_bytes: Cell<u64>,
    /// TcpStreamTx messages received from clients (one message carries
    /// up to 8 io_pages).
    pub tcp_tx_msgs: Cell<u64>,
    /// Payload bytes in those messages. Same fill caveat as tcp_rx_bytes.
    pub tcp_tx_bytes: Cell<u64>,
    /// TcpStreamRxAck messages received. One per stream: the client's
    /// I-am-ready signal that starts the RX pump (the vestigial
    /// every-8th-Rx-msg acks were deleted 2026-07-11).
    pub tcp_rx_acks: Cell<u64>,
    /// Times the TCP RX pump found the subchannel out of io_pages and
    /// had to wait for the client to consume + free one.
    pub tcp_rx_alloc_waits: Cell<u64>,
    /// smoltcp `iface.poll()` calls (all devices, loopback included).
    pub poll_runs: Cell<u64>,
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
            MetricEntry::global(ids::NET_DEVICE_RX_PACKETS, self.device_rx_packets.get()),
            MetricEntry::global(ids::NET_DEVICE_RX_BYTES, self.device_rx_bytes.get()),
            MetricEntry::global(ids::NET_DEVICE_TX_PACKETS, self.device_tx_packets.get()),
            MetricEntry::global(ids::NET_DEVICE_TX_BYTES, self.device_tx_bytes.get()),
            MetricEntry::global(ids::NET_TCP_RX_MSGS, self.tcp_rx_msgs.get()),
            MetricEntry::global(ids::NET_TCP_RX_BYTES, self.tcp_rx_bytes.get()),
            MetricEntry::global(ids::NET_TCP_TX_MSGS, self.tcp_tx_msgs.get()),
            MetricEntry::global(ids::NET_TCP_TX_BYTES, self.tcp_tx_bytes.get()),
            MetricEntry::global(ids::NET_TCP_RX_ACKS, self.tcp_rx_acks.get()),
            MetricEntry::global(ids::NET_TCP_RX_ALLOC_WAITS, self.tcp_rx_alloc_waits.get()),
            MetricEntry::global(ids::NET_POLL_RUNS, self.poll_runs.get()),
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
        MetricDescWire::new(ids::NET_DEVICE_RX_PACKETS, "net.device.rx_packets"),
        MetricDescWire::new(ids::NET_DEVICE_RX_BYTES, "net.device.rx_bytes"),
        MetricDescWire::new(ids::NET_DEVICE_TX_PACKETS, "net.device.tx_packets"),
        MetricDescWire::new(ids::NET_DEVICE_TX_BYTES, "net.device.tx_bytes"),
        MetricDescWire::new(ids::NET_TCP_RX_MSGS, "net.tcp.rx_msgs"),
        MetricDescWire::new(ids::NET_TCP_RX_BYTES, "net.tcp.rx_bytes"),
        MetricDescWire::new(ids::NET_TCP_TX_MSGS, "net.tcp.tx_msgs"),
        MetricDescWire::new(ids::NET_TCP_TX_BYTES, "net.tcp.tx_bytes"),
        MetricDescWire::new(ids::NET_TCP_RX_ACKS, "net.tcp.rx_acks"),
        MetricDescWire::new(ids::NET_TCP_RX_ALLOC_WAITS, "net.tcp.rx_alloc_waits"),
        MetricDescWire::new(ids::NET_POLL_RUNS, "net.poll_runs"),
    ]
}

/// A request from a polling thread for a fresh snapshot, carrying the one-shot
/// channel to respond on. Answered by [`stats_responder_task`] in the net runtime.
enum StatsRequest {
    /// A metrics snapshot for the moto-stats provider (`crate::stats_server`).
    Metrics(moto_async::oneshot::Sender<Vec<MetricEntry>>),
    /// A page of TCP socket stats (ids >= `start_id`, ordered) for the
    /// `sys-io-stats-service`.
    TcpSockets {
        start_id: u64,
        respond_to: moto_async::oneshot::Sender<Vec<TcpSocketStatsV1>>,
    },
}

/// Sender half of the request channel. Set once, when the net runtime spawns its
/// responder task; read by the polling threads in [`query_metrics`] and
/// [`query_tcp_socket_stats`].
static STATS_REQUESTS: OnceLock<moto_async::channel::Sender<StatsRequest>> = OnceLock::new();

/// Capacity of the request channel. Each polling thread keeps only one query
/// outstanding at a time, so this only needs slack for races.
const STATS_REQUEST_CAPACITY: usize = 4;

/// Spawn the task that answers snapshot requests from the polling threads. Call
/// once, from the net runtime.
pub(super) fn spawn_stats_responder(runtime: super::NetRuntime) {
    let (tx, rx) = moto_async::channel(STATS_REQUEST_CAPACITY);
    if STATS_REQUESTS.set(tx).is_err() {
        log::error!("sys-io: net stats responder already started");
        return;
    }

    let _ = moto_async::LocalRuntime::spawn(stats_responder_task(runtime, rx));
}

/// Listen for stats requests and answer each with a fresh snapshot built from the
/// (single-threaded) net runtime. Runs in the net runtime.
async fn stats_responder_task(
    runtime: super::NetRuntime,
    mut requests: moto_async::channel::Receiver<StatsRequest>,
) {
    while let Some(req) = requests.recv().await {
        // The receiver is gone if the polling thread stopped waiting; ignore.
        match req {
            StatsRequest::Metrics(respond_to) => {
                let _ = respond_to.send(runtime.stats.entries());
            }
            StatsRequest::TcpSockets {
                start_id,
                respond_to,
            } => {
                let _ = respond_to.send(collect_tcp_socket_stats(&runtime, start_id));
            }
        }
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
        if requests
            .send(StatsRequest::Metrics(respond_to))
            .await
            .is_err()
        {
            return Vec::new();
        }
        response.await.unwrap_or_default()
    })
}

/// Poll a page of TCP socket stats (ids >= `start_id`, ordered by id) out of the
/// net runtime. Called from the socket-stats-service thread; returns empty if the
/// net runtime isn't up yet.
fn query_tcp_socket_stats(start_id: u64) -> Vec<TcpSocketStatsV1> {
    let Some(requests) = STATS_REQUESTS.get() else {
        return Vec::new();
    };

    moto_async::LocalRuntime::new().block_on(async move {
        let (respond_to, response) = moto_async::oneshot();
        if requests
            .send(StatsRequest::TcpSockets {
                start_id,
                respond_to,
            })
            .await
            .is_err()
        {
            return Vec::new();
        }
        response.await.unwrap_or_default()
    })
}

/// Build a page of TCP socket stats: sockets with id >= `start_id`, ordered by
/// id, capped at [`MAX_TCP_SOCKET_STATS`]. Runs in the net runtime.
fn collect_tcp_socket_stats(runtime: &super::NetRuntime, start_id: u64) -> Vec<TcpSocketStatsV1> {
    use super::socket::MotoSocket;

    // Snapshot the socket handles, then drop the borrow: building each socket's
    // stats re-borrows the runtime inner (to read the smoltcp state).
    let sockets: Vec<_> = runtime.inner.borrow().sockets.values().cloned().collect();

    let mut stats: Vec<TcpSocketStatsV1> = sockets
        .iter()
        .filter(|socket| socket.borrow().is_tcp())
        .map(MotoSocket::collect_tcp_stats)
        .filter(|stat| stat.id >= start_id)
        .collect();

    // Ordered by id so clients can page through via start_id.
    stats.sort_by_key(|stat| stat.id);
    stats.truncate(MAX_TCP_SOCKET_STATS);
    stats
}

/// Spawn the `sys-io-stats-service` thread, which serves the TCP socket listing
/// (see [`moto_sys_io::stats`]). Safe to call before the net runtime is up: it
/// simply returns no sockets until the responder task is running.
pub(crate) fn start_socket_stats_service() {
    let _ = std::thread::Builder::new()
        .name("sys-io:ss".to_owned())
        .spawn(socket_stats_thread);
}

fn socket_stats_thread() {
    let mut server = match LocalServer::new(URL_IO_STATS, ChannelSize::Small, 4, 2) {
        Ok(s) => s,
        Err(err) => {
            log::error!("sys-io: failed to start socket stats server: {err:?}");
            return;
        }
    };

    log::debug!("sys-io socket stats server started");

    loop {
        match server.wait(SysHandle::NONE, &[]) {
            Ok(wakers) => {
                for waker in wakers {
                    process_socket_stats(&mut server, waker);
                }
            }
            // Dropped connections are already cleaned up by wait(); nothing to do.
            Err(_dropped) => {}
        }
    }
}

fn process_socket_stats(server: &mut LocalServer, waker: SysHandle) {
    let Some(conn) = server.get_connection(waker) else {
        return;
    };
    if !conn.connected() || !conn.have_req() {
        return;
    }

    let (cmd, start_id) = {
        let raw = conn.raw_channel();
        let req = unsafe { raw.get::<GetTcpSocketStatsRequest>() };
        (req.header.cmd, req.start_id)
    };

    match cmd {
        CMD_TCP_STATS => {
            let stats = query_tcp_socket_stats(start_id);
            let raw = conn.raw_channel();
            let resp = unsafe { raw.get_mut::<GetTcpSocketStatsResponse<MAX_TCP_SOCKET_STATS>>() };
            debug_assert!(stats.len() <= MAX_TCP_SOCKET_STATS);
            resp.num_results = stats.len() as u64;
            resp.socket_stats[..stats.len()].copy_from_slice(&stats);
            resp.header.result = moto_rt::E_OK;
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
