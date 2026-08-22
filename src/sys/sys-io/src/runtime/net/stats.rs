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
#[cfg(debug_assertions)]
use moto_sys_io::stats::{CMD_SELF_TEST, MAX_SELF_TEST_FAILURE_LEN, SelfTestResponse};
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
    pub const NET_UDP_TX_DROPPED: u32 = 19;
    pub const NET_DEVICE_RX_DROPPED: u32 = 20;
    pub const NET_RX_CSUM_FAILED: u32 = 21;
    pub const NET_TCP_HALF_OPEN: u32 = 22;
    pub const NET_TCP_HALF_OPEN_TOTAL: u32 = 23;
    pub const NET_TCP_SYN_RST_UNMATCHED: u32 = 24;
    pub const NET_TCP_BACKLOG_EXTRA: u32 = 25;
    pub const NET_TCP_SYN_BACKLOG_DROPPED: u32 = 26;
    pub const NET_NEIGHBOR_ADMISSION_REFUSED: u32 = 27;
    pub const NET_RX_LOOPBACK_DROPPED: u32 = 28;

    /// The received-frame size histogram takes this id and the ones above it,
    /// one per bucket, so the next metric added starts after the whole range.
    /// See [`super::RX_SIZE_BUCKETS`].
    pub const NET_DEVICE_RX_SIZE_BASE: u32 = 29;

    // Memory pressure mode (see [`super::super::pressure`]); the histogram
    // above owns ids 29..=33.
    pub const NET_PRESSURE_ACTIVE: u32 = 34;
    pub const NET_PRESSURE_ENTRIES: u32 = 35;
    pub const NET_PRESSURE_REFUSED: u32 = 36;
    pub const NET_PRESSURE_DEFERRED_REPLENISH: u32 = 37;
    pub const NET_PRESSURE_LOW_PAGES: u32 = 38;
    pub const NET_PRESSURE_HIGH_PAGES: u32 = 39;
    pub const NET_PRESSURE_REFUSED_CLIENTS: u32 = 40;

    // SYN cookies (see [`super::super::half_open`] for the caps that engage
    // them).
    pub const NET_TCP_COOKIES_SENT: u32 = 41;
    pub const NET_TCP_COOKIES_ACCEPTED: u32 = 42;
    pub const NET_TCP_COOKIES_REJECTED: u32 = 43;
    pub const NET_TCP_COOKIE_RESTORES_DROPPED: u32 = 44;

    // The io_channel accept pool (see `net_listener`).
    pub const NET_LISTENERS_ARMED: u32 = 45;
    pub const NET_CLIENTS_REFUSED: u32 = 46;

    // Egress rate limits on socketless replies (`max_rst_rate` /
    // `max_syn_cookie_rate` in sys-net.toml).
    pub const NET_TCP_RST_SUPPRESSED: u32 = 47;
    pub const NET_TCP_COOKIES_SUPPRESSED: u32 = 48;

    // Established sockets waiting for accept(), and connections refused at
    // that queue's hard limits.
    pub const NET_TCP_ACCEPT_BACKLOG: u32 = 49;
    pub const NET_TCP_ACCEPT_OVERFLOW: u32 = 50;

    // IP fragmentation, reassembly, and path-MTU discovery.
    pub const NET_IPV4_FRAGMENTS_RX: u32 = 51;
    pub const NET_IPV6_FRAGMENTS_RX: u32 = 52;
    pub const NET_IPV4_FRAGMENTS_TX: u32 = 53;
    pub const NET_IPV6_FRAGMENTS_TX: u32 = 54;
    pub const NET_REASSEMBLIES_COMPLETED: u32 = 55;
    pub const NET_REASSEMBLY_MALFORMED_DROPS: u32 = 56;
    pub const NET_REASSEMBLY_NO_SLOT_DROPS: u32 = 57;
    pub const NET_REASSEMBLY_ALLOCATION_DROPS: u32 = 58;
    pub const NET_REASSEMBLY_EXPIRY_DROPS: u32 = 59;
    pub const NET_REASSEMBLY_DUPLICATES: u32 = 60;
    pub const NET_REASSEMBLY_RANGE_LIMIT_DROPS: u32 = 61;
    pub const NET_EGRESS_FRAGMENT_STAGE_BUSY_DROPS: u32 = 62;
    pub const NET_PMTU_UPDATES_ACCEPTED: u32 = 63;
    pub const NET_ICMP_PMTU_MESSAGES_REJECTED: u32 = 64;

    pub const NET_CHANNELS: u32 = 65;
}

/// Upper bounds, in bytes, of the received-frame size histogram. A frame larger
/// than the last bound falls in a bucket of its own, so there is one more bucket
/// than there are bounds here.
///
/// 64 separates bare ACKs from data. 1514 is a full Ethernet frame, so the top
/// bucket cannot fill until the driver acks guest segmentation offload and the
/// device starts delivering coalesced super-segments -- the receive-coalescing
/// decision in `docs/plans/networking-remaining-steps.md`.
pub(super) const RX_SIZE_BUCKETS: [usize; 4] = [64, 512, 1024, 1514];

/// Which [`NetStats::rx_size`] bucket a frame of `len` bytes belongs in.
pub(super) fn rx_size_bucket(len: usize) -> usize {
    RX_SIZE_BUCKETS
        .iter()
        .position(|bound| len <= *bound)
        .unwrap_or(RX_SIZE_BUCKETS.len())
}

/// The metric name of histogram bucket `idx`.
fn rx_size_metric_name(idx: usize) -> String {
    match RX_SIZE_BUCKETS.get(idx) {
        Some(bound) => format!("net.device.rx_size.le_{bound}"),
        None => format!(
            "net.device.rx_size.gt_{}",
            RX_SIZE_BUCKETS[RX_SIZE_BUCKETS.len() - 1]
        ),
    }
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
    /// moto-netstack `iface.poll()` calls (all devices, loopback included).
    pub poll_runs: Cell<u64>,
    /// UDP datagrams discarded because the socket they name is not ours to
    /// send on any more: dropped, or owned by another client. A client that
    /// keeps its close behind the datagrams it staged never lands here, so a
    /// rising count means datagrams are being lost to that reordering.
    pub udp_tx_dropped: Cell<u64>,
    /// Receive completions the virtio driver rejected before the netstack saw
    /// them: a used length that cannot hold the virtio-net header or overruns
    /// the buffer we posted, or a header the negotiated feature set cannot
    /// produce (a GSO frame, or one spanning several buffers). Nothing on the
    /// network can cause one; a rising count means the device is misbehaving.
    pub device_rx_dropped: Cell<u64>,
    /// Received TCP segments and UDP datagrams the netstack dropped because
    /// their checksum did not verify. Frames the device vouched for are never
    /// verified, so they cannot land here; a nonzero count means either real
    /// corruption on the wire or a device that vouched for less than it should
    /// have.
    pub rx_csum_failed: Cell<u64>,
    /// Listening sockets that have accepted a peer's SYN and are waiting for
    /// the handshake to complete. Each one holds its full receive and transmit
    /// rings, so this is the memory a SYN flood commands; nothing bounds it
    /// today except the 15-second listening-socket timeout.
    pub tcp_half_open: Cell<u64>,
    /// How many sockets have entered that state. A handshake with a peer that
    /// answers lasts a fraction of a round trip, far less than a stats query,
    /// so the gauge above is unobservable for ordinary traffic and this is what
    /// says the accounting works. Also the arrival rate the cap is chosen from.
    pub tcp_half_open_total: Cell<u64>,
    /// Connection requests the netstack reset because nothing was listening for
    /// them. Only bare SYNs count.
    pub tcp_syn_rst_unmatched: Cell<u64>,
    /// Connection requests the netstack dropped because the listener that owns
    /// the endpoint had no socket left to take them. The peer retransmits, so
    /// unlike a reset this is a connection delayed rather than lost; a rising
    /// count is bursts arriving deeper than the pool they meet.
    pub tcp_syn_backlog_dropped: Cell<u64>,
    /// Listening sockets that demand added to the pools beyond what their
    /// clients asked for at bind, summed over every pool: the memory bursts
    /// commanded, and what `max_backlog_global` bounds. Falls back to zero as
    /// the sweep returns growth the traffic stopped using.
    pub tcp_backlog_extra: Cell<u64>,
    /// SYN cookies minted: connection requests answered statelessly because
    /// a listener's admission was at its half-open cap. A rising count is a
    /// SYN flood being ridden out.
    pub tcp_syn_cookies_sent: Cell<u64>,
    /// Cookie handshakes completed: connections a verified cookie ACK proved
    /// and a restored socket carried into the accept path.
    pub tcp_syn_cookies_accepted: Cell<u64>,
    /// Unmatched ACKs at cookie-verifying endpoints that failed validation
    /// and were reset -- forged or expired cookies, or a bad timestamp echo.
    pub tcp_syn_cookies_rejected: Cell<u64>,
    /// Verified restorations lost to a full per-poll queue or refused at
    /// enrollment (listener torn down, memory pressure); each cost the peer
    /// a retransmission.
    pub tcp_cookie_restores_dropped: Cell<u64>,
    /// No-listener resets `max_rst_rate`'s bucket suppressed: the offending
    /// segment was dropped unanswered. A rising count is a scan or reflection
    /// attempt being ridden out; loopback is exempt, so nothing local lands
    /// here.
    pub tcp_rst_suppressed: Cell<u64>,
    /// Cookie SYN|ACKs `max_syn_cookie_rate`'s bucket suppressed: the request
    /// was dropped for the peer to retransmit, as if cookies were not
    /// engaged. Nonzero means a flood beyond both the half-open cap and the
    /// cookie rate.
    pub tcp_syn_cookies_suppressed: Cell<u64>,
    /// Established sockets waiting for their listener's next accept.
    pub tcp_accept_backlog: Cell<u64>,
    /// Completed connections reset because that backlog was full.
    pub tcp_accept_overflow: Cell<u64>,
    /// io_channel listeners currently armed and parked for a client. Zero is
    /// the state where a connect would answer `NotFound`; the accept path's
    /// floor refuses its client rather than serve from it.
    pub net_listeners_armed: Cell<u64>,
    /// Clients answered with an explicit `E_OUT_OF_MEMORY` refusal -- the
    /// armed-listener floor or memory pressure -- instead of being served.
    pub clients_refused: Cell<u64>,
    /// Neighbor mappings the netstack refused because an unsolicited packet --
    /// an ARP request or a neighbor solicitation, either of which any peer on
    /// the segment can send -- offered one while the cache was full. Such a
    /// packet may never displace a cached neighbor, so a rising count means
    /// either more neighbors than the cache holds or someone trying to flush
    /// it.
    pub neighbor_admission_refused: Cell<u64>,
    /// Frames the netstack dropped because a 127/8 address arrived on a device
    /// that is not loopback. Nothing legitimate produces one: such a frame is
    /// either a peer claiming to be a local process -- the trust every program
    /// that checks for a loopback peer relies on -- or a badly misrouted one.
    pub rx_loopback_dropped: Cell<u64>,
    /// Received frame lengths, bucketed by [`RX_SIZE_BUCKETS`]. This is what
    /// `device_rx_bytes / device_rx_packets` averages away: the same 509 B/pkt
    /// mean comes both from all-512-byte data frames and from a mix of bare
    /// ACKs with MTU-framed data, and only the second leaves room to coalesce.
    pub rx_size: [Cell<u64>; RX_SIZE_BUCKETS.len() + 1],

    // IP fragmentation, reassembly, and path-MTU discovery. These accumulate
    // the drain-on-read per-interface counters in moto-netstack.
    pub ipv4_fragments_rx: Cell<u64>,
    pub ipv6_fragments_rx: Cell<u64>,
    pub ipv4_fragments_tx: Cell<u64>,
    pub ipv6_fragments_tx: Cell<u64>,
    pub reassemblies_completed: Cell<u64>,
    pub reassembly_malformed_drops: Cell<u64>,
    pub reassembly_no_slot_drops: Cell<u64>,
    pub reassembly_allocation_drops: Cell<u64>,
    pub reassembly_expiry_drops: Cell<u64>,
    pub reassembly_duplicates: Cell<u64>,
    pub reassembly_range_limit_drops: Cell<u64>,
    pub egress_fragment_stage_busy_drops: Cell<u64>,
    pub pmtu_updates_accepted: Cell<u64>,
    pub icmp_pmtu_messages_rejected: Cell<u64>,

    // Memory pressure mode; see [`super::pressure`]. The active gauge has no
    // field: it is the kernel's shared-page flag, read at snapshot time.
    /// Episodes sys-io noticed: counted on the first refusal or deferral of
    /// each, so a quiet episode nobody asked anything during is not counted.
    pub pressure_entries: Cell<u64>,
    /// Requests refused with OutOfMemory by pressure mode: TCP binds and
    /// connects, UDP binds, ICMP echoes.
    pub pressure_refused: Cell<u64>,
    /// Listening-pool replenishments parked by pressure mode. Departures
    /// count, so this can grow faster than the pools that end up parked.
    pub pressure_deferred_replenish: Cell<u64>,
    /// The kernel's watermarks, in small pages: the flag rises when
    /// free-for-admission reaches the low one and clears at the high one.
    pub pressure_low_pages: Cell<u64>,
    pub pressure_high_pages: Cell<u64>,
    /// New client connections dropped because they arrived under pressure.
    pub pressure_refused_clients: Cell<u64>,
}

impl NetStats {
    pub(super) fn add_ip_packet_stats(&self, sample: moto_netstack::iface::IpPacketStats) {
        macro_rules! accumulate {
            ($field:ident) => {
                if sample.$field != 0 {
                    self.$field
                        .set(self.$field.get().wrapping_add(sample.$field));
                }
            };
        }

        accumulate!(ipv4_fragments_rx);
        accumulate!(ipv6_fragments_rx);
        accumulate!(ipv4_fragments_tx);
        accumulate!(ipv6_fragments_tx);
        accumulate!(reassemblies_completed);
        accumulate!(reassembly_malformed_drops);
        accumulate!(reassembly_no_slot_drops);
        accumulate!(reassembly_allocation_drops);
        accumulate!(reassembly_expiry_drops);
        accumulate!(reassembly_duplicates);
        accumulate!(reassembly_range_limit_drops);
        accumulate!(egress_fragment_stage_busy_drops);
        accumulate!(pmtu_updates_accepted);
        accumulate!(icmp_pmtu_messages_rejected);
    }

    /// Build a snapshot of the metrics in moto-stats wire form. Mirrors
    /// [`descriptors`].
    fn entries(&self, channels: u64) -> Vec<MetricEntry> {
        let mut entries = vec![
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
            MetricEntry::global(ids::NET_UDP_TX_DROPPED, self.udp_tx_dropped.get()),
            MetricEntry::global(ids::NET_DEVICE_RX_DROPPED, self.device_rx_dropped.get()),
            MetricEntry::global(ids::NET_RX_CSUM_FAILED, self.rx_csum_failed.get()),
            MetricEntry::global(ids::NET_TCP_HALF_OPEN, self.tcp_half_open.get()),
            MetricEntry::global(ids::NET_TCP_HALF_OPEN_TOTAL, self.tcp_half_open_total.get()),
            MetricEntry::global(
                ids::NET_TCP_SYN_RST_UNMATCHED,
                self.tcp_syn_rst_unmatched.get(),
            ),
            MetricEntry::global(ids::NET_TCP_BACKLOG_EXTRA, self.tcp_backlog_extra.get()),
            MetricEntry::global(
                ids::NET_TCP_SYN_BACKLOG_DROPPED,
                self.tcp_syn_backlog_dropped.get(),
            ),
            MetricEntry::global(
                ids::NET_NEIGHBOR_ADMISSION_REFUSED,
                self.neighbor_admission_refused.get(),
            ),
            MetricEntry::global(ids::NET_RX_LOOPBACK_DROPPED, self.rx_loopback_dropped.get()),
        ];

        entries.extend(self.rx_size.iter().enumerate().map(|(idx, count)| {
            MetricEntry::global(ids::NET_DEVICE_RX_SIZE_BASE + idx as u32, count.get())
        }));

        entries.extend([
            MetricEntry::global(ids::NET_TCP_COOKIES_SENT, self.tcp_syn_cookies_sent.get()),
            MetricEntry::global(
                ids::NET_TCP_COOKIES_ACCEPTED,
                self.tcp_syn_cookies_accepted.get(),
            ),
            MetricEntry::global(
                ids::NET_TCP_COOKIES_REJECTED,
                self.tcp_syn_cookies_rejected.get(),
            ),
            MetricEntry::global(
                ids::NET_TCP_COOKIE_RESTORES_DROPPED,
                self.tcp_cookie_restores_dropped.get(),
            ),
            MetricEntry::global(ids::NET_LISTENERS_ARMED, self.net_listeners_armed.get()),
            MetricEntry::global(ids::NET_CLIENTS_REFUSED, self.clients_refused.get()),
            MetricEntry::global(ids::NET_CHANNELS, channels),
            MetricEntry::global(ids::NET_TCP_RST_SUPPRESSED, self.tcp_rst_suppressed.get()),
            MetricEntry::global(
                ids::NET_TCP_COOKIES_SUPPRESSED,
                self.tcp_syn_cookies_suppressed.get(),
            ),
            MetricEntry::global(ids::NET_TCP_ACCEPT_BACKLOG, self.tcp_accept_backlog.get()),
            MetricEntry::global(ids::NET_TCP_ACCEPT_OVERFLOW, self.tcp_accept_overflow.get()),
        ]);

        entries.extend([
            MetricEntry::global(ids::NET_IPV4_FRAGMENTS_RX, self.ipv4_fragments_rx.get()),
            MetricEntry::global(ids::NET_IPV6_FRAGMENTS_RX, self.ipv6_fragments_rx.get()),
            MetricEntry::global(ids::NET_IPV4_FRAGMENTS_TX, self.ipv4_fragments_tx.get()),
            MetricEntry::global(ids::NET_IPV6_FRAGMENTS_TX, self.ipv6_fragments_tx.get()),
            MetricEntry::global(
                ids::NET_REASSEMBLIES_COMPLETED,
                self.reassemblies_completed.get(),
            ),
            MetricEntry::global(
                ids::NET_REASSEMBLY_MALFORMED_DROPS,
                self.reassembly_malformed_drops.get(),
            ),
            MetricEntry::global(
                ids::NET_REASSEMBLY_NO_SLOT_DROPS,
                self.reassembly_no_slot_drops.get(),
            ),
            MetricEntry::global(
                ids::NET_REASSEMBLY_ALLOCATION_DROPS,
                self.reassembly_allocation_drops.get(),
            ),
            MetricEntry::global(
                ids::NET_REASSEMBLY_EXPIRY_DROPS,
                self.reassembly_expiry_drops.get(),
            ),
            MetricEntry::global(
                ids::NET_REASSEMBLY_DUPLICATES,
                self.reassembly_duplicates.get(),
            ),
            MetricEntry::global(
                ids::NET_REASSEMBLY_RANGE_LIMIT_DROPS,
                self.reassembly_range_limit_drops.get(),
            ),
            MetricEntry::global(
                ids::NET_EGRESS_FRAGMENT_STAGE_BUSY_DROPS,
                self.egress_fragment_stage_busy_drops.get(),
            ),
            MetricEntry::global(
                ids::NET_PMTU_UPDATES_ACCEPTED,
                self.pmtu_updates_accepted.get(),
            ),
            MetricEntry::global(
                ids::NET_ICMP_PMTU_MESSAGES_REJECTED,
                self.icmp_pmtu_messages_rejected.get(),
            ),
        ]);

        entries.extend([
            MetricEntry::global(ids::NET_PRESSURE_ACTIVE, moto_sys::memory_pressure() as u64),
            MetricEntry::global(ids::NET_PRESSURE_ENTRIES, self.pressure_entries.get()),
            MetricEntry::global(ids::NET_PRESSURE_REFUSED, self.pressure_refused.get()),
            MetricEntry::global(
                ids::NET_PRESSURE_DEFERRED_REPLENISH,
                self.pressure_deferred_replenish.get(),
            ),
            MetricEntry::global(ids::NET_PRESSURE_LOW_PAGES, self.pressure_low_pages.get()),
            MetricEntry::global(ids::NET_PRESSURE_HIGH_PAGES, self.pressure_high_pages.get()),
            MetricEntry::global(
                ids::NET_PRESSURE_REFUSED_CLIENTS,
                self.pressure_refused_clients.get(),
            ),
        ]);
        entries
    }
}

/// The metric descriptors this provider exposes (the response to `CMD_DESCRIBE`).
/// Mirrors [`NetStats::entries`]; lets collectors learn metric names at runtime.
/// Static metadata, so the stats-server thread builds it directly.
pub(crate) fn descriptors() -> Vec<MetricDescWire> {
    let mut descriptors = vec![
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
        MetricDescWire::new(ids::NET_UDP_TX_DROPPED, "net.udp.tx_dropped"),
        MetricDescWire::new(ids::NET_DEVICE_RX_DROPPED, "net.device.rx_dropped"),
        MetricDescWire::new(ids::NET_RX_CSUM_FAILED, "net.rx.csum_failed"),
        MetricDescWire::new(ids::NET_TCP_HALF_OPEN, "net.tcp.half_open"),
        MetricDescWire::new(ids::NET_TCP_HALF_OPEN_TOTAL, "net.tcp.half_open_total"),
        MetricDescWire::new(ids::NET_TCP_SYN_RST_UNMATCHED, "net.tcp.syn_rst_unmatched"),
        MetricDescWire::new(ids::NET_TCP_BACKLOG_EXTRA, "net.tcp.backlog_extra"),
        MetricDescWire::new(
            ids::NET_TCP_SYN_BACKLOG_DROPPED,
            "net.tcp.syn_backlog_dropped",
        ),
        MetricDescWire::new(
            ids::NET_NEIGHBOR_ADMISSION_REFUSED,
            "net.neighbor.admission_refused",
        ),
        MetricDescWire::new(ids::NET_RX_LOOPBACK_DROPPED, "net.rx.loopback_dropped"),
    ];

    descriptors.extend((0..=RX_SIZE_BUCKETS.len()).map(|idx| {
        MetricDescWire::new(
            ids::NET_DEVICE_RX_SIZE_BASE + idx as u32,
            &rx_size_metric_name(idx),
        )
    }));

    descriptors.extend([
        MetricDescWire::new(ids::NET_TCP_COOKIES_SENT, "net.tcp.cookies_sent"),
        MetricDescWire::new(ids::NET_TCP_COOKIES_ACCEPTED, "net.tcp.cookies_accepted"),
        MetricDescWire::new(ids::NET_TCP_COOKIES_REJECTED, "net.tcp.cookies_rejected"),
        MetricDescWire::new(
            ids::NET_TCP_COOKIE_RESTORES_DROPPED,
            "net.tcp.cookie_restores_dropped",
        ),
        MetricDescWire::new(ids::NET_LISTENERS_ARMED, "net.listeners_armed"),
        MetricDescWire::new(ids::NET_CLIENTS_REFUSED, "net.clients_refused"),
        MetricDescWire::new(ids::NET_CHANNELS, "net.channels"),
        MetricDescWire::new(ids::NET_TCP_RST_SUPPRESSED, "net.tcp.rst_suppressed"),
        MetricDescWire::new(
            ids::NET_TCP_COOKIES_SUPPRESSED,
            "net.tcp.cookies_suppressed",
        ),
        MetricDescWire::new(ids::NET_TCP_ACCEPT_BACKLOG, "net.tcp.accept_backlog"),
        MetricDescWire::new(ids::NET_TCP_ACCEPT_OVERFLOW, "net.tcp.accept_overflow"),
    ]);

    descriptors.extend([
        MetricDescWire::new(ids::NET_IPV4_FRAGMENTS_RX, "net.ipv4.fragments_rx"),
        MetricDescWire::new(ids::NET_IPV6_FRAGMENTS_RX, "net.ipv6.fragments_rx"),
        MetricDescWire::new(ids::NET_IPV4_FRAGMENTS_TX, "net.ipv4.fragments_tx"),
        MetricDescWire::new(ids::NET_IPV6_FRAGMENTS_TX, "net.ipv6.fragments_tx"),
        MetricDescWire::new(ids::NET_REASSEMBLIES_COMPLETED, "net.reassembly.completed"),
        MetricDescWire::new(
            ids::NET_REASSEMBLY_MALFORMED_DROPS,
            "net.reassembly.malformed_drops",
        ),
        MetricDescWire::new(
            ids::NET_REASSEMBLY_NO_SLOT_DROPS,
            "net.reassembly.no_slot_drops",
        ),
        MetricDescWire::new(
            ids::NET_REASSEMBLY_ALLOCATION_DROPS,
            "net.reassembly.allocation_drops",
        ),
        MetricDescWire::new(
            ids::NET_REASSEMBLY_EXPIRY_DROPS,
            "net.reassembly.expiry_drops",
        ),
        MetricDescWire::new(ids::NET_REASSEMBLY_DUPLICATES, "net.reassembly.duplicates"),
        MetricDescWire::new(
            ids::NET_REASSEMBLY_RANGE_LIMIT_DROPS,
            "net.reassembly.range_limit_drops",
        ),
        MetricDescWire::new(
            ids::NET_EGRESS_FRAGMENT_STAGE_BUSY_DROPS,
            "net.fragment.stage_busy_drops",
        ),
        MetricDescWire::new(ids::NET_PMTU_UPDATES_ACCEPTED, "net.pmtu.updates_accepted"),
        MetricDescWire::new(
            ids::NET_ICMP_PMTU_MESSAGES_REJECTED,
            "net.pmtu.icmp_messages_rejected",
        ),
    ]);

    descriptors.extend([
        MetricDescWire::new(ids::NET_PRESSURE_ACTIVE, "net.pressure_active"),
        MetricDescWire::new(ids::NET_PRESSURE_ENTRIES, "net.pressure_entries"),
        MetricDescWire::new(ids::NET_PRESSURE_REFUSED, "net.pressure_refused"),
        MetricDescWire::new(
            ids::NET_PRESSURE_DEFERRED_REPLENISH,
            "net.pressure_deferred_replenish",
        ),
        MetricDescWire::new(ids::NET_PRESSURE_LOW_PAGES, "net.pressure_low_pages"),
        MetricDescWire::new(ids::NET_PRESSURE_HIGH_PAGES, "net.pressure_high_pages"),
        MetricDescWire::new(
            ids::NET_PRESSURE_REFUSED_CLIENTS,
            "net.pressure_refused_clients",
        ),
    ]);
    descriptors
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
                let _ =
                    respond_to.send(runtime.stats.entries(runtime.channel_budget.net_channels()));
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
    // stats re-borrows the runtime inner (to read the netstack state).
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
        // Runs on this thread, not the net runtime's: the self-tests are pure
        // and quick, but nothing about them should be able to stall packets.
        #[cfg(debug_assertions)]
        CMD_SELF_TEST => {
            let outcome = crate::self_test::run_all();
            let raw = conn.raw_channel();
            let resp = unsafe { raw.get_mut::<SelfTestResponse>() };
            resp.tests_run = outcome.tests_run;
            resp.failures = outcome.failures;

            let failure = outcome.first_failure.as_bytes();
            let len = failure.len().min(MAX_SELF_TEST_FAILURE_LEN);
            resp.failure_len = len as u32;
            resp.first_failure[..len].copy_from_slice(&failure[..len]);
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

/// Debug-only tests of the code above, run inside a live sys-io. See
/// [`crate::self_test`].
#[cfg(debug_assertions)]
pub(crate) mod self_test {
    use super::*;
    use crate::self_test::{SelfTest, st_assert, st_assert_eq};

    pub(crate) const TESTS: &[SelfTest] = &[
        ("net::stats::rx_size_buckets_are_exact", buckets_are_exact),
        (
            "net::stats::every_metric_is_described",
            every_metric_is_described,
        ),
        (
            "net::stats::ip_packet_counters_accumulate_and_wrap",
            ip_packet_counters_accumulate_and_wrap,
        ),
    ];

    /// Each bound is the last length its own bucket takes.
    ///
    /// An off-by-one here would not fail anything, it would quietly file every
    /// full Ethernet frame as oversized -- which is the one reading the
    /// coalescing decision turns on.
    fn buckets_are_exact() -> Result<(), String> {
        for (idx, bound) in RX_SIZE_BUCKETS.iter().enumerate() {
            st_assert_eq!(rx_size_bucket(*bound), idx);
            st_assert_eq!(rx_size_bucket(bound + 1), idx + 1);
        }

        // A zero-length frame is impossible, but nothing here rejects one, so
        // say where it goes rather than leave it to the reader.
        st_assert_eq!(rx_size_bucket(0), 0);
        st_assert_eq!(rx_size_bucket(usize::MAX), RX_SIZE_BUCKETS.len());
        st_assert!(RX_SIZE_BUCKETS.is_sorted());
        Ok(())
    }

    fn ip_packet_counters_accumulate_and_wrap() -> Result<(), String> {
        let stats = NetStats::default();
        stats.ipv4_fragments_rx.set(u64::MAX);
        stats.add_ip_packet_stats(moto_netstack::iface::IpPacketStats {
            ipv4_fragments_rx: 2,
            reassembly_range_limit_drops: 3,
            pmtu_updates_accepted: 5,
            ..Default::default()
        });

        st_assert_eq!(stats.ipv4_fragments_rx.get(), 1);
        st_assert_eq!(stats.reassembly_range_limit_drops.get(), 3);
        st_assert_eq!(stats.pmtu_updates_accepted.get(), 5);
        st_assert_eq!(stats.ipv6_fragments_rx.get(), 0);
        Ok(())
    }

    /// Every metric reported carries a name, exactly once.
    ///
    /// [`NetStats::entries`] and [`descriptors`] are two hand-kept lists of the
    /// same ids, and a metric missing from the second reads as `?` in every
    /// collector rather than failing anywhere.
    fn every_metric_is_described() -> Result<(), String> {
        let described: Vec<u32> = descriptors().iter().map(|desc| desc.metric).collect();
        let reported: Vec<u32> = NetStats::default()
            .entries(0)
            .iter()
            .map(|entry| entry.metric)
            .collect();

        let mut seen = described.clone();
        seen.sort_unstable();
        seen.dedup();
        st_assert_eq!(seen.len(), described.len());

        st_assert_eq!(described, reported);
        Ok(())
    }
}
