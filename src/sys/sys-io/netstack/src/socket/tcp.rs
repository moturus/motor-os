// Heads up! Before working on this file you should read, at least, RFC 793 and
// the parts of RFC 1122 that discuss TCP, as well as RFC 7323 for some of the TCP options.
// Consult RFC 7414 when implementing a new feature.

use core::fmt::Display;
#[cfg(feature = "async")]
use core::task::Waker;
use core::{fmt, mem};

use crate::phy::PacketMeta;
#[cfg(feature = "async")]
use crate::socket::WakerRegistration;
use crate::socket::{Context, PollAt};
use crate::storage::{Assembler, RingBuffer};
use crate::time::{Duration, Instant};
use crate::wire::{
    IpAddress, IpEndpoint, IpListenEndpoint, IpProtocol, IpRepr, TCP_HEADER_LEN, TcpControl,
    TcpRepr, TcpSeqNumber, TcpTimestampGenerator, TcpTimestampRepr,
};

mod congestion;

macro_rules! tcp_trace {
    ($($arg:expr),*) => (net_log!(trace, $($arg),*));
}

/// Error returned by [`Socket::listen`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ListenError {
    InvalidState,
    Unaddressable,
}

impl Display for ListenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ListenError::InvalidState => write!(f, "invalid state"),
            ListenError::Unaddressable => write!(f, "unaddressable destination"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ListenError {}

/// Error returned by [`Socket::connect`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ConnectError {
    InvalidState,
    Unaddressable,
}

impl Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ConnectError::InvalidState => write!(f, "invalid state"),
            ConnectError::Unaddressable => write!(f, "unaddressable destination"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ConnectError {}

/// Error returned by [`Socket::send`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SendError {
    InvalidState,
}

impl Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SendError::InvalidState => write!(f, "invalid state"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SendError {}

/// Error returned by [`Socket::recv`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RecvError {
    InvalidState,
    Finished,
}

impl Display for RecvError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RecvError::InvalidState => write!(f, "invalid state"),
            RecvError::Finished => write!(f, "operation finished"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RecvError {}

/// A TCP socket ring buffer.
pub type SocketBuffer<'a> = RingBuffer<'a, u8>;

/// The state of a TCP socket, according to [RFC 793].
///
/// [RFC 793]: https://tools.ietf.org/html/rfc793
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum State {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            State::Closed => write!(f, "CLOSED"),
            State::Listen => write!(f, "LISTEN"),
            State::SynSent => write!(f, "SYN-SENT"),
            State::SynReceived => write!(f, "SYN-RECEIVED"),
            State::Established => write!(f, "ESTABLISHED"),
            State::FinWait1 => write!(f, "FIN-WAIT-1"),
            State::FinWait2 => write!(f, "FIN-WAIT-2"),
            State::CloseWait => write!(f, "CLOSE-WAIT"),
            State::Closing => write!(f, "CLOSING"),
            State::LastAck => write!(f, "LAST-ACK"),
            State::TimeWait => write!(f, "TIME-WAIT"),
        }
    }
}

// Every constant here, and every field of `RttEstimator`, is in **microseconds**.
// They were milliseconds, which is coarser than the paths this stack runs on:
// `Instant` counts microseconds, and a millisecond sample truncates a 60-usec
// LAN round trip to zero. Each one keeps the physical value it had; only the
// unit is finer.

/// RFC 6298: (2.1) Until a round-trip time (RTT) measurement has been made for a
/// segment sent between the sender and receiver, the sender SHOULD
/// set RTO <- 1 second,
const RTTE_INITIAL_RTO: u32 = 1_000_000;

// Minimum "safety margin" for the RTO that kicks in when the
// variance gets very low. RFC 6298 (2.4) spends this term on `G`, the clock
// granularity; 5 ms is far coarser than this clock and is really a floor under
// how tight an RTO the variance alone may ask for. Microsecond sampling is what
// makes that floor reachable -- it now binds on any path whose variance is under
// 1.25 ms -- so the value belongs to whatever decides `RTTE_MIN_RTO`, and is
// left alone until then.
const RTTE_MIN_MARGIN: u32 = 5_000;

/// K, according to RFC 6298
const RTTE_K: u32 = 4;

// RFC 6298 (2.4): Whenever RTO is computed, if it is less than 1 second, then the
// RTO SHOULD be rounded up to 1 second.
//
// 200 ms, not the RFC's second, matching Linux: `TCP_RTO_MIN` is `HZ / 5` in
// `include/net/tcp.h`, and `net.ipv4.tcp_rto_min_us` defaults to 200000. The
// RFC's own (2.4) allows this -- "a lower minimum SHOULD be used when it is
// known that a path has a shorter RTT" -- and every path this stack serves is a
// virtio link to its own host. A second here costs a full second of stall for
// one lost segment on a path whose round trip is measured in tens of
// microseconds.
//
// This floor still binds on that path: the estimate under it is about 5 ms, of
// which 5 ms is `RTTE_MIN_MARGIN`. Lowering it further is a separate question
// from matching Linux, and would want the delayed ACK of whatever is at the
// other end -- `TCP_DELACK_MAX` is *also* `HZ / 5`, so a Linux peer may sit on
// an ACK for exactly as long as this timer now waits. What keeps that from
// being a spurious retransmit is that an ACK's delay is inside the RTT sample
// that sets `srtt`, which is the thing this floor is a floor under.
const RTTE_MIN_RTO: u32 = 200_000;

// RFC 6298 (2.5) A maximum value MAY be placed on RTO provided it is at least 60
// seconds
const RTTE_MAX_RTO: u32 = 60_000_000;

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct RttEstimator {
    /// true if we have made at least one rtt measurement.
    have_measurement: bool,
    // Using u32 instead of Duration to save space (Duration is i64)
    /// Smoothed RTT, in microseconds.
    srtt: u32,
    /// RTT variance, in microseconds.
    rttvar: u32,
    /// Retransmission Time-Out, in microseconds.
    rto: u32,
    timestamp: Option<(Instant, TcpSeqNumber)>,
    max_seq_sent: Option<TcpSeqNumber>,
    rto_count: u8,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self {
            have_measurement: false,
            srtt: 0,   // ignored, will be overwritten on first measurement.
            rttvar: 0, // ignored, will be overwritten on first measurement.
            rto: RTTE_INITIAL_RTO,
            timestamp: None,
            max_seq_sent: None,
            rto_count: 0,
        }
    }
}

impl RttEstimator {
    fn retransmission_timeout(&self) -> Duration {
        Duration::from_micros(self.rto as _)
    }

    fn sample(&mut self, new_rtt: u32) {
        // A sample longer than the longest RTO cannot inform a timer that never
        // waits longer than one, so nothing is lost by capping it -- and the cap
        // is also what keeps the smoothing inside `u32`. Microseconds put the
        // top of the type at 71 minutes, which `srtt * 7` below would clear on
        // any path past ten; capped at a minute, that product has an order of
        // magnitude to spare.
        let new_rtt = new_rtt.min(RTTE_MAX_RTO);

        if self.have_measurement {
            // RFC 6298 (2.3) When a subsequent RTT measurement R' is made, a host MUST set (...)
            let diff = (self.srtt as i32 - new_rtt as i32).unsigned_abs();
            self.rttvar = (self.rttvar * 3 + diff).div_ceil(4);
            self.srtt = (self.srtt * 7 + new_rtt).div_ceil(8);
        } else {
            // RFC 6298 (2.2) When the first RTT measurement R is made, the host MUST set (...)
            self.have_measurement = true;
            self.srtt = new_rtt;
            self.rttvar = new_rtt / 2;
        }

        // RFC 6298 (2.2), (2.3)
        let margin = RTTE_MIN_MARGIN.max(self.rttvar * RTTE_K);
        self.rto = (self.srtt + margin).clamp(RTTE_MIN_RTO, RTTE_MAX_RTO);

        self.rto_count = 0;

        tcp_trace!(
            "rtte: sample={:?} srtt={:?} rttvar={:?} rto={:?}",
            new_rtt,
            self.srtt,
            self.rttvar,
            self.rto
        );
    }

    fn on_send(&mut self, timestamp: Instant, seq: TcpSeqNumber) {
        if self
            .max_seq_sent
            .map(|max_seq_sent| seq > max_seq_sent)
            .unwrap_or(true)
        {
            self.max_seq_sent = Some(seq);
            if self.timestamp.is_none() {
                self.timestamp = Some((timestamp, seq));
                tcp_trace!("rtte: sampling at seq={:?}", seq);
            }
        }
    }

    fn on_ack(&mut self, timestamp: Instant, seq: TcpSeqNumber) {
        if let Some((sent_timestamp, sent_seq)) = self.timestamp
            && seq >= sent_seq
        {
            // Saturating rather than `as`: milliseconds made an implausible RTT
            // unrepresentable, microseconds do not, and truncating a
            // stall of over 71 minutes would report it as a *short* round trip.
            let rtt = (timestamp - sent_timestamp).total_micros();
            self.sample(rtt.min(u32::MAX as u64) as u32);
            self.timestamp = None;
        }
    }

    fn on_retransmit(&mut self) {
        if self.timestamp.is_some() {
            tcp_trace!("rtte: abort sampling due to retransmit");
        }
        self.timestamp = None;

        // RFC 6298 (5.5) The host MUST set RTO <- RTO * 2 ("back off the timer").  The
        // maximum value discussed in (2.5) above may be used to provide
        // an upper bound to this doubling operation.
        self.rto = (self.rto * 2).min(RTTE_MAX_RTO);
        tcp_trace!("rtte: doubling rto to {:?}", self.rto);

        // RFC 6298: a TCP implementation MAY clear SRTT and RTTVAR after
        // backing off the timer multiple times as it is likely that the current
        // SRTT and RTTVAR are bogus in this situation.  Once SRTT and RTTVAR
        // are cleared, they should be initialized with the next RTT sample
        // taken per (2.2) rather than using (2.3).
        self.rto_count += 1;
        if self.rto_count >= 3 {
            self.rto_count = 0;
            self.have_measurement = false;
            tcp_trace!("rtte: too many retransmissions, clearing srtt, rttvar.");
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum Timer {
    Idle {
        keep_alive_at: Option<Instant>,
    },
    Retransmit {
        expires_at: Instant,
    },
    FastRetransmit,
    ZeroWindowProbe {
        expires_at: Instant,
        delay: Duration,
    },
    Close {
        expires_at: Instant,
    },
}

const ACK_DELAY_DEFAULT: Duration = Duration::from_millis(10);
const CLOSE_DELAY: Duration = Duration::from_millis(10_000);

impl Timer {
    fn new() -> Timer {
        Timer::Idle {
            keep_alive_at: None,
        }
    }

    fn should_keep_alive(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::Idle {
                keep_alive_at: Some(keep_alive_at),
            } if timestamp >= keep_alive_at => true,
            _ => false,
        }
    }

    fn should_retransmit(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::Retransmit { expires_at } if timestamp >= expires_at => true,
            Timer::FastRetransmit => true,
            _ => false,
        }
    }

    fn should_close(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::Close { expires_at } if timestamp >= expires_at => true,
            _ => false,
        }
    }

    fn should_zero_window_probe(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::ZeroWindowProbe { expires_at, .. } if timestamp >= expires_at => true,
            _ => false,
        }
    }

    fn poll_at(&self) -> PollAt {
        match *self {
            Timer::Idle {
                keep_alive_at: Some(keep_alive_at),
            } => PollAt::Time(keep_alive_at),
            Timer::Idle {
                keep_alive_at: None,
            } => PollAt::Ingress,
            Timer::ZeroWindowProbe { expires_at, .. } => PollAt::Time(expires_at),
            Timer::Retransmit { expires_at, .. } => PollAt::Time(expires_at),
            Timer::FastRetransmit => PollAt::Now,
            Timer::Close { expires_at } => PollAt::Time(expires_at),
        }
    }

    fn set_for_idle(&mut self, timestamp: Instant, interval: Option<Duration>) {
        *self = Timer::Idle {
            keep_alive_at: interval.map(|interval| timestamp + interval),
        }
    }

    fn set_keep_alive(&mut self) {
        if let Timer::Idle { keep_alive_at } = self
            && keep_alive_at.is_none()
        {
            *keep_alive_at = Some(Instant::from_millis(0))
        }
    }

    fn rewind_keep_alive(&mut self, timestamp: Instant, interval: Option<Duration>) {
        if let Timer::Idle { keep_alive_at } = self {
            *keep_alive_at = interval.map(|interval| timestamp + interval)
        }
    }

    fn set_for_retransmit(&mut self, timestamp: Instant, delay: Duration) {
        match *self {
            Timer::Idle { .. }
            | Timer::FastRetransmit
            | Timer::Retransmit { .. }
            | Timer::ZeroWindowProbe { .. } => {
                *self = Timer::Retransmit {
                    expires_at: timestamp + delay,
                }
            }
            Timer::Close { .. } => (),
        }
    }

    fn set_for_fast_retransmit(&mut self) {
        *self = Timer::FastRetransmit
    }

    fn set_for_close(&mut self, timestamp: Instant) {
        *self = Timer::Close {
            expires_at: timestamp + CLOSE_DELAY,
        }
    }

    fn set_for_zero_window_probe(&mut self, timestamp: Instant, delay: Duration) {
        *self = Timer::ZeroWindowProbe {
            expires_at: timestamp + delay,
            delay,
        }
    }

    fn rewind_zero_window_probe(&mut self, timestamp: Instant) {
        if let Timer::ZeroWindowProbe { mut delay, .. } = *self {
            delay = (delay * 2).min(Duration::from_micros(RTTE_MAX_RTO as _));
            *self = Timer::ZeroWindowProbe {
                expires_at: timestamp + delay,
                delay,
            }
        }
    }

    fn is_idle(&self) -> bool {
        matches!(self, Timer::Idle { .. })
    }

    fn is_zero_window_probe(&self) -> bool {
        matches!(self, Timer::ZeroWindowProbe { .. })
    }

    fn is_retransmit(&self) -> bool {
        matches!(self, Timer::Retransmit { .. } | Timer::FastRetransmit)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum AckDelayTimer {
    Idle,
    Waiting(Instant),
    Immediate,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct Tuple {
    local: IpEndpoint,
    remote: IpEndpoint,
}

impl Display for Tuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.local, self.remote)
    }
}

/// A congestion control algorithm.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CongestionControl {
    None,

    #[cfg(feature = "socket-tcp-reno")]
    Reno,

    #[cfg(feature = "socket-tcp-cubic")]
    Cubic,
}

/// A Transmission Control Protocol socket.
///
/// A TCP socket may passively listen for connections or actively connect to another endpoint.
/// Note that, for listening sockets, there is no "backlog"; to be able to simultaneously
/// accept several connections, as many sockets must be allocated, or any new connection
/// attempts will be reset.
#[derive(Debug)]
pub struct Socket<'a> {
    state: State,
    timer: Timer,
    rtte: RttEstimator,
    assembler: Assembler,
    rx_buffer: SocketBuffer<'a>,
    rx_fin_received: bool,
    tx_buffer: SocketBuffer<'a>,
    /// Interval after which, if no inbound packets are received, the connection is aborted.
    timeout: Option<Duration>,
    /// Interval at which keep-alive packets will be sent.
    keep_alive: Option<Duration>,
    /// The time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    hop_limit: Option<u8>,
    /// Address passed to listen(). Listen address is set when listen() is called and
    /// used every time the socket is reset back to the LISTEN state.
    listen_endpoint: IpListenEndpoint,
    /// Current 4-tuple (local and remote endpoints).
    tuple: Option<Tuple>,
    /// The sequence number corresponding to the beginning of the transmit buffer.
    /// I.e. an ACK(local_seq_no+n) packet removes n bytes from the transmit buffer.
    local_seq_no: TcpSeqNumber,
    /// The sequence number corresponding to the beginning of the receive buffer.
    /// I.e. userspace reading n bytes adds n to remote_seq_no.
    remote_seq_no: TcpSeqNumber,
    /// The last sequence number sent.
    /// I.e. in an idle socket, local_seq_no+tx_buffer.len().
    remote_last_seq: TcpSeqNumber,
    /// The last acknowledgement number sent.
    /// I.e. in an idle socket, remote_seq_no+rx_buffer.len().
    remote_last_ack: Option<TcpSeqNumber>,
    /// The last window length sent, in bytes: SYN/SYN|ACK window fields are
    /// recorded verbatim (they are never scaled), all others scaled back up
    /// by `remote_win_shift`. Consumers must not shift this value.
    remote_last_win: u32,
    /// The sending window scaling factor advertised to remotes which support RFC 1323.
    /// It is zero if the window <= 64KiB and/or the remote does not support it.
    remote_win_shift: u8,
    /// When set, `remote_win_shift` announces this value instead of the one
    /// derived from the rx ring, and `reset` restores it: the ring may start
    /// smaller than the configured capacity the scale was chosen for.
    win_shift_override: Option<u8>,
    /// Latched rx capacity target; applies once the connection is
    /// synchronized and the ring holds no unconsumed bytes.
    pending_rx_capacity: Option<usize>,
    /// Latched tx capacity target; applies once the connection is
    /// synchronized and the ring is fully acked and drained.
    pending_tx_capacity: Option<usize>,
    /// The remote window size, relative to local_seq_no
    /// I.e. we're allowed to send octets until local_seq_no+remote_win_len
    remote_win_len: usize,
    /// The receive window scaling factor for remotes which support RFC 1323, None if unsupported.
    remote_win_scale: Option<u8>,
    /// Whether or not the remote supports selective ACK as described in RFC 2018.
    remote_has_sack: bool,
    /// The maximum number of data octets that the remote side may receive.
    remote_mss: usize,
    /// The timestamp of the last packet received.
    remote_last_ts: Option<Instant>,
    /// The sequence number of the last packet received, used for sACK
    local_rx_last_seq: Option<TcpSeqNumber>,
    /// The ACK number of the last packet received.
    local_rx_last_ack: Option<TcpSeqNumber>,
    /// The number of packets received directly after
    /// each other which have the same ACK number.
    local_rx_dup_acks: u8,

    /// Duration for Delayed ACK. If None no ACKs will be delayed.
    ack_delay: Option<Duration>,
    /// Delayed ack timer. If set, packets containing exclusively
    /// ACK or window updates (ie, no data) won't be sent until expiry.
    ack_delay_timer: AckDelayTimer,

    /// Used for rate-limiting: No more challenge ACKs will be sent until this instant.
    challenge_ack_timer: Instant,

    /// Nagle's Algorithm enabled.
    nagle: bool,

    /// The congestion control algorithm.
    congestion_controller: congestion::AnyController,

    /// tsval generator - if some, tcp timestamp is enabled
    tsval_generator: Option<TcpTimestampGenerator>,

    /// 0 if not seen or timestamp not enabled
    last_remote_tsval: u32,

    #[cfg(feature = "async")]
    rx_waker: WakerRegistration,
    #[cfg(feature = "async")]
    tx_waker: WakerRegistration,

    /// If this is set, we will not send a SYN|ACK until this is unset.
    #[cfg(feature = "socket-tcp-pause-synack")]
    synack_paused: bool,
}

const DEFAULT_MSS: usize = 536;

impl<'a> Socket<'a> {
    #[allow(unused_comparisons)] // small usize platforms always pass rx_capacity check
    /// Create a socket using the given buffers.
    pub fn new<T>(rx_buffer: T, tx_buffer: T) -> Socket<'a>
    where
        T: Into<SocketBuffer<'a>>,
    {
        let (rx_buffer, tx_buffer) = (rx_buffer.into(), tx_buffer.into());
        let rx_capacity = rx_buffer.capacity();

        // From RFC 1323:
        // [...] the above constraints imply that 2 * the max window size must be less
        // than 2**31 [...] Thus, the shift count must be limited to 14 (which allows
        // windows of 2**30 = 1 Gbyte).
        #[cfg(not(target_pointer_width = "16"))] // Prevent overflow
        if rx_capacity > (1 << 30) {
            panic!("receiving buffer too large, cannot exceed 1 GiB")
        }
        let rx_cap_log2 = mem::size_of::<usize>() * 8 - rx_capacity.leading_zeros() as usize;

        Socket {
            state: State::Closed,
            timer: Timer::new(),
            rtte: RttEstimator::default(),
            assembler: Assembler::new(),
            tx_buffer,
            rx_buffer,
            rx_fin_received: false,
            timeout: None,
            keep_alive: None,
            hop_limit: None,
            listen_endpoint: IpListenEndpoint::default(),
            tuple: None,
            local_seq_no: TcpSeqNumber::default(),
            remote_seq_no: TcpSeqNumber::default(),
            remote_last_seq: TcpSeqNumber::default(),
            remote_last_ack: None,
            remote_last_win: 0,
            remote_win_len: 0,
            remote_win_shift: rx_cap_log2.saturating_sub(16) as u8,
            win_shift_override: None,
            pending_rx_capacity: None,
            pending_tx_capacity: None,
            remote_win_scale: None,
            remote_has_sack: false,
            remote_mss: DEFAULT_MSS,
            remote_last_ts: None,
            local_rx_last_ack: None,
            local_rx_last_seq: None,
            local_rx_dup_acks: 0,
            ack_delay: Some(ACK_DELAY_DEFAULT),
            ack_delay_timer: AckDelayTimer::Idle,
            challenge_ack_timer: Instant::from_secs(0),
            nagle: true,
            tsval_generator: None,
            last_remote_tsval: 0,
            congestion_controller: congestion::AnyController::new(),

            #[cfg(feature = "async")]
            rx_waker: WakerRegistration::new(),
            #[cfg(feature = "async")]
            tx_waker: WakerRegistration::new(),

            #[cfg(feature = "socket-tcp-pause-synack")]
            synack_paused: false,
        }
    }

    /// Create a socket using the given buffers, announcing the given window
    /// scale instead of the one derived from the rx ring.
    ///
    /// This lets a socket start with a small rx ring and grow it later
    /// (`SocketBuffer::grow_to`) up to what the scale can express: the scale
    /// is announced in our SYN or SYN|ACK and is immutable for the
    /// connection thereafter (RFC 7323), so it must be chosen from the
    /// configured capacity, not the allocated one. A ring smaller than
    /// `65535 << win_shift` is wire-legal; the window field simply reads
    /// small.
    ///
    /// # Panics
    /// Panics if `win_shift` exceeds 14, the largest scale RFC 7323 permits.
    pub fn new_with_win_shift<T>(rx_buffer: T, tx_buffer: T, win_shift: u8) -> Socket<'a>
    where
        T: Into<SocketBuffer<'a>>,
    {
        assert!(
            win_shift <= 14,
            "window scale must not exceed 14 (RFC 7323)"
        );
        let mut socket = Self::new(rx_buffer, tx_buffer);
        socket.win_shift_override = Some(win_shift);
        socket.remote_win_shift = win_shift;
        socket
    }

    /// Enable or disable TCP Timestamp.
    pub fn set_tsval_generator(&mut self, generator: Option<TcpTimestampGenerator>) {
        self.tsval_generator = generator;
    }

    /// Return whether TCP Timestamp is enabled.
    pub fn timestamp_enabled(&self) -> bool {
        self.tsval_generator.is_some()
    }

    /// Set an algorithm for congestion control.
    ///
    /// `CongestionControl::None` indicates that no congestion control is applied.
    /// Options `CongestionControl::Cubic` and `CongestionControl::Reno` are also available.
    /// To use Reno and Cubic, please enable the `socket-tcp-reno` and `socket-tcp-cubic` features
    /// in the `moto-netstack` crate, respectively.
    ///
    /// `CongestionControl::Reno` is a classic congestion control algorithm valued for its simplicity.
    /// Despite having a lower algorithmic complexity than `Cubic`,
    /// it is less efficient in terms of bandwidth usage.
    ///
    /// `CongestionControl::Cubic` represents a modern congestion control algorithm designed to
    /// be more efficient and fair compared to `CongestionControl::Reno`.
    /// It is the default choice for Linux, Windows, and macOS.
    /// `CongestionControl::Cubic` relies on double precision (`f64`) floating point operations, which may cause issues in some contexts:
    /// * Small embedded processors (such as Cortex-M0, Cortex-M1, and Cortex-M3) do not have an FPU, and floating point operations consume significant amounts of CPU time and Flash space.
    /// * Interrupt handlers should almost always avoid floating-point operations.
    /// * Kernel-mode code on desktop processors usually avoids FPU operations to reduce the penalty of saving and restoring FPU registers.
    ///
    /// In all these cases, `CongestionControl::Reno` is a better choice of congestion control algorithm.
    pub fn set_congestion_control(&mut self, congestion_control: CongestionControl) {
        use congestion::*;

        self.congestion_controller = match congestion_control {
            CongestionControl::None => AnyController::None(no_control::NoControl),

            #[cfg(feature = "socket-tcp-reno")]
            CongestionControl::Reno => AnyController::Reno(reno::Reno::new()),

            #[cfg(feature = "socket-tcp-cubic")]
            CongestionControl::Cubic => AnyController::Cubic(cubic::Cubic::new()),
        }
    }

    /// Return the current congestion control algorithm.
    pub fn congestion_control(&self) -> CongestionControl {
        use congestion::*;

        match self.congestion_controller {
            AnyController::None(_) => CongestionControl::None,

            #[cfg(feature = "socket-tcp-reno")]
            AnyController::Reno(_) => CongestionControl::Reno,

            #[cfg(feature = "socket-tcp-cubic")]
            AnyController::Cubic(_) => CongestionControl::Cubic,
        }
    }

    /// Register a waker for receive operations.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `recv` method calls, such as receiving data, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `recv` has
    ///   necessarily changed.
    #[cfg(feature = "async")]
    pub fn register_recv_waker(&mut self, waker: &Waker) {
        self.rx_waker.register(waker)
    }

    /// Register a waker for send operations.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `send` method calls, such as space becoming available in the transmit
    /// buffer, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `send` has
    ///   necessarily changed.
    #[cfg(feature = "async")]
    pub fn register_send_waker(&mut self, waker: &Waker) {
        self.tx_waker.register(waker)
    }

    /// Return the timeout duration.
    ///
    /// See also the [set_timeout](#method.set_timeout) method.
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Return the ACK delay duration.
    ///
    /// See also the [set_ack_delay](#method.set_ack_delay) method.
    pub fn ack_delay(&self) -> Option<Duration> {
        self.ack_delay
    }

    /// Return whether Nagle's Algorithm is enabled.
    ///
    /// See also the [set_nagle_enabled](#method.set_nagle_enabled) method.
    pub fn nagle_enabled(&self) -> bool {
        self.nagle
    }

    /// Pause sending of SYN|ACK packets.
    ///
    /// When this flag is set, the socket will get stuck in `SynReceived` state without sending
    /// any SYN|ACK packets back, until this flag is unset. This is useful for certain niche TCP
    /// proxy usecases.
    #[cfg(feature = "socket-tcp-pause-synack")]
    pub fn pause_synack(&mut self, pause: bool) {
        self.synack_paused = pause;
    }

    /// Return the current window field value, including scaling according to RFC 1323.
    ///
    /// Used in internal calculations as well as packet generation.
    #[inline]
    fn scaled_window(&self) -> u16 {
        u16::try_from(self.rx_buffer.window() >> self.remote_win_shift).unwrap_or(u16::MAX)
    }

    /// Return the last window field value, including scaling according to RFC 1323.
    ///
    /// Used in internal calculations as well as packet generation.
    ///
    /// Unlike `remote_last_win`, we take into account new packets received (but not acknowledged)
    /// since the last window update and adjust the window length accordingly. This ensures a fair
    /// comparison between the last window length and the new window length we're going to
    /// advertise.
    #[inline]
    fn last_scaled_window(&self) -> Option<u16> {
        let last_ack = self.remote_last_ack?;
        let next_ack = self.remote_seq_no + self.rx_buffer.len();

        let last_win = self.remote_last_win as usize;
        // The advertised right edge covers everything the receive path
        // accepted, so this cannot go negative; if it ever did, report no
        // previous window rather than panicking on the dispatch path.
        let last_win_adjusted = (last_ack + last_win).checked_sub(next_ack)?;

        Some(u16::try_from(last_win_adjusted >> self.remote_win_shift).unwrap_or(u16::MAX))
    }

    /// Set the timeout duration.
    ///
    /// A socket with a timeout duration set will abort the connection if either of the following
    /// occurs:
    ///
    ///   * After a [connect](#method.connect) call, the remote endpoint does not respond within
    ///     the specified duration;
    ///   * After establishing a connection, there is data in the transmit buffer and the remote
    ///     endpoint exceeds the specified duration between any two packets it sends;
    ///   * After enabling [keep-alive](#method.set_keep_alive), the remote endpoint exceeds
    ///     the specified duration between any two packets it sends.
    pub fn set_timeout(&mut self, duration: Option<Duration>) {
        self.timeout = duration
    }

    /// Set the ACK delay duration.
    ///
    /// By default, the ACK delay is set to 10ms.
    pub fn set_ack_delay(&mut self, duration: Option<Duration>) {
        self.ack_delay = duration
    }

    /// Enable or disable Nagle's Algorithm.
    ///
    /// Also known as "tinygram prevention". By default, it is enabled.
    /// Disabling it is equivalent to Linux's TCP_NODELAY flag.
    ///
    /// When enabled, Nagle's Algorithm prevents sending segments smaller than MSS if
    /// there is data in flight (sent but not acknowledged). In other words, it ensures
    /// at most only one segment smaller than MSS is in flight at a time.
    ///
    /// It ensures better network utilization by preventing sending many very small packets,
    /// at the cost of increased latency in some situations, particularly when the remote peer
    /// has ACK delay enabled.
    pub fn set_nagle_enabled(&mut self, enabled: bool) {
        self.nagle = enabled
    }

    /// Return the keep-alive interval.
    ///
    /// See also the [set_keep_alive](#method.set_keep_alive) method.
    pub fn keep_alive(&self) -> Option<Duration> {
        self.keep_alive
    }

    /// Set the keep-alive interval.
    ///
    /// An idle socket with a keep-alive interval set will transmit a "keep-alive ACK" packet
    /// every time it receives no communication during that interval. As a result, three things
    /// may happen:
    ///
    ///   * The remote endpoint is fine and answers with an ACK packet.
    ///   * The remote endpoint has rebooted and answers with an RST packet.
    ///   * The remote endpoint has crashed and does not answer.
    ///
    /// The keep-alive functionality together with the timeout functionality allows to react
    /// to these error conditions.
    pub fn set_keep_alive(&mut self, interval: Option<Duration>) {
        self.keep_alive = interval;
        if self.keep_alive.is_some() {
            // If the connection is idle and we've just set the option, it would not take effect
            // until the next packet, unless we wind up the timer explicitly.
            self.timer.set_keep_alive();
        }
    }

    /// Return the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// See also the [set_hop_limit](#method.set_hop_limit) method
    pub fn hop_limit(&self) -> Option<u8> {
        self.hop_limit
    }

    /// Set the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// A socket without an explicitly set hop limit value uses the default [IANA recommended]
    /// value (64).
    ///
    /// # Panics
    ///
    /// This function panics if a hop limit value of 0 is given. See [RFC 1122 § 3.2.1.7].
    ///
    /// [IANA recommended]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
    /// [RFC 1122 § 3.2.1.7]: https://tools.ietf.org/html/rfc1122#section-3.2.1.7
    pub fn set_hop_limit(&mut self, hop_limit: Option<u8>) {
        // A host MUST NOT send a datagram with a hop limit value of 0
        if let Some(0) = hop_limit {
            panic!("the time-to-live value of a packet must not be zero")
        }

        self.hop_limit = hop_limit
    }

    /// Return the listen endpoint
    #[inline]
    pub fn listen_endpoint(&self) -> IpListenEndpoint {
        self.listen_endpoint
    }

    /// Return the local endpoint, or None if not connected.
    #[inline]
    pub fn local_endpoint(&self) -> Option<IpEndpoint> {
        Some(self.tuple?.local)
    }

    /// Return the remote endpoint, or None if not connected.
    #[inline]
    pub fn remote_endpoint(&self) -> Option<IpEndpoint> {
        Some(self.tuple?.remote)
    }

    /// Return the connection state, in terms of the TCP state machine.
    #[inline]
    pub fn state(&self) -> State {
        self.state
    }

    fn reset(&mut self) {
        let rx_cap_log2 =
            mem::size_of::<usize>() * 8 - self.rx_buffer.capacity().leading_zeros() as usize;

        self.state = State::Closed;
        self.timer = Timer::new();
        self.rtte = RttEstimator::default();
        self.assembler = Assembler::new();
        self.tx_buffer.clear();
        self.rx_buffer.clear();
        self.rx_fin_received = false;
        self.listen_endpoint = IpListenEndpoint::default();
        self.tuple = None;
        self.local_seq_no = TcpSeqNumber::default();
        self.remote_seq_no = TcpSeqNumber::default();
        self.remote_last_seq = TcpSeqNumber::default();
        self.remote_last_ack = None;
        self.remote_last_win = 0;
        self.remote_win_len = 0;
        self.remote_win_scale = None;
        self.remote_win_shift = self
            .win_shift_override
            .unwrap_or(rx_cap_log2.saturating_sub(16) as u8);
        // A latched growth must not survive into a reused socket's next
        // connection: its owner re-decides the sizes.
        self.pending_rx_capacity = None;
        self.pending_tx_capacity = None;
        self.remote_mss = DEFAULT_MSS;
        self.remote_last_ts = None;
        self.ack_delay_timer = AckDelayTimer::Idle;
        self.challenge_ack_timer = Instant::from_secs(0);

        #[cfg(feature = "async")]
        {
            self.rx_waker.wake();
            self.tx_waker.wake();
        }
    }

    /// Start listening on the given endpoint.
    ///
    /// This function returns `Err(Error::InvalidState)` if the socket was already open
    /// (see [is_open](#method.is_open)), and `Err(Error::Unaddressable)`
    /// if the port in the given endpoint is zero.
    pub fn listen<T>(&mut self, local_endpoint: T) -> Result<(), ListenError>
    where
        T: Into<IpListenEndpoint>,
    {
        let local_endpoint = local_endpoint.into();
        if local_endpoint.port == 0 {
            return Err(ListenError::Unaddressable);
        }

        if self.is_open() {
            // If we were already listening to same endpoint there is nothing to do; exit early.
            //
            // In the past listening on an socket that was already listening was an error,
            // however this makes writing an acceptor loop with multiple sockets impossible.
            // Without this early exit, if you tried to listen on a socket that's already listening you'll
            // immediately get an error. The only way around this is to abort the socket first
            // before listening again, but this means that incoming connections can actually
            // get aborted between the abort() and the next listen().
            if matches!(self.state, State::Listen) && self.listen_endpoint == local_endpoint {
                return Ok(());
            } else {
                return Err(ListenError::InvalidState);
            }
        }

        self.reset();
        self.listen_endpoint = local_endpoint;
        self.tuple = None;
        self.set_state(State::Listen);
        Ok(())
    }

    /// Connect to a given endpoint.
    ///
    /// The local port must be provided explicitly. Assuming `fn get_ephemeral_port() -> u16`
    /// allocates a port between 49152 and 65535, a connection may be established as follows:
    ///
    /// ```no_run
    /// # #[cfg(all(
    /// #     feature = "medium-ethernet",
    /// #     feature = "proto-ipv4",
    /// # ))]
    /// # {
    /// # use moto_netstack::socket::tcp::{Socket, SocketBuffer};
    /// # use moto_netstack::iface::Interface;
    /// # use moto_netstack::wire::IpAddress;
    /// #
    /// # fn get_ephemeral_port() -> u16 {
    /// #     49152
    /// # }
    /// #
    /// # let mut socket = Socket::new(
    /// #     SocketBuffer::new(vec![0; 1200]),
    /// #     SocketBuffer::new(vec![0; 1200])
    /// # );
    /// #
    /// # let mut iface: Interface = todo!();
    /// #
    /// socket.connect(
    ///     iface.context(),
    ///     (IpAddress::v4(10, 0, 0, 1), 80),
    ///     get_ephemeral_port()
    /// ).unwrap();
    /// # }
    /// ```
    ///
    /// The local address may optionally be provided.
    ///
    /// This function returns an error if the socket was open; see [is_open](#method.is_open).
    /// It also returns an error if the local or remote port is zero, or if the remote address
    /// is unspecified.
    pub fn connect<T, U>(
        &mut self,
        cx: &mut Context,
        remote_endpoint: T,
        local_endpoint: U,
    ) -> Result<(), ConnectError>
    where
        T: Into<IpEndpoint>,
        U: Into<IpListenEndpoint>,
    {
        let remote_endpoint: IpEndpoint = remote_endpoint.into();
        let local_endpoint: IpListenEndpoint = local_endpoint.into();

        if self.is_open() {
            return Err(ConnectError::InvalidState);
        }
        if remote_endpoint.port == 0 || remote_endpoint.addr.is_unspecified() {
            return Err(ConnectError::Unaddressable);
        }
        if local_endpoint.port == 0 {
            return Err(ConnectError::Unaddressable);
        }

        // If local address is not provided, choose it automatically.
        let local_endpoint = IpEndpoint {
            addr: match local_endpoint.addr {
                Some(addr) => {
                    if addr.is_unspecified() {
                        return Err(ConnectError::Unaddressable);
                    }
                    addr
                }
                None => cx
                    .get_source_address(&remote_endpoint.addr)
                    .ok_or(ConnectError::Unaddressable)?,
            },
            port: local_endpoint.port,
        };

        if local_endpoint.addr.version() != remote_endpoint.addr.version() {
            return Err(ConnectError::Unaddressable);
        }

        self.reset();
        self.tuple = Some(Tuple {
            local: local_endpoint,
            remote: remote_endpoint,
        });
        self.set_state(State::SynSent);

        let seq = Self::initial_seq_no(cx, local_endpoint, remote_endpoint);
        self.local_seq_no = seq;
        self.remote_last_seq = seq;
        Ok(())
    }

    /// The netstack's ~6600 lines of TCP tests assert on sequence numbers, so
    /// under test the initial one is a constant rather than a hash.
    #[cfg(test)]
    fn initial_seq_no(_cx: &Context, _local: IpEndpoint, _remote: IpEndpoint) -> TcpSeqNumber {
        TcpSeqNumber(10000)
    }

    #[cfg(not(test))]
    fn initial_seq_no(cx: &Context, local: IpEndpoint, remote: IpEndpoint) -> TcpSeqNumber {
        cx.tcp_isn(local, remote)
    }

    /// Close the transmit half of the full-duplex connection.
    ///
    /// Note that there is no corresponding function for the receive half of the full-duplex
    /// connection; only the remote end can close it. If you no longer wish to receive any
    /// data and would like to reuse the socket right away, use [abort](#method.abort).
    pub fn close(&mut self) {
        match self.state {
            // In the LISTEN state there is no established connection.
            State::Listen => self.set_state(State::Closed),
            // In the SYN-SENT state the remote endpoint is not yet synchronized and, upon
            // receiving an RST, will abort the connection.
            State::SynSent => self.set_state(State::Closed),
            // In the SYN-RECEIVED, ESTABLISHED and CLOSE-WAIT states the transmit half
            // of the connection is open, and needs to be explicitly closed with a FIN.
            State::SynReceived | State::Established => self.set_state(State::FinWait1),
            State::CloseWait => self.set_state(State::LastAck),
            // In the FIN-WAIT-1, FIN-WAIT-2, CLOSING, LAST-ACK, TIME-WAIT and CLOSED states,
            // the transmit half of the connection is already closed, and no further
            // action is needed.
            State::FinWait1
            | State::FinWait2
            | State::Closing
            | State::TimeWait
            | State::LastAck
            | State::Closed => (),
        }
    }

    /// Aborts the connection, if any.
    ///
    /// This function instantly closes the socket. One reset packet will be sent to the remote
    /// endpoint.
    ///
    /// In terms of the TCP state machine, the socket may be in any state and is moved to
    /// the `CLOSED` state.
    pub fn abort(&mut self) {
        self.set_state(State::Closed);
    }

    /// Return whether the socket is passively listening for incoming connections.
    ///
    /// In terms of the TCP state machine, the socket must be in the `LISTEN` state.
    #[inline]
    pub fn is_listening(&self) -> bool {
        match self.state {
            State::Listen => true,
            _ => false,
        }
    }

    /// Return whether the socket is open.
    ///
    /// This function returns true if the socket will process incoming or dispatch outgoing
    /// packets. Note that this does not mean that it is possible to send or receive data through
    /// the socket; for that, use [can_send](#method.can_send) or [can_recv](#method.can_recv).
    ///
    /// In terms of the TCP state machine, the socket must not be in the `CLOSED`
    /// or `TIME-WAIT` states.
    #[inline]
    pub fn is_open(&self) -> bool {
        match self.state {
            State::Closed => false,
            State::TimeWait => false,
            _ => true,
        }
    }

    /// Return whether a connection is active.
    ///
    /// This function returns true if the socket is actively exchanging packets with
    /// a remote endpoint. Note that this does not mean that it is possible to send or receive
    /// data through the socket; for that, use [can_send](#method.can_send) or
    /// [can_recv](#method.can_recv).
    ///
    /// If a connection is established, [abort](#method.close) will send a reset to
    /// the remote endpoint.
    ///
    /// In terms of the TCP state machine, the socket must not be in the `CLOSED`, `TIME-WAIT`,
    /// or `LISTEN` state.
    #[inline]
    pub fn is_active(&self) -> bool {
        match self.state {
            State::Closed => false,
            State::TimeWait => false,
            State::Listen => false,
            _ => true,
        }
    }

    /// Return whether the transmit half of the full-duplex connection is open.
    ///
    /// This function returns true if it's possible to send data and have it arrive
    /// to the remote endpoint. However, it does not make any guarantees about the state
    /// of the transmit buffer, and even if it returns true, [send](#method.send) may
    /// not be able to enqueue any octets.
    ///
    /// In terms of the TCP state machine, the socket must be in the `ESTABLISHED` or
    /// `CLOSE-WAIT` state.
    #[inline]
    pub fn may_send(&self) -> bool {
        match self.state {
            State::Established => true,
            // In CLOSE-WAIT, the remote endpoint has closed our receive half of the connection
            // but we still can transmit indefinitely.
            State::CloseWait => true,
            _ => false,
        }
    }

    /// Return whether the receive half of the full-duplex connection is open.
    ///
    /// This function returns true if it's possible to receive data from the remote endpoint.
    /// It will return true while there is data in the receive buffer, and if there isn't,
    /// as long as the remote endpoint has not closed the connection.
    ///
    /// In terms of the TCP state machine, the socket must be in the `ESTABLISHED`,
    /// `FIN-WAIT-1`, or `FIN-WAIT-2` state, or have data in the receive buffer instead.
    #[inline]
    pub fn may_recv(&self) -> bool {
        match self.state {
            State::Established => true,
            // In FIN-WAIT-1/2, we have closed our transmit half of the connection but
            // we still can receive indefinitely.
            State::FinWait1 | State::FinWait2 => true,
            // If we have something in the receive buffer, we can receive that.
            _ if self.can_recv() => true,
            _ => false,
        }
    }

    /// Check whether the transmit half of the full-duplex connection is open
    /// (see [may_send](#method.may_send)), and the transmit buffer is not full.
    #[inline]
    pub fn can_send(&self) -> bool {
        if !self.may_send() {
            return false;
        }

        !self.tx_buffer.is_full()
    }

    /// Return the maximum number of bytes inside the recv buffer.
    #[inline]
    pub fn recv_capacity(&self) -> usize {
        self.rx_buffer.capacity()
    }

    /// Return the maximum number of bytes inside the transmit buffer.
    #[inline]
    pub fn send_capacity(&self) -> usize {
        self.tx_buffer.capacity()
    }

    /// Return the receive capacity the socket is committed to: the ring
    /// capacity, or the pending growth target if one is latched.
    #[inline]
    pub fn effective_recv_capacity(&self) -> usize {
        self.pending_rx_capacity
            .unwrap_or_else(|| self.rx_buffer.capacity())
    }

    /// Return the transmit capacity the socket is committed to: the ring
    /// capacity, or the pending growth target if one is latched.
    #[inline]
    pub fn effective_send_capacity(&self) -> usize {
        self.pending_tx_capacity
            .unwrap_or_else(|| self.tx_buffer.capacity())
    }

    /// Growth waits until the connection is synchronized: applying a
    /// configured size to a listener-pool or handshaking socket would
    /// defeat lazily-built backlog rings.
    fn growth_deferred(&self) -> bool {
        matches!(
            self.state,
            State::Closed | State::Listen | State::SynSent | State::SynReceived
        )
    }

    /// Request that the receive ring grow to `bytes` capacity.
    ///
    /// The request is clamped to `65535 << shift`, the most the announced
    /// window scale can express; growth never re-announces the shift
    /// (RFC 7323 makes the scale immutable once sent). It applies at the
    /// first moment the connection is synchronized and the ring holds no
    /// unconsumed bytes: immediately when both already hold, at the
    /// ESTABLISHED edge, or when the ring is fully read out. A request at
    /// or below the current capacity clears any pending growth
    /// (shrinking is not supported).
    #[cfg(feature = "alloc")]
    pub fn grow_rx_capacity(&mut self, bytes: usize) {
        let target = bytes.min(65535usize << self.remote_win_shift);
        if target <= self.rx_buffer.capacity() {
            self.pending_rx_capacity = None;
            return;
        }
        self.pending_rx_capacity = Some(target);
        self.apply_pending_rx_growth();
    }

    /// Request that the transmit ring grow to `bytes` capacity.
    ///
    /// Applies at the first moment the connection is synchronized and the
    /// ring is fully acked and drained; latches until then. A request at
    /// or below the current capacity clears any pending growth.
    #[cfg(feature = "alloc")]
    pub fn grow_tx_capacity(&mut self, bytes: usize) {
        if bytes <= self.tx_buffer.capacity() {
            self.pending_tx_capacity = None;
            return;
        }
        self.pending_tx_capacity = Some(bytes);
        self.apply_pending_tx_growth();
    }

    #[cfg(feature = "alloc")]
    fn apply_pending_rx_growth(&mut self) {
        if self.growth_deferred() || !self.rx_buffer.is_empty() {
            return;
        }
        if let Some(target) = self.pending_rx_capacity.take() {
            // Re-clamp: the shift may have shrunk since the request
            // latched (a peer without window scaling zeroes it).
            let target = target.min(65535usize << self.remote_win_shift);
            if target > self.rx_buffer.capacity() {
                self.rx_buffer.grow_to(target);
            }
        }
    }

    #[cfg(feature = "alloc")]
    fn apply_pending_tx_growth(&mut self) {
        if self.growth_deferred() || !self.tx_buffer.is_empty() {
            return;
        }
        if let Some(target) = self.pending_tx_capacity.take()
            && target > self.tx_buffer.capacity()
        {
            self.tx_buffer.grow_to(target);
        }
    }

    /// Check whether the receive buffer is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        !self.rx_buffer.is_empty()
    }

    fn send_impl<'b, F, R>(&'b mut self, f: F) -> Result<R, SendError>
    where
        F: FnOnce(&'b mut SocketBuffer<'a>) -> (usize, R),
    {
        if !self.may_send() {
            return Err(SendError::InvalidState);
        }

        let old_length = self.tx_buffer.len();
        let (size, result) = f(&mut self.tx_buffer);
        if size > 0 {
            // The connection might have been idle for a long time, and so remote_last_ts
            // would be far in the past. Unless we clear it here, we'll abort the connection
            // down over in dispatch() by erroneously detecting it as timed out.
            if old_length == 0 {
                self.remote_last_ts = None
            }

            // if remote win is zero and we go from having no data to some data pending to
            // send, start the zero window probe timer.
            if self.remote_win_len == 0 && self.timer.is_idle() {
                let delay = self.rtte.retransmission_timeout();
                tcp_trace!("starting zero-window-probe timer for t+{}", delay);

                // We don't have access to the current time here, so use Instant::ZERO instead.
                // this will cause the first ZWP to be sent immediately, but that's okay.
                self.timer.set_for_zero_window_probe(Instant::ZERO, delay);
            }

            #[cfg(any(test, feature = "verbose"))]
            tcp_trace!(
                "tx buffer: enqueueing {} octets (now {})",
                size,
                old_length + size
            );
        }
        Ok(result)
    }

    /// Call `f` with the largest contiguous slice of octets in the transmit buffer,
    /// and enqueue the amount of elements returned by `f`.
    ///
    /// This function returns `Err(Error::Illegal)` if the transmit half of
    /// the connection is not open; see [may_send](#method.may_send).
    pub fn send<'b, F, R>(&'b mut self, f: F) -> Result<R, SendError>
    where
        F: FnOnce(&'b mut [u8]) -> (usize, R),
    {
        self.send_impl(|tx_buffer| tx_buffer.enqueue_many_with(f))
    }

    /// Enqueue a sequence of octets to be sent, and fill it from a slice.
    ///
    /// This function returns the amount of octets actually enqueued, which is limited
    /// by the amount of free space in the transmit buffer; down to zero.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, data: &[u8]) -> Result<usize, SendError> {
        self.send_impl(|tx_buffer| {
            let size = tx_buffer.enqueue_slice(data);
            (size, size)
        })
    }

    fn recv_error_check(&mut self) -> Result<(), RecvError> {
        // We may have received some data inside the initial SYN, but until the connection
        // is fully open we must not dequeue any data, as it may be overwritten by e.g.
        // another (stale) SYN. (We do not support TCP Fast Open.)
        if !self.may_recv() {
            if self.rx_fin_received {
                return Err(RecvError::Finished);
            }
            return Err(RecvError::InvalidState);
        }

        Ok(())
    }

    fn recv_impl<'b, F, R>(&'b mut self, f: F) -> Result<R, RecvError>
    where
        F: FnOnce(&'b mut SocketBuffer<'a>) -> (usize, R),
    {
        self.recv_error_check()?;

        let _old_length = self.rx_buffer.len();
        let (size, result) = f(&mut self.rx_buffer);
        self.remote_seq_no += size;
        if size > 0 {
            #[cfg(any(test, feature = "verbose"))]
            tcp_trace!(
                "rx buffer: dequeueing {} octets (now {})",
                size,
                _old_length - size
            );
        }
        Ok(result)
    }

    /// Call `f` with the largest contiguous slice of octets in the receive buffer,
    /// and dequeue the amount of elements returned by `f`.
    ///
    /// This function errors if the receive half of the connection is not open.
    ///
    /// If the receive half has been gracefully closed (with a FIN packet), `Err(Error::Finished)`
    /// is returned. In this case, the previously received data is guaranteed to be complete.
    ///
    /// In all other cases, `Err(Error::Illegal)` is returned and previously received data (if any)
    /// may be incomplete (truncated).
    pub fn recv<'b, F, R>(&'b mut self, f: F) -> Result<R, RecvError>
    where
        F: FnOnce(&'b mut [u8]) -> (usize, R),
    {
        self.recv_impl(|rx_buffer| rx_buffer.dequeue_many_with(f))
    }

    /// Dequeue a sequence of received octets, and fill a slice from it.
    ///
    /// This function returns the amount of octets actually dequeued, which is limited
    /// by the amount of occupied space in the receive buffer; down to zero.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<usize, RecvError> {
        let result = self.recv_impl(|rx_buffer| {
            let size = rx_buffer.dequeue_slice(data);
            (size, size)
        });
        #[cfg(feature = "alloc")]
        self.apply_pending_rx_growth();
        result
    }

    /// Peek at a sequence of received octets without removing them from
    /// the receive buffer, and return a pointer to it.
    ///
    /// This function otherwise behaves identically to [recv](#method.recv).
    pub fn peek(&mut self, size: usize) -> Result<&[u8], RecvError> {
        self.recv_error_check()?;

        let buffer = self.rx_buffer.get_allocated(0, size);
        if !buffer.is_empty() {
            #[cfg(any(test, feature = "verbose"))]
            tcp_trace!("rx buffer: peeking at {} octets", buffer.len());
        }
        Ok(buffer)
    }

    /// Peek at a sequence of received octets without removing them from
    /// the receive buffer, and fill a slice from it.
    ///
    /// This function otherwise behaves identically to [recv_slice](#method.recv_slice).
    pub fn peek_slice(&mut self, data: &mut [u8]) -> Result<usize, RecvError> {
        Ok(self.rx_buffer.read_allocated(0, data))
    }

    /// Return the amount of octets queued in the transmit buffer.
    ///
    /// Note that the Berkeley sockets interface does not have an equivalent of this API.
    pub fn send_queue(&self) -> usize {
        self.tx_buffer.len()
    }

    /// Return the amount of octets queued in the receive buffer. This value can be larger than
    /// the slice read by the next `recv` or `peek` call because it includes all queued octets,
    /// and not only the octets that may be returned as a contiguous slice.
    ///
    /// Note that the Berkeley sockets interface does not have an equivalent of this API.
    pub fn recv_queue(&self) -> usize {
        self.rx_buffer.len()
    }

    fn set_state(&mut self, state: State) {
        if self.state != state {
            tcp_trace!("state={}=>{}", self.state, state);
        }

        #[cfg(feature = "alloc")]
        let established_edge = state == State::Established && self.state != State::Established;
        self.state = state;
        // Both rings are empty at this instant, before any payload carried
        // by the handshake-completing segment can queue.
        #[cfg(feature = "alloc")]
        if established_edge {
            self.apply_pending_rx_growth();
            self.apply_pending_tx_growth();
        }

        #[cfg(feature = "async")]
        {
            // Wake all tasks waiting. Even if we haven't received/sent data, this
            // is needed because return values of functions may change depending on the state.
            // For example, a pending read has to fail with an error if the socket is closed.
            self.rx_waker.wake();
            self.tx_waker.wake();
        }
    }

    pub(crate) fn reply(ip_repr: &IpRepr, repr: &TcpRepr) -> (IpRepr, TcpRepr<'static>) {
        let reply_repr = TcpRepr {
            src_port: repr.dst_port,
            dst_port: repr.src_port,
            control: TcpControl::None,
            seq_number: TcpSeqNumber(0),
            ack_number: None,
            window_len: 0,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        let ip_reply_repr = IpRepr::new(
            ip_repr.dst_addr(),
            ip_repr.src_addr(),
            IpProtocol::Tcp,
            reply_repr.buffer_len(),
            64,
        );
        (ip_reply_repr, reply_repr)
    }

    pub(crate) fn rst_reply(ip_repr: &IpRepr, repr: &TcpRepr) -> (IpRepr, TcpRepr<'static>) {
        debug_assert!(repr.control != TcpControl::Rst);

        let (ip_reply_repr, mut reply_repr) = Self::reply(ip_repr, repr);

        // See https://www.snellman.net/blog/archive/2016-02-01-tcp-rst/ for explanation
        // of why we sometimes send an RST and sometimes an RST|ACK
        reply_repr.control = TcpControl::Rst;
        reply_repr.seq_number = repr.ack_number.unwrap_or_default();
        if repr.control == TcpControl::Syn && repr.ack_number.is_none() {
            reply_repr.ack_number = Some(repr.seq_number + repr.segment_len());
        }

        (ip_reply_repr, reply_repr)
    }

    fn ack_reply(&mut self, ip_repr: &IpRepr, repr: &TcpRepr) -> (IpRepr, TcpRepr<'static>) {
        let (mut ip_reply_repr, mut reply_repr) = Self::reply(ip_repr, repr);
        // TSecr echoes TS.Recent, not the incoming segment's TSval (RFC 7323
        // section 4.3): this reply path answers exactly the out-of-order and
        // out-of-window arrivals whose stamps TS.Recent refuses, and echoing
        // their newer TSval back understated the peer's RTT samples right
        // when it was retransmitting. Before any in-window segment has set
        // TS.Recent (the 0 sentinel, as in the PAWS check), the incoming
        // TSval is the only stamp there is.
        reply_repr.timestamp = repr.timestamp.and_then(|tcp_ts| {
            let tsecr = if self.last_remote_tsval != 0 {
                self.last_remote_tsval
            } else {
                tcp_ts.tsval
            };
            TcpTimestampRepr::generate_reply_with_tsval(self.tsval_generator, tsecr)
        });

        // From RFC 793:
        // [...] an empty acknowledgment segment containing the current send-sequence number
        // and an acknowledgment indicating the next sequence number expected
        // to be received.
        reply_repr.seq_number = self.remote_last_seq;
        reply_repr.ack_number = Some(self.remote_seq_no + self.rx_buffer.len());
        self.remote_last_ack = reply_repr.ack_number;

        // From RFC 1323:
        // The window field [...] of every outgoing segment, with the exception of SYN
        // segments, is right-shifted by [advertised scale value] bits[...]
        reply_repr.window_len = self.scaled_window();
        self.remote_last_win = (reply_repr.window_len as u32) << self.remote_win_shift;

        // If the remote supports selective acknowledgement, add the option to the outgoing
        // segment.
        if self.remote_has_sack {
            net_debug!("sending sACK option with current assembler ranges");

            // RFC 2018: The first SACK block (i.e., the one immediately following the kind and
            // length fields in the option) MUST specify the contiguous block of data containing
            // the segment which triggered this ACK, unless that segment advanced the
            // Acknowledgment Number field in the header.
            reply_repr.sack_ranges[0] = None;

            let ack = reply_repr.ack_number.unwrap_or(TcpSeqNumber(0));

            if let Some(last_seg_seq) = self.local_rx_last_seq {
                reply_repr.sack_ranges[0] = self
                    .assembler
                    .iter_data()
                    .map(|(left, right)| (ack + left, ack + right))
                    .find(|&(left, right)| left <= last_seg_seq && right >= last_seg_seq)
                    .map(|(left, right)| (left.0 as u32, right.0 as u32));
            }

            if reply_repr.sack_ranges[0].is_none() {
                // The matching segment was removed from the assembler, meaning the acknowledgement
                // number has advanced, or there was no previous sACK.
                //
                // While the RFC says we SHOULD keep a list of reported sACK ranges, and iterate
                // through those, that is currently infeasible. Instead, we offer the range with
                // the lowest sequence number (if one exists) to hint at what segments would
                // most quickly advance the acknowledgement number.
                reply_repr.sack_ranges[0] = self
                    .assembler
                    .iter_data()
                    .map(|(left, right)| (ack + left, ack + right))
                    .next()
                    .map(|(left, right)| (left.0 as u32, right.0 as u32));
            }
        }

        // Since the sACK option may have changed the length of the payload, update that.
        ip_reply_repr.set_payload_len(reply_repr.buffer_len());
        (ip_reply_repr, reply_repr)
    }

    fn challenge_ack_reply(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        repr: &TcpRepr,
    ) -> Option<(IpRepr, TcpRepr<'static>)> {
        if cx.now() < self.challenge_ack_timer {
            return None;
        }

        // Rate-limit to 1 per second max.
        self.challenge_ack_timer = cx.now() + Duration::from_secs(1);

        Some(self.ack_reply(ip_repr, repr))
    }

    pub(crate) fn accepts(&self, _cx: &mut Context, ip_repr: &IpRepr, repr: &TcpRepr) -> bool {
        if self.state == State::Closed {
            return false;
        }

        // If we're still listening for SYNs and the packet has an ACK or a RST,
        // it cannot be destined to this socket, but another one may well listen
        // on the same local endpoint.
        if self.state == State::Listen
            && (repr.ack_number.is_some() || repr.control == TcpControl::Rst)
        {
            return false;
        }

        if let Some(tuple) = &self.tuple {
            // Reject packets not matching the 4-tuple
            ip_repr.dst_addr() == tuple.local.addr
                && repr.dst_port == tuple.local.port
                && ip_repr.src_addr() == tuple.remote.addr
                && repr.src_port == tuple.remote.port
        } else {
            // We're listening, reject packets not matching the listen endpoint.
            let addr_ok = match self.listen_endpoint.addr {
                Some(addr) => ip_repr.dst_addr() == addr,
                None => true,
            };
            addr_ok && repr.dst_port != 0 && repr.dst_port == self.listen_endpoint.port
        }
    }

    /// Return the part of `payload` that lies inside the receive window,
    /// together with its offset past the last allocated receive octet, or
    /// `None` if the two cannot be derived from consistent bounds.
    ///
    /// `rx_window` is how many octets the receive ring can still hold: the
    /// accepted part must fit, because `write_unallocated` truncates silently
    /// and the assembler would then record octets that were never stored.
    fn receive_overlap(
        payload: &[u8],
        segment_start: TcpSeqNumber,
        window_start: TcpSeqNumber,
        window_end: TcpSeqNumber,
        rx_window: usize,
    ) -> Option<(&[u8], usize)> {
        let segment_end = segment_start + payload.len();
        let overlap_start = window_start.max(segment_start);
        let overlap_end = window_end.min(segment_end);

        let start = overlap_start.checked_sub(segment_start)?;
        let end = overlap_end.checked_sub(segment_start)?;
        let offset = overlap_start.checked_sub(window_start)?;
        if start > end || end > payload.len() {
            return None;
        }
        // The accepted octets are stored at `offset..offset + len` past the
        // ring's last allocated octet, so all of that must be free space.
        if offset.checked_add(end - start)? > rx_window {
            return None;
        }

        Some((&payload[start..end], offset))
    }

    pub(crate) fn process(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        repr: &TcpRepr,
    ) -> Option<(IpRepr, TcpRepr<'static>)> {
        debug_assert!(self.accepts(cx, ip_repr, repr));

        // Consider how much the sequence number space differs from the transmit buffer space.
        let (sent_syn, sent_fin) = match self.state {
            // In SYN-SENT or SYN-RECEIVED, we've just sent a SYN.
            State::SynSent | State::SynReceived => (true, false),
            // In FIN-WAIT-1, LAST-ACK, or CLOSING, we've just sent a FIN.
            State::FinWait1 | State::LastAck | State::Closing => (false, true),
            // In all other states we've already got acknowledgements for
            // all of the control flags we sent.
            _ => (false, false),
        };
        let control_len = (sent_syn as usize) + (sent_fin as usize);

        // RFC 9293 3.10.7.4, from RFC 5961 section 4: once the connection is
        // synchronized a SYN earns a rate-limited challenge ACK and nothing
        // else, irrespective of its sequence number -- hence ahead of both the
        // acknowledgement and the window checks below, which a rebooted peer's
        // SYN fails on both counts. That peer is who this is for: its SYN used
        // to be dropped in silence, stranding it behind our half of a
        // connection it has forgotten, and the challenge ACK draws the
        // correctly sequenced reset that frees the tuple for its next try.
        // SYN-RECEIVED is left out: there a repeated SYN asks for the SYN|ACK
        // it missed, which our own retransmit already answers.
        if repr.control == TcpControl::Syn
            && !matches!(
                self.state,
                State::Listen | State::SynSent | State::SynReceived
            )
        {
            net_debug!(
                "received a SYN at {} in state {}, sending a challenge ACK",
                repr.seq_number,
                self.state
            );
            return self.challenge_ack_reply(cx, ip_repr, repr);
        }

        // Reject unacceptable acknowledgements.
        match (self.state, repr.control, repr.ack_number) {
            // An RST received in response to initial SYN is acceptable if it acknowledges
            // the initial SYN.
            (State::SynSent, TcpControl::Rst, None) => {
                net_debug!("unacceptable RST (expecting RST|ACK) in response to initial SYN");
                return None;
            }
            (State::SynSent, TcpControl::Rst, Some(ack_number)) => {
                if ack_number != self.local_seq_no + 1 {
                    net_debug!("unacceptable RST|ACK in response to initial SYN");
                    return None;
                }
            }
            // Any other RST carries no acknowledgement worth checking; its
            // sequence number is validated against RCV.NXT further down.
            (_, TcpControl::Rst, _) => (),
            // The initial SYN cannot contain an acknowledgement.
            (State::Listen, _, None) => (),
            // This case is handled in `accepts()`.
            (State::Listen, _, Some(_)) => unreachable!(),
            // SYN|ACK in the SYN-SENT state must have the exact ACK number.
            (State::SynSent, TcpControl::Syn, Some(ack_number)) => {
                if ack_number != self.local_seq_no + 1 {
                    net_debug!("unacceptable SYN|ACK in response to initial SYN");
                    return Some(Self::rst_reply(ip_repr, repr));
                }
            }
            // TCP simultaneous open.
            // This is required by RFC 9293, which states "A TCP implementation MUST support
            // simultaneous open attempts (MUST-10)."
            (State::SynSent, TcpControl::Syn, None) => (),
            // ACKs in the SYN-SENT state are invalid.
            (State::SynSent, TcpControl::None, Some(ack_number)) => {
                // If the sequence number matches, ignore it instead of RSTing.
                // I'm not sure why, I think it may be a workaround for broken TCP
                // servers, or a defense against reordering. Either way, if Linux
                // does it, we do too.
                if ack_number == self.local_seq_no + 1 {
                    net_debug!(
                        "expecting a SYN|ACK, received an ACK with the right ack_number, ignoring."
                    );
                    return None;
                }

                net_debug!(
                    "expecting a SYN|ACK, received an ACK with the wrong ack_number, sending RST."
                );
                return Some(Self::rst_reply(ip_repr, repr));
            }
            // Anything else in the SYN-SENT state is invalid.
            (State::SynSent, _, _) => {
                net_debug!("expecting a SYN|ACK");
                return None;
            }
            // Every packet after the initial SYN must be an acknowledgement.
            (_, _, None) => {
                net_debug!("expecting an ACK");
                return None;
            }
            // ACK in the SYN-RECEIVED state must have the exact ACK number, or we RST it.
            (State::SynReceived, _, Some(ack_number)) => {
                if ack_number != self.local_seq_no + 1 {
                    net_debug!("unacceptable ACK in response to SYN|ACK");
                    return Some(Self::rst_reply(ip_repr, repr));
                }
            }
            // Every acknowledgement must be for transmitted but unacknowledged data.
            (_, _, Some(ack_number)) => {
                let unacknowledged = self.tx_buffer.len() + control_len;

                // Acceptable ACK range (both inclusive)
                let mut ack_min = self.local_seq_no;
                let ack_max = self.local_seq_no + unacknowledged;

                // If we have sent a SYN, it MUST be acknowledged.
                if sent_syn {
                    ack_min += 1;
                }

                if ack_number < ack_min {
                    net_debug!(
                        "duplicate ACK ({} not in {}...{})",
                        ack_number,
                        ack_min,
                        ack_max
                    );
                    return None;
                }

                if ack_number > ack_max {
                    net_debug!(
                        "unacceptable ACK ({} not in {}...{})",
                        ack_number,
                        ack_min,
                        ack_max
                    );
                    return self.challenge_ack_reply(cx, ip_repr, repr);
                }
            }
        }

        // The two edges come from different epochs: the left one from the
        // octets received and read so far, the right one from the window we
        // advertised when we last acknowledged. Both are consistent today, but
        // nothing below enforces it, and the acceptance test's comparisons wrap
        // -- so bound the right edge by the left one and by the octets the
        // receive ring can still hold, and the accepted payload can never
        // exceed what `write_unallocated` will store.
        let window_start = self.remote_seq_no + self.rx_buffer.len();
        let ring_end = window_start + self.rx_buffer.window();
        let window_end = match self.remote_last_ack {
            Some(last_ack) => (last_ack + self.remote_last_win as usize)
                .max(window_start)
                .min(ring_end),
            None => window_start,
        };
        let segment_start = repr.seq_number;
        let segment_end = repr.seq_number + repr.payload.len();

        // RFC 9293 3.10.7.4, from RFC 5961 section 3: in every state past
        // SYN-SENT a reset is acted on only at exactly RCV.NXT. One elsewhere
        // in the window earns a rate-limited challenge ACK, which a peer that
        // really has torn the connection down answers with a correctly
        // sequenced reset; one outside the window is dropped unanswered. An
        // off-path attacker must therefore guess the one sequence number we
        // expect rather than any of the window's worth that used to do.
        if repr.control == TcpControl::Rst
            && !matches!(self.state, State::Listen | State::SynSent)
            && segment_start != window_start
        {
            return if window_start < segment_start && segment_start < window_end {
                net_debug!(
                    "received an RST at {} rather than {}, sending a challenge ACK",
                    segment_start,
                    window_start
                );
                self.challenge_ack_reply(cx, ip_repr, repr)
            } else {
                net_debug!(
                    "received an RST at {} outside the receive window {}..{}, dropping",
                    segment_start,
                    window_start,
                    window_end
                );
                None
            };
        }

        // RFC 7323 section 5.3, check R1 -- PAWS. A segment whose timestamp
        // predates the newest one we have accepted is an old duplicate that
        // wrapped the sequence space, however plausible its sequence number
        // looks. At this link's rates that is not hypothetical: 4 GiB of
        // sequence space goes by in a few seconds, and the acceptance test
        // above has nothing else to tell the wrapped copy from the real thing.
        //
        // It earns an acknowledgement, per RFC 793 page 69, so a peer that has
        // genuinely fallen out of step can resynchronize -- rate-limited,
        // because otherwise a spoofed segment with a stale timestamp would be
        // an amplification vector, and a healthy connection never comes here.
        //
        // The exclusions are the RFC's. LISTEN and SYN-SENT have no TS.Recent
        // to compare against; a reset is never subject to the check, since
        // refusing one would keep a connection the peer has already torn down;
        // and a TS.Recent of zero means "not seen yet" (see
        // `last_remote_tsval`), not "the beginning of time".
        if self.timestamp_enabled()
            && self.last_remote_tsval != 0
            && repr.control != TcpControl::Rst
            && !matches!(self.state, State::Listen | State::SynSent)
            && let Some(timestamp) = repr.timestamp
            // Modular, not numeric: the timestamp clock wraps every 49 days,
            // and "before" has to keep meaning "before" across that.
            && (timestamp.tsval.wrapping_sub(self.last_remote_tsval) as i32) < 0
        {
            net_debug!(
                "PAWS: timestamp {} predates {}, dropping as an old duplicate",
                timestamp.tsval,
                self.last_remote_tsval
            );
            return self.challenge_ack_reply(cx, ip_repr, repr);
        }

        let (payload, payload_offset) = match self.state {
            // In LISTEN and SYN-SENT states, we have not yet synchronized with the remote end.
            State::Listen | State::SynSent => (&[][..], 0),
            _ => {
                // https://www.rfc-editor.org/rfc/rfc9293.html#name-segment-acceptability-tests
                let segment_in_window = match (
                    segment_start == segment_end,
                    window_start == window_end,
                ) {
                    (true, _) if segment_end == window_start - 1 => {
                        net_debug!(
                            "received a keep-alive or window probe packet, will send an ACK"
                        );
                        false
                    }
                    (true, true) => {
                        if window_start == segment_start {
                            true
                        } else {
                            net_debug!(
                                "zero-length segment not inside zero-length window, will send an ACK."
                            );
                            false
                        }
                    }
                    (true, false) => {
                        if window_start <= segment_start && segment_start < window_end {
                            true
                        } else {
                            net_debug!("zero-length segment not inside window, will send an ACK.");
                            false
                        }
                    }
                    (false, true) => {
                        net_debug!(
                            "non-zero-length segment with zero receive window, will only send an ACK"
                        );
                        false
                    }
                    (false, false) => {
                        if (window_start <= segment_start && segment_start < window_end)
                            || (window_start < segment_end && segment_end <= window_end)
                        {
                            true
                        } else {
                            net_debug!(
                                "segment not in receive window ({}..{} not intersecting {}..{}), will send challenge ACK",
                                segment_start,
                                segment_end,
                                window_start,
                                window_end
                            );
                            false
                        }
                    }
                };

                if segment_in_window {
                    // The checks above are meant to imply an ordered overlap,
                    // but they compare wrapping sequence numbers, so derive the
                    // bounds with checked arithmetic and drop the segment
                    // rather than panic if they crossed after all.
                    let Some((payload, payload_offset)) = Self::receive_overlap(
                        repr.payload,
                        segment_start,
                        window_start,
                        window_end,
                        self.rx_buffer.window(),
                    ) else {
                        net_debug!(
                            "segment {}..{} inconsistent with receive window {}..{}, dropping",
                            segment_start,
                            segment_end,
                            window_start,
                            window_end
                        );
                        return None;
                    };

                    self.local_rx_last_seq = Some(repr.seq_number);

                    (payload, payload_offset)
                } else {
                    // If we're in the TIME-WAIT state, restart the TIME-WAIT timeout, since
                    // the remote end may not have realized we've closed the connection.
                    if self.state == State::TimeWait {
                        self.timer.set_for_close(cx.now());
                    }

                    return self.challenge_ack_reply(cx, ip_repr, repr);
                }
            }
        };

        // Compute the amount of acknowledged octets, removing the SYN and FIN bits
        // from the sequence space.
        let mut ack_len = 0;
        let mut ack_of_fin = false;
        let mut ack_all = false;
        if repr.control != TcpControl::Rst
            && let Some(ack_number) = repr.ack_number
        {
            // Sequence number corresponding to the first byte in `tx_buffer`.
            // This normally equals `local_seq_no`, but is 1 higher if we have sent a SYN,
            // as the SYN occupies 1 sequence number "before" the data.
            let tx_buffer_start_seq = self.local_seq_no + (sent_syn as usize);

            if let Some(acked) = ack_number.checked_sub(tx_buffer_start_seq) {
                ack_len = acked;

                // We could've sent data before the FIN, so only remove FIN from the sequence
                // space if all of that data is acknowledged.
                if sent_fin && self.tx_buffer.len() + 1 == ack_len {
                    ack_len -= 1;
                    tcp_trace!("received ACK of FIN");
                    ack_of_fin = true;
                }

                // The acceptable-ACK test above bounds this by the octets we
                // have unacknowledged, but it compares wrapping sequence
                // numbers: never dequeue more than the buffer holds.
                if ack_len > self.tx_buffer.len() {
                    net_debug!(
                        "ACK of {} octets exceeds the {} unacknowledged, clamping",
                        ack_len,
                        self.tx_buffer.len()
                    );
                    ack_len = self.tx_buffer.len();
                }

                ack_all = self.remote_last_seq <= ack_number;
            }

            self.rtte.on_ack(cx.now(), ack_number);
            self.congestion_controller
                .inner_mut()
                .on_ack(cx.now(), ack_len, &self.rtte);
        }

        // Disregard control flags we don't care about or shouldn't act on yet.
        let mut control = repr.control;
        control = control.quash_psh();

        // If a FIN is received at the end of the current segment, but
        // we have a hole in the assembler before the current segment, disregard this FIN.
        if control == TcpControl::Fin && window_start < segment_start {
            tcp_trace!(
                "ignoring FIN because we don't have full data yet. window_start={} segment_start={}",
                window_start,
                segment_start
            );
            control = TcpControl::None;
        }

        // Validate and update the state.
        match (self.state, control) {
            // RSTs are not accepted in the LISTEN state.
            (State::Listen, TcpControl::Rst) => return None,

            // RSTs in SYN-RECEIVED flip the socket back to the LISTEN state.
            // Here we need to additionally check `listen_endpoint`, because we want to make sure
            // that SYN-RECEIVED was actually converted from the LISTEN state (another possible
            // reason is TCP simultaneous open).
            (State::SynReceived, TcpControl::Rst) if self.listen_endpoint.port != 0 => {
                tcp_trace!("received RST");
                self.tuple = None;
                self.set_state(State::Listen);
                return None;
            }

            // RSTs in any other state close the socket.
            (_, TcpControl::Rst) => {
                tcp_trace!("received RST");
                self.set_state(State::Closed);
                self.tuple = None;
                return None;
            }

            // SYN packets in the LISTEN state change it to SYN-RECEIVED.
            (State::Listen, TcpControl::Syn) => {
                tcp_trace!("received SYN");
                if let Some(max_seg_size) = repr.max_seg_size {
                    if max_seg_size == 0 {
                        tcp_trace!("received SYNACK with zero MSS, ignoring");
                        return None;
                    }
                    self.congestion_controller
                        .inner_mut()
                        .set_mss(max_seg_size as usize);
                    self.remote_mss = max_seg_size as usize
                }

                let local = IpEndpoint::new(ip_repr.dst_addr(), repr.dst_port);
                let remote = IpEndpoint::new(ip_repr.src_addr(), repr.src_port);
                self.tuple = Some(Tuple { local, remote });
                self.local_seq_no = Self::initial_seq_no(cx, local, remote);
                self.remote_seq_no = repr.seq_number + 1;
                self.remote_last_seq = self.local_seq_no;
                self.remote_has_sack = repr.sack_permitted;
                self.remote_win_scale = repr.window_scale;
                // Remote doesn't support window scaling, don't do it.
                if self.remote_win_scale.is_none() {
                    self.remote_win_shift = 0;
                }
                // Remote doesn't support timestamping, don't do it.
                if repr.timestamp.is_none() {
                    self.tsval_generator = None;
                }
                self.set_state(State::SynReceived);
                self.timer.set_for_idle(cx.now(), self.keep_alive);
            }

            // ACK packets in the SYN-RECEIVED state change it to ESTABLISHED.
            (State::SynReceived, TcpControl::None) => {
                self.set_state(State::Established);
            }

            // FIN packets in the SYN-RECEIVED state change it to CLOSE-WAIT.
            // It's not obvious from RFC 793 that this is permitted, but
            // 7th and 8th steps in the "SEGMENT ARRIVES" event describe this behavior.
            (State::SynReceived, TcpControl::Fin) => {
                self.remote_seq_no += 1;
                self.rx_fin_received = true;
                self.set_state(State::CloseWait);
            }

            // SYN|ACK packets in the SYN-SENT state change it to ESTABLISHED.
            // SYN packets in the SYN-SENT state change it to SYN-RECEIVED.
            (State::SynSent, TcpControl::Syn) => {
                if repr.ack_number.is_some() {
                    tcp_trace!("received SYN|ACK");
                } else {
                    tcp_trace!("received SYN");
                }
                if let Some(max_seg_size) = repr.max_seg_size {
                    if max_seg_size == 0 {
                        tcp_trace!("received SYNACK with zero MSS, ignoring");
                        return None;
                    }
                    self.remote_mss = max_seg_size as usize;
                    self.congestion_controller
                        .inner_mut()
                        .set_mss(self.remote_mss);
                }

                self.remote_seq_no = repr.seq_number + 1;
                self.remote_last_seq = self.local_seq_no + 1;
                self.remote_last_ack = Some(repr.seq_number);
                self.remote_has_sack = repr.sack_permitted;
                self.remote_win_scale = repr.window_scale;
                // Remote doesn't support window scaling, don't do it.
                if self.remote_win_scale.is_none() {
                    self.remote_win_shift = 0;
                }
                // Remote doesn't support timestamping, don't do it.
                if repr.timestamp.is_none() {
                    self.tsval_generator = None;
                }

                if repr.ack_number.is_some() {
                    self.set_state(State::Established);
                } else {
                    self.set_state(State::SynReceived);
                }
            }

            (State::Established, TcpControl::None) => {}

            // FIN packets in ESTABLISHED state indicate the remote side has closed.
            (State::Established, TcpControl::Fin) => {
                self.remote_seq_no += 1;
                self.rx_fin_received = true;
                self.set_state(State::CloseWait);
            }

            // ACK packets in FIN-WAIT-1 state change it to FIN-WAIT-2, if we've already
            // sent everything in the transmit buffer. If not, they reset the retransmit timer.
            (State::FinWait1, TcpControl::None) => {
                if ack_of_fin {
                    self.set_state(State::FinWait2);
                }
            }

            // FIN packets in FIN-WAIT-1 state change it to CLOSING, or to TIME-WAIT
            // if they also acknowledge our FIN.
            (State::FinWait1, TcpControl::Fin) => {
                self.remote_seq_no += 1;
                self.rx_fin_received = true;
                if ack_of_fin {
                    self.set_state(State::TimeWait);
                    self.timer.set_for_close(cx.now());
                } else {
                    self.set_state(State::Closing);
                }
            }

            (State::FinWait2, TcpControl::None) => {}

            // FIN packets in FIN-WAIT-2 state change it to TIME-WAIT.
            (State::FinWait2, TcpControl::Fin) => {
                self.remote_seq_no += 1;
                self.rx_fin_received = true;
                self.set_state(State::TimeWait);
                self.timer.set_for_close(cx.now());
            }

            // ACK packets in CLOSING state change it to TIME-WAIT.
            (State::Closing, TcpControl::None) => {
                if ack_of_fin {
                    self.set_state(State::TimeWait);
                    self.timer.set_for_close(cx.now());
                }
            }

            (State::CloseWait, TcpControl::None) => {}

            // ACK packets in LAST-ACK state change it to CLOSED.
            (State::LastAck, TcpControl::None) => {
                if ack_of_fin {
                    // Clear the remote endpoint, or we'll send an RST there.
                    self.set_state(State::Closed);
                    self.tuple = None;
                } else if ack_len == 0 {
                    // Duplicate ACK; our FIN has not been acknowledged.
                    // Per RFC 9293 (3.10.7.4), send a challenge ACK.
                    return self.challenge_ack_reply(cx, ip_repr, repr);
                }
                // Partial ACK: fall through to advance SND.UNA normally.
            }

            _ => {
                net_debug!("unexpected packet {}", repr);
                return None;
            }
        }

        // Update remote state.
        self.remote_last_ts = Some(cx.now());

        // RFC 1323: The window field (SEG.WND) in the header of every incoming segment, with the
        // exception of SYN segments, is left-shifted by Snd.Wind.Scale bits before updating SND.WND.
        let scale = match repr.control {
            TcpControl::Syn => 0,
            _ => self.remote_win_scale.unwrap_or(0),
        };
        let new_remote_win_len = (repr.window_len as usize) << (scale as usize);
        let is_window_update = new_remote_win_len != self.remote_win_len;
        self.remote_win_len = new_remote_win_len;

        self.congestion_controller
            .inner_mut()
            .set_remote_window(new_remote_win_len);

        if ack_len > 0 {
            // Dequeue acknowledged octets.
            debug_assert!(self.tx_buffer.len() >= ack_len);
            tcp_trace!(
                "tx buffer: dequeueing {} octets (now {})",
                ack_len,
                self.tx_buffer.len() - ack_len
            );
            self.tx_buffer.dequeue_allocated(ack_len);

            #[cfg(feature = "alloc")]
            self.apply_pending_tx_growth();

            // There's new room available in tx_buffer, wake the waiting task if any.
            #[cfg(feature = "async")]
            self.tx_waker.wake();
        }

        if let Some(ack_number) = repr.ack_number {
            // TODO: When flow control is implemented,
            // refractor the following block within that implementation

            // Detect and react to duplicate ACKs by:
            // 1. Check if duplicate ACK and change self.local_rx_dup_acks accordingly
            // 2. If exactly 3 duplicate ACKs received, set for fast retransmit
            // 3. Update the last received ACK (self.local_rx_last_ack)
            match self.local_rx_last_ack {
                // Duplicate ACK if payload empty and ACK doesn't move send window ->
                // Increment duplicate ACK count and set for retransmit if we just received
                // the third duplicate ACK
                Some(last_rx_ack)
                    if repr.payload.is_empty()
                        && last_rx_ack == ack_number
                        && ack_number < self.remote_last_seq
                        && !is_window_update =>
                {
                    // Increment duplicate ACK count
                    self.local_rx_dup_acks = self.local_rx_dup_acks.saturating_add(1);

                    net_debug!(
                        "received duplicate ACK for seq {} (duplicate nr {}{})",
                        ack_number,
                        self.local_rx_dup_acks,
                        if self.local_rx_dup_acks == u8::MAX {
                            "+"
                        } else {
                            ""
                        }
                    );

                    if self.local_rx_dup_acks == 3 {
                        self.timer.set_for_fast_retransmit();
                        net_debug!("started fast retransmit");

                        // RFC 5681 section 3.2: the first and second duplicate
                        // ACKs say nothing about congestion -- they are as
                        // likely to be reordering -- and the window is reduced
                        // once per loss event, on the third, by the same signal
                        // that arms the fast retransmit above. Telling the
                        // controller on every duplicate turned one loss into as
                        // many congestion events as the peer had segments left
                        // to acknowledge; for Cubic, whose reduction is
                        // multiplicative, that is `beta` raised to the size of
                        // the flight.
                        //
                        // The exactly-equal test is what keeps this to one
                        // signal: the counter saturates upward and is reset by
                        // any ACK that advances the window, so it passes
                        // through 3 once per loss event.
                        self.congestion_controller
                            .inner_mut()
                            .on_duplicate_ack(cx.now());
                    }
                }
                // No duplicate ACK -> Reset state and update last received ACK
                _ => {
                    if self.local_rx_dup_acks > 0 {
                        self.local_rx_dup_acks = 0;
                        net_debug!("reset duplicate ACK count");
                    }
                    self.local_rx_last_ack = Some(ack_number);
                }
            };
            // We've processed everything in the incoming segment, so advance the local
            // sequence number past it.
            self.local_seq_no = ack_number;
            // During retransmission, if an earlier segment got lost but later was
            // successfully received, self.local_seq_no can move past self.remote_last_seq.
            // Do not attempt to retransmit the latter segments; not only this is pointless
            // in theory but also impossible in practice, since they have been already
            // deallocated from the buffer.
            if self.remote_last_seq < self.local_seq_no {
                self.remote_last_seq = self.local_seq_no
            }
        }

        // RFC 7323 section 5.3, check R3: TS.Recent advances only for a segment
        // that starts at or before the next byte we expect. Taking the
        // timestamp off *any* accepted segment -- which is what this used to do
        // -- lets one that arrived early, while a hole ahead of it is still
        // open, push TS.Recent past the timestamp of the retransmission that
        // will fill that hole. R1 above would then reject the repair, and the
        // connection would stall on exactly the loss it was recovering from.
        //
        // The RFC writes the condition as `SEG.SEQ <= Last.ACK.sent <
        // SEG.SEQ + SEG.LEN`, which excludes segments carrying no data at all;
        // this is Linux's reading of it (`tcp_replace_ts_recent`), and keeps a
        // stream of pure ACKs from freezing TS.Recent while the clock runs on.
        if let Some(timestamp) = repr.timestamp
            && segment_start <= window_start
        {
            self.last_remote_tsval = timestamp.tsval;
        }

        // update timers.
        match self.timer {
            Timer::Retransmit { .. } | Timer::FastRetransmit => {
                if ack_all {
                    // RFC 6298: (5.2) ACK of all outstanding data turn off the retransmit timer.
                    self.timer.set_for_idle(cx.now(), self.keep_alive);
                } else if ack_len > 0 {
                    // (5.3) ACK of new data in ESTABLISHED state restart the retransmit timer.
                    let rto = self.rtte.retransmission_timeout();
                    self.timer.set_for_retransmit(cx.now(), rto);
                }
            }
            Timer::Idle { .. } => {
                // any packet on idle refresh the keepalive timer.
                self.timer.set_for_idle(cx.now(), self.keep_alive);
            }
            _ => {}
        }

        // start/stop the Zero Window Probe timer.
        if self.remote_win_len == 0
            && !self.tx_buffer.is_empty()
            && (self.timer.is_idle() || ack_len > 0)
        {
            let delay = self.rtte.retransmission_timeout();
            tcp_trace!("starting zero-window-probe timer for t+{}", delay);
            self.timer.set_for_zero_window_probe(cx.now(), delay);
        }
        if self.remote_win_len != 0 && self.timer.is_zero_window_probe() {
            tcp_trace!("stopping zero-window-probe timer");
            self.timer.set_for_idle(cx.now(), self.keep_alive);
        }

        let payload_len = payload.len();
        if payload_len == 0 {
            return None;
        }

        // The acceptance test above already bounds the payload by the ring's
        // free space; check again before the assembler records the octets.
        // Two invariants rest on this single bound. A short write must never
        // make us acknowledge data we did not store, and the assembler has no
        // notion of the ring's capacity: a hole recorded past it can never be
        // filled, so `is_empty()` would stay false and a phantom SACK block
        // would be advertised for the rest of the connection. Assert it in
        // debug builds -- the acceptance arithmetic is what upholds it, and a
        // later change there is caught here rather than silently dropping
        // every segment.
        let rx_window = self.rx_buffer.window();
        debug_assert!(
            payload_offset + payload_len <= rx_window,
            "receive window admitted {payload_len} octets at offset {payload_offset}, \
             but the receive ring can hold only {rx_window} more"
        );
        if payload_offset + payload_len > rx_window {
            net_debug!(
                "rx buffer: no room for {} octets at offset {}, dropping",
                payload_len,
                payload_offset
            );
            return None;
        }

        let assembler_was_empty = self.assembler.is_empty();

        // Try adding payload octets to the assembler.
        let Ok(contig_len) = self
            .assembler
            .add_then_remove_front(payload_offset, payload_len)
        else {
            net_debug!(
                "assembler: too many holes to add {} octets at offset {}",
                payload_len,
                payload_offset
            );
            return None;
        };

        // Place payload octets into the buffer.
        tcp_trace!(
            "rx buffer: receiving {} octets at offset {}",
            payload_len,
            payload_offset
        );
        let len_written = self.rx_buffer.write_unallocated(payload_offset, payload);
        debug_assert!(len_written == payload_len);

        if contig_len != 0 {
            // Enqueue the contiguous data octets in front of the buffer.
            tcp_trace!(
                "rx buffer: enqueueing {} octets (now {})",
                contig_len,
                self.rx_buffer.len() + contig_len
            );
            self.rx_buffer.enqueue_unallocated(contig_len);

            // There's new data in rx_buffer, notify waiting task if any.
            #[cfg(feature = "async")]
            self.rx_waker.wake();
        }

        if !self.assembler.is_empty() {
            // Print the ranges recorded in the assembler.
            tcp_trace!("assembler: {}", self.assembler);
        }

        // Handle delayed acks
        if let Some(ack_delay) = self.ack_delay
            && self.ack_to_transmit()
        {
            self.ack_delay_timer = match self.ack_delay_timer {
                AckDelayTimer::Idle => {
                    tcp_trace!("starting delayed ack timer");
                    AckDelayTimer::Waiting(cx.now() + ack_delay)
                }
                AckDelayTimer::Waiting(_) if self.immediate_ack_to_transmit() => {
                    tcp_trace!("delayed ack timer already started, forcing expiry");
                    AckDelayTimer::Immediate
                }
                timer @ AckDelayTimer::Waiting(_) => {
                    tcp_trace!("waiting until delayed ack timer expires");
                    timer
                }
                AckDelayTimer::Immediate => {
                    tcp_trace!("delayed ack timer already force-expired");
                    AckDelayTimer::Immediate
                }
            };
        }

        // Per RFC 5681, we should send an immediate ACK when either:
        //  1) an out-of-order segment is received, or
        //  2) a segment arrives that fills in all or part of a gap in sequence space.
        if !self.assembler.is_empty() || !assembler_was_empty {
            // Note that we change the transmitter state here.
            // This is fine because moto-netstack assumes that it can always transmit zero or one
            // packets for every packet it receives.
            tcp_trace!("ACKing incoming segment");
            Some(self.ack_reply(ip_repr, repr))
        } else {
            None
        }
    }

    fn timed_out(&self, timestamp: Instant) -> bool {
        match (self.remote_last_ts, self.timeout) {
            (Some(remote_last_ts), Some(timeout)) => timestamp >= remote_last_ts + timeout,
            (_, _) => false,
        }
    }

    /// How many more octets the congestion window permits us to put on the wire.
    ///
    /// RFC 5681 section 4: `cwnd` bounds the data *outstanding* -- SND.NXT minus
    /// SND.UNA. It used to bound neither call site correctly: `seq_to_transmit`
    /// compared it against the data still *unsent*, and the segment sizer in
    /// `dispatch` did not consult it at all, so what actually left the socket
    /// was bounded by the remote window alone. Every congestion signal was
    /// being delivered and acted on; none of it reached the wire.
    fn congestion_window_headroom(&self) -> usize {
        let cwnd = self.congestion_controller.inner().window();

        // Sequence-number subtraction panics on underflow, and sys-io aborts on
        // panic. The ACK path restores this ordering right after it advances
        // SND.UNA, but do not make that an invariant this has to rely on.
        if self.remote_last_seq >= self.local_seq_no {
            cwnd.saturating_sub(self.remote_last_seq - self.local_seq_no)
        } else {
            cwnd
        }
    }

    fn seq_to_transmit(&self, cx: &mut Context) -> bool {
        let ip_header_len = match self.tuple.unwrap().local.addr {
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(_) => crate::wire::IPV4_HEADER_LEN,
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(_) => crate::wire::IPV6_HEADER_LEN,
        };

        // Max segment size we're able to send due to MTU limitations.
        let local_mss = cx.ip_mtu() - ip_header_len - TCP_HEADER_LEN;

        // The effective max segment size, taking into account our and remote's limits.
        let effective_mss = local_mss.min(self.remote_mss);

        // Have we sent data that hasn't been ACKed yet?
        let data_in_flight = self.remote_last_seq != self.local_seq_no;

        // If we want to send a SYN and we haven't done so, do it!
        if matches!(self.state, State::SynSent | State::SynReceived) && !data_in_flight {
            return true;
        }

        // max sequence number we can send.
        let max_send_seq =
            self.local_seq_no + core::cmp::min(self.remote_win_len, self.tx_buffer.len());

        // Max amount of octets we can send.
        let max_send = if max_send_seq >= self.remote_last_seq {
            max_send_seq - self.remote_last_seq
        } else {
            0
        };

        // Compare max_send with what is left of the congestion window.
        let max_send = max_send.min(self.congestion_window_headroom());

        // Can we send at least 1 octet?
        let mut can_send = max_send != 0;
        // Can we send at least 1 full segment?
        let can_send_full = max_send >= effective_mss;

        // Do we have to send a FIN?
        let want_fin = match self.state {
            State::FinWait1 => true,
            State::Closing => true,
            State::LastAck => true,
            _ => false,
        };

        // If we're applying the Nagle algorithm we don't want to send more
        // until one of:
        // * There's no data in flight
        // * We can send a full packet
        // * We have all the data we'll ever send (we're closing send)
        if self.nagle && data_in_flight && !can_send_full && !want_fin {
            can_send = false;
        }

        // Can we actually send the FIN? We can send it if:
        // 1. We have unsent data that fits in the remote window.
        // 2. We have no unsent data.
        // This condition matches only if #2, because #1 is already covered by can_data and we're ORing them.
        let can_fin = want_fin && self.remote_last_seq == self.local_seq_no + self.tx_buffer.len();

        can_send || can_fin
    }

    fn delayed_ack_expired(&self, timestamp: Instant) -> bool {
        match self.ack_delay_timer {
            AckDelayTimer::Idle => true,
            AckDelayTimer::Waiting(t) => t <= timestamp,
            AckDelayTimer::Immediate => true,
        }
    }

    fn ack_to_transmit(&self) -> bool {
        if let Some(remote_last_ack) = self.remote_last_ack {
            remote_last_ack < self.remote_seq_no + self.rx_buffer.len()
        } else {
            false
        }
    }

    /// Return whether to send ACK immediately due to the amount of unacknowledged data.
    ///
    /// RFC 9293 states "An ACK SHOULD be generated for at least every second full-sized segment or
    /// 2*RMSS bytes of new data (where RMSS is the MSS specified by the TCP endpoint receiving the
    /// segments to be acknowledged, or the default value if not specified) (SHLD-19)."
    ///
    /// Note that the RFC above only says "at least 2*RMSS bytes", which is not a hard requirement.
    /// In practice, we follow the Linux kernel's empirical value of sending an ACK for every RMSS
    /// byte of new data. For details, see
    /// <https://elixir.bootlin.com/linux/v6.11.4/source/net/ipv4/tcp_input.c#L5747>.
    fn immediate_ack_to_transmit(&self) -> bool {
        if let Some(remote_last_ack) = self.remote_last_ack {
            remote_last_ack + self.remote_mss < self.remote_seq_no + self.rx_buffer.len()
        } else {
            false
        }
    }

    /// Return whether we should send ACK immediately due to significant window updates.
    ///
    /// ACKs with significant window updates should be sent immediately to let the sender know that
    /// more data can be sent. According to the Linux kernel implementation, "significant" means
    /// doubling the receive window. The Linux kernel implementation can be found at
    /// <https://elixir.bootlin.com/linux/v6.9.9/source/net/ipv4/tcp.c#L1472>.
    fn window_to_update(&self) -> bool {
        match self.state {
            // Not before the handshake completes: `remote_last_win` records
            // the unscaled SYN|ACK advertisement, which understates a scaled
            // socket's window, but correcting it from SYN-RECEIVED would add
            // a second reply to every SYN. The update goes out on reaching
            // ESTABLISHED. (SYN-SENT could never fire: `remote_last_ack` is
            // None until the SYN|ACK arrives, which leaves SYN-SENT.)
            State::Established | State::FinWait1 | State::FinWait2 => {
                let new_win = self.scaled_window();
                if let Some(last_win) = self.last_scaled_window() {
                    new_win > 0 && new_win / 2 >= last_win
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    pub(crate) fn dispatch<F, E>(&mut self, cx: &mut Context, emit: F) -> Result<(), E>
    where
        F: FnOnce(&mut Context, PacketMeta, (IpRepr, TcpRepr)) -> Result<(), E>,
    {
        if self.tuple.is_none() {
            return Ok(());
        }

        // NOTE(unwrap): we check tuple is not None above.
        let tuple = self.tuple.unwrap();

        // Check if the interface still has our source IP address.
        // If not (e.g. the interface's IP changed), reset the socket.
        // We use reset() instead of set_state(Closed) to avoid sending
        // an RST packet with the now-invalid source IP.
        if !cx.has_ip_addr(tuple.local.addr) {
            net_debug!("source IP address no longer available, closing socket");
            self.reset();
            return Ok(());
        }

        // A growth latched behind a borrowing `recv` applies here, before
        // this pass computes the window it will advertise.
        #[cfg(feature = "alloc")]
        {
            self.apply_pending_rx_growth();
            self.apply_pending_tx_growth();
        }

        if self.remote_last_ts.is_none() {
            // We get here in exactly two cases:
            //  1) This socket just transitioned into SYN-SENT.
            //  2) This socket had an empty transmit buffer and some data was added there.
            // Both are similar in that the socket has been quiet for an indefinite
            // period of time, it isn't anymore, and the local endpoint is talking.
            // So, we start counting the timeout not from the last received packet
            // but from the first transmitted one.
            self.remote_last_ts = Some(cx.now());
        }

        self.congestion_controller
            .inner_mut()
            .pre_transmit(cx.now());

        // Check if any state needs to be changed because of a timer.
        if self.timed_out(cx.now()) {
            // If a timeout expires, we should abort the connection.
            net_debug!("timeout exceeded");
            self.set_state(State::Closed);
        } else if !self.seq_to_transmit(cx) && self.timer.should_retransmit(cx.now()) {
            // If a retransmit timer expired, we should resend data starting at the last ACK.
            net_debug!("retransmitting");

            // A fast retransmit is the same loss event the third duplicate
            // ACK already reported to the controller; reporting it again
            // here applied a multiplicative reduction twice (beta squared,
            // 0.49) per lost segment. Only an expired RTO is news.
            let rto_expired = !matches!(self.timer, Timer::FastRetransmit);

            // Rewind "last sequence number sent", as if we never
            // had sent them. This will cause all data in the queue
            // to be sent again.
            self.remote_last_seq = self.local_seq_no;

            // Clear the `should_retransmit` state. If we can't retransmit right
            // now for whatever reason (like zero window), this avoids an
            // infinite polling loop where `poll_at` returns `Now` but `dispatch`
            // can't actually do anything.
            self.timer.set_for_idle(cx.now(), self.keep_alive);

            // Inform RTTE, so that it can avoid bogus measurements.
            self.rtte.on_retransmit();

            if rto_expired {
                self.congestion_controller
                    .inner_mut()
                    .on_retransmit(cx.now());
            }
        }

        #[cfg(feature = "socket-tcp-pause-synack")]
        if matches!(self.state, State::SynReceived) && self.synack_paused {
            return Ok(());
        }

        // Decide whether we're sending a packet.
        if self.seq_to_transmit(cx) {
            // If we have data to transmit and it fits into partner's window, do it.
            tcp_trace!("outgoing segment will send data or flags");
        } else if self.ack_to_transmit() && self.delayed_ack_expired(cx.now()) {
            // If we have data to acknowledge, do it.
            tcp_trace!("outgoing segment will acknowledge");
        } else if self.window_to_update() {
            // If we have window length increase to advertise, do it.
            tcp_trace!("outgoing segment will update window");
        } else if self.state == State::Closed {
            // If we need to abort the connection, do it.
            tcp_trace!("outgoing segment will abort connection");
        } else if self.timer.should_keep_alive(cx.now()) {
            // If we need to transmit a keep-alive packet, do it.
            tcp_trace!("keep-alive timer expired");
        } else if self.timer.should_zero_window_probe(cx.now()) {
            tcp_trace!("sending zero-window probe");
        } else if self.timer.should_close(cx.now()) {
            // If we have spent enough time in the TIME-WAIT state, close the socket.
            tcp_trace!("TIME-WAIT timer expired");
            self.reset();
            return Ok(());
        } else {
            return Ok(());
        }

        // Construct the lowered IP representation.
        // We might need this to calculate the MSS, so do it early.
        let mut ip_repr = IpRepr::new(
            tuple.local.addr,
            tuple.remote.addr,
            IpProtocol::Tcp,
            0,
            self.hop_limit.unwrap_or(64),
        );

        // Construct the basic TCP representation, an empty ACK packet.
        // We'll adjust this to be more specific as needed.
        let mut repr = TcpRepr {
            src_port: tuple.local.port,
            dst_port: tuple.remote.port,
            control: TcpControl::None,
            seq_number: self.remote_last_seq,
            ack_number: Some(self.remote_seq_no + self.rx_buffer.len()),
            window_len: self.scaled_window(),
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: TcpTimestampRepr::generate_reply_with_tsval(
                self.tsval_generator,
                self.last_remote_tsval,
            ),
            payload: &[],
        };

        let mut is_zero_window_probe = false;

        match self.state {
            // We transmit an RST in the CLOSED state. If we ended up in the CLOSED state
            // with a specified endpoint, it means that the socket was aborted.
            State::Closed => {
                repr.control = TcpControl::Rst;
            }

            // We never transmit anything in the LISTEN state.
            State::Listen => return Ok(()),

            // We transmit a SYN in the SYN-SENT state.
            // We transmit a SYN|ACK in the SYN-RECEIVED state.
            State::SynSent | State::SynReceived => {
                repr.control = TcpControl::Syn;
                repr.seq_number = self.local_seq_no;
                // window len must NOT be scaled in SYNs.
                repr.window_len = u16::try_from(self.rx_buffer.window()).unwrap_or(u16::MAX);
                if self.state == State::SynSent {
                    repr.ack_number = None;
                    repr.window_scale = Some(self.remote_win_shift);
                    repr.sack_permitted = true;
                } else {
                    repr.sack_permitted = self.remote_has_sack;
                    repr.window_scale = self.remote_win_scale.map(|_| self.remote_win_shift);
                }
            }

            // We transmit data in all states where we may have data in the buffer,
            // or the transmit half of the connection is still open.
            State::Established
            | State::FinWait1
            | State::Closing
            | State::CloseWait
            | State::LastAck => {
                // Extract as much data as the remote side can receive in this packet
                // from the transmit buffer.

                // Right edge of window, ie the max sequence number we're allowed to send.
                let win_right_edge = self.local_seq_no + self.remote_win_len;

                // Max amount of octets we're allowed to send according to the remote window.
                let mut win_limit = if win_right_edge >= self.remote_last_seq {
                    win_right_edge - self.remote_last_seq
                } else {
                    // This can happen if we've sent some data and later the remote side
                    // has shrunk its window so that data is no longer inside the window.
                    // This should be very rare and is strongly discouraged by the RFCs,
                    // but it does happen in practice.
                    // http://www.tcpipguide.com/free/t_TCPWindowManagementIssues.htm
                    0
                };

                // ... and no more than the congestion window still allows. This
                // has to happen before the zero-window probe below, which is
                // exempt: a probe is what reopens a connection whose peer
                // advertised a zero window, and it must go out even when the
                // congestion window has nothing left.
                win_limit = win_limit.min(self.congestion_window_headroom());

                // To send a zero-window-probe, force the window limit to at least 1 byte.
                if win_limit == 0 && self.timer.should_zero_window_probe(cx.now()) {
                    win_limit = 1;
                    is_zero_window_probe = true;
                }

                // Maximum size we're allowed to send. This can be limited by 3 factors:
                // 1. remote window
                // 2. MSS the remote is willing to accept, probably determined by their MTU
                // 3. MSS we can send, determined by our MTU.
                //
                // Factor 3 has to subtract the header this segment will really
                // carry, not the 20-byte minimum: our options travel inside the
                // packet the MTU bounds, and with RFC 7323 timestamps on there
                // are 12 bytes of them on every single segment. Factor 2 does
                // not -- an MSS bounds payload alone (RFC 6691), so the peer's
                // number is already the right bound on ours.
                let tcp_header_len = repr.header_len();
                let effective_mss = self
                    .remote_mss
                    .min(cx.ip_mtu() - ip_repr.header_len() - tcp_header_len);

                // With TCP segmentation offload, a single emitted packet may
                // carry many effective-MSS units of payload — the device
                // splits it into wire segments (PacketMeta::tso_seg_size
                // tells it the per-segment payload size). The remote window
                // still bounds the total, and the IPv4 total-length field
                // bounds a single packet to u16::MAX.
                let max_seg = match cx.max_tso_size() {
                    0 => effective_mss,
                    tso_max => tso_max
                        .min(65535 - ip_repr.header_len() - tcp_header_len)
                        .max(effective_mss),
                };
                let size = win_limit.min(max_seg);

                let offset = self.remote_last_seq - self.local_seq_no;
                repr.payload = self.tx_buffer.get_allocated(offset, size);

                // If we've sent everything we had in the buffer, follow it with the PSH or FIN
                // flags, depending on whether the transmit half of the connection is open.
                if offset + repr.payload.len() == self.tx_buffer.len() {
                    match self.state {
                        State::FinWait1 | State::LastAck | State::Closing => {
                            repr.control = TcpControl::Fin
                        }
                        State::Established | State::CloseWait if !repr.payload.is_empty() => {
                            repr.control = TcpControl::Psh
                        }
                        _ => (),
                    }
                }
            }

            // In FIN-WAIT-2 and TIME-WAIT states we may only transmit ACKs for incoming data or FIN
            State::FinWait2 | State::TimeWait => {}
        }

        // There might be more than one reason to send a packet. E.g. the keep-alive timer
        // has expired, and we also have data in transmit buffer. Since any packet that occupies
        // sequence space will elicit an ACK, we only need to send an explicit packet if we
        // couldn't fill the sequence space with anything.
        let is_keep_alive = if self.timer.should_keep_alive(cx.now()) && repr.is_empty() {
            repr.seq_number = repr.seq_number - 1;
            repr.payload = b"\x00"; // RFC 1122 says we should do this
            true
        } else {
            false
        };

        // Trace a summary of what will be sent.
        if is_keep_alive {
            tcp_trace!("sending a keep-alive");
        } else if !repr.payload.is_empty() {
            tcp_trace!(
                "tx buffer: sending {} octets at offset {}",
                repr.payload.len(),
                self.remote_last_seq - self.local_seq_no
            );
        }
        if repr.control != TcpControl::None || repr.payload.is_empty() {
            let flags = match (repr.control, repr.ack_number) {
                (TcpControl::Syn, None) => "SYN",
                (TcpControl::Syn, Some(_)) => "SYN|ACK",
                (TcpControl::Fin, Some(_)) => "FIN|ACK",
                (TcpControl::Rst, Some(_)) => "RST|ACK",
                (TcpControl::Psh, Some(_)) => "PSH|ACK",
                (TcpControl::None, Some(_)) => "ACK",
                _ => "<unreachable>",
            };
            tcp_trace!("sending {}", flags);
        }

        if repr.control == TcpControl::Syn {
            // Fill the MSS option. See RFC 6691 for an explanation of this calculation.
            let max_segment_size = cx.ip_mtu() - ip_repr.header_len() - TCP_HEADER_LEN;
            repr.max_seg_size = Some(max_segment_size as u16);
        }

        // Actually send the packet. If this succeeds, it means the packet is in
        // the device buffer, and its transmission is imminent. If not, we might have
        // a number of problems, e.g. we need neighbor discovery.
        //
        // Bailing out if the packet isn't placed in the device buffer allows us
        // to not waste time waiting for the retransmit timer on packets that we know
        // for sure will not be successfully transmitted.
        ip_repr.set_payload_len(repr.buffer_len());

        let mut meta = PacketMeta::default();
        {
            // Segments larger than the effective MSS exist only when the
            // device advertised TSO (see the sizing above); tell it the
            // per-segment payload size to split by.
            //
            // The device copies this header onto every wire segment it makes,
            // options included, so the same subtraction the sizing above does
            // has to happen here -- otherwise each of them is over the MTU by
            // the length of the options, which is the whole super-segment's
            // worth of oversized frames rather than one.
            let effective_mss = self
                .remote_mss
                .min(cx.ip_mtu() - ip_repr.header_len() - repr.header_len());
            if repr.payload.len() > effective_mss {
                meta.tso_seg_size = effective_mss as u16;
            }
        }
        emit(cx, meta, (ip_repr, repr))?;

        // We've sent something, whether useful data or a keep-alive packet, so rewind
        // the keep-alive timer.
        self.timer.rewind_keep_alive(cx.now(), self.keep_alive);

        // Reset delayed-ack timer
        match self.ack_delay_timer {
            AckDelayTimer::Idle => {}
            AckDelayTimer::Waiting(_) => {
                tcp_trace!("stop delayed ack timer")
            }
            AckDelayTimer::Immediate => {
                tcp_trace!("stop delayed ack timer (was force-expired)")
            }
        }
        self.ack_delay_timer = AckDelayTimer::Idle;

        // Leave the rest of the state intact if sending a zero-window probe.
        if is_zero_window_probe {
            self.timer.rewind_zero_window_probe(cx.now());
            return Ok(());
        }

        // Leave the rest of the state intact if sending a keep-alive packet, since those
        // carry a fake segment.
        if is_keep_alive {
            return Ok(());
        }

        // We've sent a packet successfully, so we can update the internal state now.
        self.remote_last_seq = repr.seq_number + repr.segment_len();
        self.remote_last_ack = repr.ack_number;
        // A SYN/SYN|ACK window field is never scaled (RFC 7323 2.2); every
        // other segment's is. Record what the peer was told, in bytes.
        self.remote_last_win = if repr.control == TcpControl::Syn {
            repr.window_len as u32
        } else {
            (repr.window_len as u32) << self.remote_win_shift
        };

        if repr.segment_len() > 0 {
            self.rtte
                .on_send(cx.now(), repr.seq_number + repr.segment_len());
            self.congestion_controller
                .inner_mut()
                .post_transmit(cx.now(), repr.segment_len());
        }

        if repr.segment_len() > 0 && !self.timer.is_retransmit() {
            // RFC 6298 (5.1) Every time a packet containing data is sent (including a
            // retransmission), if the timer is not running, start it running
            // so that it will expire after RTO seconds.
            let rto = self.rtte.retransmission_timeout();
            self.timer.set_for_retransmit(cx.now(), rto);
        }

        if self.state == State::Closed {
            // When aborting a connection, forget about it after sending a single RST packet.
            self.tuple = None;
            #[cfg(feature = "async")]
            {
                // Wake tx now so that async users can wait for the RST to be sent
                self.tx_waker.wake();
            }
        }

        Ok(())
    }

    #[allow(clippy::if_same_then_else)]
    pub(crate) fn poll_at(&self, cx: &mut Context) -> PollAt {
        // The logic here mirrors the beginning of dispatch() closely.
        if self.tuple.is_none() {
            // No one to talk to, nothing to transmit.
            PollAt::Ingress
        } else if self.remote_last_ts.is_none() {
            // Socket stopped being quiet recently, we need to acquire a timestamp.
            PollAt::Now
        } else if self.state == State::Closed {
            // Socket was aborted, we have an RST packet to transmit.
            PollAt::Now
        } else if self.seq_to_transmit(cx) {
            // We have a data or flag packet to transmit.
            PollAt::Now
        } else if self.window_to_update() {
            // The receive window has been raised significantly.
            PollAt::Now
        } else {
            let want_ack = self.ack_to_transmit();

            let delayed_ack_poll_at = match (want_ack, self.ack_delay_timer) {
                (false, _) => PollAt::Ingress,
                (true, AckDelayTimer::Idle) => PollAt::Now,
                (true, AckDelayTimer::Waiting(t)) => PollAt::Time(t),
                (true, AckDelayTimer::Immediate) => PollAt::Now,
            };

            let timeout_poll_at = match (self.remote_last_ts, self.timeout) {
                // If we're transmitting or retransmitting data, we need to poll at the moment
                // when the timeout would expire.
                (Some(remote_last_ts), Some(timeout)) => PollAt::Time(remote_last_ts + timeout),
                // Otherwise we have no timeout.
                (_, _) => PollAt::Ingress,
            };

            // We wait for the earliest of our timers to fire.
            *[self.timer.poll_at(), timeout_poll_at, delayed_ack_poll_at]
                .iter()
                .min()
                .unwrap_or(&PollAt::Ingress)
        }
    }
}

impl<'a> fmt::Write for Socket<'a> {
    fn write_str(&mut self, slice: &str) -> fmt::Result {
        let slice = slice.as_bytes();
        if self.send_slice(slice) == Ok(slice.len()) {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

// TODO: TCP should work for all features. For now, we only test with the IP feature. We could do
// it for other features as well with rstest, however, this means we have to modify a lot of the
// tests in here, which I didn't had the time for at the moment.
#[cfg(all(test, feature = "medium-ip"))]
mod test {
    use super::*;
    use crate::config::IFACE_MAX_ADDR_COUNT;
    use crate::wire::{IpCidr, IpRepr};
    use std::ops::{Deref, DerefMut};
    use std::vec::Vec;

    // =========================================================================================//
    // Constants
    // =========================================================================================//

    const LOCAL_PORT: u16 = 80;
    const REMOTE_PORT: u16 = 49500;
    const LISTEN_END: IpListenEndpoint = IpListenEndpoint {
        addr: None,
        port: LOCAL_PORT,
    };
    const TUPLE: Tuple = Tuple {
        local: LOCAL_END,
        remote: REMOTE_END,
    };
    const LOCAL_SEQ: TcpSeqNumber = TcpSeqNumber(10000);
    const REMOTE_SEQ: TcpSeqNumber = TcpSeqNumber(-10001);

    cfg_if::cfg_if! {
        if #[cfg(feature = "proto-ipv4")] {
            use crate::wire::Ipv4Address as IpvXAddress;
            use crate::wire::Ipv4Repr as IpvXRepr;
            use IpRepr::Ipv4 as IpReprIpvX;

            const LOCAL_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 1);
            const REMOTE_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 2);
            const OTHER_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 3);

            const BASE_MSS: u16 = 1460;

            const LOCAL_END: IpEndpoint = IpEndpoint {
                addr: IpAddress::Ipv4(LOCAL_ADDR),
                port: LOCAL_PORT,
            };
            const REMOTE_END: IpEndpoint = IpEndpoint {
                addr: IpAddress::Ipv4(REMOTE_ADDR),
                port: REMOTE_PORT,
            };
        } else {
            use crate::wire::Ipv6Address as IpvXAddress;
            use crate::wire::Ipv6Repr as IpvXRepr;
            use IpRepr::Ipv6 as IpReprIpvX;

            const LOCAL_ADDR: IpvXAddress = IpvXAddress::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
            const REMOTE_ADDR: IpvXAddress = IpvXAddress::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
            const OTHER_ADDR: IpvXAddress = IpvXAddress::new(0xfe80, 0, 0, 0, 0, 0, 0, 3);

            const BASE_MSS: u16 = 1440;

            const LOCAL_END: IpEndpoint = IpEndpoint {
                addr: IpAddress::Ipv6(LOCAL_ADDR),
                port: LOCAL_PORT,
            };
            const REMOTE_END: IpEndpoint = IpEndpoint {
                addr: IpAddress::Ipv6(REMOTE_ADDR),
                port: REMOTE_PORT,
            };
        }
    }

    const SEND_IP_TEMPL: IpRepr = IpReprIpvX(IpvXRepr {
        src_addr: LOCAL_ADDR,
        dst_addr: REMOTE_ADDR,
        next_header: IpProtocol::Tcp,
        payload_len: 20,
        hop_limit: 64,
    });
    const SEND_TEMPL: TcpRepr<'static> = TcpRepr {
        src_port: REMOTE_PORT,
        dst_port: LOCAL_PORT,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(0),
        ack_number: Some(TcpSeqNumber(0)),
        window_len: 256,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };
    const _RECV_IP_TEMPL: IpRepr = IpReprIpvX(IpvXRepr {
        src_addr: LOCAL_ADDR,
        dst_addr: REMOTE_ADDR,
        next_header: IpProtocol::Tcp,
        payload_len: 20,
        hop_limit: 64,
    });
    const RECV_TEMPL: TcpRepr<'static> = TcpRepr {
        src_port: LOCAL_PORT,
        dst_port: REMOTE_PORT,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(0),
        ack_number: Some(TcpSeqNumber(0)),
        window_len: 64,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    // =========================================================================================//
    // Helper functions
    // =========================================================================================//

    struct TestSocket {
        socket: Socket<'static>,
        cx: Context,
    }

    impl Deref for TestSocket {
        type Target = Socket<'static>;
        fn deref(&self) -> &Self::Target {
            &self.socket
        }
    }

    impl DerefMut for TestSocket {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.socket
        }
    }

    #[track_caller]
    fn send(
        socket: &mut TestSocket,
        timestamp: Instant,
        repr: &TcpRepr,
    ) -> Option<TcpRepr<'static>> {
        socket.cx.set_now(timestamp);

        let ip_repr = IpReprIpvX(IpvXRepr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: repr.buffer_len(),
            hop_limit: 64,
        });
        net_trace!("send: {}", repr);

        assert!(socket.socket.accepts(&mut socket.cx, &ip_repr, repr));

        match socket.socket.process(&mut socket.cx, &ip_repr, repr) {
            Some((_ip_repr, repr)) => {
                net_trace!("recv: {}", repr);
                Some(repr)
            }
            None => None,
        }
    }

    #[track_caller]
    fn recv<F>(socket: &mut TestSocket, timestamp: Instant, mut f: F)
    where
        F: FnMut(Result<TcpRepr, ()>),
    {
        socket.cx.set_now(timestamp);

        let mut sent = 0;
        let result = socket
            .socket
            .dispatch(&mut socket.cx, |_, _meta, (ip_repr, tcp_repr)| {
                assert_eq!(ip_repr.next_header(), IpProtocol::Tcp);
                assert_eq!(ip_repr.src_addr(), LOCAL_ADDR.into());
                assert_eq!(ip_repr.dst_addr(), REMOTE_ADDR.into());
                assert_eq!(ip_repr.payload_len(), tcp_repr.buffer_len());

                net_trace!("recv: {}", tcp_repr);
                sent += 1;
                Ok(f(Ok(tcp_repr)))
            });
        match result {
            Ok(()) => assert_eq!(sent, 1, "Exactly one packet should be sent"),
            Err(e) => f(Err(e)),
        }
    }

    #[track_caller]
    fn recv_nothing(socket: &mut TestSocket, timestamp: Instant) {
        socket.cx.set_now(timestamp);

        let mut fail = false;
        let result: Result<(), ()> = socket.socket.dispatch(&mut socket.cx, |_, _, _| {
            fail = true;
            Ok(())
        });
        if fail {
            panic!("Should not send a packet")
        }

        assert_eq!(result, Ok(()))
    }

    #[collapse_debuginfo(yes)]
    macro_rules! send {
        ($socket:ident, $repr:expr) =>
            (send!($socket, time 0, $repr));
        ($socket:ident, $repr:expr, $result:expr) =>
            (send!($socket, time 0, $repr, $result));
        ($socket:ident, time $time:expr, $repr:expr) =>
            (send!($socket, time $time, $repr, None));
        ($socket:ident, time $time:expr, $repr:expr, $result:expr) =>
            (assert_eq!(send(&mut $socket, Instant::from_millis($time), &$repr), $result));
    }

    #[collapse_debuginfo(yes)]
    macro_rules! recv {
        ($socket:ident, [$( $repr:expr ),*]) => ({
            $( recv!($socket, Ok($repr)); )*
            recv_nothing!($socket)
        });
        ($socket:ident, time $time:expr, [$( $repr:expr ),*]) => ({
            $( recv!($socket, time $time, Ok($repr)); )*
            recv_nothing!($socket, time $time)
        });
        ($socket:ident, $result:expr) =>
            (recv!($socket, time 0, $result));
        ($socket:ident, time $time:expr, $result:expr) =>
            (recv(&mut $socket, Instant::from_millis($time), |result| {
                // Most of the time we don't care about the PSH flag.
                let result = result.map(|mut repr| {
                    repr.control = repr.control.quash_psh();
                    repr
                });
                assert_eq!(result, $result)
            }));
        ($socket:ident, time $time:expr, $result:expr, exact) =>
            (recv(&mut $socket, Instant::from_millis($time), |repr| assert_eq!(repr, $result)));
    }

    #[collapse_debuginfo(yes)]
    macro_rules! recv_nothing {
        ($socket:ident) => (recv_nothing!($socket, time 0));
        ($socket:ident, time $time:expr) => (recv_nothing(&mut $socket, Instant::from_millis($time)));
    }

    #[collapse_debuginfo(yes)]
    macro_rules! sanity {
        ($socket1:expr, $socket2:expr) => {{
            let (s1, s2) = ($socket1, $socket2);
            assert_eq!(s1.state, s2.state, "state");
            assert_eq!(s1.tuple, s2.tuple, "tuple");
            assert_eq!(s1.local_seq_no, s2.local_seq_no, "local_seq_no");
            assert_eq!(s1.remote_seq_no, s2.remote_seq_no, "remote_seq_no");
            assert_eq!(s1.remote_last_seq, s2.remote_last_seq, "remote_last_seq");
            assert_eq!(s1.remote_last_ack, s2.remote_last_ack, "remote_last_ack");
            assert_eq!(s1.remote_last_win, s2.remote_last_win, "remote_last_win");
            assert_eq!(s1.remote_win_len, s2.remote_win_len, "remote_win_len");
            assert_eq!(s1.timer, s2.timer, "timer");
        }};
    }

    fn socket() -> TestSocket {
        socket_with_buffer_sizes(64, 64)
    }

    fn socket_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let (iface, _, _) = crate::tests::setup(crate::phy::Medium::Ip);

        let rx_buffer = SocketBuffer::new(vec![0; rx_len]);
        let tx_buffer = SocketBuffer::new(vec![0; tx_len]);
        let mut socket = Socket::new(rx_buffer, tx_buffer);
        socket.set_ack_delay(None);
        TestSocket {
            socket,
            cx: iface.inner,
        }
    }

    fn socket_with_win_shift(tx_len: usize, rx_len: usize, win_shift: u8) -> TestSocket {
        let (iface, _, _) = crate::tests::setup(crate::phy::Medium::Ip);

        let rx_buffer = SocketBuffer::new(vec![0; rx_len]);
        let tx_buffer = SocketBuffer::new(vec![0; tx_len]);
        let mut socket = Socket::new_with_win_shift(rx_buffer, tx_buffer, win_shift);
        socket.set_ack_delay(None);
        TestSocket {
            socket,
            cx: iface.inner,
        }
    }

    fn socket_syn_received_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_with_buffer_sizes(tx_len, rx_len);
        s.state = State::SynReceived;
        s.tuple = Some(TUPLE);
        s.local_seq_no = LOCAL_SEQ;
        s.remote_seq_no = REMOTE_SEQ + 1;
        s.remote_last_seq = LOCAL_SEQ;
        s.remote_win_len = 256;
        s
    }

    fn socket_syn_received() -> TestSocket {
        socket_syn_received_with_buffer_sizes(64, 64)
    }

    fn socket_syn_sent_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_with_buffer_sizes(tx_len, rx_len);
        s.state = State::SynSent;
        s.tuple = Some(TUPLE);
        s.local_seq_no = LOCAL_SEQ;
        s.remote_last_seq = LOCAL_SEQ;
        s
    }

    fn socket_syn_sent() -> TestSocket {
        socket_syn_sent_with_buffer_sizes(64, 64)
    }

    fn socket_established_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_syn_received_with_buffer_sizes(tx_len, rx_len);
        s.state = State::Established;
        s.local_seq_no = LOCAL_SEQ + 1;
        s.remote_last_seq = LOCAL_SEQ + 1;
        s.remote_last_ack = Some(REMOTE_SEQ + 1);
        s.remote_last_win = (s.scaled_window() as u32) << s.remote_win_shift;
        s
    }

    fn socket_established() -> TestSocket {
        socket_established_with_buffer_sizes(64, 64)
    }

    fn socket_fin_wait_1() -> TestSocket {
        let mut s = socket_established();
        s.state = State::FinWait1;
        s
    }

    fn socket_fin_wait_2() -> TestSocket {
        let mut s = socket_fin_wait_1();
        s.state = State::FinWait2;
        s.local_seq_no = LOCAL_SEQ + 1 + 1;
        s.remote_last_seq = LOCAL_SEQ + 1 + 1;
        s
    }

    fn socket_closing() -> TestSocket {
        let mut s = socket_fin_wait_1();
        s.state = State::Closing;
        s.remote_last_seq = LOCAL_SEQ + 1 + 1;
        s.remote_seq_no = REMOTE_SEQ + 1 + 1;
        s.timer = Timer::Retransmit {
            expires_at: Instant::from_millis_const(1000),
        };
        s
    }

    fn socket_time_wait(from_closing: bool) -> TestSocket {
        let mut s = socket_fin_wait_2();
        s.state = State::TimeWait;
        s.remote_seq_no = REMOTE_SEQ + 1 + 1;
        if from_closing {
            s.remote_last_ack = Some(REMOTE_SEQ + 1 + 1);
        }
        s.timer = Timer::Close {
            expires_at: Instant::from_secs(1) + CLOSE_DELAY,
        };
        s
    }

    fn socket_close_wait() -> TestSocket {
        let mut s = socket_established();
        s.state = State::CloseWait;
        s.remote_seq_no = REMOTE_SEQ + 1 + 1;
        s.remote_last_ack = Some(REMOTE_SEQ + 1 + 1);
        s
    }

    fn socket_last_ack() -> TestSocket {
        let mut s = socket_close_wait();
        s.state = State::LastAck;
        s
    }

    fn socket_recved() -> TestSocket {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
        s
    }

    /// A byte stream long enough to overrun a receive ring, with a pattern
    /// that makes any misplaced byte visible as data, not just as a length.
    fn segmented_stream(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn drain_rx(s: &mut TestSocket) -> Vec<u8> {
        let mut drained = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match s.recv_slice(&mut chunk) {
                Ok(0) => break,
                Ok(len) => drained.extend_from_slice(&chunk[..len]),
                Err(err) => panic!("recv_slice failed: {err:?}"),
            }
        }
        drained
    }

    /// Drives the D1 overrun scenario against a just-established socket
    /// whose handshake advertised an unscaled 65535-byte window for its
    /// 65536-byte ring, before any ordinary ACK corrected the peer's view:
    /// a peer that ignores the advertised window bursts 46 in-order
    /// segments in one poll batch. Exactly `accepted` bytes must be
    /// admitted, the socket must stay usable, and the retransmitted tail
    /// must be delivered once the window reopens.
    fn overrun_burst_and_recover(mut s: TestSocket, accepted: usize) {
        const SEG_LEN: usize = 1460;
        const SEG_COUNT: usize = 46; // 67160 bytes > the 65536-byte ring

        let stream = segmented_stream(SEG_COUNT * SEG_LEN);
        for i in 0..SEG_COUNT {
            let payload = &stream[i * SEG_LEN..(i + 1) * SEG_LEN];
            let seq_number = REMOTE_SEQ + 1 + i * SEG_LEN;
            if i * SEG_LEN < accepted {
                // At least partially inside the advertised window: the
                // in-window bytes are accepted, without an immediate reply.
                send!(
                    s,
                    TcpRepr {
                        seq_number,
                        ack_number: Some(LOCAL_SEQ + 1),
                        payload,
                        ..SEND_TEMPL
                    }
                );
            } else {
                // Entirely beyond the advertised window: challenge ACK.
                send!(
                    s,
                    TcpRepr {
                        seq_number,
                        ack_number: Some(LOCAL_SEQ + 1),
                        payload,
                        ..SEND_TEMPL
                    },
                    Some(TcpRepr {
                        seq_number: LOCAL_SEQ + 1,
                        ack_number: Some(REMOTE_SEQ + 1 + accepted),
                        window_len: ((65536 - accepted) >> 1) as u16,
                        ..RECV_TEMPL
                    })
                );
            }
        }
        assert_eq!(s.state, State::Established);

        // Exactly the advertised bytes were accepted, none of them mangled.
        let received = drain_rx(&mut s);
        assert_eq!(received.len(), accepted);
        assert_eq!(received[..], stream[..accepted]);

        // Draining reopened the window; the socket advertises it and then
        // accepts the retransmitted tail: it survived the overrun usable.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + accepted),
                window_len: 32768,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + accepted,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &stream[accepted..],
                ..SEND_TEMPL
            }
        );
        let received = drain_rx(&mut s);
        assert_eq!(received[..], stream[accepted..]);
    }

    // =========================================================================================//
    // Tests for the CLOSED state.
    // =========================================================================================//
    #[test]
    fn test_closed_reject() {
        let mut s = socket();
        assert_eq!(s.state, State::Closed);

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_closed_reject_after_listen() {
        let mut s = socket();
        s.listen(LOCAL_END).unwrap();
        s.close();

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_closed_close() {
        let mut s = socket();
        s.close();
        assert_eq!(s.state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the LISTEN state.
    // =========================================================================================//
    fn socket_listen() -> TestSocket {
        let mut s = socket();
        s.state = State::Listen;
        s.listen_endpoint = LISTEN_END;
        s
    }

    #[test]
    fn test_listen_sack_option() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                sack_permitted: false,
                ..SEND_TEMPL
            }
        );
        assert!(!s.remote_has_sack);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );

        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                sack_permitted: true,
                ..SEND_TEMPL
            }
        );
        assert!(s.remote_has_sack);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_listen_syn_win_scale_buffers() {
        for (buffer_size, shift_amt) in &[
            (64, 0),
            (128, 0),
            (1024, 0),
            (65535, 0),
            (65536, 1),
            (65537, 1),
            (131071, 1),
            (131072, 2),
            (524287, 3),
            (524288, 4),
            (655350, 4),
            (1048576, 5),
        ] {
            let mut s = socket_with_buffer_sizes(64, *buffer_size);
            s.state = State::Listen;
            s.listen_endpoint = LISTEN_END;
            assert_eq!(s.remote_win_shift, *shift_amt);
            send!(
                s,
                TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: REMOTE_SEQ,
                    ack_number: None,
                    window_scale: Some(0),
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.remote_win_shift, *shift_amt);
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: Some(REMOTE_SEQ + 1),
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(*shift_amt),
                    window_len: u16::try_from(*buffer_size).unwrap_or(u16::MAX),
                    ..RECV_TEMPL
                }]
            );
        }
    }

    #[test]
    fn test_listen_syn_win_shift_override() {
        // A socket built with an explicit window scale announces it even
        // though its rx ring is far smaller than the scale would imply: the
        // scale is a pre-SYN commitment for the configured capacity, the
        // ring is not. The SYN|ACK window field stays the unscaled ring size.
        let mut s = socket_with_win_shift(64, 16384, 7);
        assert_eq!(s.remote_win_shift, 7);
        s.state = State::Listen;
        s.listen_endpoint = LISTEN_END;
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.remote_win_shift, 7);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(7),
                window_len: 16384,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_win_shift_override_survives_reset() {
        // Listener-owned sockets are reset when (re)armed; the configured
        // scale must survive, not be re-derived from the small ring.
        let mut s = socket_with_win_shift(64, 16384, 7);
        s.socket.reset();
        assert_eq!(s.remote_win_shift, 7);
    }

    #[test]
    #[should_panic(expected = "window scale must not exceed 14")]
    fn test_win_shift_override_rejects_over_14() {
        let rx = SocketBuffer::new(vec![0; 64]);
        let tx = SocketBuffer::new(vec![0; 64]);
        let _ = Socket::new_with_win_shift(rx, tx, 15);
    }

    #[test]
    fn test_listen_window_overrun_in_first_ack_round_trip() {
        // A SYN|ACK advertises an unscaled window (RFC 7323 2.2), and no
        // ordinary ACK corrects it until the current poll batch is fully
        // processed. The receive-window right edge for that first round trip
        // must be the 65535 bytes the peer was told, not
        // 65535 << remote_win_shift: a peer that ignores the advertised
        // window must not push in-order payload past the receive ring.
        let mut s = socket_with_buffer_sizes(64, 65536);
        s.state = State::Listen;
        s.listen_endpoint = LISTEN_END;
        assert_eq!(s.remote_win_shift, 1);

        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(1),
                window_len: 65535,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);

        // The whole burst arrives before we dispatch anything, like one
        // Interface::poll batch draining its receive queue before any
        // egress. The SYN|ACK's window field told the peer 65535 bytes.
        overrun_burst_and_recover(s, 65535);
    }

    #[test]
    fn test_listen_records_advertised_syn_window_in_bytes() {
        // `remote_last_win` must always record what the peer was actually
        // told, in bytes: the SYN|ACK's window field verbatim, and every
        // later segment's window field scaled back up to bytes.
        let mut s = socket_with_buffer_sizes(64, 65536);
        s.state = State::Listen;
        s.listen_endpoint = LISTEN_END;
        assert_eq!(s.remote_win_shift, 1);

        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(1),
                window_len: 65535,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.remote_last_win as usize, 65535);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 32765,
                ..RECV_TEMPL
            }]
        );
        // The peer reads that ACK's window as 32765 << 1 bytes.
        assert_eq!(s.remote_last_win as usize, 65530);
    }

    #[test]
    fn test_listen_full_window_advertised_after_establish() {
        // A scaled socket's SYN|ACK can announce at most 65535 bytes. The
        // corrected advertisement is deliberately deferred: nothing extra
        // may follow the SYN|ACK in SYN-RECEIVED (a second reply to every
        // SYN would be amplification), and the full window goes out once
        // the handshake completes.
        let mut s = socket_with_buffer_sizes(64, 131072);
        s.state = State::Listen;
        s.listen_endpoint = LISTEN_END;
        assert_eq!(s.remote_win_shift, 2);

        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        // recv! also proves nothing follows the SYN|ACK.
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(2),
                window_len: 65535,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: 32768,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.remote_last_win as usize, 131072);
    }

    #[test]
    fn test_grow_rx_applies_at_established_edge() {
        // The lazy-backlog flow: a socket with a floor-size ring and the
        // configured scale latches its growth while listening, keeps the
        // small ring through the handshake (the SYN|ACK window field reads
        // small), and grows at the ESTABLISHED edge -- so the corrective
        // full-window advertisement already announces the grown window.
        let mut s = socket_with_win_shift(64, 16384, 2);
        s.state = State::Listen;
        s.listen_endpoint = LISTEN_END;

        s.socket.grow_rx_capacity(131072);
        assert_eq!(s.recv_capacity(), 16384);
        assert_eq!(s.effective_recv_capacity(), 131072);

        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(2),
                window_len: 16384,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.recv_capacity(), 16384);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.recv_capacity(), 131072);
        assert_eq!(s.effective_recv_capacity(), 131072);
        assert_eq!(s.remote_win_shift, 2);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: 32768,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.remote_last_win as usize, 131072);
    }

    #[test]
    fn test_grow_rx_latches_until_read_out() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );

        s.socket.grow_rx_capacity(256);
        assert_eq!(s.recv_capacity(), 64);
        assert_eq!(s.effective_recv_capacity(), 256);

        let mut buf = [0; 3];
        assert_eq!(s.socket.recv_slice(&mut buf[..]), Ok(3));
        assert_eq!(s.recv_capacity(), 64);

        assert_eq!(s.socket.recv_slice(&mut buf[..]), Ok(3));
        assert_eq!(s.recv_capacity(), 256);
        assert_eq!(s.effective_recv_capacity(), 256);
    }

    #[test]
    fn test_grow_tx_latches_until_acked() {
        let mut s = socket_established();
        assert_eq!(s.socket.send_slice(b"abcdef"), Ok(6));

        s.socket.grow_tx_capacity(256);
        assert_eq!(s.send_capacity(), 64);
        assert_eq!(s.effective_send_capacity(), 256);

        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.send_capacity(), 64);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.send_capacity(), 256);
        assert_eq!(s.effective_send_capacity(), 256);
    }

    #[test]
    fn test_grow_rx_clamped_to_announced_scale() {
        // An unscaled connection can never advertise past 65535, so rx
        // growth clamps there; a request at or below the current capacity
        // clears any pending growth instead of shrinking.
        let mut s = socket_established();
        s.socket.grow_rx_capacity(1 << 20);
        assert_eq!(s.recv_capacity(), 65535);

        s.socket.grow_rx_capacity(32);
        assert_eq!(s.recv_capacity(), 65535);
        assert_eq!(s.effective_recv_capacity(), 65535);
    }

    #[test]
    fn test_listen_sanity() {
        let mut s = socket();
        s.listen(LOCAL_PORT).unwrap();
        sanity!(s, socket_listen());
    }

    #[test]
    fn test_listen_validation() {
        let mut s = socket();
        assert_eq!(s.listen(0), Err(ListenError::Unaddressable));
    }

    #[test]
    fn test_listen_twice() {
        let mut s = socket();
        assert_eq!(s.listen(80), Ok(()));
        // multiple calls to listen are okay if its the same local endpoint and the state is still in listening
        assert_eq!(s.listen(80), Ok(()));
        s.set_state(State::SynReceived); // state change, simulate incoming connection
        assert_eq!(s.listen(80), Err(ListenError::InvalidState));
    }

    #[test]
    fn test_listen_syn() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        sanity!(s, socket_syn_received());
    }

    #[test]
    fn test_listen_syn_reject_ack() {
        let mut s = socket_listen();

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ),
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));

        assert_eq!(s.state, State::Listen);
    }

    #[test]
    fn test_listen_rst() {
        let mut s = socket_listen();
        let tcp_repr = TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
        assert_eq!(s.state, State::Listen);
    }

    #[test]
    fn test_listen_close() {
        let mut s = socket_listen();
        s.close();
        assert_eq!(s.state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the SYN-RECEIVED state.
    // =========================================================================================//

    #[test]
    fn test_syn_received_ack() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        sanity!(s, socket_established());
    }

    #[cfg(feature = "socket-tcp-pause-synack")]
    #[test]
    fn test_syn_paused_ack() {
        let mut s = socket_syn_received();

        s.pause_synack(true);
        recv_nothing!(s);
        assert_eq!(s.state, State::SynReceived);

        s.pause_synack(false);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
    }

    #[test]
    fn test_syn_received_ack_too_low() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ), // wrong
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::SynReceived);
    }

    #[test]
    fn test_syn_received_ack_too_high() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2), // wrong
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 2,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::SynReceived);
    }

    #[test]
    fn test_syn_received_fin() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6 + 1),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::CloseWait);

        let mut s2 = socket_close_wait();
        s2.remote_last_ack = Some(REMOTE_SEQ + 1 + 6 + 1);
        s2.remote_last_win = 58;
        sanity!(s, s2);
    }

    #[test]
    fn test_syn_received_rst() {
        let mut s = socket_syn_received();
        s.listen_endpoint = LISTEN_END;
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Listen);
        assert_eq!(s.listen_endpoint, LISTEN_END);
        assert_eq!(s.tuple, None);
    }

    // A half-open connection is as worth protecting as an established one: an
    // off-centre reset must not knock a pending accept back to LISTEN.
    #[test]
    fn test_syn_received_rst_in_window_is_challenged() {
        let mut s = socket_syn_received();
        s.listen_endpoint = LISTEN_END;
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 2,
                ack_number: Some(LOCAL_SEQ),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
    }

    // The SYN challenge stops short of SYN-RECEIVED, where a repeated SYN is
    // the peer asking again for the SYN|ACK it never got. Answering that with
    // a bare ACK tells a peer in SYN-SENT nothing it can use, and it would
    // spend the challenge budget of a socket that has yet to accept.
    #[test]
    fn test_syn_received_syn_is_not_challenged() {
        let mut s = socket_syn_received();
        s.listen_endpoint = LISTEN_END;
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
    }

    #[test]
    fn test_syn_received_no_window_scaling() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: None,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_scale: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.remote_win_shift, 0);
        assert_eq!(s.remote_win_scale, None);
    }

    #[test]
    fn test_syn_received_window_scaling() {
        for scale in 0..14 {
            let mut s = socket_listen();
            send!(
                s,
                TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: REMOTE_SEQ,
                    ack_number: None,
                    window_scale: Some(scale),
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.state(), State::SynReceived);
            assert_eq!(s.tuple, Some(TUPLE));
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: Some(REMOTE_SEQ + 1),
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(0),
                    ..RECV_TEMPL
                }]
            );
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    window_scale: None,
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.remote_win_scale, Some(scale));
        }
    }

    #[test]
    fn test_syn_received_close() {
        let mut s = socket_syn_received();
        s.close();
        assert_eq!(s.state, State::FinWait1);
    }

    // =========================================================================================//
    // Tests for the SYN-SENT state.
    // =========================================================================================//

    #[test]
    fn test_connect_validation() {
        let mut s = socket();
        assert_eq!(
            s.socket
                .connect(&mut s.cx, REMOTE_END, (IpvXAddress::UNSPECIFIED, 0)),
            Err(ConnectError::Unaddressable)
        );
        assert_eq!(
            s.socket
                .connect(&mut s.cx, REMOTE_END, (IpvXAddress::UNSPECIFIED, 1024)),
            Err(ConnectError::Unaddressable)
        );
        assert_eq!(
            s.socket
                .connect(&mut s.cx, (IpvXAddress::UNSPECIFIED, 0), LOCAL_END),
            Err(ConnectError::Unaddressable)
        );
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END)
            .expect("Connect failed with valid parameters");
        assert_eq!(s.tuple, Some(TUPLE));
    }

    #[test]
    fn test_connect() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tuple, Some(TUPLE));
    }

    #[test]
    fn test_connect_unspecified_local() {
        let mut s = socket();
        assert_eq!(s.socket.connect(&mut s.cx, REMOTE_END, 80), Ok(()));
    }

    #[test]
    fn test_connect_specified_local() {
        let mut s = socket();
        assert_eq!(
            s.socket.connect(&mut s.cx, REMOTE_END, (REMOTE_ADDR, 80)),
            Ok(())
        );
    }

    #[test]
    fn test_connect_twice() {
        let mut s = socket();
        assert_eq!(s.socket.connect(&mut s.cx, REMOTE_END, 80), Ok(()));
        assert_eq!(
            s.socket.connect(&mut s.cx, REMOTE_END, 80),
            Err(ConnectError::InvalidState)
        );
    }

    #[test]
    fn test_syn_sent_sanity() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        sanity!(s, socket_syn_sent());
    }

    #[test]
    fn test_syn_sent_syn_ack() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s, time 1000);
        assert_eq!(s.state, State::Established);
        sanity!(s, socket_established());
    }

    #[test]
    fn test_syn_sent_syn_received_ack() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );

        // A SYN packet changes the SYN-SENT state to SYN-RECEIVED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynReceived);

        // The socket will then send a SYN|ACK packet.
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s);

        // The socket may retransmit the SYN|ACK packet.
        recv!(
            s,
            time 1001,
            Ok(TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                ..RECV_TEMPL
            })
        );

        // An ACK packet changes the SYN-RECEIVED state to ESTABLISHED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::None,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        sanity!(s, socket_established());
    }

    #[test]
    fn test_syn_sent_syn_ack_not_incremented() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ), // WRONG
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_syn_received_rst() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );

        // A SYN packet changes the SYN-SENT state to SYN-RECEIVED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynReceived);

        // A RST packet changes the SYN-RECEIVED state to CLOSED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_syn_sent_rst() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_syn_sent_rst_no_ack() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_rst_bad_ack() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: Some(TcpSeqNumber(1234)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None, // Unexpected
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1), // Correct
                ..SEND_TEMPL
            }
        );

        // It should trigger no response and change no state
        recv!(s, []);
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack_seq_1() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ), // WRONG
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ, // matching the ack_number of the unexpected ack
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );

        // It should trigger a RST, and change no state
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack_seq_2() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 123456), // WRONG
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 123456, // matching the ack_number of the unexpected ack
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );

        // It should trigger a RST, and change no state
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_close() {
        let mut s = socket();
        s.close();
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_syn_sent_sack_option() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                sack_permitted: true,
                ..SEND_TEMPL
            }
        );
        assert!(s.remote_has_sack);

        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                sack_permitted: false,
                ..SEND_TEMPL
            }
        );
        assert!(!s.remote_has_sack);
    }

    #[test]
    fn test_syn_sent_win_scale_buffers() {
        for (buffer_size, shift_amt) in &[
            (64, 0),
            (128, 0),
            (1024, 0),
            (65535, 0),
            (65536, 1),
            (65537, 1),
            (131071, 1),
            (131072, 2),
            (524287, 3),
            (524288, 4),
            (655350, 4),
            (1048576, 5),
        ] {
            let mut s = socket_with_buffer_sizes(64, *buffer_size);
            s.local_seq_no = LOCAL_SEQ;
            assert_eq!(s.remote_win_shift, *shift_amt);
            s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: None,
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(*shift_amt),
                    window_len: u16::try_from(*buffer_size).unwrap_or(u16::MAX),
                    sack_permitted: true,
                    ..RECV_TEMPL
                }]
            );
        }
    }

    #[test]
    fn test_syn_sent_win_shift_override() {
        // Active-open counterpart of test_listen_syn_win_shift_override:
        // the SYN announces the configured scale, the window field the ring.
        let mut s = socket_with_win_shift(64, 16384, 7);
        s.local_seq_no = LOCAL_SEQ;
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        assert_eq!(s.remote_win_shift, 7);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(7),
                window_len: 16384,
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_connect_window_overrun_in_first_ack_round_trip() {
        // The active-open counterpart of
        // test_listen_window_overrun_in_first_ack_round_trip: our SYN
        // advertised an unscaled 65535, and the peer's SYN|ACK plus its
        // first burst arrive in one poll batch, before our handshake ACK is
        // dispatched. Processing the SYN|ACK records `remote_last_ack` as
        // the peer's ISN, so the right edge admits one byte less of payload
        // than the advertised window.
        let mut s = socket_with_buffer_sizes(64, 65536);
        s.local_seq_no = LOCAL_SEQ;
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        assert_eq!(s.remote_win_shift, 1);

        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(1),
                window_len: 65535,
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);

        overrun_burst_and_recover(s, 65534);
    }

    #[test]
    fn test_connect_records_advertised_syn_window_in_bytes() {
        // The SYN records its unscaled window field verbatim; the handshake
        // ACK records its scaled window field converted back to bytes.
        let mut s = socket_with_buffer_sizes(64, 65536);
        s.local_seq_no = LOCAL_SEQ;
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        assert_eq!(s.remote_win_shift, 1);

        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(1),
                window_len: 65535,
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.remote_last_win as usize, 65535);

        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: 32768,
                ..RECV_TEMPL
            }]
        );
        // The peer reads that ACK's window as 32768 << 1 bytes.
        assert_eq!(s.remote_last_win as usize, 65536);
    }

    #[test]
    fn test_syn_sent_syn_ack_no_window_scaling() {
        let mut s = socket_syn_sent_with_buffer_sizes(1048576, 1048576);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                // scaling does NOT apply to the window value in SYN packets
                window_len: 65535,
                window_scale: Some(5),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.remote_win_shift, 5);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: None,
                window_len: 42,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_win_shift, 0);
        assert_eq!(s.remote_win_scale, None);
        assert_eq!(s.remote_win_len, 42);
    }

    #[test]
    fn test_syn_sent_syn_ack_window_scaling() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(7),
                window_len: 42,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_win_scale, Some(7));
        // scaling does NOT apply to the window value in SYN packets
        assert_eq!(s.remote_win_len, 42);
    }

    // =========================================================================================//
    // Tests for the ESTABLISHED state.
    // =========================================================================================//

    #[test]
    fn test_established_recv() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.rx_buffer.dequeue_many(6), &b"abcdef"[..]);
    }

    #[test]
    fn test_peek_slice() {
        const BUF_SIZE: usize = 10;

        let send_buf = b"0123456";

        let mut s = socket_established_with_buffer_sizes(BUF_SIZE, BUF_SIZE);

        // Populate the recv buffer
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &send_buf[..],
                ..SEND_TEMPL
            }
        );

        // Peek into the recv buffer
        let mut peeked_buf = [0u8; BUF_SIZE];
        let actually_peeked = s.peek_slice(&mut peeked_buf[..]).unwrap();
        let mut recv_buf = [0u8; BUF_SIZE];
        let actually_recvd = s.recv_slice(&mut recv_buf[..]).unwrap();
        assert_eq!(
            &mut peeked_buf[..actually_peeked],
            &mut recv_buf[..actually_recvd]
        );
    }

    #[test]
    fn test_peek_slice_buffer_wrap() {
        const BUF_SIZE: usize = 10;

        let send_buf = b"0123456789";

        let mut s = socket_established_with_buffer_sizes(BUF_SIZE, BUF_SIZE);

        let _ = s.rx_buffer.enqueue_slice(&send_buf[..8]);
        let _ = s.rx_buffer.dequeue_many(6);
        let _ = s.rx_buffer.enqueue_slice(&send_buf[..5]);

        let mut peeked_buf = [0u8; BUF_SIZE];
        let actually_peeked = s.peek_slice(&mut peeked_buf[..]).unwrap();
        let mut recv_buf = [0u8; BUF_SIZE];
        let actually_recvd = s.recv_slice(&mut recv_buf[..]).unwrap();
        assert_eq!(
            &mut peeked_buf[..actually_peeked],
            &mut recv_buf[..actually_recvd]
        );
    }

    fn setup_rfc2018_cases() -> (TestSocket, Vec<u8>) {
        // This is a utility function used by the tests for RFC 2018 cases. It configures a socket
        // in a particular way suitable for those cases.
        //
        // RFC 2018: Assume the left window edge is 5000 and that the data transmitter sends [...]
        // segments, each containing 500 data bytes.
        let mut s = socket_established_with_buffer_sizes(4000, 4000);
        s.remote_has_sack = true;

        // create a segment that is 500 bytes long
        let mut segment: Vec<u8> = Vec::with_capacity(500);

        // move the last ack to 5000 by sending ten of them
        for _ in 0..50 {
            segment.extend_from_slice(b"abcdefghij")
        }
        for offset in (0..5000).step_by(500) {
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + offset,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &segment,
                    ..SEND_TEMPL
                }
            );
            recv!(
                s,
                [TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1 + offset + 500),
                    window_len: 3500,
                    ..RECV_TEMPL
                }]
            );
            s.recv(|data| {
                assert_eq!(data.len(), 500);
                assert_eq!(data, segment.as_slice());
                (500, ())
            })
            .unwrap();
        }
        assert_eq!(s.remote_last_win, 3500);
        (s, segment)
    }

    #[test]
    fn test_established_rfc2018_cases() {
        // This test case verifies the exact scenarios described on pages 8-9 of RFC 2018. Please
        // ensure its behavior does not deviate from those scenarios.

        let (mut s, segment) = setup_rfc2018_cases();
        // RFC 2018:
        //
        // Case 2: The first segment is dropped but the remaining 7 are received.
        //
        // Upon receiving each of the last seven packets, the data receiver will return a TCP ACK
        // segment that acknowledges sequence number 5000 and contains a SACK option specifying one
        // block of queued data:
        //
        //   Triggering   ACK      Left Edge  Right Edge
        //   Segment
        //
        //   5000         (lost)
        //   5500         5000     5500       6000
        //   6000         5000     5500       6500
        //   6500         5000     5500       7000
        //   7000         5000     5500       7500
        //   7500         5000     5500       8000
        //   8000         5000     5500       8500
        //   8500         5000     5500       9000
        //
        for offset in (500..3500).step_by(500) {
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + offset + 5000,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &segment,
                    ..SEND_TEMPL
                },
                Some(TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1 + 5000),
                    window_len: 4000,
                    sack_ranges: [
                        Some((
                            REMOTE_SEQ.0 as u32 + 1 + 5500,
                            REMOTE_SEQ.0 as u32 + 1 + 5500 + offset as u32
                        )),
                        None,
                        None
                    ],
                    ..RECV_TEMPL
                })
            );
        }
    }

    #[test]
    fn test_established_sack_no_overflow_on_near_max_seqnumber() {
        let mut s = socket_established();
        s.remote_has_sack = true;
        s.remote_seq_no = TcpSeqNumber(-4);
        s.remote_last_ack = Some(TcpSeqNumber(-4));

        // Send an out-of-order segment 10 bytes past the expected sequence,
        // creating a 10-byte hole at the front of the assembler.
        send!(
            s,
            TcpRepr {
                seq_number: TcpSeqNumber(-4 + 10),
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"AAAAAAAAAA"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(TcpSeqNumber(-4)),
                window_len: 64,
                sack_ranges: [
                    Some(((-4_i32 + 10) as u32, (-4_i32 + 20) as u32,)),
                    None,
                    None,
                ],
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_receive_overlap_bounds() {
        const PAYLOAD: &[u8] = b"0123456789";
        let start = TcpSeqNumber(1000);

        // In order at the left edge, and truncated at the right one.
        assert_eq!(
            Socket::receive_overlap(PAYLOAD, start, start, start + 64, 64),
            Some((PAYLOAD, 0))
        );
        assert_eq!(
            Socket::receive_overlap(PAYLOAD, start, start, start + 4, 64),
            Some((&PAYLOAD[..4], 0))
        );
        // Partly already received: trimmed on the left, offset 0.
        assert_eq!(
            Socket::receive_overlap(PAYLOAD, start - 4, start, start + 64, 64),
            Some((&PAYLOAD[4..], 0))
        );
        // Out of order but inside the window: kept whole, at its offset.
        assert_eq!(
            Socket::receive_overlap(PAYLOAD, start + 8, start, start + 64, 64),
            Some((PAYLOAD, 8))
        );

        // A right edge preceding the left one, with a segment far enough
        // ahead that the wrapping comparisons of the acceptance test admit
        // it. The overlap is unbounded by the ring, so it is rejected.
        assert_eq!(
            Socket::receive_overlap(PAYLOAD, start + 2147483598, start, start - 100, 64),
            None
        );
        // The same crossed edges with a segment behind the window: the
        // overlap itself is inverted.
        assert_eq!(
            Socket::receive_overlap(PAYLOAD, start - 200, start, start - 100, 64),
            None
        );
        // Inside the window, but past what the ring can still hold: this is
        // the write that would otherwise be silently short.
        assert_eq!(
            Socket::receive_overlap(PAYLOAD, start + 60, start, start + 128, 64),
            None
        );
    }

    #[test]
    fn test_established_recorded_window_beyond_ring() {
        // Defence in depth for a receive-window right edge that outruns the
        // ring: only what the ring can store may be accepted, whatever the
        // recorded advertisement says. Constructed directly, because after
        // the SYN-window fix no packet sequence records such a window.
        let mut s = socket_established_with_buffer_sizes(64, 64);
        // A pattern in the storage, so that any octet published without
        // being written shows up as data and not just as a length.
        s.rx_buffer = SocketBuffer::new(vec![b'X'; 64]);
        s.remote_last_win = 4096;

        let stream = segmented_stream(100);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &stream,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.rx_buffer.len(), 64);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 64),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(drain_rx(&mut s)[..], stream[..64]);

        // Draining reopened the window; the retransmitted tail is delivered.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 64),
                window_len: 64,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 64,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &stream[64..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(drain_rx(&mut s)[..], stream[64..]);
    }

    #[test]
    fn test_established_crossed_receive_window() {
        // The window edges come from different epochs; a right edge that
        // precedes the left one must reject every segment rather than
        // compute a crossed overlap. Constructed directly for the same
        // reason as above.
        let mut s = socket_established();
        s.remote_last_ack = Some(REMOTE_SEQ + 1 - 100);
        s.remote_last_win = 0;

        // Far enough ahead that the wrapping acceptance comparisons would
        // admit it against the crossed edges.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 2147483598,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: 64,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.rx_buffer.len(), 0);
        assert!(s.assembler.is_empty());

        // The ACK above republished the window, and the socket is usable.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(drain_rx(&mut s)[..], b"abcdef"[..]);
    }

    #[test]
    fn test_established_out_of_order_offset_bounded_by_ring() {
        // The assembler records any offset it is handed, so an offset past
        // the receive ring would leave a hole that can never be filled. The
        // recorded window is given a right edge well beyond the ring -- the
        // only shape that ever produced such an offset -- constructed
        // directly, since no packet sequence records one any more.
        let mut s = socket_established();
        s.remote_last_win = 4096;
        assert_eq!(s.rx_buffer.window(), 64);

        // Past the ring but inside the recorded window: the segment must be
        // answered with a challenge ACK and never seen by the assembler.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 200,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"beyond"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: 64,
                ..RECV_TEMPL
            })
        );
        assert!(s.assembler.is_empty());
        assert_eq!(s.rx_buffer.len(), 0);

        // Straddling the ring's end: the in-ring part is kept at its offset,
        // and the recorded hole plus data ends exactly at the ring's end.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 60,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"0123456789"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: 64,
                ..RECV_TEMPL
            })
        );
        assert!(!s.assembler.is_empty());
        assert_eq!(s.assembler.iter_data().collect::<Vec<_>>(), vec![(60, 64)]);

        // Neither rejection nor truncation prevents in-order recovery: the
        // hole fills and the whole ring is delivered, holding the truncated
        // segment's first four octets and none of its discarded tail.
        let head = segmented_stream(60);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &head,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 64),
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert!(s.assembler.is_empty());
        let mut expected = head.clone();
        expected.extend_from_slice(b"0123");
        assert_eq!(drain_rx(&mut s), expected);
        assert_eq!(s.state, State::Established);
    }

    #[test]
    fn test_established_sliding_window_recv() {
        let mut s = socket_established();
        // Update our scaling parameters for a TCP with a scaled buffer.
        assert_eq!(s.rx_buffer.len(), 0);
        s.rx_buffer = SocketBuffer::new(vec![0; 262143]);
        s.assembler = Assembler::new();
        s.remote_win_scale = Some(0);
        // The advertised scaled window field was 65535; the field is bytes.
        s.remote_last_win = 65535 << 2;
        s.remote_win_shift = 2;

        // Create a TCP segment that will mostly fill an IP frame.
        let mut segment: Vec<u8> = Vec::with_capacity(1400);
        for _ in 0..100 {
            segment.extend_from_slice(b"abcdefghijklmn")
        }
        assert_eq!(segment.len(), 1400);

        // Send the frame
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            }
        );

        // Ensure that the received window size is shifted right by 2.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1400),
                window_len: 65185,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send() {
        let mut s = socket_established();
        // First roundtrip after establishing.
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.tx_buffer.len(), 6);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 0);
        // Second roundtrip.
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 0);
    }

    #[test]
    fn test_established_send_no_ack_send() {
        let mut s = socket_established();
        s.set_nagle_enabled(false);
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send_buf_gt_win() {
        let mut data = [0; 32];
        for (i, elem) in data.iter_mut().enumerate() {
            *elem = i as u8
        }

        let mut s = socket_established();
        s.remote_win_len = 16;
        s.send_slice(&data[..]).unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &data[0..16],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send_window_shrink() {
        let mut s = socket_established();

        // 6 octets fit on the remote side's window, so we send them.
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.tx_buffer.len(), 6);

        println!(
            "local_seq_no={} remote_win_len={} remote_last_seq={}",
            s.local_seq_no, s.remote_win_len, s.remote_last_seq
        );

        // - Peer doesn't ack them yet
        // - Sends data so we need to reply with an ACK
        // - ...AND and sends a window announcement that SHRINKS the window, so data we've
        //   previously sent is now outside the window. Yes, this is allowed by TCP.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 3,
                payload: &b"xyzxyz"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 6);

        println!(
            "local_seq_no={} remote_win_len={} remote_last_seq={}",
            s.local_seq_no, s.remote_win_len, s.remote_last_seq
        );

        // More data should not get sent since it doesn't fit in the window
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 64 - 6,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_receive_partially_outside_window() {
        let mut s = socket_established();

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();

        // Peer decides to retransmit (perhaps because the ACK was lost)
        // and also pushed data.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"def");
            (3, ())
        })
        .unwrap();
    }

    #[test]
    fn test_established_receive_overlap_across_sequence_wrap() {
        let mut s = socket_established();
        let remote_seq = TcpSeqNumber(i32::MAX - 2);
        s.remote_seq_no = remote_seq;
        s.remote_last_ack = Some(remote_seq);
        s.remote_last_win = (s.scaled_window() as u32) << s.remote_win_shift;

        send!(
            s,
            TcpRepr {
                seq_number: remote_seq,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"abcd",
                ..SEND_TEMPL
            }
        );
        let mut data = [0; 4];
        assert_eq!(s.recv_slice(&mut data), Ok(4));
        assert_eq!(&data, b"abcd");

        // Retransmit the last two bytes and append four new bytes. Both the
        // sequence range and the accepted overlap cross i32::MAX.
        send!(
            s,
            TcpRepr {
                seq_number: remote_seq + 2,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"cdefgh",
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.recv_slice(&mut data), Ok(4));
        assert_eq!(&data, b"efgh");
    }

    #[test]
    fn test_established_receive_partially_outside_window_fin() {
        let mut s = socket_established();

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();

        // Peer decides to retransmit (perhaps because the ACK was lost)
        // and also pushed data, and sent a FIN.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                control: TcpControl::Fin,
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"def");
            (3, ())
        })
        .unwrap();

        // We should accept the FIN, because even though the last packet was partially
        // outside the receive window, there is no hole after adding its data to the assembler.
        assert_eq!(s.state, State::CloseWait);
    }

    #[test]
    fn test_established_send_wrap() {
        let mut s = socket_established();
        let local_seq_start = TcpSeqNumber(i32::MAX - 1);
        s.local_seq_no = local_seq_start + 1;
        s.remote_last_seq = local_seq_start + 1;
        s.send_slice(b"abc").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: local_seq_start + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_no_ack() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
    }

    #[test]
    fn test_established_bad_ack() {
        let mut s = socket_established();
        // Already acknowledged data.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(TcpSeqNumber(LOCAL_SEQ.0 - 1)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        // Data not yet transmitted.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 10),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
    }

    #[test]
    fn test_established_bad_seq() {
        let mut s = socket_established();
        // Data outside of receive window.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);

        // Challenge ACKs are rate-limited, we don't get a second one immediately.
        send!(
            s,
            time 100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );

        // If we wait a bit, we do get a new one.
        send!(
            s,
            time 2000,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_established_fin() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::CloseWait);
        sanity!(s, socket_close_wait());
    }

    #[test]
    fn test_established_fin_after_missing() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"123456"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::Established);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6 + 6),
                window_len: 52,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::Established);
    }

    #[test]
    fn test_established_send_fin() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_rst() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_rst_no_ack() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        sanity!(s, socket_fin_wait_1());
    }

    #[test]
    fn test_established_abort() {
        let mut s = socket_established();
        s.abort();
        assert_eq!(s.state, State::Closed);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_rst_bad_seq() {
        let mut s = socket_established();
        // Inside the window but not at RCV.NXT, which is what a challenge ACK
        // answers; below the window it would now be dropped unanswered. Two
        // past RCV.NXT so that it stays wrong once the sequence advances.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 3, // Wrong seq
                ack_number: None,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );

        assert_eq!(s.state, State::Established);

        // Send something to advance seq by 1
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1, // correct seq
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        // Send wrong rst again, check that the challenge ack is correctly updated
        // The ack number must be updated even if we don't call dispatch on the socket
        // See https://github.com/smoltcp-rs/smoltcp/issues/338
        send!(
            s,
            time 2000,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 3, // Wrong seq
                ack_number: None,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2), // this has changed
                window_len: 63,
                ..RECV_TEMPL
            })
        );
    }

    // An off-centre reset does not tear the connection down, and the challenge
    // ACK tells a peer that really did lose the connection where to aim: its
    // reply to an ACK it has no connection for is a reset at that ack number,
    // which is accepted. RFC 9293 3.10.7.4.
    #[test]
    fn test_established_rst_in_window_is_challenged() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 2,
                ack_number: None,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::Established);

        send!(
            s,
            time 1000,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    // The challenge ACKs are the cost of the mitigation, so a flood of resets
    // must not turn into a flood of replies.
    #[test]
    fn test_established_rst_challenge_ack_rate_limited() {
        let mut s = socket_established();
        for (time, reply) in [
            (
                0,
                Some(TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    ..RECV_TEMPL
                }),
            ),
            (500, None),
            (999, None),
            (
                1000,
                Some(TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    ..RECV_TEMPL
                }),
            ),
        ] {
            send!(
                s,
                time time,
                TcpRepr {
                    control: TcpControl::Rst,
                    seq_number: REMOTE_SEQ + 2,
                    ack_number: None,
                    ..SEND_TEMPL
                },
                reply
            );
            assert_eq!(s.state, State::Established);
        }
    }

    // A reset outside the window is answered with nothing at all: replying
    // would tell an off-path prober which guesses are getting close.
    #[test]
    fn test_established_rst_out_of_window_is_silent() {
        let mut s = socket_established();
        // The window is the 64 octets from REMOTE_SEQ + 1; one octet below it
        // and the first octet past it are both outside.
        for seq_number in [REMOTE_SEQ, REMOTE_SEQ + 1 + 64] {
            send!(
                s,
                TcpRepr {
                    control: TcpControl::Rst,
                    seq_number,
                    ack_number: None,
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.state, State::Established);
        }

        // Silence is not the rate limiter having fired: an in-window reset
        // still draws its challenge ACK.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 63,
                ack_number: None,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::Established);
    }

    // RFC 5961 section 4: a SYN on a synchronized connection is answered with a
    // challenge ACK and changes nothing, wherever its sequence number sits.
    #[test]
    fn test_established_syn_is_challenged() {
        let mut s = socket_established();
        // A rebooted peer redials the same 4-tuple with a fresh ISN, which
        // lands nowhere near our window and carries no acknowledgement.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ + 40000,
                ack_number: None,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::Established);

        // And one that passes both checks, which used to reach the state
        // machine and die there as an "unexpected packet".
        send!(
            s,
            time 1000,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::Established);
    }

    // Same budget as every other challenge: a SYN flood must not turn into a
    // reply flood.
    #[test]
    fn test_established_syn_challenge_ack_rate_limited() {
        let mut s = socket_established();
        for (time, reply) in [
            (
                0,
                Some(TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    ..RECV_TEMPL
                }),
            ),
            (500, None),
            (999, None),
            (
                1000,
                Some(TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    ..RECV_TEMPL
                }),
            ),
        ] {
            send!(
                s,
                time time,
                TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: REMOTE_SEQ + 40000,
                    ack_number: None,
                    ..SEND_TEMPL
                },
                reply
            );
            assert_eq!(s.state, State::Established);
        }
    }

    // The whole point of the challenge: a peer that rebooted gets its port
    // back, instead of being stranded behind our half of a dead connection.
    #[test]
    fn test_established_syn_recovers_a_rebooted_peer() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ + 40000,
                ack_number: None,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );

        // The peer is in SYN-SENT, so an ACK of a connection it has forgotten
        // draws a reset seeded with that acknowledgement -- which is our
        // RCV.NXT, the one sequence number a reset is accepted at.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);

        // Its next SYN then finds the port free.
        s.listen(LOCAL_PORT).unwrap();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ + 40001,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynReceived);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 40002),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
    }

    // =========================================================================================//
    // Tests for the FIN-WAIT-1 state.
    // =========================================================================================//

    #[test]
    fn test_fin_wait_1_fin_ack() {
        let mut s = socket_fin_wait_1();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        sanity!(s, socket_fin_wait_2());
    }

    #[test]
    fn test_fin_wait_1_fin_fin() {
        let mut s = socket_fin_wait_1();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);
        sanity!(s, socket_closing());
    }

    #[test]
    fn test_fin_wait_1_fin_with_data_queued() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef123456").unwrap();
        s.close();
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait1);
    }

    #[test]
    fn test_fin_wait_1_recv() {
        let mut s = socket_fin_wait_1();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait1);
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
    }

    #[test]
    fn test_fin_wait_1_close() {
        let mut s = socket_fin_wait_1();
        s.close();
        assert_eq!(s.state, State::FinWait1);
    }

    // =========================================================================================//
    // Tests for the FIN-WAIT-2 state.
    // =========================================================================================//

    #[test]
    fn test_fin_wait_2_fin() {
        let mut s = socket_fin_wait_2();
        send!(s, time 1_000, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::TimeWait);
        sanity!(s, socket_time_wait(false));
    }

    #[test]
    fn test_fin_wait_2_recv() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_fin_wait_2_close() {
        let mut s = socket_fin_wait_2();
        s.close();
        assert_eq!(s.state, State::FinWait2);
    }

    // =========================================================================================//
    // Tests for the CLOSING state.
    // =========================================================================================//

    #[test]
    fn test_closing_ack_fin() {
        let mut s = socket_closing();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(s, time 1_000, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::TimeWait);
        sanity!(s, socket_time_wait(true));
    }

    #[test]
    fn test_closing_close() {
        let mut s = socket_closing();
        s.close();
        assert_eq!(s.state, State::Closing);
    }

    // =========================================================================================//
    // Tests for the TIME-WAIT state.
    // =========================================================================================//

    #[test]
    fn test_time_wait_from_fin_wait_2_ack() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_time_wait_from_closing_no_ack() {
        let mut s = socket_time_wait(true);
        recv!(s, []);
    }

    #[test]
    fn test_time_wait_close() {
        let mut s = socket_time_wait(false);
        s.close();
        assert_eq!(s.state, State::TimeWait);
    }

    #[test]
    fn test_time_wait_retransmit() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(s, time 5_000, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(
            s.timer,
            Timer::Close {
                expires_at: Instant::from_secs(5) + CLOSE_DELAY
            }
        );
    }

    // TIME-WAIT is a synchronized state as well. An out-of-window reset used to
    // reach the acceptability test, which restarts the 2MSL timer on its way to
    // a challenge ACK; dropping it earlier means a stream of stray resets can
    // no longer hold the socket in TIME-WAIT.
    #[test]
    fn test_time_wait_rst_out_of_window_is_silent() {
        let mut s = socket_time_wait(false);
        let timer = s.timer;
        send!(
            s,
            time 5_000,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        assert_eq!(s.timer, timer);

        send!(
            s,
            time 5_000,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    // TIME-WAIT is one of the synchronized states, and the peer redialling
    // through it is the case RFC 9293 names outright. The challenge does not
    // extend the wait the way an out-of-window segment does, so a stranger's
    // SYNs cannot hold the tuple down.
    #[test]
    fn test_time_wait_syn_is_challenged() {
        let mut s = socket_time_wait(false);
        let timer = s.timer;
        send!(
            s,
            time 5_000,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ + 40000,
                ack_number: None,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::TimeWait);
        assert_eq!(s.timer, timer);
    }

    #[test]
    fn test_time_wait_timeout() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::TimeWait);
        recv_nothing!(s, time 60_000);
        assert_eq!(s.state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the CLOSE-WAIT state.
    // =========================================================================================//

    #[test]
    fn test_close_wait_ack() {
        let mut s = socket_close_wait();
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
    }

    #[test]
    fn test_close_wait_close() {
        let mut s = socket_close_wait();
        s.close();
        assert_eq!(s.state, State::LastAck);
        sanity!(s, socket_last_ack());
    }

    // =========================================================================================//
    // Tests for the LAST-ACK state.
    // =========================================================================================//
    #[test]
    fn test_last_ack_fin_ack() {
        let mut s = socket_last_ack();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::LastAck);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_last_ack_ack_not_of_fin() {
        let mut s = socket_last_ack();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::LastAck);

        // A duplicate ACK (ack_number == SND.UNA, not the FIN ACK) must elicit a
        // challenge ACK per RFC 9293 §3.10.7.4 and must keep the state in LAST-ACK.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::LastAck);

        // ACK received of fin: socket should change to Closed.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    // RFC 9293 §3.10.7.4: duplicate ACK in LAST-ACK must elicit a challenge ACK,
    // not be silently dropped.
    #[test]
    fn test_last_ack_duplicate_ack_challenge_ack() {
        let mut s = socket_last_ack();
        // Trigger dispatch so our FIN is sent and remote_last_seq advances.
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::LastAck);

        // Remote re-sends an ACK for SND.UNA (not the FIN).  RFC 9293 requires a
        // challenge ACK in response so the remote can learn the current state.
        let challenge = send(
            &mut s,
            Instant::from_millis(0),
            &TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
        );
        assert_eq!(
            challenge,
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }),
            "expected challenge ACK in response to duplicate ACK in LAST-ACK"
        );
        // State must remain LAST-ACK: we have not received the FIN ACK.
        assert_eq!(s.state, State::LastAck);

        // A second duplicate in the same second is rate-limited; the FIN ACK
        // must still be correctly accepted regardless.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    // A partial ACK in LAST-ACK (ack_len > 0 but not FIN ACK) advances SND.UNA
    // without a challenge ACK; the FIN will be retransmitted by the timer.
    #[test]
    fn test_last_ack_partial_ack_no_challenge_ack() {
        // Build a LAST-ACK socket that has one byte of data still unacknowledged
        // before the FIN.  We manually wire the state so we can send a partial ACK.
        let mut s = socket_last_ack();
        // Push one byte into the tx buffer to simulate data that preceded the FIN.
        let _ = s.tx_buffer.enqueue_slice(b"x");
        // Mark it as already sent (remote_last_seq is past the data byte and the FIN).
        s.remote_last_seq = LOCAL_SEQ + 1 + 1 + 1; // data(1) + FIN(1)

        // Remote ACKs just the data byte, not the FIN (partial ACK).
        // ack_number = local_seq_no + 1  =>  ack_len = 1, ack_of_fin = false.
        // Per RFC 9293, a valid partial ACK should advance SND.UNA normally;
        // no challenge ACK should be emitted.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1), // acks the data byte, not FIN
                ..SEND_TEMPL
            }
        );
        // State remains LAST-ACK; FIN retransmission is handled by the timer.
        assert_eq!(s.state, State::LastAck);
        // SND.UNA has advanced to the partial ACK number.
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1 + 1);
    }

    #[test]
    fn test_last_ack_close() {
        let mut s = socket_last_ack();
        s.close();
        assert_eq!(s.state, State::LastAck);
    }

    // =========================================================================================//
    // Tests for transitioning through multiple states.
    // =========================================================================================//

    #[test]
    fn test_listen() {
        let mut s = socket();
        s.listen(LISTEN_END).unwrap();
        assert_eq!(s.state, State::Listen);
    }

    #[test]
    fn test_three_way_handshake() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_remote_close() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        s.close();
        assert_eq!(s.state, State::LastAck);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_local_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_simultaneous_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                // due to reordering, this is logically located...
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        // ... at this point
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_simultaneous_close_combined_fin_ack() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_simultaneous_close_raced() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);

        // Socket receives FIN before it has a chance to send its own FIN
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);

        // FIN + ack-of-FIN
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::Closing);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_simultaneous_close_raced_with_data() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        assert_eq!(s.state, State::FinWait1);

        // Socket receives FIN before it has a chance to send its own data+FIN
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);

        // data + FIN + ack-of-FIN
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::Closing);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_fin_with_data() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        )
    }

    #[test]
    fn test_mutual_close_with_data_1() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
    }

    #[test]
    fn test_mutual_close_with_data_2() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::TimeWait);
    }

    // =========================================================================================//
    // Tests for retransmission on packet loss.
    // =========================================================================================//

    #[test]
    fn test_duplicate_seq_ack() {
        let mut s = socket_recved();
        // remote retransmission
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_data_retransmit() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 1050);
        recv!(s, time 2000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_data_retransmit_bursts() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef012345").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        recv_nothing!(s, time 0);

        recv_nothing!(s, time 50);

        recv!(s, time 1000, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 1500, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        recv_nothing!(s, time 1550);
    }

    #[test]
    fn test_data_retransmit_bursts_half_ack() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef012345").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        // Acknowledge the first packet
        send!(s, time 5, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        // The second packet should be re-sent.
        recv!(s, time 1500, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);

        recv_nothing!(s, time 1550);
    }

    #[test]
    fn test_retransmit_timer_restart_on_partial_ack() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef012345").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        // Acknowledge the first packet
        send!(s, time 600, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        // The ACK of the first packet should restart the retransmit timer and delay a retransmission.
        recv_nothing!(s, time 2399);
        // The second packet should be re-sent.
        recv!(s, time 2400, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
    }

    #[test]
    fn test_data_retransmit_bursts_half_ack_close() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef012345").unwrap();
        s.close();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        // Acknowledge the first packet
        send!(s, time 5, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        // The second packet should be re-sent.
        recv!(s, time 1500, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);

        recv_nothing!(s, time 1550);
    }

    #[test]
    fn test_send_data_after_syn_ack_retransmit() {
        let mut s = socket_syn_received();
        recv!(s, time 50, Ok(TcpRepr {
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }));
        recv!(s, time 1050, Ok(TcpRepr { // retransmit
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        )
    }

    #[test]
    fn test_established_retransmit_for_dup_ack() {
        let mut s = socket_established();
        // Duplicate ACKs do not replace the retransmission timer
        s.send_slice(b"abc").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
        // Retransmit timer is on because all data was sent
        assert_eq!(s.tx_buffer.len(), 3);
        // ACK nothing new
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Retransmit
        recv!(s, time 4000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_retransmit_reset_after_ack() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_queue_during_retransmission() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef123456ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        })); // this one is dropped
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        })); // this one is received
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        })); // also dropped
        recv!(s, time 3000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        })); // retransmission
        send!(s, time 3005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            ..SEND_TEMPL
        }); // acknowledgement of both segments
        recv!(s, time 3010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        })); // retransmission of only unacknowledged data
    }

    #[test]
    fn test_close_wait_retransmit_reset_after_ack() {
        let mut s = socket_close_wait();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_fin_wait_1_retransmit_reset_after_ack() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        s.close();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_fast_retransmit_after_triple_duplicate_ack() {
        let mut s = socket_established();
        s.remote_mss = 6;

        // Normal ACK of previously received segment
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // Send a long string of text divided into several packets
        // because of previously received "window_len"
        s.send_slice(b"xxxxxxyyyyyywwwwwwzzzzzz").unwrap();
        // This packet is lost
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"xxxxxx"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"yyyyyy"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 2),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"wwwwww"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1015, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 3),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"zzzzzz"[..],
            ..RECV_TEMPL
        }));

        // First duplicate ACK
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Second duplicate ACK
        send!(s, time 1055, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Third duplicate ACK
        // Should trigger a fast retransmit of dropped packet
        send!(s, time 1060, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // Fast retransmit packet
        recv!(s, time 1100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"xxxxxx"[..],
            ..RECV_TEMPL
        }));

        recv!(s, time 1105, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"yyyyyy"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1110, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 2),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"wwwwww"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1115, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 3),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"zzzzzz"[..],
            ..RECV_TEMPL
        }));

        // After all was send out, enter *normal* retransmission,
        // don't stay in fast retransmission.
        assert!(match s.timer {
            Timer::Retransmit { expires_at, .. } => expires_at > Instant::from_millis(1115),
            _ => false,
        });

        // ACK all received segments
        send!(s, time 1120, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (6 * 4)),
            ..SEND_TEMPL
        });
    }

    #[test]
    fn test_fast_retransmit_duplicate_detection_with_data() {
        let mut s = socket_established();

        s.send_slice(b"abc").unwrap(); // This is lost
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        // Normal ACK of previously received segment
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // First duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Second duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );

        assert_eq!(s.local_rx_dup_acks, 2, "duplicate ACK counter is not set");

        // This packet has content, hence should not be detected
        // as a duplicate ACK and should reset the duplicate ACK count
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"xxxxxx"[..],
                ..SEND_TEMPL
            }
        );

        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 3,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is not reset when receiving data"
        );
    }

    #[test]
    fn test_fast_retransmit_duplicate_detection_with_window_update() {
        let mut s = socket_established();

        s.send_slice(b"abc").unwrap(); // This is lost
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        // Normal ACK of previously received segment
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // First duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Second duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );

        assert_eq!(s.local_rx_dup_acks, 2, "duplicate ACK counter is not set");

        // This packet has a window update, hence should not be detected
        // as a duplicate ACK and should reset the duplicate ACK count
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 400,
                ..SEND_TEMPL
            }
        );

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is not reset when receiving a window update"
        );
    }

    #[test]
    fn test_fast_retransmit_duplicate_detection() {
        let mut s = socket_established();
        s.remote_mss = 6;

        // Normal ACK of previously received segment
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // First duplicate, should not be counted as there is nothing to resend
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is set but wound not transmit data"
        );

        // Send a long string of text divided into several packets
        // because of small remote_mss
        s.send_slice(b"xxxxxxyyyyyywwwwwwzzzzzz").unwrap();

        // This packet is reordered in network
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"xxxxxx"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"yyyyyy"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 2),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"wwwwww"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1015, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 3),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"zzzzzz"[..],
            ..RECV_TEMPL
        }));

        // First duplicate ACK
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Second duplicate ACK
        send!(s, time 1055, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Reordered packet arrives which should reset duplicate ACK count
        send!(s, time 1060, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (6 * 3)),
            ..SEND_TEMPL
        });

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is not reset when receiving ACK which updates send window"
        );

        // ACK all received segments
        send!(s, time 1120, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (6 * 4)),
            ..SEND_TEMPL
        });
    }

    #[test]
    fn test_fast_retransmit_dup_acks_counter() {
        let mut s = socket_established();

        s.send_slice(b"abc").unwrap(); // This is lost
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // A lot of retransmits happen here
        s.local_rx_dup_acks = u8::MAX - 1;

        // Send 3 more ACKs, which could overflow local_rx_dup_acks,
        // but intended behaviour is that we saturate the bounds
        // of local_rx_dup_acks
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(
            s.local_rx_dup_acks,
            u8::MAX,
            "duplicate ACK count should not overflow but saturate"
        );
    }

    #[test]
    fn test_fast_retransmit_zero_window() {
        let mut s = socket_established();

        send!(s, time 1000, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        s.send_slice(b"abc").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        // 3 dup acks
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0, // boom
            ..SEND_TEMPL
        });

        // even though we're in "fast retransmit", we shouldn't
        // force-send anything because the remote's window is full.
        recv_nothing!(s);
    }

    #[test]
    fn test_retransmit_exponential_backoff() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));

        let expected_retransmission_instant = s.rtte.retransmission_timeout().total_millis() as i64;
        recv_nothing!(s, time expected_retransmission_instant - 1);
        recv!(s, time expected_retransmission_instant, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));

        // "current time" is expected_retransmission_instant, and we want to wait 2 * retransmission timeout
        let expected_retransmission_instant = 3 * expected_retransmission_instant;

        recv_nothing!(s, time expected_retransmission_instant - 1);
        recv!(s, time expected_retransmission_instant, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_data_retransmit_ack_more_than_expected() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"aaaaaabbbbbbcccccc").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"aaaaaa"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"bbbbbb"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 12,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"cccccc"[..],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 0);

        recv_nothing!(s, time 50);

        // retransmit timer expires, we want to retransmit all 3 packets
        // but we only manage to retransmit 2 (due to e.g. lack of device buffer space)
        assert!(s.timer.is_retransmit());
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"aaaaaa"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"bbbbbb"[..],
            ..RECV_TEMPL
        }));

        // ack first packet.
        send!(
            s,
            time 3000,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );

        // this should keep retransmit timer on, because there's
        // still unacked data.
        assert!(s.timer.is_retransmit());

        // ack all three packets.
        // This might confuse the TCP stack because after the retransmit
        // it "thinks" the 3rd packet hasn't been transmitted yet, but it is getting acked.
        send!(
            s,
            time 3000,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 18),
                ..SEND_TEMPL
            }
        );

        // this should exit retransmit mode.
        assert!(!s.timer.is_retransmit());
        // and consider all data ACKed.
        assert!(s.tx_buffer.is_empty());
        recv_nothing!(s, time 5000);
    }

    #[test]
    fn test_retransmit_fin() {
        let mut s = socket_established();
        s.close();
        recv!(s, time 0, Ok(TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));

        recv_nothing!(s, time 999);
        recv!(s, time 1000, Ok(TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_retransmit_fin_wait() {
        let mut s = socket_fin_wait_1();
        // we send FIN
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        // remote also sends FIN, does NOT ack ours.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // we ack it
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::None,
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }]
        );

        // we haven't got an ACK for our FIN, we should retransmit.
        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s, time 2999);
        recv!(
            s,
            time 3000,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }]
        );
    }

    // =========================================================================================//
    // Tests for window management.
    // =========================================================================================//

    #[test]
    fn test_maximum_segment_size() {
        let mut s = socket_listen();
        s.tx_buffer = SocketBuffer::new(vec![0; 32767]);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(1000),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 32767,
                ..SEND_TEMPL
            }
        );
        s.send_slice(&[0; 1200][..]).unwrap();
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &[0; 1000][..],
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_recv_out_of_recv_win() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        s.remote_mss = 32;

        // No ACKs are sent due to the ACK delay.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Psh,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; 32],
                ..SEND_TEMPL
            }
        );
        recv_nothing!(s);

        // RMSS+1 bytes of data has been received, so ACK is sent without delay.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Psh,
                seq_number: REMOTE_SEQ + 33,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; 1],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 34),
                window_len: 31,
                ..RECV_TEMPL
            })
        );

        // This frees up a byte in the receive buffer. However, the remote shouldn't be aware of
        // this since no ACKs are sent.
        s.recv_slice(&mut [0; 1]).unwrap();
        recv_nothing!(s);

        // Now, if the remote wants to send one byte outside of the receive window that we
        // previously advertised, it should not succeed.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Psh,
                seq_number: REMOTE_SEQ + 34,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; 32],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 65),
                window_len: 1, // The last byte isn't accepted.
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_close_wait_no_window_update() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[1, 2, 3, 4],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);

        // we ack the FIN, with the reduced window size.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 6),
                window_len: 60,
                ..RECV_TEMPL
            })
        );

        let rx_buf = &mut [0; 32];
        assert_eq!(s.recv_slice(rx_buf), Ok(4));

        // check that we do NOT send a window update even if it has changed.
        recv_nothing!(s);
    }

    #[test]
    fn test_time_wait_no_window_update() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                payload: &[1, 2, 3, 4],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);

        // we ack the FIN, with the reduced window size.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 6),
                window_len: 60,
                ..RECV_TEMPL
            })
        );

        let rx_buf = &mut [0; 32];
        assert_eq!(s.recv_slice(rx_buf), Ok(4));

        // check that we do NOT send a window update even if it has changed.
        recv_nothing!(s);
    }

    // =========================================================================================//
    // Tests for flow control.
    // =========================================================================================//

    #[test]
    fn test_psh_transmit() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }), exact);
    }

    #[test]
    fn test_psh_receive() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Psh,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_ack() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"123456"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_zero_window_fin() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new();
        s.ack_delay = None;

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );

        // Even though the sequence space for the FIN itself is outside the window,
        // it is not data, so FIN must be accepted when window full.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[],
                control: TcpControl::Fin,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);

        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 7),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_ack_on_window_growth() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s, time 0);
        s.recv(|buffer| {
            assert_eq!(&buffer[..3], b"abc");
            (3, ())
        })
        .unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 3,
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 0);
        s.recv(|buffer| {
            assert_eq!(buffer, b"def");
            (buffer.len(), ())
        })
        .unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 6,
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_window_update_with_delay_ack() {
        let mut s = socket_established_with_buffer_sizes(6, 6);
        s.ack_delay = Some(Duration::from_millis(10));

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 5);

        s.recv(|buffer| {
            assert_eq!(&buffer[..2], b"ab");
            (2, ())
        })
        .unwrap();
        recv!(
            s,
            time 5,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 2,
                ..RECV_TEMPL
            })
        );

        s.recv(|buffer| {
            assert_eq!(&buffer[..1], b"c");
            (1, ())
        })
        .unwrap();
        recv_nothing!(s, time 5);

        s.recv(|buffer| {
            assert_eq!(&buffer[..1], b"d");
            (1, ())
        })
        .unwrap();
        recv!(
            s,
            time 5,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 4,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_fill_peer_window() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        recv!(
            s,
            [
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"abcdef"[..],
                    ..RECV_TEMPL
                },
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + 6,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"123456"[..],
                    ..RECV_TEMPL
                },
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + 6 + 6,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"!@#$%^"[..],
                    ..RECV_TEMPL
                }
            ]
        );
    }

    #[test]
    fn test_announce_window_after_read() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 3,
                ..RECV_TEMPL
            }]
        );
        // Test that `dispatch` updates `remote_last_win`
        assert_eq!(s.remote_last_win, s.rx_buffer.window() as u32);
        s.recv(|buffer| (buffer.len(), ())).unwrap();
        assert!(s.window_to_update());
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 6,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.remote_last_win, s.rx_buffer.window() as u32);
        // Provoke immediate ACK to test that `process` updates `remote_last_win`
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"def"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 6,
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 9),
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.remote_last_win, s.rx_buffer.window() as u32);
        s.recv(|buffer| (buffer.len(), ())).unwrap();
        assert!(s.window_to_update());
    }

    // =========================================================================================//
    // Tests for zero-window probes.
    // =========================================================================================//

    #[test]
    fn test_zero_window_probe_enter_on_win_update() {
        let mut s = socket_established();

        assert!(!s.timer.is_zero_window_probe());

        s.send_slice(b"abcdef123456!@#$%^").unwrap();

        assert!(!s.timer.is_zero_window_probe());

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        assert!(s.timer.is_zero_window_probe());
    }

    #[test]
    fn test_zero_window_probe_enter_on_send() {
        let mut s = socket_established();

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        assert!(!s.timer.is_zero_window_probe());

        s.send_slice(b"abcdef123456!@#$%^").unwrap();

        assert!(s.timer.is_zero_window_probe());
    }

    #[test]
    fn test_zero_window_probe_exit() {
        let mut s = socket_established();

        s.send_slice(b"abcdef123456!@#$%^").unwrap();

        assert!(!s.timer.is_zero_window_probe());

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        assert!(s.timer.is_zero_window_probe());

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 6,
                ..SEND_TEMPL
            }
        );

        assert!(!s.timer.is_zero_window_probe());
    }

    #[test]
    fn test_zero_window_probe_exit_ack() {
        let mut s = socket_established();

        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );

        send!(
            s,
            time 1010,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                window_len: 6,
                ..SEND_TEMPL
            }
        );

        recv!(
            s,
            time 1010,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"bcdef1"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_probe_backoff_nack_reply() {
        let mut s = socket_established();
        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            time 1100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 2999);
        recv!(
            s,
            time 3000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            time 3100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 6999);
        recv!(
            s,
            time 7000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_probe_backoff_no_reply() {
        let mut s = socket_established();
        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );

        recv_nothing!(s, time 2999);
        recv!(
            s,
            time 3000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_probe_shift() {
        let mut s = socket_established();

        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );

        recv_nothing!(s, time 2999);
        recv!(
            s,
            time 3000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );

        // ack the ZWP byte, but still advertise zero window.
        // this should restart the ZWP timer.
        send!(
            s,
            time 3100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        // ZWP should be sent at 3100+1000 = 4100
        recv_nothing!(s, time 4099);
        recv!(
            s,
            time 4100,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"b"[..],
                ..RECV_TEMPL
            }]
        );
    }

    // =========================================================================================//
    // Tests for timeouts.
    // =========================================================================================//

    #[test]
    fn test_listen_timeout() {
        let mut s = socket_listen();
        s.set_timeout(Some(Duration::from_millis(100)));
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Ingress);
    }

    #[test]
    fn test_connect_timeout() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        s.set_timeout(Some(Duration::from_millis(100)));
        recv!(s, time 150, Ok(TcpRepr {
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            sack_permitted: true,
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::SynSent);
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(250))
        );
        recv!(s, time 250, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(TcpSeqNumber(0)),
            window_scale: None,
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_timeout() {
        let mut s = socket_established();
        s.set_timeout(Some(Duration::from_millis(2000)));
        recv_nothing!(s, time 250);
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(2250))
        );
        s.send_slice(b"abcdef").unwrap();
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);
        recv!(s, time 255, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(1255))
        );
        recv!(s, time 1255, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(2255))
        );
        recv!(s, time 2255, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_keep_alive_timeout() {
        let mut s = socket_established();
        s.set_keep_alive(Some(Duration::from_millis(50)));
        s.set_timeout(Some(Duration::from_millis(100)));
        recv!(s, time 100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 100);
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(150))
        );
        send!(s, time 105, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(155))
        );
        recv!(s, time 155, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 155);
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(205))
        );
        recv_nothing!(s, time 200);
        recv!(s, time 205, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 205);
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_fin_wait_1_timeout() {
        let mut s = socket_fin_wait_1();
        s.set_timeout(Some(Duration::from_millis(1000)));
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        recv!(s, time 1100, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_last_ack_timeout() {
        let mut s = socket_last_ack();
        s.set_timeout(Some(Duration::from_millis(1000)));
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }));
        recv!(s, time 1100, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_closed_timeout() {
        let mut s = socket_established();
        s.set_timeout(Some(Duration::from_millis(200)));
        s.remote_last_ts = Some(Instant::from_millis(100));
        s.abort();
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Ingress);
    }

    // =========================================================================================//
    // Tests for keep-alive.
    // =========================================================================================//

    #[test]
    fn test_responds_to_keep_alive() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_sends_keep_alive() {
        let mut s = socket_established();
        s.set_keep_alive(Some(Duration::from_millis(100)));

        // drain the forced keep-alive packet
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(100))
        );
        recv_nothing!(s, time 95);
        recv!(s, time 100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(200))
        );
        recv_nothing!(s, time 195);
        recv!(s, time 200, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        send!(s, time 250, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(350))
        );
        recv_nothing!(s, time 345);
        recv!(s, time 350, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"\x00"[..],
            ..RECV_TEMPL
        }));
    }

    // =========================================================================================//
    // Tests for time-to-live configuration.
    // =========================================================================================//

    #[test]
    fn test_set_hop_limit() {
        let mut s = socket_syn_received();

        s.set_hop_limit(Some(0x2a));
        assert_eq!(
            s.socket.dispatch(&mut s.cx, |_, _meta, (ip_repr, _)| {
                assert_eq!(ip_repr.hop_limit(), 0x2a);
                Ok::<_, ()>(())
            }),
            Ok(())
        );

        // assert that user-configurable settings are kept,
        // see https://github.com/smoltcp-rs/smoltcp/issues/601.
        s.reset();
        assert_eq!(s.hop_limit(), Some(0x2a));
    }

    #[test]
    #[should_panic(expected = "the time-to-live value of a packet must not be zero")]
    fn test_set_hop_limit_zero() {
        let mut s = socket_syn_received();
        s.set_hop_limit(Some(0));
    }

    // =========================================================================================//
    // Tests for reassembly.
    // =========================================================================================//

    #[test]
    fn test_out_of_order() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"def"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        s.recv(|buffer| {
            assert_eq!(buffer, b"");
            (buffer.len(), ())
        })
        .unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            })
        );
        s.recv(|buffer| {
            assert_eq!(buffer, b"abcdef");
            (buffer.len(), ())
        })
        .unwrap();
    }

    #[test]
    fn test_the_assembler_absorbs_a_multi_loss_window() {
        // Twelve holes in one window, which a burst drop produces easily: a
        // 128 KiB window is about ninety segments, so this is a few percent
        // loss. Deliberately a literal and not
        // `config::ASSEMBLER_MAX_SEGMENT_COUNT` -- the point is the number, and
        // reading the constant back would pass at any capacity including the
        // four this replaced.
        const LOSSES: usize = 12;
        const SEG: usize = 100;

        let mut s = socket_established_with_buffer_sizes(64, 4096);
        let remote_seq = REMOTE_SEQ + 1;
        let payload = [b'x'; SEG];

        // Every other segment arrives; the gaps are the losses.
        for index in 1..=LOSSES {
            assert!(
                send(
                    &mut s,
                    Instant::ZERO,
                    &TcpRepr {
                        seq_number: remote_seq + (2 * index - 1) * SEG,
                        ack_number: Some(LOCAL_SEQ + 1),
                        payload: &payload,
                        ..SEND_TEMPL
                    },
                )
                .is_some(),
                "out-of-order segment {index} drew no ACK, so it was dropped: \
                 the assembler ran out of holes. A sender learns of loss from \
                 these duplicate ACKs, and without them waits out its RTO."
            );
        }

        // And the data is really held, not merely acknowledged: filling the
        // first gap releases exactly the two segments that are now contiguous.
        let _ = send(
            &mut s,
            Instant::ZERO,
            &TcpRepr {
                seq_number: remote_seq,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &payload,
                ..SEND_TEMPL
            },
        );
        assert_eq!(s.rx_buffer.len(), 2 * SEG);
    }

    #[test]
    fn test_out_of_order_overflow_preserves_state() {
        let count = crate::config::ASSEMBLER_MAX_SEGMENT_COUNT;
        let mut s = socket_established_with_buffer_sizes(64, (count + 2) * 10);
        let remote_seq = REMOTE_SEQ + 1;

        for offset in (1..=count).map(|index| index * 10) {
            let _ = send(
                &mut s,
                Instant::ZERO,
                &TcpRepr {
                    seq_number: remote_seq + offset,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: b"x",
                    ..SEND_TEMPL
                },
            );
        }

        let assembler = s.assembler.clone();
        assert_eq!(
            send(
                &mut s,
                Instant::ZERO,
                &TcpRepr {
                    seq_number: remote_seq + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: b"x",
                    ..SEND_TEMPL
                },
            ),
            None
        );
        assert_eq!(s.assembler, assembler);
        assert_eq!(s.state, State::Established);

        // The next expected segment must still be accepted even with every
        // assembler slot occupied, or the connection can never recover.
        let _ = send(
            &mut s,
            Instant::ZERO,
            &TcpRepr {
                seq_number: remote_seq,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"a",
                ..SEND_TEMPL
            },
        );
        let mut data = [0];
        assert_eq!(s.recv_slice(&mut data), Ok(1));
        assert_eq!(&data, b"a");
    }

    #[test]
    fn test_buffer_wraparound_rx() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        s.recv(|buffer| {
            assert_eq!(buffer, b"abc");
            (buffer.len(), ())
        })
        .unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"defghi"[..],
                ..SEND_TEMPL
            }
        );
        let mut data = [0; 6];
        assert_eq!(s.recv_slice(&mut data[..]), Ok(6));
        assert_eq!(data, &b"defghi"[..]);
    }

    #[test]
    fn test_buffer_wraparound_tx() {
        let mut s = socket_established();
        s.set_nagle_enabled(false);

        s.tx_buffer = SocketBuffer::new(vec![b'.'; 9]);
        assert_eq!(s.send_slice(b"xxxyyy"), Ok(6));
        assert_eq!(s.tx_buffer.dequeue_many(3), &b"xxx"[..]);
        assert_eq!(s.tx_buffer.len(), 3);

        // "abcdef" not contiguous in tx buffer
        assert_eq!(s.send_slice(b"abcdef"), Ok(6));
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"yyyabc"[..],
                ..RECV_TEMPL
            })
        );
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"def"[..],
                ..RECV_TEMPL
            })
        );
    }

    // =========================================================================================//
    // Tests for graceful vs ungraceful rx close
    // =========================================================================================//

    #[test]
    fn test_rx_close_fin() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::Finished));
    }

    #[test]
    fn test_rx_close_fin_in_fin_wait_1() {
        let mut s = socket_fin_wait_1();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::Finished));
    }

    #[test]
    fn test_rx_close_fin_in_fin_wait_2() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::Finished));
    }

    #[test]
    fn test_rx_close_fin_with_hole() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"ghi"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 61,
                ..RECV_TEMPL
            })
        );
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        s.recv(|data| {
            assert_eq!(data, b"");
            (0, ())
        })
        .unwrap();
        // At RCV.NXT, which is where an accepted reset has to sit; the hole
        // above it is still there, which is what this test is about.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Error must be `Illegal` even if we've received a FIN,
        // because we are missing data.
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::InvalidState));
    }

    #[test]
    fn test_rx_close_rst() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::InvalidState));
    }

    #[test]
    fn test_rx_close_rst_with_hole() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"ghi"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 61,
                ..RECV_TEMPL
            })
        );
        // At RCV.NXT, which is where an accepted reset has to sit; the hole
        // above it is still there, which is what this test is about.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::InvalidState));
    }

    // =========================================================================================//
    // Tests for delayed ACK
    // =========================================================================================//

    #[test]
    fn test_delayed_ack() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        // After 10ms, it is sent.
        recv!(s, time 11, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            window_len: 61,
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_delayed_ack_win() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        // Reading the data off the buffer should cause a window update.
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();

        // However, no ACK or window update is immediately sent.
        recv_nothing!(s);

        // After 10ms, it is sent.
        recv!(s, time 11, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_delayed_ack_reply() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();

        s.send_slice(&b"xyz"[..]).unwrap();

        // Writing data to the socket causes ACK to not be delayed,
        // because it is immediately sent with the data.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                payload: &b"xyz"[..],
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_delayed_ack_every_rmss() {
        let mut s = socket_established_with_buffer_sizes(DEFAULT_MSS * 2, DEFAULT_MSS * 2);
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; DEFAULT_MSS - 1],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + (DEFAULT_MSS - 1),
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + DEFAULT_MSS,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        // RMSS+1 bytes of data has been received, so ACK is sent without delay.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + (DEFAULT_MSS + 1)),
                window_len: (DEFAULT_MSS - 1) as u16,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_delayed_ack_every_rmss_or_more() {
        let mut s = socket_established_with_buffer_sizes(DEFAULT_MSS * 2, DEFAULT_MSS * 2);
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; DEFAULT_MSS],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + DEFAULT_MSS,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + (DEFAULT_MSS + 1),
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"b"[..],
                ..SEND_TEMPL
            }
        );

        // RMSS+2 bytes of data has been received, so ACK is sent without delay.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + (DEFAULT_MSS + 2)),
                window_len: (DEFAULT_MSS - 2) as u16,
                ..RECV_TEMPL
            })
        );
    }

    // =========================================================================================//
    // Tests for Nagle's Algorithm
    // =========================================================================================//

    #[test]
    fn test_nagle() {
        let mut s = socket_established();
        s.remote_mss = 6;

        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );

        // If there's data in flight, full segments get sent.
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                ..RECV_TEMPL
            }]
        );

        s.send_slice(b"aaabbbccc").unwrap();
        // If there's data in flight, not-full segments don't get sent.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"aaabbb"[..],
                ..RECV_TEMPL
            }]
        );

        // Data gets ACKd, so there's no longer data in flight
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 6 + 6),
                ..SEND_TEMPL
            }
        );

        // Now non-full segment gets sent.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6 + 6 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"ccc"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_final_packet_in_stream_doesnt_wait_for_nagle() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef0").unwrap();
        s.socket.close();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"0"[..],
            ..RECV_TEMPL
        }), exact);
    }

    // =========================================================================================//
    // Tests for packet filtering.
    // =========================================================================================//

    #[test]
    fn test_doesnt_accept_wrong_port() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new();

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            dst_port: LOCAL_PORT + 1,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            src_port: REMOTE_PORT + 1,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_doesnt_accept_wrong_ip() {
        let mut s = socket_established();

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        };

        let ip_repr = IpReprIpvX(IpvXRepr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(s.socket.accepts(&mut s.cx, &ip_repr, &tcp_repr));

        let ip_repr_wrong_src = IpReprIpvX(IpvXRepr {
            src_addr: OTHER_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(!s.socket.accepts(&mut s.cx, &ip_repr_wrong_src, &tcp_repr));

        let ip_repr_wrong_dst = IpReprIpvX(IpvXRepr {
            src_addr: REMOTE_ADDR,
            dst_addr: OTHER_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(!s.socket.accepts(&mut s.cx, &ip_repr_wrong_dst, &tcp_repr));
    }

    // =========================================================================================//
    // Tests for congestion control
    // =========================================================================================//

    // Every test in here needs a controller with a real window to observe:
    // `NoControl` reports `usize::MAX` and bounds nothing.
    #[cfg(any(feature = "socket-tcp-reno", feature = "socket-tcp-cubic"))]
    mod congestion_control {
        use super::*;

        // Wide enough that the remote window is never what bounds the tests below.
        const CC_WIN_LEN: u16 = 65535;
        // Small enough to get several segments out of one send buffer, and set on
        // the socket rather than negotiated, so it never reaches the controller's
        // `set_mss` and `min_cwnd` stays at its 2048-byte default.
        const CC_MSS: usize = 1024;

        fn socket_established_for_congestion_control() -> TestSocket {
            let mut s = socket_established_with_buffer_sizes(8192, 64);
            s.remote_win_len = CC_WIN_LEN as usize;
            s.remote_mss = CC_MSS;
            s
        }

        #[test]
        fn test_congestion_window_bounds_bytes_in_flight() {
            let mut s = socket_established_for_congestion_control();
            assert_eq!(
                s.congestion_controller.inner().window(),
                2 * CC_MSS,
                "this test is written around a two-segment initial window"
            );

            s.send_slice(&[0; 8192][..]).unwrap();

            // Four times the window is queued and the remote would take all of it,
            // so the only thing that can stop the third segment is the congestion
            // window. Before it bounded the data in flight it bounded the data
            // still unsent, which the first two segments had already emptied.
            recv!(
                s,
                time 0,
                [
                    TcpRepr {
                        seq_number: LOCAL_SEQ + 1,
                        ack_number: Some(REMOTE_SEQ + 1),
                        payload: &[0; CC_MSS][..],
                        ..RECV_TEMPL
                    },
                    TcpRepr {
                        seq_number: LOCAL_SEQ + 1 + CC_MSS,
                        ack_number: Some(REMOTE_SEQ + 1),
                        payload: &[0; CC_MSS][..],
                        ..RECV_TEMPL
                    }
                ]
            );
        }

        #[test]
        fn test_congestion_window_reopens_as_data_is_acknowledged() {
            let mut s = socket_established_for_congestion_control();
            s.send_slice(&[0; 8192][..]).unwrap();
            recv!(
                s,
                time 0,
                [
                    TcpRepr {
                        seq_number: LOCAL_SEQ + 1,
                        ack_number: Some(REMOTE_SEQ + 1),
                        payload: &[0; CC_MSS][..],
                        ..RECV_TEMPL
                    },
                    TcpRepr {
                        seq_number: LOCAL_SEQ + 1 + CC_MSS,
                        ack_number: Some(REMOTE_SEQ + 1),
                        payload: &[0; CC_MSS][..],
                        ..RECV_TEMPL
                    }
                ]
            );

            // Acknowledging one segment retires it from the flight and, in slow
            // start, adds its length to the window.
            send!(s, time 10, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + CC_MSS),
                window_len: CC_WIN_LEN,
                ..SEND_TEMPL
            });
            assert_eq!(s.congestion_controller.inner().window(), 3 * CC_MSS);

            // 3072 bytes of window against 1024 still in flight: room for two more
            // segments, and then not a third.
            recv!(
                s,
                time 10,
                [
                    TcpRepr {
                        seq_number: LOCAL_SEQ + 1 + 2 * CC_MSS,
                        ack_number: Some(REMOTE_SEQ + 1),
                        payload: &[0; CC_MSS][..],
                        ..RECV_TEMPL
                    },
                    TcpRepr {
                        seq_number: LOCAL_SEQ + 1 + 3 * CC_MSS,
                        ack_number: Some(REMOTE_SEQ + 1),
                        payload: &[0; CC_MSS][..],
                        ..RECV_TEMPL
                    }
                ]
            );
        }

        // RFC 6928's initial window is `min(10*MSS, max(2*MSS, 14600))`, and the
        // MSS it is sized from arrives only in a handshake -- so a handshake is
        // the only thing that can set it, and both directions of open have to.
        // A listener learns the MSS from the SYN, a connect from the SYN|ACK.
        #[test]
        fn test_handshake_sets_the_initial_congestion_window() {
            // Each of the expression's three branches: ten segments, then the
            // 14600 cap holding a large MSS down, then the two-segment floor
            // lifting a jumbo one back over that cap. The 100-byte case is the
            // one that matters for assigning rather than taking the larger of
            // the two -- its RFC window is *below* the constructor's 2048-byte
            // placeholder, and keeping the placeholder there would be twenty
            // segments in flight before a single ACK.
            for (mss, expected) in [
                (100u16, 1_000usize),
                (1460, 14_600),
                (4000, 14_600),
                (8000, 16_000),
            ] {
                let mut s = socket_listen();
                send!(
                    s,
                    TcpRepr {
                        control: TcpControl::Syn,
                        seq_number: REMOTE_SEQ,
                        ack_number: None,
                        max_seg_size: Some(mss),
                        ..SEND_TEMPL
                    }
                );
                assert_eq!(
                    s.congestion_controller.inner().window(),
                    expected,
                    "passive open, mss {mss}"
                );
            }

            // The active open reaches it by a different path in `process`, and
            // sys-io opens connections both ways.
            let mut s = socket_syn_sent();
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: None,
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(0),
                    sack_permitted: true,
                    ..RECV_TEMPL
                }]
            );
            send!(
                s,
                TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: REMOTE_SEQ,
                    ack_number: Some(LOCAL_SEQ + 1),
                    max_seg_size: Some(1460),
                    window_scale: Some(0),
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.state, State::Established);
            assert_eq!(s.congestion_controller.inner().window(), 14_600);
        }

        // Reno's `on_duplicate_ack` only lowers `ssthresh`, which is idempotent --
        // it brings the window itself down in `on_retransmit`. Cubic's two hooks
        // are the same reduction, so Cubic is where a repeated signal compounds and
        // where the reduction is visible in the window straight away.
        #[cfg(feature = "socket-tcp-cubic")]
        #[test]
        fn test_duplicate_acks_reduce_the_window_once_per_loss() {
            let mut s = socket_established_for_congestion_control();
            s.set_congestion_control(CongestionControl::Cubic);

            // Lift the window clear of `min_cwnd`: at its default the floor absorbs
            // every reduction, and a floored window hides what this measures.
            for _ in 0..32 {
                s.congestion_controller.inner_mut().on_ack(
                    Instant::from_millis(0),
                    2048,
                    &RttEstimator::default(),
                );
            }
            let cwnd_before = s.congestion_controller.inner().window();
            assert!(cwnd_before > 32 * 1024, "cwnd_before = {cwnd_before}");

            // Something has to be in flight for an ACK to be a duplicate of it.
            s.send_slice(&[0; 8192][..]).unwrap();
            for i in 0..8 {
                recv!(s, time 0, Ok(TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + i * CC_MSS,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &[0; CC_MSS][..],
                    ..RECV_TEMPL
                }));
            }

            // Seven ACKs: the first is not a duplicate of anything -- it is what
            // gives the six after it something to repeat.
            for i in 0..7i64 {
                send!(s, time 1000 + i * 5, TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    window_len: CC_WIN_LEN,
                    ..SEND_TEMPL
                });
                // A poll runs between arriving packets on a real link, and
                // `pre_transmit` is where the controller applies a reduction it has
                // been told about. Called here rather than by dispatching, so that
                // the fast retransmit armed by the third duplicate -- itself a
                // second congestion signal -- stays out of the measurement.
                s.congestion_controller
                    .inner_mut()
                    .pre_transmit(Instant::from_millis(1000 + i * 5));
            }

            assert!(
                matches!(s.timer, Timer::FastRetransmit),
                "the third duplicate should still arm the fast retransmit"
            );

            let cwnd_after = s.congestion_controller.inner().window();
            assert!(
                cwnd_after < cwnd_before,
                "the loss should have cost something: {cwnd_before} -> {cwnd_after}"
            );
            // One reduction is `beta`, 0.7. Six of them, which is what reducing on
            // every duplicate ACK cost, is 0.12.
            assert!(
                cwnd_after * 3 >= cwnd_before * 2,
                "six duplicates compounded into more than one congestion event: \
                 {cwnd_before} -> {cwnd_after}"
            );
        }

        // The companion measurement the test above deliberately dodged:
        // dispatching the fast retransmit the third duplicate armed used to
        // charge the controller a second time (`on_retransmit`), so one loss
        // cost beta squared -- 0.49 -- instead of 0.7. The loss is one event;
        // the controller hears about it once.
        #[cfg(feature = "socket-tcp-cubic")]
        #[test]
        fn test_fast_retransmit_charges_the_controller_once() {
            let mut s = socket_established_for_congestion_control();
            s.set_congestion_control(CongestionControl::Cubic);

            for _ in 0..32 {
                s.congestion_controller.inner_mut().on_ack(
                    Instant::from_millis(0),
                    2048,
                    &RttEstimator::default(),
                );
            }
            let cwnd_before = s.congestion_controller.inner().window();
            assert!(cwnd_before > 32 * 1024, "cwnd_before = {cwnd_before}");

            s.send_slice(&[0; 8192][..]).unwrap();
            for i in 0..8 {
                recv!(s, time 0, Ok(TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + i * CC_MSS,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &[0; CC_MSS][..],
                    ..RECV_TEMPL
                }));
            }
            for i in 0..4i64 {
                send!(s, time 1000 + i * 5, TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    window_len: CC_WIN_LEN,
                    ..SEND_TEMPL
                });
            }
            assert!(matches!(s.timer, Timer::FastRetransmit));

            // Dispatch the fast retransmit (the rewind resends from the ACK
            // point), then one more segment so the post-charge `pre_transmit`
            // has run and the window reflects every charge taken.
            recv!(s, time 1100, Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &[0; CC_MSS][..],
                ..RECV_TEMPL
            }));
            recv!(s, time 1105, Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1 + CC_MSS,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &[0; CC_MSS][..],
                ..RECV_TEMPL
            }));

            let cwnd_after = s.congestion_controller.inner().window();
            assert!(
                cwnd_after < cwnd_before,
                "the loss should have cost something: {cwnd_before} -> {cwnd_after}"
            );
            assert!(
                cwnd_after * 3 >= cwnd_before * 2,
                "the fast retransmit dispatch charged a second reduction: \
                 {cwnd_before} -> {cwnd_after}"
            );
        }

        // An expired RTO is not the duplicate-ACK event's echo -- it is the
        // controller's only signal on a silent link, and skipping it there
        // would leave the window untouched by a real loss.
        #[cfg(feature = "socket-tcp-cubic")]
        #[test]
        fn test_rto_still_charges_the_controller() {
            let mut s = socket_established_for_congestion_control();
            s.set_congestion_control(CongestionControl::Cubic);

            for _ in 0..32 {
                s.congestion_controller.inner_mut().on_ack(
                    Instant::from_millis(0),
                    2048,
                    &RttEstimator::default(),
                );
            }
            let cwnd_before = s.congestion_controller.inner().window();

            s.send_slice(&[0; 1024][..]).unwrap();
            recv!(s, time 0, Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &[0; CC_MSS][..],
                ..RECV_TEMPL
            }));

            // No ACK ever arrives; the retransmission and the poll after it
            // land after the RTO, so the charge has been applied to the
            // window by the second dispatch.
            recv!(s, time 5000, Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &[0; CC_MSS][..],
                ..RECV_TEMPL
            }));
            s.congestion_controller
                .inner_mut()
                .pre_transmit(Instant::from_millis(5010));

            let cwnd_after = s.congestion_controller.inner().window();
            assert!(
                cwnd_after < cwnd_before,
                "an RTO left the window uncharged: {cwnd_before} -> {cwnd_after}"
            );
        }
    }

    // =========================================================================================//
    // Timer tests
    // =========================================================================================//

    #[test]
    fn test_timer_retransmit() {
        const RTO: Duration = Duration::from_millis(100);
        let mut r = Timer::new();
        assert!(!r.should_retransmit(Instant::from_secs(1)));
        r.set_for_retransmit(Instant::from_millis(1000), RTO);
        assert!(!r.should_retransmit(Instant::from_millis(1000)));
        assert!(!r.should_retransmit(Instant::from_millis(1050)));
        assert!(r.should_retransmit(Instant::from_millis(1101)));
        r.set_for_retransmit(Instant::from_millis(1101), RTO);
        assert!(!r.should_retransmit(Instant::from_millis(1101)));
        assert!(!r.should_retransmit(Instant::from_millis(1150)));
        assert!(!r.should_retransmit(Instant::from_millis(1200)));
        assert!(r.should_retransmit(Instant::from_millis(1301)));
        r.set_for_idle(Instant::from_millis(1301), None);
        assert!(!r.should_retransmit(Instant::from_millis(1350)));
    }

    #[test]
    fn test_rtt_estimator() {
        let mut r = RttEstimator::default();

        // The same two-second round trip this asserted in milliseconds, and the
        // same curve: RFC 6298's estimator converging from an over-cautious
        // first RTO down onto the path. Every figure is within 8 usec per
        // millisecond of the old table, which is the rounding the old units did
        // and this one does not.
        //
        // Where the two genuinely part is the tail. The old one settled at
        // 2012 ms because `rttvar` cannot fall below 1 under `div_ceil`, and
        // 1 ms of variance times K is 4 ms -- so the plateau was an artifact of
        // the unit, not a decision. In microseconds that term is negligible and
        // the plateau is `RTTE_MIN_MARGIN` above `srtt`, where it was always
        // meant to be.
        let rtos = &[
            6_000_000, 5_000_000, 4_250_000, 3_687_500, 3_265_628, 2_949_224, 2_711_920, 2_533_940,
            2_400_456, 2_300_344, 2_225_260, 2_168_948, 2_126_712, 2_095_036, 2_071_280, 2_053_460,
            2_040_096, 2_030_072, 2_022_556, 2_016_920, 2_012_692, 2_009_520, 2_007_140, 2_005_356,
        ];

        for &rto in rtos {
            r.sample(2_000_000);
            assert_eq!(r.retransmission_timeout(), Duration::from_micros(rto));
        }
    }

    #[test]
    fn test_rtt_estimator_caps_an_implausible_sample() {
        let mut r = RttEstimator::default();

        // Milliseconds made a round trip this long unrepresentable; microseconds
        // do not, and the smoothing multiplies by seven. Capped at the largest
        // RTO the timer will ever wait, because a sample past that informs
        // nothing.
        r.sample(u32::MAX);
        assert_eq!(r.srtt, RTTE_MAX_RTO);
        assert_eq!(
            r.retransmission_timeout(),
            Duration::from_micros(RTTE_MAX_RTO as u64)
        );

        r.sample(u32::MAX);
        assert_eq!(r.srtt, RTTE_MAX_RTO);
    }

    #[test]
    fn test_rtt_sampling_survives_a_lan_round_trip() {
        // A round trip across this stack's own tap is tens of microseconds. Read
        // off a millisecond clock every such sample truncated to zero, so `srtt`
        // and `rttvar` sat at zero for the life of every connection: the
        // estimator ran, and measured nothing.
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();

        recv(&mut s, Instant::from_micros(0), |result| {
            assert!(result.is_ok())
        });
        send(
            &mut s,
            Instant::from_micros(60),
            &TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            },
        );

        assert!(s.rtte.have_measurement);
        assert_eq!(s.rtte.srtt, 60);
        assert_eq!(s.rtte.rttvar, 30);

        // The estimate still does not reach the wire: 60 usec plus
        // `RTTE_MIN_MARGIN` is far under the floor, so `RTTE_MIN_RTO` is what
        // the timer waits. What the floor should *be* is a separate question,
        // pinned by the test below.
        assert_eq!(s.rtte.rto, RTTE_MIN_RTO);
    }

    #[test]
    fn test_a_measured_short_path_retransmits_at_linuxs_floor() {
        let mut s = socket_established();

        // A round trip first, because the floor governs only a *measured* path.
        // With no measurement yet RFC 6298 (2.1) wants a one-second first RTO,
        // which is `RTTE_INITIAL_RTO` and is unchanged -- it is also what Linux
        // does, as `TCP_TIMEOUT_INIT`.
        s.send_slice(b"abcdef").unwrap();
        recv(&mut s, Instant::from_micros(0), |result| {
            assert!(result.is_ok())
        });
        send(
            &mut s,
            Instant::from_micros(60),
            &TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            },
        );
        assert!(s.rtte.have_measurement);

        // Now something the peer never acknowledges.
        let sent_at = 100;
        s.send_slice(b"ghijkl").unwrap();
        recv(&mut s, Instant::from_micros(sent_at), |result| {
            assert!(result.is_ok())
        });

        // 200 ms, Linux's `TCP_RTO_MIN`, rather than the RFC's second. Stated as
        // the wire behaviour and not as `RTTE_MIN_RTO`, so that the constant
        // cannot quietly move without this failing.
        recv_nothing(&mut s, Instant::from_micros(sent_at + 200_000 - 1));
        recv(&mut s, Instant::from_micros(sent_at + 200_000), |result| {
            assert_eq!(
                result.map(|repr| repr.payload),
                Ok(&b"ghijkl"[..]),
                "the segment should be retransmitted 200 ms after it was sent"
            )
        });
    }

    #[test]
    fn test_set_get_congestion_control() {
        let mut s = socket_established();

        #[cfg(feature = "socket-tcp-reno")]
        {
            s.set_congestion_control(CongestionControl::Reno);
            assert_eq!(s.congestion_control(), CongestionControl::Reno);
        }

        #[cfg(feature = "socket-tcp-cubic")]
        {
            s.set_congestion_control(CongestionControl::Cubic);
            assert_eq!(s.congestion_control(), CongestionControl::Cubic);
        }

        s.set_congestion_control(CongestionControl::None);
        assert_eq!(s.congestion_control(), CongestionControl::None);
    }

    // =========================================================================================//
    // Timestamp tests
    // =========================================================================================//

    #[test]
    fn test_tsval_established_connection() {
        let mut s = socket_established();
        s.set_tsval_generator(Some(|| 1));

        assert!(s.timestamp_enabled());

        // First roundtrip after establishing.
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                timestamp: Some(TcpTimestampRepr::new(1, 0)),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.tx_buffer.len(), 6);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                timestamp: Some(TcpTimestampRepr::new(500, 1)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 0);
        // Second roundtrip.
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                timestamp: Some(TcpTimestampRepr::new(1, 500)),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 0);
    }

    #[test]
    fn test_tsval_disabled_in_remote_client() {
        let mut s = socket_listen();
        s.set_tsval_generator(Some(|| 1));
        assert!(s.timestamp_enabled());
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        assert!(!s.timestamp_enabled());
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_tsval_disabled_in_local_server() {
        let mut s = socket_listen();
        // s.set_timestamp(false); // commented to alert if the default state changes
        assert!(!s.timestamp_enabled());
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                timestamp: Some(TcpTimestampRepr::new(500, 0)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        assert!(!s.timestamp_enabled());
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_tsval_disabled_in_remote_server() {
        let mut s = socket();
        s.set_tsval_generator(Some(|| 1));
        assert!(s.timestamp_enabled());
        s.local_seq_no = LOCAL_SEQ;
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                timestamp: Some(TcpTimestampRepr::new(1, 0)),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                timestamp: None,
                ..SEND_TEMPL
            }
        );
        assert!(!s.timestamp_enabled());
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                timestamp: None,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_tsval_disabled_in_local_client() {
        let mut s = socket();
        // s.set_timestamp(false); // commented to alert if the default state changes
        assert!(!s.timestamp_enabled());
        s.local_seq_no = LOCAL_SEQ;
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                timestamp: Some(TcpTimestampRepr::new(500, 0)),
                ..SEND_TEMPL
            }
        );
        assert!(!s.timestamp_enabled());
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                timestamp: None,
                ..RECV_TEMPL
            }]
        );
    }

    /// Emits one full-sized data segment and reports how it divided up:
    /// (payload bytes, whole-packet bytes).
    fn one_full_segment(generator: Option<TcpTimestampGenerator>) -> (usize, usize) {
        let mut s = socket_established_with_buffer_sizes(65536, 65536);
        s.remote_win_len = 65535;
        // Neither the peer's window nor its MSS may be what bounds the segment
        // here: the MTU has to be, since the MTU is what this is about. The
        // default `remote_mss` is 536 and would bind first.
        s.remote_mss = 65535;
        s.set_tsval_generator(generator);
        s.send_slice(&[0; 65536][..]).unwrap();

        let mut sizes = (0, 0);
        recv(&mut s, Instant::from_millis(0), |result| {
            let repr = result.unwrap();
            assert_eq!(repr.timestamp.is_some(), generator.is_some());
            sizes = (repr.payload.len(), repr.buffer_len());
        });
        sizes
    }

    /// A segment's own options ride inside the packet the MTU bounds, so they
    /// have to come out of its payload -- `dispatch` used to size the payload
    /// against a bare 20-byte header, which put every full segment 12 bytes
    /// over the link's MTU the moment timestamps were switched on.
    ///
    /// Stated as a difference between the two arms rather than as an absolute,
    /// so that it holds for whichever IP version the crate is built for.
    #[test]
    fn test_timestamps_come_out_of_the_payload_not_the_mtu() {
        let (plain_payload, plain_packet) = one_full_segment(None);
        let (stamped_payload, stamped_packet) = one_full_segment(Some(|| 1));

        assert_eq!(
            stamped_payload,
            plain_payload - 12,
            "the option's 12 bytes come out of the payload"
        );
        assert_eq!(
            stamped_packet, plain_packet,
            "so the packet that reaches the wire is the same size either way"
        );
    }

    // =========================================================================================//
    // PAWS -- RFC 7323 section 5.3
    // =========================================================================================//

    /// An established socket offering timestamps, with TS.Recent primed to
    /// `tsval` by one segment the way a real connection primes it.
    fn socket_established_with_ts_recent(tsval: u32) -> TestSocket {
        let mut s = socket_established_with_buffer_sizes(4096, 4096);
        s.remote_win_len = 4096;
        s.set_tsval_generator(Some(|| 1));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                timestamp: Some(TcpTimestampRepr::new(tsval, 1)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.last_remote_tsval, tsval);
        s
    }

    // The immediate ACK a disordered segment draws must echo TS.Recent, not
    // the newer stamp the disordered segment itself carries (RFC 7323
    // section 4.3): the peer times its retransmissions by that echo, and a
    // too-new TSecr understates its RTT samples exactly while it is
    // recovering from the loss that disordered the flight.
    #[test]
    fn test_immediate_ack_echoes_ts_recent_not_the_arriving_tsval() {
        let mut s = socket_established_with_ts_recent(5000);

        let reply = send(
            &mut s,
            Instant::from_millis(0),
            &TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 10,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"early"[..],
                timestamp: Some(TcpTimestampRepr::new(6000, 1)),
                ..SEND_TEMPL
            },
        )
        .expect("a disordered segment draws an immediate duplicate ACK");
        assert_eq!(s.last_remote_tsval, 5000, "TS.Recent must not advance");
        let ts = reply
            .timestamp
            .expect("the duplicate ACK carries timestamps");
        assert_eq!(
            ts.tsecr, 5000,
            "TSecr echoed the disordered segment's TSval instead of TS.Recent"
        );
    }

    #[test]
    fn test_paws_drops_a_perfectly_sequenced_old_duplicate() {
        let mut s = socket_established_with_ts_recent(5000);

        // Sequence number, ACK and window are all exactly what the acceptance
        // test wants. The timestamp is the only thing that gives it away, which
        // is the entire point of the check.
        let reply = send(
            &mut s,
            Instant::from_millis(0),
            &TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"stale"[..],
                timestamp: Some(TcpTimestampRepr::new(4999, 1)),
                ..SEND_TEMPL
            },
        );

        assert!(
            reply.is_some(),
            "an old duplicate is acknowledged, so a peer out of step can resync"
        );
        assert_eq!(
            s.recv_queue(),
            0,
            "and its payload never reaches the reader"
        );
        assert_eq!(s.last_remote_tsval, 5000, "and it does not move TS.Recent");
    }

    #[test]
    fn test_paws_admits_a_current_timestamp() {
        let mut s = socket_established_with_ts_recent(5000);
        // In-order data is acknowledged by the next dispatch rather than in
        // reply here, so `None` is the accepting answer; what the check does to
        // a rejected segment is the previous test.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"fresh"[..],
                timestamp: Some(TcpTimestampRepr::new(5001, 1)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.recv_queue(), 5);
        assert_eq!(s.last_remote_tsval, 5001);
    }

    /// The timestamp clock wraps every 49 days, so "before" has to survive the
    /// wrap: a tsval just past zero is newer than one just below it, not 4
    /// billion ticks older.
    #[test]
    fn test_paws_compares_timestamps_modularly() {
        let mut s = socket_established_with_ts_recent(u32::MAX - 1);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"wrapped"[..],
                timestamp: Some(TcpTimestampRepr::new(2, 1)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.recv_queue(), 7, "a wrapped timestamp is newer, not older");
        assert_eq!(s.last_remote_tsval, 2);
    }

    /// RFC 7323 section 5.2: a reset is not subject to PAWS. Refusing one would
    /// hold open a connection the peer has already destroyed -- and an old
    /// timestamp on a reset is ordinary, since a peer that has lost all state
    /// has no timestamp clock left to draw from.
    #[test]
    fn test_paws_does_not_shield_the_socket_from_a_reset() {
        let mut s = socket_established_with_ts_recent(5000);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                timestamp: Some(TcpTimestampRepr::new(1, 1)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    /// Check R3, and the reason it is a condition rather than an unconditional
    /// assignment: a segment that arrives while a hole ahead of it is still
    /// open must not advance TS.Recent, or the retransmission that fills the
    /// hole -- older, because it was first sent earlier -- is rejected by R1
    /// and the connection stalls on the very loss it was recovering from.
    #[test]
    fn test_paws_lets_a_retransmission_repair_a_hole_behind_an_early_segment() {
        let mut s = socket_established_with_ts_recent(5000);

        // Ten bytes are lost; what follows them arrives, and is buffered out of
        // order. Its timestamp is the newest seen so far. The duplicate ACK it
        // draws is not this test's subject -- see the note on the echoed TSecr
        // in the plan -- so the reply is not asserted here.
        send(
            &mut s,
            Instant::from_millis(0),
            &TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 10,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"second"[..],
                timestamp: Some(TcpTimestampRepr::new(6000, 1)),
                ..SEND_TEMPL
            },
        );
        assert_eq!(
            s.last_remote_tsval, 5000,
            "an out-of-order segment must not advance TS.Recent"
        );

        // The retransmission of the lost bytes. It was first sent before the
        // segment above, so it carries an older timestamp than that one; under
        // an unconditional TS.Recent it would now be refused as an old
        // duplicate, and the hole would never close.
        send(
            &mut s,
            Instant::from_millis(0),
            &TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"0123456789"[..],
                timestamp: Some(TcpTimestampRepr::new(5500, 1)),
                ..SEND_TEMPL
            },
        );
        assert_eq!(
            s.recv_queue(),
            16,
            "the repair is accepted and the hole closes"
        );
        assert_eq!(s.last_remote_tsval, 5500);
    }

    // =========================================================================================//
    // Tests for source IP address change.
    // =========================================================================================//

    #[test]
    fn test_established_close_on_src_ip_change() {
        let mut s = socket_established();

        // Verify socket is working normally
        s.send_slice(b"abc").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abc"[..],
                ..RECV_TEMPL
            }]
        );

        // Simulate interface IP change - remove the socket's source IP
        // and add a different one.
        let mut new_addrs = heapless::Vec::<IpCidr, IFACE_MAX_ADDR_COUNT>::new();
        new_addrs.push(IpCidr::new(OTHER_ADDR.into(), 24)).unwrap();
        s.cx.set_ip_addrs(new_addrs);

        // The socket's source IP is no longer on the interface.
        // When dispatch() runs, it should detect this and reset the socket
        // silently (no RST sent, since that would use the invalid source IP).
        s.send_slice(b"def").unwrap();
        recv_nothing!(s);
        assert_eq!(s.state, State::Closed);
    }
}
