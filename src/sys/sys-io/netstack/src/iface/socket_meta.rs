use super::SocketHandle;
use crate::{
    socket::PollAt,
    time::{Duration, Instant},
    wire::IpAddress,
};

/// Neighbor dependency.
///
/// This enum tracks whether the socket should be polled based on the neighbor
/// it is going to send packets to.
#[derive(Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum NeighborState {
    /// Socket can be polled immediately.
    #[default]
    Active,
    /// Socket should not be polled until either `silent_until` passes or
    /// `neighbor` appears in the neighbor cache.
    Waiting {
        neighbor: IpAddress,
        silent_until: Instant,
        attempts: u8,
    },
    Backoff { retry_at: Instant },
}

/// Network socket metadata.
///
/// This includes things that only external (to the socket, that is) code
/// is interested in, but which are more conveniently stored inside the socket
/// itself.
#[derive(Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct Meta {
    /// Handle of this socket within its enclosing `SocketSet`.
    /// Mainly useful for debug output.
    pub(crate) handle: SocketHandle,
    /// The socket's demux identity as of its last set-visible transition.
    /// Every path that can change the identity re-derives this (the SocketSet
    /// operations, the interface's process/dispatch loops), which is the
    /// invariant the demux maps are maintained from.
    pub(crate) demux_key: Option<crate::socket::DemuxKey>,
    /// See [NeighborState](struct.NeighborState.html).
    neighbor_state: NeighborState,
    /// The socket's [`PollAt`] as of its last refresh, mirrored into the
    /// set's poll index. Every path that can change what the socket would
    /// transmit refreshes it (the interface's process/egress loops) or
    /// marks the socket stale for the next poll entry (the SocketSet's
    /// mutable accessors) -- the same invariant shape `demux_key` has.
    pub(crate) poll_at_cache: PollAt,
}

impl Meta {
    pub(crate) fn poll_at<F>(
        &self,
        socket_poll_at: PollAt,
        has_neighbor: F,
        timestamp: Instant,
    ) -> PollAt
    where
        F: Fn(IpAddress) -> bool,
    {
        match self.neighbor_state {
            NeighborState::Active => socket_poll_at,
            NeighborState::Waiting { neighbor, .. } if has_neighbor(neighbor) => socket_poll_at,
            NeighborState::Waiting { silent_until, .. } if timestamp >= silent_until => {
                socket_poll_at
            }
            NeighborState::Waiting { silent_until, .. } => PollAt::Time(silent_until),
            NeighborState::Backoff { retry_at } if timestamp >= retry_at => socket_poll_at,
            NeighborState::Backoff { retry_at } => PollAt::Time(retry_at),
        }
    }

    pub(crate) fn egress_permitted<F>(&mut self, timestamp: Instant, has_neighbor: F) -> bool
    where
        F: Fn(IpAddress) -> bool,
    {
        match self.neighbor_state {
            NeighborState::Active => true,
            NeighborState::Waiting {
                neighbor,
                silent_until,
                ..
            } => {
                if has_neighbor(neighbor) {
                    net_trace!(
                        "{}: neighbor {} discovered, unsilencing",
                        self.handle,
                        neighbor
                    );
                    self.neighbor_state = NeighborState::Active;
                    true
                } else if timestamp >= silent_until {
                    net_trace!(
                        "{}: neighbor {} silence timer expired, rediscovering",
                        self.handle,
                        neighbor
                    );
                    true
                } else {
                    false
                }
            }
            NeighborState::Backoff { retry_at } => {
                if timestamp >= retry_at {
                    self.neighbor_state = NeighborState::Active;
                    true
                } else {
                    false
                }
            }
        }
    }

    pub(crate) fn neighbor_resolution_failed<F>(
        &self,
        timestamp: Instant,
        has_neighbor: F,
    ) -> bool
    where
        F: Fn(IpAddress) -> bool,
    {
        matches!(
            self.neighbor_state,
            NeighborState::Waiting {
                neighbor,
                silent_until,
                attempts: 3..
            } if timestamp >= silent_until && !has_neighbor(neighbor)
        )
    }

    pub(crate) fn reset_egress(&mut self) {
        self.neighbor_state = NeighborState::Active;
    }

    pub(crate) fn defer(&mut self, timestamp: Instant, delay: Duration) {
        self.neighbor_state = NeighborState::Backoff {
            retry_at: timestamp + delay,
        };
    }

    pub(crate) fn neighbor_missing(
        &mut self,
        timestamp: Instant,
        neighbor: IpAddress,
        delay: Duration,
    ) {
        let attempts = match self.neighbor_state {
            NeighborState::Waiting {
                neighbor: pending,
                attempts,
                ..
            } if pending == neighbor => attempts.saturating_add(1),
            _ => 1,
        };
        net_trace!(
            "{}: neighbor {} missing after attempt {}, silencing until t+{}",
            self.handle,
            neighbor,
            attempts,
            delay
        );
        self.neighbor_state = NeighborState::Waiting {
            neighbor,
            silent_until: timestamp + delay,
            attempts,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "proto-ipv4")]
    const NEIGHBOR: IpAddress = IpAddress::v4(192, 168, 1, 1);
    #[cfg(not(feature = "proto-ipv4"))]
    const NEIGHBOR: IpAddress = IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1);

    fn meta() -> Meta {
        Meta {
            handle: SocketHandle::default(),
            demux_key: None,
            neighbor_state: NeighborState::Active,
            poll_at_cache: PollAt::Ingress,
        }
    }

    #[test]
    fn poll_at_active_passes_through() {
        let m = meta();
        let t = Instant::from_millis(1000);

        assert_eq!(m.poll_at(PollAt::Ingress, |_| false, t), PollAt::Ingress);
        assert_eq!(m.poll_at(PollAt::Now, |_| false, t), PollAt::Now);
        let future = Instant::from_millis(2000);
        assert_eq!(
            m.poll_at(PollAt::Time(future), |_| false, t),
            PollAt::Time(future),
        );
    }

    #[test]
    fn poll_at_waiting_neighbor_found() {
        let mut m = meta();
        m.neighbor_missing(
            Instant::from_millis(1000),
            NEIGHBOR,
            Duration::from_millis(1000),
        );

        assert_eq!(
            m.poll_at(PollAt::Now, |_| true, Instant::from_millis(1000)),
            PollAt::Now,
        );
        assert_eq!(
            m.poll_at(PollAt::Ingress, |_| true, Instant::from_millis(1000)),
            PollAt::Ingress,
        );
    }

    #[test]
    fn poll_at_waiting_before_silent_until() {
        let mut m = meta();
        let t0 = Instant::from_millis(1000);
        m.neighbor_missing(t0, NEIGHBOR, Duration::from_millis(1000));
        let silent_until = t0 + Duration::from_millis(1000);

        let t_before = Instant::from_millis(1500);
        assert!(t_before < silent_until);

        assert_eq!(
            m.poll_at(PollAt::Ingress, |_| false, t_before),
            PollAt::Time(silent_until),
        );
        assert_eq!(
            m.poll_at(PollAt::Now, |_| false, t_before),
            PollAt::Time(silent_until),
        );
    }

    #[test]
    fn poll_at_waiting_after_silent_until_returns_socket_poll_at() {
        let mut m = meta();
        let t0 = Instant::from_millis(1000);
        m.neighbor_missing(t0, NEIGHBOR, Duration::from_millis(1000));
        let silent_until = t0 + Duration::from_millis(1000);

        let t_after = Instant::from_millis(2500);
        assert!(t_after >= silent_until);

        assert_eq!(
            m.poll_at(PollAt::Ingress, |_| false, t_after),
            PollAt::Ingress,
        );
        assert_eq!(m.poll_at(PollAt::Now, |_| false, t_after), PollAt::Now);
        let future = Instant::from_millis(5000);
        assert_eq!(
            m.poll_at(PollAt::Time(future), |_| false, t_after),
            PollAt::Time(future),
        );
    }

    #[test]
    fn poll_at_waiting_at_exact_silent_until() {
        let mut m = meta();
        let t0 = Instant::from_millis(1000);
        m.neighbor_missing(t0, NEIGHBOR, Duration::from_millis(1000));
        let silent_until = t0 + Duration::from_millis(1000);

        assert_eq!(
            m.poll_at(PollAt::Ingress, |_| false, silent_until),
            PollAt::Ingress,
        );
    }

    #[test]
    fn egress_permitted_consistent_with_poll_at() {
        let mut m = meta();
        let t0 = Instant::from_millis(1000);
        m.neighbor_missing(t0, NEIGHBOR, Duration::from_millis(1000));
        let silent_until = t0 + Duration::from_millis(1000);

        let t_before = Instant::from_millis(1500);
        assert!(!m.egress_permitted(t_before, |_| false));
        assert_eq!(
            m.poll_at(PollAt::Ingress, |_| false, t_before),
            PollAt::Time(silent_until),
        );

        let t_after = Instant::from_millis(2500);
        assert!(m.egress_permitted(t_after, |_| false));
    }

    #[test]
    fn neighbor_failure_follows_three_elapsed_attempts() {
        let mut m = meta();
        let delay = Duration::from_millis(50);

        for now in [1000, 1050] {
            m.neighbor_missing(Instant::from_millis(now), NEIGHBOR, delay);
            assert!(!m.neighbor_resolution_failed(
                Instant::from_millis(now + 50),
                |_| false
            ));
        }
        m.neighbor_missing(Instant::from_millis(1100), NEIGHBOR, delay);
        assert!(!m.neighbor_resolution_failed(Instant::from_millis(1149), |_| false));
        assert!(m.neighbor_resolution_failed(Instant::from_millis(1150), |_| false));
        assert!(!m.neighbor_resolution_failed(Instant::from_millis(1150), |_| true));
    }

    #[test]
    fn transient_backoff_does_not_become_neighbor_failure() {
        let mut m = meta();
        m.defer(
            Instant::from_millis(1000),
            Duration::from_millis(50),
        );

        assert_eq!(
            m.poll_at(PollAt::Now, |_| false, Instant::from_millis(1049)),
            PollAt::Time(Instant::from_millis(1050))
        );
        assert!(!m.neighbor_resolution_failed(Instant::from_millis(2000), |_| false));
        assert!(m.egress_permitted(Instant::from_millis(1050), |_| false));
    }
}
