const MAX_STREAMS: usize = 64;
const MAX_LISTENERS: usize = 32;
const EPHEMERAL_START: u32 = 49_152;
const LAST_PORT: u32 = u32::MAX - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VsockAddr {
    pub(crate) cid: u32,
    pub(crate) port: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConnectionTuple {
    pub(crate) local: VsockAddr,
    pub(crate) peer: VsockAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionError {
    InvalidPort,
    PortInUse,
    TupleInUse,
    SocketIdInUse,
    UnknownListener,
    StreamLimit,
    ListenerLimit,
    OutOfMemory,
}

/// A secondary index only. Socket state and client authority remain in the
/// common socket map under these opaque IDs. Entries survive connecting,
/// unaccepted, and closing states until their owner explicitly removes them.
pub(crate) struct TupleIndex {
    streams: Vec<(ConnectionTuple, u64)>,
    listeners: Vec<(VsockAddr, u64)>,
    next_ephemeral: u32,
}

impl TupleIndex {
    pub(crate) fn new() -> Self {
        Self {
            streams: Vec::new(),
            listeners: Vec::new(),
            next_ephemeral: EPHEMERAL_START,
        }
    }

    pub(crate) fn reserve_listener(
        &mut self,
        socket_id: u64,
        local_cid: u32,
        requested_port: u32,
    ) -> Result<u32, AdmissionError> {
        if requested_port == u32::MAX {
            return Err(AdmissionError::InvalidPort);
        }
        if self.listeners.len() == MAX_LISTENERS {
            return Err(AdmissionError::ListenerLimit);
        }
        self.check_socket_id(socket_id)?;
        let (port, next) = if requested_port == 0 {
            self.choose_ephemeral(local_cid)
        } else {
            if self.local_port_in_use(local_cid, requested_port) {
                return Err(AdmissionError::PortInUse);
            }
            (requested_port, self.next_ephemeral)
        };
        self.listeners
            .try_reserve(1)
            .map_err(|_| AdmissionError::OutOfMemory)?;
        self.listeners.push((
            VsockAddr {
                cid: local_cid,
                port,
            },
            socket_id,
        ));
        self.next_ephemeral = next;
        Ok(port)
    }

    pub(crate) fn reserve_outgoing(
        &mut self,
        socket_id: u64,
        local_cid: u32,
        peer: VsockAddr,
    ) -> Result<ConnectionTuple, AdmissionError> {
        validate_connect_port(peer.port)?;
        if self.streams.len() == MAX_STREAMS {
            return Err(AdmissionError::StreamLimit);
        }
        self.check_socket_id(socket_id)?;
        let (port, next) = self.choose_ephemeral(local_cid);
        self.streams
            .try_reserve(1)
            .map_err(|_| AdmissionError::OutOfMemory)?;
        let tuple = ConnectionTuple {
            local: VsockAddr {
                cid: local_cid,
                port,
            },
            peer,
        };
        self.streams.push((tuple, socket_id));
        self.next_ephemeral = next;
        Ok(tuple)
    }

    /// Admit a child against a live listener. Children may share its local
    /// port, but their complete tuples remain unique after the listener drops.
    /// Peer source ports are wire identities, not native connect targets.
    pub(crate) fn reserve_accepted(
        &mut self,
        listener_id: u64,
        socket_id: u64,
        peer: VsockAddr,
    ) -> Result<ConnectionTuple, AdmissionError> {
        if self.streams.len() == MAX_STREAMS {
            return Err(AdmissionError::StreamLimit);
        }
        self.check_socket_id(socket_id)?;
        let local = self
            .listeners
            .iter()
            .find_map(|(addr, id)| (*id == listener_id).then_some(*addr))
            .ok_or(AdmissionError::UnknownListener)?;
        let tuple = ConnectionTuple { local, peer };
        if self.stream_socket(tuple).is_some() {
            return Err(AdmissionError::TupleInUse);
        }
        self.streams
            .try_reserve(1)
            .map_err(|_| AdmissionError::OutOfMemory)?;
        self.streams.push((tuple, socket_id));
        Ok(tuple)
    }

    pub(crate) fn stream_socket(&self, tuple: ConnectionTuple) -> Option<u64> {
        self.streams
            .iter()
            .find_map(|(candidate, id)| (*candidate == tuple).then_some(*id))
    }

    pub(crate) fn listener_socket(&self, local: VsockAddr) -> Option<u64> {
        self.listeners
            .iter()
            .find_map(|(candidate, id)| (*candidate == local).then_some(*id))
    }

    pub(crate) fn remove_stream(&mut self, socket_id: u64) -> Option<ConnectionTuple> {
        let index = self.streams.iter().position(|(_, id)| *id == socket_id)?;
        Some(self.streams.swap_remove(index).0)
    }

    pub(crate) fn remove_listener(&mut self, socket_id: u64) -> Option<VsockAddr> {
        let index = self.listeners.iter().position(|(_, id)| *id == socket_id)?;
        Some(self.listeners.swap_remove(index).0)
    }

    /// A transport reset invalidates old stream tuples, but listeners keep
    /// their ports and follow the device's refreshed guest CID.
    pub(crate) fn refresh_listener_cid(&mut self, local_cid: u32) {
        for (local, _) in &mut self.listeners {
            local.cid = local_cid;
        }
    }

    pub(crate) fn counts(&self) -> (usize, usize) {
        (self.streams.len(), self.listeners.len())
    }

    pub(crate) fn stream_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.streams.iter().map(|(_, socket_id)| *socket_id)
    }

    fn choose_ephemeral(&self, local_cid: u32) -> (u32, u32) {
        find_ephemeral(self.next_ephemeral, |port| {
            self.local_port_in_use(local_cid, port)
        })
        .expect("bounded vsock admission left no ephemeral port")
    }

    fn local_port_in_use(&self, cid: u32, port: u32) -> bool {
        self.listeners
            .iter()
            .any(|(addr, _)| addr.cid == cid && addr.port == port)
            || self
                .streams
                .iter()
                .any(|(tuple, _)| tuple.local.cid == cid && tuple.local.port == port)
    }

    fn check_socket_id(&self, socket_id: u64) -> Result<(), AdmissionError> {
        if self.streams.iter().any(|(_, id)| *id == socket_id)
            || self.listeners.iter().any(|(_, id)| *id == socket_id)
        {
            Err(AdmissionError::SocketIdInUse)
        } else {
            Ok(())
        }
    }
}

fn validate_connect_port(port: u32) -> Result<(), AdmissionError> {
    if port == 0 || port == u32::MAX {
        Err(AdmissionError::InvalidPort)
    } else {
        Ok(())
    }
}

pub(crate) fn find_ephemeral(
    mut port: u32,
    mut in_use: impl FnMut(u32) -> bool,
) -> Option<(u32, u32)> {
    debug_assert!((EPHEMERAL_START..=LAST_PORT).contains(&port));
    for _ in 0..=(MAX_STREAMS + MAX_LISTENERS) {
        let next = if port == LAST_PORT {
            EPHEMERAL_START
        } else {
            port + 1
        };
        if !in_use(port) {
            return Some((port, next));
        }
        port = next;
    }
    None
}
