use core::fmt;

use std::collections::{BTreeMap, HashMap};

use super::socket_meta::Meta;
use crate::socket::{AnySocket, DemuxKey, Socket};
use crate::wire::{IpAddress, IpEndpoint};

/// An item of a socket set.
#[derive(Debug)]
pub(crate) struct Item<'a> {
    pub(crate) meta: Meta,
    pub(crate) socket: Socket<'a>,
}

/// The demux maps, maintained from [`Meta::demux_key`] transitions.
///
/// Authoritative, not a cache: every identity-changing path ends in
/// [`DemuxIndex::resync`] -- the `tcp_*` operations below, `add`/`remove`,
/// and the interface's process/dispatch loops for the transitions inside
/// packet and timer handling -- so an ingress miss *means* no socket. Hash
/// maps are safe against peer-chosen keys here: std's hasher is randomly
/// seeded SipHash.
#[derive(Debug, Default)]
pub(crate) struct DemuxIndex {
    /// (local, remote) of every socket holding an open connection's tuple.
    /// At most one live socket per tuple: a connect cannot claim a taken
    /// port, a listener's SYN-take makes a tuple no live socket holds, and a
    /// cookie restore verifies against the same demux this map serves.
    tcp_tuples: HashMap<(IpEndpoint, IpEndpoint), SocketHandle>,
    /// The listening pools: every `State::Listen` socket, under
    /// (port, listen address), `None` the wildcard. Handles stay sorted, so
    /// pool selection is deterministic -- the lowest live handle serves.
    tcp_listeners: HashMap<(u16, Option<IpAddress>), Vec<SocketHandle>>,
    /// Every bound UDP socket, by port: (bound address, handle) pairs in
    /// handle order. One Vec per port rather than per (port, address),
    /// because a broadcast or multicast datagram may land on any binding of
    /// its port, whatever address it is bound to.
    udp_ports: HashMap<u16, Vec<(Option<IpAddress>, SocketHandle)>>,
}

impl DemuxIndex {
    /// Re-derive `item`'s demux key and move its map entries to match. Every
    /// identity-changing path ends here.
    pub(crate) fn resync(&mut self, item: &mut Item<'_>) {
        let new = item.socket.demux_key();
        if new == item.meta.demux_key {
            return;
        }
        self.retire(&item.meta);
        match new {
            Some(DemuxKey::TcpTuple { local, remote }) => {
                let evicted = self.tcp_tuples.insert((local, remote), item.meta.handle);
                debug_assert!(
                    evicted.is_none(),
                    "two live sockets claim {local} <-> {remote}"
                );
            }
            Some(DemuxKey::TcpListen(endpoint)) => {
                let pool = self
                    .tcp_listeners
                    .entry((endpoint.port, endpoint.addr))
                    .or_default();
                let position = pool
                    .binary_search(&item.meta.handle)
                    .expect_err("a handle has one identity, it cannot be pooled twice");
                pool.insert(position, item.meta.handle);
            }
            Some(DemuxKey::UdpBind(endpoint)) => {
                let pool = self.udp_ports.entry(endpoint.port).or_default();
                let position = pool
                    .binary_search_by_key(&item.meta.handle, |(_, handle)| *handle)
                    .expect_err("a handle has one identity, it cannot be bound twice");
                pool.insert(position, (endpoint.addr, item.meta.handle));
            }
            None => {}
        }
        item.meta.demux_key = new;
    }

    /// Drop the entries `meta` holds, on removal from the set.
    pub(crate) fn retire(&mut self, meta: &Meta) {
        match meta.demux_key {
            Some(DemuxKey::TcpTuple { local, remote }) => {
                self.tcp_tuples.remove(&(local, remote));
            }
            Some(DemuxKey::TcpListen(endpoint)) => {
                let key = (endpoint.port, endpoint.addr);
                if let Some(pool) = self.tcp_listeners.get_mut(&key) {
                    pool.retain(|handle| *handle != meta.handle);
                    if pool.is_empty() {
                        self.tcp_listeners.remove(&key);
                    }
                }
            }
            Some(DemuxKey::UdpBind(endpoint)) => {
                if let Some(pool) = self.udp_ports.get_mut(&endpoint.port) {
                    pool.retain(|(_, handle)| *handle != meta.handle);
                    if pool.is_empty() {
                        self.udp_ports.remove(&endpoint.port);
                    }
                }
            }
            None => {}
        }
    }

    /// The socket holding the connection `(local, remote)`, if one does.
    pub(crate) fn tcp_tuple(&self, local: IpEndpoint, remote: IpEndpoint) -> Option<SocketHandle> {
        self.tcp_tuples.get(&(local, remote)).copied()
    }

    /// The listening socket serving `local`, if one does: a specific-address
    /// pool outranks the wildcard pool on the same port (the Linux rule),
    /// and within a pool the lowest handle serves.
    pub(crate) fn tcp_listener(&self, local: IpEndpoint) -> Option<SocketHandle> {
        self.tcp_listeners
            .get(&(local.port, Some(local.addr)))
            .or_else(|| self.tcp_listeners.get(&(local.port, None)))
            .and_then(|pool| pool.first().copied())
    }

    /// The UDP socket serving a datagram to `local`, if one does. For a
    /// unicast destination an exact-address binding outranks a wildcard one
    /// (the same rule as the listener pools); a broadcast or multicast
    /// destination (`promiscuous`) lands on the port's lowest handle,
    /// whatever it is bound to -- as `accepts()` always allowed. Ties go to
    /// the lowest handle.
    pub(crate) fn udp_socket(&self, local: IpEndpoint, promiscuous: bool) -> Option<SocketHandle> {
        let pool = self.udp_ports.get(&local.port)?;
        if promiscuous {
            return pool.first().map(|(_, handle)| *handle);
        }
        pool.iter()
            .find(|(addr, _)| *addr == Some(local.addr))
            .or_else(|| pool.iter().find(|(addr, _)| addr.is_none()))
            .map(|(_, handle)| *handle)
    }
}

/// A handle, identifying a socket in an Interface.
///
/// The value is the id the caller supplied to [`SocketSet::add`]. The caller
/// owns the id space and must never repeat an id, even after the socket's
/// removal (in sys-io a single counter allocates them); a handle held past
/// its socket's life then can only dangle -- it cannot alias a newer socket
/// the way a recycled slot index could.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SocketHandle(u64);

impl fmt::Display for SocketHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

impl From<u64> for SocketHandle {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

impl From<SocketHandle> for u64 {
    fn from(handle: SocketHandle) -> u64 {
        handle.0
    }
}

/// An extensible set of sockets, keyed by stable handles.
///
/// The lifetime `'a` is used when storing a `Socket<'a>`.  If you're using
/// owned buffers for your sockets (passed in as `Vec`s) you can use
/// `SocketSet<'static>`.
#[derive(Debug, Default)]
pub struct SocketSet<'a> {
    sockets: BTreeMap<u64, Item<'a>>,
    demux: DemuxIndex,
}

impl<'a> SocketSet<'a> {
    /// Create an empty socket set.
    pub fn new() -> SocketSet<'a> {
        Self::default()
    }

    /// Add a socket to the set under the caller-supplied `id`, and return its
    /// handle.
    ///
    /// # Panics
    /// This function panics if `id` already names a live socket in this set.
    /// See [`SocketHandle`] for the caller's wider contract: ids are never
    /// repeated, even after removal.
    pub fn add<T: AnySocket<'a>>(&mut self, id: u64, socket: T) -> SocketHandle {
        let handle = SocketHandle(id);
        net_trace!("[{}]: adding", id);

        let mut meta = Meta::default();
        meta.handle = handle;
        let mut item = Item {
            meta,
            socket: socket.upcast(),
        };
        // A socket can arrive pre-configured (listening, mid-connect): its
        // identity is on record from the first packet on.
        self.demux.resync(&mut item);
        let evicted = self.sockets.insert(id, item);
        assert!(evicted.is_none(), "socket id {id} is already in the set");
        handle
    }

    /// Re-derive `handle`'s demux key and index entries; a no-op for a
    /// removed socket.
    pub(crate) fn sync_demux(&mut self, handle: SocketHandle) {
        if let Some(item) = self.sockets.get_mut(&handle.0) {
            self.demux.resync(item);
        }
    }

    /// The socket set's contents split from its demux index, for loops that
    /// mutate sockets while keeping the index true (see `socket_egress`).
    pub(crate) fn parts_mut(&mut self) -> (&mut BTreeMap<u64, Item<'a>>, &mut DemuxIndex) {
        (&mut self.sockets, &mut self.demux)
    }

    /// The socket holding the connection `(local, remote)`, if one does.
    pub(crate) fn tcp_tuple(&self, local: IpEndpoint, remote: IpEndpoint) -> Option<SocketHandle> {
        self.demux.tcp_tuple(local, remote)
    }

    /// The listening socket serving `local`, if one does.
    pub(crate) fn tcp_listener(&self, local: IpEndpoint) -> Option<SocketHandle> {
        self.demux.tcp_listener(local)
    }

    /// The UDP socket serving a datagram to `local`, if one does.
    pub(crate) fn udp_socket(&self, local: IpEndpoint, promiscuous: bool) -> Option<SocketHandle> {
        self.demux.udp_socket(local, promiscuous)
    }

    /// Get a socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get<T: AnySocket<'a>>(&self, handle: SocketHandle) -> &T {
        match self.sockets.get(&handle.0) {
            Some(item) => {
                T::downcast(&item.socket).expect("handle refers to a socket of a wrong type")
            }
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Get a mutable socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get_mut<T: AnySocket<'a>>(&mut self, handle: SocketHandle) -> &mut T {
        match self.sockets.get_mut(&handle.0) {
            Some(item) => T::downcast_mut(&mut item.socket)
                .expect("handle refers to a socket of a wrong type"),
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Remove a socket from the set, without changing its state.
    ///
    /// The removal returns the socket's memory to the allocator directly;
    /// nothing of a departed burst outlives the burst, and no survivor pins
    /// storage the way a high slot in the retired slab did.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set.
    pub fn remove(&mut self, handle: SocketHandle) -> Socket<'a> {
        net_trace!("[{}]: removing", handle.0);
        match self.sockets.remove(&handle.0) {
            Some(item) => {
                self.demux.retire(&item.meta);
                item.socket
            }
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Get an iterator to the inner sockets.
    pub fn iter(&self) -> impl Iterator<Item = (SocketHandle, &Socket<'a>)> {
        self.items().map(|i| (i.meta.handle, &i.socket))
    }

    /// Get a mutable iterator to the inner sockets.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (SocketHandle, &mut Socket<'a>)> {
        self.items_mut().map(|i| (i.meta.handle, &mut i.socket))
    }

    /// Iterate every socket in this set, in handle (creation) order.
    pub(crate) fn items(&self) -> impl Iterator<Item = &Item<'a>> + '_ {
        self.sockets.values()
    }

    /// Iterate every socket in this set, in handle (creation) order.
    pub(crate) fn items_mut(&mut self) -> impl Iterator<Item = &mut Item<'a>> + '_ {
        self.sockets.values_mut()
    }
}

/// The identity-changing TCP operations, mediated by the set.
///
/// These five are the only ways a caller can change which packets a TCP
/// socket answers for -- [`crate::socket::tcp::Socket`] keeps them
/// crate-private, so `get_mut` hands out data operations alone -- and each
/// re-derives the socket's recorded demux key on the way out. The
/// transitions that happen *inside* packet and timer handling are re-synced
/// by the interface's own loops; between the two, `Meta::demux_key` is
/// always current.
#[cfg(feature = "socket-tcp")]
impl SocketSet<'_> {
    /// [`tcp::Socket::listen`] through the set.
    ///
    /// # Panics
    /// Panics if `handle` does not refer to a live TCP socket.
    pub fn tcp_listen<T>(
        &mut self,
        handle: SocketHandle,
        local_endpoint: T,
    ) -> Result<(), crate::socket::tcp::ListenError>
    where
        T: Into<crate::wire::IpListenEndpoint>,
    {
        let result = self
            .get_mut::<crate::socket::tcp::Socket>(handle)
            .listen(local_endpoint);
        self.sync_demux(handle);
        result
    }

    /// [`tcp::Socket::connect`] through the set.
    ///
    /// # Panics
    /// Panics if `handle` does not refer to a live TCP socket.
    pub fn tcp_connect<T, U>(
        &mut self,
        handle: SocketHandle,
        cx: &mut super::Context,
        remote_endpoint: T,
        local_endpoint: U,
    ) -> Result<(), crate::socket::tcp::ConnectError>
    where
        T: Into<crate::wire::IpEndpoint>,
        U: Into<crate::wire::IpListenEndpoint>,
    {
        let result = self.get_mut::<crate::socket::tcp::Socket>(handle).connect(
            cx,
            remote_endpoint,
            local_endpoint,
        );
        self.sync_demux(handle);
        result
    }

    /// [`tcp::Socket::restore_from_cookie`] through the set.
    ///
    /// # Panics
    /// Panics if `handle` does not refer to a live TCP socket.
    pub fn tcp_restore_from_cookie(
        &mut self,
        handle: SocketHandle,
        cx: &mut super::Context,
        restore: &crate::socket::tcp::TcpCookieRestore,
    ) -> Result<(), crate::socket::tcp::ListenError> {
        let result = self
            .get_mut::<crate::socket::tcp::Socket>(handle)
            .restore_from_cookie(cx, restore);
        self.sync_demux(handle);
        result
    }

    /// [`tcp::Socket::close`] through the set.
    ///
    /// # Panics
    /// Panics if `handle` does not refer to a live TCP socket.
    pub fn tcp_close(&mut self, handle: SocketHandle) {
        self.get_mut::<crate::socket::tcp::Socket>(handle).close();
        self.sync_demux(handle);
    }

    /// [`tcp::Socket::abort`] through the set.
    ///
    /// # Panics
    /// Panics if `handle` does not refer to a live TCP socket.
    pub fn tcp_abort(&mut self, handle: SocketHandle) {
        self.get_mut::<crate::socket::tcp::Socket>(handle).abort();
        self.sync_demux(handle);
    }
}

/// The identity-changing UDP operations, mediated by the set for the same
/// reason as the TCP five above. UDP has only these two: nothing inside
/// packet or timer handling ever changes a UDP socket's binding.
#[cfg(feature = "socket-udp")]
impl SocketSet<'_> {
    /// [`udp::Socket::bind`] through the set.
    ///
    /// # Panics
    /// Panics if `handle` does not refer to a live UDP socket.
    pub fn udp_bind<T>(
        &mut self,
        handle: SocketHandle,
        endpoint: T,
    ) -> Result<(), crate::socket::udp::BindError>
    where
        T: Into<crate::wire::IpListenEndpoint>,
    {
        let result = self
            .get_mut::<crate::socket::udp::Socket>(handle)
            .bind(endpoint);
        self.sync_demux(handle);
        result
    }

    /// [`udp::Socket::close`] through the set.
    ///
    /// # Panics
    /// Panics if `handle` does not refer to a live UDP socket.
    pub fn udp_close(&mut self, handle: SocketHandle) {
        self.get_mut::<crate::socket::udp::Socket>(handle).close();
        self.sync_demux(handle);
    }
}

#[cfg(all(test, feature = "socket-tcp"))]
mod tests {
    use super::*;
    use crate::socket::tcp;

    fn socket() -> tcp::Socket<'static> {
        tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 64]),
            tcp::SocketBuffer::new(vec![0; 64]),
        )
    }

    /// Membership tracks removal one for one, in either teardown order: the
    /// keyed store has no tail to collapse and no holes to walk.
    #[test]
    fn storage_follows_removal_in_any_order() {
        for lifo in [true, false] {
            let mut set = SocketSet::new();
            let handles: Vec<_> = (0..256).map(|id| set.add(id, socket())).collect();
            assert_eq!(set.sockets.len(), 256);

            let order: Vec<_> = if lifo {
                handles.iter().rev().copied().collect()
            } else {
                handles.clone()
            };
            for (removed, handle) in order.into_iter().enumerate() {
                set.remove(handle);
                assert_eq!(set.sockets.len(), 255 - removed, "lifo={lifo}");
            }
        }
    }

    /// An id naming a live socket is refused loudly: silently replacing the
    /// occupant would strand its handle on the newcomer.
    #[test]
    #[should_panic(expected = "already in the set")]
    fn a_live_id_cannot_be_reused() {
        let mut set = SocketSet::new();
        set.add(7, socket());
        set.add(7, socket());
    }

    /// A long-lived socket keeps its handle valid while a burst churns
    /// through around it.
    #[test]
    fn a_survivor_keeps_its_handle() {
        let mut set = SocketSet::new();
        let keeper = set.add(0, socket());
        let burst: Vec<_> = (1..256).map(|id| set.add(id, socket())).collect();
        for handle in burst {
            set.remove(handle);
        }

        assert_eq!(set.sockets.len(), 1);
        let _ = set.get::<tcp::Socket>(keeper);
    }
}
