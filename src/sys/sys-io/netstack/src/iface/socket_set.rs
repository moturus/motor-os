use core::fmt;

use std::collections::BTreeMap;

use super::socket_meta::Meta;
use crate::socket::{AnySocket, Socket};

/// An item of a socket set.
#[derive(Debug)]
pub(crate) struct Item<'a> {
    pub(crate) meta: Meta,
    pub(crate) socket: Socket<'a>,
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
        let item = Item {
            meta,
            socket: socket.upcast(),
        };
        let evicted = self.sockets.insert(id, item);
        assert!(evicted.is_none(), "socket id {id} is already in the set");
        handle
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
            Some(item) => item.socket,
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
