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
/// The value is stable for the socket's whole life and is never reused by its
/// set, so a handle held past its socket's removal can only dangle -- it
/// cannot alias a newer socket the way a recycled slot index could.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SocketHandle(u64);

impl fmt::Display for SocketHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "#{}", self.0)
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
    next_id: u64,
}

impl<'a> SocketSet<'a> {
    /// Create an empty socket set.
    pub fn new() -> SocketSet<'a> {
        Self::default()
    }

    /// Add a socket to the set, and return its handle.
    pub fn add<T: AnySocket<'a>>(&mut self, socket: T) -> SocketHandle {
        let handle = SocketHandle(self.next_id);
        self.next_id += 1;
        net_trace!("[{}]: adding", handle.0);

        let mut meta = Meta::default();
        meta.handle = handle;
        let item = Item {
            meta,
            socket: socket.upcast(),
        };
        let evicted = self.sockets.insert(handle.0, item);
        debug_assert!(evicted.is_none(), "socket handles must not repeat");
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
            let handles: Vec<_> = (0..256).map(|_| set.add(socket())).collect();
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

    /// A handle is never reused: a socket added after a removal gets a fresh
    /// value, so a handle held past its socket's life cannot alias the
    /// newcomer.
    #[test]
    fn handles_are_never_reused() {
        let mut set = SocketSet::new();
        let first = set.add(socket());
        set.remove(first);
        let second = set.add(socket());

        assert_ne!(first, second);
        let _ = set.get::<tcp::Socket>(second);
    }

    /// A long-lived socket keeps its handle valid while a burst churns
    /// through around it.
    #[test]
    fn a_survivor_keeps_its_handle() {
        let mut set = SocketSet::new();
        let keeper = set.add(socket());
        let burst: Vec<_> = (0..255).map(|_| set.add(socket())).collect();
        for handle in burst {
            set.remove(handle);
        }

        assert_eq!(set.sockets.len(), 1);
        let _ = set.get::<tcp::Socket>(keeper);
    }
}
