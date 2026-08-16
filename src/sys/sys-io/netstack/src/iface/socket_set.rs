use core::fmt;
use managed::ManagedSlice;

use super::socket_meta::Meta;
use crate::socket::{AnySocket, Socket};

/// Opaque struct with space for storing one socket.
///
/// This is public so you can use it to allocate space for storing
/// sockets when creating an Interface.
#[derive(Debug, Default)]
pub struct SocketStorage<'a> {
    inner: Option<Item<'a>>,
}

impl<'a> SocketStorage<'a> {
    pub const EMPTY: Self = Self { inner: None };
}

/// An item of a socket set.
#[derive(Debug)]
pub(crate) struct Item<'a> {
    pub(crate) meta: Meta,
    pub(crate) socket: Socket<'a>,
}

/// A handle, identifying a socket in an Interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SocketHandle(usize);

impl fmt::Display for SocketHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// An extensible set of sockets.
///
/// The lifetime `'a` is used when storing a `Socket<'a>`.  If you're using
/// owned buffers for your sockets (passed in as `Vec`s) you can use
/// `SocketSet<'static>`.
#[derive(Debug)]
pub struct SocketSet<'a> {
    sockets: ManagedSlice<'a, SocketStorage<'a>>,
}

impl<'a> SocketSet<'a> {
    /// Create a socket set using the provided storage.
    pub fn new<SocketsT>(sockets: SocketsT) -> SocketSet<'a>
    where
        SocketsT: Into<ManagedSlice<'a, SocketStorage<'a>>>,
    {
        let sockets = sockets.into();
        SocketSet { sockets }
    }

    /// Add a socket to the set, and return its handle.
    ///
    /// # Panics
    /// This function panics if the storage is fixed-size (not a `Vec`) and is full.
    pub fn add<T: AnySocket<'a>>(&mut self, socket: T) -> SocketHandle {
        fn put<'a>(index: usize, slot: &mut SocketStorage<'a>, socket: Socket<'a>) -> SocketHandle {
            net_trace!("[{}]: adding", index);
            let handle = SocketHandle(index);
            let mut meta = Meta::default();
            meta.handle = handle;
            *slot = SocketStorage {
                inner: Some(Item { meta, socket }),
            };
            handle
        }

        let socket = socket.upcast();

        for (index, slot) in self.sockets.iter_mut().enumerate() {
            if slot.inner.is_none() {
                return put(index, slot, socket);
            }
        }

        match &mut self.sockets {
            ManagedSlice::Borrowed(_) => panic!("adding a socket to a full SocketSet"),
            ManagedSlice::Owned(sockets) => {
                sockets.push(SocketStorage { inner: None });
                let index = sockets.len() - 1;
                put(index, &mut sockets[index], socket)
            }
        }
    }

    /// Get a socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get<T: AnySocket<'a>>(&self, handle: SocketHandle) -> &T {
        match self.sockets[handle.0].inner.as_ref() {
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
        match self.sockets[handle.0].inner.as_mut() {
            Some(item) => T::downcast_mut(&mut item.socket)
                .expect("handle refers to a socket of a wrong type"),
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Remove a socket from the set, without changing its state.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set.
    pub fn remove(&mut self, handle: SocketHandle) -> Socket<'a> {
        net_trace!("[{}]: removing", handle.0);
        let socket = match self.sockets[handle.0].inner.take() {
            Some(item) => item.socket,
            None => panic!("handle does not refer to a valid socket"),
        };
        if handle.0 + 1 == self.sockets.len() {
            self.shrink();
        }
        socket
    }

    /// Give back the storage a departed burst grew.
    ///
    /// Handles are slot indices and sockets store multiple KiB inline, so a
    /// burst of adds doubles this into tens of MB that hole-reuse alone never
    /// returns (a 2k-listener flood left a 16k-slot store, ~48 MB, behind).
    /// Truncating the trailing empty run is the shrink that cannot move a
    /// live slot; it runs only when the tail socket itself was removed, so a
    /// teardown pays for it once per trailing run rather than per remove.
    /// The capacity follows with hysteresis. A long-lived socket parked in a
    /// high slot pins everything below it -- the residual the step 1 store
    /// rework owns.
    fn shrink(&mut self) {
        let ManagedSlice::Owned(sockets) = &mut self.sockets else {
            return;
        };
        let live_end = sockets
            .iter()
            .rposition(|slot| slot.inner.is_some())
            .map_or(0, |index| index + 1);
        sockets.truncate(live_end);
        if sockets.capacity() >= 64 && sockets.len() <= sockets.capacity() / 4 {
            sockets.shrink_to(sockets.len() * 2);
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

    /// Iterate every socket in this set.
    pub(crate) fn items(&self) -> impl Iterator<Item = &Item<'a>> + '_ {
        self.sockets.iter().filter_map(|x| x.inner.as_ref())
    }

    /// Iterate every socket in this set.
    pub(crate) fn items_mut(&mut self) -> impl Iterator<Item = &mut Item<'a>> + '_ {
        self.sockets.iter_mut().filter_map(|x| x.inner.as_mut())
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

    fn storage(set: &SocketSet<'_>) -> (usize, usize) {
        match &set.sockets {
            ManagedSlice::Owned(sockets) => (sockets.len(), sockets.capacity()),
            ManagedSlice::Borrowed(_) => unreachable!(),
        }
    }

    /// A burst's storage goes back when the burst does, in either teardown
    /// order: LIFO removes truncate as they go, FIFO removes leave holes the
    /// final tail remove collapses at once.
    #[test]
    fn a_departed_burst_returns_its_storage() {
        for lifo in [true, false] {
            let mut set = SocketSet::new(vec![]);
            let handles: Vec<_> = (0..256).map(|_| set.add(socket())).collect();
            let (len, capacity) = storage(&set);
            assert_eq!(len, 256);
            assert!(capacity >= 256);

            let order: Vec<_> = if lifo {
                handles.iter().rev().copied().collect()
            } else {
                handles.clone()
            };
            for handle in order {
                set.remove(handle);
            }

            let (len, capacity) = storage(&set);
            assert_eq!(len, 0, "lifo={lifo}");
            assert!(capacity < 64, "lifo={lifo}: capacity {capacity} retained");
        }
    }

    /// A live socket keeps its handle valid across the shrinking around it,
    /// and a survivor in a high slot pins the slots below it -- the recorded
    /// residual -- until it too departs.
    #[test]
    fn shrink_never_moves_a_live_slot() {
        let mut set = SocketSet::new(vec![]);
        let keeper = set.add(socket());
        let burst: Vec<_> = (0..255).map(|_| set.add(socket())).collect();
        let survivor = *burst.last().unwrap();

        for handle in &burst[..254] {
            set.remove(*handle);
        }
        // The survivor holds the tail slot: nothing shrinks under it.
        let (len, _) = storage(&set);
        assert_eq!(len, 256);
        let _ = set.get::<tcp::Socket>(keeper);
        let _ = set.get::<tcp::Socket>(survivor);

        set.remove(survivor);
        let (len, capacity) = storage(&set);
        assert_eq!(len, 1);
        assert!(capacity < 64);
        let _ = set.get::<tcp::Socket>(keeper);
    }
}
