use std::{collections::VecDeque, io::ErrorKind};

pub(crate) const BACKLOG: usize = 8;
pub(crate) const MAX_PENDING_ACCEPTS: usize = 8;

/// Bounded secondary ordering for common-map sockets awaiting application
/// accept. `accepts` contains only calls still waiting for a child; matched
/// replies remain in the common map under the global stream/control bounds.
/// All socket/client authority remains in that common owner map.
pub(crate) struct ListenerState<T = ()> {
    children: VecDeque<u64>,
    accepts: VecDeque<T>,
}

impl<T> ListenerState<T> {
    pub(crate) fn new() -> std::io::Result<Self> {
        let mut children = VecDeque::new();
        children
            .try_reserve_exact(BACKLOG)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        let mut accepts = VecDeque::new();
        accepts
            .try_reserve_exact(MAX_PENDING_ACCEPTS)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        Ok(Self { children, accepts })
    }

    pub(crate) fn has_capacity(&self) -> bool {
        self.children.len() < BACKLOG
    }

    pub(crate) fn push(&mut self, socket_id: u64) -> Option<T> {
        if let Some(accept) = self.accepts.pop_front() {
            return Some(accept);
        }
        assert!(self.has_capacity());
        assert!(!self.children.contains(&socket_id));
        self.children.push_back(socket_id);
        None
    }

    pub(crate) fn pop(&mut self) -> Option<u64> {
        self.children.pop_front()
    }

    pub(crate) fn remove(&mut self, socket_id: u64) -> bool {
        let Some(index) = self.children.iter().position(|id| *id == socket_id) else {
            return false;
        };
        self.children.remove(index);
        true
    }

    pub(crate) fn enqueue_accept(&mut self, pending: T) -> Result<(), ()> {
        if self.accepts.len() == MAX_PENDING_ACCEPTS {
            return Err(());
        }
        self.accepts.push_back(pending);
        Ok(())
    }

    pub(crate) fn take_accepts(&mut self) -> VecDeque<T> {
        std::mem::take(&mut self.accepts)
    }

    pub(crate) fn remove_accept(&mut self, remove: impl Fn(&T) -> bool) -> Option<T> {
        let index = self.accepts.iter().position(remove)?;
        self.accepts.remove(index)
    }
}

impl<T> Drop for ListenerState<T> {
    fn drop(&mut self) {
        assert!(self.children.is_empty());
        assert!(self.accepts.is_empty());
    }
}
