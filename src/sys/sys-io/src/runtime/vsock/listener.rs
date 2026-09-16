use std::{collections::VecDeque, io::ErrorKind};

pub(crate) const BACKLOG: usize = 8;

/// Bounded secondary ordering for common-map sockets awaiting application
/// accept. Socket state and client authority remain in the common owner map.
pub(crate) struct ListenerState {
    children: VecDeque<u64>,
}

impl ListenerState {
    pub(crate) fn new() -> std::io::Result<Self> {
        let mut children = VecDeque::new();
        children
            .try_reserve_exact(BACKLOG)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        Ok(Self { children })
    }

    pub(crate) fn has_capacity(&self) -> bool {
        self.children.len() < BACKLOG
    }

    pub(crate) fn push(&mut self, socket_id: u64) {
        assert!(self.has_capacity());
        assert!(!self.children.contains(&socket_id));
        self.children.push_back(socket_id);
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
}

impl Drop for ListenerState {
    fn drop(&mut self) {
        assert!(self.children.is_empty());
    }
}
