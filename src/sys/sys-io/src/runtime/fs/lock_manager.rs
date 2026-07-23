use std::collections::{HashMap, HashSet, VecDeque};

pub type ConnectionId = u64;
pub type OpenId = u64;
pub type EntryId = u128;

const MAX_QUEUED_PER_CONNECTION: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Shared,
    Exclusive,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Acquire<T> {
    Granted,
    WouldBlock,
    Queued,
    AlreadyOwned(T),
    QueueFull(T),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseError {
    AcquisitionPending,
}

struct Waiter<T> {
    connection: ConnectionId,
    open: OpenId,
    mode: Mode,
    token: T,
}

struct FileLocks<T> {
    exclusive: Option<(ConnectionId, OpenId)>,
    shared: HashSet<(ConnectionId, OpenId)>,
    waiters: VecDeque<Waiter<T>>,
}

impl<T> Default for FileLocks<T> {
    fn default() -> Self {
        Self {
            exclusive: None,
            shared: HashSet::new(),
            waiters: VecDeque::new(),
        }
    }
}

pub struct LockManager<T> {
    files: HashMap<EntryId, FileLocks<T>>,
    connections: HashMap<ConnectionId, ConnectionLocks>,
}

#[derive(Default)]
struct ConnectionLocks {
    entries: HashSet<EntryId>,
    queued: usize,
}

impl<T> Default for LockManager<T> {
    fn default() -> Self {
        Self {
            files: HashMap::new(),
            connections: HashMap::new(),
        }
    }
}

impl<T> LockManager<T> {
    pub fn acquire(
        &mut self,
        entry: EntryId,
        connection: ConnectionId,
        open: OpenId,
        mode: Mode,
        blocking: bool,
        token: T,
    ) -> Acquire<T> {
        let owner = (connection, open);
        let file = self.files.entry(entry).or_default();
        if file.exclusive == Some(owner)
            || file.shared.contains(&owner)
            || file
                .waiters
                .iter()
                .any(|waiter| (waiter.connection, waiter.open) == owner)
        {
            return Acquire::AlreadyOwned(token);
        }
        let compatible = file.waiters.is_empty()
            && file.exclusive.is_none()
            && (mode == Mode::Shared || file.shared.is_empty());
        if compatible {
            Self::hold(file, owner, mode);
            self.connections
                .entry(connection)
                .or_default()
                .entries
                .insert(entry);
            return Acquire::Granted;
        }
        if !blocking {
            return Acquire::WouldBlock;
        }
        let connection_locks = self.connections.entry(connection).or_default();
        if connection_locks.queued == MAX_QUEUED_PER_CONNECTION {
            return Acquire::QueueFull(token);
        }
        connection_locks.queued += 1;
        connection_locks.entries.insert(entry);
        file.waiters.push_back(Waiter {
            connection,
            open,
            mode,
            token,
        });
        Acquire::Queued
    }

    pub fn owns(&self, entry: EntryId, connection: ConnectionId, open: OpenId) -> bool {
        self.files.get(&entry).is_some_and(|file| {
            file.exclusive == Some((connection, open)) || file.shared.contains(&(connection, open))
        })
    }

    pub fn release(
        &mut self,
        entry: EntryId,
        connection: ConnectionId,
        open: OpenId,
    ) -> Result<Vec<T>, ReleaseError> {
        let Some(file) = self.files.get_mut(&entry) else {
            return Ok(Vec::new());
        };
        let owner = (connection, open);
        if file
            .waiters
            .iter()
            .any(|waiter| (waiter.connection, waiter.open) == owner)
        {
            return Err(ReleaseError::AcquisitionPending);
        }
        if file.exclusive == Some(owner) {
            file.exclusive = None;
        } else {
            file.shared.remove(&owner);
        }
        let granted = self.grant(entry);
        self.remove_inactive_connection_entry(entry, connection);
        Ok(granted)
    }

    pub fn disconnect(&mut self, connection: ConnectionId) -> Vec<T> {
        let Some(connection_locks) = self.connections.remove(&connection) else {
            return Vec::new();
        };
        let mut granted = Vec::new();
        for entry in connection_locks.entries {
            let file = self.files.get_mut(&entry).unwrap();
            if file.exclusive.is_some_and(|owner| owner.0 == connection) {
                file.exclusive = None;
            }
            file.shared.retain(|owner| owner.0 != connection);
            file.waiters
                .retain(|waiter| waiter.connection != connection);
            granted.extend(self.grant(entry));
        }
        granted
    }

    fn hold(file: &mut FileLocks<T>, owner: (ConnectionId, OpenId), mode: Mode) {
        match mode {
            Mode::Shared => {
                file.shared.insert(owner);
            }
            Mode::Exclusive => file.exclusive = Some(owner),
        }
    }

    fn grant(&mut self, entry: EntryId) -> Vec<T> {
        let mut granted = Vec::new();
        let mut remove = false;
        if let Some(file) = self.files.get_mut(&entry) {
            if file.exclusive.is_none()
                && file.shared.is_empty()
                && let Some(waiter) = file.waiters.pop_front()
            {
                self.connections.get_mut(&waiter.connection).unwrap().queued -= 1;
                let mode = waiter.mode;
                Self::hold(file, (waiter.connection, waiter.open), mode);
                granted.push(waiter.token);
                if mode == Mode::Shared {
                    while file.waiters.front().is_some_and(|w| w.mode == Mode::Shared) {
                        let waiter = file.waiters.pop_front().unwrap();
                        self.connections.get_mut(&waiter.connection).unwrap().queued -= 1;
                        Self::hold(file, (waiter.connection, waiter.open), Mode::Shared);
                        granted.push(waiter.token);
                    }
                }
            }
            remove = file.exclusive.is_none() && file.shared.is_empty() && file.waiters.is_empty();
        }
        if remove {
            self.files.remove(&entry);
        }
        granted
    }

    fn remove_inactive_connection_entry(&mut self, entry: EntryId, connection: ConnectionId) {
        let active = self.files.get(&entry).is_some_and(|file| {
            file.exclusive.is_some_and(|owner| owner.0 == connection)
                || file.shared.iter().any(|owner| owner.0 == connection)
                || file
                    .waiters
                    .iter()
                    .any(|waiter| waiter.connection == connection)
        });
        if !active && let Some(locks) = self.connections.get_mut(&connection) {
            locks.entries.remove(&entry);
            if locks.entries.is_empty() {
                self.connections.remove(&connection);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_fifo_and_shared_batching() {
        let mut m = LockManager::default();
        assert_eq!(m.acquire(1, 1, 1, Mode::Shared, true, 1), Acquire::Granted);
        assert_eq!(m.acquire(1, 2, 2, Mode::Shared, true, 2), Acquire::Granted);
        assert_eq!(
            m.acquire(1, 3, 3, Mode::Exclusive, true, 3),
            Acquire::Queued
        );
        assert_eq!(
            m.acquire(1, 4, 4, Mode::Shared, false, 4),
            Acquire::WouldBlock
        );
        assert_eq!(m.release(1, 1, 1), Ok(vec![]));
        assert_eq!(m.release(1, 2, 2), Ok(vec![3]));
        assert_eq!(m.acquire(1, 4, 4, Mode::Shared, true, 4), Acquire::Queued);
        assert_eq!(m.acquire(1, 5, 5, Mode::Shared, true, 5), Acquire::Queued);
        assert_eq!(m.release(1, 3, 3), Ok(vec![4, 5]));
    }

    #[test]
    fn disconnect_releases_and_cancels() {
        let mut m = LockManager::default();
        assert_eq!(
            m.acquire(1, 1, 1, Mode::Exclusive, true, 1),
            Acquire::Granted
        );
        assert_eq!(
            m.acquire(1, 2, 2, Mode::Exclusive, true, 2),
            Acquire::Queued
        );
        assert_eq!(
            m.acquire(1, 3, 3, Mode::Exclusive, true, 3),
            Acquire::Queued
        );
        assert!(m.disconnect(2).is_empty());
        assert_eq!(m.disconnect(1), vec![3]);
        assert!(m.owns(1, 3, 3));
    }

    #[test]
    fn release_rejects_queued_owner() {
        let mut m = LockManager::default();
        assert_eq!(
            m.acquire(1, 1, 1, Mode::Exclusive, true, 1),
            Acquire::Granted
        );
        assert_eq!(
            m.acquire(1, 2, 2, Mode::Exclusive, true, 2),
            Acquire::Queued
        );

        assert_eq!(m.release(1, 2, 2), Err(ReleaseError::AcquisitionPending));
        assert_eq!(m.release(1, 1, 1), Ok(vec![2]));
        assert!(m.owns(1, 2, 2));
    }

    #[test]
    fn queued_owner_cannot_queue_twice() {
        let mut m = LockManager::default();
        assert_eq!(
            m.acquire(1, 1, 1, Mode::Exclusive, true, 1),
            Acquire::Granted
        );
        assert_eq!(
            m.acquire(1, 2, 2, Mode::Exclusive, true, 2),
            Acquire::Queued
        );
        assert_eq!(
            m.acquire(1, 2, 2, Mode::Shared, true, 3),
            Acquire::AlreadyOwned(3)
        );

        assert_eq!(m.release(1, 1, 1), Ok(vec![2]));
        assert_eq!(m.release(1, 2, 2), Ok(vec![]));
        assert!(!m.owns(1, 2, 2));
    }
}
