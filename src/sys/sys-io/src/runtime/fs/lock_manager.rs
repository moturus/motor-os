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
            // `entries` is a hint, not an index: `release` prunes it only for
            // the connection doing the releasing, so an entry can outlive the
            // locks it names. Having nothing to drop is a no-op, not an error.
            let Some(file) = self.files.get_mut(&entry) else {
                continue;
            };
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

    /// Give back the slot a waiter took against [`MAX_QUEUED_PER_CONNECTION`].
    ///
    /// A queued waiter always has live `ConnectionLocks`: `disconnect` drops a
    /// connection's waiters and its bookkeeping together. That is an invariant
    /// of this module rather than anything a client can steer, so a mismatch is
    /// logged instead of asserted -- sys-io is `panic = "abort"`, and one lost
    /// queue slot is cheaper than losing the filesystem and networking.
    fn release_queue_slot(
        connections: &mut HashMap<ConnectionId, ConnectionLocks>,
        connection: ConnectionId,
    ) {
        match connections.get_mut(&connection) {
            Some(locks) if locks.queued > 0 => locks.queued -= 1,
            _ => log::error!("lock_manager: connection {connection} waited without a queue slot"),
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
                Self::release_queue_slot(&mut self.connections, waiter.connection);
                let mode = waiter.mode;
                Self::hold(file, (waiter.connection, waiter.open), mode);
                granted.push(waiter.token);
                if mode == Mode::Shared {
                    while file.waiters.front().is_some_and(|w| w.mode == Mode::Shared) {
                        let waiter = file.waiters.pop_front().unwrap();
                        Self::release_queue_slot(&mut self.connections, waiter.connection);
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

/// These ran nowhere before: they were `#[cfg(test)]`, and sys-io has no
/// reachable `cargo test`. See [`crate::self_test`].
#[cfg(debug_assertions)]
pub(crate) mod self_test {
    use super::*;
    use crate::self_test::{SelfTest, st_assert, st_assert_eq};

    pub(crate) const TESTS: &[SelfTest] = &[
        (
            "fs::lock_manager::compatibility_fifo_and_shared_batching",
            compatibility_fifo_and_shared_batching,
        ),
        (
            "fs::lock_manager::disconnect_releases_and_cancels",
            disconnect_releases_and_cancels,
        ),
        (
            "fs::lock_manager::release_rejects_queued_owner",
            release_rejects_queued_owner,
        ),
        (
            "fs::lock_manager::queued_owner_cannot_queue_twice",
            queued_owner_cannot_queue_twice,
        ),
        (
            "fs::lock_manager::disconnect_tolerates_a_stale_entry",
            disconnect_tolerates_a_stale_entry,
        ),
    ];

    fn compatibility_fifo_and_shared_batching() -> Result<(), String> {
        let mut m = LockManager::default();
        st_assert_eq!(m.acquire(1, 1, 1, Mode::Shared, true, 1), Acquire::Granted);
        st_assert_eq!(m.acquire(1, 2, 2, Mode::Shared, true, 2), Acquire::Granted);
        st_assert_eq!(
            m.acquire(1, 3, 3, Mode::Exclusive, true, 3),
            Acquire::Queued
        );
        st_assert_eq!(
            m.acquire(1, 4, 4, Mode::Shared, false, 4),
            Acquire::WouldBlock
        );
        st_assert_eq!(m.release(1, 1, 1), Ok(vec![]));
        st_assert_eq!(m.release(1, 2, 2), Ok(vec![3]));
        st_assert_eq!(m.acquire(1, 4, 4, Mode::Shared, true, 4), Acquire::Queued);
        st_assert_eq!(m.acquire(1, 5, 5, Mode::Shared, true, 5), Acquire::Queued);
        st_assert_eq!(m.release(1, 3, 3), Ok(vec![4, 5]));
        Ok(())
    }

    fn disconnect_releases_and_cancels() -> Result<(), String> {
        let mut m = LockManager::default();
        st_assert_eq!(
            m.acquire(1, 1, 1, Mode::Exclusive, true, 1),
            Acquire::Granted
        );
        st_assert_eq!(
            m.acquire(1, 2, 2, Mode::Exclusive, true, 2),
            Acquire::Queued
        );
        st_assert_eq!(
            m.acquire(1, 3, 3, Mode::Exclusive, true, 3),
            Acquire::Queued
        );
        st_assert!(m.disconnect(2).is_empty());
        st_assert_eq!(m.disconnect(1), vec![3]);
        st_assert!(m.owns(1, 3, 3));
        Ok(())
    }

    fn release_rejects_queued_owner() -> Result<(), String> {
        let mut m = LockManager::default();
        st_assert_eq!(
            m.acquire(1, 1, 1, Mode::Exclusive, true, 1),
            Acquire::Granted
        );
        st_assert_eq!(
            m.acquire(1, 2, 2, Mode::Exclusive, true, 2),
            Acquire::Queued
        );

        st_assert_eq!(m.release(1, 2, 2), Err(ReleaseError::AcquisitionPending));
        st_assert_eq!(m.release(1, 1, 1), Ok(vec![2]));
        st_assert!(m.owns(1, 2, 2));
        Ok(())
    }

    fn queued_owner_cannot_queue_twice() -> Result<(), String> {
        let mut m = LockManager::default();
        st_assert_eq!(
            m.acquire(1, 1, 1, Mode::Exclusive, true, 1),
            Acquire::Granted
        );
        st_assert_eq!(
            m.acquire(1, 2, 2, Mode::Exclusive, true, 2),
            Acquire::Queued
        );
        st_assert_eq!(
            m.acquire(1, 2, 2, Mode::Shared, true, 3),
            Acquire::AlreadyOwned(3)
        );

        st_assert_eq!(m.release(1, 1, 1), Ok(vec![2]));
        st_assert_eq!(m.release(1, 2, 2), Ok(vec![]));
        st_assert!(!m.owns(1, 2, 2));
        Ok(())
    }

    /// A connection's entry set can name an entry whose locks are already gone.
    /// `disconnect` must skip it and keep going: it used to unwrap, and an
    /// unwrap here aborts sys-io -- filesystem and networking both.
    ///
    /// The state is reached by hand because no client request sequence reaches
    /// it today. That is what makes the branch worth pinning: it guards against
    /// a future caller, so nothing else would catch it regressing.
    fn disconnect_tolerates_a_stale_entry() -> Result<(), String> {
        let mut m = LockManager::default();
        st_assert_eq!(
            m.acquire(1, 1, 1, Mode::Exclusive, true, 1),
            Acquire::Granted
        );
        st_assert_eq!(
            m.acquire(2, 1, 2, Mode::Exclusive, true, 2),
            Acquire::Granted
        );

        m.files.remove(&1);
        st_assert_eq!(m.disconnect(1), vec![]);

        // Entry 2 still got cleaned up: the stale entry was skipped, not fatal.
        st_assert!(!m.owns(2, 1, 2));
        st_assert!(m.files.is_empty());
        st_assert!(m.connections.is_empty());
        Ok(())
    }
}
