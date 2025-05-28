//! Runtime to support I/O and polling mechanisms.
//!
//! Somewhat similar to Linux's epoll, but supports only edge-triggered events.
//!
//! Note: when an FD is closed "on our side", no HANGUP events are triggered.

use core::any::Any;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use crate::posix;
use crate::posix::PosixFile;
use crate::posix::PosixKind;
use alloc::collections::btree_map::BTreeMap;
use alloc::collections::vec_deque::VecDeque;
use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec::Vec;
use moto_ipc::io_channel;
use moto_rt::poll::Event;
use moto_rt::poll::EventBits;
use moto_rt::poll::Interests;
use moto_rt::poll::Token;
use moto_rt::spinlock::SpinLock;
use moto_rt::ErrorCode;
use moto_rt::RtFd;
use moto_rt::E_BAD_HANDLE;
use moto_rt::E_INVALID_ARGUMENT;
use moto_rt::E_OK;
use moto_rt::E_TIMED_OUT;
use moto_sys::SysHandle;

/// A leaf object that can be waited on.
///
/// Event sources are flat, they either represent sockets (and, later, files)
/// directly, or a user-managed EventObject, which is similar to eventfd in Linux.
/// Event sources are owned by their parent objects (e.g. sockets);
/// but an event source can be added to multiple "Registries" with different tokens.
///
struct EventSourceBase<MaybeBits> {
    // A single object, e.g. a TCP socket, can have multiple FDs, and these
    // FDs can be polled by multiple registries (many-to-many).
    // (Registry ID, SourceFd) -> (Token, Interests, V).
    #[allow(clippy::type_complexity)]
    registries: SpinLock<BTreeMap<(u64, RtFd), (Token, Interests, MaybeBits)>>,
    supported_interests: Interests,
}

impl<MaybeBits> EventSourceBase<MaybeBits> {
    fn new(supported_interests: Interests) -> Self {
        Self {
            registries: SpinLock::new(BTreeMap::new()),
            supported_interests,
        }
    }

    fn add_interests(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
        zero: MaybeBits,
    ) -> Result<(), ErrorCode> {
        if interests & !self.supported_interests != 0 {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let mut registries = self.registries.lock();
        match registries.entry((r_id, source_fd)) {
            alloc::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((token, interests, zero));
            }
            alloc::collections::btree_map::Entry::Occupied(_) => return Err(E_INVALID_ARGUMENT),
        }
        Ok(())
    }

    fn set_interests(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
        zero: MaybeBits,
    ) -> Result<(), ErrorCode> {
        if interests & !self.supported_interests != 0 {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        let mut registries = self.registries.lock();
        if let Some(val) = registries.get_mut(&(r_id, source_fd)) {
            *val = (token, interests, zero);
            Ok(())
        } else {
            Err(E_INVALID_ARGUMENT)
        }
    }

    fn del_interests(&self, r_id: u64, source_fd: RtFd) -> Result<(), ErrorCode> {
        let Some((token, interests, _)) = self.registries.lock().remove(&(r_id, source_fd)) else {
            return Err(E_INVALID_ARGUMENT);
        };

        if let Some(registry) = Option::flatten(REGISTRIES.lock().get(&r_id).map(|r| r.upgrade())) {
            registry.clear_event_bits(token, interests);
        }

        Ok(())
    }

    fn on_closed_locally(&self, source_fd: RtFd) {
        self.registries
            .lock()
            .retain(|&(_, s_fd), _| s_fd != source_fd)
    }
}

// An event source that is managed by an internal I/O thread.
pub struct EventSourceManaged {
    base: EventSourceBase<()>,
    readable_futex: AtomicU32,
    writable_futex: AtomicU32,
}

impl EventSourceManaged {
    const FUTEX_EMPTY: u32 = 0;
    const FUTEX_WAITING: u32 = 1;
    const FUTEX_WAKING: u32 = 2;

    pub fn new(supported_interests: Interests) -> Self {
        Self {
            base: EventSourceBase::new(supported_interests),
            readable_futex: AtomicU32::new(0),
            writable_futex: AtomicU32::new(0),
        }
    }

    pub fn add_interests(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        if REGISTRIES.lock().get(&r_id).is_none() {
            return Err(E_BAD_HANDLE);
        }
        self.base
            .add_interests(r_id, source_fd, token, interests, ())
    }

    pub fn set_interests(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        self.base
            .set_interests(r_id, source_fd, token, interests, ())
    }

    pub fn del_interests(&self, r_id: u64, source_fd: RtFd) -> Result<(), ErrorCode> {
        self.base.del_interests(r_id, source_fd)
    }

    pub fn on_event(&self, events: EventBits) {
        {
            // TODO: call registry.on_event() without holding the mutex.
            let mut dropped_registries = alloc::vec::Vec::new();
            let mut registries = self.base.registries.lock();
            for entry in &*registries {
                let ((r_id, s_fd), (token, interests, _)) = entry;
                // Update interests: *_CLOSED events are always of interest.
                let interests = interests
                    | moto_rt::poll::POLL_READ_CLOSED
                    | moto_rt::poll::POLL_WRITE_CLOSED
                    | moto_rt::poll::POLL_ERROR;
                if interests & events != 0 {
                    if let Some(registry) =
                        Option::flatten(REGISTRIES.lock().get(r_id).map(|r| r.upgrade()))
                    {
                        registry.on_event(*token, interests & events);
                    } else {
                        dropped_registries.push((*r_id, *s_fd));
                    }
                }
            }
            for id in dropped_registries {
                registries.remove(&id);
            }
        }

        if events & moto_rt::poll::POLL_READABLE != 0 {
            Self::wake_futex(&self.readable_futex);
        }
        if events & moto_rt::poll::POLL_WRITABLE != 0 {
            Self::wake_futex(&self.writable_futex);
        }
    }

    fn wake_futex(futex: &AtomicU32) {
        let prev = futex.swap(Self::FUTEX_WAKING, Ordering::AcqRel);
        if prev == Self::FUTEX_EMPTY {
            return;
        }
        moto_rt::futex_wake_all(futex);
    }

    // This is only used internally.
    pub fn wait(&self, interest: Interests, deadline: Option<moto_rt::time::Instant>) {
        let futex: &AtomicU32 = match interest {
            moto_rt::poll::POLL_READABLE => &self.readable_futex,
            moto_rt::poll::POLL_WRITABLE => &self.writable_futex,
            _ => panic!("Bad interest: {interest}"),
        };

        let prev = futex.swap(Self::FUTEX_WAITING, Ordering::AcqRel);
        if prev != Self::FUTEX_EMPTY {
            return;
        }

        let _ = moto_rt::futex_wait(
            futex,
            Self::FUTEX_WAITING,
            deadline.map(|val| val.duration_since(moto_rt::time::Instant::now())),
        );

        // Consume the wakeup.
        let _ = futex.compare_exchange(
            Self::FUTEX_WAKING,
            Self::FUTEX_EMPTY,
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
    }

    pub fn on_closed_locally(&self, source_fd: RtFd) {
        self.base.on_closed_locally(source_fd);
    }
}

pub trait UnmanagedEventSourceHolder: Send + Sync {
    fn check_interests(&self, interests: Interests) -> EventBits;
    fn on_handle_error(&self);
}

// An event source that exposes a wait handle to be managed by runtime here.
pub struct EventSourceUnmanaged {
    wait_handle: SysHandle,
    base: EventSourceBase<EventBits>,
    owner: Weak<dyn UnmanagedEventSourceHolder>,
    closed: AtomicBool,
}

impl EventSourceUnmanaged {
    pub fn new(
        wait_handle: SysHandle,
        owner: Weak<dyn UnmanagedEventSourceHolder>,
        supported_interests: Interests,
    ) -> Arc<Self> {
        Arc::new(Self {
            wait_handle,
            base: EventSourceBase::new(supported_interests),
            owner,
            closed: AtomicBool::new(false),
        })
    }

    pub fn add_interests(
        self: &Arc<Self>,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        let Some(registry) = Option::flatten(REGISTRIES.lock().get(&r_id).map(|r| r.upgrade()))
        else {
            return Err(E_BAD_HANDLE);
        };

        self.base
            .add_interests(r_id, source_fd, token, interests, 0 as EventBits)?;

        registry.add_waiting_handle(self);
        Ok(())
    }

    pub fn set_interests(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        self.base
            .set_interests(r_id, source_fd, token, interests, 0 as EventBits)
    }

    pub fn del_interests(&self, r_id: u64, source_fd: RtFd) -> Result<(), ErrorCode> {
        self.base.del_interests(r_id, source_fd)
    }

    // Called by the owner when an interest becomes false (e.g. !readable).
    pub fn reset_interest(&self, interest: Interests) {
        let mut dropped_registries = alloc::vec::Vec::new();
        let mut registries = self.base.registries.lock();
        for entry in &mut *registries {
            let ((r_id, s_fd), (_token, _interests, events)) = entry;
            if interest & *events != 0 {
                if let Some(Some(registry)) = REGISTRIES.lock().get(r_id).map(|r| r.upgrade()) {
                    *events &= !interest;
                } else {
                    dropped_registries.push((*r_id, *s_fd));
                }
            }
        }
        for id in dropped_registries {
            registries.remove(&id);
        }
    }

    // Called by a woken registry to check if this object's owner has a new event to report.
    // Note that we must convert "level-triggered events" into "edge-triggered events" here.
    fn check_interests_for_registry(&self, reg_id: u64) {
        let mut registries = self.base.registries.lock();
        let mut dropped_registries = alloc::vec::Vec::new();
        for entry in &mut *registries {
            let ((r_id, s_fd), (token, interests, events)) = entry;
            if reg_id != *r_id {
                continue;
            }

            let (token, new_events) = {
                // Any not-yet-reported interests?
                let unreported_interests = *interests & !*events;
                if unreported_interests == 0 {
                    continue;
                }

                let mut new_events = self
                    .owner
                    .upgrade()
                    .unwrap()
                    .check_interests(unreported_interests);
                if new_events == 0 {
                    if self.closed.load(Ordering::Acquire) {
                        if *interests & moto_rt::poll::POLL_READABLE != 0 {
                            new_events |= moto_rt::poll::POLL_READ_CLOSED;
                        }
                        if *interests & moto_rt::poll::POLL_WRITABLE != 0 {
                            new_events |= moto_rt::poll::POLL_WRITE_CLOSED;
                        }

                        if new_events == 0 {
                            continue;
                        }
                    } else {
                        continue;
                    }
                } else {
                    *events |= new_events;
                }

                (*token, new_events)
            };

            if let Some(registry) = REGISTRIES.lock().get(r_id) {
                if let Some(registry) = registry.upgrade() {
                    registry.on_event(token, new_events);
                } else {
                    dropped_registries.push((*r_id, *s_fd));
                }
            } else {
                dropped_registries.push((*r_id, *s_fd));
            }
        }

        for id in dropped_registries {
            registries.remove(&id);
        }
    }

    pub fn on_closed_remotely(&self, leave_tombstones: bool) {
        self.closed.store(true, Ordering::Release);

        let mut registries = BTreeMap::new();
        #[allow(clippy::swap_with_temporary)]
        core::mem::swap(&mut registries, &mut self.base.registries.lock());

        if !leave_tombstones {
            return;
        }

        let mut tombstones = alloc::vec::Vec::new();
        for ((r_id, s_fd), (token, interests, _)) in registries {
            let mut events = 0;
            if interests & moto_rt::poll::POLL_READABLE != 0 {
                events |= moto_rt::poll::POLL_READ_CLOSED;
            }
            if interests & moto_rt::poll::POLL_WRITABLE != 0 {
                events |= moto_rt::poll::POLL_WRITE_CLOSED;
            }

            let event = moto_rt::poll::Event { token, events };
            tombstones.push((r_id, s_fd, event));
        }

        for (r_id, s_fd, tombstone) in tombstones {
            if let Some(registry) =
                Option::flatten(REGISTRIES.lock().get(&r_id).map(|r| r.upgrade()))
            {
                registry.add_tombstone(s_fd, tombstone);
            }
        }
    }

    fn on_handle_error(&self) {
        self.owner.upgrade().unwrap().on_handle_error();
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn on_closed_locally(&self, source_fd: RtFd) {
        self.base.on_closed_locally(source_fd);
    }
}

static REGISTRIES: SpinLock<BTreeMap<u64, Weak<Registry>>> = SpinLock::new(BTreeMap::new());

pub struct Registry {
    id: u64,
    events: SpinLock<BTreeMap<Token, EventBits>>,
    wait_handle: AtomicU64,
    event_source: EventSourceManaged,

    // Pollees like sockets have their own runtime/wakups, and they notify their registries
    // via on_event(). Pollees that don't have their own runtime (e.g. async stdio)
    // have wait handles, and registries have to wait on those to get notifications.
    //
    // Note: a single EventSourceWithHandle may be registered multiple times via
    //       different FDs, so we should be careful re: when to remove the handle.
    unmanaged_sources: SpinLock<BTreeMap<SysHandle, Weak<EventSourceUnmanaged>>>,

    // We need to keep week refs to added sources, otherwise fds are reused and bugs ensue.
    // We also need a way to remove waiting_handle_objects on poll_del (so that no
    // events occur), and we need to keep smth to respond with HANGUP when the file
    // is closed by before poll_del().
    pollees: SpinLock<BTreeMap<RtFd, Weak<dyn PosixFile>>>,

    // When a pollee goes away, it may leave a tombstone here if needed for
    // POLL_READ_CLOSED/POLL_WRITE_CLOSED.
    tombstones: SpinLock<BTreeMap<RtFd, Event>>,
}

impl Drop for Registry {
    fn drop(&mut self) {
        let _ = REGISTRIES.lock().remove(&self.id);
    }
}

impl PosixFile for Registry {
    fn kind(&self) -> PosixKind {
        PosixKind::PollRegistry
    }

    fn poll_add(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        if interests != moto_rt::poll::POLL_READABLE {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        self.event_source
            .add_interests(r_id, source_fd, token, interests)?;
        Ok(())
    }

    fn poll_set(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        if interests != moto_rt::poll::POLL_READABLE {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        self.event_source
            .set_interests(r_id, source_fd, token, interests)?;
        Ok(())
    }

    fn poll_del(&self, r_id: u64, source_fd: RtFd) -> Result<(), ErrorCode> {
        self.event_source.del_interests(r_id, source_fd)
    }

    fn close(&self, rt_fd: RtFd) -> Result<(), ErrorCode> {
        Ok(())
    }
}

impl Registry {
    pub fn new() -> Arc<Self> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

        let result = Arc::new(Self {
            id,
            events: SpinLock::new(BTreeMap::new()),
            wait_handle: AtomicU64::new(SysHandle::NONE.as_u64()),
            event_source: EventSourceManaged::new(moto_rt::poll::POLL_READABLE),
            unmanaged_sources: SpinLock::new(BTreeMap::new()),
            pollees: SpinLock::new(BTreeMap::new()),
            tombstones: SpinLock::new(BTreeMap::new()),
        });

        REGISTRIES.lock().insert(id, Arc::downgrade(&result));
        result
    }

    pub fn add(&self, source_fd: RtFd, token: Token, interests: Interests) -> ErrorCode {
        let Some(posix_file) = posix::get_file(source_fd) else {
            return E_BAD_HANDLE;
        };

        if let Err(err) = posix_file.poll_add(self.id, source_fd, token, interests) {
            err
        } else {
            assert!(self
                .pollees
                .lock()
                .insert(source_fd, Arc::downgrade(&posix_file))
                .is_none());
            E_OK
        }
    }

    pub fn set(&self, source_fd: RtFd, token: Token, interests: Interests) -> ErrorCode {
        let Some(posix_file) = self.pollees.lock().get(&source_fd).cloned() else {
            return E_BAD_HANDLE;
        };

        let Some(posix_file) = posix_file.upgrade() else {
            return E_BAD_HANDLE;
        };

        if let Err(err) = posix_file.poll_set(self.id, source_fd, token, interests) {
            err
        } else {
            E_OK
        }
    }

    pub fn del(&self, source_fd: RtFd) -> ErrorCode {
        let Some(posix_file) = self.pollees.lock().remove(&source_fd) else {
            return E_BAD_HANDLE;
        };

        let _ = self.tombstones.lock().remove(&source_fd);

        let Some(posix_file) = posix_file.upgrade() else {
            return E_OK;
        };

        if let Err(err) = posix_file.poll_del(self.id, source_fd) {
            err
        } else {
            E_OK
        }
    }

    fn clear_event_bits(&self, token: Token, event_bits: EventBits) {
        let mut events = self.events.lock();
        if let alloc::collections::btree_map::Entry::Occupied(mut entry) = events.entry(token) {
            *entry.get_mut() &= !event_bits;
            if *entry.get() == 0 {
                entry.remove();
            }
        }
    }

    fn add_waiting_handle(&self, waiting_handle: &Arc<EventSourceUnmanaged>) {
        // Note: the registry may already have this ref (multiple FDs can ref the same obj).
        self.unmanaged_sources
            .lock()
            .insert(waiting_handle.wait_handle, Arc::downgrade(waiting_handle));
    }

    pub fn wake(&self) -> ErrorCode {
        self.event_source.on_event(moto_rt::poll::POLL_READABLE);
        E_OK
    }

    pub fn wait(&self, events_buf: &mut [Event], deadline: Option<moto_rt::time::Instant>) -> i32 {
        if events_buf.is_empty() {
            return 0;
        }

        let mut wait_handles = Vec::new();
        loop {
            {
                // If there are tombstones, just return them.
                let mut idx = 0;
                // for entry in self.tombstones.lock().values() {
                while let Some((_, entry)) = self.tombstones.lock().pop_first() {
                    events_buf[idx] = entry;
                    idx += 1;
                    if idx >= events_buf.len() {
                        break;
                    }
                }

                if idx > 0 {
                    return idx as i32;
                }
            }

            // Prepare wait handles.
            {
                wait_handles.clear();
                let mut waiting_handle_objects = self.unmanaged_sources.lock();
                let mut dropped_handles = alloc::vec::Vec::new();

                for (handle, obj) in &*waiting_handle_objects {
                    if let Some(obj) = obj.upgrade() {
                        obj.check_interests_for_registry(self.id);
                        wait_handles.push(*handle);
                    } else {
                        dropped_handles.push(*handle);
                    }
                }

                for handle in dropped_handles {
                    waiting_handle_objects.remove(&handle);
                }
            }

            // We must store the handle before we check self.events,
            // otherwise we may lose a concurrently happening wakeup.
            self.wait_handle.store(
                moto_sys::UserThreadControlBlock::get().self_handle,
                Ordering::Release,
            );

            if !self.events.lock().is_empty() {
                self.wait_handle
                    .store(SysHandle::NONE.as_u64(), Ordering::Release);
                break;
            }

            let result = moto_sys::SysCpu::wait(
                wait_handles.as_mut_slice(),
                SysHandle::NONE,
                SysHandle::NONE,
                deadline,
            );
            // Need to clear self.wait_handle so that on_event(), when called from
            // check_interests_for_registry(), does not try to wake the current thread.
            self.wait_handle
                .store(SysHandle::NONE.as_u64(), Ordering::Release);

            if let Err(moto_rt::E_BAD_HANDLE) = result {
                // The first object is the bad handle.
                assert!(!wait_handles.is_empty());
                let bad_handle = wait_handles[0];
                let obj = self.unmanaged_sources.lock().remove(&bad_handle).unwrap();

                if let Some(obj) = obj.upgrade() {
                    obj.on_handle_error();
                    obj.check_interests_for_registry(self.id);
                }
            } else if let Err(moto_rt::E_TIMED_OUT) = result {
                if !self.events.lock().is_empty() {
                    break;
                }

                // MIO docs for poll() say that upon timeout poll() returns OK(()),
                // and MIO tests (specifically tcp::listen_then_close() rely on this).
                return 0; // -(E_TIMED_OUT as i32);
            } else {
                for handle in &wait_handles {
                    if *handle == SysHandle::NONE {
                        break;
                    }

                    let obj = self.unmanaged_sources.lock().get(handle).unwrap().clone();

                    if let Some(obj) = obj.upgrade() {
                        obj.check_interests_for_registry(self.id);
                    } else {
                        self.unmanaged_sources.lock().remove(handle);
                    }
                }
            }

            if !self.events.lock().is_empty() {
                break;
            }
        }

        let mut events = self.events.lock();
        let mut idx = 0;
        while idx < events_buf.len() {
            let Some((token, bits)) = events.pop_first() else {
                break;
            };
            let entry = &mut events_buf[idx];
            entry.token = token;
            entry.events = bits;
            idx += 1;
        }

        idx as i32
    }

    fn on_event(&self, token: Token, event_bits: EventBits) {
        self.events
            .lock()
            .entry(token)
            .and_modify(|curr| *curr |= event_bits)
            .or_insert(event_bits);

        let handle = SysHandle::from_u64(self.wait_handle.load(Ordering::Acquire));
        if handle != SysHandle::NONE {
            let _ = moto_sys::SysCpu::wake(handle);
        }
    }

    fn add_tombstone(&self, source_fd: RtFd, tombstone: Event) {
        self.tombstones.lock().insert(source_fd, tombstone);
        let handle = SysHandle::from_u64(self.wait_handle.load(Ordering::Acquire));
        if handle != SysHandle::NONE {
            let _ = moto_sys::SysCpu::wake(handle);
        }
    }
}
