//! Runtime to support I/O and polling mechanisms.
//!
//! Somewhat similar to Linux's epoll, but supports only edge-triggered events.

use core::any::Any;
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

pub trait ResponseHandler {
    fn on_response(&self, resp: io_channel::Msg);
}

/// A leaf object that can be waited on.
///
/// Wait objects are flat, they either represent sockets (and, later, files)
/// directly, or a user-managed EventObject, which is similar to eventfd in Linux.
/// Wait objects are owned by their parent objects (e.g. sockets);
/// but a wait object can be added to multiple "Registries" with different tokens.
pub struct WaitObject {
    // Registry ID -> (Token, Interests).
    // TODO: is there a way to go from Arc<dyn PosixFile> to Arc<Registry>?
    // If so, then we can have Weak<Registry> below.
    #[allow(clippy::type_complexity)]
    registries: SpinLock<BTreeMap<u64, (Token, Interests)>>,

    readable_futex: AtomicU32,
    writable_futex: AtomicU32,

    supported_interests: Interests,
}

impl Drop for WaitObject {
    fn drop(&mut self) {
        // MIO test tcp::test_listen_then_close() panics if an event
        // is received for dropped TCP Listener.
        // self.on_event(moto_rt::poll::POLL_READ_CLOSED | moto_rt::poll::POLL_WRITE_CLOSED);
    }
}

impl WaitObject {
    const FUTEX_EMPTY: u32 = 0;
    const FUTEX_WAITING: u32 = 1;
    const FUTEX_WAKING: u32 = 2;

    pub fn new(supported_interests: Interests) -> Self {
        Self {
            registries: SpinLock::new(BTreeMap::new()),
            readable_futex: AtomicU32::new(0),
            writable_futex: AtomicU32::new(0),
            supported_interests,
        }
    }

    pub fn add_interests(
        &self,
        r_id: u64,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        if interests & !self.supported_interests != 0 {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        if REGISTRIES.lock().get(&r_id).is_none() {
            return Err(E_BAD_HANDLE);
        }

        let mut registries = self.registries.lock();
        match registries.entry(r_id) {
            alloc::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((token, interests));
            }
            alloc::collections::btree_map::Entry::Occupied(_) => return Err(E_INVALID_ARGUMENT),
        }

        Ok(())
    }

    pub fn set_interests(
        &self,
        r_id: u64,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        if interests & !self.supported_interests != 0 {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        let mut registries = self.registries.lock();
        if let Some(val) = registries.get_mut(&r_id) {
            *val = (token, interests);
            Ok(())
        } else {
            Err(E_INVALID_ARGUMENT)
        }
    }

    pub fn del_interests(&self, r_id: u64) -> Result<(), ErrorCode> {
        let Some((token, interests)) = self.registries.lock().remove(&r_id) else {
            return Err(E_INVALID_ARGUMENT);
        };

        if let Some(registry) = Option::flatten(REGISTRIES.lock().get(&r_id).map(|r| r.upgrade())) {
            registry.clear_event_bits(token, interests);
        }

        Ok(())
    }

    pub fn on_event(&self, events: EventBits) {
        {
            // TODO: call registry.on_event() without holding the mutex.
            let mut dropped_registries = alloc::vec::Vec::new();
            let mut registries = self.registries.lock();
            for entry in &*registries {
                let (registry_id, (token, interests)) = entry;
                // Update interests: *_CLOSED events are always of interest.
                let interests = interests
                    | moto_rt::poll::POLL_READ_CLOSED
                    | moto_rt::poll::POLL_WRITE_CLOSED
                    | moto_rt::poll::POLL_ERROR;
                if interests & events != 0 {
                    if let Some(registry) =
                        Option::flatten(REGISTRIES.lock().get(registry_id).map(|r| r.upgrade()))
                    {
                        registry.on_event(*token, interests & events);
                    } else {
                        dropped_registries.push(*registry_id);
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
}

pub trait WaitHandleHolder: Send + Sync {
    // Returns true is the interests is satisfied (e.g. readable).
    fn check_interests(&self, interests: Interests) -> EventBits;
}

// WaitObjects above are used in sys-io-related entities like sockets, as
// the IO thread will trigger events. But some object, e.g. stdio, have
// wait handles that should be waited on, and have to convert their own
// "level" events (readable/writable) into needed "edge" events (newly
// readable, newly writable).
pub struct WaitingHandle {
    wait_handle: SysHandle,
    owner: Weak<dyn WaitHandleHolder>,

    // Registry ID -> (Token, Interests, EventBits).
    // EventBits below contain events that the registry has been notified
    // about and thus should not be notified again.
    //
    // TODO: is there a way to go from Arc<dyn PosixFile> to Arc<Registry>?
    // If so, then we can have Weak<Registry> below.
    #[allow(clippy::type_complexity)]
    registries: SpinLock<BTreeMap<u64, (Token, Interests, EventBits)>>,

    supported_interests: Interests,
    this: Weak<Self>,
}

impl Drop for WaitingHandle {
    fn drop(&mut self) {
        loop {
            let Some((r_id, (token, interests, event_bits))) = self.registries.lock().pop_first()
            else {
                break;
            };
            self.check_interests_for_registry(r_id);
        }
    }
}

impl WaitingHandle {
    pub fn new(
        wait_handle: SysHandle,
        owner: Weak<dyn WaitHandleHolder>,
        supported_interests: Interests,
    ) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            wait_handle,
            owner,
            registries: SpinLock::new(BTreeMap::new()),
            supported_interests,
            this: me.clone(),
        })
    }

    pub fn add_interests(
        &self,
        r_id: u64,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        if interests & !self.supported_interests != 0 {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        if let Some(registry) = Option::flatten(REGISTRIES.lock().get(&r_id).map(|r| r.upgrade())) {
            registry.add_waiting_handle(self);
        } else {
            return Err(E_BAD_HANDLE);
        }

        let mut registries = self.registries.lock();
        match registries.entry(r_id) {
            alloc::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((token, interests, 0));
            }
            alloc::collections::btree_map::Entry::Occupied(_) => return Err(E_INVALID_ARGUMENT),
        }

        Ok(())
    }

    pub fn set_interests(
        &self,
        r_id: u64,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        if interests & !self.supported_interests != 0 {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        let mut registries = self.registries.lock();
        if let Some(val) = registries.get_mut(&r_id) {
            *val = (token, interests, 0);
            Ok(())
        } else {
            Err(E_INVALID_ARGUMENT)
        }
    }

    pub fn del_interests(&self, r_id: u64) -> Result<(), ErrorCode> {
        let Some((token, interests, _)) = self.registries.lock().remove(&r_id) else {
            return Err(E_INVALID_ARGUMENT);
        };

        if let Some(registry) = Option::flatten(REGISTRIES.lock().get(&r_id).map(|r| r.upgrade())) {
            registry.clear_event_bits(token, interests);
            registry.del_waiting_handle(self);
        } else {
            return Err(E_INVALID_ARGUMENT);
        }

        Ok(())
    }

    // Called by the owner when an interest becomes false (e.g. !readable).
    pub fn reset_interest(&self, interest: Interests) {
        let mut dropped_registries = alloc::vec::Vec::new();
        let mut registries = self.registries.lock();
        for entry in &mut *registries {
            let (registry_id, (token, interests, events)) = entry;
            if interest & *events != 0 {
                if let Some(Some(registry)) =
                    REGISTRIES.lock().get(registry_id).map(|r| r.upgrade())
                {
                    *events &= !interest;
                } else {
                    dropped_registries.push(*registry_id);
                }
            }
        }
        for id in dropped_registries {
            registries.remove(&id);
        }
    }

    // Called by a woken registry to check if this object's owner has a new event to report.
    fn check_interests_for_registry(&self, r_id: u64) {
        let (token, new_events) = {
            let mut registries = self.registries.lock();
            let Some((token, interests, events)) = registries.get_mut(&r_id) else {
                return;
            };

            // Any not-yet-reported interests?
            let unreported_interests = *interests & !*events;
            if unreported_interests == 0 {
                return;
            }
            let Some(owner) = self.owner.upgrade() else {
                return;
            };
            let new_events = owner.check_interests(unreported_interests);
            if new_events == 0 {
                return;
            }

            *events |= new_events;
            (*token, new_events)
        };

        if let Some(registry) = REGISTRIES.lock().get(&r_id) {
            if let Some(registry) = registry.upgrade() {
                registry.on_event(token, new_events);
            } else {
                panic!()
            }
        } else {
            panic!();
        }
    }
}

static REGISTRIES: SpinLock<BTreeMap<u64, Weak<Registry>>> = SpinLock::new(BTreeMap::new());

pub struct Registry {
    id: u64,
    events: SpinLock<BTreeMap<Token, EventBits>>,
    wait_handle: AtomicU64,
    wait_object: WaitObject,

    waiting_handle_objects: SpinLock<BTreeMap<SysHandle, Weak<WaitingHandle>>>,
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

    fn poll_add(&self, r_id: u64, token: Token, interests: Interests) -> Result<(), ErrorCode> {
        if interests != moto_rt::poll::POLL_READABLE {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        self.wait_object.add_interests(r_id, token, interests)?;
        Ok(())
    }

    fn poll_set(&self, r_id: u64, token: Token, interests: Interests) -> Result<(), ErrorCode> {
        if interests != moto_rt::poll::POLL_READABLE {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        self.wait_object.set_interests(r_id, token, interests)?;
        Ok(())
    }

    fn poll_del(&self, r_id: u64) -> Result<(), ErrorCode> {
        self.wait_object.del_interests(r_id)
    }

    fn close(&self) -> Result<(), ErrorCode> {
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
            wait_object: WaitObject::new(moto_rt::poll::POLL_READABLE),
            waiting_handle_objects: SpinLock::new(BTreeMap::new()),
        });

        REGISTRIES.lock().insert(id, Arc::downgrade(&result));
        result
    }

    pub fn add(&self, source_fd: RtFd, token: Token, interests: Interests) -> ErrorCode {
        let Some(posix_file) = posix::get_file(source_fd) else {
            return E_BAD_HANDLE;
        };

        if let Err(err) = posix_file.poll_add(self.id, token, interests) {
            err
        } else {
            E_OK
        }
    }

    pub fn set(&self, source_fd: RtFd, token: Token, interests: Interests) -> ErrorCode {
        let Some(posix_file) = posix::get_file(source_fd) else {
            return E_BAD_HANDLE;
        };

        if let Err(err) = posix_file.poll_set(self.id, token, interests) {
            err
        } else {
            E_OK
        }
    }

    pub fn del(&self, source_fd: RtFd) -> ErrorCode {
        let Some(posix_file) = posix::get_file(source_fd) else {
            return E_BAD_HANDLE;
        };

        if let Err(err) = posix_file.poll_del(self.id) {
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

    fn add_waiting_handle(&self, waiting_handle: &WaitingHandle) {
        self.waiting_handle_objects
            .lock()
            .insert(waiting_handle.wait_handle, waiting_handle.this.clone());
    }

    fn del_waiting_handle(&self, waiting_handle: &WaitingHandle) {
        self.waiting_handle_objects
            .lock()
            .remove(&waiting_handle.wait_handle);
    }

    pub fn wake(&self) -> ErrorCode {
        self.wait_object.on_event(moto_rt::poll::POLL_READABLE);
        E_OK
    }

    pub fn wait(&self, events_buf: &mut [Event], deadline: Option<moto_rt::time::Instant>) -> i32 {
        let mut wait_handles = Vec::new();
        let mut gone_wait_handles = Vec::new();
        loop {
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

            // Prepare wait handles.
            {
                wait_handles.clear();
                gone_wait_handles.clear();
                let mut waiting_handle_objects = self.waiting_handle_objects.lock();
                for (handle, weak_pointer) in &*waiting_handle_objects {
                    if weak_pointer.strong_count() > 0 {
                        wait_handles.push(*handle);
                    } else {
                        gone_wait_handles.push(*handle);
                    }
                }
                for handle in &gone_wait_handles {
                    waiting_handle_objects.remove(handle);
                }
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
                if let Some(obj) = Option::flatten(
                    self.waiting_handle_objects
                        .lock()
                        .remove(&bad_handle)
                        .map(|o| o.upgrade()),
                ) {
                    obj.check_interests_for_registry(self.id);
                }
                continue;
            }
            for handle in &wait_handles {
                if *handle == SysHandle::NONE {
                    break;
                }

                let Some(obj) = Option::flatten(
                    self.waiting_handle_objects
                        .lock()
                        .get(handle)
                        .map(|o| o.upgrade()),
                ) else {
                    self.waiting_handle_objects.lock().remove(handle);
                    continue;
                };

                obj.check_interests_for_registry(self.id);
            }

            if !self.events.lock().is_empty() {
                break;
            }

            if let Some(deadline) = deadline {
                if deadline <= moto_rt::time::Instant::now() {
                    // MIO docs for poll() say that upon timeout poll() returns OK(()),
                    // and MIO tests (specifically tcp::listen_then_close() rely on this).
                    return 0; // -(E_TIMED_OUT as i32);
                }
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
}
