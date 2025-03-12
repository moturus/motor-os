//! Runtime to support I/O and polling mechanisms.
//!
//! Somewhat similar to Linux's epoll, but supports only edge-triggered events.

use core::any::Any;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use crate::posix;
use crate::posix::PosixFile;
use alloc::collections::btree_map::BTreeMap;
use alloc::sync::Arc;
use alloc::sync::Weak;
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
}

impl Drop for WaitObject {
    fn drop(&mut self) {
        // MIO test tcp::test_listen_then_close() panics if an event
        // is received for dropped TCP Listener.
        // self.on_event(moto_rt::poll::POLL_READ_CLOSED | moto_rt::poll::POLL_WRITE_CLOSED);
    }
}

impl WaitObject {
    pub fn new(supported_interests: Interests) -> Self {
        Self {
            registries: SpinLock::new(BTreeMap::new()),
        }
    }

    pub fn add_interests(
        &self,
        r_id: u64,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
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
        let mut registries = self.registries.lock();
        if let Some(val) = registries.get_mut(&r_id) {
            *val = (token, interests);
            Ok(())
        } else {
            Err(E_INVALID_ARGUMENT)
        }
    }

    pub fn del_interests(&self, r_id: u64) -> Result<(), ErrorCode> {
        self.registries
            .lock()
            .remove(&r_id)
            .map(|_| ())
            .ok_or(E_INVALID_ARGUMENT)
    }

    pub fn on_event(&self, events: EventBits) {
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
                if let Some(registry) = REGISTRIES.lock().get(registry_id) {
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
}

static REGISTRIES: SpinLock<BTreeMap<u64, Arc<Registry>>> = SpinLock::new(BTreeMap::new());

pub struct Registry {
    id: u64,
    events: SpinLock<BTreeMap<Token, EventBits>>,
    wait_handle: AtomicU64,
    wait_object: WaitObject,
}

impl Drop for Registry {
    fn drop(&mut self) {
        let _ = REGISTRIES.lock().remove(&self.id);
    }
}

impl PosixFile for Registry {
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
        });

        REGISTRIES.lock().insert(id, result.clone());
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

    pub fn wake(&self) -> ErrorCode {
        self.wait_object.on_event(moto_rt::poll::POLL_READABLE);
        E_OK
    }

    pub fn wait(&self, events_buf: &mut [Event], deadline: Option<moto_rt::time::Instant>) -> i32 {
        self.wait_handle.store(
            moto_sys::UserThreadControlBlock::get().self_handle,
            Ordering::Release,
        );

        loop {
            if !self.events.lock().is_empty() {
                break;
            }
            let _ = moto_sys::SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, deadline);
            if !self.events.lock().is_empty() {
                break;
            }
            if let Some(deadline) = deadline {
                if deadline <= moto_rt::time::Instant::now() {
                    self.wait_handle
                        .store(SysHandle::NONE.as_u64(), Ordering::Release);
                    // MIO docs for poll() say that upon timeout poll() returns OK(()),
                    // and MIO tests (specifically tcp::listen_then_close() rely on this).
                    return 0; // -(E_TIMED_OUT as i32);
                }
            }
        }
        self.wait_handle
            .store(SysHandle::NONE.as_u64(), Ordering::Release);

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
            // crate::moto_log!("returning token: {token} event: {bits}");
        }

        idx as i32
    }

    fn on_event(&self, token: Token, event_bits: EventBits) {
        // crate::moto_log!("on_event: token: {token} events: {event_bits}");
        // crate::util::logging::log_backtrace(-1);

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
