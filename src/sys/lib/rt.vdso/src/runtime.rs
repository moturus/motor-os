//! Runtime to support I/O and polling mechanisms.
//!
//! Somewhat similar to Linux's epoll, but supports only edge-triggered events.

use core::any::Any;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use crate::posix;
use crate::posix::PosixFile;
use crate::spin::Mutex;
use alloc::collections::btree_map::BTreeMap;
use alloc::sync::Arc;
use alloc::sync::Weak;
use moto_ipc::io_channel;
use moto_rt::poll::Event;
use moto_rt::poll::EventBits;
use moto_rt::poll::Interests;
use moto_rt::poll::Token;
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
    supported_interests: Interests,

    // Registry FD -> (Registry, Token).
    // TODO: is there a way to go from Arc<dyn PosixFile> to Arc<Registry>?
    // If so, then we can have Weak<Registry> below.
    #[allow(clippy::type_complexity)]
    registries: Mutex<BTreeMap<RtFd, (Weak<dyn PosixFile>, Token, Interests)>>,
}

impl Drop for WaitObject {
    fn drop(&mut self) {
        // todo!("notify registries")
        crate::moto_log!("WaitObject::drop(): notify registries");
    }
}

impl WaitObject {
    pub fn new(supported_interests: Interests) -> Self {
        Self {
            supported_interests,
            registries: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn add_interests(
        &self,
        registry_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        let Some(posix_file) = posix::get_file(registry_fd) else {
            return Err(E_BAD_HANDLE);
        };
        if (posix_file.as_ref() as &dyn Any)
            .downcast_ref::<Registry>()
            .is_none()
        {
            return Err(E_BAD_HANDLE);
        }
        let registry = Arc::downgrade(&posix_file);

        let mut registries = self.registries.lock();
        match registries.entry(registry_fd) {
            alloc::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((registry, token, interests));
            }
            alloc::collections::btree_map::Entry::Occupied(_) => return Err(E_INVALID_ARGUMENT),
        }

        Ok(())
    }

    pub fn set_interests(
        &self,
        registry_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        let Some(posix_file) = posix::get_file(registry_fd) else {
            return Err(E_BAD_HANDLE);
        };
        if (posix_file.as_ref() as &dyn Any)
            .downcast_ref::<Registry>()
            .is_none()
        {
            return Err(E_BAD_HANDLE);
        }
        let registry = Arc::downgrade(&posix_file);

        let mut registries = self.registries.lock();
        if let Some(val) = registries.get_mut(&registry_fd) {
            *val = (registry, token, interests);
            Ok(())
        } else {
            Err(E_INVALID_ARGUMENT)
        }
    }

    pub fn del_interests(&self, registry_fd: RtFd) -> Result<(), ErrorCode> {
        self.registries
            .lock()
            .remove(&registry_fd)
            .map(|_| ())
            .ok_or(E_INVALID_ARGUMENT)
    }

    pub fn on_event(&self, events: EventBits) {
        let mut dropped_registries = alloc::vec::Vec::new();
        let mut registries = self.registries.lock();
        for entry in &*registries {
            let (registry_id, (registry, token, interests)) = entry;
            if interests & events != 0 {
                if let Some(registry) = registry.upgrade() {
                    let registry = (registry.as_ref() as &dyn Any)
                        .downcast_ref::<Registry>()
                        .unwrap();
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

pub struct Registry {
    fd: RtFd,
    events: Mutex<BTreeMap<Token, EventBits>>,
    wait_handle: AtomicU64,
}

impl PosixFile for Registry {}

impl Registry {
    pub fn new(fd: RtFd) -> Self {
        Self {
            fd,
            events: Mutex::new(BTreeMap::new()),
            wait_handle: AtomicU64::new(SysHandle::NONE.as_u64()),
        }
    }

    pub fn add(&self, source_fd: RtFd, token: Token, interests: Interests) -> ErrorCode {
        let Some(posix_file) = posix::get_file(source_fd) else {
            return E_BAD_HANDLE;
        };

        if let Err(err) = posix_file.poll_add(self.fd, token, interests) {
            err
        } else {
            E_OK
        }
    }

    pub fn set(&self, source_fd: RtFd, token: Token, interests: Interests) -> ErrorCode {
        let Some(posix_file) = posix::get_file(source_fd) else {
            return E_BAD_HANDLE;
        };

        if let Err(err) = posix_file.poll_set(self.fd, token, interests) {
            err
        } else {
            E_OK
        }
    }

    pub fn del(&self, source_fd: RtFd) -> ErrorCode {
        let Some(posix_file) = posix::get_file(source_fd) else {
            return E_BAD_HANDLE;
        };

        if let Err(err) = posix_file.poll_del(self.fd) {
            err
        } else {
            E_OK
        }
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
                    return -(E_TIMED_OUT as i32);
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
        }

        (idx + 1) as i32
    }

    pub fn on_event(&self, token: Token, event_bits: EventBits) {
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
