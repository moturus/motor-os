use crate::{
    mm::{MappingOptions, PageType},
    uspace::sysobject::object_from_handle,
    util::{SpinLock, StaticRef},
};
use alloc::{
    borrow::ToOwned,
    collections::{BTreeMap, LinkedList},
    string::String,
    sync::{Arc, Weak},
};
use moto_sys::{ErrorCode, SysHandle};

use super::{sysobject::SysObject, Process};

// A SysObject shared between different userspace processes.
struct Shared {
    page_type: PageType,
    page_num: u16,

    owner_addr: u64,
    owner: Weak<Process>,
    url: Arc<String>,

    sharer: Weak<SysObject>,
    // We have to use a mutex here, because the field is initialized
    // dynamically on connect, which can race with a drop/wake by the sharer.
    sharee: SpinLock<Weak<SysObject>>,
}

unsafe impl Send for Shared {}
unsafe impl Sync for Shared {}

impl Shared {
    fn wake_other(&self, wakee_id: u64, wakee_thread: SysHandle, this_cpu: bool) -> Result<(), ()> {
        if let Some(sharer) = self.sharer.upgrade() {
            if sharer.id() == wakee_id {
                let lock = self.sharee.lock(line!());
                if let Some(sharee) = lock.upgrade() {
                    if sharee.closed() {
                        return Err(());
                    }
                    if wakee_thread != SysHandle::NONE {
                        return sharee.wake_thread(wakee_thread, this_cpu);
                    }
                    sharee.wake(this_cpu);
                    return Ok(());
                }
            } else {
                if sharer.closed() {
                    return Err(());
                }
                if wakee_thread != SysHandle::NONE {
                    return sharer.wake_thread(wakee_thread, this_cpu);
                }
                sharer.wake(this_cpu);
                return Ok(());
            }
        }
        Err(())
    }

    // W7: wake_other(wakee_thread = NONE, this_cpu = true), but claiming
    // the peer's waiting thread for a direct switch (see
    // SysObject::wake_for_switch). Ok(None) means the peer was woken (or
    // had nothing to wake) without a claimable thread.
    fn wake_other_for_switch(
        &self,
        wakee_id: u64,
    ) -> Result<Option<Arc<super::process::Thread>>, ()> {
        if let Some(sharer) = self.sharer.upgrade() {
            if sharer.id() == wakee_id {
                let lock = self.sharee.lock(line!());
                if let Some(sharee) = lock.upgrade() {
                    if sharee.closed() {
                        return Err(());
                    }
                    return Ok(sharee.wake_for_switch());
                }
            } else {
                if sharer.closed() {
                    return Err(());
                }
                return Ok(sharer.wake_for_switch());
            }
        }
        Err(())
    }

    fn on_sharer_dropped(&self) {
        let lock = self.sharee.lock(line!());
        if let Some(sharee) = lock.upgrade() {
            sharee.on_sibling_dropped(); // Wakes the peer.
        }
    }

    fn on_drop(&self, child: &SysObject) {
        // Pointer identity still works during Drop, when Weak::upgrade fails.
        if core::ptr::eq(self.sharer.as_ptr(), child) {
            self.release_name();
            self.on_sharer_dropped();
        } else if let Some(sharer) = self.sharer.upgrade() {
            sharer.on_sibling_dropped(); // Wakes the peer.
        }
    }

    fn release_name(&self) {
        // Unnamed IPC pairs do not participate in service discovery.
        if self.owner.ptr_eq(&Weak::new()) {
            return;
        }
        let mut listeners = LISTENERS.lock(line!());
        let Some(service) = listeners.get_mut(&self.url) else {
            return;
        };
        // An exited owner's remaining handles must not affect its successor.
        if !service.owner.ptr_eq(&self.owner) {
            return;
        }
        service.endpoints -= 1;
        if service.endpoints == 0 {
            listeners.remove(&self.url);
        }
    }
}

struct Service {
    owner: Weak<Process>,
    // Listening and connected server endpoints both reserve the service name.
    endpoints: usize,
    pending: LinkedList<Arc<Shared>>,
}

// It would have been better to use a HashMap, but it is unavailable in [no-std].
// TODO: use a HashMap instead of BTreeMap.
static LISTENERS: StaticRef<SpinLock<BTreeMap<Arc<String>, Service>>> = StaticRef::default_const();

static IPC_PAIR_URL: StaticRef<Arc<String>> = StaticRef::default_const();

pub(super) fn init() {
    use alloc::boxed::Box;
    LISTENERS.set(Box::leak(Box::new(SpinLock::new(BTreeMap::new()))));
    IPC_PAIR_URL.set(Box::leak(Box::new(Arc::new("ipc_pair".to_owned()))));
}

pub(super) fn create(
    owner: Arc<Process>,
    url: String,
    owner_addr: u64,
    page_type: PageType,
    page_num: u16,
) -> Result<Arc<SysObject>, ErrorCode> {
    // Only sys-io can create "sys-io" listeners.
    if url == "sys-io" && owner.pid() != super::process::SYS_IO_PID {
        return Err(moto_rt::E_NOT_ALLOWED);
    }

    let url = Arc::new(url);
    let process_owner = Arc::downgrade(&owner);
    let mut listeners = LISTENERS.lock(line!());
    let service = listeners.entry(url.clone()).or_insert_with(|| Service {
        owner: process_owner.clone(),
        endpoints: 0,
        pending: LinkedList::new(),
    });
    if !service.owner.ptr_eq(&process_owner) {
        if service
            .owner
            .upgrade()
            .is_some_and(|proc| proc.status().is_alive())
        {
            log::debug!("User error: Shared URL '{url}' exists with a different owner.");
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        // Process handles can retain an exited owner; they do not reserve URLs.
        service.owner = process_owner.clone();
        service.endpoints = 0;
        service.pending.clear();
    }

    // Only registered endpoints may run service-name cleanup on drop.
    let self_ = Arc::new(Shared {
        page_type,
        page_num,
        owner_addr,
        url: url.clone(),
        owner: process_owner,
        sharer: Weak::default(),
        sharee: SpinLock::new(Weak::default()),
    });

    let sharer = SysObject::new_owned(url.clone(), self_.clone(), Arc::downgrade(&owner));
    // Safe because we just constructed self_ and all references to it are here.
    unsafe {
        let ptr = Arc::as_ptr(&self_) as usize as *mut Shared;
        (*ptr).sharer = Arc::downgrade(&sharer);
    }

    service.endpoints += 1;
    service.pending.push_back(self_);
    Ok(sharer)
}

pub(super) fn get(
    requestor: Arc<Process>,
    url: String,
    requestor_addr: u64,
    page_type: PageType,
    page_num: u16,
) -> Result<Arc<SysObject>, ErrorCode> {
    let (listener, owner_process) = {
        let mut listeners = LISTENERS.lock(line!());
        if let Some(service) = listeners.get_mut(&url) {
            let Some(proc) = service
                .owner
                .upgrade()
                .filter(|proc| proc.status().is_alive())
            else {
                listeners.remove(&url);
                return Err(moto_rt::E_NOT_FOUND);
            };
            loop {
                let Some(shared) = service.pending.front() else {
                    // Exhausting the listener pool does not release ownership.
                    return Err(moto_rt::E_NOT_FOUND);
                };
                if shared.sharer.upgrade().is_none_or(|sharer| sharer.closed()) {
                    service.pending.pop_front();
                    continue;
                }

                if shared.page_type != page_type || shared.page_num != page_num {
                    log::debug!("shared: get: '{url}': pages don't match.");
                    return Err(moto_rt::E_INVALID_ARGUMENT);
                }
                let listener = service.pending.pop_front().unwrap();
                log::debug!("shared: got '{url}'.");
                break (listener, proc);
            }
        } else {
            log::debug!("shared: get: bad url: '{url}'.");
            return Err(moto_rt::E_NOT_FOUND);
        }
    };

    debug_assert!(listener.sharee.lock(line!()).upgrade().is_none());

    let mapping_result = crate::mm::user::UserAddressSpace::map_shared(
        owner_process.address_space(),
        listener.owner_addr,
        requestor.address_space(),
        requestor_addr,
        MappingOptions::USER_ACCESSIBLE
            | MappingOptions::READABLE
            | MappingOptions::WRITABLE
            | MappingOptions::DONT_ZERO,
    );
    if mapping_result.is_err() {
        log::warn!("consider re-adding listener to LISTENERS.");
        log::debug!("shared: get: failed to map.");
        // The server may have closed the listener after LISTENERS was released.
        if let Some(sharer) = listener.sharer.upgrade() {
            sharer.wake(false);
        }
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }
    let sharee = SysObject::new_owned(
        listener.url.clone(),
        listener.clone(),
        Arc::downgrade(&requestor),
    );
    *listener.sharee.lock(line!()) = Arc::downgrade(&sharee);

    Ok(sharee)
}

/// Attempts to wake the peer.
pub(super) fn try_wake(
    maybe_shared: &Arc<SysObject>,
    wakee_thread: SysHandle,
    this_cpu: bool,
) -> Result<(), ()> {
    if let Some(shared) = super::sysobject::object_from_sysobject::<Shared>(maybe_shared) {
        shared.wake_other(maybe_shared.id(), wakee_thread, this_cpu)
    } else {
        Err(())
    }
}

/// W7: try_wake(wakee_thread = NONE, this_cpu = true), claiming the woken
/// thread for a direct switch when possible.
pub(super) fn try_wake_for_switch(
    maybe_shared: &Arc<SysObject>,
) -> Result<Option<Arc<super::process::Thread>>, ()> {
    if let Some(shared) = super::sysobject::object_from_sysobject::<Shared>(maybe_shared) {
        shared.wake_other_for_switch(maybe_shared.id())
    } else {
        Err(())
    }
}

pub(super) fn has_peer(maybe_shared: &Arc<SysObject>) -> Result<bool, moto_rt::ErrorCode> {
    let Some(shared) = super::sysobject::object_from_sysobject::<Shared>(maybe_shared) else {
        return Err(moto_rt::E_BAD_HANDLE);
    };

    let sharer_open = shared
        .sharer
        .upgrade()
        .is_some_and(|sharer| !sharer.closed());
    let sharee_open = shared
        .sharee
        .lock(line!())
        .upgrade()
        .is_some_and(|sharee| !sharee.closed());
    Ok(sharer_open && sharee_open)
}

pub(super) fn peer_owner(
    this: super::process::ProcessId,
    maybe_shared: &Arc<SysObject>,
) -> Option<Arc<Process>> {
    if let Some(shared) = super::sysobject::object_from_sysobject::<Shared>(maybe_shared) {
        let sharer = shared
            .sharer
            .upgrade()
            .and_then(|sharer| sharer.process_owner().upgrade());
        let sharee = shared
            .sharee
            .lock(line!())
            .upgrade()
            .and_then(|sharee| sharee.process_owner().upgrade());

        if let Some(sharer) = &sharer {
            if sharer.pid() == this {
                return sharee;
            }
        }

        if let Some(sharee) = &sharee {
            if sharee.pid() == this {
                return sharer;
            }
        }
    }

    None
}

pub(super) fn on_drop(maybe_shared: &SysObject) {
    if let Ok(shared) = Arc::downcast::<Shared>(maybe_shared.owner().clone()) {
        if maybe_shared.mark_closed() {
            shared.on_drop(maybe_shared);
        }
    }
}

pub(super) fn create_ipc_pair(
    requesting_thread: &super::process::Thread,
    process1_handle: SysHandle,
    process2_handle: SysHandle,
) -> Result<(SysHandle, SysHandle), ErrorCode> {
    let requestor = requesting_thread.owner();

    fn process_from_handle(
        owner: &Arc<Process>,
        handle: SysHandle,
    ) -> Result<Arc<Process>, ErrorCode> {
        match handle {
            SysHandle::SELF => Ok(owner.self_pinned().unwrap()),
            _ => match object_from_handle::<Process>(owner, handle) {
                Some(process) => Ok(process),
                None => Err(moto_rt::E_INVALID_ARGUMENT),
            },
        }
    }

    let process1 = process_from_handle(&requestor, process1_handle)?;
    let process2 = process_from_handle(&requestor, process2_handle)?;

    let url = IPC_PAIR_URL.clone();
    let mut shared = Arc::new(Shared {
        page_type: PageType::Unknown,
        page_num: 0,
        owner_addr: 0,
        url: url.clone(),
        owner: Weak::new(), // Unnamed pairs have no service owner.
        sharer: Weak::new(),
        sharee: SpinLock::new(Weak::new()),
    });

    let obj1 = SysObject::new_owned(url.clone(), shared.clone(), Arc::downgrade(&process1));

    // Safety: nobody else uses shared yet.
    unsafe {
        Arc::get_mut_unchecked(&mut shared).sharer = Arc::downgrade(&obj1);
    }

    let obj2 = SysObject::new_owned(url.clone(), shared.clone(), Arc::downgrade(&process2));
    *shared.sharee.lock(line!()) = Arc::downgrade(&obj2);

    log::debug!(
        "created ipc pair: {}:{}-{}:{}",
        process1.pid().as_u64(),
        obj1.id(),
        process2.pid().as_u64(),
        obj2.id()
    );

    Ok((process1.add_object(obj1), process2.add_object(obj2)))
}
