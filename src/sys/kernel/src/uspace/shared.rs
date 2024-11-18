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

/*
impl Drop for Shared {
    fn drop(&mut self) {
        log::debug!("Dropping Shared.");
    }
}
*/

impl Shared {
    fn wake_other(&self, wakee_id: u64, wakee_thread: SysHandle, this_cpu: bool) -> Result<(), ()> {
        if let Some(sharer) = self.sharer.upgrade() {
            if sharer.id() == wakee_id {
                let lock = self.sharee.lock(line!());
                if let Some(sharee) = lock.upgrade() {
                    if wakee_thread != SysHandle::NONE {
                        return sharee.wake_thread(wakee_thread, this_cpu);
                    }
                    sharee.wake(this_cpu);
                    return Ok(());
                }
            } else {
                if wakee_thread != SysHandle::NONE {
                    return sharer.wake_thread(wakee_thread, this_cpu);
                }
                sharer.wake(this_cpu);
                return Ok(());
            }
        }
        Err(())
    }

    fn on_drop(&self, child: &SysObject) {
        if let Some(sharer) = self.sharer.upgrade() {
            if sharer.id() == child.id() {
                let lock = self.sharee.lock(line!());
                if let Some(sharee) = lock.upgrade() {
                    // SysObject::wake(&sharee, false);
                    sharee.on_sibling_dropped();
                }
            } else {
                // SysObject::wake(&sharer, false);
                sharer.on_sibling_dropped();
            }
        }
    }
}

// It would have been better to use a HashMap, but it is unavailable in [no-std].
// TODO: use a HashMap instead of BTreeMap.
#[allow(clippy::type_complexity)]
static LISTENERS: StaticRef<SpinLock<BTreeMap<Arc<String>, LinkedList<Arc<Shared>>>>> =
    StaticRef::default_const();

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
    let self_ = Arc::new(Shared {
        page_type,
        page_num,
        owner_addr,
        url: url.clone(),
        owner: Arc::downgrade(&owner),
        sharer: Weak::default(),
        sharee: SpinLock::new(Weak::default()),
    });

    let sharer = SysObject::new_owned(url.clone(), self_.clone(), Arc::downgrade(&owner));
    log::debug!("Created shared id: {} for '{}'", sharer.id(), url);
    // Safe because we just constructed self_ and all references to it are here.
    unsafe {
        let ptr = Arc::as_ptr(&self_) as usize as *mut Shared;
        (*ptr).sharer = Arc::downgrade(&sharer);
    }

    let mut listeners = LISTENERS.lock(line!());
    if let Some(list) = listeners.get_mut(&url) {
        // Don't allow different processes to create same listener URLs.
        loop {
            // The previous owner could have died and restarted; in this case
            // we clear out the list.
            let shared = list.front();
            if shared.is_none() {
                // Removed all dead entries below.
                list.push_back(self_);
                return Ok(sharer);
            }

            match shared.unwrap().owner.upgrade() {
                Some(proc) => {
                    let pid = proc.pid();
                    if pid != owner.pid() {
                        log::debug!(
                            "User error: Shared URL '{}' exists with a different owner.",
                            url
                        );
                        return Err(moto_rt::E_INVALID_ARGUMENT);
                    }

                    list.push_back(self_);
                    return Ok(sharer);
                }
                None => {
                    list.pop_front();
                    continue;
                }
            }
        }
    } else {
        let mut list = LinkedList::new();
        list.push_back(self_);
        listeners.insert(url, list);
        Ok(sharer)
    }
}

pub(super) fn get(
    requestor: Arc<Process>,
    url: String,
    requestor_addr: u64,
    page_type: PageType,
    page_num: u16,
) -> Result<Arc<SysObject>, ErrorCode> {
    let listener = {
        let mut listeners = LISTENERS.lock(line!());
        if let Some(list) = listeners.get_mut(&url) {
            let shared = list.front().unwrap();

            if shared.page_type != page_type || shared.page_num != page_num {
                log::debug!("shared: get: '{}': pages don't match.", url);
                return Err(moto_rt::E_INVALID_ARGUMENT);
            }
            let result = list.pop_front().unwrap();
            if list.is_empty() {
                listeners.remove(&url);
            }
            log::debug!("shared: got '{}'.", url);
            result
        } else {
            log::debug!("shared: get: bad url: '{}'.", url);
            return Err(moto_rt::E_NOT_FOUND);
        }
    };

    debug_assert!(listener.sharee.lock(line!()).upgrade().is_none());

    let owner_process = listener.owner.upgrade().unwrap();
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
        SysObject::wake(listener.sharer.upgrade().as_ref().unwrap(), false);
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
        shared.on_drop(maybe_shared);
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
    let shared = Arc::new(Shared {
        page_type: PageType::Unknown,
        page_num: 0,
        owner_addr: 0,
        url: url.clone(),
        owner: Weak::new(), // Not needed here: used only for memory mapping.
        sharer: Weak::new(),
        sharee: SpinLock::new(Weak::new()),
    });

    let obj1 = SysObject::new_owned(url.clone(), shared.clone(), Arc::downgrade(&process1));
    // Safe because we just constructed shared and all references to it are here.
    unsafe {
        let ptr = Arc::as_ptr(&shared) as usize as *mut Shared;
        (*ptr).sharer = Arc::downgrade(&obj1);
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
