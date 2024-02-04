use alloc::collections::BTreeMap;
use core::sync::atomic::*;
use crate::external::spin;

pub type Key = usize;
pub type Dtor = unsafe extern "C" fn(*mut u8);

static NEXT_KEY: AtomicUsize = AtomicUsize::new(1); // Rust does not accept zeroes.
static KEYS: spin::Mutex<BTreeMap<Key, Option<Dtor>>> = spin::Mutex::new(BTreeMap::new());

pub fn create(dtor: Option<Dtor>) -> Key {
    let key = NEXT_KEY.fetch_add(1, Ordering::Relaxed);
    KEYS.lock().insert(key, dtor);
    key
}

type PerCpuMap = BTreeMap<Key, usize>;

pub fn set(key: Key, value: *mut u8) {
    // super::log_backtrace("TLS::set");
    let tcb = moto_sys::UserThreadControlBlock::get_mut();
    let map: &mut PerCpuMap = unsafe {
        if tcb.tls == 0 {
            let boxed = alloc::boxed::Box::new(PerCpuMap::new());
            let ptr = alloc::boxed::Box::into_raw(boxed);
            tcb.tls = ptr as usize;
            ptr.as_mut().unwrap_unchecked()
        } else {
            let ptr = tcb.tls as *mut PerCpuMap;
            ptr.as_mut().unwrap_unchecked()
        }
    };

    map.insert(key, value as usize);
}

pub fn get(key: Key) -> *mut u8 {
    let tcb = moto_sys::UserThreadControlBlock::get();
    if tcb.tls == 0 {
        return core::ptr::null_mut();
    }

    unsafe {
        let ptr = tcb.tls as *const PerCpuMap;
        let map = ptr.as_ref().unwrap_unchecked();
        if let Some(value) = map.get(&key) {
            return *value as *mut u8;
        }
    }
    return core::ptr::null_mut();
}

pub fn thread_exiting() {
    let tcb = moto_sys::UserThreadControlBlock::get_mut();
    if tcb.tls == 0 {
        return;
    }

    // Run dtors.
    unsafe {
        let ptr = tcb.tls as *mut PerCpuMap;
        let map = &mut *ptr;
        for (key, pval) in map.iter_mut() {
            let keys = KEYS.lock();
            if let Some(dtor_option) = keys.get(key) {
                if let Some(dtor) = dtor_option {
                    dtor((*pval) as *mut u8);
                    *pval = 0;
                }
            }
        }

        // Drop the map.
        let _ = alloc::boxed::Box::from_raw(ptr);
        tcb.tls = 0;
    }
}

pub fn destroy(key: Key) {
    // This never happens, it seems. Maybe we should call it?
    moto_sys::syscalls::SysMem::log("tls::destroy").ok();
    KEYS.lock().remove(&key);
}
