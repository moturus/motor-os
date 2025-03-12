use alloc::collections::BTreeMap;
use core::sync::atomic::*;
use moto_rt::spinlock::SpinLock;
use moto_rt::tls::Key;

pub type Dtor = unsafe extern "C" fn(*mut u8);

static NEXT_KEY: AtomicUsize = AtomicUsize::new(1); // Rust does not accept zeroes.
static KEYS: SpinLock<BTreeMap<Key, Option<Dtor>>> = SpinLock::new(BTreeMap::new());

type PerCpuMap = BTreeMap<Key, usize>;

/// Runtime impl of ```fn create(dtor: Option<unsafe extern "C" fn(*mut u8)>) -> Key```
pub unsafe extern "C" fn create(dtor: u64) -> Key {
    let key = NEXT_KEY.fetch_add(1, Ordering::Relaxed);
    if dtor == 0 {
        KEYS.lock().insert(key, None);
    } else {
        #[allow(clippy::missing_transmute_annotations)]
        KEYS.lock().insert(key, Some(core::mem::transmute(dtor)));
    }
    key
}

/// Runtime impl of ```fn set(key: Key, value: *mut u8)```
pub unsafe extern "C" fn set(key: Key, value: *mut u8) {
    let tcb = moto_sys::UserThreadControlBlock::get_mut();
    let map: &mut PerCpuMap = unsafe {
        if tcb.tls == 0 {
            let boxed = alloc::boxed::Box::new(PerCpuMap::new());
            let ptr = alloc::boxed::Box::into_raw(boxed);
            tcb.tls = ptr as usize as u64;
            ptr.as_mut().unwrap_unchecked()
        } else {
            let ptr = tcb.tls as *mut PerCpuMap;
            ptr.as_mut().unwrap_unchecked()
        }
    };

    map.insert(key, value as usize);
}

/// Runtime impl of  ```fn get(key: Key) -> *mut u8```
pub unsafe extern "C" fn get(key: Key) -> *mut u8 {
    let tcb = moto_sys::UserThreadControlBlock::get();
    if tcb.tls == 0 {
        return core::ptr::null_mut();
    }

    unsafe {
        let ptr = tcb.tls as usize as *const PerCpuMap;
        let map = ptr.as_ref().unwrap_unchecked();
        if let Some(value) = map.get(&key) {
            return *value as *mut u8;
        }
    }
    core::ptr::null_mut()
}

/// Runtim impl of ```fn destroy(key: Key)```
pub unsafe extern "C" fn destroy(key: Key) {
    KEYS.lock().remove(&key);
}

pub unsafe extern "C" fn tmp_on_thread_exiting() {
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
            if let Some(Some(dtor)) = keys.get(key) {
                dtor((*pval) as *mut u8);
                *pval = 0;
            }
        }

        // Drop the map.
        core::mem::drop(alloc::boxed::Box::from_raw(ptr));
        tcb.tls = 0;
    }
}
