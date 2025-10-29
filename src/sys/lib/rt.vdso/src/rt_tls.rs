use alloc::collections::BTreeMap;
use core::sync::atomic::*;
use moto_rt::spinlock::SpinLock;
use moto_rt::tls::Key;

pub type Dtor = unsafe extern "C" fn(*mut u8);

static NEXT_KEY: AtomicUsize = AtomicUsize::new(1); // Rust does not accept zeroes.
static KEYS: SpinLock<BTreeMap<Key, Option<Dtor>>> = SpinLock::new(BTreeMap::new());

type PerThreadMap = BTreeMap<Key, usize>;

/// Runtime impl of ```fn create(dtor: Option<unsafe extern "C" fn(*mut u8)>) -> Key```
pub unsafe extern "C" fn create(dtor: u64) -> Key {
    let key = NEXT_KEY.fetch_add(1, Ordering::Relaxed);
    if dtor == 0 {
        KEYS.lock().insert(key, None);
    } else {
        #[allow(clippy::missing_transmute_annotations)]
        KEYS.lock()
            .insert(key, Some(unsafe { core::mem::transmute(dtor) }));
    }
    key
}

/// Runtime impl of ```fn set(key: Key, value: *mut u8)```
pub unsafe extern "C" fn set(key: Key, value: *mut u8) {
    let tcb = moto_sys::UserThreadControlBlock::get_mut();
    let map: &mut PerThreadMap = unsafe {
        if tcb.tls == 0 {
            if value.is_null() {
                return;
            }
            let boxed = alloc::boxed::Box::new(PerThreadMap::new());
            let ptr = alloc::boxed::Box::into_raw(boxed);
            tcb.tls = ptr as usize as u64;
            ptr.as_mut().unwrap_unchecked()
        } else {
            let ptr = tcb.tls as *mut PerThreadMap;
            ptr.as_mut().unwrap_unchecked()
        }
    };

    let prev_value = if value.is_null() {
        map.remove(&key)
    } else {
        map.insert(key, value as usize)
    };

    if let Some(prev_value) = prev_value {
        unsafe { run_dtor(key, prev_value) };
    }
}

/// Runtime impl of  ```fn get(key: Key) -> *mut u8```
pub unsafe extern "C" fn get(key: Key) -> *mut u8 {
    let tcb = moto_sys::UserThreadControlBlock::get();
    if tcb.tls == 0 {
        return core::ptr::null_mut();
    }

    unsafe {
        let ptr = tcb.tls as usize as *const PerThreadMap;
        let map = ptr.as_ref().unwrap_unchecked();
        if let Some(value) = map.get(&key) {
            // if *value == 1 {
            //     // This is a "sentinel" value.
            //     return core::ptr::null_mut();
            // }
            return *value as *mut u8;
        }
    }
    core::ptr::null_mut()
}

/// Runtim impl of ```fn destroy(key: Key)```
pub unsafe extern "C" fn destroy(key: Key) {
    KEYS.lock().remove(&key);
}

unsafe fn run_dtor(key: Key, value: usize) {
    if value == 1 {
        return; // Sentinel.
    }

    // Note: we should not hold the KEYS lock when running dtors,
    // as a dtor can spawn a thread and then end up here, trying
    // to acquire the same lock (=> deadlock).
    let dtor: Option<Dtor> = {
        let keys = KEYS.lock();
        if let Some(Some(dtor)) = keys.get(&key) {
            Some(*dtor)
        } else {
            None
        }
    };

    if let Some(dtor) = dtor {
        unsafe { dtor(value as *mut u8) };
    }
}

// Returns true if it did some work.
unsafe fn run_one_dtor(map: &mut PerThreadMap) -> bool {
    if let Some((key, pval)) = map.pop_first() {
        if pval == 0 {
            return true;
        }
        unsafe { run_dtor(key, pval) };
        true
    } else {
        false
    }
}

pub(super) unsafe fn on_thread_exiting() {
    // Dtors can insert values into TLS, and then a tokio test complains
    // that a thing was not destroyed, so we need to handle TLS modifications
    // happening during thread exiting.
    loop {
        let tcb = moto_sys::UserThreadControlBlock::get_mut();
        if tcb.tls == 0 {
            return;
        }

        let ptr = tcb.tls as *mut PerThreadMap;
        let map = unsafe { &mut *ptr };
        tcb.tls = 0;

        while unsafe { run_one_dtor(map) } {}

        // Drop the map.
        core::mem::drop(unsafe { alloc::boxed::Box::from_raw(ptr) });
    }
}
