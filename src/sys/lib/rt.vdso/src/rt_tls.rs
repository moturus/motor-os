use alloc::collections::BTreeMap;
use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::*;
use moto_rt::spinlock::SpinLock;
use moto_rt::tls::Key;

pub type Dtor = unsafe extern "C" fn(*mut u8);

static NEXT_KEY: AtomicUsize = AtomicUsize::new(1); // Rust does not accept zeroes.
static KEYS: SpinLock<BTreeMap<Key, Option<Dtor>>> = SpinLock::new(BTreeMap::new());

type PerThreadMap = BTreeMap<Key, usize>;

/// What a thread keeps in the `tls` word of its control block: its TLS
/// values and its allocator cache. Created on the thread's first
/// allocation or TLS write, released when the thread exits through the
/// runtime's trampoline. Threads that never exit keep theirs.
struct ThreadBlock {
    map: PerThreadMap,
    cache: frusa::Cache4K,
}

impl ThreadBlock {
    fn current() -> Option<&'static mut ThreadBlock> {
        let tcb = moto_sys::UserThreadControlBlock::get_mut();
        if tcb.tls == 0 {
            None
        } else {
            Some(unsafe { &mut *(tcb.tls as usize as *mut ThreadBlock) })
        }
    }

    /// The block, created if the thread has none. The block itself comes
    /// from the shared path of the allocator, never through the cache it
    /// is about to hold.
    fn ensure() -> &'static mut ThreadBlock {
        let tcb = moto_sys::UserThreadControlBlock::get_mut();
        if tcb.tls == 0 {
            let block = unsafe {
                super::rt_alloc::FRUSA.alloc(Layout::new::<ThreadBlock>()) as *mut ThreadBlock
            };
            assert!(!block.is_null(), "out of memory creating a thread block");
            unsafe {
                block.write(ThreadBlock {
                    map: PerThreadMap::new(),
                    cache: frusa::Cache4K::new(),
                })
            };
            tcb.tls = block as usize as u64;
        }
        unsafe { &mut *(tcb.tls as usize as *mut ThreadBlock) }
    }
}

/// The calling thread's allocator cache, with its guard shard set to the
/// CPU it is running on. Consulted by the global allocator on every call,
/// so this is one control-block read.
pub(crate) fn thread_cache() -> Option<&'static frusa::Cache4K> {
    let tcb = moto_sys::UserThreadControlBlock::get();
    if tcb.tls == 0 {
        // First allocation on this thread: the block is created on the
        // shared path and serves from the next call on.
        let block = ThreadBlock::ensure();
        block
            .cache
            .set_shard(tcb.current_cpu.load(Ordering::Relaxed));
        return Some(&block.cache);
    }
    let block = unsafe { &*(tcb.tls as usize as *const ThreadBlock) };
    block
        .cache
        .set_shard(tcb.current_cpu.load(Ordering::Relaxed));
    Some(&block.cache)
}

/// The cache if this thread already has a block. Frees use this so that a
/// thread whose block was released at exit does not get a new one for a
/// late free.
pub(crate) fn existing_thread_cache() -> Option<&'static frusa::Cache4K> {
    let tcb = moto_sys::UserThreadControlBlock::get();
    if tcb.tls == 0 {
        return None;
    }
    let block = unsafe { &*(tcb.tls as usize as *const ThreadBlock) };
    block
        .cache
        .set_shard(tcb.current_cpu.load(Ordering::Relaxed));
    Some(&block.cache)
}

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
    let block = match ThreadBlock::current() {
        Some(block) => block,
        None if value.is_null() => return,
        None => ThreadBlock::ensure(),
    };

    let prev_value = if value.is_null() {
        block.map.remove(&key)
    } else {
        block.map.insert(key, value as usize)
    };

    if let Some(prev_value) = prev_value {
        unsafe { run_dtor(key, prev_value) };
    }
}

/// Runtime impl of  ```fn get(key: Key) -> *mut u8```
pub unsafe extern "C" fn get(key: Key) -> *mut u8 {
    match ThreadBlock::current() {
        Some(block) => block
            .map
            .get(&key)
            .map_or(core::ptr::null_mut(), |value| *value as *mut u8),
        None => core::ptr::null_mut(),
    }
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
    let Some(block) = ThreadBlock::current() else {
        return;
    };
    // Dtors can insert values into TLS, and then a tokio test complains
    // that a thing was not destroyed, so we need to handle TLS modifications
    // happening during thread exiting.
    loop {
        let mut map = core::mem::take(&mut block.map);
        if map.is_empty() {
            break;
        }
        while unsafe { run_one_dtor(&mut map) } {}
    }
    // The cache's private blocks rejoin their slabs. The slot is cleared
    // before the thread block is freed on the shared path, so nothing on
    // this thread can find a freed cache; a free after this point takes the
    // shared path, and an allocation would make a new block.
    super::rt_alloc::FRUSA.release_cache(&block.cache);
    moto_sys::UserThreadControlBlock::get_mut().tls = 0;
    unsafe {
        super::rt_alloc::FRUSA.dealloc(
            block as *mut ThreadBlock as *mut u8,
            Layout::new::<ThreadBlock>(),
        )
    };
}
