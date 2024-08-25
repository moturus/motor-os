// A somewhat unsafe, but very fast static ref.
// Should be used where lazy_static would normally
// be used, but where taking spinlocks is not desirable.
// Another advantage over lazy_static is that StaticRef
// has an explicit init.

use core::marker::PhantomData;
use core::sync::atomic::*;

pub struct StaticRef<T> {
    ptr: core::sync::atomic::AtomicUsize,
    _unused: PhantomData<T>,
}

impl<T> Default for StaticRef<T> {
    fn default() -> Self {
        Self {
            ptr: core::sync::atomic::AtomicUsize::new(0),
            _unused: PhantomData {},
        }
    }
}

impl<T> core::ops::Deref for StaticRef<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inst()
    }
}

impl<T> StaticRef<T> {
    pub const fn default_const() -> Self {
        Self {
            ptr: core::sync::atomic::AtomicUsize::new(0),
            _unused: PhantomData {},
        }
    }

    pub fn set(&self, val: &'static T) {
        assert_eq!(0, self.ptr.load(Ordering::Acquire));
        let new_ptr = val as *const T;
        let new_ptr = new_ptr as usize;

        self.ptr.store(new_ptr, Ordering::Release);
    }

    // Unsafe because can race with another set/reset.
    // pub unsafe fn _reset(&self, val: &'static T) {
    //     let new_ptr = val as *const T;
    //     let new_ptr = new_ptr as usize;

    //     self.ptr.store(new_ptr, Ordering::Release);
    // }

    fn inst(&self) -> &T {
        let ptr = self.ptr.load(Ordering::Acquire);
        assert_ne!(ptr, 0);
        let ptr = ptr as *const T;
        let ptr = unsafe { &*ptr };
        ptr
    }

    pub fn spin_until_set(&self) {
        while self.ptr.load(Ordering::Acquire) == 0 {
            crate::arch::nop();
        }
    }

    pub fn is_set(&self) -> bool {
        self.ptr.load(Ordering::Acquire) != 0
    }

    pub fn get(&self) -> Option<&T> {
        let ptr = self.ptr.load(Ordering::Relaxed);
        if ptr == 0 {
            None
        } else {
            let ptr = ptr as *const T;
            let ptr = unsafe { &*ptr };
            Some(ptr)
        }
    }

    /*
    pub fn take(&self) -> Option<&'static T> {
        let ptr = self.ptr.swap(0, Ordering::AcqRel);
        if ptr == 0 {
            None
        } else {
            let ptr = ptr as *const T;
            let ptr = unsafe { &*ptr };
            Some(ptr)
        }
    }
    */
}
