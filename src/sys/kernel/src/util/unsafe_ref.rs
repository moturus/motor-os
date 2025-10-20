// Rust is bad at circular references, and there is often
// a need to reference the parent from a child, e.g.
// VmemRegion referencing its AddressSpace.
//
// Also these things should be Send/Sync.
//
// Rather than jumping through cruft of Pin, Arc, Weak, etc.
// we use unsafe pointers, as we do low-level memory management
// anyway.

use core::marker::PhantomData;

pub struct UnsafeRef<T> {
    addr: u64,
    foo_: PhantomData<T>,
}

impl<T> Default for UnsafeRef<T> {
    fn default() -> Self {
        Self::const_default()
    }
}

impl<T> UnsafeRef<T> {
    pub const fn const_default() -> Self {
        Self {
            addr: 0,
            foo_: PhantomData,
        }
    }

    pub fn from(ref_: &T) -> Self {
        Self {
            addr: ref_ as *const T as usize as u64,
            foo_: PhantomData,
        }
    }

    pub fn from_ptr(ptr: *const T) -> Self {
        Self {
            addr: ptr as usize as u64,
            foo_: PhantomData,
        }
    }

    pub fn once_init(&mut self, ref_: &T) {
        assert_eq!(self.addr, 0);
        self.addr = ref_ as *const T as usize as u64;
    }

    /// # Safety
    ///
    /// Safe if self has been properly initialized.
    pub unsafe fn get(&self) -> &'static T {
        assert_ne!(self.addr, 0);
        let res = self.addr as usize as *const T;
        res.as_ref().unwrap()
    }

    /// # Safety
    ///
    /// Safe if self has been properly initialized.
    pub unsafe fn get_mut(&self) -> &'static mut T {
        assert_ne!(self.addr, 0);
        let res = self.addr as usize as *mut T;
        res.as_mut().unwrap()
    }

    pub fn set(&mut self, ref_: &T) {
        self.addr = ref_ as *const T as usize as u64;
    }

    pub fn is_null(&self) -> bool {
        self.addr == 0
    }

    pub fn equals(&self, ref_: &T) -> bool {
        if self.addr == 0 {
            return false;
        }
        self.addr == (ref_ as *const T as usize as u64)
    }

    pub fn set_from(&mut self, other: &UnsafeRef<T>) {
        self.addr = other.addr;
    }

    pub fn clear(&mut self) {
        self.addr = 0;
    }
}
