//! IoBuf: pinned &[u8] that is aligned at its length.

#[cfg(feature = "std")]
use std::alloc;

#[cfg(not(feature = "std"))]
extern crate alloc;

pub struct IoBuf {
    ptr: *mut u8,
    layout_size_align: usize,
    len: usize,
}

impl Drop for IoBuf {
    fn drop(&mut self) {
        if self.ptr.is_null() {
            return;
        }

        // SAFETY: save by construction.
        unsafe {
            alloc::alloc::dealloc(
                self.ptr,
                core::alloc::Layout::from_size_align(
                    self.layout_size_align,
                    self.layout_size_align,
                )
                .unwrap(),
            );
        }
    }
}

impl IoBuf {
    pub fn new_from_size_align(layout_size_align: usize) -> Option<Self> {
        // SAFETY: save by construction.
        let ptr = unsafe {
            alloc::alloc::alloc(
                core::alloc::Layout::from_size_align(layout_size_align, layout_size_align).unwrap(),
            )
        };

        if ptr.is_null() {
            None
        } else {
            Some(Self {
                ptr,
                layout_size_align,
                len: layout_size_align,
            })
        }
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: save by construction.
        unsafe { core::slice::from_raw_parts(self.ptr, self.layout_size_align) }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: save by construction.
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.layout_size_align) }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn set_len(&mut self, len: usize) {
        #[cfg(debug_assertions)]
        {
            if len > self.len {
                panic!("IoBuf::set_len: {len} > {}", self.len);
            }
        }
        assert!(len <= self.layout_size_align);
        self.len = len;
    }

    pub fn raw_ptr(&self) -> *const u8 {
        self.ptr
    }

    pub fn raw_ptr_mut(&mut self) -> *mut u8 {
        self.ptr
    }

    pub fn clear(&mut self) {
        self.len = self.layout_size_align;
        self.bytes_mut().fill(0);
    }
}

impl AsRef<[u8]> for IoBuf {
    fn as_ref(&self) -> &[u8] {
        &self.bytes()[..self.len]
    }
}

impl AsMut<[u8]> for IoBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        let len = self.len;
        &mut self.bytes_mut()[..len]
    }
}

impl AsRef<IoBuf> for IoBuf {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AsMut<IoBuf> for IoBuf {
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}
