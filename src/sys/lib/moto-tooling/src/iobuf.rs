use fittings::iobuf::IoBuf as InnerBuf;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Extends fittings::iobuf to support caching the physical address
/// of the underlying buffer.
pub struct IoBuf {
    inner: InnerBuf,
    phys_addr: core::cell::Cell<usize>, // The physical address of inner::ptr.
    // Per-4K-page physical addresses (see phys_addr_at); resolved lazily,
    // 0 = not yet resolved. Empty until first phys_addr_at call.
    phys_pages: core::cell::RefCell<Vec<u64>>,
}

impl IoBuf {
    pub fn new_from_size_align(layout_size_align: usize) -> Option<Self> {
        InnerBuf::new_from_size_align(layout_size_align).map(|inner| Self {
            inner,
            phys_addr: 0.into(),
            phys_pages: core::cell::RefCell::new(Vec::new()),
        })
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn set_len(&mut self, len: usize) {
        self.inner.set_len(len)
    }

    pub fn raw_ptr(&self) -> *const u8 {
        self.inner.raw_ptr()
    }

    pub fn raw_ptr_mut(&mut self) -> *mut u8 {
        self.inner.raw_ptr_mut()
    }

    pub fn clear(&mut self) {
        self.inner.clear()
    }

    pub fn phys_addr(&self) -> usize {
        let phys_addr = self.phys_addr.get();
        if phys_addr != 0 {
            return phys_addr;
        }

        let virt_addr = self.raw_ptr() as usize as u64;
        let page_addr = virt_addr & !(moto_sys::sys_mem::PAGE_SIZE_SMALL - 1);
        let offset = virt_addr & (moto_sys::sys_mem::PAGE_SIZE_SMALL - 1);

        let phys_addr = (offset + moto_sys::SysMem::virt_to_phys(page_addr).unwrap()) as usize;
        self.phys_addr.set(phys_addr);
        phys_addr
    }

    /// The physical address of the byte at `offset`. The buffer is
    /// virtually contiguous but physically contiguous only within a 4K
    /// page — DMA of a range that crosses page boundaries must be split
    /// into per-page runs (see e.g. virtio_net's TX chains). Per-page
    /// physical addresses are resolved lazily and cached, so pooled/
    /// reused buffers pay the virt_to_phys syscalls only once.
    pub fn phys_addr_at(&self, offset: usize) -> u64 {
        const PAGE_SIZE: u64 = moto_sys::sys_mem::PAGE_SIZE_SMALL;
        assert!(offset < self.inner.capacity());

        let virt_start = self.raw_ptr() as usize as u64;
        let virt_addr = virt_start + offset as u64;
        let page_idx = ((virt_addr >> 12) - (virt_start >> 12)) as usize;

        let mut pages = self.phys_pages.borrow_mut();
        if pages.is_empty() {
            let num_pages =
                (((virt_start + self.inner.capacity() as u64 - 1) >> 12) - (virt_start >> 12) + 1)
                    as usize;
            pages.resize(num_pages, 0);
        }
        if pages[page_idx] == 0 {
            let page_addr = virt_addr & !(PAGE_SIZE - 1);
            pages[page_idx] = moto_sys::SysMem::virt_to_phys(page_addr).unwrap();
        }
        pages[page_idx] + (virt_addr & (PAGE_SIZE - 1))
    }

    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }
}

impl AsRef<[u8]> for IoBuf {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl AsMut<[u8]> for IoBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        self.inner.as_mut()
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
