use fittings::iobuf::IoBuf as InnerBuf;

/// Extends fittings::iobuf to support caching the physical address
/// of the underlying buffer.
pub struct IoBuf {
    inner: InnerBuf,
    phys_addr: core::cell::Cell<usize>, // The physical address of inner::ptr.
}

impl IoBuf {
    pub fn new_from_size_align(layout_size_align: usize) -> Option<Self> {
        InnerBuf::new_from_size_align(layout_size_align).map(|inner| Self {
            inner,
            phys_addr: 0.into(),
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
