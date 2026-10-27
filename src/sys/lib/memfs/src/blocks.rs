use moto_sdk::async_fs::BLOCK_SIZE;
use std::cell::RefCell;
use std::io::{ErrorKind, Result};
use std::ptr::NonNull;
use std::rc::Rc;

/// Unique ownership of a page, independent of the filesystem and its cache.
pub(crate) struct Block(NonNull<u8>);

impl Block {
    fn new() -> Result<Self> {
        // SysMem::alloc publishes zeroed pages; cache reuse is cleared in take().
        #[cfg(target_os = "motor")]
        let ptr = moto_sys::SysMem::alloc(moto_sys::sys_mem::PAGE_SIZE_SMALL, 1)
            .map_err(|_| ErrorKind::StorageFull)? as *mut u8;
        #[cfg(not(target_os = "motor"))]
        // SAFETY: the nonzero layout describes exactly one aligned page.
        let ptr = unsafe { std::alloc::alloc_zeroed(Self::layout()) };
        Ok(Self(NonNull::new(ptr).ok_or(ErrorKind::StorageFull)?))
    }

    #[cfg(not(target_os = "motor"))]
    fn layout() -> std::alloc::Layout {
        std::alloc::Layout::from_size_align(BLOCK_SIZE, BLOCK_SIZE).unwrap()
    }

    pub(crate) fn bytes(&self) -> &[u8; BLOCK_SIZE] {
        // SAFETY: this object owns a live, initialized page for its lifetime.
        unsafe { &*self.0.as_ptr().cast() }
    }

    pub(crate) fn bytes_mut(&mut self) -> &mut [u8; BLOCK_SIZE] {
        // SAFETY: unique ownership and &mut self exclude aliases to the page.
        unsafe { &mut *self.0.as_ptr().cast() }
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        #[cfg(target_os = "motor")]
        moto_sys::SysMem::free(self.0.as_ptr() as u64).expect("free owned memfs page");
        #[cfg(not(target_os = "motor"))]
        // SAFETY: this pointer was allocated with this layout and is owned once.
        unsafe {
            std::alloc::dealloc(self.0.as_ptr(), Self::layout())
        };
    }
}

/// Independently drainable, single-threaded cache of already-free pages.
/// Cloning this handle never shares live file data or borrows the filesystem.
#[derive(Clone)]
pub struct FreeBlockCache(Rc<RefCell<FreeBlocks>>);

struct FreeBlocks {
    head: Option<NonNull<u8>>,
    len: u64,
    cap: u64,
    #[cfg(test)]
    fail_alloc: bool,
    #[cfg(test)]
    allocated: u64,
    #[cfg(test)]
    released: u64,
}

impl FreeBlocks {
    fn pop(&mut self) -> Option<Block> {
        let head = self.head.take()?;
        // SAFETY: cached pages contain a link written by put(), are page-aligned,
        // and are owned exclusively by this list until popped.
        self.head = unsafe { head.as_ptr().cast::<Option<NonNull<u8>>>().read() };
        self.len -= 1;
        Some(Block(head))
    }

    fn release(&mut self, block: Block) {
        drop(block);
        #[cfg(test)]
        {
            self.released += 1;
        }
    }

    fn drain(&mut self) {
        while let Some(block) = self.pop() {
            self.release(block);
        }
    }
}

impl Drop for FreeBlocks {
    fn drop(&mut self) {
        self.drain();
    }
}

impl FreeBlockCache {
    pub(crate) fn new(cap: u64) -> Self {
        Self(Rc::new(RefCell::new(FreeBlocks {
            head: None,
            len: 0,
            cap: cap / BLOCK_SIZE as u64,
            #[cfg(test)]
            fail_alloc: false,
            #[cfg(test)]
            allocated: 0,
            #[cfg(test)]
            released: 0,
        })))
    }

    pub fn cached_free_bytes(&self) -> u64 {
        self.0.borrow().len * BLOCK_SIZE as u64
    }

    /// Return all cached pages without allocating or acquiring a filesystem lock.
    pub fn release_free_blocks(&self) {
        self.0.borrow_mut().drain();
    }

    pub(crate) fn take(&self) -> Result<Block> {
        let mut cache = self.0.borrow_mut();
        if let Some(mut block) = cache.pop() {
            block.bytes_mut().fill(0);
            return Ok(block);
        }
        #[cfg(test)]
        if cache.fail_alloc {
            return Err(ErrorKind::StorageFull.into());
        }
        let block = Block::new()?;
        #[cfg(test)]
        {
            cache.allocated += 1;
        }
        Ok(block)
    }

    pub(crate) fn put(&self, block: Block) {
        let mut cache = self.0.borrow_mut();
        if cache.len == cache.cap {
            cache.release(block);
            return;
        }
        // SAFETY: the page is uniquely owned and aligned for its link. No user
        // bytes are read until take() clears the entire page, including the link.
        unsafe {
            block
                .0
                .as_ptr()
                .cast::<Option<NonNull<u8>>>()
                .write(cache.head)
        };
        cache.head = Some(block.0);
        cache.len += 1;
        std::mem::forget(block); // Ownership transfers to the intrusive list.
    }

    #[cfg(test)]
    pub(crate) fn fail_alloc(&self, fail: bool) {
        self.0.borrow_mut().fail_alloc = fail;
    }

    #[cfg(test)]
    pub(crate) fn page_counts(&self) -> (u64, u64) {
        let cache = self.0.borrow();
        (cache.allocated, cache.released)
    }
}
