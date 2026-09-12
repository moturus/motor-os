//! A block: 64 equally sized slots and the descriptor that tracks them.
//! Descriptors live in the metadata slab, separate from the data they
//! describe, except for metadata blocks, whose descriptor is their own first
//! slot.

use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

/// Set while the block is linked into its slab's partial stack. Read and
/// written only under the slab's partial lock (or its write guard).
pub(crate) const ON_STACK: u32 = 1;

#[repr(C)]
pub(crate) struct Block {
    pub entry_sz_log2: u32,
    // Blocks are allocated in batches; a batch is reclaimed whole.
    pub batch_pos: u16,
    pub batch_sz: u16,
    pub used_bitmap: AtomicU64,
    pub data: *mut u8, // entry_sz * 64
    /// Batch list link, owned by growth and reclaim under the write guard.
    pub next: AtomicPtr<Block>,
    /// Partial stack link, valid while `ON_STACK` is set.
    pub partial_next: AtomicPtr<Block>,
    /// The thread cache that holds this block privately, or null.
    pub owner: AtomicPtr<()>,
    pub flags: AtomicU32,
    _reserved: [u32; 3], // Keeps size_of::<Self>() at 64.
}

const _: () = assert!(core::mem::size_of::<Block>() == 64);

impl Block {
    pub const ENTRIES: usize = 64;

    pub fn init(&mut self, entry_sz_log2: u32, batch_pos: u16, batch_sz: u16, data: *mut u8) {
        self.entry_sz_log2 = entry_sz_log2;
        self.batch_pos = batch_pos;
        self.batch_sz = batch_sz;
        self.used_bitmap.store(0, Ordering::Release);
        self.data = data;
        self.next.store(core::ptr::null_mut(), Ordering::Release);
        self.partial_next
            .store(core::ptr::null_mut(), Ordering::Release);
        self.owner.store(core::ptr::null_mut(), Ordering::Release);
        self.flags.store(0, Ordering::Release);
    }

    pub fn entry_size(&self) -> usize {
        1 << self.entry_sz_log2
    }

    pub fn block_size(&self) -> usize {
        Self::ENTRIES << self.entry_sz_log2
    }

    pub fn is_full(&self) -> bool {
        self.used_bitmap.load(Ordering::SeqCst) == u64::MAX
    }

    pub fn is_empty(&self) -> bool {
        self.used_bitmap.load(Ordering::SeqCst) == 0
    }

    pub fn on_stack(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & ON_STACK != 0
    }

    pub fn set_on_stack(&self, on: bool) {
        self.flags
            .store(if on { ON_STACK } else { 0 }, Ordering::Relaxed);
    }

    /// Claims the lowest free slot. Returns the slot's address and whether
    /// this claim filled the block, or `None` if the block is full. A
    /// compare-and-swap that loses to a concurrent free is retried; only
    /// a full block is a failure.
    pub fn alloc(&self) -> Option<(*mut u8, bool)> {
        let mut bitmap = self.used_bitmap.load(Ordering::Relaxed);
        loop {
            let ones = bitmap.trailing_ones();
            if ones == 64 {
                return None;
            }
            let claimed = bitmap | (1u64 << ones);
            match self.used_bitmap.compare_exchange_weak(
                bitmap,
                claimed,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let ptr = unsafe { self.data.add((ones as usize) << self.entry_sz_log2) };
                    return Some((ptr, claimed == u64::MAX));
                }
                Err(current) => bitmap = current,
            }
        }
    }

    /// The slot index of `ptr`, or `None` if it is outside this block or
    /// not on a slot boundary.
    pub fn slot_of(&self, ptr: *mut u8) -> Option<u32> {
        let offset = (ptr as usize).checked_sub(self.data as usize)?;
        if offset >= self.block_size() || offset & (self.entry_size() - 1) != 0 {
            return None;
        }
        Some((offset >> self.entry_sz_log2) as u32)
    }

    /// Releases the slot holding `ptr`. Returns whether the block was full
    /// before this free, which is the moment it must rejoin the partial
    /// stack. Panics on a pointer this block does not own or a slot that
    /// is not in use.
    pub fn dealloc(&self, ptr: *mut u8) -> bool {
        let Some(slot) = self.slot_of(ptr) else {
            panic!("FRUSA: bad ptr for dealloc");
        };
        let bit = 1u64 << slot;
        let prev = self.used_bitmap.fetch_xor(bit, Ordering::SeqCst);
        assert_eq!(prev & bit, bit, "FRUSA: double free");
        prev == u64::MAX
    }
}
