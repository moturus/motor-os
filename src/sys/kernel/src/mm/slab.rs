use crate::util::SpinLock;
use core::sync::atomic::*;
use moto_rt::ErrorCode;

pub trait Slabbable: Sized + 'static + Send + Sync {
    // Initialize @self in place, assuming uninit.
    fn inplace_init(&mut self);

    // Called immediately before the object is reinserted back into the slab.
    fn drop_slabbable(&mut self);
}

pub struct SlabArc<T: Slabbable> {
    slab: *const Slab4096<T>,
    data: *mut T,
    refs: *const AtomicU32,
}

unsafe impl<T: Slabbable> Send for SlabArc<T> {}
unsafe impl<T: Slabbable> Sync for SlabArc<T> {}

impl<T: Slabbable> Default for SlabArc<T> {
    fn default() -> Self {
        Self::null()
    }
}

impl<T: Slabbable> SlabArc<T> {
    pub fn get(&self) -> Option<&T> {
        unsafe { self.data.as_ref() }
    }

    #[allow(clippy::mut_from_ref)]
    pub fn get_mut(&self) -> Option<&mut T> {
        unsafe { self.data.as_mut() }
    }

    pub fn is_null(&self) -> bool {
        self.data.is_null()
    }

    pub fn null() -> Self {
        SlabArc {
            slab: core::ptr::null(),
            data: core::ptr::null_mut(),
            refs: core::ptr::null(),
        }
    }

    pub fn take(&mut self) -> Self {
        let res = Self {
            slab: self.slab,
            data: self.data,
            refs: self.refs,
        };
        self.clear_may_leak();
        res
    }

    pub fn refs(&self) -> u32 {
        let refs = unsafe { self.refs.as_ref() };
        match refs {
            Some(refs) => refs.load(Ordering::Relaxed),
            None => 0,
        }
    }

    pub fn clone(&self) -> Self {
        let refs = unsafe { self.refs.as_ref() };
        if let Some(refs) = refs {
            refs.fetch_add(1, Ordering::Relaxed);
        };
        Self {
            slab: self.slab,
            data: self.data,
            refs: self.refs,
        }
    }

    pub fn clear_may_leak(&mut self) {
        self.slab = core::ptr::null();
        self.data = core::ptr::null_mut();
        self.refs = core::ptr::null();
    }
}

impl<T: Slabbable> Drop for SlabArc<T> {
    fn drop(&mut self) {
        let refs = unsafe { self.refs.as_ref() };
        if let Some(refs) = refs {
            // AcqRel: release orders this owner's writes before the decrement;
            // acquire makes all owners' writes visible to the last owner,
            // which runs drop_slabbable() below.
            let refs = refs.fetch_sub(1, Ordering::AcqRel);
            if refs == 1 {
                unsafe {
                    self.data.as_mut().unwrap().drop_slabbable();
                    self.slab.as_ref().unwrap().free(self.data);
                    self.data = core::ptr::null_mut();
                    self.slab = core::ptr::null();
                }
            }
        }
    }
}

// Slab for 4096 items.
#[repr(C)]
pub struct Slab4096<T: Slabbable> {
    used_bitmap: [AtomicU64; 64],
    data: [T; 4096],
    // Allocated slots plus allocation reservations. Reserving before touching
    // the bitmap keeps this count authoritative at the full boundary.
    used: AtomicU16,                // Max is 4096, so u16 is enough.
    refs: *const [AtomicU32; 4096], // If null, only SlabBox can be allocated; otherwise SlabArc.

    // Partial-list link; meaningful only while the slab is in the list.
    // Mutated only under the owner's list_lock.
    partial_next: AtomicPtr<Self>,
    // True iff this slab is in the owner's partial list. Accessed only under
    // the owner's list_lock, so membership is exact: a slab is never pushed
    // twice, which would link the list into a cycle.
    in_list: AtomicBool,
    // Back-pointer to the owning MMSlab, so that free() can reach the partial
    // list. The owner must never move after its first alloc(); see MMSlab::new().
    owner: *const MMSlab<T>,
}

impl<T: Slabbable> Slab4096<T> {
    const NUM_ELEMENTS: usize = 4096;
    const NUM_BITMAPS: usize = 64;
    const NUM_ELEMENTS_PER_BITMAP: usize = 64;

    pub unsafe fn from_uninit(
        mem: *mut Self,
        refs: *const [AtomicU32; 4096],
        owner: *const MMSlab<T>,
    ) -> &'static Self {
        let slab_ref = &mut *mem;
        for idx in 0..Self::NUM_BITMAPS {
            slab_ref.used_bitmap[idx].store(0, Ordering::Relaxed);
        }
        for idx in 0..Self::NUM_ELEMENTS {
            slab_ref.data[idx].inplace_init()
        }

        slab_ref.used.store(0, Ordering::Relaxed);

        slab_ref.refs = refs;
        if !refs.is_null() {
            let refs = refs.as_ref().unwrap();
            for entry in refs {
                entry.store(0, Ordering::Relaxed);
            }
        }

        slab_ref.partial_next = AtomicPtr::new(core::ptr::null_mut());
        slab_ref.in_list = AtomicBool::new(false);
        slab_ref.owner = owner;

        slab_ref
    }

    fn alloc(&'static self) -> Result<(*mut T, usize), moto_rt::ErrorCode> {
        // Reserve capacity before claiming a bitmap slot. With the opposite
        // order, another CPU can observe every bit set while `used` still
        // says the slab is partial, and spin until the reserving CPU runs.
        if self
            .used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                ((used as usize) < Self::NUM_ELEMENTS).then_some(used + 1)
            })
            .is_err()
        {
            return Err(moto_rt::E_OUT_OF_MEMORY);
        }

        loop {
            for bitmap_idx in 0..Self::NUM_BITMAPS {
                let bitmap = self.used_bitmap.get(bitmap_idx).unwrap();
                let prev = bitmap.load(Ordering::Relaxed);

                let ones = prev.trailing_ones();
                if ones == 64 {
                    continue;
                }

                let bit = 1u64 << ones;
                assert_eq!(0, prev & bit);
                if bitmap
                    .compare_exchange_weak(prev, prev | bit, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
                {
                    let idx = bitmap_idx * Self::NUM_ELEMENTS_PER_BITMAP + (ones as usize);
                    assert!(idx < Self::NUM_ELEMENTS);

                    let res = unsafe { self.data.get_unchecked(idx) };
                    unsafe {
                        // Safe because res cannot be referenced by anything else yet at this point.
                        let ptr = res as *const T;
                        let ptr = ptr as *mut T;
                        (*ptr).inplace_init();
                    }
                    return Ok((res as *const T as *mut T, idx));
                }
            }
            core::hint::spin_loop();
        }
    }

    fn free(&'static self, data: *mut T) {
        let idx = unsafe { data.offset_from(self.data.get_unchecked(0) as *const T) };
        assert!(idx >= 0);
        let idx = idx as usize;
        assert!(idx < Self::NUM_ELEMENTS);

        let bitmap_idx = idx >> 6;
        assert_eq!(Self::NUM_ELEMENTS_PER_BITMAP >> 6, 1);
        let bit = 1 << (idx & (Self::NUM_ELEMENTS_PER_BITMAP - 1));

        let bitmap = self.used_bitmap.get(bitmap_idx).unwrap();
        // Release pairs with the AcqRel CAS in alloc(): the freeing thread's
        // writes to the slot (drop_slabbable) become visible to the thread
        // that reallocates it.
        let prev = bitmap.fetch_xor(bit, Ordering::Release);
        assert_eq!(bit, prev & bit);

        // If this free transitions the slab from full to partial, push it
        // onto the partial list so future allocations can find it without
        // scanning. fetch_sub returns the previous value, so a return of
        // NUM_ELEMENTS means the slab was full before this free; exactly one
        // free() observes the transition.
        // Release publishes the cleared bitmap bit before another allocator
        // acquires the capacity reservation made available by this decrement.
        let prev_used = self.used.fetch_sub(1, Ordering::Release);
        if prev_used as usize == Self::NUM_ELEMENTS {
            let owner = unsafe { self.owner.as_ref().unwrap() };
            owner.push_partial(self as *const Self as *mut Self);
        }
    }
}

// A slab allocator over a list of partial slabs: slabs with free slots.
// The allocation fast path (head peek + bitmap CAS) is lock-free; list_lock
// serializes only list membership changes, which happen about once per 4096
// allocations plus once per full->partial transition.
pub struct MMSlab<T: Slabbable> {
    // Head of the partial list. Atomic so alloc() can peek it locklessly;
    // stores happen only under list_lock.
    partial: AtomicPtr<Slab4096<T>>,
    // Protects partial, partial_next, and in_list. A leaf lock: nothing is
    // allocated and no other lock is taken while it is held.
    list_lock: SpinLock<()>,
    // Whether slabs are shared (have refcounts). Stored at construction so
    // that lazy slab creation doesn't need to inspect an existing slab.
    shared: bool,
}

impl<T: Slabbable> MMSlab<T> {
    unsafe fn new_pslab(shared: bool, owner: *const MMSlab<T>) -> *mut Slab4096<T> {
        let pslab = crate::mm::raw_alloc_for_slab::<Slab4096<T>>();
        let prefs = if shared {
            crate::mm::raw_alloc_for_slab::<[AtomicU32; 4096]>()
        } else {
            core::ptr::null()
        };
        let _init = Slab4096::<T>::from_uninit(pslab, prefs, owner);
        pslab
    }

    pub fn new(shared: bool) -> Self {
        // The first slab is created lazily in alloc(): slabs hold a back
        // pointer to their owner, so self must be at its final address, which
        // is guaranteed at the first alloc(), not during new().
        Self {
            partial: AtomicPtr::new(core::ptr::null_mut()),
            list_lock: SpinLock::new(()),
            shared,
        }
    }

    pub fn alloc_arc(&self) -> Result<SlabArc<T>, ErrorCode> {
        let ((data, idx), slab) = self.alloc()?;

        let refs = unsafe { (*slab).refs };
        assert!(!refs.is_null());
        let refs = unsafe { refs.as_ref().unwrap().get(idx).unwrap() };
        let prev = refs.fetch_add(1, Ordering::Relaxed);
        assert_eq!(0, prev);
        Ok(SlabArc {
            slab,
            data,
            refs: refs as *const AtomicU32,
        })
    }

    // Push a slab onto the partial list unless it is already in it. Used both
    // for newly created slabs and by free() on full->partial transitions.
    fn push_partial(&self, pslab: *mut Slab4096<T>) {
        let _lock = self.list_lock.lock(line!());
        let slab = unsafe { pslab.as_ref().unwrap() };
        if slab.in_list.load(Ordering::Relaxed) {
            return;
        }
        slab.partial_next
            .store(self.partial.load(Ordering::Relaxed), Ordering::Relaxed);
        slab.in_list.store(true, Ordering::Relaxed);
        // Release publishes the slab's contents to lock-free peeks in alloc().
        self.partial.store(pslab, Ordering::Release);
    }

    // Pop the slab if it is still the list head and still full. The re-check
    // of used under the lock is what prevents losing a slab: if a racing
    // free() made the slab partial again, either the free's decrement is
    // visible here (lock ordering) and we keep the slab listed, or the free's
    // own push_partial() runs after us and relists it.
    fn maybe_pop_full(&self, pslab: *mut Slab4096<T>) {
        let _lock = self.list_lock.lock(line!());
        if self.partial.load(Ordering::Relaxed) != pslab {
            return;
        }
        let slab = unsafe { pslab.as_ref().unwrap() };
        if (slab.used.load(Ordering::Relaxed) as usize) < Slab4096::<T>::NUM_ELEMENTS {
            return;
        }
        self.partial
            .store(slab.partial_next.load(Ordering::Relaxed), Ordering::Release);
        slab.in_list.store(false, Ordering::Relaxed);
        slab.partial_next
            .store(core::ptr::null_mut(), Ordering::Relaxed);
    }

    fn alloc(&self) -> Result<((*mut T, usize), *const Slab4096<T>), ErrorCode> {
        loop {
            let pslab = self.partial.load(Ordering::Acquire);

            if pslab.is_null() {
                // No partial slabs. Create one before taking list_lock, as
                // raw_alloc_for_slab() takes mm locks and list_lock must stay
                // a leaf lock. Concurrent callers may each push a slab; the
                // extra slabs are used later, not leaked.
                let new = unsafe { Self::new_pslab(self.shared, self as *const Self) };
                self.push_partial(new);
                continue;
            }

            let slab = unsafe { pslab.as_ref().unwrap() };
            debug_assert!(core::ptr::eq(slab.owner, self)); // See new(): self must not move.
            match slab.alloc() {
                Ok(res) => {
                    if slab.used.load(Ordering::Relaxed) as usize == Slab4096::<T>::NUM_ELEMENTS {
                        self.maybe_pop_full(pslab);
                    }
                    return Ok((res, slab));
                }
                Err(_) => {
                    // The slab is full: pop it (re-checked under the lock)
                    // and retry with the next one.
                    self.maybe_pop_full(pslab);
                    continue;
                }
            }
        }
    }
}
