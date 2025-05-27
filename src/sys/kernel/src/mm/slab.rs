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
            let refs = refs.fetch_sub(1, Ordering::Relaxed);
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
    next: AtomicPtr<Self>, // use a ptr instead of an option due to inplace_init
    used: AtomicU16,       // Max is 4096, so u16 is enough.
    refs: *const [AtomicU32; 4096], // If null, only SlabBox can be allocated; otherwise SlabArc.
    next_lock: SpinLock<()>, // Protects self.next changes.
}

impl<T: Slabbable> Slab4096<T> {
    const NUM_ELEMENTS: usize = 4096;
    const NUM_BITMAPS: usize = 64;
    const NUM_ELEMENTS_PER_BITMAP: usize = 64;

    pub unsafe fn from_uninit(mem: *mut Self, refs: *const [AtomicU32; 4096]) -> &'static Self {
        let slab_ref = &mut *mem;
        for idx in 0..Self::NUM_BITMAPS {
            slab_ref.used_bitmap[idx].store(0, Ordering::Relaxed);
        }
        for idx in 0..Self::NUM_ELEMENTS {
            slab_ref.data[idx].inplace_init()
        }

        slab_ref
            .next
            .store(core::ptr::null_mut(), Ordering::Relaxed);
        slab_ref.used.store(0, Ordering::Relaxed);

        slab_ref.refs = refs;
        if !refs.is_null() {
            let refs = refs.as_ref().unwrap();
            for entry in refs {
                entry.store(0, Ordering::Relaxed);
            }
        }

        slab_ref
    }

    fn alloc(&'static self) -> Result<(*mut T, usize), moto_rt::ErrorCode> {
        let mut iters = 0_u64;
        loop {
            iters += 1;
            if iters > 10000 {
                panic!("slab alloc looping (1)");
            }
            if self.used.load(Ordering::Relaxed) as usize == Self::NUM_ELEMENTS {
                return Err(moto_rt::E_OUT_OF_MEMORY);
            }

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
                    self.used.fetch_add(1, Ordering::Relaxed);

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
        }
    }

    fn free(&'static self, data: *mut T) {
        let idx = unsafe { data.offset_from(self.data.get_unchecked(0) as *const T) };
        assert!(idx >= 0);
        let idx = idx as usize;
        assert!(idx <= Self::NUM_ELEMENTS);

        let bitmap_idx = idx >> 6;
        assert_eq!(Self::NUM_ELEMENTS_PER_BITMAP >> 6, 1);
        let bit = 1 << (idx & (Self::NUM_ELEMENTS_PER_BITMAP - 1));

        let bitmap = self.used_bitmap.get(bitmap_idx).unwrap();
        let prev = bitmap.fetch_xor(bit, Ordering::Relaxed);
        assert_eq!(bit, prev & bit);
        self.used.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct MMSlab<T: Slabbable> {
    slabs: AtomicPtr<Slab4096<T>>,
    // The number of used/allocated data items is not tracked at this level
    // because deallocation happens at Slab4096 level, i.e. this object is
    // bypassed.
}

impl<T: Slabbable> Drop for MMSlab<T> {
    fn drop(&mut self) {
        // There are slabs per address space, so this is called on every
        // process/address space drop.
        let mut pslab = self.slabs.load(Ordering::Acquire);
        while !pslab.is_null() {
            let slab = unsafe { pslab.as_ref().unwrap() };
            pslab = {
                slab.next_lock.lock(line!());
                let pnext = slab.next.load(Ordering::Acquire);
                unsafe {
                    Self::drop_pslab(pslab);
                }
                pnext
            };
        }
    }
}

impl<T: Slabbable> MMSlab<T> {
    unsafe fn drop_pslab(_pslab: *mut Slab4096<T>) {
        panic!("Slabs are used only for phys pages, so we never drop them.")
        // let slab = pslab.as_mut().unwrap();
        // assert_eq!(slab.used.load(Ordering::Relaxed), 0);
        // let refs = slab.refs;
        // if !refs.is_null() {
        //     crate::mm::raw_dealloc_for_slab(refs);
        //     slab.refs = core::ptr::null();
        // }
        // crate::mm::raw_dealloc_for_slab(pslab as *const Slab4096<T>);
    }

    unsafe fn new_pslab(shared: bool) -> *mut Slab4096<T> {
        let pslab = crate::mm::raw_alloc_for_slab::<Slab4096<T>>();
        let prefs = if shared {
            crate::mm::raw_alloc_for_slab::<[AtomicU32; 4096]>()
        } else {
            core::ptr::null()
        };
        // _init below is not used; but from_uninit() call is required.
        let _init = Slab4096::<T>::from_uninit(pslab, prefs);
        pslab
    }

    pub fn new(shared: bool) -> Self {
        unsafe {
            let pslab = Self::new_pslab(shared);
            Self {
                slabs: AtomicPtr::new(pslab),
            }
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

    fn alloc(&self) -> Result<((*mut T, usize), *const Slab4096<T>), ErrorCode> {
        let mut pslab: *const _ = self.slabs.load(Ordering::Relaxed);

        let mut iters = 0_u64;
        loop {
            iters += 1;
            if iters > 100 {
                panic!("slab alloc looping (2)");
            }
            let slab = unsafe { pslab.as_ref().unwrap() };
            if let Ok(res) = slab.alloc() {
                return Ok((res, slab));
            }

            pslab = self.next_slab(slab)?
        }
    }

    fn next_slab(&self, slab: &Slab4096<T>) -> Result<*const Slab4096<T>, ErrorCode> {
        // First, try unlocked.
        let pnext: *const _ = slab.next.load(Ordering::Relaxed);
        if !pnext.is_null() {
            return Ok(pnext);
        }

        let shared = !slab.refs.is_null();

        {
            let _lock = slab.next_lock.lock(line!());

            // Try again with the lock.
            let pnext: *const _ = slab.next.load(Ordering::Relaxed);
            if !pnext.is_null() {
                return Ok(pnext);
            }

            let pnext = unsafe { Self::new_pslab(shared) };

            slab.next
                .compare_exchange(
                    core::ptr::null_mut(),
                    pnext,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .unwrap();

            core::mem::drop(_lock);
            Ok(pnext)
        }
    }
}
