use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::*;

extern crate test;
use test::Bencher;

use crate::{Block, Frusa, Frusa4K};

// The two facts below are taken from the type instead of written down. Both
// were written down before, and both silently went stale when `Frusa4K` grew
// its ninth slab to keep 4K pages inside.

/// How many data slabs `frusa` has.
fn num_slabs<const SLABS: usize>(_frusa: &Frusa<SLABS>) -> usize {
    SLABS
}

/// The largest allocation `frusa` serves from those slabs rather than from the
/// back end.
fn max_inside_size<const SLABS: usize>(_frusa: &Frusa<SLABS>) -> usize {
    Frusa::<SLABS>::MAX_SIZE
}

struct BackEndAllocator {}

unsafe impl Send for BackEndAllocator {}
unsafe impl Sync for BackEndAllocator {}

unsafe impl GlobalAlloc for BackEndAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
}

static BACK_END: BackEndAllocator = BackEndAllocator {};

struct FlakyBackEndAllocator {}

unsafe impl Send for FlakyBackEndAllocator {}
unsafe impl Sync for FlakyBackEndAllocator {}

unsafe impl GlobalAlloc for FlakyBackEndAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        if FLAKY.load(Ordering::Relaxed) {
            use rand::Rng;
            let mut rng = rand::thread_rng();

            let random = rng.r#gen::<u8>();
            if random < 50 {
                return core::ptr::null_mut();
            }
        }
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
}

static FLAKY_BACK_END: FlakyBackEndAllocator = FlakyBackEndAllocator {};
static FLAKY: AtomicBool = AtomicBool::new(false);

#[test]
fn test_block() {
    unsafe {
        let mut meta = [0_u8; 32];
        let mut data = [0_u8; 32 * 64];
        let pblock = meta.as_mut_ptr() as *mut Block;
        let block = pblock.as_mut().unwrap();
        block.init(32_u64.ilog2(), 0, 0, data.as_mut_ptr());

        let mut expected = data.as_mut_ptr() as usize;

        for _ in 0..64 {
            let ptr = block.alloc();
            assert_eq!(ptr as usize, expected);
            expected += 32;
        }
        let ptr = block.alloc();
        assert!(ptr.is_null());

        let ptr = data.as_mut_ptr().add(32 * 13);
        assert!(block.dealloc(ptr).is_ok());

        assert_eq!(ptr, block.alloc());
    }
}

#[test]
fn test_init() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let slabs = num_slabs(&frusa.inner);
    assert_eq!(0, frusa.stats().allocated_metadata);

    // One metadata struct per slab, plus one for the metadata block holding
    // them: the stats() call above already forced the lazy init.
    assert_eq!((slabs + 1) * 64, frusa.stats().in_use_metadata);

    frusa.inner.init();

    /* One page for the metadata slab. */
    assert_eq!(4096, frusa.stats().allocated_from_fallback);
    const METADATA_ITEMS_PER_4K: usize = 4096 / (64 * 64);
    assert_eq!(
        (slabs + METADATA_ITEMS_PER_4K) << frusa.inner.metadata_slab.entry_sz_log2,
        frusa.stats().in_use_metadata
    );

    let layout = Layout::from_size_align(1, 1).unwrap();
    let ptr = unsafe { frusa.alloc(layout) };
    assert!(!ptr.is_null());

    /* One page for the metadata slab, and one page for the smallest slab. */
    assert_eq!(4096 * 2, frusa.stats().allocated_from_fallback);
    assert_eq!(
        (slabs + METADATA_ITEMS_PER_4K + (4096 / (16 * 64)))
            << frusa.inner.metadata_slab.entry_sz_log2,
        frusa.stats().in_use_metadata
    );
    assert_eq!(frusa.stats().in_use, frusa.stats().in_use_metadata + 16);

    unsafe {
        frusa.dealloc(ptr, layout);
    }
}

#[test]
fn basic_test() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);

    for size in 1..5000 {
        for align_step in 1..8 {
            let align: usize = 1 << align_step;
            let layout = Layout::from_size_align(size, align).unwrap();
            unsafe {
                let ptr = frusa.alloc(layout);
                assert!(!ptr.is_null());
                assert_eq!(0, (ptr as usize) & (align - 1));
                let buf = core::slice::from_raw_parts_mut(ptr, size);
                for idx in 0..size {
                    buf[idx] = (idx % 256) as u8;
                    assert_eq!((idx % 256) as u8, buf[idx]);
                }
            }
        }
    }
}

#[test]
fn reclaim_test() {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    frusa.inner.init();

    #[cfg(not(debug_assertions))]
    const ALLOCS: usize = 1_000_000;
    #[cfg(debug_assertions)]
    const ALLOCS: usize = 10_000;

    println!(
        "init: allocated from system: {} used bytes: {}",
        frusa.stats().allocated_from_fallback,
        frusa.stats().in_use
    );

    let mut ptrs: std::vec::Vec<(*mut u8, Layout)> = std::vec::Vec::with_capacity(ALLOCS);
    for _ in 0..ALLOCS {
        let alloc_bucket: usize = 4 + (rng.r#gen::<u16>() % 8) as usize;
        let sz = 1 << alloc_bucket;
        let layout = Layout::from_size_align(sz, 8).unwrap();

        let ptr = unsafe { frusa.alloc(layout) };
        assert!(!ptr.is_null());
        ptrs.push((ptr, layout));
    }

    println!(
        "alloc: allocated from system: {} used bytes: {}",
        frusa.stats().allocated_from_fallback,
        frusa.stats().in_use
    );

    for (ptr, layout) in &ptrs {
        unsafe { frusa.dealloc(*ptr, *layout) };
    }
    frusa.reclaim();

    println!(
        "reclaim: allocated from system: {} used bytes: {} of these metadata: {} - {}",
        frusa.stats().allocated_from_fallback,
        frusa.stats().in_use,
        frusa.stats().allocated_metadata,
        frusa.stats().in_use_metadata
    );
}

#[test]
fn stress_test() {
    FLAKY.store(false, Ordering::Relaxed);
    static STRESSED_FRUSA: Frusa4K = Frusa4K::new(&FLAKY_BACK_END);

    #[cfg(debug_assertions)]
    const STEPS: usize = 1_000;
    #[cfg(not(debug_assertions))]
    const STEPS: usize = 1_000_000;

    let thread_fn = || {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        for step in 0..STEPS {
            let alloc_bucket: usize = 4 + (rng.r#gen::<u16>() % 20) as usize;
            let sz = 1 << alloc_bucket;

            if step == 50 {
                // Don't fail during the init phase, but fail later.
                FLAKY.store(true, Ordering::Relaxed);
            }

            let layout = Layout::from_size_align(sz, 8).unwrap();

            let ptr = loop {
                let ptr = unsafe { STRESSED_FRUSA.alloc(layout) };
                if !ptr.is_null() {
                    break ptr;
                } else {
                    continue;
                }
            };
            let buf = unsafe { core::slice::from_raw_parts_mut(ptr, sz) };
            if sz < 1024 {
                // Doing this check for larger buffers gets too slow.
                for idx in 0..(sz) {
                    buf[idx] = (idx % 256) as u8;
                }
                for idx in 0..(sz) {
                    assert_eq!((idx % 256) as u8, buf[idx]);
                }
            }
            unsafe { STRESSED_FRUSA.dealloc(ptr, layout) };
        }
    };

    let mut threads = vec![];

    for _ in 0..8 {
        threads.push(std::thread::spawn(thread_fn));
    }

    // Concurrently with threads above, do alloc + reclaim.
    use rand::Rng;
    let mut rng = rand::thread_rng();

    for _ in 0..100 {
        const ALLOCS: usize = STEPS / 100;
        let mut ptrs: std::vec::Vec<(*mut u8, Layout)> = std::vec::Vec::with_capacity(ALLOCS);

        for _ in 0..ALLOCS {
            let alloc_bucket: usize = 4 + (rng.r#gen::<u16>() % 10) as usize;
            let sz = 1 << alloc_bucket;
            let layout = Layout::from_size_align(sz, 8).unwrap();

            let ptr = loop {
                let ptr = unsafe { STRESSED_FRUSA.alloc(layout) };
                if !ptr.is_null() {
                    break ptr;
                } else {
                    continue;
                }
            };
            ptrs.push((ptr, layout));
        }

        for (ptr, layout) in &ptrs {
            unsafe { STRESSED_FRUSA.dealloc(*ptr, *layout) };
        }

        STRESSED_FRUSA.reclaim();
    }

    for handle in threads {
        handle.join().unwrap();
    }
}

#[bench]
fn single_threaded_speed_test(bench: &mut Bencher) {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    frusa.inner.init();

    // Anything larger goes to the back end, and would benchmark that instead.
    let max_inside = max_inside_size(&frusa.inner);

    let bench_fn = || {
        let sz: usize = (rng.r#gen::<u16>() as usize) % (max_inside + 1);

        let layout = Layout::from_size_align(sz, 8).unwrap();
        let ptr = unsafe { frusa.alloc(layout) };
        assert!(!ptr.is_null());
        unsafe { frusa.dealloc(ptr, layout) };
    };

    bench.iter(bench_fn);
}

static FRUSA: Frusa4K = Frusa4K::new(&BACK_END);
#[derive(Clone, Copy)]
enum UseAlloc {
    Frusa,
    System,
}

impl UseAlloc {
    fn get(&self) -> &'static dyn GlobalAlloc {
        match self {
            Self::Frusa => &FRUSA,
            Self::System => &BACK_END,
        }
    }
}

fn concurrent_speed_test_impl(use_alloc: UseAlloc, num_threads: usize) {
    #[cfg(not(debug_assertions))]
    const STEPS: usize = 10_000_000;
    #[cfg(debug_assertions)]
    const STEPS: usize = 10_000;

    let max_inside = max_inside_size(&FRUSA.inner);
    let slabs = num_slabs(&FRUSA.inner);

    let thread_fn = move || {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let allocator = use_alloc.get();

        for _ in 0..STEPS {
            // Randomize across buckets rather than linearly, otherwise the
            // largest bucket gets half of all allocations. Shifting down from
            // the largest size served inside hits every slab and nothing that
            // would land in the back end.
            let sz = max_inside >> (rng.r#gen::<u16>() as usize % slabs);
            let layout = Layout::from_size_align(sz, 8).unwrap();

            let ptr = unsafe { allocator.alloc(layout) };
            assert!(!ptr.is_null());
            unsafe { allocator.dealloc(ptr, layout) };
        }
    };

    let mut threads = std::vec::Vec::with_capacity(num_threads);

    let start = std::time::Instant::now();
    for _ in 0..num_threads {
        threads.push(std::thread::spawn(thread_fn));
    }

    for handle in threads {
        handle.join().unwrap();
    }
    let nanos = start.elapsed().as_nanos() as f64;

    let ns_per_op = nanos / (STEPS as f64);
    let throughput = (1000 * STEPS * num_threads) as f64 / nanos;
    println!(
        "concurrent speed test: {} threads: {:>7.2} ns per alloc/dealloc; throughput: {:>6.2} ops/usec",
        num_threads, ns_per_op, throughput
    );
}

#[test]
fn concurrent_speed_test() {
    FRUSA.inner.init();

    println!("\n------- FRUSA Allocator ---------------");
    concurrent_speed_test_impl(UseAlloc::Frusa, 1);
    concurrent_speed_test_impl(UseAlloc::Frusa, 2);
    concurrent_speed_test_impl(UseAlloc::Frusa, 4);
    concurrent_speed_test_impl(UseAlloc::Frusa, 8);

    println!("\n------- Rust System Allocator ----------");
    concurrent_speed_test_impl(UseAlloc::System, 1);
    concurrent_speed_test_impl(UseAlloc::System, 2);
    concurrent_speed_test_impl(UseAlloc::System, 4);
    concurrent_speed_test_impl(UseAlloc::System, 8);
}
