use crate::pvh::PvhStartInfo;
use core::alloc::Layout;
use core::sync::atomic::Ordering;

/* KLoader memory layout is very simple:
 * [0..1M) is reserved for early boot stages/bios/firmware.
 * initrd is [0..512) - header
 *           [512..kloader.size) - kloader
 *           [xx..yy) - kernel
 *           [yy..zz) - sys-io
 *
 * x64.boot loads initrd at 1M (in qemu).
 * PVH loaders (CHV, Firecracker) load initrd at the top of RAM.
 *
 * CHV loads kloader at 1M + 512.
 *
 * So kloader is at [1M+512..kloader.len)
 *
 * [0..1G) - direct mapped by bootup_bsp.s
 *
 * KLOADER: 1M + 512, direct mapped.
 * STACK  : phys: [15M..15.5M), the BSP stack grows down from 15.5M.
 * HEAP   : phys: [15.5M..16M).
 * KERNEL : phys: [16M..), virt: at kernel_offset.
 *
 * An initrd at 1M must end below the stack: the debug one is about 11M.
 * Everything below the kernel is released by the kernel once it is up, so
 * placing the kernel higher costs no RAM; it only raises the smallest RAM
 * that can boot.
 *
 * The whole phys mem is mapped at PAGING_DIRECT_MAP_OFFSET.
 */

const ONE_MB: usize = 1 << 20;

// We load the kernel at 16MB phys and PAGING_DIRECT_MAP_OFFSET + 16MB virt.
// Keep in sync with KERNEL_PHYS_START in the kernel and with layout.ld.
pub const KERNEL_PHYS_START: usize = ONE_MB * 16;

// The heap holds the AP stacks (16K each) and the kernel's bootup info:
// 240K with 16 CPUs.
const HEAP_SZ: usize = ONE_MB / 2;
const HEAP_START: usize = KERNEL_PHYS_START - HEAP_SZ;

// The BSP stack needs under 8K even in debug builds.
const STACK_SZ: usize = ONE_MB / 2;
const STACK_BOTTOM: usize = HEAP_START - STACK_SZ;

#[no_mangle]
pub static BOOTUP_STACK_START: u32 = HEAP_START as u32;

static ALLOCATED_HEAP: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

pub fn align_up(val: usize, align: usize) -> usize {
    assert!(align.is_power_of_two());
    (val + align - 1) & !(align - 1)
}

pub const PAGE_SIZE_SMALL: u64 = 4096;
// The full physical memory is mapped to [DIRECT_MAP_OFFSET, *)
pub const PAGING_DIRECT_MAP_OFFSET: u64 = 1_u64 << 46;

// Where to load the kernel.
// Note that we don't do kaslr, as it is mostly pointless:
// https://grsecurity.net/kaslr_an_exercise_in_cargo_cult_security
pub const fn kernel_offset() -> u64 {
    PAGING_DIRECT_MAP_OFFSET + (KERNEL_PHYS_START as u64)
}

#[allow(clippy::upper_case_acronyms)]
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct PTE {
    entry: u64,
}

impl PTE {
    const PRESENT: u64 = 0b_0000_0001; // bit 0.
    const WRITABLE: u64 = 0b_0000_0010; // bit 1.
    const HUGE: u64 = 0b_1000_0000; // bit 7.

    #[inline]
    const fn empty() -> Self {
        Self { entry: 0 }
    }

    fn from_u64(val: u64) -> Self {
        Self { entry: val }
    }
}

#[repr(align(4096))]
#[repr(C)]
struct HwPageTable {
    entries: [PTE; Self::PTE_COUNT],
}

impl HwPageTable {
    // The number of entries in a page table.
    const PTE_COUNT: usize = 512;

    // Creates an empty page table. Used for static L4,L3.
    const fn new() -> Self {
        const EMPTY: PTE = PTE::empty();
        HwPageTable {
            entries: [EMPTY; Self::PTE_COUNT],
        }
    }

    fn set(&mut self, idx: u64, pte: PTE) {
        let idx = idx as usize;
        assert!(idx < Self::PTE_COUNT);
        self.entries[idx] = pte;
    }
}

#[no_mangle]
static mut L4_TABLE: HwPageTable = HwPageTable::new();
#[no_mangle]
static mut L3_TABLE: HwPageTable = HwPageTable::new();

fn set_heap_start(start: usize) {
    // Allow allocations only on bsp.
    assert_eq!(0, crate::cpuid::apic_id_32());

    assert_eq!(ALLOCATED_HEAP.swap(start, Ordering::Relaxed), 0);
}

struct BumpAllocator {}

unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        alloc(layout) as *mut u8
    }

    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}

pub unsafe fn alloc(layout: Layout) -> usize {
    // Allow allocations only on bsp.
    assert_eq!(0, crate::cpuid::apic_id_32());

    // set_heap_start() must have been called.
    assert_ne!(ALLOCATED_HEAP.load(Ordering::Relaxed), 0);

    let start = align_up(ALLOCATED_HEAP.load(Ordering::Relaxed), layout.align());
    ALLOCATED_HEAP.store(start + layout.size(), Ordering::Relaxed);

    // The heap ends where the kernel starts.
    assert!(ALLOCATED_HEAP.load(Ordering::Relaxed) <= HEAP_START + HEAP_SZ);

    start
}

#[global_allocator]
static BUMP_ALLOCATOR: BumpAllocator = BumpAllocator {};

pub fn init(pvh: &'static PvhStartInfo) {
    let max_addr = {
        let mut max_addr = 0;
        for mm_entry in pvh.mem_map() {
            max_addr = max_addr.max(mm_entry.addr + mm_entry.size);
        }
        max_addr
    };
    assert!(max_addr <= PAGING_DIRECT_MAP_OFFSET);

    if max_addr > (1_u64 << 39) {
        // We don't currently support more than 512GB of physical memory. Won't be too
        // difficult to change that.
        crate::raw_log!("WARNING: physical memory above 512GB is present but not used.\n");
    }

    // Map the full physical memory to DIRECT_MAP_OFFSET in 1G pages.
    // While it would've been nice to have a single 512GB huge page to cover all
    // physical memory, it seems that Intel CPUs don't support hugepages of this size.
    static mut L3_TABLE_DIRECT_MAP: HwPageTable = HwPageTable::new();

    unsafe {
        #[allow(static_mut_refs)]
        set_l3_table_for_direct_map(0, max_addr, &mut L3_TABLE_DIRECT_MAP);

        let idx_l4 = idx_l4(PAGING_DIRECT_MAP_OFFSET);
        assert_eq!(idx_l4, idx_l4 & ((1 << 9) - 1));

        let mut pte = core::ptr::addr_of!(L3_TABLE_DIRECT_MAP) as usize as u64;
        assert_eq!(0, pte & ((1 << 12) - 1));

        pte |= PTE::PRESENT | PTE::WRITABLE;
        #[allow(static_mut_refs)]
        L4_TABLE.set(idx_l4, PTE::from_u64(pte));

        // validate.
        let l4_addr = core::ptr::addr_of!(L4_TABLE) as usize;
        assert_eq!(
            (l4_addr as *const u64).as_ref().unwrap(),
            ((l4_addr + (PAGING_DIRECT_MAP_OFFSET as usize)) as *const u64)
                .as_ref()
                .unwrap()
        );
    }

    // initrd is either loaded at 1M by our x64.boot, below the stack, or at
    // the top of RAM by a PVH loader, above the kernel.
    let (initrd_start, initrd_size) = pvh.initrd();
    let initrd_end = initrd_start + initrd_size;
    let kernel_end = KERNEL_PHYS_START + crate::KERNEL_IMAGE_LEN;
    if initrd_end > STACK_BOTTOM && initrd_start < kernel_end {
        crate::raw_log!(
            "KLOADER: initrd [0x{:x}..0x{:x}) overlaps the boot stack, heap or kernel at [0x{:x}..0x{:x}).\n",
            initrd_start,
            initrd_end,
            STACK_BOTTOM,
            kernel_end
        );
        if initrd_start < STACK_BOTTOM {
            crate::raw_log!("The initrd is too large for KERNEL_PHYS_START.\n");
        } else {
            crate::raw_log!("Try adding more RAM.\n");
        }
        crate::vmm_exit();
    }

    // Don't need to offset heap addresses as the first 1G is direct-mapped.
    set_heap_start(HEAP_START);
}

const fn idx_l4(virt_addr: u64) -> u64 {
    (virt_addr >> 39) & 0o777 // 39 == (12 + 9 + 9 + 9)
}

fn set_l3_table_for_direct_map(start: u64, max_addr: u64, l3_table: &mut HwPageTable) {
    let mut start = start;
    let end = {
        if max_addr - start > (1_u64 << 39) {
            start + (1_u64 << 39)
        } else {
            max_addr
        }
    };

    while start < end {
        let idx_l3 = (start & ((1_u64 << 39) - 1)) >> (12 + 9 + 9);
        assert_eq!(idx_l3, idx_l3 & ((1 << 9) - 1));

        let mut pte = start;
        assert_eq!(0, pte & ((1 << 12) - 1));
        pte |= PTE::PRESENT | PTE::WRITABLE | PTE::HUGE;

        l3_table.set(idx_l3, PTE::from_u64(pte));
        start += 1_u64 << 30;
    }
}
